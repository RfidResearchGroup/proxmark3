//-----------------------------------------------------------------------------
// BWM WiFi bring-up (PM5 / AT32 side). See bwm_wifi.h.
//-----------------------------------------------------------------------------
#include "bwm_wifi.h"
#include "bwm_uart_at32.h"   // bwm_uart_write / bwm_uart_rx_available / bwm_uart_read
#include "bwm_forward.h"     // app_com header bytes + BWM_CMD_* forward codes
#include "pm3_cmd.h"         // PM3_SUCCESS / PM3_ETIMEOUT / PM3_EFAILED / PM3_EOVFLOW
#include "ticks_apis.h"      // GetTickCount / GetTickCountDelta
#include "dbprint.h"
#include "string.h"

// app_com CRC-16/CCITT-FALSE (same as bwm_forward)
static uint16_t wifi_crc16(const uint8_t *d, size_t n, uint16_t crc) {
    for (size_t i = 0; i < n; i++) {
        crc ^= (uint16_t)d[i] << 8;
        for (int b = 0; b < 8; b++)
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
    }
    return crc;
}

// Minimal one-shot app_com response parser: scans the UART RX stream for a
// SLAVE_RESP (0x2D 0x3D) echoing want_cmd, or a SLAVE_BCAST CMD_ERROR (8091).
// Runs only during setup, so it fully owns the RX stream here.
typedef enum { W_H1, W_H2, W_CL, W_CH, W_LL, W_LH, W_PL, W_KL, W_KH } wstate_t;

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

// Drop whatever is already sitting in the UART RX ring so a late ACK from a
// timed-out command cannot be consumed as the next command's response (same
// cmd code, e.g. a slow OTA_BEGIN ack arriving after we already gave up).
static void bwm_cmd_drain_rx(void) {
    uint8_t buf[64];
    uint32_t t0 = GetTickCount();
    while (bwm_uart_rx_available()) {
        uint16_t avail = bwm_uart_rx_available();
        (void)bwm_uart_read(buf, (uint32_t)MIN(avail, (uint16_t)sizeof(buf)));
        if (GetTickCountDelta(t0) > 50) {
            break;
        }
    }
}

int bwm_cmd(uint16_t cmd, const uint8_t *req, uint16_t req_len,
            uint8_t *resp, uint16_t *resp_len, uint32_t timeout_ms) {

    bwm_cmd_drain_rx();

    // ---- build + send HOST_CMD frame ----
    uint8_t frame[8 + 256];
    if (req_len > sizeof(frame) - 8) {
        return PM3_EOVFLOW;
    }
    size_t idx = 0;
    frame[idx++] = BWM_HDR_HOST_CMD_1;
    frame[idx++] = BWM_HDR_HOST_CMD_2;
    frame[idx++] = (uint8_t)(cmd & 0xFF);
    frame[idx++] = (uint8_t)(cmd >> 8);
    frame[idx++] = (uint8_t)(req_len & 0xFF);
    frame[idx++] = (uint8_t)(req_len >> 8);
    if (req_len) {
        memcpy(&frame[idx], req, req_len);
        idx += req_len;
    }
    uint16_t crc = wifi_crc16(frame, idx, 0xFFFF);
    frame[idx++] = (uint8_t)(crc & 0xFF);
    frame[idx++] = (uint8_t)(crc >> 8);
    bwm_uart_write(frame, idx);

    // ---- wait for the matching SLAVE_RESP ----
    wstate_t st = W_H1;
    bool     is_resp = false;
    uint16_t rcmd = 0, rlen = 0, rgot = 0, rcrc_recv = 0, rcrc_calc = 0;
    uint8_t  pbuf[256];
    uint8_t  h1 = 0;

    uint32_t t0 = GetTickCount();
    for (;;) {
        if (GetTickCountDelta(t0) > timeout_ms) {
            return PM3_ETIMEOUT;
        }
        uint8_t buf[64];
        uint16_t avail = bwm_uart_rx_available();
        if (avail == 0) {
            SpinDelay(1);
            continue;
        }
        uint32_t n = bwm_uart_read(buf, (uint32_t)MIN(avail, (uint16_t)sizeof(buf)));
        for (uint32_t i = 0; i < n; i++) {
            uint8_t byte = buf[i];
            switch (st) {
                case W_H1:
                    if (byte == BWM_HDR_SLAVE_RESP_1 || byte == BWM_HDR_SLAVE_BCAST_1) {
                        h1 = byte;
                        is_resp = (byte == BWM_HDR_SLAVE_RESP_1);
                        st = W_H2;
                    }
                    break;
                case W_H2: {
                    bool ok = (is_resp  && byte == BWM_HDR_SLAVE_RESP_2) ||
                              (!is_resp && byte == BWM_HDR_SLAVE_BCAST_2);
                    if (ok) {
                        uint8_t hdr[2] = { h1, byte };
                        rcrc_calc = wifi_crc16(hdr, 2, 0xFFFF);
                        rgot = 0;
                        st = W_CL;
                    } else {
                        st = W_H1;
                    }
                    break;
                }
                case W_CL:
                    rcmd = byte;
                    rcrc_calc = wifi_crc16(&byte, 1, rcrc_calc);
                    st = W_CH;
                    break;
                case W_CH:
                    rcmd |= (uint16_t)byte << 8;
                    rcrc_calc = wifi_crc16(&byte, 1, rcrc_calc);
                    st = W_LL;
                    break;
                case W_LL:
                    rlen = byte;
                    rcrc_calc = wifi_crc16(&byte, 1, rcrc_calc);
                    st = W_LH;
                    break;
                case W_LH:
                    rlen |= (uint16_t)byte << 8;
                    rcrc_calc = wifi_crc16(&byte, 1, rcrc_calc);
                    st = (rlen ? W_PL : W_KL);
                    break;
                case W_PL:
                    if (rgot < sizeof(pbuf)) pbuf[rgot] = byte;
                    rcrc_calc = wifi_crc16(&byte, 1, rcrc_calc);
                    if (++rgot >= rlen) st = W_KL;
                    break;
                case W_KL:
                    rcrc_recv = byte;
                    st = W_KH;
                    break;
                case W_KH: {
                    rcrc_recv |= (uint16_t)byte << 8;
                    if (rcrc_recv == rcrc_calc) {
                        if (is_resp && rcmd == cmd) {
                            // matching ack for our command
                            if (resp && resp_len) {
                                uint16_t cpy = MIN(rlen, *resp_len);
                                memcpy(resp, pbuf, cpy);
                                *resp_len = cpy;
                            }
                            return PM3_SUCCESS;
                        }
                        if (!is_resp && rcmd == BWM_CMD_CMD_ERROR && rlen >= 2) {
                            uint16_t failed_cmd = (uint16_t)pbuf[0] | ((uint16_t)pbuf[1] << 8);
                            if (failed_cmd == cmd) {
                                int32_t esp_err = 0;
                                if (rlen >= 6) {
                                    esp_err = (int32_t)((uint32_t)pbuf[2] | ((uint32_t)pbuf[3] << 8) |
                                                         ((uint32_t)pbuf[4] << 16) | ((uint32_t)pbuf[5] << 24));
                                }
                                Dbprintf("[bwm-wifi] cmd 0x%04x failed, esp_err=0x%08x", (unsigned)cmd, (unsigned)esp_err);
                                return PM3_EFAILED;
                            }
                        }
                    }
                    st = W_H1;
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------

static int step(uint16_t cmd, const uint8_t *req, uint16_t rl,
                uint8_t *resp, uint16_t *resp_len, uint32_t to, const char *what) {
    int r = bwm_cmd(cmd, req, rl, resp, resp_len, to);
    if (r != PM3_SUCCESS) {
        Dbprintf("[bwm-wifi] %s failed (%d)", what, r);
    }
    return r;
}

int bwm_wifi_forward_up(const char *ssid, const char *password,
                        const char *hostname, uint16_t tcp_port, uint32_t *ip_out) {
    int r;
    uint8_t b;
    const uint32_t TO = 2000;   // per-config-step timeout (ms)

    // 0) force a clean slate. If the BWM is already in forward mode (persisted
    //    NVS state or a failed boot auto-connect), SET_TO_WIFI_FORWARD_MODE
    //    takes an "already forward, skip init" path and leaves the WiFi context
    //    uninitialized, which then rejects SET_SSID. Disabling first guarantees
    //    the next forward-mode command runs the init path. Best-effort: the
    //    disable handler always acks, so ignore its result.
    (void)bwm_cmd(BWM_CMD_SET_TO_WIFI_DISABLE_MODE, NULL, 0, NULL, NULL, TO);

    // 1) forwarding target = TCP server
    b = BWM_WIFI_FORWARD_TCP_SERVER;
    if ((r = step(BWM_CMD_SET_TO_WIFI_FORWARD_MODE, &b, 1, NULL, NULL, TO, "set forward mode")) != PM3_SUCCESS) return r;

    // 2) STA credentials
    if ((r = step(BWM_CMD_SET_WIFI_CONNECT_CFG_SSID, (const uint8_t *)ssid, (uint16_t)strlen(ssid), NULL, NULL, TO, "set ssid")) != PM3_SUCCESS) return r;
    if ((r = step(BWM_CMD_SET_WIFI_CONNECT_CFG_PWD, (const uint8_t *)password, (uint16_t)strlen(password), NULL, NULL, TO, "set password")) != PM3_SUCCESS) return r;

    // 3) TCP listen port (LE)
    uint8_t p2[2] = { (uint8_t)(tcp_port & 0xFF), (uint8_t)(tcp_port >> 8) };
    if ((r = step(BWM_CMD_SET_TCP_SERVER_PORT, p2, 2, NULL, NULL, TO, "set tcp port")) != PM3_SUCCESS) return r;

    // 3b) DHCP hostname - must be set before the join so it rides the DHCP request
    if ((r = step(BWM_CMD_SET_WIFI_CFG_HOST_NAME, (const uint8_t *)hostname, (uint16_t)strlen(hostname), NULL, NULL, TO, "set hostname")) != PM3_SUCCESS) return r;

    // 4) join the AP and wait for it to finish (up to ~15s)
    if ((r = step(BWM_CMD_START_WIFI_CONNECT_TASK, NULL, 0, NULL, NULL, TO, "start connect")) != PM3_SUCCESS) return r;
    uint8_t secs = 25;   // iPhone/phone hotspots can be slow to become joinable
    uint8_t wr[2];
    uint16_t wl = sizeof(wr);
    if ((r = step(BWM_CMD_WAIT_FOR_WIFI_CONNECT_TASK, &secs, 1, wr, &wl, 30000, "wait connect")) != PM3_SUCCESS) return r;

    // 5) wait for DHCP. The STA reports "connected" on association, before it
    //    has an address, so poll GET_IP until a non-zero IP appears. Phone
    //    hotspots can take several seconds to hand one out.
    uint32_t ip = 0;
    uint32_t dhcp_start = GetTickCount();
    for (;;) {
        uint8_t ipb[12];
        uint16_t il = sizeof(ipb);
        if ((bwm_cmd(BWM_CMD_GET_WIFI_CFG_IP_ADDR, NULL, 0, ipb, &il, TO) == PM3_SUCCESS) && (il >= 4)) {
            ip = (uint32_t)ipb[0] | ((uint32_t)ipb[1] << 8) | ((uint32_t)ipb[2] << 16) | ((uint32_t)ipb[3] << 24);
            if (ip != 0) {
                break;
            }
        }
        if (GetTickCountDelta(dhcp_start) > BWM_WIFI_DHCP_WAIT_MS) {
            break;   // gave up waiting for a lease
        }
        uint32_t t = GetTickCount();   // brief pause before re-polling
        while (GetTickCountDelta(t) < BWM_WIFI_DHCP_POLL_MS) { }
    }
    if (ip == 0) {
        Dbprintf("[bwm-wifi] joined but no IP after DHCP wait (result=%u err=%u)", wr[0], wr[1]);
        return PM3_EFAILED;
    }

    // 6) start the TCP server (binds the STA interface now that it has an IP)
    if ((r = step(BWM_CMD_START_TCP_SERVER, NULL, 0, NULL, NULL, TO, "start tcp server")) != PM3_SUCCESS) return r;

    *ip_out = ip;
    return PM3_SUCCESS;
}

int bwm_wifi_forward_status(uint8_t *state, uint32_t *ip_out) {
    const uint32_t TO = 2000;
    *ip_out = 0;
    *state  = BWM_WIFI_STATE_OFF;

    // Ask the ESP for the WiFi connect state (not just the IP): this tells apart
    // off / disconnected / connecting / connected, which the IP alone cannot.
    uint8_t st = 0;
    uint16_t sl = sizeof(st);
    int r = bwm_cmd(BWM_CMD_GET_WIFI_CONNECT_STATUS, NULL, 0, &st, &sl, TO);
    if (r == PM3_ETIMEOUT) {
        return r;                        // BWM genuinely not responding
    }
    if (r != PM3_SUCCESS || sl < 1) {
        *state = BWM_WIFI_STATE_OFF;      // BWM answered; WiFi subsystem is off (BLE-only)
        return PM3_SUCCESS;
    }
    *state = st;                         // 0 down, 1 connecting, 2 connected, 3 reconnecting, 4 stopped

    // Only chase an IP when actually connected.
    if (st == BWM_WIFI_STATE_CONNECTED) {
        uint8_t ipb[12];
        uint16_t il = sizeof(ipb);
        if ((bwm_cmd(BWM_CMD_GET_WIFI_CFG_IP_ADDR, NULL, 0, ipb, &il, TO) == PM3_SUCCESS) && (il >= 4)) {
            *ip_out = (uint32_t)ipb[0] | ((uint32_t)ipb[1] << 8) | ((uint32_t)ipb[2] << 16) | ((uint32_t)ipb[3] << 24);
        }
    }
    return PM3_SUCCESS;
}

int bwm_wifi_forward_down(void) {
    // The ESP tears down the STA + TCP server and persists to NVS BEFORE it acks,
    // and its command task blocks during the teardown - so that ack can outlast
    // any timeout or be dropped. A plain ack-wait therefore reports failure on a
    // disable that actually worked. Instead: fire the disable, then CONFIRM by
    // polling the connect status. Once WiFi is gone the status query returns a
    // non-timeout error (the subsystem is down) - that is our proof of success.
    (void)bwm_cmd(BWM_CMD_SET_TO_WIFI_DISABLE_MODE, NULL, 0, NULL, NULL, 3000);

    uint32_t t0 = GetTickCount();
    while (GetTickCountDelta(t0) < 12000) {   // overall cap
        uint8_t st = 0;
        uint16_t sl = sizeof(st);
        int q = bwm_cmd(BWM_CMD_GET_WIFI_CONNECT_STATUS, NULL, 0, &st, &sl, 500);
        // ETIMEOUT while the ESP is busy tearing down -> keep waiting.
        // SUCCESS with a state -> still up mid-teardown -> keep waiting.
        // any other (EFAILED etc.) -> BWM answered but WiFi is gone -> disabled.
        if (q != PM3_SUCCESS && q != PM3_ETIMEOUT) {
            return PM3_SUCCESS;
        }
        SpinDelay(300);
    }
    return PM3_ETIMEOUT;
}

// ---------------------------------------------------------------------------
// ESP OTA forwarders. Each maps a host request to one ESP OTA app_com command.
// esp_ota_begin erases the target partition and esp_ota_end finalizes + sets the
// boot slot, so those get generous timeouts.
// ---------------------------------------------------------------------------
// Read the ESP's running firmware version string (APP_CMD_GET_VERSION_INFO).
int bwm_esp_get_version(uint8_t *buf, uint16_t *buflen) {
    return bwm_cmd(BWM_CMD_GET_VERSION_INFO, NULL, 0, buf, buflen, 3000);
}

int bwm_esp_ota_begin(uint32_t total_size) {
    // SILENCE ESP log forwarding for the OTA. With it on, the ESP's background
    // log broadcasts (WiFi/coex/BLE) interleave with the per-chunk acks across
    // the thousands of round-trips; one landing in an ack window drops that
    // chunk's reply -> random PM3_ETIMEOUT. Restored in bwm_esp_ota_end().
    // Best-effort: ignore failure.
    uint8_t off = 0;
    (void)bwm_cmd(BWM_CMD_LOG_FORWARD_ENABLE, &off, 1, NULL, NULL, 500);

    // Stop BLE so NimBLE is not hitting flash (NVS / auto-suspend) while we
    // erase and program the OTA slot. WiFi stays as-is: tearing it down here
    // is slow and the USB OTA path does not need it off.
    (void)bwm_cmd(BWM_CMD_STOP_BLE_SPP, NULL, 0, NULL, NULL, 2000);

    // Do NOT retune the UART here. Version already proved the current baud
    // works; dropping 921600 -> 460800/460000 can leave the ESP on one rate
    // and the AT32 on the other, after which every OTA_BEGIN times out.

    uint8_t p[4] = {
        (uint8_t)(total_size & 0xFF),         (uint8_t)((total_size >> 8) & 0xFF),
        (uint8_t)((total_size >> 16) & 0xFF), (uint8_t)((total_size >> 24) & 0xFF)
    };
    return bwm_cmd(BWM_CMD_OTA_BEGIN, p, sizeof(p), NULL, NULL, BWM_OTA_BEGIN_TIMEOUT_MS);
}

int bwm_esp_ota_write(const uint8_t *data, uint16_t len) {
    // Documented OTA has no resume/offset: the payload is the raw chunk, written
    // sequentially. A dropped chunk cannot be re-sent (it would double-write and
    // fail the OTA_END size check) - recovery is to restart the whole OTA, which
    // the client does. Keep a generous timeout so a slow flash write is not
    // mistaken for a drop.
    return bwm_cmd(BWM_CMD_OTA_WRITE, data, len, NULL, NULL, BWM_OTA_WRITE_TIMEOUT_MS);
}

int bwm_esp_ota_end(void) {
    int r = bwm_cmd(BWM_CMD_OTA_END, NULL, 0, NULL, NULL, 20000);
    uint8_t on = 1;
    (void)bwm_cmd(BWM_CMD_LOG_FORWARD_ENABLE, &on, 1, NULL, NULL, 500);
    (void)bwm_cmd(BWM_CMD_START_BLE_SPP, NULL, 0, NULL, NULL, 2000);
    return r;
}

int bwm_esp_ota_abort(void) {
    // Restore logs + BLE. Leave the UART baud alone (see begin). The ESP's
    // incomplete OTA state is discarded by the next BEGIN.
    uint8_t on = 1;
    (void)bwm_cmd(BWM_CMD_LOG_FORWARD_ENABLE, &on, 1, NULL, NULL, 500);
    (void)bwm_cmd(BWM_CMD_START_BLE_SPP, NULL, 0, NULL, NULL, 2000);
    return PM3_SUCCESS;
}

int bwm_esp_reboot(void) {
    // The ESP acks then calls esp_restart() - the ack itself may or may not
    // make it back before the UART goes away, so treat a timeout here as a
    // benign race, not a failure: the reboot was still requested.
    int r = bwm_cmd(BWM_CMD_REBOOT, NULL, 0, NULL, NULL, 3000);
    return (r == PM3_ETIMEOUT) ? PM3_SUCCESS : r;
}
