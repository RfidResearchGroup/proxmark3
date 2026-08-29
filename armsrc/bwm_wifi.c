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

int bwm_cmd(uint16_t cmd, const uint8_t *req, uint16_t req_len,
            uint8_t *resp, uint16_t *resp_len, uint32_t timeout_ms) {

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
                        // a CMD_ERROR broadcast referencing our cmd -> failure.
                        // (payload carries the failing cmd; treat any error report
                        // that arrives while we wait as a failure of this step.)
                        if (!is_resp && rcmd == BWM_CMD_CMD_ERROR) {
                            return PM3_EFAILED;
                        }
                        // otherwise: some other frame (e.g. a stray broadcast) - ignore
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

int bwm_wifi_forward_status(uint8_t *connected, uint32_t *ip_out) {
    const uint32_t TO = 2000;
    uint32_t ip = 0;
    uint8_t ipb[12];
    uint16_t il = sizeof(ipb);
    int r = bwm_cmd(BWM_CMD_GET_WIFI_CFG_IP_ADDR, NULL, 0, ipb, &il, TO);
    if (r != PM3_SUCCESS) {
        return r;   // BWM / UART not responding
    }
    if (il >= 4) {
        ip = (uint32_t)ipb[0] | ((uint32_t)ipb[1] << 8) | ((uint32_t)ipb[2] << 16) | ((uint32_t)ipb[3] << 24);
    }
    *ip_out = ip;
    *connected = (ip != 0) ? 1 : 0;   // a lease == a usable connection
    return PM3_SUCCESS;
}

int bwm_wifi_forward_down(void) {
    // Single command: the BWM deinits the TCP server + disconnects the STA and
    // returns to BLE-only. It persists the disable mode to NVS.
    return step(BWM_CMD_SET_TO_WIFI_DISABLE_MODE, NULL, 0, NULL, NULL, 2000, "wifi disable");
}
