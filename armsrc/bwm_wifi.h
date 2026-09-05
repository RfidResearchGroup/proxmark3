//-----------------------------------------------------------------------------
// BWM WiFi bring-up (PM5 / AT32 side).
//
// Drives the BWM ESP32 into STA + TCP-server forward mode over the existing
// app_com UART4 link, so the pm3 client can connect with `tcp:<bwm-ip>:<port>`.
// This is the request/response counterpart to bwm_forward's transparent path:
// it is used at setup time, when no PM3 traffic is being forwarded.
//-----------------------------------------------------------------------------
#ifndef BWM_WIFI_H
#define BWM_WIFI_H

#include "common.h"

// app_com command codes (authoritative, from BWM main/app_com_defs.h)
#define BWM_CMD_SET_TO_WIFI_DISABLE_MODE   2000   // no payload: tear down WiFi, back to BLE-only
#define BWM_CMD_SET_TO_WIFI_FORWARD_MODE   2001   // payload: 1 byte forward type (0 = TCP server)
#define BWM_CMD_GET_WIFI_CFG_IP_ADDR       2020   // resp: 3x uint32 LE {ip, netmask, gw}

// After association the STA reports "connected" before DHCP completes, so we
// poll GET_IP until a non-zero address appears (or give up).
#ifndef BWM_WIFI_DHCP_WAIT_MS
#define BWM_WIFI_DHCP_WAIT_MS   20000   // total time to wait for a DHCP lease
#endif
#ifndef BWM_WIFI_DHCP_POLL_MS
#define BWM_WIFI_DHCP_POLL_MS   500     // gap between GET_IP polls
#endif
#define BWM_CMD_SET_WIFI_CONNECT_CFG_SSID  2023   // payload: SSID bytes
#define BWM_CMD_SET_WIFI_CONNECT_CFG_PWD   2025   // payload: password bytes
#define BWM_CMD_SET_WIFI_CFG_HOST_NAME     2021   // payload: hostname bytes (no NUL)
#define BWM_CMD_START_WIFI_CONNECT_TASK    2048   // no payload
#define BWM_CMD_GET_WIFI_CONNECT_STATUS    2050   // resp: 1 byte status
#define BWM_CMD_WAIT_FOR_WIFI_CONNECT_TASK 2051   // payload: 1 byte timeout(s); resp: {result, err_reason}
#define BWM_CMD_START_TCP_SERVER           2201   // no payload
#define BWM_CMD_SET_TCP_SERVER_PORT        2205   // payload: uint16 LE port

#define BWM_WIFI_FORWARD_TCP_SERVER        0      // wifi_forward_type_t::WIFI_FORWARD_TCP_SERVER
#define BWM_CMD_CMD_ERROR                  8091   // slave bcast: command error report
#define BWM_CMD_LOG_FORWARD_ENABLE         1014   // payload: u8 (0=stop, non-zero=start)
#define BWM_CMD_LOG_MESSAGE                8090   // slave bcast: ESP_LOGx output (string)

// Low-level: send one app_com HOST_CMD and wait for its SLAVE_RESP.
// resp/resp_len may be NULL if no response payload is expected.
// Returns PM3_SUCCESS on the matching ack, PM3_EFAILED on a CMD_ERROR report,
// PM3_ETIMEOUT if no response within timeout_ms.
int bwm_cmd(uint16_t cmd, const uint8_t *req, uint16_t req_len,
            uint8_t *resp, uint16_t *resp_len, uint32_t timeout_ms);

// High-level: full STA-join + TCP-server bring-up. On success writes the
// BWM's IPv4 (host byte order, a in low byte) to *ip_out.
int bwm_wifi_forward_up(const char *ssid, const char *password,
                        const char *hostname, uint16_t tcp_port, uint32_t *ip_out);

// Tear down WiFi forward mode (disconnect STA + stop TCP server, back to
// BLE-only). Persisted on the BWM so it stays off across reboots.
int bwm_wifi_forward_down(void);

// Query current forward-mode connection state without reconfiguring. Writes the
// BWM IPv4 (host order, a in low byte; 0 if none) to *ip_out and 1/0 to
// *connected (true == has a DHCP lease). Returns PM3_EFAILED if the BWM/UART
// does not answer.
// WiFi connect state reported by --status (mirrors the ESP enum; 0xFF = off).
#define BWM_WIFI_STATE_DISCONNECTED  0
#define BWM_WIFI_STATE_CONNECTING    1
#define BWM_WIFI_STATE_CONNECTED     2
#define BWM_WIFI_STATE_RECONNECT     3
#define BWM_WIFI_STATE_STOPPED       4
#define BWM_WIFI_STATE_OFF           0xFF
int bwm_wifi_forward_status(uint8_t *state, uint32_t *ip_out);

// ESP OTA over the BWM UART link (no header/soldering): drives the ESP's own
// OTA commands to reflash a *working* BWM to a new ESP image.
#define BWM_CMD_OTA_BEGIN   1800   // req: u32 total size
#define BWM_CMD_OTA_WRITE   1801   // req: firmware chunk
#define BWM_CMD_OTA_END     1802   // no payload: finalize + set boot partition
// After a working OTA_END, the ESP has marked the new partition bootable but
// does not reboot on its own - REBOOT must be sent explicitly (DEV.md 12.8).
#define BWM_CMD_REBOOT      1803
// BEGIN erases (or finishes aborting) an OTA slot. A 1.8 MB erase on ESP32-C2
// commonly takes 20-40 s, so this must be well above the old 15 s race.
#ifndef BWM_OTA_BEGIN_TIMEOUT_MS
#define BWM_OTA_BEGIN_TIMEOUT_MS   60000
#endif
#ifndef BWM_OTA_WRITE_TIMEOUT_MS
#define BWM_OTA_WRITE_TIMEOUT_MS   20000
#endif
#define BWM_CMD_GET_VERSION_INFO   1000   // resp: running firmware version string
#define BWM_CMD_STOP_BLE_SPP       4022   // no payload: stop BLE during OTA (flash contention)
#define BWM_CMD_START_BLE_SPP      4021   // no payload: restore BLE after OTA
int bwm_esp_get_version(uint8_t *buf, uint16_t *buflen);
int bwm_esp_ota_begin(uint32_t total_size);
int bwm_esp_ota_write(const uint8_t *data, uint16_t len);
int bwm_esp_ota_end(void);
int bwm_esp_reboot(void);
int bwm_esp_ota_abort(void);

#endif
