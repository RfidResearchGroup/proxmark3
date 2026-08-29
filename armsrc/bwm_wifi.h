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
int bwm_wifi_forward_status(uint8_t *connected, uint32_t *ip_out);

#endif
