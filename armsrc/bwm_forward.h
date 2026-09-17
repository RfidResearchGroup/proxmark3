//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// Proxmark5 Battery Wireless Module (BWM) transport shim.
//
// The BWM (ESP32-C2, RfidResearchGroup/Proxmark5_BWM_esp32) bridges the AT32
// host <-> BLE/WiFi. Its ESP<->AT32 UART link does NOT carry raw PacketCommandNG;
// it uses a framed "app_com" protocol. Transparent host<->wireless traffic rides
// inside that framing:
//
//   AT32 -> ESP (our reply, toward wireless host):
//       [0x7C 0xC7] cmd=APP_CMD_SEND_FORWARD_DATA(5000) len(LE) payload CRC16(LE)
//   ESP -> AT32 (command from wireless host):
//       [0xD2 0xD3] cmd=APP_BROADCAST_DATA_FORWARD(8089) len(LE) payload CRC16(LE)
//
//   Frame = HDR1 HDR2 | CMD(LE16) | LEN(LE16) | PAYLOAD[LEN] | CRC(LE16)
//   CRC   = CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF, MSB-first, no xorout)
//           over HDR..PAYLOAD. (NOT compute_crc(CRC_14443_A) - different CRC.)
//
// This shim wraps outgoing NG/OLD reply bytes into a SEND_FORWARD_DATA frame and
// de-frames incoming DATA_FORWARD frames back into a raw NG byte stream, so the
// stock reply_ng()/receive_ng() paths work unchanged over the BWM link.
//
// Enabled by -DWITH_BWM_FORWARD (implies WITH_FPC_USART_HOST).
//-----------------------------------------------------------------------------

#ifndef __BWM_FORWARD_H
#define __BWM_FORWARD_H

#include "common.h"

// app_com framing constants (verified against BWM firmware app_cmd_uart.[ch] /
// app_com_defs.h).
#define BWM_HDR_HOST_CMD_1     0x7C   // AT32 -> ESP  (host command)
#define BWM_HDR_HOST_CMD_2     0xC7
#define BWM_HDR_SLAVE_BCAST_1  0xD2   // ESP  -> AT32 (slave broadcast)
#define BWM_HDR_SLAVE_BCAST_2  0xD3
#define BWM_HDR_SLAVE_RESP_1   0x2D   // ESP  -> AT32 (slave response; forward-frame ack)
#define BWM_HDR_SLAVE_RESP_2   0x3D

#define BWM_CMD_SEND_FORWARD_DATA   5000   // host cmd: payload -> BLE/WiFi endpoint
#define BWM_CMD_DATA_FORWARD        8089   // slave bcast: payload came from endpoint
#define BWM_CMD_LINK_STATE          8092   // slave bcast: [ble u8][wifi u8], 1 = a client is connected
// System command: set the ESP<->AT32 UART baud (app_com_defs.h, enum @1000).
// SET is a HOST_CMD carrying u32 LE baud; the ESP replies with a SLAVE_RESP
// echoing this cmd (len 0) at the OLD baud, then commits to the new baud.
#define BWM_CMD_SET_UART_BAUD       1011
#define BWM_CMD_GET_UART_BAUD       1009   // read back the ESP's live baud (negotiation verify)
// Flow control (byte window). The ESP acks each forward frame with a SLAVE_RESP
// echoing SEND_FORWARD_DATA once it has taken the frame out of its UART ring
// (module firmware from the companion PR; older firmware acks after the radio,
// which also works, just slower), and acks come back in order, so un-acked bytes
// bound what that ring holds. The window is sized to the ring (UART_RX_BUF_SIZE
// in the BWM firmware's app_cmd_uart.h): keep BWM_ESP_UART_RX_BUF equal to it.
// Frames run ~30 B to ~2.1 KB, hence bytes. A frame the ESP cannot deliver is
// answered with CMD_ERROR instead and leaves the window the same way. When acks
// stall on a full window the gate waits BWM_FC_ACK_TIMEOUT_MS, then forgets just
// enough of the oldest frames to send this one. Acks are counted, not matched:
// a lost or late ack shifts the window by a frame until it drains at idle.
#define BWM_ESP_UART_RX_BUF         12288
#define BWM_FC_BYTES                (BWM_ESP_UART_RX_BUF - 1024)   // in-flight bytes allowed; slack for the ESP's FIFO and parser lag
#define BWM_FC_MAX_FRAMES           64     // depth of the in-flight length FIFO; also caps tiny frames in flight
#ifndef BWM_FC_ACK_TIMEOUT_MS
// Hard cap (ms) on how long a forward write may block the main loop waiting for
// acks. A spin COUNT was unbounded in wall-clock time and could hang the main
// loop long enough that the client gives up and the device looks dead (USB still
// enumerates on interrupts). Time-bounded => the main loop is always serviced.
// A full window that stays full this long means the ESP is stuck on the radio
// (a phone scanning stalls BLE for a few hundred ms); every timeout then leaks
// one frame into a full ring, so wait long enough for the usual stalls to pass.
#define BWM_FC_ACK_TIMEOUT_MS       200    // safety valve: proceed if acks stall, never hard-hang
#endif // safety valve: give up waiting for credit (avoid hard hang)

#define BWM_CRC16_POLY  0x1021
#define BWM_CRC16_INIT  0xFFFF

// Wrap `len` raw reply bytes (a whole PacketResponseNG/OLD frame) into one
// SEND_FORWARD_DATA app_com frame and write it synchronously to the FPC USART.
// Returns PM3_SUCCESS or the underlying usart error. Drop-in for the FPC
// usart_writebuffer_sync() call in reply_ng_internal()/reply_old().
int bwm_fwd_writebuffer_sync(const uint8_t *data, size_t len);

// De-framed read: returns up to `len` raw NG bytes recovered from inbound
// DATA_FORWARD frames, blocking-with-timeout exactly like usart_read_ng().
// Drop-in for usart_read_ng() as the receive_ng() read callback.
uint32_t bwm_read_ng(uint8_t *data, size_t len);

// >0 when raw bytes are waiting on the FPC USART (gate for receive_ng()).
uint16_t bwm_fwd_rxdata_available(void);

// Flow-control diagnostics since boot (hw status at debug level).
typedef struct {
    uint32_t frames;            // forward frames sent
    uint32_t acks;              // SLAVE_RESP acks seen
    uint32_t errors;            // CMD_ERROR answers seen (undeliverable frames)
    uint32_t timeouts;          // gate waited BWM_FC_ACK_TIMEOUT_MS on a full window
    uint32_t forgotten;         // frames the gate stopped counting on those timeouts
    uint32_t bytes_max;         // peak bytes in flight
    uint8_t  in_flight_frames;  // now
    uint32_t in_flight_bytes;   // now
} bwm_fc_stats_t;
void bwm_fwd_fc_stats(bwm_fc_stats_t *out);

// True while the ESP reports a client on BLE or on its WiFi TCP server (the
// LINK_STATE broadcast, sent on change only). ESP firmware without it: never true.
bool bwm_fwd_link_connected(void);
// Seed the BLE half from a status query at boot (a client can outlive an AT32 reset).
void bwm_fwd_link_seed_ble(bool connected);

// Bring the ESP<->AT32 UART to `target` baud: adopt it if the ESP is already
// there (its baud survives an AT32-only reset), else negotiate up via app_com
// cmd 1011 and re-init UART4 to match. Returns true if the link runs at
// `target`; false (left at the boot baud) if no ESP answered or the switch
// could not be verified. Call once after bwm_uart_init().
bool bwm_fwd_negotiate_baud(uint32_t target);

#endif // __BWM_FORWARD_H
