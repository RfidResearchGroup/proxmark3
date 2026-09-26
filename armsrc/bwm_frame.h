//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// BWM app_com de-framer shared by the PM5 OS and bootrom.
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
//-----------------------------------------------------------------------------
#ifndef BWM_FRAME_H
#define BWM_FRAME_H

#include "common.h"
#include "pm3_cmd.h"

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
#define BWM_CMD_CMD_ERROR           8091   // slave bcast: command error report
#define BWM_CMD_LINK_STATE          8092   // slave bcast: [ble u8][wifi u8], 1 = a client is connected
// System command: set the ESP<->AT32 UART baud (app_com_defs.h, enum @1000).
// SET is a HOST_CMD carrying u32 LE baud; the ESP replies with a SLAVE_RESP
// echoing this cmd (len 0) at the OLD baud, then commits to the new baud.
#define BWM_CMD_SET_UART_BAUD       1011
#define BWM_CMD_GET_UART_BAUD       1009   // read back the ESP's live baud (negotiation verify)

#define BWM_CRC16_POLY  0x1021
#define BWM_CRC16_INIT  0xFFFF

#ifdef AS_BOOTROM
#ifndef BWM_FRAME_RX_MAX
#define BWM_FRAME_RX_MAX  576
#endif
#ifndef BWM_FIFO_SZ
#define BWM_FIFO_SZ       1024
#endif
#else
#ifndef BWM_FRAME_RX_MAX
#define BWM_FRAME_RX_MAX  (PM3_CMD_DATA_SIZE + 64)   // NG/OLD frame ceiling
#endif
#ifndef BWM_FIFO_SZ
#define BWM_FIFO_SZ       2048            // >= one full NG frame's payload
#endif
#endif

uint16_t bwm_crc16(const uint8_t *data, size_t len, uint16_t crc);

void bwm_frame_reset(void);
void bwm_frame_feed(uint8_t byte);

uint16_t bwm_fifo_count(void);
uint8_t bwm_fifo_pop(void);

int16_t bwm_frame_inflight(void);
void bwm_frame_inflight_inc(void);
void bwm_frame_inflight_zero(void);

bool bwm_frame_take_fwd_ack(void);
bool bwm_frame_baud_ack(void);
void bwm_frame_clear_baud_ack(void);
bool bwm_frame_getbaud_ack(void);
void bwm_frame_clear_getbaud_ack(void);

size_t bwm_frame_build(uint16_t cmd, const uint8_t *payload, uint16_t len,
                       uint8_t *out, size_t outsz);

#ifndef AS_BOOTROM
void bwm_fwd_on_frame_ack(void);
void bwm_fwd_on_frame_error(void);
void bwm_fwd_on_link_state(uint8_t ble, uint8_t wifi);
#endif

#endif
