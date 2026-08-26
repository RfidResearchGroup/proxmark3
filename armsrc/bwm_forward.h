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
#define BWM_HDR_SLAVE_RESP_1   0x2D   // ESP  -> AT32 (slave response, skipped here)
#define BWM_HDR_SLAVE_RESP_2   0x3D

#define BWM_CMD_SEND_FORWARD_DATA   5000   // host cmd: payload -> BLE/WiFi endpoint
#define BWM_CMD_DATA_FORWARD        8089   // slave bcast: payload came from endpoint

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

#endif // __BWM_FORWARD_H
