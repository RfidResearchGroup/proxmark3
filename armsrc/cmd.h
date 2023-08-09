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

#ifndef _PROXMARK_CMD_H_
#define _PROXMARK_CMD_H_

#include "common.h"
#include "pm3_cmd.h"

// Flags to tell where to add CRC on sent replies
extern bool g_reply_with_crc_on_usb;
extern bool g_reply_with_crc_on_fpc;
// "Session" flag, to tell via which interface next msgs should be sent: USB and/or FPC USART
extern bool g_reply_via_fpc;
extern bool g_reply_via_usb;

int reply_old(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, const void *data, size_t len);
int reply_ng(uint16_t cmd, int16_t status, const uint8_t *data, size_t len);
int reply_mix(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, const void *data, size_t len);
int receive_ng(PacketCommandNG *rx);

#endif // _PROXMARK_CMD_H_

