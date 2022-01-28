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
// ISO 14443B type prototyping
//-----------------------------------------------------------------------------

#ifndef _ISO14B_H_
#define _ISO14B_H_

#include "common.h"
typedef struct {
    uint8_t uid[10];
    uint8_t uidlen;
    uint8_t atqb[7];
    uint8_t chipid;
    uint8_t cid;
} PACKED iso14b_card_select_t;

typedef struct {
    uint8_t uid[4];
    uint8_t pc;
    uint8_t fc;
} PACKED iso14b_cts_card_select_t;

typedef enum ISO14B_COMMAND {
    ISO14B_CONNECT = (1 << 0),
    ISO14B_DISCONNECT = (1 << 1),
    ISO14B_APDU = (1 << 2),
    ISO14B_RAW = (1 << 3),
    ISO14B_REQUEST_TRIGGER = (1 << 4),
    ISO14B_APPEND_CRC = (1 << 5),
    ISO14B_SELECT_STD = (1 << 6),
    ISO14B_SELECT_SR = (1 << 7),
    ISO14B_SET_TIMEOUT = (1 << 8),
    ISO14B_SEND_CHAINING = (1 << 9),
    ISO14B_SELECT_CTS = (1 << 10),
    ISO14B_CLEARTRACE = (1 << 11),
} iso14b_command_t;

typedef struct {
    uint16_t flags;      // the ISO14B_COMMAND enum
    uint32_t timeout;
    uint16_t rawlen;
    uint8_t raw[];
} PACKED iso14b_raw_cmd_t;


#define US_TO_SSP(x)   ( (uint32_t)((x) * 3.39) )
#define SSP_TO_US(x)   ( (uint32_t)((x) / 3.39) )

#define ETU_TO_SSP(x)  ((uint32_t)((x) * 32))
#define SSP_TO_ETU(x)  ((uint32_t)((x) / 32))

#define ETU_TO_US(x)   ((uint32_t)((((x) * 9440000) / 1000000) + 0.5))
#define US_TO_ETU(x)   ((uint32_t)(((x) * 1000000 / 9440000) + 0.5))

#endif // _ISO14B_H_
