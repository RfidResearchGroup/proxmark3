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
// ISO 15693 type prototyping
//-----------------------------------------------------------------------------

#ifndef _ISO15_H_
#define _ISO15_H_

#include "common.h"
typedef struct {
    uint8_t uid[8];
    uint8_t uidlen;
    uint8_t atqb[7];
    uint8_t chipid;
    uint8_t cid;
} PACKED iso15_card_select_t;

typedef enum ISO15_COMMAND {
    ISO15_CONNECT = (1 << 0),
    ISO15_NO_DISCONNECT = (1 << 1),
    ISO15_RAW = (1 << 2),
    ISO15_APPEND_CRC = (1 << 3),
    ISO15_HIGH_SPEED = (1 << 4),
    ISO15_READ_RESPONSE = (1 << 5)
} iso15_command_t;


#endif // _ISO15_H_
