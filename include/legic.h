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
// LEGIC type prototyping
//-----------------------------------------------------------------------------

#ifndef _LEGIC_H_
#define _LEGIC_H_

#include "common.h"

//-----------------------------------------------------------------------------
// LEGIC
//-----------------------------------------------------------------------------
typedef struct {
    uint8_t uid[4];
    uint32_t tagtype;
    uint8_t cmdsize;
    uint8_t addrsize;
    uint16_t cardsize;
} PACKED legic_card_select_t;

typedef struct {
    uint16_t offset;
    uint16_t len;
    uint8_t iv;
    uint8_t data[];
} PACKED legic_packet_t;

// iceman: todo :  this should be packed

#endif // _LEGIC_H_
