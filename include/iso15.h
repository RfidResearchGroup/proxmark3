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
    ISO15_READ_RESPONSE = (1 << 5),
    ISO15_LONG_WAIT = (1 << 6),
} iso15_command_t;

typedef struct {
    uint8_t flags;      // PM3 Flags - see iso15_command_t
    uint16_t rawlen;
    uint8_t raw[];      // First byte in raw,  raw[0] is ISO15693 protocol flag byte
} PACKED iso15_raw_cmd_t;

#define ISO15693_TAG_MAX_PAGES 64 // in page
#define ISO15693_TAG_MAX_SIZE 2048 // in byte (64 pages of 256 bits)

typedef struct {
    uint8_t uid[8];
    uint8_t dsfid;
    bool dsfidLock;
    uint8_t afi;
    bool afiLock;
    uint8_t bytesPerPage;
    uint8_t pagesCount;
    uint8_t ic;
    uint8_t locks[ISO15693_TAG_MAX_PAGES];
    uint8_t data[ISO15693_TAG_MAX_SIZE];
    uint8_t random[2];
    uint8_t privacyPasswd[4];
    enum {
        TAG_STATE_NO_FIELD,
        TAG_STATE_READY,
        TAG_STATE_ACTIVATED, // useless ?
        TAG_STATE_SELECTED,
        TAG_STATE_SILENCED
    } state;
    bool expectFast;
    bool expectFsk;
} PACKED iso15_tag_t;

#endif // _ISO15_H_
