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

#define ISO15693_UID_LENGTH      8
#define ISO15693_ATQB_LENGTH     7

// on-disk length of a raw iso15_tag_t dump, per struct revision. A .bin is
// identified by its length alone, so every revision needs a constant here.
#define ISO15_V4_DUMP_LENGTH     2235   // u8  pagesCount, locks[0xA0]
#define ISO15_V5_DUMP_LENGTH     2332   // u16 pagesCount, locks[0x100]

typedef struct {
    uint8_t uid[ISO15693_UID_LENGTH];
    uint8_t uidlen;
    uint8_t atqb[ISO15693_ATQB_LENGTH];
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

// 16-slot inventory support
#define ISO15693_MAX_SLOTS          16
#define ISO15693_MAX_SLOT_RESPONSE  128

typedef struct {
    uint8_t status;  // 0=no response (timeout), 1=valid response, 2=collision/error
    uint8_t len;     // response data length for this slot
} PACKED iso15_slot_result_t;

typedef struct {
    uint8_t slot_count;                           // 1 or 16
    iso15_slot_result_t slots[ISO15693_MAX_SLOTS]; // per-slot metadata
    uint8_t data[];                                // concatenated response bytes
} PACKED iso15_inventory_response_t;

// Two independent caps, not one expressed twice.
//
//   MAX_PAGES sizes locks[], one byte per page. 0x100 is the real ceiling: a tag
//             reports its block count in a single byte of the Get System Info
//             response, so 256 blocks is as many as there can be.
//   MAX_SIZE  sizes data[], the whole payload.
//
// The product is what actually has to fit, and every load checks it:
//
//     (pagesCount * bytesPerPage) > ISO15693_TAG_MAX_SIZE   -> rejected
//
// so 2048 bytes covers 0x100 pages of 8, or 64 pages of 32 (256 bits), but not
// 0x100 pages of 16 or more. Tags with blocks larger than 8 bytes are therefore
// only supported up to 2048 bytes of memory. Raising this means raising
// CARD_MEMORY_SIZE too -- iso15_tag_t lives in BigBuf EM on the ARM.
#define ISO15693_TAG_MAX_PAGES   0x100  // in pages, one lock byte each
#define ISO15693_TAG_MAX_SIZE    2048   // in bytes, total payload

typedef struct {
    uint8_t uid[8];
    uint8_t dsfid;
    bool dsfidLock;
    uint8_t afi;
    bool afiLock;
    uint8_t bytesPerPage;
    uint16_t pagesCount;
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

// The previous on-disk layout. Kept so a v4 dump can be converted to the
// current struct instead of being rejected for having the wrong length.
// Note the state enum: v4 carries TAG_STATE_ACTIVATED, so the enumerators
// match iso15_tag_t one for one and `state` copies straight across.
typedef struct {
    uint8_t uid[8];
    uint8_t dsfid;
    bool dsfidLock;
    uint8_t afi;
    bool afiLock;
    uint8_t bytesPerPage;
    uint8_t pagesCount;
    uint8_t ic;
    uint8_t locks[0xA0];
    uint8_t data[ISO15693_TAG_MAX_SIZE];
    uint8_t random[2];
    uint8_t privacyPasswd[4];
    enum {
        TAGv4_STATE_NO_FIELD,
        TAGv4_STATE_READY,
        TAGv4_STATE_ACTIVATED, // useless ?
        TAGv4_STATE_SELECTED,
        TAGv4_STATE_SILENCED
    } state;
    bool expectFast;
    bool expectFsk;
} PACKED iso15_tag_v4_t;

#endif // _ISO15_H_
