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
// MIFARE Classic dump access for the transit parsers, 1K/4K block layout
//-----------------------------------------------------------------------------

#ifndef PARSETRANSITMFC_H__
#define PARSETRANSITMFC_H__

#include "common.h"

#define TRANSIT_MFC_BLOCK_SIZE  16

static inline size_t transit_mfc_first_block(uint8_t sector) {
    return (sector < 32) ? ((size_t)sector * 4) : (128 + ((size_t)(sector - 32) * 16));
}

static inline uint8_t transit_mfc_blocks_in_sector(uint8_t sector) {
    return (sector < 32) ? 4 : 16;
}

// Data block of a sector, NULL when the dump does not reach it
static inline const uint8_t *transit_mfc_block(const uint8_t *dump, size_t dumplen, uint8_t sector, uint8_t blk) {
    if (dump == NULL || blk >= transit_mfc_blocks_in_sector(sector)) {
        return NULL;
    }
    size_t off = (transit_mfc_first_block(sector) + blk) * TRANSIT_MFC_BLOCK_SIZE;
    if (off + TRANSIT_MFC_BLOCK_SIZE > dumplen) {
        return NULL;
    }
    return dump + off;
}

// Key A or B from the sector trailer, as a 48 bit big endian number, 0 when out of range
static inline uint64_t transit_mfc_key(const uint8_t *dump, size_t dumplen, uint8_t sector, bool key_b) {
    const uint8_t *t = transit_mfc_block(dump, dumplen, sector, transit_mfc_blocks_in_sector(sector) - 1);
    if (t == NULL) {
        return 0;
    }
    const uint8_t *k = t + (key_b ? 10 : 0);
    uint64_t v = 0;
    for (uint8_t i = 0; i < 6; i++) {
        v = (v << 8) | k[i];
    }
    return v;
}

// True when key A or key B of the sector is the given one
static inline bool transit_mfc_has_key(const uint8_t *dump, size_t dumplen, uint8_t sector, uint64_t key) {
    return (transit_mfc_key(dump, dumplen, sector, false) == key) || (transit_mfc_key(dump, dumplen, sector, true) == key);
}

// Writes a key into a sector trailer, for building self test dumps
static inline void transit_mfc_set_key(uint8_t *dump, size_t dumplen, uint8_t sector, bool key_b, uint64_t key) {
    size_t off = (transit_mfc_first_block(sector) + transit_mfc_blocks_in_sector(sector) - 1) * TRANSIT_MFC_BLOCK_SIZE;
    if (off + TRANSIT_MFC_BLOCK_SIZE > dumplen) {
        return;
    }
    uint8_t *k = dump + off + (key_b ? 10 : 0);
    for (uint8_t i = 0; i < 6; i++) {
        k[i] = (uint8_t)(key >> (40 - (8 * i)));
    }
}

#endif
