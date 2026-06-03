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
// MIFARE Application Directory (MAD) functions
//-----------------------------------------------------------------------------

#ifndef _MAD_H_
#define _MAD_H_

#include "common.h"

// ---------------------------------------------------------------------------
// On-card layout structures
// ---------------------------------------------------------------------------

// AID as stored on the card: low byte first, then high byte.
typedef struct PACKED {
    uint8_t lo;
    uint8_t hi;
} mad_aid_t;

static inline uint16_t mad_aid_get(const mad_aid_t *a) {
    return (a->hi << 8) | a->lo;
}

static inline void mad_aid_set(mad_aid_t *a, uint16_t val) {
    a->lo = val & 0xFF;
    a->hi = (val >> 8) & 0xFF;
}

// MAD1 lives in sector 0 (blocks 0-3, 64 bytes total).
typedef struct PACKED {
    uint8_t manufacturer[16];
    uint8_t crc;
    uint8_t info;
    mad_aid_t aid[15];      // sectors 1-15
    uint8_t key_a[6];
    uint8_t access_bits[3];
    uint8_t gpb;
    uint8_t key_b[6];
} mad1_sector_t;

// MAD2 lives in sector 0x10 (blocks 0-3 of that sector, 64 bytes total).
typedef struct PACKED {
    uint8_t crc;
    uint8_t info;
    mad_aid_t aid[23];      // sectors 17-39
    uint8_t key_a[6];
    uint8_t access_bits[3];
    uint8_t gpb;
    uint8_t key_b[6];
} mad2_sector_t;

// AID counts per MAD version
#define MAD1_AID_COUNT  15
#define MAD2_AID_COUNT  23

// Maximum decoded AID entries: 15 (MAD1) + 1 (MAD2 marker) + 23 (MAD2) = 39
#define MAD_MAX_AID_ENTRIES  (MAD1_AID_COUNT + 1 + MAD2_AID_COUNT)

// Wrapper for a raw sector buffer passed with explicit size.
typedef struct {
    const uint8_t *data;
    size_t len;
} mad_sector_t;

// Output of MADDecode.
typedef struct {
    uint16_t entries[MAD_MAX_AID_ENTRIES];
    size_t count;
    bool has_mad2;
    uint8_t info_byte;
    uint8_t gpb;
    bool crc1_ok;
    bool crc2_ok;
} mad_t;

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

#define MADComputeCRC(m) CRC8Mad((uint8_t *)&(m)->info, sizeof((m)->info) + sizeof((m)->aid))

int MADCheck(const mad_sector_t *sector0, const mad_sector_t *sector16, bool verbose, bool *haveMAD2);
int MADDecode(const mad_sector_t *sector0, const mad_sector_t *sector16, mad_t *out, bool swapmad, bool override);
int MAD1DecodeAndPrint(const mad_sector_t *sector, bool swapmad, bool verbose, bool *haveMAD2);
int MAD2DecodeAndPrint(const mad_sector_t *sector, bool swapmad, bool verbose);
int MADDFDecodeAndPrint(uint32_t short_aid, bool verbose);
int MADCardHolderInfoDecode(const uint8_t *data, size_t datalen, bool verbose);
void MADPrintHeader(void);
bool HasMADKey(const mad_sector_t *sector);
int DetectHID(const mad_sector_t *sector, uint16_t manufacture);
int convert_mad_to_arr(const uint8_t *in, size_t ilen, uint8_t *out, size_t *olen, size_t olen_max, bool override);

#endif // _MAD_H_
