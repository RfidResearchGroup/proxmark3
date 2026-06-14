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
#include "mifaredefault.h"

// MAD1/MAD2 AID counts per NXP AN10787
#define MAD1_NUM_AIDS  15
#define MAD2_NUM_AIDS  23

// MAD1: overlays bytes 16-47 of sector 0 (blocks 1-2, skipping manufacturer block 0)
typedef struct {
    uint8_t crc;
    uint8_t info;
    uint16_t aid[MAD1_NUM_AIDS];
} PACKED mad1_t;

// MAD2: overlays bytes 0-47 of sector 16 (blocks 0-2)
typedef struct {
    uint8_t crc;
    uint8_t info;
    uint16_t aid[MAD2_NUM_AIDS];
} PACKED mad2_t;

// Full MAD1 sector (sector 0): manufacturer block + MAD1 data + trailer
typedef struct {
    uint8_t manufacturer[MFBLOCK_SIZE];
    mad1_t mad;
    mf_trailer_t trailer;
} PACKED mad1_sector_t;

_Static_assert(sizeof(mad1_sector_t) == MFBLOCK_SIZE * 4, "mad1_sector_t must be 4 blocks");

// Full MAD2 sector (sector 16): MAD2 data + trailer
typedef struct {
    mad2_t mad;
    mf_trailer_t trailer;
} PACKED mad2_sector_t;

_Static_assert(sizeof(mad2_sector_t) == MFBLOCK_SIZE * 4, "mad2_sector_t must be 4 blocks");

// Access the i-th block of a sector struct as raw bytes
#define MF_SECTOR_BLOCK(sector, i) ((const uint8_t *)&(sector) + (i) * MFBLOCK_SIZE)

// Single decoded MAD entry: sector number + AID
typedef struct {
    uint8_t sector;
    uint16_t aid;
} mad_entry_t;

#define MAD_MAX_ENTRIES (MAD1_NUM_AIDS + MAD2_NUM_AIDS)

typedef struct {
    mad_entry_t entries[MAD_MAX_ENTRIES];
    size_t len;
} mad_entry_list_t;

// Card transport ops struct for MAD operations.
// Abstracts over MIFARE Classic (CRYPTO1) and MIFARE Plus (AES).
typedef struct {
    // Read a full sector (all blocks including trailer) into buf.
    // buf must hold mfNumBlocksPerSector(sector_no) * MFBLOCK_SIZE bytes.
    int (*read_sector)(uint8_t sector_no, uint8_t key_type,
                       const uint8_t *key, uint8_t *buf, bool verbose);

    // Write the data blocks (non-trailer) of a sector.
    // data points to (mfNumBlocksPerSector(sector_no) - 1) * MFBLOCK_SIZE bytes.
    int (*write_sector_data)(uint8_t sector_no, uint8_t key_type,
                             const uint8_t *key, const uint8_t *data, bool verbose);

    const uint8_t *mad_key;
    uint8_t mad_key_type;
    const uint8_t *app_key;
    uint8_t app_key_type;
    bool verbose;
} mad_ops_t;

// AID admin codes (0x0000-0x0005)
#define MAD_AID_ADMIN_MAX   5

// GPB (General Purpose Byte) bit masks
#define MAD_GPB_DA_MASK     0x80
#define MAD_GPB_MA_MASK     0x40
#define MAD_GPB_VER_MASK    0x03

// Info byte: lower 6 bits = card publisher sector pointer
#define MAD_INFO_MASK       0x3F

// Card holder info TLV encoding
#define MAD_TLV_LEN_MASK    0x3F
#define MAD_TLV_TYPE_SHIFT  6

int MADCheck(const mad1_sector_t *sector0, const mad2_sector_t *mad2, bool verbose, bool *haveMAD2);
int MADDecode(const mad1_sector_t *sector0, const mad2_sector_t *mad2, mad_entry_list_t *mad_list, bool swapmad, bool override);
int MAD1DecodeAndPrint(const mad1_sector_t *sector, bool swapmad, bool verbose, bool *haveMAD2);
int MAD2DecodeAndPrint(const mad2_sector_t *sector, bool swapmad, bool verbose);
int MADDFDecodeAndPrint(uint32_t short_aid, bool verbose);
int MADCardHolderInfoDecode(const uint8_t *data, size_t datalen, bool verbose);
void MADPrintHeader(void);
bool HasMADKey(const mad1_sector_t *s0);
int DetectHID(const mad1_sector_t *s0, uint16_t manufacture);
int convert_mad_to_arr(const mad1_sector_t *s0, const mad2_sector_t *s16,
                       size_t dump_len,
                       uint8_t *out, size_t omax, size_t *olen, bool override);

int mad_app_read(const mad_ops_t *ops, uint16_t aid, bool swapmad, bool override,
                 uint8_t *out, size_t max_len, size_t *out_len);
int mad_app_write(const mad_ops_t *ops, uint16_t aid, bool swapmad, bool override,
                  const uint8_t *data, size_t data_len);
int mad_app_verify(const mad_ops_t *ops, uint16_t aid, bool swapmad, bool override,
                   const uint8_t *expected, size_t expected_len);
#endif // _MAD_H_
