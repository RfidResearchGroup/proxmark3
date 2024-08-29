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
// High frequency MIFARE ULTRALIGHT (C) commands
//-----------------------------------------------------------------------------
#ifndef CMDHFMFU_H__
#define CMDHFMFU_H__

#include "common.h"

#include "mifare.h" // structs


#define MFU_BLOCK_SIZE      0x04
#define MFU_MAX_BLOCKS      0xFF
#define MFU_MAX_BYTES       (MFU_MAX_BLOCKS * MFU_BLOCK_SIZE)

// Old Ultralight/NTAG dump file format
// It is used only for converting
#define OLD_MFU_DUMP_PREFIX_LENGTH 48

typedef struct {
    uint8_t version[8];
    uint8_t tbo[2];
    uint8_t tearing[3];
    uint8_t pack[2];
    uint8_t tbo1[1];
    uint8_t signature[32];
    //uint8_t counter[3];
    uint8_t data[1024];
} PACKED old_mfu_dump_t;

typedef struct {
    const char *name;
    const char *model;
    const char *version;
} ul_family_t;

uint64_t GetHF14AMfU_Type(void);
int ul_print_type(uint64_t tagtype, uint8_t spaces);
void mfu_print_dump(mfu_dump_t *card, uint16_t pages, uint8_t startpage, bool dense_output);
int ul_read_uid(uint8_t *uid);
int trace_mfuc_try_default_3des_keys(uint8_t **correct_key, int state, uint8_t (*authdata)[16]);

int CmdHFMFUltra(const char *Cmd);
int CmdHF14MfuNDEFRead(const char *Cmd);
int CmdHF14MfUTamper(const char *Cmd);

#define MFU_TT_UNKNOWN          0x0ULL
#define MFU_TT_UL               0x1ULL
#define MFU_TT_UL_C             0x2ULL
#define MFU_TT_UL_EV1_48        0x4ULL
#define MFU_TT_UL_EV1_128       0x8ULL
#define MFU_TT_NTAG             0x10ULL
#define MFU_TT_NTAG_203         0x20ULL
#define MFU_TT_NTAG_210         0x40ULL
#define MFU_TT_NTAG_212         0x80ULL
#define MFU_TT_NTAG_213         0x100ULL
#define MFU_TT_NTAG_215         0x200ULL
#define MFU_TT_NTAG_216         0x400ULL
#define MFU_TT_MY_D             0x800ULL
#define MFU_TT_MY_D_NFC         0x1000ULL
#define MFU_TT_MY_D_MOVE        0x2000ULL
#define MFU_TT_MY_D_MOVE_NFC    0x4000ULL
#define MFU_TT_MY_D_MOVE_LEAN   0x8000ULL
#define MFU_TT_NTAG_I2C_1K      0x10000ULL
#define MFU_TT_NTAG_I2C_2K      0x20000ULL
#define MFU_TT_NTAG_I2C_1K_PLUS 0x40000ULL
#define MFU_TT_NTAG_I2C_2K_PLUS 0x80000ULL
#define MFU_TT_FUDAN_UL         0x100000ULL
#define MFU_TT_MAGIC            0x200000ULL
#define MFU_TT_NTAG_213_F       0x400000ULL
#define MFU_TT_NTAG_216_F       0x800000ULL
#define MFU_TT_UL_EV1           0x1000000ULL
#define MFU_TT_UL_NANO_40       0x2000000ULL
#define MFU_TT_NTAG_213_TT      0x4000000ULL
#define MFU_TT_NTAG_213_C       0x8000000ULL
#define MFU_TT_MAGIC_1A         0x10000000ULL
#define MFU_TT_MAGIC_1B         0x20000000ULL
#define MFU_TT_MAGIC_NTAG       0x40000000ULL
#define MFU_TT_NTAG_210u        0x80000000ULL
#define MFU_TT_UL_AES           0x100000000ULL
#define MFU_TT_MAGIC_2          0x200000000ULL
#define MFU_TT_MAGIC_4          0x400000000ULL
#define MFU_TT_MAGIC_4_GDM      0x800000000ULL
#define MFU_TT_MAGIC_NTAG21X    0x1000000000ULL
#define MFU_TT_UL_MAGIC         (MFU_TT_UL | MFU_TT_MAGIC)
#define MFU_TT_UL_C_MAGIC       (MFU_TT_UL_C | MFU_TT_MAGIC)
// Don't forget to fill UL_TYPES_ARRAY and UL_MEMORY_ARRAY if new types are added
#define MFU_TT_UL_ERROR         0x7FFFFFFFULL


#endif
