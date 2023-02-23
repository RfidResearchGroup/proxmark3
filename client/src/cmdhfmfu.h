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

uint32_t GetHF14AMfU_Type(void);
int ul_print_type(uint32_t tagtype, uint8_t spaces);
void printMFUdumpEx(mfu_dump_t *card, uint16_t pages, uint8_t startpage);
int ul_read_uid(uint8_t *uid);
int trace_mfuc_try_default_3des_keys(uint8_t **correct_key, int state, uint8_t (*authdata)[16]);

int CmdHFMFUltra(const char *Cmd);
int CmdHF14MfuNDEFRead(const char *Cmd);
int CmdHF14MfUTamper(const char *Cmd);

uint16_t ul_ev1_packgen_VCNEW(uint8_t *uid, uint32_t pwd);
uint32_t ul_ev1_otpgenA(uint8_t *uid);

typedef enum TAGTYPE_UL {
    UNKNOWN          = 0x000000,
    UL               = 0x1,
    UL_C             = 0x2,
    UL_EV1_48        = 0x4,
    UL_EV1_128       = 0x8,
    NTAG             = 0x10,
    NTAG_203         = 0x20,
    NTAG_210         = 0x40,
    NTAG_212         = 0x80,
    NTAG_213         = 0x100,
    NTAG_215         = 0x200,
    NTAG_216         = 0x400,
    MY_D             = 0x800,
    MY_D_NFC         = 0x1000,
    MY_D_MOVE        = 0x2000,
    MY_D_MOVE_NFC    = 0x4000,
    MY_D_MOVE_LEAN   = 0x8000,
    NTAG_I2C_1K      = 0x10000,
    NTAG_I2C_2K      = 0x20000,
    NTAG_I2C_1K_PLUS = 0x40000,
    NTAG_I2C_2K_PLUS = 0x80000,
    FUDAN_UL         = 0x100000,
    MAGIC            = 0x200000,
    NTAG_213_F       = 0x400000,
    NTAG_216_F       = 0x800000,
    UL_EV1           = 0x1000000,
    UL_NANO_40       = 0x2000000,
    NTAG_213_TT      = 0x4000000,
    NTAG_213_C       = 0x8000000,
    MAGIC_1A         = 0x10000000 | MAGIC,
    MAGIC_1B         = 0x20000000 | MAGIC,
    MAGIC_NTAG       = 0x40000000 | MAGIC,
    NTAG_210u        = 0x80000000,
    UL_MAGIC         = UL | MAGIC,
    UL_C_MAGIC       = UL_C | MAGIC,
    // Don't forget to fill UL_TYPES_ARRAY and UL_MEMORY_ARRAY if new types are added
    UL_ERROR         = 0xFFFFFF,
} TagTypeUL_t;

#endif
