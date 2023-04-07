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
// High frequency Topaz (NFC Type 1) commands
//-----------------------------------------------------------------------------

#ifndef CMDHFTOPAZ_H__
#define CMDHFTOPAZ_H__

#include "common.h"


#define TOPAZ_STATIC_MEMORY (0x0F * 8)  // 15 blocks with 8 Bytes each
#define TOPAZ_BLOCK_SIZE    8
#define TOPAZ_MAX_SIZE      512

// a struct to describe a memory area which contains lock bits and the corresponding lockable memory area
typedef struct dynamic_lock_area_s {
    struct dynamic_lock_area_s *next;
    uint16_t byte_offset;               // the address of the lock bits
    uint16_t size_in_bits;
    uint16_t first_locked_byte;         // the address of the lockable area
    uint16_t bytes_locked_per_bit;
} dynamic_lock_area_t;

typedef struct topaz_tag_s {
    uint8_t HR01[2];
    uint8_t uid[7];
    uint16_t size;
    uint8_t data_blocks[TOPAZ_STATIC_MEMORY / 8][8]; // this memory is always there
    uint8_t *dynamic_memory;                         // this memory can be there
    dynamic_lock_area_t *dynamic_lock_areas;         // lock area descriptors
} topaz_tag_t;



int CmdHFTopaz(const char *Cmd);
int CmdHFTopazInfo(const char *Cmd);
int readTopazUid(bool loop, bool verbose);
#endif
