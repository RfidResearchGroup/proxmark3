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
// Flashing utility functions
//-----------------------------------------------------------------------------

#ifndef __FLASH_H__
#define __FLASH_H__

#include "common.h"
#include "elf.h"

#define FLASH_MAX_FILES 4
#define ONE_KB 1024

typedef struct {
    void *data;
    uint32_t start;
    uint32_t length;
} flash_seg_t;

typedef struct {
    const char *filename;
    Elf32_Phdr_t *phdrs;
    uint16_t num_phdrs;
    int can_write_bl;
    int num_segs;
    flash_seg_t *segments;
} flash_file_t;

int flash_check(flash_file_t *ctx, const char *name);
int flash_load(flash_file_t *ctx, int can_write_bl, int flash_size);
int flash_start_flashing(int enable_bl_writes, char *serial_port_name, uint32_t *max_allowed);
int flash_write(flash_file_t *ctx);
void flash_free(flash_file_t *ctx);
int flash_stop_flashing(void);
#endif

