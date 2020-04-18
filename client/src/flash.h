//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Flashing utility functions
//-----------------------------------------------------------------------------

#ifndef __FLASH_H__
#define __FLASH_H__

#include "common.h"

#define FLASH_MAX_FILES 4
#define ONE_KB 1024

typedef struct {
    void *data;
    uint32_t start;
    uint32_t length;
} flash_seg_t;

typedef struct {
    const char *filename;
    int can_write_bl;
    int num_segs;
    flash_seg_t *segments;
} flash_file_t;

int flash_load(flash_file_t *ctx, const char *name, int can_write_bl, int flash_size);
int flash_start_flashing(int enable_bl_writes, char *serial_port_name, uint32_t *max_allowed);
int flash_write(flash_file_t *ctx);
void flash_free(flash_file_t *ctx);
int flash_stop_flashing(void);
#endif

