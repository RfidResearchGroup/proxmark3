//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Data utilities
//-----------------------------------------------------------------------------

#ifndef DATA_H__
#define DATA_H__
#include <stdint.h>
#include <stdbool.h>
#include "util.h"

#define FILE_PATH_SIZE 1000												

extern uint32_t sample_buf_size;
extern uint8_t* sample_buf;
extern void GetFromBigBuf(uint8_t *dest, uint32_t len, uint32_t start_index);
extern bool GetEMLFromBigBuf(uint8_t *dest, uint32_t len, uint32_t start_index);
extern void GetFromFlashMen(uint8_t *dest, uint32_t len, uint32_t start_index);
#endif
