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

#define SAMPLE_BUFFER_SIZE 64

extern uint8_t sample_buf[SAMPLE_BUFFER_SIZE];
#define arraylen(x) (sizeof(x)/sizeof((x)[0]))

void GetFromBigBuf(uint8_t *dest, int bytes, int start_index);

#endif
