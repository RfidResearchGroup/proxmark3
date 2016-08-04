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
#include "util.h"
extern uint8_t* sample_buf;
void GetFromBigBuf(uint8_t *dest, int bytes, int start_index);
void GetEMLFromBigBuf(uint8_t *dest, int bytes, int start_index);
#endif
