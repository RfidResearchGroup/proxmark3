//-----------------------------------------------------------------------------
// Copyright (C) 2019 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// LTO-CM commands
//-----------------------------------------------------------------------------

#ifndef CMDHFLTO_H__
#define CMDHFLTO_H__

#include "common.h"

int infoLTO(bool verbose);
int dumpLTO(uint8_t *dump, bool verbose);
int restoreLTO(uint8_t *dump, bool verbose);
int rdblLTO(uint8_t st_blk, uint8_t end_blk, bool verbose);
int wrblLTO(uint8_t blk, uint8_t *data, bool verbose);
int CmdHFLTO(const char *Cmd);

#endif

