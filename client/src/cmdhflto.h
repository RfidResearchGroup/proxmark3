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
// LTO-CM commands
//-----------------------------------------------------------------------------

#ifndef CMDHFLTO_H__
#define CMDHFLTO_H__

#include "common.h"

int reader_lto(bool loop, bool verbose);
int infoLTO(bool verbose);
int dumpLTO(uint8_t *dump, bool verbose);
int restoreLTO(uint8_t *dump, bool verbose);
int rdblLTO(uint8_t st_blk, uint8_t end_blk, bool verbose);
int wrblLTO(uint8_t blk, uint8_t *data, bool verbose);
int CmdHFLTO(const char *Cmd);

#endif

