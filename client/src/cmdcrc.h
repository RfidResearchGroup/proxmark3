//-----------------------------------------------------------------------------
// Borrowed initially from https://reveng.sourceforge.io/
// Copyright (C) Greg Cook 2019
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
// CRC Calculations from the software reveng commands
//-----------------------------------------------------------------------------

#ifndef CMDCRC_H__
#define CMDCRC_H__

#include "common.h"

int CmdCrc(const char *Cmd);

int GetModels(char *Models[], int *count, uint8_t *width);
int RunModel(char *inModel, char *inHexStr, bool reverse, char endian, char *result);
#endif
