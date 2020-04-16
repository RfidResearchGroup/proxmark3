//-----------------------------------------------------------------------------
// Copyright (C) 2015 iceman <iceman at iuse.se>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
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
