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
// Low frequency EM 410x commands
//-----------------------------------------------------------------------------

#ifndef CMDLFEM410X_H__
#define CMDLFEM410X_H__

#include "common.h"

int CmdLFEM410X(const char *Cmd);

int demodEM410x(bool verbose);
void printEM410x(uint32_t hi, uint64_t id, bool verbose, int type);

int AskEm410xDecode(bool verbose, uint32_t *hi, uint64_t *lo);
int AskEm410xDemod(int clk, int invert, int maxErr, size_t maxLen, bool amplify, uint32_t *hi, uint64_t *lo, bool verbose);

#endif
