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
// Low frequency NEDAP tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFNEDAP_H__
#define CMDLFNEDAP_H__

#include "common.h"

int CmdLFNedap(const char *Cmd);

int demodNedap(bool verbose);
int detectNedap(uint8_t *dest, size_t *size);
int getNedapBits(uint32_t cn, uint8_t *nedapBits);

#endif

