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
// Low frequency G Prox II tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFGUARD_H__
#define CMDLFGUARD_H__

#include "common.h"

int CmdLFGuard(const char *Cmd);
int detectGProxII(uint8_t *bits, size_t *size);
int demodGuard(bool verbose);
int getGuardBits(uint8_t xorKey, uint8_t fmtlen, uint32_t fc, uint32_t cn, uint8_t *guardBits);
#endif
