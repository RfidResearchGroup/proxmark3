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
// Low frequency fdx-b tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFFDXB_H__
#define CMDLFFDXB_H__

#include "common.h"

typedef struct {
    uint16_t code;
    const char *desc;
} fdxbCountryMapping_t;

int CmdLFFdxB(const char *Cmd);
int detectFDXB(uint8_t *dest, size_t *size);
int demodFDXB(bool verbose);
//int getFDXBBits(uint64_t national_code, uint16_t country_code, uint8_t is_animal, uint8_t is_extended, uint16_t extended, uint8_t *bits);

#endif

