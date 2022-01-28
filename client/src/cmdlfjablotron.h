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
// Low frequency Jablotron tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFJABLOTRON_H__
#define CMDLFJABLOTRON_H__

#include "common.h"

int CmdLFJablotron(const char *Cmd);

int demodJablotron(bool verbose);
int detectJablotron(uint8_t *bits, size_t *size);
int getJablotronBits(uint64_t fullcode, uint8_t *bits);

#endif

