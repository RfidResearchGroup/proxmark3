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
// Low frequency COTAG commands
//-----------------------------------------------------------------------------

#ifndef CMDLFCOTAG_H__
#define CMDLFCOTAG_H__

#include "common.h"
#include <stdbool.h>

#ifndef COTAG_BITS
#define COTAG_BITS 264
#endif

int CmdLFCOTAG(const char *Cmd);
int demodCOTAG(bool verbose);
int readCOTAGUid(void);
#endif
