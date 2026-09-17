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
// Low frequency Hitag µ support
//-----------------------------------------------------------------------------

#ifndef CMDLFHITAGU_H__
#define CMDLFHITAGU_H__

#include "common.h"
#include "hitag.h"

uint8_t hitagu_CRC_check(uint8_t *d, uint32_t nbit);
void annotateHitagU(char *exp, size_t size, const uint8_t *cmd, uint8_t cmdsize, bool is_response);

int CmdLFHitagU(const char *Cmd);

int read_htu_uid(void);

#endif //CMDLFHITAGU_H__
