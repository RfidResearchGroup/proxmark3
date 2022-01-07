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
// High frequency Legic commands
//-----------------------------------------------------------------------------

#ifndef CMDHFLEGIC_H__
#define CMDHFLEGIC_H__

#include "common.h"

#include "legic.h" // struct

int CmdHFLegic(const char *Cmd);

int readLegicUid(bool loop, bool verbose);
int legic_print_type(uint32_t tagtype, uint8_t spaces);
int legic_get_type(legic_card_select_t *card);
void legic_chk_iv(uint32_t *iv);
void legic_seteml(uint8_t *src, uint32_t offset, uint32_t numofbytes);
int legic_read_mem(uint32_t offset, uint32_t len, uint32_t iv, uint8_t *out, uint16_t *outlen);

#endif
