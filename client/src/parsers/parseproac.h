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
// PROAC parser for MIFARE Classic dumps
//-----------------------------------------------------------------------------

#ifndef PARSEPROAC_H__
#define PARSEPROAC_H__

#include "common.h"

// MAD application id, function cluster 0x49, the VIGIK cluster
#define PROAC_MAD_AID   0x4982

// True when the MAD claims a sector for the PROAC application
bool is_valid_proac_card(const uint8_t *dump, size_t dumplen);

// Print what is known about the layout of a PROAC card
int proac_parser_parse(const uint8_t *dump, size_t dumplen);

#endif
