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
// RENFE Cercanias Suma 10 parser for MIFARE Classic dumps
//
// Layout from the Metroflip renfe_sum10 plugin, GPLv3. Only the parts it
// states plainly are decoded, the event timestamp format is not known.
//-----------------------------------------------------------------------------

#ifndef PARSERENFE_H__
#define PARSERENFE_H__

#include "common.h"

// True when the sector 0 and 1 key A are the RENFE ones
bool is_valid_renfe_card(const uint8_t *dump, size_t dumplen);

// Remaining trips, zone code and history events
int renfe_parser_parse(const uint8_t *dump, size_t dumplen);

// Decode a synthetic card built from the layout
int renfe_selftest(void);

#endif
