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
// Troika (Moscow) parser for MIFARE Classic and Ultralight dumps
//
// Block layouts ported from Metrodroid (GPLv3) transit/troika, sector keys
// from the Flipper Zero troika plugin (GPLv3).
//-----------------------------------------------------------------------------

#ifndef PARSETROIKA_H__
#define PARSETROIKA_H__

#include "common.h"

// MIFARE Classic, a Troika block in sector 8 or 4 under the Troika keys
bool is_valid_troika_card(const uint8_t *dump, size_t dumplen);
int troika_parser_parse(const uint8_t *dump, size_t dumplen);
int troika_selftest(void);

// MIFARE Ultralight, the Troika block starts at page 4
bool is_valid_troika_ul_card(const uint8_t *data, size_t datalen);
int troika_ul_parser_parse(const uint8_t *data, size_t datalen);
int troika_ul_selftest(void);

#endif
