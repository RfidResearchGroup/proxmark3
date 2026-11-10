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
// CharlieCard (MBTA, Boston) parser for MIFARE Classic dumps
//
// Layout from Metrodroid CharlieCardTransitData and the Flipper Zero
// charliecard plugin, both GPLv3.
//-----------------------------------------------------------------------------

#ifndef PARSECHARLIE_H__
#define PARSECHARLIE_H__

#include "common.h"
#include "parsetransit.h"       // transit_mfc_keyset_t

// Sector 0 and 1 keys, identifying for info commands too
extern const transit_mfc_keyset_t charlie_keyset;

// True when the sector 0 and 1 keys are the CharlieCard ones
bool is_valid_charlie_card(const uint8_t *dump, size_t dumplen);

// Serial, card type, balance, issue / validity dates and trips
int charlie_parser_parse(const uint8_t *dump, size_t dumplen);

// Decode a synthetic card built from the layout
int charlie_selftest(void);

#endif
