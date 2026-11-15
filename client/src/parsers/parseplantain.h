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
// Podorozhnik / Plantain (Saint Petersburg) parser for MIFARE Classic dumps
//
// Layout ported from Metrodroid (GPLv3) transit/podorozhnik, sector keys from
// the Flipper Zero plantain plugin (GPLv3). Also covers the purse half of the
// Two Cities (Troika + Podorozhnik) card, the Troika parser takes the rest.
//-----------------------------------------------------------------------------

#ifndef PARSEPLANTAIN_H__
#define PARSEPLANTAIN_H__

#include "common.h"
#include "parsetransit.h"       // transit_mfc_keyset_t

// Sector 4 and 5 keys, identifying for info commands too
extern const transit_mfc_keyset_t plantain_keyset;

// Sectors 4 and 5 under the Podorozhnik keys
bool is_valid_plantain_card(const uint8_t *dump, size_t dumplen);
int plantain_parser_parse(const uint8_t *dump, size_t dumplen);
int plantain_selftest(void);

#endif
