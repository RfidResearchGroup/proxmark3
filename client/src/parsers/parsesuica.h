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
// Japan IC transit card parser for FeliCa dumps
//
// Suica, PASMO, ICOCA, Kitaca, manaca, nimoca, PiTaPa, SUGOCA, TOICA and
// Hayakaken share one layout in system 0003. Ported from Metrodroid
// (GPLv3), transit/suica.
//-----------------------------------------------------------------------------

#ifndef PARSESUICA_H__
#define PARSESUICA_H__

#include "common.h"
#include "parsetransit.h"

#define SUICA_SYSTEM_CODE       0x0003
#define SUICA_SERVICE_ATTRIBUTE 0x008B
#define SUICA_SERVICE_HISTORY   0x090F

// True when system 0003 carries a readable history service
bool is_valid_suica_card(const transit_felica_card_t *card);

// Name the card from its service codes, print balance and history
int suica_parser_parse(const transit_felica_card_t *card);

// Decode built history blocks and identify cards from Metrodroid's service lists
int suica_selftest(void);

#endif
