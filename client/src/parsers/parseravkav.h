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
// Rav-Kav (Israel) Calypso parser
//
// Layouts from Metrodroid transit/ravkav (GPLv3), cross checked against
// Metroflip api/calypso/cards/ravkav.c (GPLv3).
//-----------------------------------------------------------------------------

#ifndef PARSERAVKAV_H__
#define PARSERAVKAV_H__

#include "common.h"
#include "parsetransit.h"

// Rav-Kav keeps its own environment: version 3 bits, then country 376 and
// an 8 bit issuer as a 20 bit network id
#define RAVKAV_COUNTRY_ISRAEL   0x376

bool is_valid_ravkav_card(const transit_calypso_card_t *card);
int ravkav_parser_parse(const transit_calypso_card_t *card);
int ravkav_selftest(void);

#endif
