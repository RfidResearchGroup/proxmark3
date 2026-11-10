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
// Intercode (French Calypso networks) parser, Navigo included
//
// Layouts from Metrodroid transit/intercode (GPLv3), cross checked against
// Metroflip api/calypso/cards/intercode.c (GPLv3).
//-----------------------------------------------------------------------------

#ifndef PARSEINTERCODE_H__
#define PARSEINTERCODE_H__

#include "common.h"
#include "parsetransit.h"

// Country 250 (France) in the top 12 bits of EnvNetworkId
#define INTERCODE_COUNTRY_FRANCE    0x250
#define INTERCODE_NETWORK_NAVIGO    0x250901

// Navigo, Ile-de-France Mobilites
bool is_valid_navigo_card(const transit_calypso_card_t *card);
int navigo_parser_parse(const transit_calypso_card_t *card);
int navigo_selftest(void);

// Any other French Intercode network
bool is_valid_intercode_card(const transit_calypso_card_t *card);
int intercode_parser_parse(const transit_calypso_card_t *card);
int intercode_selftest(void);

#endif
