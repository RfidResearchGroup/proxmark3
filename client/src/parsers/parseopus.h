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
// Opus (Montreal / Quebec) Calypso parser
//
// Layouts from Metrodroid transit/opus (GPLv3).
//-----------------------------------------------------------------------------

#ifndef PARSEOPUS_H__
#define PARSEOPUS_H__

#include "common.h"
#include "parsetransit.h"

// Country 124 (Canada), network 001, Intercode style environment
#define OPUS_NETWORK_ID     0x124001

bool is_valid_opus_card(const transit_calypso_card_t *card);
int opus_parser_parse(const transit_calypso_card_t *card);
int opus_selftest(void);

#endif
