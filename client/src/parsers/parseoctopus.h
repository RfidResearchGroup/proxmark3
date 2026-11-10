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
// Octopus (Hong Kong) and Shenzhen Tong parser for FeliCa dumps
//
// Ported from Metrodroid (GPLv3), transit/octopus.
//-----------------------------------------------------------------------------

#ifndef PARSEOCTOPUS_H__
#define PARSEOCTOPUS_H__

#include "common.h"
#include "parsetransit.h"

#define OCTOPUS_SYSTEM_CODE     0x8008
#define OCTOPUS_SERVICE_BALANCE 0x0117
#define SZT_SYSTEM_CODE         0x8005
#define SZT_SERVICE_BALANCE     0x0118

// True when either balance service was read
bool is_valid_octopus_card(const transit_felica_card_t *card);

// Print the Octopus and / or Shenzhen Tong balance
int octopus_parser_parse(const transit_felica_card_t *card);

// Metrodroid OctopusTest vectors
int octopus_selftest(void);

#endif
