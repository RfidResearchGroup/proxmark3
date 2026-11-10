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
// Cubic Nextfare parser for MIFARE Classic dumps: Go card (Brisbane),
// TAP (Los Angeles), Go-To (Minneapolis) and other Nextfare systems
//
// Layout from Metrodroid NextfareTransitData, SeqGoTransitData,
// LaxTapTransitData and MspGotoTransitData, GPLv3.
//-----------------------------------------------------------------------------

#ifndef PARSENEXTFARE_H__
#define PARSENEXTFARE_H__

#include "common.h"

// True when sector 0 block 1 carries the Nextfare manufacturer signature
bool is_valid_nextfare_card(const uint8_t *dump, size_t dumplen);

// Card number, balance, ticket type, expiry, top ups and taps
int nextfare_parser_parse(const uint8_t *dump, size_t dumplen);

// Metrodroid NextfareTest vectors
int nextfare_selftest(void);

#endif
