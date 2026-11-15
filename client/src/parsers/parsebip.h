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
// Bip! (Santiago de Chile) parser for MIFARE Classic dumps
//
// Layout from Metrodroid ChileBipTransitData and the Flipper Zero bip plugin,
// both GPLv3.
//-----------------------------------------------------------------------------

#ifndef PARSEBIP_H__
#define PARSEBIP_H__

#include "common.h"
#include "parsetransit.h"       // transit_mfc_keyset_t

// Sector 0 and 1 keys, identifying for info commands too
extern const transit_mfc_keyset_t bip_keyset;

// True when the sector 0 and 1 keys are the Bip! ones
bool is_valid_bip_card(const uint8_t *dump, size_t dumplen);

// Card number, holder, balance, last trips and top ups
int bip_parser_parse(const uint8_t *dump, size_t dumplen);

// Decode a synthetic card built from the layout
int bip_selftest(void);

#endif
