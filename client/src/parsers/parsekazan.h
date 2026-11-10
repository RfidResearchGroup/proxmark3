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
// Kazan transport card parser for MIFARE Classic dumps
//
// Layout from Metrodroid (GPLv3) transit/kazan and the Flipper Zero kazan
// plugin (GPLv3), which also supplies the sector 8 keys and tariff names.
//-----------------------------------------------------------------------------

#ifndef PARSEKAZAN_H__
#define PARSEKAZAN_H__

#include "common.h"
#include "parsetransit.h"       // transit_mfc_keyset_t

// Sector 8 keys, identifying for info commands too
extern const transit_mfc_keyset_t kazan_keyset;

// Sector 8 under one of the Kazan key sets
bool is_valid_kazan_card(const uint8_t *dump, size_t dumplen);
int kazan_parser_parse(const uint8_t *dump, size_t dumplen);
int kazan_selftest(void);

#endif
