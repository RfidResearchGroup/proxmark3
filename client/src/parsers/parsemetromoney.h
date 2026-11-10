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
// Metromoney (Tbilisi) parser for MIFARE Classic dumps
//
// Layout from the Flipper Zero metromoney plugin (GPLv3) and Metrodroid
// (GPLv3) transit/metromoney.
//-----------------------------------------------------------------------------

#ifndef PARSEMETROMONEY_H__
#define PARSEMETROMONEY_H__

#include "common.h"

// Sectors 0 and 1 under the Metromoney keys
bool is_valid_metromoney_card(const uint8_t *dump, size_t dumplen);
int metromoney_parser_parse(const uint8_t *dump, size_t dumplen);
int metromoney_selftest(void);

#endif
