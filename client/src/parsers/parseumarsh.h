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
// Umarsh parser for MIFARE Classic dumps
//
// Regional Russian cards on the Umarsh format (Siticard, Omka, E-karta, ...).
// Layout ported from Metrodroid (GPLv3) transit/umarsh and the Flipper Zero
// umarsh plugin (GPLv3).
//-----------------------------------------------------------------------------

#ifndef PARSEUMARSH_H__
#define PARSEUMARSH_H__

#include "common.h"

// Sector 8 block 0 holds the Umarsh value block header
bool is_valid_umarsh_card(const uint8_t *dump, size_t dumplen);
int umarsh_parser_parse(const uint8_t *dump, size_t dumplen);
int umarsh_selftest(void);

#endif
