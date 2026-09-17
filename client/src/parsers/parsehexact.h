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
// Hexact / COGELEC / Intratone parser for MIFARE Classic dumps
//-----------------------------------------------------------------------------

#ifndef PARSEHEXACT_H__
#define PARSEHEXACT_H__

#include "common.h"

// True when sector 15 carries the Hexact system identifier
bool is_valid_hexact_card(const uint8_t *dump, size_t dumplen);

// Print what is known about the layout of a Hexact card
int hexact_parser_parse(const uint8_t *dump, size_t dumplen);

// Decode a card built from the model and check the decoder agrees, both ways
int hexact_selftest(void);

#endif
