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
// Ventra (Chicago) paper ticket parser for MIFARE Ultralight
//
// Layout from the Flipper Zero ventra plugin by @hazardousvoltage and the
// Metrodroid Nextfare Ultralight code, both GPLv3.
//-----------------------------------------------------------------------------

#ifndef PARSEVENTRA_H__
#define PARSEVENTRA_H__

#include "common.h"

bool is_valid_ventra_card(const uint8_t *data, size_t datalen);
int ventra_parser_parse(const uint8_t *data, size_t datalen);
int ventra_selftest(void);

#endif
