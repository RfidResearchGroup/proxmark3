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
// Intertic parser for ST25TB / SRT512 dumps
//
// French and Moroccan disposable transport tickets. Ported from
// client/pyscripts/intertic.py by Benjamin Delpy and the Metroflip port
// (GPLv3). The usage records are reverse engineered, not specified.
//-----------------------------------------------------------------------------

#ifndef PARSEINTERTIC_H__
#define PARSEINTERTIC_H__

#include "common.h"

// 16 blocks of 4 bytes plus the system block, as `hf 14b dump` stores SRT512
#define INTERTIC_DUMP_SIZE  68

// True for a known product id with a France or Morocco network id
bool is_valid_intertic_card(const uint8_t *data, size_t datalen, const uint8_t *uid);

// Print distribution data, counter and both usage records
int intertic_parser_parse(const uint8_t *data, size_t datalen, const uint8_t *uid);

// Build tickets from the field layout and check the decoder reads them back
int intertic_selftest(void);

#endif
