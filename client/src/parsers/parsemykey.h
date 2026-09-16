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
// MyKey / COGES parser for SRIX4K - ST25TB04K dumps
//-----------------------------------------------------------------------------

#ifndef PARSEMYKEY_H__
#define PARSEMYKEY_H__

#include "common.h"

#define MYKEY_BLOCK_SIZE    4
#define MYKEY_NUM_BLOCKS    128
#define MYKEY_BYTES         (MYKEY_NUM_BLOCKS * MYKEY_BLOCK_SIZE)

bool is_valid_mykey_card(const uint8_t *dump, size_t dumplen);
int mykey_parser_parse(const uint8_t *dump, size_t dumplen, const uint8_t *uid);
int mykey_selftest(void);

#endif
