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
// Mifare default constants
//-----------------------------------------------------------------------------

#include "mifaredefault.h"
#include "commonutil.h"  // ARRAYLEN

const char *g_mifare_plus_default_keys[] = {
    "ffffffffffffffffffffffffffffffff",  // default key
    "00000000000000000000000000000000",
    "a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7",  // MAD key
    "b0b1b2b3b4b5b6b7b0b1b2b3b4b5b6b7",
    "d3f7d3f7d3f7d3f7d3f7d3f7d3f7d3f7",  // NDEF key
    "11111111111111111111111111111111",
    "22222222222222222222222222222222",
    "33333333333333333333333333333333",
    "44444444444444444444444444444444",
    "55555555555555555555555555555555",
    "66666666666666666666666666666666",
    "77777777777777777777777777777777",
    "88888888888888888888888888888888",
    "99999999999999999999999999999999",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "cccccccccccccccccccccccccccccccc",
    "dddddddddddddddddddddddddddddddd",
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "000102030405060708090a0b0c0d0e0f",
    "0102030405060708090a0b0c0d0e0f10",
    "00010203040506070809101112131415",
    "01020304050607080910111213141516",
    "00112233445566778899aabbccddeeff",
    "404142434445464748494a4b4c4d4e4f",
    "303132333435363738393a3b3c3d3e3f",
};
size_t g_mifare_plus_default_keys_len = ARRAYLEN(g_mifare_plus_default_keys);
