//-----------------------------------------------------------------------------
// Borrowed initially from
// https://web.archive.org/web/20070920142755/http://www.simonshepherd.supanet.com:80/source.htm#ansi
// Copyright (C) Simon Shepherd 2003
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
// Generic TEA crypto code.
//-----------------------------------------------------------------------------
#include "tea.h"

#include "commonutil.h" // bytes_to_num etc

#define ROUNDS 32
#define DELTA  0x9E3779B9
#define SUM    0xC6EF3720

void tea_encrypt(uint8_t *v, uint8_t *key) {

    uint32_t a = 0, b = 0, c = 0, d = 0, y = 0, z = 0;
    uint32_t sum = 0;
    uint8_t n = ROUNDS;

    //key
    a = bytes_to_num(key, 4);
    b = bytes_to_num(key + 4, 4);
    c = bytes_to_num(key + 8, 4);
    d = bytes_to_num(key + 12, 4);

    //input
    y = bytes_to_num(v, 4);
    z = bytes_to_num(v + 4, 4);

    while (n-- > 0) {
        sum += DELTA;
        y += ((z << 4) + a) ^ (z + sum) ^ ((z >> 5) + b);
        z += ((y << 4) + c) ^ (y + sum) ^ ((y >> 5) + d);
    }

    num_to_bytes(y, 4, v);
    num_to_bytes(z, 4, v + 4);
}

void tea_decrypt(uint8_t *v, uint8_t *key) {

    uint32_t a = 0, b = 0, c = 0, d = 0, y = 0, z = 0;
    uint32_t sum = SUM;
    uint8_t n = ROUNDS;

    //key
    a = bytes_to_num(key, 4);
    b = bytes_to_num(key + 4, 4);
    c = bytes_to_num(key + 8, 4);
    d = bytes_to_num(key + 12, 4);

    //input
    y = bytes_to_num(v, 4);
    z = bytes_to_num(v + 4, 4);

    /* sum = delta<<5, in general sum = delta * n */
    while (n-- > 0) {
        z -= ((y << 4) + c) ^ (y + sum) ^ ((y >> 5) + d);
        y -= ((z << 4) + a) ^ (z + sum) ^ ((z >> 5) + b);
        sum -= DELTA;
    }
    num_to_bytes(y, 4, v);
    num_to_bytes(z, 4, v + 4);
}
