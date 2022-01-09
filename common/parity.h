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
// Parity functions
//-----------------------------------------------------------------------------

// all functions defined in header file by purpose. Allows compiler optimizations.

#ifndef __PARITY_H
#define __PARITY_H

#include "common.h"

static const uint8_t g_odd_byte_parity[256] = {
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1
};

//extern const uint8_t OddByteParity[256];

#define ODD_PARITY8(x)   { g_odd_byte_parity[x] }
#define EVEN_PARITY8(x)  { !g_odd_byte_parity[x] }

static inline uint8_t oddparity8(const uint8_t x) {
    return g_odd_byte_parity[x];
}

static inline uint8_t evenparity8(const uint8_t x) {
    return !g_odd_byte_parity[x];
}

static inline uint8_t evenparity16(uint16_t x) {
#if !defined __GNUC__
    x ^= x >> 8;
    return EVEN_PARITY8(x) ;
#else
    return (__builtin_parity(x) & 0xFF);
#endif
}

static inline uint8_t oddparity16(uint16_t x) {
#if !defined __GNUC__
    x ^= x >> 8;
    return ODD_PARITY8(x);
#else
    return !__builtin_parity(x);
#endif
}

static inline uint8_t evenparity32(uint32_t x) {
#if !defined __GNUC__
    x ^= x >> 16;
    x ^= x >> 8;
    return EVEN_PARITY8(x);
#else
    return (__builtin_parity(x) & 0xFF);
#endif
}

static inline uint8_t oddparity32(uint32_t x) {
#if !defined __GNUC__
    x ^= x >> 16;
    x ^= x >> 8;
    return ODD_PARITY8(x);
#else
    return !__builtin_parity(x);
#endif
}

#endif /* __PARITY_H */
