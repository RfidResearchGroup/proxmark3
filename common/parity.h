//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Parity functions
//-----------------------------------------------------------------------------

// all functions defined in header file by purpose. Allows compiler optimizations.

#ifndef __PARITY_H
#define __PARITY_H

#include "common.h"

extern const uint8_t OddByteParity[256];

static inline uint8_t oddparity8(const uint8_t x) {
    return OddByteParity[x];
}

static inline uint8_t evenparity8(const uint8_t x) {
    return !OddByteParity[x];
}

static inline uint8_t evenparity16(uint16_t x) {
#if !defined __GNUC__
    x ^= x >> 8;
    return evenparity8(x);
#else
    return (__builtin_parity(x) & 0xFF);
#endif
}

static inline uint8_t oddparity16(uint16_t x) {
#if !defined __GNUC__
    x ^= x >> 8;
    return oddparity8(x);
#else
    return !__builtin_parity(x);
#endif
}

static inline uint8_t evenparity32(uint32_t x) {
#if !defined __GNUC__
    x ^= x >> 16;
    x ^= x >> 8;
    return evenparity8(x);
#else
    return (__builtin_parity(x) & 0xFF);
#endif
}

static inline uint8_t oddparity32(uint32_t x) {
#if !defined __GNUC__
    x ^= x >> 16;
    x ^= x >> 8;
    return oddparity8(x);
#else
    return !__builtin_parity(x);
#endif
}

#endif /* __PARITY_H */
