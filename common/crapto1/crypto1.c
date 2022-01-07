//-----------------------------------------------------------------------------
// Copyright (C) 2008-2014 bla <blapost@gmail.com>
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
#include <stdlib.h>
#include "crapto1.h"
#include "parity.h"

#ifdef __OPTIMIZE_SIZE__
int filter(uint32_t const x) {
    uint32_t f;

    f  = 0xf22c0 >> (x       & 0xf) & 16;
    f |= 0x6c9c0 >> (x >>  4 & 0xf) &  8;
    f |= 0x3c8b0 >> (x >>  8 & 0xf) &  4;
    f |= 0x1e458 >> (x >> 12 & 0xf) &  2;
    f |= 0x0d938 >> (x >> 16 & 0xf) &  1;
    return BIT(0xEC57E80A, f);
}
#endif

#define SWAPENDIAN(x)\
    (x = (x >> 8 & 0xff00ff) | (x & 0xff00ff) << 8, x = x >> 16 | x << 16)

void crypto1_init(struct Crypto1State *state, uint64_t key) {
    if (state == NULL)
        return;
    state->odd = 0;
    state->even = 0;
    for (int i = 47; i > 0; i -= 2) {
        state->odd  = state->odd  << 1 | BIT(key, (i - 1) ^ 7);
        state->even = state->even << 1 | BIT(key, i ^ 7);
    }
}

void crypto1_deinit(struct Crypto1State *state) {
    state->odd = 0;
    state->even = 0;
}

#if !defined(__arm__) || defined(__linux__) || defined(_WIN32) || defined(__APPLE__) // bare metal ARM Proxmark lacks calloc()/free()
struct Crypto1State *crypto1_create(uint64_t key) {
    struct Crypto1State *state = calloc(sizeof(*state), sizeof(uint8_t));
    if (!state) return NULL;
    crypto1_init(state, key);
    return state;
}

void crypto1_destroy(struct Crypto1State *state) {
    free(state);
}
#endif

void crypto1_get_lfsr(struct Crypto1State *state, uint64_t *lfsr) {
    int i;
    for (*lfsr = 0, i = 23; i >= 0; --i) {
        *lfsr = *lfsr << 1 | BIT(state->odd, i ^ 3);
        *lfsr = *lfsr << 1 | BIT(state->even, i ^ 3);
    }
}
uint8_t crypto1_bit(struct Crypto1State *s, uint8_t in, int is_encrypted) {
    uint32_t feedin, t;
    uint8_t ret = filter(s->odd);

    feedin  = ret & (!!is_encrypted);
    feedin ^= !!in;
    feedin ^= LF_POLY_ODD & s->odd;
    feedin ^= LF_POLY_EVEN & s->even;
    s->even = s->even << 1 | (evenparity32(feedin));

    t = s->odd;
    s->odd = s->even;
    s->even = t;

    return ret;
}
uint8_t crypto1_byte(struct Crypto1State *s, uint8_t in, int is_encrypted) {
    uint8_t ret = 0;
    ret |= crypto1_bit(s, BIT(in, 0), is_encrypted) << 0;
    ret |= crypto1_bit(s, BIT(in, 1), is_encrypted) << 1;
    ret |= crypto1_bit(s, BIT(in, 2), is_encrypted) << 2;
    ret |= crypto1_bit(s, BIT(in, 3), is_encrypted) << 3;
    ret |= crypto1_bit(s, BIT(in, 4), is_encrypted) << 4;
    ret |= crypto1_bit(s, BIT(in, 5), is_encrypted) << 5;
    ret |= crypto1_bit(s, BIT(in, 6), is_encrypted) << 6;
    ret |= crypto1_bit(s, BIT(in, 7), is_encrypted) << 7;
    return ret;
}
uint32_t crypto1_word(struct Crypto1State *s, uint32_t in, int is_encrypted) {
    uint32_t ret = 0;
    // note: xor args have been swapped because some compilers emit a warning
    // for 10^x and 2^x as possible misuses for exponentiation. No comment.
    ret |= crypto1_bit(s, BEBIT(in, 0), is_encrypted) << (24 ^ 0);
    ret |= crypto1_bit(s, BEBIT(in, 1), is_encrypted) << (24 ^ 1);
    ret |= crypto1_bit(s, BEBIT(in, 2), is_encrypted) << (24 ^ 2);
    ret |= crypto1_bit(s, BEBIT(in, 3), is_encrypted) << (24 ^ 3);
    ret |= crypto1_bit(s, BEBIT(in, 4), is_encrypted) << (24 ^ 4);
    ret |= crypto1_bit(s, BEBIT(in, 5), is_encrypted) << (24 ^ 5);
    ret |= crypto1_bit(s, BEBIT(in, 6), is_encrypted) << (24 ^ 6);
    ret |= crypto1_bit(s, BEBIT(in, 7), is_encrypted) << (24 ^ 7);

    ret |= crypto1_bit(s, BEBIT(in, 8), is_encrypted) << (24 ^ 8);
    ret |= crypto1_bit(s, BEBIT(in, 9), is_encrypted) << (24 ^ 9);
    ret |= crypto1_bit(s, BEBIT(in, 10), is_encrypted) << (24 ^ 10);
    ret |= crypto1_bit(s, BEBIT(in, 11), is_encrypted) << (24 ^ 11);
    ret |= crypto1_bit(s, BEBIT(in, 12), is_encrypted) << (24 ^ 12);
    ret |= crypto1_bit(s, BEBIT(in, 13), is_encrypted) << (24 ^ 13);
    ret |= crypto1_bit(s, BEBIT(in, 14), is_encrypted) << (24 ^ 14);
    ret |= crypto1_bit(s, BEBIT(in, 15), is_encrypted) << (24 ^ 15);

    ret |= crypto1_bit(s, BEBIT(in, 16), is_encrypted) << (24 ^ 16);
    ret |= crypto1_bit(s, BEBIT(in, 17), is_encrypted) << (24 ^ 17);
    ret |= crypto1_bit(s, BEBIT(in, 18), is_encrypted) << (24 ^ 18);
    ret |= crypto1_bit(s, BEBIT(in, 19), is_encrypted) << (24 ^ 19);
    ret |= crypto1_bit(s, BEBIT(in, 20), is_encrypted) << (24 ^ 20);
    ret |= crypto1_bit(s, BEBIT(in, 21), is_encrypted) << (24 ^ 21);
    ret |= crypto1_bit(s, BEBIT(in, 22), is_encrypted) << (24 ^ 22);
    ret |= crypto1_bit(s, BEBIT(in, 23), is_encrypted) << (24 ^ 23);

    ret |= crypto1_bit(s, BEBIT(in, 24), is_encrypted) << (24 ^ 24);
    ret |= crypto1_bit(s, BEBIT(in, 25), is_encrypted) << (24 ^ 25);
    ret |= crypto1_bit(s, BEBIT(in, 26), is_encrypted) << (24 ^ 26);
    ret |= crypto1_bit(s, BEBIT(in, 27), is_encrypted) << (24 ^ 27);
    ret |= crypto1_bit(s, BEBIT(in, 28), is_encrypted) << (24 ^ 28);
    ret |= crypto1_bit(s, BEBIT(in, 29), is_encrypted) << (24 ^ 29);
    ret |= crypto1_bit(s, BEBIT(in, 30), is_encrypted) << (24 ^ 30);
    ret |= crypto1_bit(s, BEBIT(in, 31), is_encrypted) << (24 ^ 31);
    return ret;
}

/* prng_successor
 * helper used to obscure the keystream during authentication
 */
uint32_t prng_successor(uint32_t x, uint32_t n) {
    SWAPENDIAN(x);
    while (n--)
        x = x >> 1 | (x >> 16 ^ x >> 18 ^ x >> 19 ^ x >> 21) << 31;

    return SWAPENDIAN(x);
}
