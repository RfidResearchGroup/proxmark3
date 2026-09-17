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
#ifndef CRAPTO1_INCLUDED
#define CRAPTO1_INCLUDED

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

struct Crypto1State {uint32_t odd, even;};
void crypto1_init(struct Crypto1State *state, uint64_t key);
void crypto1_deinit(struct Crypto1State *);
#if !defined(__arm__) || defined(__linux__) || defined(_WIN32) || defined(__APPLE__) // bare metal ARM Proxmark lacks malloc()/free()
struct Crypto1State *crypto1_create(uint64_t key);
void crypto1_destroy(struct Crypto1State *);
#endif
void crypto1_get_lfsr(struct Crypto1State *, uint64_t *);
uint8_t crypto1_bit(struct Crypto1State *, uint8_t, int);
uint8_t crypto1_byte(struct Crypto1State *, uint8_t, int);
uint32_t crypto1_word(struct Crypto1State *, uint32_t, int);
uint32_t prng_successor(uint32_t x, uint32_t n);

#if !defined(__arm__) || defined(__linux__) || defined(_WIN32) || defined(__APPLE__) // bare metal ARM Proxmark lacks malloc()/free()
struct Crypto1State *lfsr_recovery32(uint32_t ks2, uint32_t in);
struct Crypto1State *lfsr_recovery64(uint32_t ks2, uint32_t ks3);
struct Crypto1State *
lfsr_common_prefix(uint32_t pfx, uint32_t rr, uint8_t ks[8], uint8_t par[8][8], uint32_t no_par);
#endif
uint32_t *lfsr_prefix_ks(const uint8_t ks[8], int isodd);


uint8_t lfsr_rollback_bit(struct Crypto1State *s, uint32_t in, int fb);
uint8_t lfsr_rollback_byte(struct Crypto1State *s, uint32_t in, int fb);
uint32_t lfsr_rollback_word(struct Crypto1State *s, uint32_t in, int fb);
int nonce_distance(uint32_t from, uint32_t to);
bool validate_prng_nonce(uint32_t nonce);
#define FOREACH_VALID_NONCE(N, FILTER, FSIZE)\
    uint32_t __n = 0,__M = 0, N = 0;\
    int __i;\
    for(; __n < 1 << 16; N = prng_successor(__M = ++__n, 16))\
        for(__i = FSIZE - 1; __i >= 0; __i--)\
            if(BIT(FILTER, __i) ^ evenparity32(__M & 0xFF01))\
                break;\
            else if(__i)\
                __M = prng_successor(__M, (__i == 7) ? 48 : 8);\
            else

#define LF_POLY_ODD (0x29CE5C)
#define LF_POLY_EVEN (0x870804)
#define BIT(x, n) ((x) >> (n) & 1)
#define BEBIT(x, n) BIT(x, (n) ^ 24)
#ifdef __OPTIMIZE_SIZE__
int filter(uint32_t const x);
#else
static inline int filter(uint32_t const x) {
    uint32_t f;

    f  = 0xf22c0 >> (x       & 0xf) & 16;
    f |= 0x6c9c0 >> (x >>  4 & 0xf) &  8;
    f |= 0x3c8b0 >> (x >>  8 & 0xf) &  4;
    f |= 0x1e458 >> (x >> 12 & 0xf) &  2;
    f |= 0x0d938 >> (x >> 16 & 0xf) &  1;
    return BIT(0xEC57E80A, f);
}
#endif
#endif
