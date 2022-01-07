//-----------------------------------------------------------------------------
// Borrowed initially from http://burtleburtle.net/bob/rand/smallprng.html
// Copyright (C) Bob Jenkins
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
// Burtle Prng - Modified.   42iterations instead of 20.
//-----------------------------------------------------------------------------
#include "prng.h"

#define rot(x,k) (((x)<<(k))|((x)>>(32-(k))))
uint32_t burtle_get_mod(prng_ctx_t *x) {
    uint32_t e = x->a - rot(x->b, 21);
    x->a = x->b ^ rot(x->c, 19);
    x->b = x->c + rot(x->d, 6);
    x->c = x->d + e;
    x->d = e + x->a;
    return x->d;
}

void burtle_init_mod(prng_ctx_t *x, uint32_t seed) {
    x->a = 0xf1ea5eed;
    x->b = x->c = x->d = seed;
    for (uint8_t i = 0; i < 42; ++i) {
        (void)burtle_get_mod(x);
    }
}

void burtle_init(prng_ctx_t *x, uint32_t seed) {
    uint32_t i;
    x->a = 0xf1ea5eed, x->b = x->c = x->d = seed;
    for (i = 0; i < 20; ++i) {
        (void)burtle_get_mod(x);
    }
}


uint32_t GetSimplePrng(uint32_t seed) {
    seed *= 0x19660D;
    seed += 0x3C6EF35F;
    return seed;
}
