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

#ifndef __PRNG_H
#define __PRNG_H

#include "common.h"

typedef struct {
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
} prng_ctx_t;

//uint32_t burtle_get( prng_ctx_t *x );
uint32_t burtle_get_mod(prng_ctx_t *x);
void burtle_init_mod(prng_ctx_t *x, uint32_t seed);
void burtle_init(prng_ctx_t *x, uint32_t seed);

uint32_t GetSimplePrng(uint32_t seed);

#endif /* __PRNG_H */
