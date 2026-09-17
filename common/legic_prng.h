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
// LEGIC's obfuscation function
//-----------------------------------------------------------------------------

#ifndef __LEGIC_PRNG_H
#define __LEGIC_PRNG_H

#include "common.h"

void legic_prng_init(uint8_t iv);
void legic_prng_forward(int count);
uint8_t legic_prng_get_bit(void);
uint32_t legic_prng_get_bits(uint8_t len);

#endif

