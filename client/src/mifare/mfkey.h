//-----------------------------------------------------------------------------
// Copyright (C) Roel Verdult 2009
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
// MIFARE Darkside hack
//-----------------------------------------------------------------------------

#ifndef MFKEY_H
#define MFKEY_H

#include "common.h"
#include "mifare.h"

uint32_t nonce2key(uint32_t uid, uint32_t nt, uint32_t nr, uint32_t ar, uint64_t par_info, uint64_t ks_info, uint64_t **keys);
bool mfkey32(nonces_t *data, uint64_t *outputkey);
bool mfkey32_moebius(nonces_t *data, uint64_t *outputkey);
int mfkey64(nonces_t *data, uint64_t *outputkey);

int compare_uint64(const void *a, const void *b);
uint32_t intersection(uint64_t *listA, uint64_t *listB);

#endif
