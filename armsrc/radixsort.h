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
#ifndef RADIXSORT_H__
#define RADIXSORT_H__

#include "common.h"

typedef union {
    struct {
        uint32_t c8[256];
        uint32_t c7[256];
        uint32_t c6[256];
        uint32_t c5[256];
        uint32_t c4[256];
        uint32_t c3[256];
        uint32_t c2[256];
        uint32_t c1[256];
    };
    uint32_t counts[256 * 8];
} rscounts_t;

uint64_t *radixSort(uint64_t *array, uint32_t size);

#endif // RADIXSORT_H__
