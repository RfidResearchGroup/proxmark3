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
#ifndef BUCKETSORT_H__
#define BUCKETSORT_H__

#include "common.h"

typedef struct bucket {
    uint32_t *head;
    uint32_t *bp;
} bucket_t;

typedef bucket_t bucket_array_t[2][0x100];

typedef struct bucket_info {
    struct {
        uint32_t *head, *tail;
    } bucket_info[2][0x100];
    uint32_t numbuckets;
} bucket_info_t;

void bucket_sort_intersect(uint32_t *const estart, uint32_t *const estop,
                           uint32_t *const ostart, uint32_t *const ostop,
                           bucket_info_t *bucket_info, bucket_array_t bucket);

#endif
