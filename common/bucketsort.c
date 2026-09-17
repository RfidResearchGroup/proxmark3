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
#include "bucketsort.h"

extern void bucket_sort_intersect(uint32_t *const estart, uint32_t *const estop,
                                  uint32_t *const ostart, uint32_t *const ostop,
                                  bucket_info_t *bucket_info, bucket_array_t bucket) {
    uint32_t *p1, *p2;
    uint32_t *start[2];
    uint32_t *stop[2];

    start[0] = estart;
    stop[0] = estop;
    start[1] = ostart;
    stop[1] = ostop;

    // init buckets to be empty
    for (uint32_t i = 0; i < 2; i++) {
        for (uint32_t j = 0x00; j <= 0xff; j++) {
            bucket[i][j].bp = bucket[i][j].head;
        }
    }

    // sort the lists into the buckets based on the MSB (contribution bits)
    for (uint32_t i = 0; i < 2; i++) {
        for (p1 = start[i]; p1 <= stop[i]; p1++) {
            uint32_t bucket_index = (*p1 & 0xff000000) >> 24;
            *(bucket[i][bucket_index].bp++) = *p1;
        }
    }

    // write back intersecting buckets as sorted list.
    // fill in bucket_info with head and tail of the bucket contents in the list and number of non-empty buckets.
    for (uint32_t i = 0; i < 2; i++) {
        p1 = start[i];
        uint32_t nonempty_bucket = 0;
        for (uint32_t j = 0x00; j <= 0xff; j++) {
            if (bucket[0][j].bp != bucket[0][j].head && bucket[1][j].bp != bucket[1][j].head) { // non-empty intersecting buckets only
                bucket_info->bucket_info[i][nonempty_bucket].head = p1;
                for (p2 = bucket[i][j].head; p2 < bucket[i][j].bp; *p1++ = *p2++);
                bucket_info->bucket_info[i][nonempty_bucket].tail = p1 - 1;
                nonempty_bucket++;
            }
        }
        bucket_info->numbuckets = nonempty_bucket;
    }
}
