#include "radixsort.h"

uint64_t *radixSort(uint64_t *array, uint32_t size) {
    rscounts_t counts;
    memset(&counts, 0, 256 * 8 * sizeof(uint32_t));
    uint64_t *cpy = (uint64_t *)calloc(size * sizeof(uint64_t), sizeof(uint8_t));
    uint32_t o8 = 0, o7 = 0, o6 = 0, o5 = 0, o4 = 0, o3 = 0, o2 = 0, o1 = 0;
    uint32_t t8, t7, t6, t5, t4, t3, t2, t1;
    uint32_t x;
    // calculate counts
    for (x = 0; x < size; ++x) {
        t8 = array[x] & 0xff;
        t7 = (array[x] >> 8) & 0xff;
        t6 = (array[x] >> 16) & 0xff;
        t5 = (array[x] >> 24) & 0xff;
        t4 = (array[x] >> 32) & 0xff;
        t3 = (array[x] >> 40) & 0xff;
        t2 = (array[x] >> 48) & 0xff;
        t1 = (array[x] >> 56) & 0xff;
        counts.c8[t8]++;
        counts.c7[t7]++;
        counts.c6[t6]++;
        counts.c5[t5]++;
        counts.c4[t4]++;
        counts.c3[t3]++;
        counts.c2[t2]++;
        counts.c1[t1]++;
    }
    // convert counts to offsets
    for (x = 0; x < 256; ++x) {
        t8 = o8 + counts.c8[x];
        t7 = o7 + counts.c7[x];
        t6 = o6 + counts.c6[x];
        t5 = o5 + counts.c5[x];
        t4 = o4 + counts.c4[x];
        t3 = o3 + counts.c3[x];
        t2 = o2 + counts.c2[x];
        t1 = o1 + counts.c1[x];
        counts.c8[x] = o8;
        counts.c7[x] = o7;
        counts.c6[x] = o6;
        counts.c5[x] = o5;
        counts.c4[x] = o4;
        counts.c3[x] = o3;
        counts.c2[x] = o2;
        counts.c1[x] = o1;
        o8 = t8;
        o7 = t7;
        o6 = t6;
        o5 = t5;
        o4 = t4;
        o3 = t3;
        o2 = t2;
        o1 = t1;
    }
    // radix
    for (x = 0; x < size; ++x) {
        t8 = array[x] & 0xff;
        cpy[counts.c8[t8]] = array[x];
        counts.c8[t8]++;
    }
    for (x = 0; x < size; ++x) {
        t7 = (cpy[x] >> 8) & 0xff;
        array[counts.c7[t7]] = cpy[x];
        counts.c7[t7]++;
    }
    for (x = 0; x < size; ++x) {
        t6 = (array[x] >> 16) & 0xff;
        cpy[counts.c6[t6]] = array[x];
        counts.c6[t6]++;
    }
    for (x = 0; x < size; ++x) {
        t5 = (cpy[x] >> 24) & 0xff;
        array[counts.c5[t5]] = cpy[x];
        counts.c5[t5]++;
    }
    for (x = 0; x < size; ++x) {
        t4 = (array[x] >> 32) & 0xff;
        cpy[counts.c4[t4]] = array[x];
        counts.c4[t4]++;
    }
    for (x = 0; x < size; ++x) {
        t3 = (cpy[x] >> 40) & 0xff;
        array[counts.c3[t3]] = cpy[x];
        counts.c3[t3]++;
    }
    for (x = 0; x < size; ++x) {
        t2 = (array[x] >> 48) & 0xff;
        cpy[counts.c2[t2]] = array[x];
        counts.c2[t2]++;
    }
    for (x = 0; x < size; ++x) {
        t1 = (cpy[x] >> 56) & 0xff;
        array[counts.c1[t1]] = cpy[x];
        counts.c1[t1]++;
    }
    free(cpy);
    return array;
}
