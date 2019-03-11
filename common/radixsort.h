#ifndef RADIXSORT_H__
#define RADIXSORT_H__

#include <string.h>
#include <stdint.h>
#include <stdlib.h>

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
