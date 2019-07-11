#ifndef BUCKETSORT_H__
#define BUCKETSORT_H__

#include <stdint.h>
#include <stdlib.h>

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
