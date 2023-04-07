#include "randoms.h"
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>

// linear congruential generator (LCG)
//
// ref
// https://en.wikipedia.org/wiki/Linear_congruential_generator#Parameters_in_common_use

void make_key_borland_n(uint32_t seed, uint8_t key[], const size_t keylen) {

    uint32_t lseed = ((seed * 22695477U) + 1) % UINT_MAX;

    for (int i = 0; i < keylen; i++) {
        lseed = ((lseed * 22695477U) + 1) % UINT_MAX;
        key[i] = ((lseed >> 16) & 0x7fff) % 0xFF;
    }
}

void make_key_recipies_n(uint32_t seed, uint8_t key[], const size_t keylen) {

    //uint32_t lseed = ((seed * 1664525) + 1013904223) % UINT_MAX;
    uint32_t lseed = seed;

    for (int i = 0; i < keylen; i++) {
        lseed = ((lseed * 1664525U) + 1013904223U) % UINT_MAX;
        key[i] = (lseed % 0xFF);
    }
}

void make_key_glibc_n(uint32_t seed, uint8_t key[], const size_t keylen) {

    //uint32_t lseed = ((seed * 1103515245) + 12345) % 0x7fffffff;
    uint32_t lseed = seed;


    for (int i = 0; i < keylen; i++) {
        lseed = ((lseed * 1103515245U) + 12345U) & 0x7fffffff;
        key[i] = (lseed & 0xFF);
    }
}

void make_key_ansic_n(uint32_t seed, uint8_t key[], const size_t keylen) {

    //uint32_t lseed = ((seed * 1103515245) + 12345) % 0x7fffffff;
    uint32_t lseed = seed;

    for (int i = 0; i < keylen; i++) {
        lseed = ((lseed * 1103515245U) + 12345U) & 0x7fffffff;
        key[i] = ((lseed >> 16) & 0x7fff) & 0xFF;
    }
}

void make_key_turbopascal_n(uint32_t seed, uint8_t key[], const size_t keylen) {

    //uint32_t lseed = ((seed * 134775813 ) + 1 ) % UINT_MAX;
    uint32_t lseed = seed;

    for (int i = 0; i < keylen; i++) {
        lseed = ((lseed * 134775813) + 1) % UINT_MAX;
        key[i] = (lseed % 0xFF);
    }
}

/* This algorithm is mentioned in the ISO C standard, here extended
   for 32 bits.  */
void make_key_posix_rand_r_n(uint32_t seed, uint8_t key[], const size_t keylen) {

    uint32_t lseed = seed;

    for (int i = 0; i < keylen; i++) {

        lseed *= 1103515245;
        lseed += 12345;
        int result = (uint16_t)(lseed / 0x10000) % 2048;

        lseed *= 1103515245;
        lseed += 12345;
        result <<= 10;
        result ^= (uint16_t)(lseed / 0x10000) % 1024;

        lseed *= 1103515245;
        lseed += 12345;
        result <<= 10;
        result ^= (uint16_t)(lseed / 0x10000) % 1024;

        key[i] = (result % 0xFF);
    }
}

// Microsoft C runtime lib rand
void make_key_ms_rand_r_n(uint32_t seed, uint8_t key[], const size_t keylen) {

    uint32_t lseed = seed;

    for (int i = 0; i < keylen; i++) {
        lseed = ((lseed * 214013L) + 2531011L);
        key[i] = ((lseed >> 16) & 0x7FFF);
    }
}
