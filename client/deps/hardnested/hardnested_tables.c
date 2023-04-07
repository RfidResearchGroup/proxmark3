//-----------------------------------------------------------------------------
// Copyright (C) 2015, 2016 by piwi
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Implements a card only attack based on crypto text (encrypted nonces
// received during a nested authentication) only. Unlike other card only
// attacks this doesn't rely on implementation errors but only on the
// inherent weaknesses of the crypto1 cypher. Described in
//   Carlo Meijer, Roel Verdult, "Ciphertext-only Cryptanalysis on Hardened
//   Mifare Classic Cards" in Proceedings of the 22nd ACM SIGSAC Conference on
//   Computer and Communications Security, 2015
//-----------------------------------------------------------------------------
//
// This program calculates tables with possible states for a given
// bitflip property.
//
//-----------------------------------------------------------------------------

// To compile it:
// gcc -I../../../common -I../../../include -o hardnested_tables hardnested_tables.c

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#ifndef __APPLE__
#include <malloc.h>
#endif
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "crapto1/crapto1.h"
#include "parity.h"


#define NUM_PART_SUMS       9
#define BITFLIP_2ND_BYTE    0x0200

typedef enum {
    EVEN_STATE = 0,
    ODD_STATE = 1
} odd_even_t;


static uint16_t PartialSumProperty(uint32_t state, odd_even_t odd_even) {
    uint16_t sum = 0;
    for (uint16_t j = 0; j < 16; j++) {
        uint32_t st = state;
        uint16_t part_sum = 0;
        if (odd_even == ODD_STATE) {
            part_sum ^= filter(st);
            for (uint16_t i = 0; i < 4; i++) {
                st = (st << 1) | ((j >> (3 - i)) & 0x01) ;
                part_sum ^= filter(st);
            }
            part_sum ^= 1; // XOR 1 cancelled out for the other 8 bits
        } else {
            for (uint16_t i = 0; i < 4; i++) {
                st = (st << 1) | ((j >> (3 - i)) & 0x01) ;
                part_sum ^= filter(st);
            }
        }
        sum += part_sum;
    }
    return sum;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// bitarray functions

#if defined (_WIN32)
#define malloc_bitarray(x) __builtin_assume_aligned(_aligned_malloc((x), __BIGGEST_ALIGNMENT__), __BIGGEST_ALIGNMENT__)
#define free_bitarray(x) _aligned_free(x)
#elif defined (__APPLE__)
static void *malloc_bitarray(size_t x) {
    char *allocated_memory;
    if (posix_memalign((void **)&allocated_memory, __BIGGEST_ALIGNMENT__, x)) {
        return NULL;
    } else {
        return __builtin_assume_aligned(allocated_memory, __BIGGEST_ALIGNMENT__);
    }
}
#define free_bitarray(x) free(x)
#else
//#define malloc_bitarray(x) memalign(__BIGGEST_ALIGNMENT__, (x))
#define malloc_bitarray(x) __builtin_assume_aligned(memalign(__BIGGEST_ALIGNMENT__, (x)), __BIGGEST_ALIGNMENT__);
#define free_bitarray(x) free(x)
#endif

static inline void clear_bitarray24(uint32_t *bitarray) {
    memset(bitarray, 0x00, sizeof(uint32_t) * (1 << 19));
}

static inline uint32_t test_bit24(const uint32_t *bitarray, uint32_t index) {
    return bitarray[index >> 5] & (0x80000000 >> (index & 0x0000001f));
}

static inline void set_bit24(uint32_t *bitarray, uint32_t index) {
    bitarray[index >> 5] |= 0x80000000 >> (index & 0x0000001f);
}

static inline uint32_t next_state(const uint32_t *bitset, uint32_t state) {
    if (++state == 1 << 24) {
        return 1 << 24;
    }

    uint32_t index = state >> 5;
    uint_fast8_t bit = state & 0x1f;
    uint32_t line = bitset[index] << bit;
    while (bit <= 0x1f) {
        if (line & 0x80000000) {
            return state;
        }
        state++;
        bit++;
        line <<= 1;
    }

    index++;
    while (bitset[index] == 0x00000000 && state < 1 << 24) {
        index++;
        state += 0x20;
    }

    if (state >= 1 << 24) {
        return 1 << 24;
    }
#if defined __GNUC__
    return state + __builtin_clz(bitset[index]);
#else
    bit = 0x00;
    line = bitset[index];
    while (bit <= 0x1f) {
        if (line & 0x80000000) {
            return state;
        }
        state++;
        bit++;
        line <<= 1;
    }
    return 1 << 24;
#endif
}


static inline uint32_t next_not_state(const uint32_t *bitset, uint32_t state) {
    if (++state == 1 << 24) return 1 << 24;
    uint32_t index = state >> 5;
    uint_fast8_t bit = state & 0x1f;
    uint32_t line = bitset[index] << bit;
    while (bit <= 0x1f) {
        if ((line & 0x80000000) == 0) return state;
        state++;
        bit++;
        line <<= 1;
    }
    index++;
    while (bitset[index] == 0xffffffff && state < 1 << 24) {
        index++;
        state += 0x20;
    }
    if (state >= 1 << 24) return 1 << 24;
#if defined __GNUC__
    return state + __builtin_clz(~bitset[index]);
#else
    bit = 0x00;
    line = bitset[index];
    while (bit <= 0x1f) {
        if ((line & 0x80000000) == 0) return state;
        state++;
        bit++;
        line <<= 1;
    }
    return 1 << 24;
#endif
}


static inline uint32_t bitcount(uint32_t a) {
#if defined __GNUC__
    return __builtin_popcountl(a);
#else
    a = a - ((a >> 1) & 0x55555555);
    a = (a & 0x33333333) + ((a >> 2) & 0x33333333);
    return (((a + (a >> 4)) & 0x0f0f0f0f) * 0x01010101) >> 24;
#endif
}


static inline uint32_t count_states(uint32_t *bitset) {
    uint32_t count = 0;
    for (uint32_t i = 0; i < (1 << 19); i++) {
        count += bitcount(bitset[i]);
    }
    return count;
}


static void write_bitflips_file(odd_even_t odd_even, uint16_t bitflip, int sum_a0, uint32_t *bitset, uint32_t count) {
    char filename[80];
    snprintf(filename, sizeof(filename), "bitflip_%d_%03" PRIx16 "_sum%d_states.bin", odd_even, bitflip, sum_a0);
    FILE *outfile = fopen(filename, "wb");
    fwrite(&count, 1, sizeof(count), outfile);
    fwrite(bitset, 1, sizeof(uint32_t) * (1 << 19), outfile);
    fclose(outfile);
}


uint32_t *restrict part_sum_a0_bitarrays[2][NUM_PART_SUMS];

static void init_part_sum_bitarrays(void) {
    printf("init_part_sum_bitarrays()...");
    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        for (uint16_t part_sum_a0 = 0; part_sum_a0 < NUM_PART_SUMS; part_sum_a0++) {
            part_sum_a0_bitarrays[odd_even][part_sum_a0] = (uint32_t *)malloc_bitarray(sizeof(uint32_t) * (1 << 19));
            if (part_sum_a0_bitarrays[odd_even][part_sum_a0] == NULL) {
                printf("Out of memory error in init_part_suma0_statelists(). Aborting...\n");
                exit(4);
            }
            clear_bitarray24(part_sum_a0_bitarrays[odd_even][part_sum_a0]);
        }
    }
    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        //printf("(%d, %" PRIu16 ")...", odd_even, part_sum_a0);
        for (uint32_t state = 0; state < (1 << 20); state++) {
            uint16_t part_sum_a0 = PartialSumProperty(state, odd_even) / 2;
            for (uint16_t low_bits = 0; low_bits < 1 << 4; low_bits++) {
                set_bit24(part_sum_a0_bitarrays[odd_even][part_sum_a0], state << 4 | low_bits);
            }
        }
    }
    printf("done.\n");
}


static void free_part_sum_bitarrays(void) {
    printf("free_part_sum_bitarrays()...");
    for (int16_t part_sum_a0 = (NUM_PART_SUMS - 1); part_sum_a0 >= 0; part_sum_a0--) {
        free_bitarray(part_sum_a0_bitarrays[ODD_STATE][part_sum_a0]);
    }
    for (int16_t part_sum_a0 = (NUM_PART_SUMS - 1); part_sum_a0 >= 0; part_sum_a0--) {
        free_bitarray(part_sum_a0_bitarrays[EVEN_STATE][part_sum_a0]);
    }
    printf("done.\n");
}

uint32_t *restrict sum_a0_bitarray[2];

void init_sum_bitarray(uint16_t sum_a0) {
    printf("init_sum_bitarray()...\n");
    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        sum_a0_bitarray[odd_even] = (uint32_t *)malloc_bitarray(sizeof(uint32_t) * (1 << 19));
        if (sum_a0_bitarray[odd_even] == NULL) {
            printf("Out of memory error in init_sum_bitarrays(). Aborting...\n");
            exit(4);
        }
        clear_bitarray24(sum_a0_bitarray[odd_even]);
    }
    for (uint8_t p = 0; p < NUM_PART_SUMS; p++) {
        for (uint8_t q = 0; q < NUM_PART_SUMS; q++) {
            if (sum_a0 == 2 * p * (16 - 2 * q) + (16 - 2 * p) * 2 * q) {
                for (uint32_t i = 0; i < (1 << 19); i++) {
                    sum_a0_bitarray[EVEN_STATE][i] |= part_sum_a0_bitarrays[EVEN_STATE][q][i];
                    sum_a0_bitarray[ODD_STATE][i] |= part_sum_a0_bitarrays[ODD_STATE][p][i];
                }
            }
        }
    }
    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        uint32_t count = count_states(sum_a0_bitarray[odd_even]);
        printf("sum_a0_bitarray[%s] has %u states (%5.2f%%)\n", odd_even == EVEN_STATE ? "even" : "odd ", count, (float)count / (1 << 24) * 100.0);
    }
    printf("done.\n");
}


static void free_sum_bitarray(void) {
    printf("free_sum_bitarray()...");
    free_bitarray(sum_a0_bitarray[ODD_STATE]);
    free_bitarray(sum_a0_bitarray[EVEN_STATE]);
    printf("done.\n");
}


static void precalculate_bit0_bitflip_bitarrays(uint8_t const bitflip, uint16_t const sum_a0) {
    // #define TEST_RUN
#ifdef TEST_RUN
#define NUM_TEST_STATES (1<<10)
#else
#define NUM_TEST_STATES (1<<23)
#endif

    time_t start_time = time(NULL);
    time_t last_check_time = start_time;

    uint32_t *restrict test_bitarray[2];
    uint32_t *restrict test_not_bitarray[2];

    test_bitarray[EVEN_STATE] = malloc_bitarray(sizeof(uint32_t) * (1 << 19));
    clear_bitarray24(test_bitarray[EVEN_STATE]);
    test_bitarray[ODD_STATE] = malloc_bitarray(sizeof(uint32_t) * (1 << 19));
    clear_bitarray24(test_bitarray[ODD_STATE]);

    test_not_bitarray[EVEN_STATE] = malloc_bitarray(sizeof(uint32_t) * (1 << 19));
    clear_bitarray24(test_not_bitarray[EVEN_STATE]);
    test_not_bitarray[ODD_STATE] = malloc_bitarray(sizeof(uint32_t) * (1 << 19));
    clear_bitarray24(test_not_bitarray[ODD_STATE]);

    uint32_t count[2];
    bool all_odd_states_are_possible_for_notbitflip = false;

    printf("\n\nStarting search for crypto1 states resulting in bitflip property 0x%03x...\n", bitflip);
    for (uint32_t even_state = next_state(sum_a0_bitarray[EVEN_STATE], -1); even_state < NUM_TEST_STATES; even_state = next_state(sum_a0_bitarray[EVEN_STATE], even_state)) {
        bool even_state_is_possible = false;
        time_t time_now = time(NULL);
        if (difftime(time_now, last_check_time) > 5 * 60) { // print status every 5 minutes
            float runtime = difftime(time_now, start_time);
            float remaining_time = runtime * ((1 << 23) - even_state) / even_state;
            printf("\n%1.1f hours elapsed, expected completion in %1.1f hours (%1.1f days)", runtime / 3600, remaining_time / 3600, remaining_time / 3600 / 24);
            last_check_time = time_now;
        }
        for (uint32_t odd_state = next_state(sum_a0_bitarray[ODD_STATE], -1); odd_state < (1 << 24); odd_state = next_state(test_bitarray[ODD_STATE], odd_state)) {
            if (even_state_is_possible && test_bit24(test_bitarray[ODD_STATE], odd_state)) continue;
            // load crypto1 state
            struct Crypto1State cs;
            cs.odd = odd_state >> 4;
            cs.even = even_state >> 4;

            // track flipping bits in state
            struct Crypto1DeltaState {
                uint_fast8_t odd;
                uint_fast8_t even;
            } cs_delta;
            cs_delta.odd = 0;
            cs_delta.even = 0;

            uint_fast16_t keystream = 0;

            // decrypt 9 bits
            for (int i = 0; i < 9; i++) {
                uint_fast8_t keystream_bit = filter(cs.odd & 0x000fffff) ^ filter((cs.odd & 0x000fffff) ^ cs_delta.odd);
                keystream = keystream << 1 | keystream_bit;
                uint_fast8_t nt_bit = BIT(bitflip, i) ^ keystream_bit;
                uint_fast8_t LSFR_feedback = BIT(cs_delta.odd, 2) ^ BIT(cs_delta.even, 2) ^ BIT(cs_delta.odd, 3);

                cs_delta.even = cs_delta.even << 1 | (LSFR_feedback ^ nt_bit);
                uint_fast8_t tmp = cs_delta.odd;
                cs_delta.odd = cs_delta.even;
                cs_delta.even = tmp;

                cs.even = cs.odd;
                if (i & 1) {
                    cs.odd = odd_state >> (7 - i) / 2;
                } else {
                    cs.odd = even_state >> (7 - i) / 2;
                }
            }

            if (evenparity32(keystream) == evenparity32(bitflip)) {
                // found valid bitflip state
                even_state_is_possible = true;
                set_bit24(test_bitarray[EVEN_STATE], even_state);
                set_bit24(test_bitarray[EVEN_STATE], 1 << 23 | even_state);
                set_bit24(test_bitarray[ODD_STATE], odd_state);
            } else {
                // found valid !bitflip state
                set_bit24(test_not_bitarray[EVEN_STATE], even_state);
                set_bit24(test_not_bitarray[EVEN_STATE], 1 << 23 | even_state);
                set_bit24(test_not_bitarray[ODD_STATE], odd_state);
            }
        }
        if (!even_state_is_possible) {
            all_odd_states_are_possible_for_notbitflip = true;
        }
    }

    printf("\nAnalysis completed. Checking for effective bitflip properties...\n");
    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        count[odd_even] = count_states(test_bitarray[odd_even]);
        if (count[odd_even] != 1 << 24) {
            printf("Writing %u possible %s states for bitflip property %03x (%u (%1.2f%%) states eliminated)\n",
                   count[odd_even],
                   odd_even == EVEN_STATE ? "even" : "odd",
                   bitflip,
                   (1 << 24) - count[odd_even],
                   (float)((1 << 24) - count[odd_even]) / (1 << 24) * 100.0);
#ifndef TEST_RUN
            write_bitflips_file(odd_even, bitflip, sum_a0, test_bitarray[odd_even], count[odd_even]);
#endif
        } else {
            printf("All %s states for bitflip property %03x are possible. No file written.\n", odd_even == EVEN_STATE ? "even" : "odd", bitflip);
        }
    }
    uint32_t *restrict test_bitarray_2nd = malloc_bitarray(sizeof(uint32_t) * (1 << 19));
    clear_bitarray24(test_bitarray_2nd);
    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        if (count[odd_even] != 1 << 24) {
            for (uint32_t state = 0; state < (1 << 24); state += 1 << 4) {
                uint32_t line = test_bitarray[odd_even][state >> 5];
                uint16_t half_line = (state & 0x000000010) ? line & 0x0000ffff : line >> 16;
                if (half_line != 0) {
                    for (uint32_t low_bits = 0; low_bits < (1 << 4); low_bits++) {
                        set_bit24(test_bitarray_2nd, low_bits << 20 | state >> 4);
                    }
                }
            }
            count[odd_even] = count_states(test_bitarray_2nd);
            if (count[odd_even] != 1 << 24) {
                printf("Writing %u possible %s states for bitflip property %03x (%u (%1.2f%%) states eliminated)\n",
                       count[odd_even],
                       odd_even == EVEN_STATE ? "even" : "odd",
                       bitflip | BITFLIP_2ND_BYTE,
                       (1 << 24) - count[odd_even],
                       (float)((1 << 24) - count[odd_even]) / (1 << 24) * 100.0);
#ifndef TEST_RUN
                write_bitflips_file(odd_even, bitflip | BITFLIP_2ND_BYTE, sum_a0, test_bitarray_2nd, count[odd_even]);
#endif
            } else {
                printf("All %s states for bitflip property %03x are possible. No file written.\n", odd_even == EVEN_STATE ? "even" : "odd", bitflip | BITFLIP_2ND_BYTE);
            }
        } else {
            printf("All %s states for bitflip property %03x are possible. No file written.\n", odd_even == EVEN_STATE ? "even" : "odd", bitflip | BITFLIP_2ND_BYTE);
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // second run for the remaining "not bitflip" states
    printf("\n\nStarting search for crypto1 states resulting in bitflip property 0x%03x...", bitflip | 0x100);
    start_time = time(NULL);
    last_check_time = start_time;
    for (uint32_t even_state = next_state(sum_a0_bitarray[EVEN_STATE], -1); even_state < NUM_TEST_STATES; even_state = next_state(sum_a0_bitarray[EVEN_STATE], even_state)) {
        bool even_state_is_possible = test_bit24(test_not_bitarray[EVEN_STATE], even_state);
        time_t time_now = time(NULL);
        if (difftime(time_now, last_check_time) > 5 * 60) { // print status every 5 minutes
            float runtime = difftime(time_now, start_time);
            float remaining_time = runtime * ((1 << 23) - even_state) / even_state;
            printf("\n%1.1f hours elapsed, expected completion in %1.1f hours (%1.1f days)", runtime / 3600, remaining_time / 3600, remaining_time / 3600 / 24);
            last_check_time = time_now;
        }
        for (uint32_t odd_state = next_state(sum_a0_bitarray[ODD_STATE], -1); odd_state < (1 << 24); odd_state = next_state(sum_a0_bitarray[ODD_STATE], odd_state)) {
            if (even_state_is_possible) {
                if (all_odd_states_are_possible_for_notbitflip) break;
                if (test_bit24(test_not_bitarray[ODD_STATE], odd_state)) continue;
            }
            // load crypto1 state
            struct Crypto1State cs;
            cs.odd = odd_state >> 4;
            cs.even = even_state >> 4;

            // track flipping bits in state
            struct Crypto1DeltaState {
                uint_fast8_t odd;
                uint_fast8_t even;
            } cs_delta;
            cs_delta.odd = 0;
            cs_delta.even = 0;

            uint_fast16_t keystream = 0;
            // uint_fast16_t nt = 0;

            // decrypt 9 bits
            for (int i = 0; i < 9; i++) {
                uint_fast8_t keystream_bit = filter(cs.odd & 0x000fffff) ^ filter((cs.odd & 0x000fffff) ^ cs_delta.odd);
                keystream = keystream << 1 | keystream_bit;
                uint_fast8_t nt_bit = BIT(bitflip | 0x100, i) ^ keystream_bit;
                uint_fast8_t LSFR_feedback = BIT(cs_delta.odd, 2) ^ BIT(cs_delta.even, 2) ^ BIT(cs_delta.odd, 3);

                cs_delta.even = cs_delta.even << 1 | (LSFR_feedback ^ nt_bit);
                uint_fast8_t tmp = cs_delta.odd;
                cs_delta.odd = cs_delta.even;
                cs_delta.even = tmp;

                cs.even = cs.odd;
                if (i & 1) {
                    cs.odd = odd_state >> (7 - i) / 2;
                } else {
                    cs.odd = even_state >> (7 - i) / 2;
                }
            }

            if (evenparity32(keystream) != evenparity32(bitflip)) {
                // found valid !bitflip state
                even_state_is_possible = true;
                set_bit24(test_not_bitarray[EVEN_STATE], even_state);
                set_bit24(test_not_bitarray[EVEN_STATE], 1 << 23 | even_state);
                set_bit24(test_not_bitarray[ODD_STATE], odd_state);
            }
        }
    }

    printf("\nAnalysis completed. Checking for effective !bitflip properties...\n");
    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        count[odd_even] = count_states(test_not_bitarray[odd_even]);
        if (count[odd_even] != 1 << 24) {
            printf("Writing %u possible %s states for bitflip property %03x (%u (%1.2f%%) states eliminated)\n",
                   count[odd_even],
                   odd_even == EVEN_STATE ? "even" : "odd",
                   bitflip | 0x100,
                   (1 << 24) - count[odd_even],
                   (float)((1 << 24) - count[odd_even]) / (1 << 24) * 100.0);
#ifndef TEST_RUN
            write_bitflips_file(odd_even, bitflip | 0x100, sum_a0, test_not_bitarray[odd_even], count[odd_even]);
#endif
        } else {
            printf("All %s states for bitflip property %03x are possible. No file written.\n", odd_even == EVEN_STATE ? "even" : "odd", bitflip | 0x100);
        }
    }

    clear_bitarray24(test_bitarray_2nd);
    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        if (count[odd_even] != 1 << 24) {
            for (uint32_t state = 0; state < (1 << 24); state += 1 << 4) {
                uint32_t line = test_not_bitarray[odd_even][state >> 5];
                uint16_t half_line = (state & 0x000000010) ? line & 0x0000ffff : line >> 16;
                if (half_line != 0) {
                    for (uint32_t low_bits = 0; low_bits < (1 << 4); low_bits++) {
                        set_bit24(test_bitarray_2nd, low_bits << 20 | state >> 4);
                    }
                }
            }
            count[odd_even] = count_states(test_bitarray_2nd);
            if (count[odd_even] != 1 << 24) {
                printf("Writing %u possible %s states for bitflip property %03x (%u (%1.2f%%) states eliminated)\n",
                       count[odd_even],
                       odd_even == EVEN_STATE ? "even" : "odd",
                       bitflip | 0x100 | BITFLIP_2ND_BYTE,
                       (1 << 24) - count[odd_even],
                       (float)((1 << 24) - count[odd_even]) / (1 << 24) * 100.0);
#ifndef TEST_RUN
                write_bitflips_file(odd_even, bitflip | 0x100 | BITFLIP_2ND_BYTE, sum_a0, test_bitarray_2nd, count[odd_even]);
#endif
            } else {
                printf("All %s states for bitflip property %03x are possible. No file written.\n", odd_even == EVEN_STATE ? "even" : "odd", bitflip | 0x100 | BITFLIP_2ND_BYTE);
            }
        } else {
            printf("All %s states for bitflip property %03x are possible. No file written.\n", odd_even == EVEN_STATE ? "even" : "odd", bitflip | 0x100 | BITFLIP_2ND_BYTE);
        }
    }

    free_bitarray(test_bitarray_2nd);
    free_bitarray(test_not_bitarray[ODD_STATE]);
    free_bitarray(test_not_bitarray[EVEN_STATE]);
    free_bitarray(test_bitarray[ODD_STATE]);
    free_bitarray(test_bitarray[EVEN_STATE]);
    exit(0);
}


int main(int argc, char *argv[]) {

    unsigned int bitflip_in;
    int sum_a0 = 0;

    printf("Create tables required by hardnested attack.\n");
    printf("Expect a runtime in the range of days or weeks.\n");
    printf("Single thread only. If you want to use several threads, start it multiple times :-)\n\n");

    if (argc != 2 && argc != 3) {
        printf(" syntax: %s <bitflip property> [<Sum_a0>]\n\n", argv[0]);
        printf(" example: %s 1f\n", argv[0]);
        return 1;
    }

    sscanf(argv[1], "%x", &bitflip_in);

    if (bitflip_in > 255) {
        printf("Bitflip property must be less than or equal to 0xff\n\n");
        return 1;
    }

    if (argc == 3) {
        sscanf(argv[2], "%d", &sum_a0);
    }

    switch (sum_a0) {
        case  0:
        case  32:
        case  56:
        case  64:
        case  80:
        case  96:
        case  104:
        case  112:
        case  120:
        case  128:
        case  136:
        case  144:
        case  152:
        case  160:
        case  176:
        case  192:
        case  200:
        case  224:
        case  256:
            break;
        default:
            sum_a0 = -1;
    }

    printf("Calculating for bitflip = %02x, sum_a0 = %d\n", bitflip_in, sum_a0);

    init_part_sum_bitarrays();
    init_sum_bitarray(sum_a0);

    precalculate_bit0_bitflip_bitarrays(bitflip_in, sum_a0);

    free_sum_bitarray();
    free_part_sum_bitarrays();

    return 0;
}
