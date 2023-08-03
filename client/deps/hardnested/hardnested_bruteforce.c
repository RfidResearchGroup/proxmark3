//-----------------------------------------------------------------------------
// Copyright (C) 2016, 2017 by piwi
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
// brute forcing is based on @aczids bitsliced brute forcer
// https://github.com/aczid/crypto1_bs with some modifications. Mainly:
// - don't rollback. Start with 2nd byte of nonce instead
// - reuse results of filter subfunctions
// - reuse results of previous nonces if some first bits are identical
//
//-----------------------------------------------------------------------------
// aczid's Copyright notice:
//
// Bit-sliced Crypto-1 brute-forcing implementation
// Builds on the data structures returned by CraptEV1 craptev1_get_space(nonces, threshold, uid)
/*
Copyright (c) 2015-2016 Aram Verstegen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include "hardnested_bruteforce.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "proxmark3.h"
#include "cmdhfmfhard.h"
#include "hardnested_bf_core.h"
#include "ui.h"
#include "util.h"
#include "util_posix.h"
#include "crapto1/crapto1.h"
#include "parity.h"
#include "fileutils.h"
#include "pm3_cmd.h"

#define NUM_BRUTE_FORCE_THREADS         (num_CPUs())
#define DEFAULT_BRUTE_FORCE_RATE        (120000000.0) // if benchmark doesn't succeed
#define TEST_BENCH_SIZE                 (6000)        // number of odd and even states for brute force benchmark
#define TEST_BENCH_FILENAME             "hardnested_bf_bench_data.bin"
//#define WRITE_BENCH_FILE

// debugging options
#define DEBUG_KEY_ELIMINATION           1
// #define DEBUG_BRUTE_FORCE

#define MIN_BUCKETS_SIZE                128

typedef enum {
    EVEN_STATE = 0,
    ODD_STATE = 1
} odd_even_t;

static uint32_t nonces_to_bruteforce = 0;
static uint32_t bf_test_nonce[256];
static uint8_t bf_test_nonce_2nd_byte[256];
static uint8_t bf_test_nonce_par[256];
static uint32_t bucket_count = 0;
static size_t buckets_allocated = 0;
static statelist_t **buckets = NULL;
static uint32_t keys_found = 0;
static uint64_t num_keys_tested;
static uint64_t found_bs_key = 0;

uint8_t trailing_zeros(uint8_t byte) {
    static const uint8_t trailing_zeros_LUT[256] = {
        8, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
        4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
        5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
        4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
        6, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
        4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
        5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
        4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
        7, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
        4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
        5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
        4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
        6, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
        4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
        5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
        4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0
    };

    return trailing_zeros_LUT[byte];
}


bool verify_key(uint32_t cuid, noncelist_t *nonces, const uint8_t *best_first_bytes, uint32_t odd, uint32_t even) {
    struct Crypto1State pcs;
    for (uint16_t test_first_byte = 1; test_first_byte < 256; test_first_byte++) {
        noncelistentry_t *test_nonce = nonces[best_first_bytes[test_first_byte]].first;
        while (test_nonce != NULL) {
            pcs.odd = odd;
            pcs.even = even;
            lfsr_rollback_byte(&pcs, (cuid >> 24) ^ best_first_bytes[0], true);
            for (int8_t byte_pos = 3; byte_pos >= 0; byte_pos--) {
                uint8_t test_par_enc_bit = (test_nonce->par_enc >> byte_pos) & 0x01;     // the encoded parity bit
                uint8_t test_byte_enc = (test_nonce->nonce_enc >> (8 * byte_pos)) & 0xff; // the encoded nonce byte
                uint8_t test_byte_dec = crypto1_byte(&pcs, test_byte_enc /* ^ (cuid >> (8*byte_pos)) */, true) ^ test_byte_enc; // decode the nonce byte
                uint8_t ks_par = filter(pcs.odd);                                        // the keystream bit to encode/decode the parity bit
                uint8_t test_par_enc2 = ks_par ^ evenparity8(test_byte_dec);             // determine the decoded byte's parity and encode it
                if (test_par_enc_bit != test_par_enc2) {
                    return false;
                }
            }
            test_nonce = test_nonce->next;
        }
    }
    return true;
}
static void *
#ifdef __has_attribute
#if __has_attribute(force_align_arg_pointer)
__attribute__((force_align_arg_pointer))
#endif
#endif
crack_states_thread(void *x) {
    struct arg {
        bool silent;
        int thread_ID;
        uint32_t cuid;
        uint32_t num_acquired_nonces;
        uint64_t maximum_states;
        noncelist_t *nonces;
        uint8_t *best_first_bytes;
    } *thread_arg;

    const int num_brute_force_threads = NUM_BRUTE_FORCE_THREADS;
    thread_arg = (struct arg *)x;
    const int thread_id = thread_arg->thread_ID;
    uint32_t current_bucket = thread_id;
    while (current_bucket < bucket_count) {
        statelist_t *bucket = buckets[current_bucket];
        if (bucket) {
#if defined (DEBUG_BRUTE_FORCE)
            PrintAndLogEx(INFO, "Thread " _YELLOW_("%u") " starts working on bucket " _YELLOW_("%u") "\n", thread_id, current_bucket);
#endif
            const uint64_t key = crack_states_bitsliced(thread_arg->cuid, thread_arg->best_first_bytes, bucket, &keys_found, &num_keys_tested, nonces_to_bruteforce, bf_test_nonce_2nd_byte, thread_arg->nonces);
            if (key != -1) {
                __atomic_fetch_add(&keys_found, 1, __ATOMIC_SEQ_CST);
                __atomic_fetch_add(&found_bs_key, key, __ATOMIC_SEQ_CST);

                char progress_text[80];
                char keystr[19];
                snprintf(keystr, sizeof(keystr), "%012" PRIX64 "  ", key);
                snprintf(progress_text, sizeof(progress_text), "Brute force phase completed.  Key found: " _GREEN_("%s"), keystr);
                hardnested_print_progress(thread_arg->num_acquired_nonces, progress_text, 0.0, 0);
                break;
            } else if (keys_found) {
                break;
            } else {
                if (!thread_arg->silent) {
                    char progress_text[80];
                    snprintf(progress_text, sizeof(progress_text), "Brute force phase: %6.02f%%  ", 100.0 * (float)num_keys_tested / (float)(thread_arg->maximum_states));
                    float remaining_bruteforce = thread_arg->nonces[thread_arg->best_first_bytes[0]].expected_num_brute_force - (float)num_keys_tested / 2;
                    hardnested_print_progress(thread_arg->num_acquired_nonces, progress_text, remaining_bruteforce, 5000);
                }
            }
        }
        current_bucket += num_brute_force_threads;
    }
    return NULL;
}


void prepare_bf_test_nonces(noncelist_t *nonces, uint8_t best_first_byte) {
    // we do bitsliced brute forcing with best_first_bytes[0] only.
    // Extract the corresponding 2nd bytes
    noncelistentry_t *test_nonce = nonces[best_first_byte].first;
    uint32_t i = 0;
    while (test_nonce != NULL) {
        bf_test_nonce[i] = test_nonce->nonce_enc;
        bf_test_nonce_par[i] = test_nonce->par_enc;
        bf_test_nonce_2nd_byte[i] = (test_nonce->nonce_enc >> 16) & 0xff;
        test_nonce = test_nonce->next;
        i++;
    }
    nonces_to_bruteforce = i;

    // printf("Nonces to bruteforce: %d\n", nonces_to_bruteforce);
    // printf("Common bits of first 4 2nd nonce bytes (before sorting): %u %u %u\n",
    // trailing_zeros(bf_test_nonce_2nd_byte[1] ^ bf_test_nonce_2nd_byte[0]),
    // trailing_zeros(bf_test_nonce_2nd_byte[2] ^ bf_test_nonce_2nd_byte[1]),
    // trailing_zeros(bf_test_nonce_2nd_byte[3] ^ bf_test_nonce_2nd_byte[2]));

    uint8_t best_4[4] = {0};
    int sum_best = -1;
    for (uint32_t n1 = 0; n1 < nonces_to_bruteforce; n1++) {
        for (uint32_t n2 = 0; n2 < nonces_to_bruteforce; n2++) {
            if (n2 != n1) {
                for (uint32_t n3 = 0; n3 < nonces_to_bruteforce; n3++) {
                    if ((n3 != n2 && n3 != n1) || nonces_to_bruteforce < 3
                            // && trailing_zeros(bf_test_nonce_2nd_byte[n1] ^ bf_test_nonce_2nd_byte[n2])
                            // > trailing_zeros(bf_test_nonce_2nd_byte[n2] ^ bf_test_nonce_2nd_byte[n3])
                       ) {
                        for (uint32_t n4 = 0; n4 < nonces_to_bruteforce; n4++) {
                            if ((n4 != n3 && n4 != n2 && n4 != n1) || nonces_to_bruteforce < 4
                                    // && trailing_zeros(bf_test_nonce_2nd_byte[n2] ^ bf_test_nonce_2nd_byte[n3])
                                    // > trailing_zeros(bf_test_nonce_2nd_byte[n3] ^ bf_test_nonce_2nd_byte[n4])
                               ) {
                                int sum = nonces_to_bruteforce > 1 ? trailing_zeros(bf_test_nonce_2nd_byte[n1] ^ bf_test_nonce_2nd_byte[n2]) : 0.0
                                          + nonces_to_bruteforce > 2 ? trailing_zeros(bf_test_nonce_2nd_byte[n2] ^ bf_test_nonce_2nd_byte[n3]) : 0.0
                                          + nonces_to_bruteforce > 3 ? trailing_zeros(bf_test_nonce_2nd_byte[n3] ^ bf_test_nonce_2nd_byte[n4]) : 0.0;
                                if (sum > sum_best) {
                                    sum_best = sum;
                                    best_4[0] = n1;
                                    best_4[1] = n2;
                                    best_4[2] = n3;
                                    best_4[3] = n4;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    uint32_t bf_test_nonce_temp[4];
    uint8_t bf_test_nonce_par_temp[4];
    uint8_t bf_test_nonce_2nd_byte_temp[4];
    for (uint32_t j = 0; j < 4 && j < nonces_to_bruteforce; j++) {
        bf_test_nonce_temp[j] = bf_test_nonce[best_4[j]];

        bf_test_nonce_par_temp[j] = bf_test_nonce_par[best_4[j]];
        bf_test_nonce_2nd_byte_temp[j] = bf_test_nonce_2nd_byte[best_4[j]];
    }
    for (uint32_t j = 0; j < 4 && j < nonces_to_bruteforce; j++) {
        bf_test_nonce[j] = bf_test_nonce_temp[j];
        bf_test_nonce_par[j] = bf_test_nonce_par_temp[j];
        bf_test_nonce_2nd_byte[j] = bf_test_nonce_2nd_byte_temp[j];
    }
}


#if defined (WRITE_BENCH_FILE)
static void write_benchfile(statelist_t *candidates) {

    PrintAndLogEx(NORMAL, "Writing brute force benchmark data in " RESOURCES_SUBDIR " subdirectory...");
    FILE *benchfile = fopen(RESOURCES_SUBDIR TEST_BENCH_FILENAME, "wb");
    if (benchfile == NULL) {
        PrintAndLogEx(ERR, "Can't write " RESOURCES_SUBDIR TEST_BENCH_FILENAME", abort!");
        return;
    }
    fwrite(&nonces_to_bruteforce, 1, sizeof(nonces_to_bruteforce), benchfile);
    for (uint32_t i = 0; i < nonces_to_bruteforce; i++) {
        fwrite(&(bf_test_nonce[i]), 1, sizeof(bf_test_nonce[i]), benchfile);
        fwrite(&(bf_test_nonce_par[i]), 1, sizeof(bf_test_nonce_par[i]), benchfile);
    }
    uint32_t num_states = MIN(candidates->len[EVEN_STATE], TEST_BENCH_SIZE);
    fwrite(&num_states, 1, sizeof(num_states), benchfile);
    for (uint32_t i = 0; i < num_states; i++) {
        fwrite(&(candidates->states[EVEN_STATE][i]), 1, sizeof(uint32_t), benchfile);
    }
    num_states = MIN(candidates->len[ODD_STATE], TEST_BENCH_SIZE);
    fwrite(&num_states, 1, sizeof(num_states), benchfile);
    for (uint32_t i = 0; i < num_states; i++) {
        fwrite(&(candidates->states[ODD_STATE][i]), 1, sizeof(uint32_t), benchfile);
    }
    fclose(benchfile);
    PrintAndLogEx(NORMAL, "Done");
}
#endif


static bool ensure_buckets_alloc(size_t need_buckets) {
    if (need_buckets > buckets_allocated) {
        size_t alloc_sz = ((buckets_allocated == 0) ? MIN_BUCKETS_SIZE : (buckets_allocated * 2));
        while (need_buckets > alloc_sz) {
            alloc_sz *= 2;
        }

        buckets = realloc(buckets, sizeof(statelist_t *) * alloc_sz);
        if (buckets == NULL) {
            buckets_allocated = 0;
            return false;
        }
        memset(buckets + buckets_allocated, 0, (alloc_sz - buckets_allocated) * sizeof(statelist_t *));
        buckets_allocated = alloc_sz;
    }

    return true;
}


bool brute_force_bs(float *bf_rate, statelist_t *candidates, uint32_t cuid, uint32_t num_acquired_nonces, uint64_t maximum_states, noncelist_t *nonces, uint8_t *best_first_bytes, uint64_t *found_key) {
#if defined (WRITE_BENCH_FILE)
    write_benchfile(candidates);
#endif
    bool silent = (bf_rate != NULL);

    const int num_brute_force_threads = NUM_BRUTE_FORCE_THREADS;

    keys_found = 0;
    num_keys_tested = 0;
    found_bs_key = 0;

    bitslice_test_nonces(nonces_to_bruteforce, bf_test_nonce, bf_test_nonce_par);

    // count number of states to go
    bucket_count = 0;
    for (statelist_t *p = candidates; p != NULL; p = p->next) {
        if (p->states[ODD_STATE] != NULL && p->states[EVEN_STATE] != NULL) {
            if (!ensure_buckets_alloc(bucket_count + 1)) {
                PrintAndLogEx(ERR, "Can't allocate buckets, abort!");
                return false;
            }

            buckets[bucket_count] = p;
            bucket_count++;
        }
    }

    uint64_t start_time = msclock();

#if defined(__linux__) ||  defined(__APPLE__)
    if (NUM_BRUTE_FORCE_THREADS < 0)
        return false;
#endif

    pthread_t threads[num_brute_force_threads];
    struct args {
        bool silent;
        int thread_ID;
        uint32_t cuid;
        uint32_t num_acquired_nonces;
        uint64_t maximum_states;
        noncelist_t *nonces;
        uint8_t *best_first_bytes;
    } thread_args[num_brute_force_threads];

    for (uint32_t i = 0; i < num_brute_force_threads; i++) {
        thread_args[i].thread_ID = i;
        thread_args[i].silent = silent;
        thread_args[i].cuid = cuid;
        thread_args[i].num_acquired_nonces = num_acquired_nonces;
        thread_args[i].maximum_states = maximum_states;
        thread_args[i].nonces = nonces;
        thread_args[i].best_first_bytes = best_first_bytes;
        pthread_create(&threads[i], NULL, crack_states_thread, (void *)&thread_args[i]);
    }
    for (uint32_t i = 0; i < num_brute_force_threads; i++) {
        pthread_join(threads[i], 0);
    }

    free(buckets);
    buckets = NULL;
    buckets_allocated = 0;

    uint64_t elapsed_time = msclock() - start_time;

    if (bf_rate != NULL)
        *bf_rate = (float)num_keys_tested / ((float)elapsed_time / 1000.0);

    if (keys_found > 0)
        *found_key = found_bs_key;

    return (keys_found != 0);
}


static bool read_bench_data(statelist_t *test_candidates) {

    size_t bytes_read = 0;
    uint32_t temp = 0;
    uint32_t num_states = 0;
    uint32_t states_read = 0;

    char *path;
    if (searchFile(&path, RESOURCES_SUBDIR, TEST_BENCH_FILENAME, "", false) != PM3_SUCCESS) {
        return false;
    }

    FILE *benchfile = fopen(path, "rb");
    if (benchfile == NULL) {
        free(path);
        return false;
    }
    free(path);

    // read 4 bytes of data ?
    bytes_read = fread(&nonces_to_bruteforce, 1, sizeof(uint32_t), benchfile);
    if (bytes_read != sizeof(uint32_t) || (nonces_to_bruteforce >= 256)) {
        fclose(benchfile);
        return false;
    }

    for (uint32_t i = 0; i < nonces_to_bruteforce && i < 256; i++) {
        bytes_read = fread(&bf_test_nonce[i], 1, sizeof(uint32_t), benchfile);
        if (bytes_read != sizeof(uint32_t)) {
            fclose(benchfile);
            return false;
        }
        bf_test_nonce_2nd_byte[i] = (bf_test_nonce[i] >> 16) & 0xff;
        bytes_read = fread(&bf_test_nonce_par[i], 1, sizeof(uint8_t), benchfile);
        if (bytes_read != sizeof(uint8_t)) {
            fclose(benchfile);
            return false;
        }
    }

    bytes_read = fread(&num_states, 1, sizeof(uint32_t), benchfile);
    if (bytes_read != sizeof(uint32_t)) {
        fclose(benchfile);
        return false;
    }

    for (states_read = 0; states_read < MIN(num_states, TEST_BENCH_SIZE); states_read++) {
        bytes_read = fread(test_candidates->states[EVEN_STATE] + states_read, 1, sizeof(uint32_t), benchfile);
        if (bytes_read != sizeof(uint32_t)) {
            fclose(benchfile);
            return false;
        }
    }

    for (uint32_t i = states_read; i < TEST_BENCH_SIZE; i++) {
        test_candidates->states[EVEN_STATE][i] = test_candidates->states[EVEN_STATE][i - states_read];
    }

    for (uint32_t i = states_read; i < num_states; i++) {
        bytes_read = fread(&temp, 1, sizeof(uint32_t), benchfile);
        if (bytes_read != sizeof(uint32_t)) {
            fclose(benchfile);
            return false;
        }
    }

    for (states_read = 0; states_read < MIN(num_states, TEST_BENCH_SIZE); states_read++) {
        bytes_read = fread(test_candidates->states[ODD_STATE] + states_read, 1, sizeof(uint32_t), benchfile);
        if (bytes_read != sizeof(uint32_t)) {
            fclose(benchfile);
            return false;
        }
    }

    for (uint32_t i = states_read; i < TEST_BENCH_SIZE; i++) {
        test_candidates->states[ODD_STATE][i] = test_candidates->states[ODD_STATE][i - states_read];
    }

    fclose(benchfile);
    return true;
}


float brute_force_benchmark(void) {
    const int num_brute_force_threads = NUM_BRUTE_FORCE_THREADS;
    statelist_t test_candidates[num_brute_force_threads];

    test_candidates[0].states[ODD_STATE] = calloc(1, (TEST_BENCH_SIZE + 1) * sizeof(uint32_t));
    test_candidates[0].states[EVEN_STATE] = calloc(1, (TEST_BENCH_SIZE + 1) * sizeof(uint32_t));
    for (uint32_t i = 0; i < num_brute_force_threads - 1; i++) {
        test_candidates[i].next = test_candidates + i + 1;
        test_candidates[i + 1].states[ODD_STATE] = test_candidates[0].states[ODD_STATE];
        test_candidates[i + 1].states[EVEN_STATE] = test_candidates[0].states[EVEN_STATE];
    }
    test_candidates[num_brute_force_threads - 1].next = NULL;

    if (!read_bench_data(test_candidates)) {
        PrintAndLogEx(NORMAL, "Couldn't read benchmark data. Assuming brute force rate of %1.0f states per second", DEFAULT_BRUTE_FORCE_RATE);
        return DEFAULT_BRUTE_FORCE_RATE;
    }

    for (uint32_t i = 0; i < num_brute_force_threads; i++) {
        test_candidates[i].len[ODD_STATE] = TEST_BENCH_SIZE;
        test_candidates[i].len[EVEN_STATE] = TEST_BENCH_SIZE;
        test_candidates[i].states[ODD_STATE][TEST_BENCH_SIZE] = -1;
        test_candidates[i].states[EVEN_STATE][TEST_BENCH_SIZE] = -1;
    }

    uint64_t maximum_states = TEST_BENCH_SIZE * TEST_BENCH_SIZE * (uint64_t)num_brute_force_threads;

    float bf_rate;
    uint64_t found_key = 0;
    brute_force_bs(&bf_rate, test_candidates, 0, 0, maximum_states, NULL, 0, &found_key);

    free(test_candidates[0].states[ODD_STATE]);
    free(test_candidates[0].states[EVEN_STATE]);
    test_candidates[0].len[ODD_STATE] = 0;
    test_candidates[0].len[EVEN_STATE] = 0;
    return bf_rate;
}


