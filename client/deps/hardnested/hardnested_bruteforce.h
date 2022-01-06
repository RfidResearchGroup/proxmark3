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

#ifndef HARDNESTED_BRUTEFORCE_H__
#define HARDNESTED_BRUTEFORCE_H__

#include <stdint.h>
#include <stdbool.h>

#define NUM_SUMS 19 // number of possible sum property values

typedef struct guess_sum_a8 {
    float prob;
    uint64_t num_states;
    uint16_t sum_a8_idx;
} guess_sum_a8_t;

typedef struct noncelistentry {
    uint32_t nonce_enc;
    uint8_t par_enc;
    void *next;
} noncelistentry_t;

typedef struct noncelist {
    uint16_t num;
    uint16_t Sum;
    guess_sum_a8_t sum_a8_guess[NUM_SUMS];
    bool sum_a8_guess_dirty;
    float expected_num_brute_force;
    uint16_t BitFlips[0x400];
    uint32_t *states_bitarray[2];
    uint32_t num_states_bitarray[2];
    bool all_bitflips_dirty[2];
    noncelistentry_t *first;
} noncelist_t;

typedef struct {
    uint32_t *states[2];
    uint32_t len[2];
    void *next;
} statelist_t;

void prepare_bf_test_nonces(noncelist_t *nonces, uint8_t best_first_byte);
bool brute_force_bs(float *bf_rate, statelist_t *candidates, uint32_t cuid, uint32_t num_acquired_nonces, uint64_t maximum_states, noncelist_t *nonces, uint8_t *best_first_bytes, uint64_t *found_key);
float brute_force_benchmark(void);
uint8_t trailing_zeros(uint8_t byte);
bool verify_key(uint32_t cuid, noncelist_t *nonces, const uint8_t *best_first_bytes, uint32_t odd, uint32_t even);

#endif
