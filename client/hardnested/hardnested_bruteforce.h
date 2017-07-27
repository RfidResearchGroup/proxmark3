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
#include "cmdhfmfhard.h"

typedef struct {
	uint32_t *states[2];
	uint32_t len[2];
	void* next;
} statelist_t;

extern void prepare_bf_test_nonces(noncelist_t *nonces, uint8_t best_first_byte);
extern bool brute_force_bs(float *bf_rate, statelist_t *candidates, uint32_t cuid, uint32_t num_acquired_nonces, uint64_t maximum_states, noncelist_t *nonces, uint8_t *best_first_bytes);
extern float brute_force_benchmark();
extern uint8_t trailing_zeros(uint8_t byte); 
extern bool verify_key(uint32_t cuid, noncelist_t *nonces, uint8_t *best_first_bytes, uint32_t odd, uint32_t even);

#endif
