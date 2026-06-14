//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// 512-wide bitsliced iClass cipher MAC (AVX-512F). 8x throughput over the
// portable u64 bitslice on hosts with AVX-512F.
//
// Buffers are exposed as plain uint64_t arrays to avoid leaking __m512i into
// callers that may not be AVX-512-built. Each __m512i occupies BS512_WORDS
// (= 8) uint64_t.
//-----------------------------------------------------------------------------

#ifndef CIPHER_BS_AVX512_H
#define CIPHER_BS_AVX512_H

#include <stdint.h>
#include <stdbool.h>

#define BS512_WIDTH 512
#define BS512_WORDS 8

bool bs_avx512_supported(void);

void prepare_ccnr_bits_bs512(const uint8_t *cc_nr, uint64_t y_bits_bs[96 * BS512_WORDS]);
void prepare_target_mac_bs512(const uint8_t target_mac[4], uint64_t target_mac_bs[32 * BS512_WORDS]);
void build_bitslice_key_512(const uint8_t partial_key[8], uint64_t index_start, uint64_t kb[64 * BS512_WORDS]);
void doMAC_brute_match512(const uint64_t y_bits_bs[96 * BS512_WORDS],
                          const uint64_t kb[64 * BS512_WORDS],
                          const uint64_t target_mac_bs[32 * BS512_WORDS],
                          uint64_t match_out[BS512_WORDS]);

#endif // CIPHER_BS_AVX512_H
