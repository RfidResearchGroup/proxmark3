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
// 256-wide bitsliced iClass cipher MAC (AVX2). Same algorithm as cipher_bs.c
// but swaps uint64_t lanes for __m256i, yielding 256 candidates per bs_tick
// (4x throughput over the portable u64 path on AVX2-capable x86).
//
// The interface hides __m256i behind plain uint64_t arrays so callers do not
// need the AVX2 headers. Each __m256i occupies BS256_WORDS (= 4) uint64_t;
// the implementation uses unaligned loads/stores, so no special alignment
// is required from the caller.
//
// On non-x86 builds (or when AVX2 is absent at runtime) every function in
// this header is a safe no-op; callers should gate use with the return value
// of bs_avx2_supported().
//-----------------------------------------------------------------------------

#ifndef CIPHER_BS_AVX2_H
#define CIPHER_BS_AVX2_H

#include <stdint.h>
#include <stdbool.h>

#define BS256_WIDTH 256
#define BS256_WORDS 4

// Returns true iff the running CPU supports AVX2 and this translation unit
// was built for an x86 target. Cached after first call.
bool bs_avx2_supported(void);

// Expand 12 cc_nr bytes into 96 bit masks broadcast across 256 lanes.
void prepare_ccnr_bits_bs256(const uint8_t *cc_nr, uint64_t y_bits_bs[96 * BS256_WORDS]);

// Expand a 4-byte target MAC into 32 bit masks for per-tick comparison.
void prepare_target_mac_bs256(const uint8_t target_mac[4], uint64_t target_mac_bs[32 * BS256_WORDS]);

// Build the 256-wide bitsliced key for 256 consecutive candidates starting
// at index_start. index_start MUST be a multiple of 256 so the low 8 index
// bits reduce to the lane index.
void build_bitslice_key_256(const uint8_t partial_key[8], uint64_t index_start, uint64_t kb[64 * BS256_WORDS]);

// Run the bitsliced MAC and write a 256-bit lane match mask into match_out
// (match_out[0] = lanes 0..63, match_out[1] = lanes 64..127, ..., match_out[3]
// = lanes 192..255). All zeros on complete miss or on an early-out eliminating
// every lane.
void doMAC_brute_match256(const uint64_t y_bits_bs[96 * BS256_WORDS],
                          const uint64_t kb[64 * BS256_WORDS],
                          const uint64_t target_mac_bs[32 * BS256_WORDS],
                          uint64_t match_out[BS256_WORDS]);

#endif // CIPHER_BS_AVX2_H
