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
// 128-wide bitsliced iClass cipher MAC (ARM NEON). 2x throughput over the
// portable u64 bitslice on AArch64 (NEON is mandatory there) and on 32-bit
// ARM builds that enable NEON. Buffers are plain uint64_t arrays so the
// header stays toolchain-agnostic.
//-----------------------------------------------------------------------------

#ifndef CIPHER_BS_NEON_H
#define CIPHER_BS_NEON_H

#include <stdint.h>
#include <stdbool.h>

#define BS128_WIDTH 128
#define BS128_WORDS 2

bool bs_neon_supported(void);

void prepare_ccnr_bits_bs128(const uint8_t *cc_nr, uint64_t y_bits_bs[96 * BS128_WORDS]);
void prepare_target_mac_bs128(const uint8_t target_mac[4], uint64_t target_mac_bs[32 * BS128_WORDS]);
void build_bitslice_key_128(const uint8_t partial_key[8], uint64_t index_start, uint64_t kb[64 * BS128_WORDS]);
void doMAC_brute_match128(const uint64_t y_bits_bs[96 * BS128_WORDS],
                          const uint64_t kb[64 * BS128_WORDS],
                          const uint64_t target_mac_bs[32 * BS128_WORDS],
                          uint64_t match_out[BS128_WORDS]);

#endif // CIPHER_BS_NEON_H
