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
// 64-wide bitsliced iClass cipher MAC for the legbrute hot loop. Ports the
// approach used in the hashcat m64000 kernel to portable C (uint64_t lanes).
// Each "bit" of the cipher state is stored as a uint64_t holding that bit for
// 64 parallel candidates; all arithmetic is expressed as bitwise ops plus a
// ripple-carry adder, so one bs_tick advances 64 MACs at once.
//-----------------------------------------------------------------------------

#ifndef CIPHER_BS_H
#define CIPHER_BS_H

#include <stdint.h>

// Expand 12 cc_nr bytes into 96 LSB-first bit masks (0 or all-ones) shared
// across the 64 lanes. Call once per thread.
void prepare_ccnr_bits_bs(const uint8_t *cc_nr, uint64_t y_bits_bs[96]);

// Expand a 4-byte target MAC into 32 bit masks for per-tick comparison.
// target_mac_bs[t] == ~0 iff the target bit at tick t is 1.
// Tick t corresponds to bit (t mod 8) of target_mac[t / 8] (matches the
// scalar output_bytes packing order).
void prepare_target_mac_bs(const uint8_t target_mac[4], uint64_t target_mac_bs[32]);

// Build the 64-wide bitsliced key for 64 consecutive candidates starting at
// index_start. index_start MUST be a multiple of 64 so the low 6 index bits
// are the pure lane index.
void build_bitslice_key_64(const uint8_t partial_key[8], uint64_t index_start, uint64_t kb[64]);

// Run the bitsliced MAC against a pre-expanded target and return a 64-bit
// lane mask: bit L is set iff candidate (index_start + L) produces target_mac.
// Early-exits after any 8-bit MAC byte that rules out every lane.
uint64_t doMAC_brute_match64(const uint64_t y_bits_bs[96], const uint64_t kb[64], const uint64_t target_mac_bs[32]);

#endif // CIPHER_BS_H
