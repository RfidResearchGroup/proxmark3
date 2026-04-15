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
// 64-wide bitsliced iClass cipher MAC. Mirrors m64000_a3-pure.cl but targets
// portable uint64_t so every CPU gets 64 parallel candidates per bs_tick,
// regardless of SSE/AVX availability.
//-----------------------------------------------------------------------------

#include "cipher_bs.h"

#define BS_ALL_ONES (~(uint64_t)0)

// Bitsliced 3-bit select over 8 key bytes. Each z/nz is the bit across all
// 64 lanes. Returns the mux result per lane.
static inline uint64_t bs_mux8(uint64_t z0, uint64_t z1, uint64_t z2,
                               uint64_t nz0, uint64_t nz1, uint64_t nz2,
                               uint64_t v0, uint64_t v1, uint64_t v2, uint64_t v3,
                               uint64_t v4, uint64_t v5, uint64_t v6, uint64_t v7) {
    const uint64_t a0 = (z2 & v1) | (nz2 & v0);
    const uint64_t a1 = (z2 & v3) | (nz2 & v2);
    const uint64_t a2 = (z2 & v5) | (nz2 & v4);
    const uint64_t a3 = (z2 & v7) | (nz2 & v6);
    const uint64_t b0 = (z1 & a1) | (nz1 & a0);
    const uint64_t b1 = (z1 & a3) | (nz1 & a2);
    return (z0 & b1) | (nz0 & b0);
}

// Bitsliced 8-bit add (ripple-carry). out = (a + b) mod 256 per lane.
static inline void bs_add8(const uint64_t *a, const uint64_t *b, uint64_t *out) {
    uint64_t carry = 0;
    for (int i = 0; i < 8; i++) {
        const uint64_t x = a[i] ^ b[i];
        out[i] = x ^ carry;
        carry = (a[i] & b[i]) | (carry & x);
    }
}

// One cipher tick, bitsliced. t[16], b[8], l[8], r[8] are the cipher state
// where array index is bit position (LSB first) and each slot is a uint64_t
// holding that bit for 64 lanes. kb[64] is the bitsliced key schedule.
// y_bs is the input bit broadcast to all 64 lanes (0 or all-ones).
static inline void bs_tick(uint64_t *t, uint64_t *b, uint64_t *l, uint64_t *r,
                           const uint64_t *kb, uint64_t y_bs) {

    const uint64_t Tt = t[15] ^ t[14] ^ t[10] ^ t[8] ^ t[5] ^ t[4] ^ t[1] ^ t[0];
    const uint64_t Bt = b[6] ^ b[5] ^ b[4] ^ b[0];

    const uint64_t cr0 = r[7], cr1 = r[6], cr2 = r[5], cr3 = r[4];
    const uint64_t cr4 = r[3], cr5 = r[2], cr6 = r[1], cr7 = r[0];

    const uint64_t new_t = Tt ^ cr0 ^ cr4;
    const uint64_t new_b = Bt ^ cr7;

    // Shift t (bit 0 drops out, new_t goes in at bit 15) and b similarly.
    t[0]  = t[1];  t[1]  = t[2];  t[2]  = t[3];  t[3]  = t[4];
    t[4]  = t[5];  t[5]  = t[6];  t[6]  = t[7];  t[7]  = t[8];
    t[8]  = t[9];  t[9]  = t[10]; t[10] = t[11]; t[11] = t[12];
    t[12] = t[13]; t[13] = t[14]; t[14] = t[15]; t[15] = new_t;

    b[0] = b[1]; b[1] = b[2]; b[2] = b[3]; b[3] = b[4];
    b[4] = b[5]; b[5] = b[6]; b[6] = b[7]; b[7] = new_b;

    const uint64_t ncr3 = ~cr3;
    const uint64_t ncr5 = ~cr5;

    const uint64_t z0 = (cr0 & cr2) ^ (cr1 & ncr3) ^ (cr2 | cr4);
    const uint64_t z1 = (cr0 | cr2) ^ (cr5 | cr7) ^ cr1 ^ cr6 ^ Tt ^ y_bs;
    const uint64_t z2 = (cr3 & ncr5) ^ (cr4 & cr6) ^ cr7 ^ Tt;

    const uint64_t nz0 = ~z0, nz1 = ~z1, nz2 = ~z2;

    uint64_t val[8];
    for (int bit = 0; bit < 8; bit++) {
        val[bit] = bs_mux8(z0, z1, z2, nz0, nz1, nz2,
                           kb[0 * 8 + bit], kb[1 * 8 + bit],
                           kb[2 * 8 + bit], kb[3 * 8 + bit],
                           kb[4 * 8 + bit], kb[5 * 8 + bit],
                           kb[6 * 8 + bit], kb[7 * 8 + bit]);
    }

    val[0] ^= b[0]; val[1] ^= b[1]; val[2] ^= b[2]; val[3] ^= b[3];
    val[4] ^= b[4]; val[5] ^= b[5]; val[6] ^= b[6]; val[7] ^= b[7];

    uint64_t old_r[8];
    for (int i = 0; i < 8; i++) old_r[i] = r[i];

    // r = val + l ; l = r + old_r
    bs_add8(val, l, r);
    bs_add8(r, old_r, l);
}

void prepare_ccnr_bits_bs(const uint8_t *cc_nr, uint64_t y_bits_bs[96]) {
    for (int i = 0; i < 12; i++) {
        const uint8_t byte = cc_nr[i];
        y_bits_bs[i * 8 + 0] = (byte       & 1) ? BS_ALL_ONES : 0;
        y_bits_bs[i * 8 + 1] = ((byte >> 1) & 1) ? BS_ALL_ONES : 0;
        y_bits_bs[i * 8 + 2] = ((byte >> 2) & 1) ? BS_ALL_ONES : 0;
        y_bits_bs[i * 8 + 3] = ((byte >> 3) & 1) ? BS_ALL_ONES : 0;
        y_bits_bs[i * 8 + 4] = ((byte >> 4) & 1) ? BS_ALL_ONES : 0;
        y_bits_bs[i * 8 + 5] = ((byte >> 5) & 1) ? BS_ALL_ONES : 0;
        y_bits_bs[i * 8 + 6] = ((byte >> 6) & 1) ? BS_ALL_ONES : 0;
        y_bits_bs[i * 8 + 7] = ((byte >> 7) & 1) ? BS_ALL_ONES : 0;
    }
}

void prepare_target_mac_bs(const uint8_t target_mac[4], uint64_t target_mac_bs[32]) {
    for (int i = 0; i < 4; i++) {
        const uint8_t byte = target_mac[i];
        for (int bit = 0; bit < 8; bit++) {
            target_mac_bs[i * 8 + bit] = ((byte >> bit) & 1) ? BS_ALL_ONES : 0;
        }
    }
}

// Lane patterns for L bits 0..5 (L = 0..63). Each pattern has bit L set iff
// bit k of L is 1. These are constant for 64-aligned batches — bits 0..5 of
// (index_start + L) collapse to the pure lane index L.
static const uint64_t LANE_BITS[6] = {
    0xAAAAAAAAAAAAAAAAULL,  // L bit 0
    0xCCCCCCCCCCCCCCCCULL,  // L bit 1
    0xF0F0F0F0F0F0F0F0ULL,  // L bit 2
    0xFF00FF00FF00FF00ULL,  // L bit 3
    0xFFFF0000FFFF0000ULL,  // L bit 4
    0xFFFFFFFF00000000ULL,  // L bit 5
};

void build_bitslice_key_64(const uint8_t partial_key[8], uint64_t index_start, uint64_t kb[64]) {

    // Low 3 bits of each key byte are fixed by the partial key and broadcast.
    for (int j = 0; j < 8; j++) {
        kb[j * 8 + 0] = (partial_key[j] & 0x01) ? BS_ALL_ONES : 0;
        kb[j * 8 + 1] = (partial_key[j] & 0x02) ? BS_ALL_ONES : 0;
        kb[j * 8 + 2] = (partial_key[j] & 0x04) ? BS_ALL_ONES : 0;
    }

    // High 5 bits per byte come from the 40-bit index. Byte j consumes index
    // bits [5*(7-j) .. 5*(7-j)+4]. For a 64-aligned index_start, bits 0..5 of
    // (index_start + L) equal the lane index L, so they pick up LANE_BITS;
    // bits 6..39 are broadcast from index_start.
    for (int j = 0; j < 8; j++) {
        const int base_bit = 5 * (7 - j);
        for (int k = 0; k < 5; k++) {
            const int idx_bit = base_bit + k;
            uint64_t pattern;
            if (idx_bit < 6) {
                pattern = LANE_BITS[idx_bit];
            } else {
                pattern = ((index_start >> idx_bit) & 1) ? BS_ALL_ONES : 0;
            }
            kb[j * 8 + 3 + k] = pattern;
        }
    }
}

// init(k) for the iClass cipher with k[0] variable and b, t constants:
//   l = ((k[0] ^ 0x4c) + 0xEC) & 0xff
//   r = ((k[0] ^ 0x4c) + 0x21) & 0xff
//   b = 0x4C, t = 0xE012
// Bitsliced: flip kb[0..7] bits that differ under XOR with 0x4C, then bs_add8
// against the broadcast 0xEC / 0x21 bit patterns.
static inline void bs_init_state(const uint64_t kb[64],
                                 uint64_t l[8], uint64_t r[8],
                                 uint64_t b[8], uint64_t t[16]) {

    // 0x4C = 0b01001100 → bits set at positions 2, 3, 6.
    uint64_t k0xor[8];
    k0xor[0] = kb[0];
    k0xor[1] = kb[1];
    k0xor[2] = kb[2] ^ BS_ALL_ONES;
    k0xor[3] = kb[3] ^ BS_ALL_ONES;
    k0xor[4] = kb[4];
    k0xor[5] = kb[5];
    k0xor[6] = kb[6] ^ BS_ALL_ONES;
    k0xor[7] = kb[7];

    // 0xEC = 0b11101100 → LSB-first bit pattern: 0,0,1,1,0,1,1,1
    const uint64_t ec[8] = {0, 0, BS_ALL_ONES, BS_ALL_ONES, 0, BS_ALL_ONES, BS_ALL_ONES, BS_ALL_ONES};
    // 0x21 = 0b00100001 → LSB-first: 1,0,0,0,0,1,0,0
    const uint64_t x21[8] = {BS_ALL_ONES, 0, 0, 0, 0, BS_ALL_ONES, 0, 0};

    bs_add8(k0xor, ec, l);
    bs_add8(k0xor, x21, r);

    // b = 0x4C → 0,0,1,1,0,0,1,0 (LSB first)
    b[0] = 0;           b[1] = 0;
    b[2] = BS_ALL_ONES; b[3] = BS_ALL_ONES;
    b[4] = 0;           b[5] = 0;
    b[6] = BS_ALL_ONES; b[7] = 0;

    // t = 0xE012 → LSB-first across 16 bits:
    //   0xE012 = 0b1110_0000_0001_0010
    //   bit0=0 bit1=1 bit2=0 bit3=0 bit4=1 bit5=0 bit6=0 bit7=0
    //   bit8=0 bit9=0 bit10=0 bit11=0 bit12=0 bit13=1 bit14=1 bit15=1
    t[ 0] = 0;           t[ 1] = BS_ALL_ONES; t[ 2] = 0;           t[ 3] = 0;
    t[ 4] = BS_ALL_ONES; t[ 5] = 0;           t[ 6] = 0;           t[ 7] = 0;
    t[ 8] = 0;           t[ 9] = 0;           t[10] = 0;           t[11] = 0;
    t[12] = 0;           t[13] = BS_ALL_ONES; t[14] = BS_ALL_ONES; t[15] = BS_ALL_ONES;
}

uint64_t doMAC_brute_match64(const uint64_t y_bits_bs[96], const uint64_t kb[64], const uint64_t target_mac_bs[32]) {

    uint64_t l[8], r[8], b[8], t[16];
    bs_init_state(kb, l, r, b, t);

    // 96-tick input phase: consume the 96 cc_nr bits.
    for (int i = 0; i < 96; i++) {
        bs_tick(t, b, l, r, kb, y_bits_bs[i]);
    }

    // 32-tick output phase with per-byte early-exit. r[2] at tick t yields
    // bit (t mod 8) of MAC byte (t / 8), so we AND away lanes whose output
    // disagrees with target_mac_bs[t]. Bail once every lane is eliminated.
    uint64_t mac_match = BS_ALL_ONES;

    for (int tick = 0; tick < 32; tick++) {
        mac_match &= ~(r[2] ^ target_mac_bs[tick]);

        if ((tick == 7 || tick == 15 || tick == 23) && mac_match == 0) {
            return 0;
        }

        if (tick < 31) {
            bs_tick(t, b, l, r, kb, 0);
        }
    }

    return mac_match;
}
