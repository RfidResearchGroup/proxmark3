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
// ARM NEON 128-wide bitsliced iClass cipher MAC. Same algorithm as cipher_bs.c
// with uint64x2_t lanes. Seven LANE_BITS patterns cover log2(128) = 7 bits.
//-----------------------------------------------------------------------------

#include "cipher_bs_neon.h"

#if defined(__ARM_NEON) || defined(__ARM_NEON__)

#include <arm_neon.h>

#define BS_ZERO vdupq_n_u64(0)
#define BS_ONES vdupq_n_u64(~(uint64_t)0)

static inline uint64x2_t bs_not(uint64x2_t v) { return veorq_u64(v, BS_ONES); }

static inline uint64x2_t bs_mux8(uint64x2_t z0, uint64x2_t z1, uint64x2_t z2,
                                 uint64x2_t nz0, uint64x2_t nz1, uint64x2_t nz2,
                                 uint64x2_t v0, uint64x2_t v1, uint64x2_t v2, uint64x2_t v3,
                                 uint64x2_t v4, uint64x2_t v5, uint64x2_t v6, uint64x2_t v7) {
    const uint64x2_t a0 = vorrq_u64(vandq_u64(z2, v1), vandq_u64(nz2, v0));
    const uint64x2_t a1 = vorrq_u64(vandq_u64(z2, v3), vandq_u64(nz2, v2));
    const uint64x2_t a2 = vorrq_u64(vandq_u64(z2, v5), vandq_u64(nz2, v4));
    const uint64x2_t a3 = vorrq_u64(vandq_u64(z2, v7), vandq_u64(nz2, v6));
    const uint64x2_t b0 = vorrq_u64(vandq_u64(z1, a1), vandq_u64(nz1, a0));
    const uint64x2_t b1 = vorrq_u64(vandq_u64(z1, a3), vandq_u64(nz1, a2));
    return vorrq_u64(vandq_u64(z0, b1), vandq_u64(nz0, b0));
}

static inline void bs_add8(const uint64x2_t *a, const uint64x2_t *b, uint64x2_t *out) {
    uint64x2_t carry = BS_ZERO;
    for (int i = 0; i < 8; i++) {
        const uint64x2_t x = veorq_u64(a[i], b[i]);
        out[i] = veorq_u64(x, carry);
        carry = vorrq_u64(vandq_u64(a[i], b[i]), vandq_u64(carry, x));
    }
}

static inline void bs_tick(uint64x2_t *t, uint64x2_t *b, uint64x2_t *l, uint64x2_t *r,
                           const uint64x2_t *kb, uint64x2_t y_bs) {

    const uint64x2_t Tt = veorq_u64(veorq_u64(veorq_u64(veorq_u64(
                                        veorq_u64(veorq_u64(veorq_u64(t[15], t[14]), t[10]), t[8]),
                                        t[5]), t[4]), t[1]), t[0]);
    const uint64x2_t Bt = veorq_u64(veorq_u64(veorq_u64(b[6], b[5]), b[4]), b[0]);

    const uint64x2_t cr0 = r[7], cr1 = r[6], cr2 = r[5], cr3 = r[4];
    const uint64x2_t cr4 = r[3], cr5 = r[2], cr6 = r[1], cr7 = r[0];

    const uint64x2_t new_t = veorq_u64(veorq_u64(Tt, cr0), cr4);
    const uint64x2_t new_b = veorq_u64(Bt, cr7);

    for (int i = 0; i < 15; i++) t[i] = t[i + 1];
    t[15] = new_t;
    for (int i = 0; i < 7; i++) b[i] = b[i + 1];
    b[7] = new_b;

    const uint64x2_t ncr3 = bs_not(cr3);
    const uint64x2_t ncr5 = bs_not(cr5);

    const uint64x2_t z0 = veorq_u64(veorq_u64(vandq_u64(cr0, cr2), vandq_u64(cr1, ncr3)),
                                    vorrq_u64(cr2, cr4));
    const uint64x2_t z1 = veorq_u64(veorq_u64(veorq_u64(veorq_u64(veorq_u64(
                                        vorrq_u64(cr0, cr2), vorrq_u64(cr5, cr7)), cr1), cr6), Tt), y_bs);
    const uint64x2_t z2 = veorq_u64(veorq_u64(veorq_u64(
                                        vandq_u64(cr3, ncr5), vandq_u64(cr4, cr6)), cr7), Tt);

    const uint64x2_t nz0 = bs_not(z0);
    const uint64x2_t nz1 = bs_not(z1);
    const uint64x2_t nz2 = bs_not(z2);

    uint64x2_t val[8];
    for (int bit = 0; bit < 8; bit++) {
        val[bit] = bs_mux8(z0, z1, z2, nz0, nz1, nz2,
                           kb[0 * 8 + bit], kb[1 * 8 + bit],
                           kb[2 * 8 + bit], kb[3 * 8 + bit],
                           kb[4 * 8 + bit], kb[5 * 8 + bit],
                           kb[6 * 8 + bit], kb[7 * 8 + bit]);
    }

    for (int i = 0; i < 8; i++) val[i] = veorq_u64(val[i], b[i]);

    uint64x2_t old_r[8];
    for (int i = 0; i < 8; i++) old_r[i] = r[i];
    bs_add8(val, l, r);
    bs_add8(r, old_r, l);
}

// Lane patterns for L = 0..127, stored as 2 × uint64_t (low word = lanes 0..63,
// high word = lanes 64..127).
static const uint64_t LANE_BITS_128_RAW[7][BS128_WORDS] = {
    {0xAAAAAAAAAAAAAAAAULL, 0xAAAAAAAAAAAAAAAAULL}, // k=0
    {0xCCCCCCCCCCCCCCCCULL, 0xCCCCCCCCCCCCCCCCULL}, // k=1
    {0xF0F0F0F0F0F0F0F0ULL, 0xF0F0F0F0F0F0F0F0ULL}, // k=2
    {0xFF00FF00FF00FF00ULL, 0xFF00FF00FF00FF00ULL}, // k=3
    {0xFFFF0000FFFF0000ULL, 0xFFFF0000FFFF0000ULL}, // k=4
    {0xFFFFFFFF00000000ULL, 0xFFFFFFFF00000000ULL}, // k=5
    {0x0000000000000000ULL, 0xFFFFFFFFFFFFFFFFULL}, // k=6
};

static inline uint64x2_t lane_bits_128(int k) {
    return vld1q_u64(LANE_BITS_128_RAW[k]);
}

static inline void bs_init_state(const uint64x2_t kb[64],
                                 uint64x2_t l[8], uint64x2_t r[8],
                                 uint64x2_t b[8], uint64x2_t t[16]) {

    uint64x2_t k0xor[8];
    k0xor[0] = kb[0];
    k0xor[1] = kb[1];
    k0xor[2] = veorq_u64(kb[2], BS_ONES);
    k0xor[3] = veorq_u64(kb[3], BS_ONES);
    k0xor[4] = kb[4];
    k0xor[5] = kb[5];
    k0xor[6] = veorq_u64(kb[6], BS_ONES);
    k0xor[7] = kb[7];

    const uint64x2_t ec[8]  = {BS_ZERO, BS_ZERO, BS_ONES, BS_ONES, BS_ZERO, BS_ONES, BS_ONES, BS_ONES};
    const uint64x2_t x21[8] = {BS_ONES, BS_ZERO, BS_ZERO, BS_ZERO, BS_ZERO, BS_ONES, BS_ZERO, BS_ZERO};

    bs_add8(k0xor, ec, l);
    bs_add8(k0xor, x21, r);

    b[0] = BS_ZERO; b[1] = BS_ZERO; b[2] = BS_ONES; b[3] = BS_ONES;
    b[4] = BS_ZERO; b[5] = BS_ZERO; b[6] = BS_ONES; b[7] = BS_ZERO;

    t[ 0] = BS_ZERO; t[ 1] = BS_ONES; t[ 2] = BS_ZERO; t[ 3] = BS_ZERO;
    t[ 4] = BS_ONES; t[ 5] = BS_ZERO; t[ 6] = BS_ZERO; t[ 7] = BS_ZERO;
    t[ 8] = BS_ZERO; t[ 9] = BS_ZERO; t[10] = BS_ZERO; t[11] = BS_ZERO;
    t[12] = BS_ZERO; t[13] = BS_ONES; t[14] = BS_ONES; t[15] = BS_ONES;
}

void prepare_ccnr_bits_bs128(const uint8_t *cc_nr, uint64_t y_bits_bs[96 * BS128_WORDS]) {
    for (int i = 0; i < 12; i++) {
        const uint8_t byte = cc_nr[i];
        for (int bit = 0; bit < 8; bit++) {
            vst1q_u64(&y_bits_bs[(i * 8 + bit) * BS128_WORDS],
                      ((byte >> bit) & 1) ? BS_ONES : BS_ZERO);
        }
    }
}

void prepare_target_mac_bs128(const uint8_t target_mac[4], uint64_t target_mac_bs[32 * BS128_WORDS]) {
    for (int i = 0; i < 4; i++) {
        const uint8_t byte = target_mac[i];
        for (int bit = 0; bit < 8; bit++) {
            vst1q_u64(&target_mac_bs[(i * 8 + bit) * BS128_WORDS],
                      ((byte >> bit) & 1) ? BS_ONES : BS_ZERO);
        }
    }
}

void build_bitslice_key_128(const uint8_t partial_key[8], uint64_t index_start, uint64_t kb[64 * BS128_WORDS]) {

    for (int j = 0; j < 8; j++) {
        vst1q_u64(&kb[(j * 8 + 0) * BS128_WORDS], (partial_key[j] & 0x01) ? BS_ONES : BS_ZERO);
        vst1q_u64(&kb[(j * 8 + 1) * BS128_WORDS], (partial_key[j] & 0x02) ? BS_ONES : BS_ZERO);
        vst1q_u64(&kb[(j * 8 + 2) * BS128_WORDS], (partial_key[j] & 0x04) ? BS_ONES : BS_ZERO);
    }

    for (int j = 0; j < 8; j++) {
        const int base_bit = 5 * (7 - j);
        for (int kk = 0; kk < 5; kk++) {
            const int idx_bit = base_bit + kk;
            uint64x2_t pattern;
            if (idx_bit < 7) {
                pattern = lane_bits_128(idx_bit);
            } else {
                pattern = ((index_start >> idx_bit) & 1) ? BS_ONES : BS_ZERO;
            }
            vst1q_u64(&kb[(j * 8 + 3 + kk) * BS128_WORDS], pattern);
        }
    }
}

// True iff every lane of v is zero. Portable NEON (works on AArch32 + AArch64).
static inline bool bs128_all_zero(uint64x2_t v) {
    return (vgetq_lane_u64(v, 0) | vgetq_lane_u64(v, 1)) == 0;
}

void doMAC_brute_match128(const uint64_t y_bits_bs[96 * BS128_WORDS],
                          const uint64_t kb[64 * BS128_WORDS],
                          const uint64_t target_mac_bs[32 * BS128_WORDS],
                          uint64_t match_out[BS128_WORDS]) {

    uint64x2_t k[64];
    for (int i = 0; i < 64; i++) k[i] = vld1q_u64(&kb[i * BS128_WORDS]);

    uint64x2_t l[8], r[8], b[8], t[16];
    bs_init_state(k, l, r, b, t);

    for (int i = 0; i < 96; i++) {
        bs_tick(t, b, l, r, k, vld1q_u64(&y_bits_bs[i * BS128_WORDS]));
    }

    uint64x2_t mac_match = BS_ONES;
    for (int tick = 0; tick < 32; tick++) {
        const uint64x2_t diff = veorq_u64(r[2], vld1q_u64(&target_mac_bs[tick * BS128_WORDS]));
        // mac_match &= ~diff  →  vbicq_u64(mac_match, diff) = mac_match AND NOT diff
        mac_match = vbicq_u64(mac_match, diff);

        if ((tick == 7 || tick == 15 || tick == 23) && bs128_all_zero(mac_match)) {
            match_out[0] = 0; match_out[1] = 0;
            return;
        }

        if (tick < 31) {
            bs_tick(t, b, l, r, k, BS_ZERO);
        }
    }

    vst1q_u64(match_out, mac_match);
}

bool bs_neon_supported(void) { return true; }

#else // no NEON

bool bs_neon_supported(void) { return false; }

void prepare_ccnr_bits_bs128(const uint8_t *cc_nr, uint64_t y_bits_bs[96 * BS128_WORDS]) {
    (void)cc_nr; (void)y_bits_bs;
}
void prepare_target_mac_bs128(const uint8_t target_mac[4], uint64_t target_mac_bs[32 * BS128_WORDS]) {
    (void)target_mac; (void)target_mac_bs;
}
void build_bitslice_key_128(const uint8_t partial_key[8], uint64_t index_start, uint64_t kb[64 * BS128_WORDS]) {
    (void)partial_key; (void)index_start; (void)kb;
}
void doMAC_brute_match128(const uint64_t y_bits_bs[96 * BS128_WORDS],
                          const uint64_t kb[64 * BS128_WORDS],
                          const uint64_t target_mac_bs[32 * BS128_WORDS],
                          uint64_t match_out[BS128_WORDS]) {
    (void)y_bits_bs; (void)kb; (void)target_mac_bs;
    for (int i = 0; i < BS128_WORDS; i++) match_out[i] = 0;
}

#endif
