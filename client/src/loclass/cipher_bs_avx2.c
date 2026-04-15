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
// AVX2 256-wide bitsliced iClass cipher MAC. Mirrors cipher_bs.c exactly;
// the only substantive change is the lane type (__m256i in place of uint64_t).
//-----------------------------------------------------------------------------

#include "cipher_bs_avx2.h"

#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)

#include <immintrin.h>

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC push_options
#pragma GCC target("avx2")
#endif

#define BS_ZERO    _mm256_setzero_si256()
#define BS_ONES    _mm256_set1_epi64x(-1)

static inline __m256i bs_not(__m256i v) { return _mm256_xor_si256(v, BS_ONES); }

static inline __m256i bs_mux8(__m256i z0, __m256i z1, __m256i z2,
                              __m256i nz0, __m256i nz1, __m256i nz2,
                              __m256i v0, __m256i v1, __m256i v2, __m256i v3,
                              __m256i v4, __m256i v5, __m256i v6, __m256i v7) {
    const __m256i a0 = _mm256_or_si256(_mm256_and_si256(z2, v1), _mm256_and_si256(nz2, v0));
    const __m256i a1 = _mm256_or_si256(_mm256_and_si256(z2, v3), _mm256_and_si256(nz2, v2));
    const __m256i a2 = _mm256_or_si256(_mm256_and_si256(z2, v5), _mm256_and_si256(nz2, v4));
    const __m256i a3 = _mm256_or_si256(_mm256_and_si256(z2, v7), _mm256_and_si256(nz2, v6));
    const __m256i b0 = _mm256_or_si256(_mm256_and_si256(z1, a1), _mm256_and_si256(nz1, a0));
    const __m256i b1 = _mm256_or_si256(_mm256_and_si256(z1, a3), _mm256_and_si256(nz1, a2));
    return _mm256_or_si256(_mm256_and_si256(z0, b1), _mm256_and_si256(nz0, b0));
}

static inline void bs_add8(const __m256i *a, const __m256i *b, __m256i *out) {
    __m256i carry = BS_ZERO;
    for (int i = 0; i < 8; i++) {
        const __m256i x = _mm256_xor_si256(a[i], b[i]);
        out[i] = _mm256_xor_si256(x, carry);
        carry = _mm256_or_si256(_mm256_and_si256(a[i], b[i]), _mm256_and_si256(carry, x));
    }
}

static inline void bs_tick(__m256i *t, __m256i *b, __m256i *l, __m256i *r,
                           const __m256i *kb, __m256i y_bs) {

    const __m256i Tt = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(
                                            _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(t[15], t[14]), t[10]), t[8]),
                                            t[5]), t[4]), t[1]), t[0]);
    const __m256i Bt = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(b[6], b[5]), b[4]), b[0]);

    const __m256i cr0 = r[7], cr1 = r[6], cr2 = r[5], cr3 = r[4];
    const __m256i cr4 = r[3], cr5 = r[2], cr6 = r[1], cr7 = r[0];

    const __m256i new_t = _mm256_xor_si256(_mm256_xor_si256(Tt, cr0), cr4);
    const __m256i new_b = _mm256_xor_si256(Bt, cr7);

    for (int i = 0; i < 15; i++) t[i] = t[i + 1];
    t[15] = new_t;
    for (int i = 0; i < 7; i++) b[i] = b[i + 1];
    b[7] = new_b;

    const __m256i ncr3 = bs_not(cr3);
    const __m256i ncr5 = bs_not(cr5);

    const __m256i z0 = _mm256_xor_si256(_mm256_xor_si256(_mm256_and_si256(cr0, cr2), _mm256_and_si256(cr1, ncr3)),
                                        _mm256_or_si256(cr2, cr4));
    const __m256i z1 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(
                                            _mm256_or_si256(cr0, cr2), _mm256_or_si256(cr5, cr7)), cr1), cr6), Tt), y_bs);
    const __m256i z2 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(
                                            _mm256_and_si256(cr3, ncr5), _mm256_and_si256(cr4, cr6)), cr7), Tt);

    const __m256i nz0 = bs_not(z0);
    const __m256i nz1 = bs_not(z1);
    const __m256i nz2 = bs_not(z2);

    __m256i val[8];
    for (int bit = 0; bit < 8; bit++) {
        val[bit] = bs_mux8(z0, z1, z2, nz0, nz1, nz2,
                           kb[0 * 8 + bit], kb[1 * 8 + bit],
                           kb[2 * 8 + bit], kb[3 * 8 + bit],
                           kb[4 * 8 + bit], kb[5 * 8 + bit],
                           kb[6 * 8 + bit], kb[7 * 8 + bit]);
    }

    for (int i = 0; i < 8; i++) val[i] = _mm256_xor_si256(val[i], b[i]);

    __m256i old_r[8];
    for (int i = 0; i < 8; i++) old_r[i] = r[i];
    bs_add8(val, l, r);
    bs_add8(r, old_r, l);
}

// Lane patterns for L bit k (L = 0..255). Pattern bit L set iff bit k of L
// equals 1. Stored as 4 × uint64_t (low word = lanes 0..63, etc.) so they
// match the __m256i memory layout on little-endian x86.
static const uint64_t LANE_BITS_256_RAW[8][BS256_WORDS] = {
    {0xAAAAAAAAAAAAAAAAULL, 0xAAAAAAAAAAAAAAAAULL, 0xAAAAAAAAAAAAAAAAULL, 0xAAAAAAAAAAAAAAAAULL}, // k=0
    {0xCCCCCCCCCCCCCCCCULL, 0xCCCCCCCCCCCCCCCCULL, 0xCCCCCCCCCCCCCCCCULL, 0xCCCCCCCCCCCCCCCCULL}, // k=1
    {0xF0F0F0F0F0F0F0F0ULL, 0xF0F0F0F0F0F0F0F0ULL, 0xF0F0F0F0F0F0F0F0ULL, 0xF0F0F0F0F0F0F0F0ULL}, // k=2
    {0xFF00FF00FF00FF00ULL, 0xFF00FF00FF00FF00ULL, 0xFF00FF00FF00FF00ULL, 0xFF00FF00FF00FF00ULL}, // k=3
    {0xFFFF0000FFFF0000ULL, 0xFFFF0000FFFF0000ULL, 0xFFFF0000FFFF0000ULL, 0xFFFF0000FFFF0000ULL}, // k=4
    {0xFFFFFFFF00000000ULL, 0xFFFFFFFF00000000ULL, 0xFFFFFFFF00000000ULL, 0xFFFFFFFF00000000ULL}, // k=5
    {0x0000000000000000ULL, 0xFFFFFFFFFFFFFFFFULL, 0x0000000000000000ULL, 0xFFFFFFFFFFFFFFFFULL}, // k=6
    {0x0000000000000000ULL, 0x0000000000000000ULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL}, // k=7
};

static inline __m256i lane_bits_256(int k) {
    return _mm256_loadu_si256((const __m256i *)LANE_BITS_256_RAW[k]);
}

static inline void bs_init_state(const __m256i kb[64],
                                 __m256i l[8], __m256i r[8],
                                 __m256i b[8], __m256i t[16]) {

    __m256i k0xor[8];
    k0xor[0] = kb[0];
    k0xor[1] = kb[1];
    k0xor[2] = _mm256_xor_si256(kb[2], BS_ONES);
    k0xor[3] = _mm256_xor_si256(kb[3], BS_ONES);
    k0xor[4] = kb[4];
    k0xor[5] = kb[5];
    k0xor[6] = _mm256_xor_si256(kb[6], BS_ONES);
    k0xor[7] = kb[7];

    // 0xEC LSB-first: 0,0,1,1,0,1,1,1
    const __m256i ec[8] = {BS_ZERO, BS_ZERO, BS_ONES, BS_ONES, BS_ZERO, BS_ONES, BS_ONES, BS_ONES};
    // 0x21 LSB-first: 1,0,0,0,0,1,0,0
    const __m256i x21[8] = {BS_ONES, BS_ZERO, BS_ZERO, BS_ZERO, BS_ZERO, BS_ONES, BS_ZERO, BS_ZERO};

    bs_add8(k0xor, ec, l);
    bs_add8(k0xor, x21, r);

    // b = 0x4C LSB-first: 0,0,1,1,0,0,1,0
    b[0] = BS_ZERO; b[1] = BS_ZERO; b[2] = BS_ONES; b[3] = BS_ONES;
    b[4] = BS_ZERO; b[5] = BS_ZERO; b[6] = BS_ONES; b[7] = BS_ZERO;

    // t = 0xE012 LSB-first: 0,1,0,0,1,0,0,0, 0,0,0,0,0,1,1,1
    t[ 0] = BS_ZERO; t[ 1] = BS_ONES; t[ 2] = BS_ZERO; t[ 3] = BS_ZERO;
    t[ 4] = BS_ONES; t[ 5] = BS_ZERO; t[ 6] = BS_ZERO; t[ 7] = BS_ZERO;
    t[ 8] = BS_ZERO; t[ 9] = BS_ZERO; t[10] = BS_ZERO; t[11] = BS_ZERO;
    t[12] = BS_ZERO; t[13] = BS_ONES; t[14] = BS_ONES; t[15] = BS_ONES;
}

void prepare_ccnr_bits_bs256(const uint8_t *cc_nr, uint64_t y_bits_bs[96 * BS256_WORDS]) {
    __m256i *y = (__m256i *)y_bits_bs;
    for (int i = 0; i < 12; i++) {
        const uint8_t byte = cc_nr[i];
        for (int bit = 0; bit < 8; bit++) {
            _mm256_storeu_si256(&y[i * 8 + bit], ((byte >> bit) & 1) ? BS_ONES : BS_ZERO);
        }
    }
}

void prepare_target_mac_bs256(const uint8_t target_mac[4], uint64_t target_mac_bs[32 * BS256_WORDS]) {
    __m256i *tm = (__m256i *)target_mac_bs;
    for (int i = 0; i < 4; i++) {
        const uint8_t byte = target_mac[i];
        for (int bit = 0; bit < 8; bit++) {
            _mm256_storeu_si256(&tm[i * 8 + bit], ((byte >> bit) & 1) ? BS_ONES : BS_ZERO);
        }
    }
}

void build_bitslice_key_256(const uint8_t partial_key[8], uint64_t index_start, uint64_t kb[64 * BS256_WORDS]) {
    __m256i *k = (__m256i *)kb;

    for (int j = 0; j < 8; j++) {
        _mm256_storeu_si256(&k[j * 8 + 0], (partial_key[j] & 0x01) ? BS_ONES : BS_ZERO);
        _mm256_storeu_si256(&k[j * 8 + 1], (partial_key[j] & 0x02) ? BS_ONES : BS_ZERO);
        _mm256_storeu_si256(&k[j * 8 + 2], (partial_key[j] & 0x04) ? BS_ONES : BS_ZERO);
    }

    for (int j = 0; j < 8; j++) {
        const int base_bit = 5 * (7 - j);
        for (int kk = 0; kk < 5; kk++) {
            const int idx_bit = base_bit + kk;
            __m256i pattern;
            if (idx_bit < 8) {
                pattern = lane_bits_256(idx_bit);
            } else {
                pattern = ((index_start >> idx_bit) & 1) ? BS_ONES : BS_ZERO;
            }
            _mm256_storeu_si256(&k[j * 8 + 3 + kk], pattern);
        }
    }
}

void doMAC_brute_match256(const uint64_t y_bits_bs[96 * BS256_WORDS],
                          const uint64_t kb[64 * BS256_WORDS],
                          const uint64_t target_mac_bs[32 * BS256_WORDS],
                          uint64_t match_out[BS256_WORDS]) {

    // Load key into local __m256i array for fast access.
    __m256i k[64];
    const __m256i *kb_m = (const __m256i *)kb;
    for (int i = 0; i < 64; i++) k[i] = _mm256_loadu_si256(&kb_m[i]);

    __m256i l[8], r[8], b[8], t[16];
    bs_init_state(k, l, r, b, t);

    const __m256i *y = (const __m256i *)y_bits_bs;
    const __m256i *tm = (const __m256i *)target_mac_bs;

    for (int i = 0; i < 96; i++) {
        bs_tick(t, b, l, r, k, _mm256_loadu_si256(&y[i]));
    }

    __m256i mac_match = BS_ONES;
    for (int tick = 0; tick < 32; tick++) {
        const __m256i diff = _mm256_xor_si256(r[2], _mm256_loadu_si256(&tm[tick]));
        // mac_match &= ~diff  →  andnot(diff, mac_match) = ~diff & mac_match
        mac_match = _mm256_andnot_si256(diff, mac_match);

        if ((tick == 7 || tick == 15 || tick == 23) && _mm256_testz_si256(mac_match, mac_match)) {
            for (int i = 0; i < BS256_WORDS; i++) match_out[i] = 0;
            return;
        }

        if (tick < 31) {
            bs_tick(t, b, l, r, k, BS_ZERO);
        }
    }

    _mm256_storeu_si256((__m256i *)match_out, mac_match);
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC pop_options
#endif

bool bs_avx2_supported(void) {
    static int cached = -1;
    if (cached < 0) {
#if defined(__GNUC__) || defined(__clang__)
        __builtin_cpu_init();
        cached = __builtin_cpu_supports("avx2") ? 1 : 0;
#else
        cached = 0;
#endif
    }
    return cached != 0;
}

#else // non-x86 build: everything is a no-op, bs_avx2_supported returns false.

bool bs_avx2_supported(void) { return false; }

void prepare_ccnr_bits_bs256(const uint8_t *cc_nr, uint64_t y_bits_bs[96 * BS256_WORDS]) {
    (void)cc_nr; (void)y_bits_bs;
}
void prepare_target_mac_bs256(const uint8_t target_mac[4], uint64_t target_mac_bs[32 * BS256_WORDS]) {
    (void)target_mac; (void)target_mac_bs;
}
void build_bitslice_key_256(const uint8_t partial_key[8], uint64_t index_start, uint64_t kb[64 * BS256_WORDS]) {
    (void)partial_key; (void)index_start; (void)kb;
}
void doMAC_brute_match256(const uint64_t y_bits_bs[96 * BS256_WORDS],
                          const uint64_t kb[64 * BS256_WORDS],
                          const uint64_t target_mac_bs[32 * BS256_WORDS],
                          uint64_t match_out[BS256_WORDS]) {
    (void)y_bits_bs; (void)kb; (void)target_mac_bs;
    for (int i = 0; i < BS256_WORDS; i++) match_out[i] = 0;
}

#endif
