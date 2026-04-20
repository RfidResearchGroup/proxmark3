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
// AVX-512F 512-wide bitsliced iClass cipher MAC. Same algorithm as cipher_bs.c
// with __m512i lanes. Nine LANE_BITS patterns cover the log2(512) = 9 lane-
// varying index bits.
//-----------------------------------------------------------------------------

#include "cipher_bs_avx512.h"

#if defined(__x86_64__) || defined(_M_X64)

#include <immintrin.h>

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC push_options
#pragma GCC target("avx512f")
#endif

#define BS_ZERO   _mm512_setzero_si512()
#define BS_ONES   _mm512_set1_epi64(-1)

static inline __m512i bs_not(__m512i v) { 
    return _mm512_xor_si512(v, BS_ONES);
}

static inline __m512i bs_mux8(__m512i z0, __m512i z1, __m512i z2,
                              __m512i nz0, __m512i nz1, __m512i nz2,
                              __m512i v0, __m512i v1, __m512i v2, __m512i v3,
                              __m512i v4, __m512i v5, __m512i v6, __m512i v7) {
    const __m512i a0 = _mm512_or_si512(_mm512_and_si512(z2, v1), _mm512_and_si512(nz2, v0));
    const __m512i a1 = _mm512_or_si512(_mm512_and_si512(z2, v3), _mm512_and_si512(nz2, v2));
    const __m512i a2 = _mm512_or_si512(_mm512_and_si512(z2, v5), _mm512_and_si512(nz2, v4));
    const __m512i a3 = _mm512_or_si512(_mm512_and_si512(z2, v7), _mm512_and_si512(nz2, v6));
    const __m512i b0 = _mm512_or_si512(_mm512_and_si512(z1, a1), _mm512_and_si512(nz1, a0));
    const __m512i b1 = _mm512_or_si512(_mm512_and_si512(z1, a3), _mm512_and_si512(nz1, a2));
    return _mm512_or_si512(_mm512_and_si512(z0, b1), _mm512_and_si512(nz0, b0));
}

static inline void bs_add8(const __m512i *a, const __m512i *b, __m512i *out) {
    __m512i carry = BS_ZERO;
    for (int i = 0; i < 8; i++) {
        const __m512i x = _mm512_xor_si512(a[i], b[i]);
        out[i] = _mm512_xor_si512(x, carry);
        carry = _mm512_or_si512(_mm512_and_si512(a[i], b[i]), _mm512_and_si512(carry, x));
    }
}

static inline void bs_tick(__m512i *t, __m512i *b, __m512i *l, __m512i *r,
                           const __m512i *kb, __m512i y_bs) {

    const __m512i Tt = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(
                                            _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(t[15], t[14]), t[10]), t[8]), t[5]), t[4]), t[1]), t[0]);
    const __m512i Bt = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(b[6], b[5]), b[4]), b[0]);

    const __m512i cr0 = r[7], cr1 = r[6], cr2 = r[5], cr3 = r[4];
    const __m512i cr4 = r[3], cr5 = r[2], cr6 = r[1], cr7 = r[0];

    const __m512i new_t = _mm512_xor_si512(_mm512_xor_si512(Tt, cr0), cr4);
    const __m512i new_b = _mm512_xor_si512(Bt, cr7);

    for (int i = 0; i < 15; i++) {
        t[i] = t[i + 1];
    }

    t[15] = new_t;

    for (int i = 0; i < 7; i++) {
        b[i] = b[i + 1];
    }

    b[7] = new_b;

    const __m512i ncr3 = bs_not(cr3);
    const __m512i ncr5 = bs_not(cr5);

    const __m512i z0 = _mm512_xor_si512(_mm512_xor_si512(_mm512_and_si512(cr0, cr2), _mm512_and_si512(cr1, ncr3)), _mm512_or_si512(cr2, cr4));
    const __m512i z1 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512( _mm512_or_si512(cr0, cr2), _mm512_or_si512(cr5, cr7)), cr1), cr6), Tt), y_bs);
    const __m512i z2 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(_mm512_and_si512(cr3, ncr5), _mm512_and_si512(cr4, cr6)), cr7), Tt);

    const __m512i nz0 = bs_not(z0);
    const __m512i nz1 = bs_not(z1);
    const __m512i nz2 = bs_not(z2);

    __m512i val[8];
    for (int bit = 0; bit < 8; bit++) {
        val[bit] = bs_mux8(z0, z1, z2, nz0, nz1, nz2,
                           kb[0 * 8 + bit], kb[1 * 8 + bit],
                           kb[2 * 8 + bit], kb[3 * 8 + bit],
                           kb[4 * 8 + bit], kb[5 * 8 + bit],
                           kb[6 * 8 + bit], kb[7 * 8 + bit]);
    }

    for (int i = 0; i < 8; i++) {
        val[i] = _mm512_xor_si512(val[i], b[i]);
    }

    __m512i old_r[8];
    for (int i = 0; i < 8; i++) {
        old_r[i] = r[i];
    }

    bs_add8(val, l, r);
    bs_add8(r, old_r, l);
}

// Lane patterns for L = 0..511, stored as 8 × uint64_t (word w covers lanes
// w*64 .. w*64+63, bit b of word w = lane w*64+b).
static const uint64_t LANE_BITS_512_RAW[9][BS512_WORDS] = {
    // k=0..5 are the same in-word pattern repeated across all 8 words.
    {0xAAAAAAAAAAAAAAAAULL, 0xAAAAAAAAAAAAAAAAULL, 0xAAAAAAAAAAAAAAAAULL, 0xAAAAAAAAAAAAAAAAULL,
     0xAAAAAAAAAAAAAAAAULL, 0xAAAAAAAAAAAAAAAAULL, 0xAAAAAAAAAAAAAAAAULL, 0xAAAAAAAAAAAAAAAAULL}, // k=0
    {0xCCCCCCCCCCCCCCCCULL, 0xCCCCCCCCCCCCCCCCULL, 0xCCCCCCCCCCCCCCCCULL, 0xCCCCCCCCCCCCCCCCULL,
     0xCCCCCCCCCCCCCCCCULL, 0xCCCCCCCCCCCCCCCCULL, 0xCCCCCCCCCCCCCCCCULL, 0xCCCCCCCCCCCCCCCCULL}, // k=1
    {0xF0F0F0F0F0F0F0F0ULL, 0xF0F0F0F0F0F0F0F0ULL, 0xF0F0F0F0F0F0F0F0ULL, 0xF0F0F0F0F0F0F0F0ULL,
     0xF0F0F0F0F0F0F0F0ULL, 0xF0F0F0F0F0F0F0F0ULL, 0xF0F0F0F0F0F0F0F0ULL, 0xF0F0F0F0F0F0F0F0ULL}, // k=2
    {0xFF00FF00FF00FF00ULL, 0xFF00FF00FF00FF00ULL, 0xFF00FF00FF00FF00ULL, 0xFF00FF00FF00FF00ULL,
     0xFF00FF00FF00FF00ULL, 0xFF00FF00FF00FF00ULL, 0xFF00FF00FF00FF00ULL, 0xFF00FF00FF00FF00ULL}, // k=3
    {0xFFFF0000FFFF0000ULL, 0xFFFF0000FFFF0000ULL, 0xFFFF0000FFFF0000ULL, 0xFFFF0000FFFF0000ULL,
     0xFFFF0000FFFF0000ULL, 0xFFFF0000FFFF0000ULL, 0xFFFF0000FFFF0000ULL, 0xFFFF0000FFFF0000ULL}, // k=4
    {0xFFFFFFFF00000000ULL, 0xFFFFFFFF00000000ULL, 0xFFFFFFFF00000000ULL, 0xFFFFFFFF00000000ULL,
     0xFFFFFFFF00000000ULL, 0xFFFFFFFF00000000ULL, 0xFFFFFFFF00000000ULL, 0xFFFFFFFF00000000ULL}, // k=5
    // k=6: alternate zero/all-ones per word.
    {0x0000000000000000ULL, 0xFFFFFFFFFFFFFFFFULL, 0x0000000000000000ULL, 0xFFFFFFFFFFFFFFFFULL,
     0x0000000000000000ULL, 0xFFFFFFFFFFFFFFFFULL, 0x0000000000000000ULL, 0xFFFFFFFFFFFFFFFFULL}, // k=6
    // k=7: 00110011 across words.
    {0x0000000000000000ULL, 0x0000000000000000ULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
     0x0000000000000000ULL, 0x0000000000000000ULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL}, // k=7
    // k=8: low half zero, high half all-ones.
    {0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL,
     0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL}, // k=8
};

static inline __m512i lane_bits_512(int k) {
    return _mm512_loadu_si512((const void *)LANE_BITS_512_RAW[k]);
}

static inline void bs_init_state(const __m512i kb[64],
                                 __m512i l[8], __m512i r[8],
                                 __m512i b[8], __m512i t[16]) {

    __m512i k0xor[8];
    k0xor[0] = kb[0];
    k0xor[1] = kb[1];
    k0xor[2] = _mm512_xor_si512(kb[2], BS_ONES);
    k0xor[3] = _mm512_xor_si512(kb[3], BS_ONES);
    k0xor[4] = kb[4];
    k0xor[5] = kb[5];
    k0xor[6] = _mm512_xor_si512(kb[6], BS_ONES);
    k0xor[7] = kb[7];

    const __m512i ec[8]  = {BS_ZERO, BS_ZERO, BS_ONES, BS_ONES, BS_ZERO, BS_ONES, BS_ONES, BS_ONES};
    const __m512i x21[8] = {BS_ONES, BS_ZERO, BS_ZERO, BS_ZERO, BS_ZERO, BS_ONES, BS_ZERO, BS_ZERO};

    bs_add8(k0xor, ec, l);
    bs_add8(k0xor, x21, r);

    b[0] = BS_ZERO; b[1] = BS_ZERO; b[2] = BS_ONES; b[3] = BS_ONES;
    b[4] = BS_ZERO; b[5] = BS_ZERO; b[6] = BS_ONES; b[7] = BS_ZERO;

    t[ 0] = BS_ZERO; t[ 1] = BS_ONES; t[ 2] = BS_ZERO; t[ 3] = BS_ZERO;
    t[ 4] = BS_ONES; t[ 5] = BS_ZERO; t[ 6] = BS_ZERO; t[ 7] = BS_ZERO;
    t[ 8] = BS_ZERO; t[ 9] = BS_ZERO; t[10] = BS_ZERO; t[11] = BS_ZERO;
    t[12] = BS_ZERO; t[13] = BS_ONES; t[14] = BS_ONES; t[15] = BS_ONES;
}

void prepare_ccnr_bits_bs512(const uint8_t *cc_nr, uint64_t y_bits_bs[96 * BS512_WORDS]) {
    for (int i = 0; i < 12; i++) {
        const uint8_t byte = cc_nr[i];
        for (int bit = 0; bit < 8; bit++) {
            _mm512_storeu_si512((void *)&y_bits_bs[(i * 8 + bit) * BS512_WORDS], ((byte >> bit) & 1) ? BS_ONES : BS_ZERO);
        }
    }
}

void prepare_target_mac_bs512(const uint8_t target_mac[4], uint64_t target_mac_bs[32 * BS512_WORDS]) {
    for (int i = 0; i < 4; i++) {
        const uint8_t byte = target_mac[i];
        for (int bit = 0; bit < 8; bit++) {
            _mm512_storeu_si512((void *)&target_mac_bs[(i * 8 + bit) * BS512_WORDS], ((byte >> bit) & 1) ? BS_ONES : BS_ZERO);
        }
    }
}

void build_bitslice_key_512(const uint8_t partial_key[8], uint64_t index_start, uint64_t kb[64 * BS512_WORDS]) {

    for (int j = 0; j < 8; j++) {
        _mm512_storeu_si512((void *)&kb[(j * 8 + 0) * BS512_WORDS], (partial_key[j] & 0x01) ? BS_ONES : BS_ZERO);
        _mm512_storeu_si512((void *)&kb[(j * 8 + 1) * BS512_WORDS], (partial_key[j] & 0x02) ? BS_ONES : BS_ZERO);
        _mm512_storeu_si512((void *)&kb[(j * 8 + 2) * BS512_WORDS], (partial_key[j] & 0x04) ? BS_ONES : BS_ZERO);
    }

    for (int j = 0; j < 8; j++) {

        const int base_bit = 5 * (7 - j);

        for (int kk = 0; kk < 5; kk++) {

            const int idx_bit = base_bit + kk;

            __m512i pattern;
            if (idx_bit < 9) {
                pattern = lane_bits_512(idx_bit);
            } else {
                pattern = ((index_start >> idx_bit) & 1) ? BS_ONES : BS_ZERO;
            }
            _mm512_storeu_si512((void *)&kb[(j * 8 + 3 + kk) * BS512_WORDS], pattern);
        }
    }
}

void doMAC_brute_match512(const uint64_t y_bits_bs[96 * BS512_WORDS],
                          const uint64_t kb[64 * BS512_WORDS],
                          const uint64_t target_mac_bs[32 * BS512_WORDS],
                          uint64_t match_out[BS512_WORDS]) {

    __m512i k[64];
    for (int i = 0; i < 64; i++) {
        k[i] = _mm512_loadu_si512((const void *)&kb[i * BS512_WORDS]);
    }
    __m512i l[8], r[8], b[8], t[16];
    bs_init_state(k, l, r, b, t);

    for (int i = 0; i < 96; i++) {
        bs_tick(t, b, l, r, k, _mm512_loadu_si512((const void *)&y_bits_bs[i * BS512_WORDS]));
    }

    __m512i mac_match = BS_ONES;
    for (int tick = 0; tick < 32; tick++) {

        const __m512i diff = _mm512_xor_si512(r[2], _mm512_loadu_si512((const void *)&target_mac_bs[tick * BS512_WORDS]));

        mac_match = _mm512_andnot_si512(diff, mac_match);

        if ((tick == 7 || tick == 15 || tick == 23) && _mm512_test_epi64_mask(mac_match, mac_match) == 0) {
            for (int i = 0; i < BS512_WORDS; i++) {
                match_out[i] = 0;
            }
            return;
        }

        if (tick < 31) {
            bs_tick(t, b, l, r, k, BS_ZERO);
        }
    }

    _mm512_storeu_si512((void *)match_out, mac_match);
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC pop_options
#endif

bool bs_avx512_supported(void) {
    static int cached = -1;
    if (cached < 0) {
#if defined(__GNUC__) || defined(__clang__)
        __builtin_cpu_init();
        cached = __builtin_cpu_supports("avx512f") ? 1 : 0;
#else
        cached = 0;
#endif
    }
    return cached != 0;
}

#else // non-x86 build

bool bs_avx512_supported(void) { return false; }

void prepare_ccnr_bits_bs512(const uint8_t *cc_nr, uint64_t y_bits_bs[96 * BS512_WORDS]) {
    (void)cc_nr; 
    (void)y_bits_bs;
}
void prepare_target_mac_bs512(const uint8_t target_mac[4], uint64_t target_mac_bs[32 * BS512_WORDS]) {
    (void)target_mac; 
    (void)target_mac_bs;
}
void build_bitslice_key_512(const uint8_t partial_key[8], uint64_t index_start, uint64_t kb[64 * BS512_WORDS]) {
    (void)partial_key; 
    (void)index_start; 
    (void)kb;
}
void doMAC_brute_match512(const uint64_t y_bits_bs[96 * BS512_WORDS],
                          const uint64_t kb[64 * BS512_WORDS],
                          const uint64_t target_mac_bs[32 * BS512_WORDS],
                          uint64_t match_out[BS512_WORDS]) {
    
    (void)y_bits_bs; 
    (void)kb; 
    (void)target_mac_bs;
    
    for (int i = 0; i < BS512_WORDS; i++) {
        match_out[i] = 0;
    }
}

#endif
