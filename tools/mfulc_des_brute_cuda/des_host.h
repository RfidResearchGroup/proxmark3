/*
 * des_host.h — Self-contained CPU DES implementation (no OpenSSL, no CUDA).
 * Used for LFSR detection before GPU launch.
 *
 * All uint64_t values are "big-endian packed": byte 0 of the DES block occupies
 * bits 63-56, byte 7 occupies bits 7-0. This matches our GPU DES output format
 * exactly, so the same LFSR / rotation checks work on both sides without bswap.
 */
#pragma once
#include <stdint.h>
#include <string.h>

/* -------------------------------------------------------------------------- */
/* DES constant tables (1-indexed bit positions, MSB = bit 1 = our bit 0)    */
/* -------------------------------------------------------------------------- */

static const uint8_t H_PC1[56] = {
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
};

static const uint8_t H_PC2[48] = {
    14, 17, 11, 24, 1, 5,  3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

static const uint8_t H_SHIFTS[16] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

static const uint8_t H_IP[64] = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
};

static const uint8_t H_FP[64] = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
};

static const uint8_t H_E[48] = {
    32, 1, 2, 3, 4, 5,  4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
};

static const uint8_t H_P[32] = {
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
};

static const uint8_t H_SBOX[8][4][16] = {
    {   {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7}, /* S1 */
        {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    },
    {   {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10}, /* S2 */
        {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
        {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
        {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
    },
    {   {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8}, /* S3 */
        {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
        {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
        {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
    },
    {   {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15}, /* S4 */
        {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
        {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
        {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
    },
    {   {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9}, /* S5 */
        {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
        {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
        {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
    },
    {   {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11}, /* S6 */
        {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
        {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
        {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
    },
    {   {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1}, /* S7 */
        {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
        {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
        {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
    },
    {   {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7}, /* S8 */
        {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
        {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
        {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
    }
};

/* -------------------------------------------------------------------------- */
/* Utility                                                                     */
/* -------------------------------------------------------------------------- */

/* Convert 8-byte array (big-endian) → packed uint64 (byte 0 in bits 63-56) */
static inline uint64_t bytes_to_u64(const uint8_t *b) {
    return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) |
           ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32) |
           ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] <<  8) | (uint64_t)b[7];
}

/* -------------------------------------------------------------------------- */
/* CPU DES primitives                                                          */
/* -------------------------------------------------------------------------- */

static inline uint64_t h_perm(uint64_t src, int src_bits, const uint8_t *tbl, int n) {
    uint64_t dst = 0;
    int i;
    for (i = 0; i < n; i++) {
        int sb = tbl[i] - 1;
        dst |= ((src >> (src_bits - 1 - sb)) & 1ULL) << (n - 1 - i);
    }
    return dst;
}

static inline void h_des_keyschedule(uint64_t key64, uint64_t sk[16]) {
    uint64_t key56 = h_perm(key64, 64, H_PC1, 56);
    uint32_t C = (uint32_t)(key56 >> 28) & 0x0FFFFFFFU;
    uint32_t D = (uint32_t)(key56)       & 0x0FFFFFFFU;
    int i;
    for (i = 0; i < 16; i++) {
        int s = H_SHIFTS[i];
        C = ((C << s) | (C >> (28 - s))) & 0x0FFFFFFFU;
        D = ((D << s) | (D >> (28 - s))) & 0x0FFFFFFFU;
        sk[i] = h_perm(((uint64_t)C << 28) | D, 56, H_PC2, 48);
    }
}

static inline uint64_t h_des_crypt(uint64_t block, const uint64_t sk[16]) {
    uint64_t ip  = h_perm(block, 64, H_IP, 64);
    uint32_t L   = (uint32_t)(ip >> 32);
    uint32_t R   = (uint32_t)(ip);
    int i;
    for (i = 0; i < 16; i++) {
        uint64_t eR  = h_perm((uint64_t)R, 32, H_E, 48);
        uint64_t x   = eR ^ sk[i];
        uint32_t sout = 0;
        int s;
        for (s = 0; s < 8; s++) {
            uint8_t b6  = (uint8_t)((x >> (42 - s * 6)) & 0x3F);
            int row = ((b6 >> 5) & 1) * 2 + (b6 & 1);
            int col = (b6 >> 1) & 0xF;
            sout |= (uint32_t)H_SBOX[s][row][col] << (28 - s * 4);
        }
        uint32_t f  = (uint32_t)h_perm((uint64_t)sout, 32, H_P, 32);
        uint32_t nR = L ^ f;
        L = R;
        R = nR;
    }
    return h_perm(((uint64_t)R << 32) | L, 64, H_FP, 64);
}

static inline uint64_t h_des_decrypt(uint64_t block, const uint64_t sk[16]) {
    uint64_t rsk[16];
    int i;
    for (i = 0; i < 16; i++) rsk[i] = sk[15 - i];
    return h_des_crypt(block, rsk);
}

/* -------------------------------------------------------------------------- */
/* LFSR validators (input: BE uint64, byte 0 in bits 63-56)                  */
/* -------------------------------------------------------------------------- */

static inline int h_valid_lfsr_ulcg(uint64_t x64) {
    /* x64 is already B0=MSB; original code bswap'd from OpenSSL LE, we skip that */
    uint16_t x16 = (uint16_t)(x64 >> 48);
    x16 = (uint16_t)(x16 << 15 | ((x16 >> 1) ^ ((x16 >> 3 ^ x16 >> 4 ^ x16 >> 6) & 1)));
    if (x16 != (uint16_t)((x64 >> 32) & 0xFFFF)) return 0;
    x16 = (uint16_t)(x16 << 15 | ((x16 >> 1) ^ ((x16 >> 3 ^ x16 >> 4 ^ x16 >> 6) & 1)));
    if (x16 != (uint16_t)((x64 >> 16) & 0xFFFF)) return 0;
    x16 = (uint16_t)(x16 << 15 | ((x16 >> 1) ^ ((x16 >> 3 ^ x16 >> 4 ^ x16 >> 6) & 1)));
    if (x16 != (uint16_t)(x64 & 0xFFFF)) return 0;
    return 1;
}

static inline int h_valid_lfsr_mfc(uint64_t x64) {
    uint16_t x16 = (uint16_t)(x64 & 0xFFFF);
    int i;
    for (i = 0; i < 16; i++)
        x16 = (uint16_t)(x16 >> 1 | (x16 ^ x16 >> 2 ^ x16 >> 3 ^ x16 >> 5) << 15);
    if (x16 != (uint16_t)((x64 >> 16) & 0xFFFF)) return 0;
    for (i = 0; i < 16; i++)
        x16 = (uint16_t)(x16 >> 1 | (x16 ^ x16 >> 2 ^ x16 >> 3 ^ x16 >> 5) << 15);
    if (x16 != (uint16_t)((x64 >> 32) & 0xFFFF)) return 0;
    for (i = 0; i < 16; i++)
        x16 = (uint16_t)(x16 >> 1 | (x16 ^ x16 >> 2 ^ x16 >> 3 ^ x16 >> 5) << 15);
    if (x16 != (uint16_t)((x64 >> 48) & 0xFFFF)) return 0;
    return 1;
}

/*
 * Detect LFSR type from init_ciphertext (8 bytes).
 * Decrypts with the all-zero DES key and checks LFSR structure.
 * Returns 1=ULCG, 2=MFC, 0=unknown.
 */
static inline int h_detect_lfsr(const uint8_t init_ciphertext[8]) {
    uint8_t zero_key[8];
    uint64_t sk[16];
    uint64_t ct, out;
    memset(zero_key, 0, 8);
    h_des_keyschedule(bytes_to_u64(zero_key), sk);
    ct  = bytes_to_u64(init_ciphertext);
    out = h_des_decrypt(ct, sk);
    if (h_valid_lfsr_ulcg(out)) return 1;
    if (h_valid_lfsr_mfc(out))  return 2;
    return 0;
}
