//-----------------------------------------------------------------------------
// Copyright (C) Aaron Tulino - December 2025
// Copyright (C) Christian Herrmman, Iceman - October 2025
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// Calculate CMAC 3DES
//-----------------------------------------------------------------------------
#include "cmac_3des.h"

#include <string.h>
#include "commonutil.h"
#include "dbprint.h"
#include "mbedtls/des.h"

// XOR two 64-bit blocks
static void xor_64(const uint8_t *a, const uint8_t *b, uint8_t *out) {
    for (int i = 0; i < 8; i++) {
        out[i] = a[i] ^ b[i];
    }
}

// Left shift one bit in a 64-bit block
static void left_shift_64(const uint8_t *input, uint8_t *output) {
    uint8_t overflow = 0;
    for (int i = 7; i >= 0; i--) {
        output[i] = (input[i] << 1) | overflow;
        overflow = (input[i] & 0x80) ? 1 : 0;
    }
}

// Generate Subkeys K1 and K2
static void generate_subkeys(mbedtls_des3_context *ctx, uint8_t *K1, uint8_t *K2) {
    uint8_t L[8] = {0};

    // Step 1: L = 3DES-ENC(0^64)
    mbedtls_des3_crypt_ecb(ctx, L, L);

    // Step 2: K1 = L << 1 (with conditional XOR with 0x1B)
    left_shift_64(L, K1);
    if (L[0] & 0x80) {
        // If MSB is 1
        K1[7] ^= 0x1B;
    }

    // Step 3: K2 = K1 << 1 (with conditional XOR with 0x1B)
    left_shift_64(K1, K2);
    if (K1[0] & 0x80) {
        K2[7] ^= 0x1B;
    }
}

// Pad the last block (adds 0x80 followed by zeros)
static void padding(const uint8_t *lastb, uint8_t *pad, size_t len) {
    memset(pad, 0x00, len);
    memcpy(pad, lastb, len);
    pad[len] = 0x80;
}

// CMAC implementation
void des3_cmac(const uint8_t *key, size_t key_len, const uint8_t *input, size_t ilen, uint8_t output[8]) {
    uint8_t last[8] = {0};
    uint8_t X[8] = {0};
    uint8_t Y[8] = {0};
    uint8_t buffer[8] = {0};
    uint8_t K1[8] = {0};
    uint8_t K2[8] = {0};

    int last_block_complete = (ilen % 8 == 0 && ilen != 0);

    mbedtls_des3_context ctx;
    mbedtls_des3_init(&ctx);
    if (key_len == 16) {
        mbedtls_des3_set2key_enc(&ctx, key);
    } else if (key_len == 24) {
        mbedtls_des3_set3key_enc(&ctx, key);
    }

    generate_subkeys(&ctx, K1, K2);

    size_t n_blocks = (ilen + 7) / 8;

    // prepare last block
    if (n_blocks == 0) {
        // if message is empty, CMAC is just MAC of padded block XOR K2
        // since buffer is all zeros here.
        n_blocks = 1;
        buffer[0] = 0x80;
        xor_64(buffer, K2, last);
    } else {

        const uint8_t *last_block = input + 8 * (n_blocks - 1);

        if (last_block_complete) {
            xor_64(last_block, K1, last);
        } else {
            padding(last_block, buffer, ilen % 8);
            xor_64(buffer, K2, last);
        }
    }

    // main loop
    for (size_t i = 0; i < n_blocks - 1; i++) {
        xor_64(X, input + 8 * i, Y);
        mbedtls_des3_crypt_ecb(&ctx, Y, X);
    }

    // last block
    xor_64(X, last, Y);
    mbedtls_des3_crypt_ecb(&ctx, Y, output);
    mbedtls_des3_free(&ctx);

}
