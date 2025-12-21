//-----------------------------------------------------------------------------
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
// Calculate CMAC AES
//-----------------------------------------------------------------------------
#include "cmac_calc.h"

#include <string.h>
#include "commonutil.h"
#include "BigBuf.h"
#include "dbprint.h"
#include "mbedtls/aes.h"

static ulaes_key_t g_secure_session = {
    .counter = 0,
    .use_schann = false,
};

// initialise global secure session object
void init_secure_session(void) {
    g_secure_session.counter = 0;
    g_secure_session.use_schann = false;
    memset(g_secure_session.cmac_sk1, 0, sizeof(g_secure_session.cmac_sk1));
    memset(g_secure_session.cmac_sk2, 0, sizeof(g_secure_session.cmac_sk2));
    memset(g_secure_session.sessionkey, 0, sizeof(g_secure_session.sessionkey));
}

void increase_session_counter(void) {
    g_secure_session.counter++;
}

void set_session_channel(bool use_schann) {
    g_secure_session.use_schann = use_schann;
}

ulaes_key_t *get_secure_session_obj(void) {
    return &g_secure_session;
}

// XOR two 128-bit blocks
static void xor_128(const uint8_t *a, const uint8_t *b, uint8_t *out) {
    for (int i = 0; i < 16; i++) {
        out[i] = a[i] ^ b[i];
    }
}

// Left shift one bit in a 128-bit block
static void left_shift_128(const uint8_t *input, uint8_t *output) {
    uint8_t overflow = 0;
    for (int i = 15; i >= 0; i--) {
        output[i] = (input[i] << 1) | overflow;
        overflow = (input[i] & 0x80) ? 1 : 0;
    }
}

// Generate Subkeys K1 and K2
static void generate_subkeys(mbedtls_aes_context *ctx, uint8_t *K1, uint8_t *K2) {
    uint8_t L[16] = {0};

    // Step 1: L = AES-ENC(0^128)
    mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, L, L);

    // Step 2: K1 = L << 1 (with conditional XOR with 0x87)
    left_shift_128(L, K1);
    if (L[0] & 0x80) {
        // If MSB is 1
        K1[15] ^= 0x87;
    }

    // Step 3: K2 = K1 << 1 (with conditional XOR with 0x87)
    left_shift_128(K1, K2);
    if (K1[0] & 0x80) {
        K2[15] ^= 0x87;
    }
}

// Pad the last block (adds 0x80 followed by zeros)
static void padding(const uint8_t *lastb, uint8_t *pad, size_t len) {
    memset(pad, 0x00, len);
    memcpy(pad, lastb, len);
    pad[len] = 0x80;
}

// CMAC implementation
void ulaes_cmac(const uint8_t *key, size_t key_len, const uint8_t *input, size_t ilen, uint8_t output[16]) {

    uint8_t last[16] = {0};
    uint8_t X[16] = {0};
    uint8_t Y[16] = {0};
    uint8_t buffer[16] = {0};

    int last_block_complete = (ilen % 16 == 0 && ilen != 0);

    memset(g_secure_session.cmac_sk1, 0, sizeof(g_secure_session.cmac_sk1));
    memset(g_secure_session.cmac_sk2, 0, sizeof(g_secure_session.cmac_sk2));

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 128);

    generate_subkeys(&ctx, g_secure_session.cmac_sk1, g_secure_session.cmac_sk2);

    size_t n_blocks = (ilen + 15) / 16;

    // prepare last block
    if (n_blocks == 0) {
        // if message is empty, CMAC is just MAC of padded block XOR K2
        // since buffer is all zeros here.
        n_blocks = 1;
        buffer[0] = 0x80;
        xor_128(buffer, g_secure_session.cmac_sk2, last);
    } else {

        const uint8_t *last_block = input + 16 * (n_blocks - 1);

        if (last_block_complete) {
            xor_128(last_block, g_secure_session.cmac_sk1, last);
        } else {
            padding(last_block, buffer, ilen % 16);
            xor_128(buffer, g_secure_session.cmac_sk2, last);
        }
    }

    // main loop
    for (size_t i = 0; i < n_blocks - 1; i++) {
        xor_128(X, input + 16 * i, Y);
        mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, Y, X);
    }

    // last block
    xor_128(X, last, Y);
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, Y, output);
    mbedtls_aes_free(&ctx);
}

// convert from 16 bytes to 8 bytes
void ulaes_cmac8(uint8_t *cmac, uint8_t *mac) {
    uint8_t j = 0;
    for (int i = 1; i < 16; i += 2) {
        mac[j++] = cmac[i];
    }
}

void append_cmac(uint8_t *d, size_t n) {
    uint8_t mac[16] = {0};
    uint8_t cmd_mac[2 + n];
    cmd_mac[0] = g_secure_session.counter & 0xFF;
    cmd_mac[1] = (g_secure_session.counter >> 8) & 0xFF;
    memcpy(cmd_mac + 2, d, n);

    print_result("cmd mac", cmd_mac, (2 + n));

    ulaes_cmac(g_secure_session.sessionkey, sizeof(g_secure_session.sessionkey), cmd_mac, (2 + n), mac);
    // append CMAC to end of the command we are trying to send
    ulaes_cmac8(mac, d + n);

    increase_session_counter();
}
