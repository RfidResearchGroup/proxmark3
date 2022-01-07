//-----------------------------------------------------------------------------
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
// description here: Leakage Resilient Primitive (LRP) Specification, https://www.nxp.com/docs/en/application-note/AN12304.pdf
//-----------------------------------------------------------------------------

#include "lrpcrypto.h"

#include <stdlib.h>
#include <string.h>
#include <util.h>
#include "ui.h"
#include "aes.h"
#include "commonutil.h"

static uint8_t constAA[] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};
static uint8_t const55[] = {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
static uint8_t const00[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

void LRPClearContext(LRPContext_t *ctx) {
    memset(ctx->key, 0, CRYPTO_AES128_KEY_SIZE);

    ctx->useBitPadding = false;
    ctx->plaintextsCount = 0;
    memset(ctx->plaintexts, 0, LRP_MAX_PLAINTEXTS_SIZE * CRYPTO_AES128_KEY_SIZE);
    ctx->updatedKeysCount = 0;
    memset(ctx->updatedKeys, 0, LRP_MAX_UPDATED_KEYS_SIZE * CRYPTO_AES128_KEY_SIZE);
    ctx->useUpdatedKeyNum = 0;
}

void LRPSetKey(LRPContext_t *ctx, uint8_t *key, size_t updatedKeyNum, bool useBitPadding) {
    LRPClearContext(ctx);

    memcpy(ctx->key, key, CRYPTO_AES128_KEY_SIZE);

    LRPGeneratePlaintexts(ctx, 16);
    LRPGenerateUpdatedKeys(ctx, 4);

    ctx->useUpdatedKeyNum = updatedKeyNum;
    ctx->useBitPadding = useBitPadding;

    memcpy(ctx->counter, const00, CRYPTO_AES128_KEY_SIZE);
    ctx->counterLenNibbles = CRYPTO_AES128_KEY_SIZE;
}

void LRPSetCounter(LRPContext_t *ctx, uint8_t *counter, size_t counterLenNibbles) {
    memcpy(ctx->counter, counter, counterLenNibbles / 2);
    ctx->counterLenNibbles = counterLenNibbles;
}

void LRPSetKeyEx(LRPContext_t *ctx, uint8_t *key, uint8_t *counter, size_t counterLenNibbles, size_t updatedKeyNum, bool useBitPadding) {
    LRPSetKey(ctx, key, updatedKeyNum, useBitPadding);
    LRPSetCounter(ctx, counter, counterLenNibbles);
}


// https://www.nxp.com/docs/en/application-note/AN12304.pdf
// Algorithm 1
void LRPGeneratePlaintexts(LRPContext_t *ctx, size_t plaintextsCount) {
    if (plaintextsCount > LRP_MAX_PLAINTEXTS_SIZE)
        return;

    uint8_t h[CRYPTO_AES128_KEY_SIZE] = {0};
    memcpy(h, ctx->key, CRYPTO_AES128_KEY_SIZE);

    for (int i = 0; i < plaintextsCount; i++) {
        aes_encode(NULL, h, const55, h, CRYPTO_AES128_KEY_SIZE);
        aes_encode(NULL, h, constAA, ctx->plaintexts[i], CRYPTO_AES128_KEY_SIZE);
    }

    ctx->plaintextsCount = plaintextsCount;
}

// https://www.nxp.com/docs/en/application-note/AN12304.pdf
// Algorithm 2
void LRPGenerateUpdatedKeys(LRPContext_t *ctx, size_t updatedKeysCount) {
    if (updatedKeysCount > LRP_MAX_UPDATED_KEYS_SIZE)
        return;

    uint8_t h[CRYPTO_AES128_KEY_SIZE] = {0};
    aes_encode(NULL, ctx->key, constAA, h, CRYPTO_AES128_KEY_SIZE);

    for (int i = 0; i < updatedKeysCount; i++) {
        aes_encode(NULL, h, constAA, ctx->updatedKeys[i], CRYPTO_AES128_KEY_SIZE);
        aes_encode(NULL, h, const55, h, CRYPTO_AES128_KEY_SIZE);
    }

    ctx->updatedKeysCount = updatedKeysCount;
}

// https://www.nxp.com/docs/en/application-note/AN12304.pdf
// Algorithm 3
void LRPEvalLRP(LRPContext_t *ctx, const uint8_t *iv, size_t ivlen, bool final, uint8_t *y) {
    uint8_t ry[CRYPTO_AES128_KEY_SIZE] = {0};
    memcpy(ry, ctx->updatedKeys[ctx->useUpdatedKeyNum], CRYPTO_AES128_KEY_SIZE);

    for (int i = 0; i < ivlen; i++) {
        uint8_t nk = (i % 2) ? iv[i / 2] & 0x0f : (iv[i / 2] >> 4) & 0x0f;
        aes_encode(NULL, ry, ctx->plaintexts[nk], ry, CRYPTO_AES128_KEY_SIZE);
    }

    if (final)
        aes_encode(NULL, ry, const00, ry, CRYPTO_AES128_KEY_SIZE);
    memcpy(y, ry, CRYPTO_AES128_KEY_SIZE);
}

void LRPIncCounter(uint8_t *ctr, size_t ctrlen) {
    bool carry = true;
    for (int i = ctrlen - 1; i >= 0; i--) {
        uint8_t nk = (i % 2) ? ctr[i / 2] & 0x0f : (ctr[i / 2] >> 4) & 0x0f;

        if (carry)
            nk++;

        carry = (nk > 0xf);
        if (i % 2)
            ctr[i / 2] = (ctr[i / 2] & 0xf0) | (nk & 0x0f);
        else
            ctr[i / 2] = (ctr[i / 2] & 0x0f) | ((nk << 4) & 0xf0);

        if (!carry)
            break;
    }
}

// https://www.nxp.com/docs/en/application-note/AN12304.pdf
// Algorithm 4
void LRPEncode(LRPContext_t *ctx, uint8_t *data, size_t datalen, uint8_t *resp, size_t *resplen) {
    *resplen = 0;

    if ((datalen > 0) && (data == NULL)) {
        return;
    }
    uint8_t xdata[1024] = {0};
    memcpy(xdata, data, datalen);
    if (ctx->useBitPadding) {
        xdata[datalen] = 0x80;
        datalen++;
    }

    if (datalen % CRYPTO_AES128_KEY_SIZE)
        datalen = datalen + CRYPTO_AES128_KEY_SIZE - (datalen % CRYPTO_AES128_KEY_SIZE);

    if (datalen == 0)
        return;

    uint8_t y[CRYPTO_AES128_KEY_SIZE] = {0};
    for (int i = 0; i < datalen / CRYPTO_AES128_KEY_SIZE; i++) {
        LRPEvalLRP(ctx, ctx->counter, ctx->counterLenNibbles, true, y);
        aes_encode(NULL, y, &xdata[i * CRYPTO_AES128_KEY_SIZE], &resp[i * CRYPTO_AES128_KEY_SIZE], CRYPTO_AES128_KEY_SIZE);
        *resplen += CRYPTO_AES128_KEY_SIZE;
        LRPIncCounter(ctx->counter, ctx->counterLenNibbles);
    }
}

// https://www.nxp.com/docs/en/application-note/AN12304.pdf
// Algorithm 5
void LRPDecode(LRPContext_t *ctx, uint8_t *data, size_t datalen, uint8_t *resp, size_t *resplen) {
    *resplen = 0;
    if (datalen % CRYPTO_AES128_KEY_SIZE)
        return;

    uint8_t y[CRYPTO_AES128_KEY_SIZE] = {0};
    for (int i = 0; i < datalen / CRYPTO_AES128_KEY_SIZE; i++) {
        LRPEvalLRP(ctx, ctx->counter, ctx->counterLenNibbles, true, y);
        aes_decode(NULL, y, &data[i * CRYPTO_AES128_KEY_SIZE], &resp[i * CRYPTO_AES128_KEY_SIZE], CRYPTO_AES128_KEY_SIZE);
        *resplen += CRYPTO_AES128_KEY_SIZE;
        LRPIncCounter(ctx->counter, ctx->counterLenNibbles);
    }

    // search padding
    if (ctx->useBitPadding) {
        for (int i = *resplen - 1; i >= *resplen - CRYPTO_AES128_KEY_SIZE; i--) {
            if (resp[i] == 0x80)
                *resplen = i;
            if (resp[i] != 0x00)
                break;
        }
    }
}

void LRPEncDec(uint8_t *key, uint8_t *iv, bool encode, uint8_t *data, size_t datalen, uint8_t *resp, size_t *resplen) {
    LRPContext_t ctx = {0};

    LRPSetKeyEx(&ctx, key, iv, 4 * 2, 1, true);
    if (encode)
        LRPEncode(&ctx, data, datalen, resp, resplen);
    else
        LRPDecode(&ctx, data, datalen, resp, resplen);
}

static bool shiftLeftBe(uint8_t *data, size_t length) {
    if (length == 0)
        return false;

    bool carry = false;
    for (int i = length - 1; i >= 0; i--) {
        uint8_t val = data[i];
        val = (val << 1) | ((carry) ? 1 : 0);
        carry = ((data[i] & 0x80) != 0);
        data[i] = val;
    }
    return carry;
}

// GF(2 ^ 128)
// poly x^128 + x ^ 7 + x ^ 2 + x + 1
// bit: 1000..0010000111 == 0x1 00 00 .. 00 00 87
static void mulPolyX(uint8_t *data) {
    if (shiftLeftBe(data, 16))
        data[15] = data[15] ^ 0x87;
}

void LRPGenSubkeys(uint8_t *key, uint8_t *sk1, uint8_t *sk2) {
    LRPContext_t ctx = {0};
    LRPSetKey(&ctx, key, 0, true);

    uint8_t y[CRYPTO_AES128_KEY_SIZE] = {0};
    LRPEvalLRP(&ctx, const00, CRYPTO_AES128_KEY_SIZE * 2, true, y);

    mulPolyX(y);
    memcpy(sk1, y, CRYPTO_AES128_KEY_SIZE);

    mulPolyX(y);
    memcpy(sk2, y, CRYPTO_AES128_KEY_SIZE);
}

// https://www.nxp.com/docs/en/application-note/AN12304.pdf
// Algorithm 6
void LRPCMAC(LRPContext_t *ctx, uint8_t *data, size_t datalen, uint8_t *cmac) {
    uint8_t sk1[CRYPTO_AES128_KEY_SIZE] = {0};
    uint8_t sk2[CRYPTO_AES128_KEY_SIZE] = {0};
    LRPGenSubkeys(ctx->key, sk1, sk2);

    uint8_t y[CRYPTO_AES128_KEY_SIZE] = {0};
    size_t clen = 0;
    for (int i = 0; i < datalen / CRYPTO_AES128_KEY_SIZE; i++) {
        if (datalen - clen <= CRYPTO_AES128_KEY_SIZE)
            break;

        bin_xor(y, &data[i * CRYPTO_AES128_KEY_SIZE], CRYPTO_AES128_KEY_SIZE);
        LRPEvalLRP(ctx, y, CRYPTO_AES128_KEY_SIZE * 2, true, y);
        clen += CRYPTO_AES128_KEY_SIZE;
    }

    size_t bllen = datalen - clen;
    bllen = MIN(bllen, CRYPTO_AES128_KEY_SIZE); // coverity
    uint8_t bl[CRYPTO_AES128_KEY_SIZE] = {0};
    memcpy(bl, &data[clen], bllen);

    // last block
    if (bllen == 16) {
        bin_xor(y, bl, CRYPTO_AES128_KEY_SIZE);

        bin_xor(y, sk1, CRYPTO_AES128_KEY_SIZE);
    } else {
        // padding
        bl[bllen] = 0x80;
        bin_xor(y, bl, CRYPTO_AES128_KEY_SIZE);

        bin_xor(y, sk2, CRYPTO_AES128_KEY_SIZE);
    }

    LRPEvalLRP(ctx, y, CRYPTO_AES128_KEY_SIZE * 2, true, cmac);
}

void LRPCMAC8(LRPContext_t *ctx, uint8_t *data, size_t datalen, uint8_t *cmac) {
    uint8_t cmac_tmp[16] = {0};
    memset(cmac, 0x00, 8);

    LRPCMAC(ctx, data, datalen, cmac_tmp);

    for (int i = 0; i < 8; i++)
        cmac[i] = cmac_tmp[i * 2 + 1];
}
