/*-
 * Copyright (C) 2021 Merlok
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 * $Id$
 */

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

void LRPClearContext(LRPContext *ctx) {
    memset(ctx->key, 0, CRYPTO_AES128_KEY_SIZE);
    
    ctx->useBitPadding = false;
    ctx->plaintextsCount = 0;
    memset(ctx->plaintexts, 0, LRP_MAX_PLAINTEXTS_SIZE * CRYPTO_AES128_KEY_SIZE);
    ctx->updatedKeysCount = 0;
    memset(ctx->updatedKeys, 0, LRP_MAX_UPDATED_KEYS_SIZE * CRYPTO_AES128_KEY_SIZE);
    ctx->useUpdatedKeyNum = 0;
}

void LRPSetKey(LRPContext *ctx, uint8_t *key, size_t updatedKeyNum, bool useBitPadding) {
    LRPClearContext(ctx);
    
    memcpy(ctx->key, key, CRYPTO_AES128_KEY_SIZE);
    
    LRPGeneratePlaintexts(ctx, 16);
    LRPGenerateUpdatedKeys(ctx, 4);
    
    ctx->useUpdatedKeyNum = updatedKeyNum;
    ctx->useBitPadding = useBitPadding;
}

void LRPSetCounter(LRPContext *ctx, uint8_t *counter, size_t counterLenNibbles) {
    memcpy(ctx->counter, counter, counterLenNibbles / 2);
    ctx->counterLenNibbles = counterLenNibbles;
}

void LRPSetKeyEx(LRPContext *ctx, uint8_t *key, uint8_t *counter, size_t counterLenNibbles, size_t updatedKeyNum, bool useBitPadding){
    LRPSetKey(ctx, key, updatedKeyNum, useBitPadding);
    LRPSetCounter(ctx, counter, counterLenNibbles);
}


// https://www.nxp.com/docs/en/application-note/AN12304.pdf
// Algorithm 1
void LRPGeneratePlaintexts(LRPContext *ctx, size_t plaintextsCount) {
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
void LRPGenerateUpdatedKeys(LRPContext *ctx, size_t updatedKeysCount) {
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
void LRPEvalLRP(LRPContext *ctx, uint8_t *iv, size_t ivlen, bool final, uint8_t *y) {
    memcpy(y, ctx->updatedKeys[ctx->useUpdatedKeyNum], CRYPTO_AES128_KEY_SIZE);
    
    for (int i = 0; i < ivlen; i++) {
        uint8_t nk = (i % 2) ? iv[i / 2] & 0x0f : (iv[i / 2] >> 4) & 0x0f;
        aes_encode(NULL, y, ctx->plaintexts[nk], y, CRYPTO_AES128_KEY_SIZE);
    }
    
    if (final)
        aes_encode(NULL, y, const00, y, CRYPTO_AES128_KEY_SIZE);
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
        
        if(!carry)
            break;
    }
}

// https://www.nxp.com/docs/en/application-note/AN12304.pdf
// Algorithm 4
void LRPEncode(LRPContext *ctx, uint8_t *data, size_t datalen, uint8_t *resp, size_t *resplen) {
    *resplen = 0;
    
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

void LRPDecode(LRPContext *ctx, uint8_t *data, size_t datalen, uint8_t *resp, size_t *resplen) {
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
