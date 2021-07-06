/*-
 * Copyright (C) 2010, Romain Tartiere.
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

#include "desfirecrypto.h"

#include <stdlib.h>
#include <string.h>
#include <util.h>
#include "ui.h"
#include "crc.h"
#include "crc16.h"        // crc16 ccitt
#include "crc32.h"
#include "commonutil.h"
#include "mifare/desfire_crypto.h"

void DesfireClearContext(DesfireContext *ctx) {
    ctx->keyNum = 0;
    ctx->keyType = T_DES;
    memset(ctx->key, 0, sizeof(ctx->key));

    ctx->secureChannel = DACNone;
    ctx->cmdSet = DCCNative;
    ctx->commMode = DCMNone;

    ctx->kdfAlgo = 0;
    ctx->kdfInputLen = 0;
    memset(ctx->kdfInput, 0, sizeof(ctx->kdfInput));

    DesfireClearSession(ctx);
}

void DesfireClearSession(DesfireContext *ctx) {
    ctx->secureChannel = DACNone; // here none - not authenticared

    memset(ctx->IV, 0, sizeof(ctx->IV));
    memset(ctx->sessionKeyMAC, 0, sizeof(ctx->sessionKeyMAC));
    memset(ctx->sessionKeyEnc, 0, sizeof(ctx->sessionKeyEnc));
    memset(ctx->lastIV, 0, sizeof(ctx->lastIV));
    ctx->cntrTx = 0;
    ctx->cntrRx = 0;
    memset(ctx->TI, 0, sizeof(ctx->TI));
}

void DesfireSetKey(DesfireContext *ctx, uint8_t keyNum, enum DESFIRE_CRYPTOALGO keyType, uint8_t *key) {
    DesfireClearContext(ctx);

    ctx->keyNum = keyNum;
    ctx->keyType = keyType;
    memcpy(ctx->key, key, desfire_get_key_length(keyType));
}

void DesfireSetCommandSet(DesfireContext *ctx, DesfireCommandSet cmdSet) {
    ctx->cmdSet = cmdSet;
}

void DesfireSetCommMode(DesfireContext *ctx, DesfireCommunicationMode commMode) {
    ctx->commMode = commMode;
}

void DesfireSetKdf(DesfireContext *ctx, uint8_t kdfAlgo, uint8_t *kdfInput, uint8_t kdfInputLen) {
    ctx->kdfAlgo = kdfAlgo;
    ctx->kdfInputLen = kdfInputLen;
    if (kdfInputLen)
        memcpy(ctx->kdfInput, kdfInput, kdfInputLen);
}

bool DesfireIsAuthenticated(DesfireContext *dctx) {
    return dctx->secureChannel != DACNone;
}

void DesfireCryptoEncDec(DesfireContext *ctx, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, bool encode) {
    uint8_t data[1024] = {0};

    switch (ctx->keyType) {
        case T_DES:
            if (ctx->secureChannel == DACd40) {
                if (encode)
                    des_encrypt_ecb(data, srcdata, srcdatalen, ctx->key);
                else
                    des_decrypt_ecb(data, srcdata, srcdatalen, ctx->key);
            }
            if (ctx->secureChannel == DACEV1) {
                if (encode)
                    des_encrypt_cbc(data, srcdata, srcdatalen, ctx->key, ctx->IV);
                else
                    des_decrypt_cbc(data, srcdata, srcdatalen, ctx->key, ctx->IV);
            }

            if (dstdata)
                memcpy(dstdata, data, srcdatalen);
            break;
        case T_3DES:
            break;
        case T_3K3DES:
            break;
        case T_AES:
            if (encode)
                aes_encode(ctx->IV, ctx->key, srcdata, data, srcdatalen);
            else
                aes_decode(ctx->IV, ctx->key, srcdata, data, srcdatalen);
            if (dstdata)
                memcpy(dstdata, data, srcdatalen);
            break;
    }
}

