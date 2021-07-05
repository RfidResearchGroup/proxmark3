//-----------------------------------------------------------------------------
// Copyright (C) 2010 Romain Tartiere.
// Copyright (C) 2014 Iceman
// Copyright (C) 2021 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency Desfire secure channel functions
//-----------------------------------------------------------------------------

#include "desfiresecurechan.h"

#include <stdlib.h>
#include <string.h>
#include <util.h>
#include "ui.h"
#include "crc.h"
#include "crc16.h"        // crc16 ccitt
#include "crc32.h"
#include "commonutil.h"
#include "mifare/desfire_crypto.h"


void DesfireCryptoEncDec(DesfireContext *ctx, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, bool encode) {
    uint8_t data[1024] = {0};

    switch(ctx->keyType) {
        case T_DES:
            if (ctx->secureChannel == DACd40) {
                if (encode)
                    des_encrypt_ecb(data, srcdata, srcdatalen, ctx->key);
                else
                    des_decrypt_ecb(data, srcdata, srcdatalen, ctx->key);
            } if (ctx->secureChannel == DACEV1) {
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

static void DesfireSecureChannelEncodeD40(DesfireContext *ctx, uint8_t cmd, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, size_t *dstdatalen) {
    memcpy(dstdata, srcdata, srcdatalen);
    *dstdatalen = srcdatalen;
    
    uint8_t data[1024] = {0};
    size_t rlen = 0;

    switch(ctx->commMode) {
        case DCMPlain:
            memcpy(dstdata, srcdata, srcdatalen);
            *dstdatalen = srcdatalen;
            break;
        case DCMMACed:
            if (srcdatalen == 0)
                break;
            
            rlen = padded_data_length(srcdatalen, desfire_get_key_block_length(ctx->keyType));
            memcpy(data, srcdata, srcdatalen);
            DesfireCryptoEncDec(ctx, data, rlen, NULL, true);
            memcpy(dstdata, srcdata, srcdatalen);
            memcpy(&dstdata[srcdatalen], ctx->IV, 4);
            *dstdatalen = rlen;
            break;
        case DCMEncrypted:
            rlen = padded_data_length(srcdatalen + 2, desfire_get_key_block_length(ctx->keyType)); // 2 - crc16
            memcpy(data, srcdata, srcdatalen);
            compute_crc(CRC_14443_A, data, srcdatalen, &data[srcdatalen], &data[srcdatalen + 1]);
            DesfireCryptoEncDec(ctx, data, rlen, dstdata, true);
            *dstdatalen = rlen;
            break;
        case DCMNone:;
    }
}

static void DesfireSecureChannelEncodeEV1(DesfireContext *ctx, uint8_t cmd, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, size_t *dstdatalen) {
    memcpy(dstdata, srcdata, srcdatalen);
    *dstdatalen = srcdatalen;

    switch(ctx->commMode) {
        case DCMPlain:
        case DCMMACed:
            
            break;
        case DCMEncrypted:
            break;
        case DCMNone:;
    }
}

void DesfireSecureChannelEncode(DesfireContext *ctx, uint8_t cmd, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, size_t *dstdatalen) {
    switch(ctx->secureChannel) {
        case DACd40:
            DesfireSecureChannelEncodeD40(ctx, cmd, srcdata, srcdatalen, dstdata, dstdatalen);
            break;
        case DACEV1:
            DesfireSecureChannelEncodeEV1(ctx, cmd, srcdata, srcdatalen, dstdata, dstdatalen);
            break;
        case DACEV2:
            break;
        case DACNone:
            memcpy(dstdata, srcdata, srcdatalen);
            *dstdatalen = srcdatalen;
            break;
    }
}

static void DesfireSecureChannelDecodeD40(DesfireContext *ctx, uint8_t *srcdata, size_t srcdatalen, uint8_t respcode, uint8_t *dstdata, size_t *dstdatalen) {
    memcpy(dstdata, srcdata, srcdatalen);
    *dstdatalen = srcdatalen;

    switch(ctx->commMode) {
        case DCMMACed:

            break;
        case DCMEncrypted:
            break;
        case DCMPlain:
        case DACNone:
            memcpy(dstdata, srcdata, srcdatalen);
            *dstdatalen = srcdatalen;
            break;
    }    
}

static void DesfireSecureChannelDecodeEV1(DesfireContext *ctx, uint8_t *srcdata, size_t srcdatalen, uint8_t respcode, uint8_t *dstdata, size_t *dstdatalen) {
    memcpy(dstdata, srcdata, srcdatalen);
    *dstdatalen = srcdatalen;

    switch(ctx->commMode) {
        case DCMPlain:
        case DCMMACed:
            memcpy(dstdata, srcdata, srcdatalen - 8);
            *dstdatalen = srcdatalen - 8;
            
            break;
        case DCMEncrypted:
            break;
        case DACNone:
            memcpy(dstdata, srcdata, srcdatalen);
            *dstdatalen = srcdatalen;
            break;
    }    
}

void DesfireSecureChannelDecode(DesfireContext *ctx, uint8_t *srcdata, size_t srcdatalen, uint8_t respcode, uint8_t *dstdata, size_t *dstdatalen) {
    switch(ctx->secureChannel) {
        case DACd40:
            DesfireSecureChannelDecodeD40(ctx, srcdata, srcdatalen, respcode, dstdata, dstdatalen);
            break;
        case DACEV1:
            DesfireSecureChannelDecodeEV1(ctx, srcdata, srcdatalen, respcode, dstdata, dstdatalen);
            break;
        case DACEV2:
            break;
        case DACNone:
            memcpy(dstdata, srcdata, srcdatalen);
            *dstdatalen = srcdatalen;
            break;
    }
}
