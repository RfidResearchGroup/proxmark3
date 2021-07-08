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

static void DesfireSecureChannelEncodeD40(DesfireContext *ctx, uint8_t cmd, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, size_t *dstdatalen) {
    memcpy(dstdata, srcdata, srcdatalen);
    *dstdatalen = srcdatalen;

    uint8_t data[1024] = {0};
    size_t rlen = 0;

    switch (ctx->commMode) {
        case DCMPlain:
            memcpy(dstdata, srcdata, srcdatalen);
            *dstdatalen = srcdatalen;
            break;
        case DCMMACed:
            if (srcdatalen == 0)
                break;

            rlen = padded_data_length(srcdatalen, desfire_get_key_block_length(ctx->keyType));
            memcpy(data, srcdata, srcdatalen);
            DesfireCryptoEncDec(ctx, true, data, rlen, NULL, true);
            memcpy(dstdata, srcdata, srcdatalen);
            memcpy(&dstdata[srcdatalen], ctx->IV, 4);
            *dstdatalen = rlen;
            break;
        case DCMEncrypted:
            rlen = padded_data_length(srcdatalen + 2, desfire_get_key_block_length(ctx->keyType)); // 2 - crc16
            memcpy(data, srcdata, srcdatalen);
            compute_crc(CRC_14443_A, data, srcdatalen, &data[srcdatalen], &data[srcdatalen + 1]);
            DesfireCryptoEncDec(ctx, true, data, rlen, dstdata, true);
            *dstdatalen = rlen;
            break;
        case DCMNone:
            ;
    }
}

static void DesfireSecureChannelEncodeEV1(DesfireContext *ctx, uint8_t cmd, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, size_t *dstdatalen) {
    uint8_t data[1024] = {0};

    // we calc MAC anyway
    // if encypted channel and no data - we only calc MAC
    if (ctx->commMode == DCMPlain || ctx->commMode == DCMMACed || (ctx->commMode == DCMEncrypted && srcdatalen == 0)) {
        data[0] = cmd;
        memcpy(&data[1], srcdata, srcdatalen);
        uint8_t cmac[DESFIRE_MAX_CRYPTO_BLOCK_SIZE] = {0};
        DesfireCryptoCMAC(ctx, data, srcdatalen + 1, cmac);
PrintAndLogEx(INFO, "mac iv: %s", sprint_hex(ctx->IV, 16));

        memcpy(dstdata, srcdata, srcdatalen);
        if (srcdatalen != 0 && ctx->commMode == DCMMACed) {
            memcpy(&dstdata[srcdatalen], cmac, DesfireGetMACLength(ctx));
            *dstdatalen = srcdatalen + DesfireGetMACLength(ctx);
        }
    } else if (ctx->commMode == DCMEncrypted) {
            
            
            
    } else {
        memcpy(dstdata, srcdata, srcdatalen);
        *dstdatalen = srcdatalen;
    }
}

void DesfireSecureChannelEncode(DesfireContext *ctx, uint8_t cmd, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, size_t *dstdatalen) {
    ctx->lastCommand = cmd;
    ctx->lastRequestZeroLen = (srcdatalen == 0);

    switch (ctx->secureChannel) {
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

    switch (ctx->commMode) {
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
    uint8_t data[1024] = {0};

    // if comm mode = plain --> response with MAC
    // if request is not zero length --> response MAC
    if (ctx->commMode == DCMPlain || ctx->commMode == DCMMACed || (ctx->commMode == DCMEncrypted && !ctx->lastRequestZeroLen)) {
        if (srcdatalen < DesfireGetMACLength(ctx)) {
            memcpy(dstdata, srcdata, srcdatalen);
            *dstdatalen = srcdatalen;
            return;
        }
        
        memcpy(dstdata, srcdata, srcdatalen - DesfireGetMACLength(ctx));
        *dstdatalen = srcdatalen - DesfireGetMACLength(ctx);
        
        memcpy(data, srcdata, *dstdatalen);
        data[*dstdatalen] = respcode;
        
        uint8_t cmac[DESFIRE_MAX_CRYPTO_BLOCK_SIZE] = {0};
        DesfireCryptoCMAC(ctx, data, *dstdatalen + 1, cmac);
        if (memcmp(&srcdata[*dstdatalen], cmac, DesfireGetMACLength(ctx)) != 0) {
            PrintAndLogEx(WARNING, "Received MAC is not match with calculated");
            PrintAndLogEx(INFO, "  received MAC:   %s", sprint_hex(&srcdata[*dstdatalen], desfire_get_key_block_length(ctx->keyType)));
            PrintAndLogEx(INFO, "  calculated MAC: %s", sprint_hex(cmac, desfire_get_key_block_length(ctx->keyType)));
        }
    } else if (ctx->commMode == DCMEncrypted) {
            //mifare_cypher_blocks_chained(tag, NULL, NULL, res, *nbytes, MCD_RECEIVE, MCO_DECYPHER);
PrintAndLogEx(INFO, "data: %s", sprint_hex(srcdata, srcdatalen));
PrintAndLogEx(INFO, "dec iv: %s", sprint_hex(ctx->IV, 16));
            DesfireCryptoEncDec(ctx, true, srcdata, srcdatalen, dstdata, false);
PrintAndLogEx(INFO, "dec iv: %s", sprint_hex(ctx->IV, 16));
            PrintAndLogEx(INFO, "decoded[%d]: %s", srcdatalen, sprint_hex(dstdata, srcdatalen));
    } else {
        memcpy(dstdata, srcdata, srcdatalen);
        *dstdatalen = srcdatalen;
    }
}

void DesfireSecureChannelDecode(DesfireContext *ctx, uint8_t *srcdata, size_t srcdatalen, uint8_t respcode, uint8_t *dstdata, size_t *dstdatalen) {
    switch (ctx->secureChannel) {
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
