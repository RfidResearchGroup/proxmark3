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
#include "protocols.h"
#include "mifare/desfire_crypto.h"

AllowedChannelModesS AllowedChannelModes[] = {
    {MFDES_CREATE_APPLICATION,    DACd40,  DCCNative,    DCMPlain},
    {MFDES_DELETE_APPLICATION,    DACd40,  DCCNative,    DCMPlain},
    {MFDES_GET_APPLICATION_IDS,   DACd40,  DCCNative,    DCMPlain},
    {MFDES_GET_DF_NAMES,          DACd40,  DCCNative,    DCMPlain},
    {MFDES_GET_KEY_SETTINGS,      DACd40,  DCCNative,    DCMPlain},
    {MFDES_GET_KEY_VERSION,       DACd40,  DCCNative,    DCMPlain},
    {MFDES_GET_FREE_MEMORY,       DACd40,  DCCNative,    DCMPlain},

    {MFDES_READ_DATA,             DACd40,  DCCNative,    DCMMACed},
    {MFDES_WRITE_DATA,            DACd40,  DCCNative,    DCMMACed},
    {MFDES_GET_VALUE,             DACd40,  DCCNative,    DCMMACed},
    {MFDES_CREDIT,                DACd40,  DCCNative,    DCMMACed},
    {MFDES_DEBIT,                 DACd40,  DCCNative,    DCMMACed},
    {MFDES_LIMITED_CREDIT,        DACd40,  DCCNative,    DCMMACed},
    {MFDES_READ_RECORDS,          DACd40,  DCCNative,    DCMMACed},
    {MFDES_WRITE_RECORD,          DACd40,  DCCNative,    DCMMACed},
    {MFDES_UPDATE_RECORD1,        DACd40,  DCCNative,    DCMMACed},
    {MFDES_UPDATE_RECORD2,        DACd40,  DCCNativeISO, DCMMACed},
    {MFDES_INIT_KEY_SETTINGS,     DACd40,  DCCNative,    DCMMACed},
    {MFDES_FINALIZE_KEY_SETTINGS, DACd40,  DCCNative,    DCMMACed},
    {MFDES_ROLL_KEY_SETTINGS,     DACd40,  DCCNative,    DCMMACed},
    {MFDES_COMMIT_READER_ID,      DACd40,  DCCNative,    DCMMACed},
    {MFDES_FORMAT_PICC,           DACd40,  DCCNative,    DCMMACed},
    {MFDES_GET_FILE_IDS,          DACd40,  DCCNative,    DCMMACed},
    {MFDES_GET_ISOFILE_IDS,       DACd40,  DCCNative,    DCMMACed},

    {MFDES_GET_UID,               DACd40,  DCCNative,    DCMEncrypted},
    {MFDES_CHANGE_KEY_SETTINGS,   DACd40,  DCCNative,    DCMEncrypted},
    {MFDES_READ_DATA,             DACd40,  DCCNative,    DCMEncrypted},
    {MFDES_WRITE_DATA,            DACd40,  DCCNative,    DCMEncrypted},

    {MFDES_CHANGE_KEY,            DACd40,  DCCNative,    DCMEncryptedPlain},
    {MFDES_CHANGE_KEY_EV2,        DACd40,  DCCNative,    DCMEncryptedPlain},

    {MFDES_GET_KEY_VERSION,       DACEV1,  DCCNative,    DCMPlain},
    {MFDES_GET_FREE_MEMORY,       DACEV1,  DCCNative,    DCMPlain},

    {MFDES_CREATE_APPLICATION,    DACEV1,  DCCNative,    DCMMACed},
    {MFDES_DELETE_APPLICATION,    DACEV1,  DCCNative,    DCMMACed},
    {MFDES_GET_APPLICATION_IDS,   DACEV1,  DCCNative,    DCMMACed},
    {MFDES_GET_DF_NAMES,          DACEV1,  DCCNative,    DCMMACed},
    {MFDES_GET_KEY_SETTINGS,      DACEV1,  DCCNative,    DCMMACed},
    {MFDES_FORMAT_PICC,           DACEV1,  DCCNative,    DCMMACed},
    {MFDES_GET_FILE_IDS,          DACEV1,  DCCNative,    DCMMACed},
    {MFDES_GET_ISOFILE_IDS,       DACEV1,  DCCNative,    DCMMACed},
    {MFDES_GET_FILE_SETTINGS,     DACEV1,  DCCNative,    DCMMACed},

    {MFDES_GET_UID,               DACEV1,  DCCNative,    DCMEncrypted},
    {MFDES_CHANGE_KEY_SETTINGS,   DACEV1,  DCCNative,    DCMEncrypted},

    {MFDES_CHANGE_KEY,            DACEV1,  DCCNative,    DCMEncryptedPlain},
    {MFDES_CHANGE_KEY_EV2,        DACEV1,  DCCNative,    DCMEncryptedPlain},
};

static uint8_t DesfireGetCmdHeaderLen(uint8_t cmd) {
    if (cmd == MFDES_CHANGE_KEY || cmd == MFDES_CHANGE_CONFIGURATION)
        return 1;

    if (cmd == MFDES_CHANGE_KEY_EV2)
        return 2;

    return 0;
}

static void DesfireSecureChannelEncodeD40(DesfireContext *ctx, uint8_t cmd, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, size_t *dstdatalen) {
    memcpy(dstdata, srcdata, srcdatalen);
    *dstdatalen = srcdatalen;

    uint8_t data[1024] = {0};
    size_t rlen = 0;
    uint8_t hdrlen = DesfireGetCmdHeaderLen(cmd);

    switch (ctx->commMode) {
        case DCMPlain:
            memcpy(dstdata, srcdata, srcdatalen);
            *dstdatalen = srcdatalen;
            break;
        case DCMMACed:
            if (srcdatalen == 0)
                break;

            rlen = srcdatalen + DesfireGetMACLength(ctx);
            memcpy(data, srcdata, srcdatalen);
            DesfireCryptoEncDec(ctx, true, data, srcdatalen, NULL, true);
            memcpy(dstdata, srcdata, srcdatalen);
            memcpy(&dstdata[srcdatalen], ctx->IV, 4);
            *dstdatalen = rlen;
            break;
        case DCMEncrypted:
            if (srcdatalen == 0 || srcdatalen <= hdrlen)
                break;

            rlen = padded_data_length(srcdatalen + 2, desfire_get_key_block_length(ctx->keyType)); // 2 - crc16
            memcpy(data, srcdata, srcdatalen);
            compute_crc(CRC_14443_A, data, srcdatalen, &data[srcdatalen], &data[srcdatalen + 1]);
            DesfireCryptoEncDec(ctx, true, data, rlen, dstdata, true);
            *dstdatalen = rlen;
            break;
        case DCMEncryptedPlain:
            if (srcdatalen == 0 || srcdatalen <= hdrlen)
                break;

            rlen = padded_data_length(srcdatalen - hdrlen, desfire_get_key_block_length(ctx->keyType)) + hdrlen;
            memcpy(data, srcdata, srcdatalen);
            memcpy(dstdata, srcdata, hdrlen);
            DesfireCryptoEncDec(ctx, true, &data[hdrlen], rlen - hdrlen, &dstdata[hdrlen], true);
            *dstdatalen = rlen;
            ctx->commMode = DCMEncrypted;
            break;
        case DCMNone:
            ;
    }
}

static void DesfireSecureChannelEncodeEV1(DesfireContext *ctx, uint8_t cmd, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, size_t *dstdatalen) {
    uint8_t data[1024] = {0};
    size_t rlen = 0;

    memcpy(dstdata, srcdata, srcdatalen);
    *dstdatalen = srcdatalen;
    uint8_t hdrlen = DesfireGetCmdHeaderLen(cmd);

    // we calc MAC anyway
    // if encypted channel and no data - we only calc MAC
    if (ctx->commMode == DCMPlain || ctx->commMode == DCMMACed || (ctx->commMode == DCMEncrypted && srcdatalen == 0)) {
        data[0] = cmd;
        memcpy(&data[1], srcdata, srcdatalen);
        uint8_t cmac[DESFIRE_MAX_CRYPTO_BLOCK_SIZE] = {0};
        DesfireCryptoCMAC(ctx, data, srcdatalen + 1, cmac);

        memcpy(dstdata, srcdata, srcdatalen);
        *dstdatalen = srcdatalen;
        if (srcdatalen != 0 && ctx->commMode == DCMMACed) {
            memcpy(&dstdata[srcdatalen], cmac, DesfireGetMACLength(ctx));
            *dstdatalen = srcdatalen + DesfireGetMACLength(ctx);
        }
    } else if (ctx->commMode == DCMEncrypted) {
        rlen = padded_data_length(srcdatalen + 4, desfire_get_key_block_length(ctx->keyType));
        data[0] = cmd;
        memcpy(&data[1], srcdata, srcdatalen);
        desfire_crc32_append(data, srcdatalen + 1);

        DesfireCryptoEncDec(ctx, true, &data[1], rlen, dstdata, true);

        *dstdatalen = rlen;
    } else if (ctx->commMode == DCMEncryptedPlain) {
        if (srcdatalen == 0 || srcdatalen <= hdrlen)
            return;

        memcpy(&dstdata[0], srcdata, hdrlen);
        memcpy(data, &srcdata[hdrlen], srcdatalen);
        rlen = padded_data_length(srcdatalen - hdrlen, desfire_get_key_block_length(ctx->keyType));
        DesfireCryptoEncDec(ctx, true, data, rlen, &dstdata[hdrlen], true);
        *dstdatalen = hdrlen + rlen;
        ctx->commMode = DCMEncrypted;
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
            if (srcdatalen < desfire_get_key_block_length(ctx->keyType)) {
                memcpy(dstdata, srcdata, srcdatalen);
                *dstdatalen = srcdatalen;
                return;
            }

            DesfireCryptoEncDec(ctx, true, srcdata, srcdatalen, dstdata, false);
            //PrintAndLogEx(INFO, "decoded[%d]: %s", srcdatalen, sprint_hex(dstdata, srcdatalen));

            size_t puredatalen = DesfireSearchCRCPos(dstdata, srcdatalen, respcode, 2);
            if (puredatalen != 0) {
                *dstdatalen = puredatalen;
            } else {
                PrintAndLogEx(WARNING, "CRC16 error.");
                *dstdatalen = srcdatalen;
            }
            break;
        case DCMPlain:
        case DACNone:
        case DCMEncryptedPlain:
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
        if (srcdatalen < desfire_get_key_block_length(ctx->keyType)) {
            memcpy(dstdata, srcdata, srcdatalen);
            *dstdatalen = srcdatalen;
            return;
        }

        DesfireCryptoEncDec(ctx, true, srcdata, srcdatalen, dstdata, false);
        //PrintAndLogEx(INFO, "decoded[%d]: %s", srcdatalen, sprint_hex(dstdata, srcdatalen));

        size_t puredatalen = DesfireSearchCRCPos(dstdata, srcdatalen, respcode, 4);
        if (puredatalen != 0) {
            *dstdatalen = puredatalen;
        } else {
            PrintAndLogEx(WARNING, "CRC32 error.");
            *dstdatalen = srcdatalen;
        }

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

bool PrintChannelModeWarning(uint8_t cmd, DesfireSecureChannel secureChannel, DesfireCommandSet cmdSet, DesfireCommunicationMode commMode) {
    if (commMode == DCMNone) {
        PrintAndLogEx(WARNING, "Communication mode can't be NONE. command: %02x", cmd);
        return false;
    }

    // no security set
    if (secureChannel == DACNone)
        return true;

    bool found = false;
    for (int i = 0; i < ARRAY_LENGTH(AllowedChannelModes); i++)
        if (AllowedChannelModes[i].cmd == cmd) {
            // full compare
            if (AllowedChannelModes[i].secureChannel == secureChannel &&
                    (AllowedChannelModes[i].cmdSet == cmdSet || (AllowedChannelModes[i].cmdSet == DCCNative && cmdSet == DCCNativeISO)) &&
                    AllowedChannelModes[i].commMode == commMode) {

                found = true;
                break;
            }

            // ev1 plain and mac are the same
            if (AllowedChannelModes[i].secureChannel == secureChannel &&
                    AllowedChannelModes[i].secureChannel == DACEV1 &&
                    (AllowedChannelModes[i].cmdSet == cmdSet || (AllowedChannelModes[i].cmdSet == DCCNative && cmdSet == DCCNativeISO)) &&
                    (commMode == DCMPlain || commMode == DCMMACed)) {

                found = true;
                break;
            }

        }

    if (!found)
        PrintAndLogEx(WARNING, "Wrong communication mode. Check settings. command: %02x", cmd);

    return found;
}

