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

static const uint8_t CommandsCanUseAnyChannel[] = {
    MFDES_S_ADDITIONAL_FRAME,
    MFDES_READ_DATA,
    MFDES_WRITE_DATA,
    MFDES_GET_VALUE,
    MFDES_READ_RECORDS,
    MFDES_WRITE_RECORD,
    MFDES_UPDATE_RECORD,
};

static bool CommandCanUseAnyChannel(uint8_t cmd) {
    for (int i = 0; i < ARRAYLEN(CommandsCanUseAnyChannel); i++)
        if (CommandsCanUseAnyChannel[i] == cmd)
            return true;
    return false;
}

static const AllowedChannelModesS AllowedChannelModes[] = {
    {MFDES_SELECT_APPLICATION,        DACd40,  DCCNative,    DCMPlain},
    {MFDES_CREATE_APPLICATION,        DACd40,  DCCNative,    DCMPlain},
    {MFDES_DELETE_APPLICATION,        DACd40,  DCCNative,    DCMPlain},
    {MFDES_GET_APPLICATION_IDS,       DACd40,  DCCNative,    DCMPlain},
    {MFDES_GET_DF_NAMES,              DACd40,  DCCNative,    DCMPlain},
    {MFDES_GET_KEY_SETTINGS,          DACd40,  DCCNative,    DCMPlain},
    {MFDES_GET_KEY_VERSION,           DACd40,  DCCNative,    DCMPlain},
    {MFDES_GET_FREE_MEMORY,           DACd40,  DCCNative,    DCMPlain},
    {MFDES_CREATE_STD_DATA_FILE,      DACd40,  DCCNative,    DCMPlain},
    {MFDES_CREATE_BACKUP_DATA_FILE,   DACd40,  DCCNative,    DCMPlain},
    {MFDES_CREATE_VALUE_FILE,         DACd40,  DCCNative,    DCMPlain},
    {MFDES_CREATE_LINEAR_RECORD_FILE, DACd40,  DCCNative,    DCMPlain},
    {MFDES_CREATE_CYCLIC_RECORD_FILE, DACd40,  DCCNative,    DCMPlain},
    {MFDES_GET_VALUE,                 DACd40,  DCCNative,    DCMPlain},
    {MFDES_CREDIT,                    DACd40,  DCCNative,    DCMPlain},
    {MFDES_LIMITED_CREDIT,            DACd40,  DCCNative,    DCMPlain},
    {MFDES_DEBIT,                     DACd40,  DCCNative,    DCMPlain},
    {MFDES_COMMIT_TRANSACTION,        DACd40,  DCCNative,    DCMPlain},
    {MFDES_CLEAR_RECORD_FILE,         DACd40,  DCCNative,    DCMPlain},
    {MFDES_GET_FILE_SETTINGS,         DACd40,  DCCNative,    DCMPlain},

    {MFDES_GET_VALUE,                 DACd40,  DCCNative,    DCMMACed},
    {MFDES_CREDIT,                    DACd40,  DCCNative,    DCMMACed},
    {MFDES_DEBIT,                     DACd40,  DCCNative,    DCMMACed},
    {MFDES_LIMITED_CREDIT,            DACd40,  DCCNative,    DCMMACed},
    {MFDES_READ_RECORDS,              DACd40,  DCCNative,    DCMMACed},
    {MFDES_WRITE_RECORD,              DACd40,  DCCNative,    DCMMACed},
    {MFDES_UPDATE_RECORD,             DACd40,  DCCNative,    DCMMACed},
    {MFDES_UPDATE_RECORD2,            DACd40,  DCCNativeISO, DCMMACed},
    {MFDES_INIT_KEY_SETTINGS,         DACd40,  DCCNative,    DCMMACed},
    {MFDES_FINALIZE_KEY_SETTINGS,     DACd40,  DCCNative,    DCMMACed},
    {MFDES_ROLL_KEY_SETTINGS,         DACd40,  DCCNative,    DCMMACed},
    {MFDES_COMMIT_READER_ID,          DACd40,  DCCNative,    DCMMACed},
    {MFDES_FORMAT_PICC,               DACd40,  DCCNative,    DCMMACed},
    {MFDES_GET_FILE_IDS,              DACd40,  DCCNative,    DCMMACed},
    {MFDES_GET_ISOFILE_IDS,           DACd40,  DCCNative,    DCMMACed},

    {MFDES_GET_UID,                   DACd40,  DCCNative,    DCMEncrypted},
    {MFDES_CHANGE_KEY_SETTINGS,       DACd40,  DCCNative,    DCMEncrypted},
    {MFDES_CHANGE_FILE_SETTINGS,      DACd40,  DCCNative,    DCMEncrypted},

    {MFDES_CHANGE_KEY,                DACd40,  DCCNative,    DCMEncryptedPlain},
    {MFDES_CHANGE_KEY_EV2,            DACd40,  DCCNative,    DCMEncryptedPlain},

    {MFDES_GET_KEY_VERSION,           DACEV1,  DCCNative,    DCMPlain},
    {MFDES_GET_FREE_MEMORY,           DACEV1,  DCCNative,    DCMPlain},
    {MFDES_SELECT_APPLICATION,        DACEV1,  DCCNative,    DCMPlain},

    {MFDES_CREATE_APPLICATION,        DACEV1,  DCCNative,    DCMMACed},
    {MFDES_DELETE_APPLICATION,        DACEV1,  DCCNative,    DCMMACed},
    {MFDES_GET_APPLICATION_IDS,       DACEV1,  DCCNative,    DCMMACed},
    {MFDES_GET_DF_NAMES,              DACEV1,  DCCNative,    DCMMACed},
    {MFDES_GET_KEY_SETTINGS,          DACEV1,  DCCNative,    DCMMACed},
    {MFDES_FORMAT_PICC,               DACEV1,  DCCNative,    DCMMACed},
    {MFDES_GET_FILE_IDS,              DACEV1,  DCCNative,    DCMMACed},
    {MFDES_GET_ISOFILE_IDS,           DACEV1,  DCCNative,    DCMMACed},
    {MFDES_GET_FILE_SETTINGS,         DACEV1,  DCCNative,    DCMMACed},
    {MFDES_CREATE_STD_DATA_FILE,      DACEV1,  DCCNative,    DCMMACed},
    {MFDES_CREATE_BACKUP_DATA_FILE,   DACEV1,  DCCNative,    DCMMACed},
    {MFDES_CREATE_VALUE_FILE,         DACEV1,  DCCNative,    DCMMACed},
    {MFDES_CREATE_LINEAR_RECORD_FILE, DACEV1,  DCCNative,    DCMMACed},
    {MFDES_CREATE_CYCLIC_RECORD_FILE, DACEV1,  DCCNative,    DCMMACed},
    {MFDES_GET_VALUE,                 DACEV1,  DCCNative,    DCMMACed},
    {MFDES_CREDIT,                    DACEV1,  DCCNative,    DCMMACed},
    {MFDES_LIMITED_CREDIT,            DACEV1,  DCCNative,    DCMMACed},
    {MFDES_DEBIT,                     DACEV1,  DCCNative,    DCMMACed},
    {MFDES_COMMIT_TRANSACTION,        DACEV1,  DCCNative,    DCMMACed},
    {MFDES_CLEAR_RECORD_FILE,         DACEV1,  DCCNative,    DCMMACed},

    {MFDES_GET_UID,                   DACEV1,  DCCNative,    DCMEncrypted},
    {MFDES_CHANGE_KEY_SETTINGS,       DACEV1,  DCCNative,    DCMEncrypted},
    {MFDES_CHANGE_FILE_SETTINGS,      DACEV1,  DCCNative,    DCMEncrypted},
    {MFDES_CREATE_TRANS_MAC_FILE,     DACEV1,  DCCNative,    DCMEncrypted},

    {MFDES_CHANGE_KEY,                DACEV1,  DCCNative,    DCMEncryptedPlain},
    {MFDES_CHANGE_KEY_EV2,            DACEV1,  DCCNative,    DCMEncryptedPlain},
    
    {MFDES_AUTHENTICATE_EV2F,         DACEV2,  DCCNative,    DCMPlain},
    {MFDES_AUTHENTICATE_EV2NF,        DACEV2,  DCCNative,    DCMPlain},
};

#define CMD_HEADER_LEN_ALL 0xffff
static const CmdHeaderLengthsS CmdHeaderLengths[] = {
    {MFDES_CREATE_APPLICATION,     CMD_HEADER_LEN_ALL},
    {MFDES_DELETE_APPLICATION,     CMD_HEADER_LEN_ALL},
    {MFDES_CHANGE_KEY,             1},
    {MFDES_CHANGE_KEY_EV2,         2},
    {MFDES_CHANGE_CONFIGURATION,   1},
    {MFDES_GET_FILE_SETTINGS,      1},
    {MFDES_CHANGE_FILE_SETTINGS,   1},
    {MFDES_CREATE_TRANS_MAC_FILE,  5},
    {MFDES_READ_DATA,              7},
    {MFDES_WRITE_DATA,             7},
    {MFDES_READ_RECORDS,           7},
    {MFDES_WRITE_RECORD,           7},
    {MFDES_UPDATE_RECORD,         10},
};

static uint8_t DesfireGetCmdHeaderLen(uint8_t cmd) {
    for (int i = 0; i < ARRAY_LENGTH(CmdHeaderLengths); i++)
        if (CmdHeaderLengths[i].cmd == cmd)
            return CmdHeaderLengths[i].len;

    return 0;
}

static void DesfireSecureChannelEncodeD40(DesfireContext *ctx, uint8_t cmd, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, size_t *dstdatalen) {
    uint8_t data[1024] = {0};
    size_t rlen = 0;

    memcpy(dstdata, srcdata, srcdatalen);
    *dstdatalen = srcdatalen;

    uint8_t hdrlen = DesfireGetCmdHeaderLen(cmd);

    if (ctx->commMode == DCMMACed || (ctx->commMode == DCMEncrypted && srcdatalen <= hdrlen)) {
        if (srcdatalen == 0)
            return;

        rlen = srcdatalen + DesfireGetMACLength(ctx);

        memcpy(data, &srcdata[hdrlen], srcdatalen - hdrlen);
        size_t srcmaclen = padded_data_length(srcdatalen - hdrlen, desfire_get_key_block_length(ctx->keyType));

        uint8_t mac[32] = {0};
        DesfireCryptoEncDecEx(ctx, true, data, srcmaclen, NULL, true, true, mac);

        memcpy(dstdata, srcdata, srcdatalen);
        memcpy(&dstdata[srcdatalen], mac, DesfireGetMACLength(ctx));
        *dstdatalen = rlen;
    } else if (ctx->commMode == DCMEncrypted) {
        if (srcdatalen <= hdrlen)
            return;

        rlen = padded_data_length(srcdatalen + 2 - hdrlen, desfire_get_key_block_length(ctx->keyType)) + hdrlen; // 2 - crc16
        memcpy(data, &srcdata[hdrlen], srcdatalen - hdrlen);
        iso14443a_crc_append(data, srcdatalen - hdrlen);

        memcpy(dstdata, srcdata, hdrlen);
        //PrintAndLogEx(INFO, "src[%d]: %s", srcdatalen - hdrlen + 2, sprint_hex(data, srcdatalen - hdrlen + 2));
        DesfireCryptoEncDec(ctx, true, data, rlen - hdrlen, &dstdata[hdrlen], true);

        *dstdatalen = rlen;
    } else if (ctx->commMode == DCMEncryptedPlain) {
        if (srcdatalen == 0 || srcdatalen <= hdrlen)
            return;

        rlen = padded_data_length(srcdatalen - hdrlen, desfire_get_key_block_length(ctx->keyType)) + hdrlen;
        memcpy(data, srcdata, srcdatalen);
        memcpy(dstdata, srcdata, hdrlen);
        DesfireCryptoEncDec(ctx, true, &data[hdrlen], rlen - hdrlen, &dstdata[hdrlen], true);
        *dstdatalen = rlen;
        ctx->commMode = DCMEncrypted;
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
    if (ctx->commMode == DCMPlain || ctx->commMode == DCMMACed || (ctx->commMode == DCMEncrypted && srcdatalen <= hdrlen)) {
        data[0] = cmd;
        memcpy(&data[1], srcdata, srcdatalen);
        uint8_t cmac[DESFIRE_MAX_CRYPTO_BLOCK_SIZE] = {0};
        DesfireCryptoCMAC(ctx, data, srcdatalen + 1, cmac);

        memcpy(dstdata, srcdata, srcdatalen);
        *dstdatalen = srcdatalen;
        if (srcdatalen > hdrlen && ctx->commMode == DCMMACed) {
            memcpy(&dstdata[srcdatalen], cmac, DesfireGetMACLength(ctx));
            *dstdatalen = srcdatalen + DesfireGetMACLength(ctx);
        }
    } else if (ctx->commMode == DCMEncrypted) {
        rlen = padded_data_length(srcdatalen + 4 - hdrlen, desfire_get_key_block_length(ctx->keyType));
        data[0] = cmd;
        memcpy(&data[1], srcdata, srcdatalen);
        desfire_crc32_append(data, srcdatalen + 1);

        memcpy(dstdata, srcdata, hdrlen);
        DesfireCryptoEncDec(ctx, true, &data[1 + hdrlen], rlen, &dstdata[hdrlen], true);

        *dstdatalen = hdrlen + rlen;
    } else if (ctx->commMode == DCMEncryptedPlain) {
        if (srcdatalen <= hdrlen)
            return;

        memcpy(dstdata, srcdata, hdrlen);
        memcpy(data, &srcdata[hdrlen], srcdatalen);
        rlen = padded_data_length(srcdatalen - hdrlen, desfire_get_key_block_length(ctx->keyType));
        DesfireCryptoEncDec(ctx, true, data, rlen, &dstdata[hdrlen], true);
        *dstdatalen = hdrlen + rlen;
        ctx->commMode = DCMEncrypted;
    }
}

static void DesfireSecureChannelEncodeEV2(DesfireContext *ctx, uint8_t cmd, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, size_t *dstdatalen) {
    memcpy(dstdata, srcdata, srcdatalen);
    *dstdatalen = srcdatalen;
    
    ctx->cmdCntr++;
}

void DesfireSecureChannelEncode(DesfireContext *ctx, uint8_t cmd, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, size_t *dstdatalen) {
    ctx->lastCommand = cmd;
    ctx->lastRequestZeroLen = (srcdatalen <= DesfireGetCmdHeaderLen(cmd));

    switch (ctx->secureChannel) {
        case DACd40:
            DesfireSecureChannelEncodeD40(ctx, cmd, srcdata, srcdatalen, dstdata, dstdatalen);
            break;
        case DACEV1:
            DesfireSecureChannelEncodeEV1(ctx, cmd, srcdata, srcdatalen, dstdata, dstdatalen);
            break;
        case DACEV2:
            DesfireSecureChannelEncodeEV2(ctx, cmd, srcdata, srcdatalen, dstdata, dstdatalen);
            break;
        case DACNone:
            memcpy(dstdata, srcdata, srcdatalen);
            *dstdatalen = srcdatalen;
            break;
    }
}

static void DesfireSecureChannelDecodeD40(DesfireContext *ctx, uint8_t *srcdata, size_t srcdatalen, uint8_t respcode, uint8_t *dstdata, size_t *dstdatalen) {
    uint8_t data[1024] = {0};
    size_t rlen = 0;

    memcpy(dstdata, srcdata, srcdatalen);
    *dstdatalen = srcdatalen;

    switch (ctx->commMode) {
        case DCMMACed: {
            size_t maclen = DesfireGetMACLength(ctx);
            if (srcdatalen > maclen) {
                uint8_t mac[16] = {0};
                rlen = padded_data_length(srcdatalen - maclen, desfire_get_key_block_length(ctx->keyType));
                memcpy(data, srcdata, srcdatalen - maclen);
                DesfireCryptoEncDecEx(ctx, true, data, rlen, NULL, true, true, mac);

                if (memcmp(mac, &srcdata[srcdatalen - maclen], maclen) == 0) {
                    *dstdatalen = srcdatalen - maclen;
                } else {
                    PrintAndLogEx(WARNING, "Received MAC is not match with calculated");
                    //PrintAndLogEx(INFO, "  received MAC:   %s", sprint_hex(&srcdata[srcdatalen - maclen], maclen));
                    //PrintAndLogEx(INFO, "  calculated MAC: %s", sprint_hex(mac, maclen));
                }
            }
            break;
        }
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

static void DesfireSecureChannelDecodeEV2(DesfireContext *ctx, uint8_t *srcdata, size_t srcdatalen, uint8_t respcode, uint8_t *dstdata, size_t *dstdatalen) {
    memcpy(dstdata, srcdata, srcdatalen);
    *dstdatalen = srcdatalen;
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
            DesfireSecureChannelDecodeEV2(ctx, srcdata, srcdatalen, respcode, dstdata, dstdatalen);
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
    if (CommandCanUseAnyChannel(cmd))
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

