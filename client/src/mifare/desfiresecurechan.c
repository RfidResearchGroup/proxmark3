//-----------------------------------------------------------------------------
// Borrowed initially from https://github.com/nfc-tools/libfreefare
// Copyright (C) 2010, Romain Tartiere.
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

static const uint8_t CommandsCanUseAnyChannel[] = {
    MFDES_S_ADDITIONAL_FRAME,
    MFDES_READ_DATA,
    MFDES_READ_DATA2,
    MFDES_WRITE_DATA,
    MFDES_WRITE_DATA2,
    MFDES_READ_RECORDS,
    MFDES_READ_RECORDS2,
    MFDES_WRITE_RECORD,
    MFDES_WRITE_RECORD2,
    MFDES_UPDATE_RECORD,
    MFDES_UPDATE_RECORD2,
    MFDES_GET_VALUE,
    MFDES_CREDIT,
    MFDES_DEBIT,
    MFDES_LIMITED_CREDIT,
};

static bool CommandCanUseAnyChannel(uint8_t cmd) {
    for (int i = 0; i < ARRAYLEN(CommandsCanUseAnyChannel); i++)
        if (CommandsCanUseAnyChannel[i] == cmd)
            return true;
    return false;
}

static const AllowedChannelModes_t AllowedChannelModes[] = {
    // D40 channel
    {MFDES_SELECT_APPLICATION,        DACd40,  DCCNative,    DCMPlain},

    {MFDES_CREATE_APPLICATION,        DACd40,  DCCNative,    DCMMACed},
    {MFDES_DELETE_APPLICATION,        DACd40,  DCCNative,    DCMMACed},
    {MFDES_GET_APPLICATION_IDS,       DACd40,  DCCNative,    DCMMACed},
    {MFDES_GET_DF_NAMES,              DACd40,  DCCNative,    DCMMACed},
    {MFDES_GET_KEY_SETTINGS,          DACd40,  DCCNative,    DCMMACed},
    {MFDES_GET_KEY_VERSION,           DACd40,  DCCNative,    DCMMACed},
    {MFDES_GET_FREE_MEMORY,           DACd40,  DCCNative,    DCMMACed},
    {MFDES_CREATE_STD_DATA_FILE,      DACd40,  DCCNative,    DCMMACed},
    {MFDES_CREATE_BACKUP_DATA_FILE,   DACd40,  DCCNative,    DCMMACed},
    {MFDES_CREATE_VALUE_FILE,         DACd40,  DCCNative,    DCMMACed},
    {MFDES_CREATE_LINEAR_RECORD_FILE, DACd40,  DCCNative,    DCMMACed},
    {MFDES_CREATE_CYCLIC_RECORD_FILE, DACd40,  DCCNative,    DCMMACed},
    {MFDES_DELETE_FILE,               DACd40,  DCCNative,    DCMMACed},
    {MFDES_COMMIT_TRANSACTION,        DACd40,  DCCNative,    DCMMACed},
    {MFDES_CLEAR_RECORD_FILE,         DACd40,  DCCNative,    DCMMACed},
    {MFDES_GET_FILE_SETTINGS,         DACd40,  DCCNative,    DCMMACed},
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
    {MFDES_ABORT_TRANSACTION,         DACd40,  DCCNative,    DCMMACed},

    {MFDES_GET_UID,                   DACd40,  DCCNative,    DCMEncrypted},
    {MFDES_CHANGE_KEY_SETTINGS,       DACd40,  DCCNative,    DCMEncrypted},
    {MFDES_CHANGE_FILE_SETTINGS,      DACd40,  DCCNative,    DCMEncrypted},
    {MFDES_CHANGE_CONFIGURATION,      DACd40,  DCCNative,    DCMEncrypted},

    {MFDES_CHANGE_KEY,                DACd40,  DCCNative,    DCMEncryptedPlain},
    {MFDES_CHANGE_KEY_EV2,            DACd40,  DCCNative,    DCMEncryptedPlain},

    // EV1 and EV2 channel
    {MFDES_SELECT_APPLICATION,        DACEV1,  DCCNative,    DCMPlain},

    {MFDES_GET_KEY_VERSION,           DACEV1,  DCCNative,    DCMMACed},
    {MFDES_GET_FREE_MEMORY,           DACEV1,  DCCNative,    DCMMACed},
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
    {MFDES_DELETE_FILE,               DACEV1,  DCCNative,    DCMMACed},
    {MFDES_GET_VALUE,                 DACEV1,  DCCNative,    DCMMACed},
    {MFDES_CREDIT,                    DACEV1,  DCCNative,    DCMMACed},
    {MFDES_LIMITED_CREDIT,            DACEV1,  DCCNative,    DCMMACed},
    {MFDES_DEBIT,                     DACEV1,  DCCNative,    DCMMACed},
    {MFDES_COMMIT_TRANSACTION,        DACEV1,  DCCNative,    DCMMACed},
    {MFDES_CLEAR_RECORD_FILE,         DACEV1,  DCCNative,    DCMMACed},
    {MFDES_COMMIT_READER_ID,          DACEV1,  DCCNative,    DCMMACed},
    {MFDES_ABORT_TRANSACTION,         DACEV1,  DCCNative,    DCMMACed},

    {MFDES_GET_UID,                   DACEV1,  DCCNative,    DCMEncrypted},
    {MFDES_CHANGE_KEY_SETTINGS,       DACEV1,  DCCNative,    DCMEncrypted},
    {MFDES_CHANGE_FILE_SETTINGS,      DACEV1,  DCCNative,    DCMEncrypted},
    {MFDES_CREATE_TRANS_MAC_FILE,     DACEV1,  DCCNative,    DCMEncrypted},
    {MFDES_CHANGE_CONFIGURATION,      DACEV1,  DCCNative,    DCMEncrypted},

    {MFDES_CHANGE_KEY,                DACEV1,  DCCNative,    DCMEncryptedPlain},
    {MFDES_CHANGE_KEY_EV2,            DACEV1,  DCCNative,    DCMEncryptedPlain},

    // EV2 channel separately
    {MFDES_AUTHENTICATE_EV2F,         DACEV2,  DCCNative,    DCMPlain},
    {MFDES_AUTHENTICATE_EV2NF,        DACEV2,  DCCNative,    DCMPlain},

    // ISO channel
    {ISO7816_READ_BINARY,             DACd40,  DCCISO,       DCMPlain},
    {ISO7816_UPDATE_BINARY,           DACd40,  DCCISO,       DCMPlain},
    {ISO7816_READ_RECORDS,            DACd40,  DCCISO,       DCMPlain},
    {ISO7816_APPEND_RECORD,           DACd40,  DCCISO,       DCMPlain},

    {ISO7816_READ_BINARY,             DACd40,  DCCISO,       DCMMACed},
    {ISO7816_READ_RECORDS,            DACd40,  DCCISO,       DCMMACed},

    {ISO7816_READ_BINARY,             DACEV1,  DCCISO,       DCMPlain},
    {ISO7816_UPDATE_BINARY,           DACEV1,  DCCISO,       DCMPlain},
    {ISO7816_READ_RECORDS,            DACEV1,  DCCISO,       DCMPlain},
    {ISO7816_APPEND_RECORD,           DACEV1,  DCCISO,       DCMPlain},

    {ISO7816_READ_BINARY,             DACEV1,  DCCISO,       DCMMACed},
    {ISO7816_READ_RECORDS,            DACEV1,  DCCISO,       DCMMACed},

    // LRP channel separately
    {MFDES_AUTHENTICATE_EV2F,         DACLRP,  DCCNative,    DCMPlain},
    {MFDES_AUTHENTICATE_EV2NF,        DACLRP,  DCCNative,    DCMPlain},

    {MFDES_GET_FILE_IDS,              DACLRP,  DCCNative,    DCMMACed},
    {MFDES_GET_ISOFILE_IDS,           DACLRP,  DCCNative,    DCMMACed},
    {MFDES_GET_FILE_SETTINGS,         DACLRP,  DCCNative,    DCMMACed},
    {MFDES_GET_KEY_VERSION,           DACLRP,  DCCNative,    DCMMACed},
    {MFDES_CLEAR_RECORD_FILE,         DACLRP,  DCCNative,    DCMMACed},
    {MFDES_COMMIT_TRANSACTION,        DACLRP,  DCCNative,    DCMMACed},
    {MFDES_ABORT_TRANSACTION,         DACLRP,  DCCNative,    DCMMACed},
    {MFDES_COMMIT_READER_ID,          DACLRP,  DCCNative,    DCMMACed},

    {MFDES_GET_UID,                   DACLRP,  DCCNative,    DCMEncrypted},
    {MFDES_CHANGE_FILE_SETTINGS,      DACLRP,  DCCNative,    DCMEncrypted},
    {MFDES_CHANGE_CONFIGURATION,      DACLRP,  DCCNative,    DCMEncrypted},
    {MFDES_CREATE_TRANS_MAC_FILE,     DACLRP,  DCCNative,    DCMEncrypted},

    {MFDES_CHANGE_KEY,                DACLRP,  DCCNative,    DCMEncryptedPlain},
};

#define CMD_HEADER_LEN_ALL 0xffff
static const CmdHeaderLengths_t CmdHeaderLengths[] = {
    {MFDES_CREATE_APPLICATION,     CMD_HEADER_LEN_ALL},
    {MFDES_DELETE_APPLICATION,     CMD_HEADER_LEN_ALL},
    {MFDES_CHANGE_KEY,             1},
    {MFDES_CHANGE_KEY_EV2,         2},
    {MFDES_CHANGE_CONFIGURATION,   1},
    {MFDES_GET_FILE_SETTINGS,      1},
    {MFDES_CHANGE_FILE_SETTINGS,   1},
    {MFDES_CREATE_TRANS_MAC_FILE,  5},
    {MFDES_READ_DATA,              7},
    {MFDES_READ_DATA2,             7},
    {MFDES_WRITE_DATA,             7},
    {MFDES_WRITE_DATA2,            7},
    {MFDES_READ_RECORDS,           7},
    {MFDES_READ_RECORDS2,          7},
    {MFDES_WRITE_RECORD,           7},
    {MFDES_WRITE_RECORD2,          7},
    {MFDES_UPDATE_RECORD,         10},
    {MFDES_UPDATE_RECORD2,        10},
    {MFDES_GET_VALUE,              1},
    {MFDES_CREDIT,                 1},
    {MFDES_DEBIT,                  1},
    {MFDES_LIMITED_CREDIT,         1},
};

static uint8_t DesfireGetCmdHeaderLen(uint8_t cmd) {
    for (int i = 0; i < ARRAYLEN(CmdHeaderLengths); i++)
        if (CmdHeaderLengths[i].cmd == cmd)
            return CmdHeaderLengths[i].len;

    return 0;
}

static const uint8_t EV1D40TransmitMAC[] = {
    MFDES_WRITE_DATA,
    MFDES_CREDIT,
    MFDES_LIMITED_CREDIT,
    MFDES_DEBIT,
    MFDES_WRITE_RECORD,
    MFDES_UPDATE_RECORD,
    MFDES_COMMIT_READER_ID,
    MFDES_INIT_KEY_SETTINGS,
    MFDES_ROLL_KEY_SETTINGS,
    MFDES_FINALIZE_KEY_SETTINGS,
};

static bool DesfireEV1D40TransmitMAC(DesfireContext_t *ctx, uint8_t cmd) {
    if (ctx->secureChannel != DACd40 && ctx->secureChannel != DACEV1)
        return true;

    for (int i = 0; i < ARRAYLEN(EV1D40TransmitMAC); i++)
        if (EV1D40TransmitMAC[i] == cmd)
            return true;

    return false;
}

static const uint8_t D40ReceiveMAC[] = {
    MFDES_READ_DATA,
    MFDES_READ_DATA2,
    MFDES_READ_RECORDS,
    MFDES_READ_RECORDS2,
    MFDES_GET_VALUE,
};

static bool DesfireEV1D40ReceiveMAC(DesfireContext_t *ctx, uint8_t cmd) {
    if (ctx->secureChannel != DACd40)
        return true;

    for (int i = 0; i < ARRAYLEN(D40ReceiveMAC); i++)
        if (D40ReceiveMAC[i] == cmd)
            return true;

    return false;
}

static const uint8_t ISOChannelValidCmd[] = {
    ISO7816_SELECT_FILE,
    ISO7816_READ_BINARY,
    ISO7816_UPDATE_BINARY,
    ISO7816_READ_RECORDS,
    ISO7816_APPEND_RECORD,
    ISO7816_GET_CHALLENGE,
    ISO7816_EXTERNAL_AUTHENTICATION,
    ISO7816_INTERNAL_AUTHENTICATION
};

static bool DesfireISOChannelValidCmd(uint8_t cmd) {
    for (int i = 0; i < ARRAYLEN(ISOChannelValidCmd); i++)
        if (ISOChannelValidCmd[i] == cmd)
            return true;

    return false;
}

static void DesfireSecureChannelEncodeD40(DesfireContext_t *ctx, uint8_t cmd, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, size_t *dstdatalen) {

    uint8_t *data  = calloc(DESFIRE_BUFFER_SIZE, sizeof(uint8_t));
    if (data == NULL)
        return;

    memcpy(dstdata, srcdata, srcdatalen);
    *dstdatalen = srcdatalen;

    uint8_t hdrlen = DesfireGetCmdHeaderLen(cmd);
    if (srcdatalen < hdrlen)
        hdrlen = srcdatalen;

    size_t rlen;

    if (ctx->commMode == DCMMACed || (ctx->commMode == DCMEncrypted && srcdatalen <= hdrlen)) {
        if (srcdatalen == 0) {
            free(data);
            return;
        }

        rlen = srcdatalen + DesfireGetMACLength(ctx);

        memcpy(data, &srcdata[hdrlen], srcdatalen - hdrlen);
        size_t srcmaclen = padded_data_length(srcdatalen - hdrlen, desfire_get_key_block_length(ctx->keyType));

        uint8_t mac[32] = {0};
        DesfireCryptoEncDecEx(ctx, DCOSessionKeyMac, data, srcmaclen, NULL, true, true, mac);

        if (DesfireEV1D40TransmitMAC(ctx, cmd)) {
            memcpy(&dstdata[srcdatalen], mac, DesfireGetMACLength(ctx));
            *dstdatalen = rlen;
        }
    } else if (ctx->commMode == DCMEncrypted || ctx->commMode == DCMEncryptedWithPadding) {
        if (srcdatalen <= hdrlen) {
            free(data);
            return;
        }

        uint8_t paddinglen = (ctx->commMode == DCMEncryptedWithPadding) ? 1 : 0;
        rlen = padded_data_length(srcdatalen + 2 + paddinglen - hdrlen, desfire_get_key_block_length(ctx->keyType)) + hdrlen; // 2 - crc16
        memcpy(data, &srcdata[hdrlen], srcdatalen - hdrlen);
        iso14443a_crc_append(data, srcdatalen - hdrlen);

        // add padding
        if (paddinglen > 0)
            data[srcdatalen - hdrlen + 2] = 0x80;

        memcpy(dstdata, srcdata, hdrlen);
        //PrintAndLogEx(INFO, "src[%d]: %s", srcdatalen - hdrlen + 2, sprint_hex(data, srcdatalen - hdrlen + 2));
        DesfireCryptoEncDec(ctx, DCOSessionKeyEnc, data, rlen - hdrlen, &dstdata[hdrlen], true);

        *dstdatalen = rlen;
    } else if (ctx->commMode == DCMEncryptedPlain) {
        if (srcdatalen == 0 || srcdatalen <= hdrlen) {
            free(data);
            return;
        }

        rlen = padded_data_length(srcdatalen - hdrlen, desfire_get_key_block_length(ctx->keyType)) + hdrlen;
        memcpy(data, srcdata, srcdatalen);
        memcpy(dstdata, srcdata, hdrlen);
        DesfireCryptoEncDec(ctx, DCOSessionKeyEnc, &data[hdrlen], rlen - hdrlen, &dstdata[hdrlen], true);
        *dstdatalen = rlen;
        ctx->commMode = DCMEncrypted;
    }

    free(data);
}

static void DesfireSecureChannelEncodeEV1(DesfireContext_t *ctx, uint8_t cmd, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, size_t *dstdatalen) {

    uint8_t *data  = calloc(DESFIRE_BUFFER_SIZE, sizeof(uint8_t));
    if (data == NULL)
        return;

    memcpy(dstdata, srcdata, srcdatalen);
    *dstdatalen = srcdatalen;

    uint8_t hdrlen = DesfireGetCmdHeaderLen(cmd);
    if (srcdatalen < hdrlen)
        hdrlen = srcdatalen;

    size_t rlen;

    // we calc MAC anyway
    // if encypted channel and no data - we only calc MAC
    if (ctx->commMode == DCMPlain || ctx->commMode == DCMMACed || (ctx->commMode == DCMEncrypted && srcdatalen <= hdrlen)) {
        data[0] = cmd;
        memcpy(&data[1], srcdata, srcdatalen);
        uint8_t cmac[DESFIRE_MAX_CRYPTO_BLOCK_SIZE] = {0};
        DesfireCryptoCMAC(ctx, data, srcdatalen + 1, cmac);

        memcpy(dstdata, srcdata, srcdatalen);
        *dstdatalen = srcdatalen;
        if (ctx->commMode == DCMMACed && DesfireEV1D40TransmitMAC(ctx, cmd)) {
            memcpy(&dstdata[srcdatalen], cmac, DesfireGetMACLength(ctx));
            *dstdatalen = srcdatalen + DesfireGetMACLength(ctx);
        }

    } else if (ctx->commMode == DCMEncrypted || ctx->commMode == DCMEncryptedWithPadding) {
        uint8_t paddinglen = (ctx->commMode == DCMEncryptedWithPadding) ? 1 : 0;
        rlen = padded_data_length(srcdatalen + 4 + paddinglen - hdrlen, desfire_get_key_block_length(ctx->keyType));
        data[0] = cmd;

        // crc
        memcpy(&data[1], srcdata, srcdatalen);
        desfire_crc32_append(data, srcdatalen + 1);

        // add padding
        if (paddinglen > 0)
            data[srcdatalen + 1 + 4] = 0x80;

        memcpy(dstdata, srcdata, hdrlen);
        DesfireCryptoEncDec(ctx, DCOSessionKeyEnc, &data[1 + hdrlen], rlen, &dstdata[hdrlen], true);

        *dstdatalen = hdrlen + rlen;
        ctx->commMode = DCMEncrypted;
    } else if (ctx->commMode == DCMEncryptedPlain) {
        if (srcdatalen <= hdrlen) {
            free(data);
            return;
        }

        memcpy(dstdata, srcdata, hdrlen);
        memcpy(data, &srcdata[hdrlen], srcdatalen);
        rlen = padded_data_length(srcdatalen - hdrlen, desfire_get_key_block_length(ctx->keyType));
        DesfireCryptoEncDec(ctx, DCOSessionKeyEnc, data, rlen, &dstdata[hdrlen], true);
        *dstdatalen = hdrlen + rlen;
        ctx->commMode = DCMEncrypted;
    }
    free(data);
}

static void DesfireSecureChannelEncodeEV2(DesfireContext_t *ctx, uint8_t cmd, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, size_t *dstdatalen) {

    uint8_t *data  = calloc(DESFIRE_BUFFER_SIZE, sizeof(uint8_t));
    if (data == NULL)
        return;

    memcpy(dstdata, srcdata, srcdatalen);
    *dstdatalen = srcdatalen;

    uint8_t hdrlen = DesfireGetCmdHeaderLen(cmd);
    if (srcdatalen < hdrlen)
        hdrlen = srcdatalen;

    if (ctx->commMode == DCMMACed) {
        uint8_t cmac[DESFIRE_MAX_CRYPTO_BLOCK_SIZE] = {0};
        DesfireEV2CalcCMAC(ctx, cmd, srcdata, srcdatalen, cmac);

        memcpy(&dstdata[srcdatalen], cmac, DesfireGetMACLength(ctx));
        *dstdatalen = srcdatalen + DesfireGetMACLength(ctx);
    } else if (ctx->commMode == DCMEncrypted || ctx->commMode == DCMEncryptedWithPadding || ctx->commMode == DCMEncryptedPlain) {
        memcpy(dstdata, srcdata, hdrlen);

        size_t rlen = 0;
        if (srcdatalen > hdrlen) {
            rlen = padded_data_length(srcdatalen + 1 - hdrlen, desfire_get_key_block_length(ctx->keyType));
            memcpy(data, &srcdata[hdrlen], srcdatalen - hdrlen);
            data[srcdatalen - hdrlen] = 0x80; // padding

            DesfireEV2FillIV(ctx, true, NULL); // fill IV to ctx
            DesfireCryptoEncDec(ctx, DCOSessionKeyEnc, data, rlen, &dstdata[hdrlen], true);
        }

        uint8_t cmac[DESFIRE_MAX_CRYPTO_BLOCK_SIZE] = {0};
        DesfireEV2CalcCMAC(ctx, cmd, dstdata, hdrlen + rlen, cmac);

        memcpy(&dstdata[hdrlen + rlen], cmac, DesfireGetMACLength(ctx));

        *dstdatalen = hdrlen + rlen + DesfireGetMACLength(ctx);
        ctx->commMode = DCMEncrypted;
    }
    free(data);
}

static void DesfireSecureChannelEncodeLRP(DesfireContext_t *ctx, uint8_t cmd, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, size_t *dstdatalen) {

    uint8_t *data  = calloc(DESFIRE_BUFFER_SIZE, sizeof(uint8_t));
    if (data == NULL)
        return;

    memcpy(dstdata, srcdata, srcdatalen);
    *dstdatalen = srcdatalen;

    uint8_t hdrlen = DesfireGetCmdHeaderLen(cmd);
    if (srcdatalen < hdrlen)
        hdrlen = srcdatalen;

    if (ctx->commMode == DCMMACed) {
        uint8_t cmac[DESFIRE_MAX_CRYPTO_BLOCK_SIZE] = {0};
        DesfireLRPCalcCMAC(ctx, cmd, srcdata, srcdatalen, cmac);

        memcpy(&dstdata[srcdatalen], cmac, DesfireGetMACLength(ctx));
        *dstdatalen = srcdatalen + DesfireGetMACLength(ctx);
    } else if (ctx->commMode == DCMEncrypted || ctx->commMode == DCMEncryptedWithPadding || ctx->commMode == DCMEncryptedPlain) {
        memcpy(dstdata, srcdata, hdrlen);

        size_t rlen = 0;
        if (srcdatalen > hdrlen) {
            rlen = padded_data_length(srcdatalen + 1 - hdrlen, desfire_get_key_block_length(ctx->keyType));
            memcpy(data, &srcdata[hdrlen], srcdatalen - hdrlen);
            data[srcdatalen - hdrlen] = 0x80; // padding

            DesfireCryptoEncDec(ctx, DCOSessionKeyEnc, data, rlen, &dstdata[hdrlen], true);
        }

        uint8_t cmac[DESFIRE_MAX_CRYPTO_BLOCK_SIZE] = {0};
        DesfireLRPCalcCMAC(ctx, cmd, dstdata, hdrlen + rlen, cmac);

        memcpy(&dstdata[hdrlen + rlen], cmac, DesfireGetMACLength(ctx));

        *dstdatalen = hdrlen + rlen + DesfireGetMACLength(ctx);
        ctx->commMode = DCMEncrypted;
    }
    free(data);
}

void DesfireSecureChannelEncode(DesfireContext_t *ctx, uint8_t cmd, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, size_t *dstdatalen) {
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
        case DACLRP:
            DesfireSecureChannelEncodeLRP(ctx, cmd, srcdata, srcdatalen, dstdata, dstdatalen);
            break;
        case DACNone:
            memcpy(dstdata, srcdata, srcdatalen);
            *dstdatalen = srcdatalen;
            break;
    }
}

static void DesfireSecureChannelDecodeD40(DesfireContext_t *ctx, uint8_t *srcdata, size_t srcdatalen, uint8_t respcode, uint8_t *dstdata, size_t *dstdatalen) {

    uint8_t *data  = calloc(DESFIRE_BUFFER_SIZE, sizeof(uint8_t));
    if (data == NULL)
        return;

    memcpy(dstdata, srcdata, srcdatalen);
    *dstdatalen = srcdatalen;

    switch (ctx->commMode) {
        case DCMMACed: {
            size_t maclen = DesfireGetMACLength(ctx);
            if (srcdatalen > maclen && DesfireEV1D40ReceiveMAC(ctx, ctx->lastCommand)) {
                uint8_t mac[16] = {0};
                size_t rlen = padded_data_length(srcdatalen - maclen, desfire_get_key_block_length(ctx->keyType));
                memcpy(data, srcdata, srcdatalen - maclen);
                DesfireCryptoEncDecEx(ctx, DCOSessionKeyMac, data, rlen, NULL, true, true, mac);

                if (memcmp(mac, &srcdata[srcdatalen - maclen], maclen) == 0) {
                    *dstdatalen = srcdatalen - maclen;
                    if (GetAPDULogging())
                        PrintAndLogEx(INFO, "Received MAC OK");
                } else {
                    PrintAndLogEx(WARNING, "Received MAC is not match with calculated");
                    PrintAndLogEx(INFO, "  received MAC:   %s", sprint_hex(&srcdata[srcdatalen - maclen], maclen));
                    PrintAndLogEx(INFO, "  calculated MAC: %s", sprint_hex(mac, maclen));
                }
            }
            break;
        }
        case DCMEncrypted:
        case DCMEncryptedWithPadding:
            if (srcdatalen < desfire_get_key_block_length(ctx->keyType)) {
                memcpy(dstdata, srcdata, srcdatalen);
                *dstdatalen = srcdatalen;
                free(data);
                return;
            }

            DesfireCryptoEncDec(ctx, DCOSessionKeyEnc, srcdata, srcdatalen, dstdata, false);
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
    free(data);
}

static void DesfireSecureChannelDecodeEV1(DesfireContext_t *ctx, uint8_t *srcdata, size_t srcdatalen, uint8_t respcode, uint8_t *dstdata, size_t *dstdatalen) {

    uint8_t *data  = calloc(DESFIRE_BUFFER_SIZE, sizeof(uint8_t));
    if (data == NULL)
        return;

    // if comm mode = plain --> response with MAC
    // if request is not zero length --> response MAC
    if (ctx->commMode == DCMPlain || ctx->commMode == DCMMACed || (ctx->commMode == DCMEncrypted && !ctx->lastRequestZeroLen)) {
        if (srcdatalen < DesfireGetMACLength(ctx)) {
            memcpy(dstdata, srcdata, srcdatalen);
            *dstdatalen = srcdatalen;
            free(data);
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
            PrintAndLogEx(INFO, "  received MAC:   %s", sprint_hex(&srcdata[*dstdatalen], DesfireGetMACLength(ctx)));
            PrintAndLogEx(INFO, "  calculated MAC: %s", sprint_hex(cmac, DesfireGetMACLength(ctx)));
        } else {
            if (GetAPDULogging())
                PrintAndLogEx(INFO, "Received MAC OK");
        }
    } else if (ctx->commMode == DCMEncrypted || ctx->commMode == DCMEncryptedWithPadding) {
        if (srcdatalen < desfire_get_key_block_length(ctx->keyType)) {
            memcpy(dstdata, srcdata, srcdatalen);
            *dstdatalen = srcdatalen;
            free(data);
            return;
        }

        DesfireCryptoEncDec(ctx, DCOSessionKeyEnc, srcdata, srcdatalen, dstdata, false);
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
    free(data);
}

static void DesfireSecureChannelDecodeEV2(DesfireContext_t *ctx, uint8_t *srcdata, size_t srcdatalen, uint8_t respcode, uint8_t *dstdata, size_t *dstdatalen) {
    ctx->cmdCntr++;

    memcpy(dstdata, srcdata, srcdatalen);
    *dstdatalen = srcdatalen;
    uint8_t cmac[DESFIRE_MAX_CRYPTO_BLOCK_SIZE] = {0};

    if (ctx->commMode == DCMMACed) {
        if (srcdatalen < DesfireGetMACLength(ctx)) {
            memcpy(dstdata, srcdata, srcdatalen);
            *dstdatalen = srcdatalen;
            return;
        }

        memcpy(dstdata, srcdata, srcdatalen - DesfireGetMACLength(ctx));
        *dstdatalen = srcdatalen - DesfireGetMACLength(ctx);

        DesfireEV2CalcCMAC(ctx, 0x00, srcdata, *dstdatalen, cmac);
        if (memcmp(&srcdata[*dstdatalen], cmac, DesfireGetMACLength(ctx)) != 0) {
            PrintAndLogEx(WARNING, "Received MAC is not match with calculated");
            PrintAndLogEx(INFO, "  received MAC:   %s", sprint_hex(&srcdata[*dstdatalen], DesfireGetMACLength(ctx)));
            PrintAndLogEx(INFO, "  calculated MAC: %s", sprint_hex(cmac, DesfireGetMACLength(ctx)));
        } else {
            if (GetAPDULogging())
                PrintAndLogEx(INFO, "Received MAC OK");
        }
    } else if (ctx->commMode == DCMEncrypted || ctx->commMode == DCMEncryptedWithPadding) {
        if (srcdatalen < DesfireGetMACLength(ctx)) {
            memcpy(dstdata, srcdata, srcdatalen);
            *dstdatalen = srcdatalen;
            return;
        }

        *dstdatalen = srcdatalen - DesfireGetMACLength(ctx);
        DesfireEV2CalcCMAC(ctx, 0x00, srcdata, *dstdatalen, cmac);
        if (memcmp(&srcdata[*dstdatalen], cmac, DesfireGetMACLength(ctx)) != 0) {
            PrintAndLogEx(WARNING, "Received MAC is not match with calculated");
            PrintAndLogEx(INFO, "  received MAC:   %s", sprint_hex(&srcdata[*dstdatalen], DesfireGetMACLength(ctx)));
            PrintAndLogEx(INFO, "  calculated MAC: %s", sprint_hex(cmac, DesfireGetMACLength(ctx)));
        } else {
            if (GetAPDULogging())
                PrintAndLogEx(INFO, "Received MAC OK");
        }

        if (*dstdatalen >= desfire_get_key_block_length(ctx->keyType)) {
            DesfireEV2FillIV(ctx, false, NULL); // fill response IV to ctx
            DesfireCryptoEncDec(ctx, DCOSessionKeyEnc, srcdata, *dstdatalen, dstdata, false);

            size_t puredatalen = FindISO9797M2PaddingDataLen(dstdata, *dstdatalen);
            if (puredatalen != 0) {
                *dstdatalen = puredatalen;
            } else {
                PrintAndLogEx(WARNING, "Padding search error.");
            }
        }
    }
}

static void DesfireSecureChannelDecodeLRP(DesfireContext_t *ctx, uint8_t *srcdata, size_t srcdatalen, uint8_t respcode, uint8_t *dstdata, size_t *dstdatalen) {
    ctx->cmdCntr++;

    memcpy(dstdata, srcdata, srcdatalen);
    *dstdatalen = srcdatalen;
    uint8_t cmac[DESFIRE_MAX_CRYPTO_BLOCK_SIZE] = {0};

    if (ctx->commMode == DCMMACed) {
        if (srcdatalen < DesfireGetMACLength(ctx)) {
            memcpy(dstdata, srcdata, srcdatalen);
            *dstdatalen = srcdatalen;
            return;
        }

        memcpy(dstdata, srcdata, srcdatalen - DesfireGetMACLength(ctx));
        *dstdatalen = srcdatalen - DesfireGetMACLength(ctx);

        DesfireLRPCalcCMAC(ctx, 0x00, srcdata, *dstdatalen, cmac);
        if (memcmp(&srcdata[*dstdatalen], cmac, DesfireGetMACLength(ctx)) != 0) {
            PrintAndLogEx(WARNING, "Received MAC is not match with calculated");
            PrintAndLogEx(INFO, "  received MAC:   %s", sprint_hex(&srcdata[*dstdatalen], DesfireGetMACLength(ctx)));
            PrintAndLogEx(INFO, "  calculated MAC: %s", sprint_hex(cmac, DesfireGetMACLength(ctx)));
        } else {
            if (GetAPDULogging())
                PrintAndLogEx(INFO, "Received MAC OK");
        }
    } else if (ctx->commMode == DCMEncrypted || ctx->commMode == DCMEncryptedWithPadding) {
        if (srcdatalen < DesfireGetMACLength(ctx)) {
            memcpy(dstdata, srcdata, srcdatalen);
            *dstdatalen = srcdatalen;
            return;
        }

        *dstdatalen = srcdatalen - DesfireGetMACLength(ctx);
        DesfireLRPCalcCMAC(ctx, 0x00, srcdata, *dstdatalen, cmac);
        if (memcmp(&srcdata[*dstdatalen], cmac, DesfireGetMACLength(ctx)) != 0) {
            PrintAndLogEx(WARNING, "Received MAC is not match with calculated");
            PrintAndLogEx(INFO, "  received MAC:   %s", sprint_hex(&srcdata[*dstdatalen], DesfireGetMACLength(ctx)));
            PrintAndLogEx(INFO, "  calculated MAC: %s", sprint_hex(cmac, DesfireGetMACLength(ctx)));
        } else {
            if (GetAPDULogging())
                PrintAndLogEx(INFO, "Received MAC OK");
        }

        if (*dstdatalen >= desfire_get_key_block_length(ctx->keyType)) {
            DesfireCryptoEncDec(ctx, DCOSessionKeyEnc, srcdata, *dstdatalen, dstdata, false);

            size_t puredatalen = FindISO9797M2PaddingDataLen(dstdata, *dstdatalen);
            if (puredatalen != 0) {
                *dstdatalen = puredatalen;
            } else {
                PrintAndLogEx(WARNING, "Padding search error.");
            }
        }
    }
}

static void DesfireISODecode(DesfireContext_t *ctx, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, size_t *dstdatalen) {
    memcpy(dstdata, srcdata, srcdatalen);
    *dstdatalen = srcdatalen;

    if (srcdatalen < DesfireGetMACLength(ctx))
        return;

    uint8_t *data  = calloc(DESFIRE_BUFFER_SIZE, 1);
    if (data == NULL)
        return;

    uint8_t maclen = DesfireGetMACLength(ctx);
    if (DesfireIsAuthenticated(ctx)) {
        memcpy(data, srcdata, srcdatalen - maclen);
        data[*dstdatalen] = 0x00; // respcode

        uint8_t cmac[DESFIRE_MAX_CRYPTO_BLOCK_SIZE] = {0};
        DesfireCryptoCMAC(ctx, data, srcdatalen - maclen + 1, cmac);
        if (memcmp(&srcdata[srcdatalen - maclen], cmac, maclen) != 0) {
            PrintAndLogEx(WARNING, "Received MAC is not match with calculated");
            PrintAndLogEx(INFO, "  received MAC:   %s", sprint_hex(&srcdata[srcdatalen - maclen], maclen));
            PrintAndLogEx(INFO, "  calculated MAC: %s", sprint_hex(cmac, maclen));
        } else {
            *dstdatalen = srcdatalen - maclen;
            if (GetAPDULogging())
                PrintAndLogEx(INFO, "Received MAC OK");
        }
    }
    free(data);
}

void DesfireSecureChannelDecode(DesfireContext_t *ctx, uint8_t *srcdata, size_t srcdatalen, uint8_t respcode, uint8_t *dstdata, size_t *dstdatalen) {
    if (ctx->cmdSet == DCCISO) {
        DesfireISODecode(ctx, srcdata, srcdatalen, dstdata, dstdatalen);
        return;
    }

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
        case DACLRP:
            DesfireSecureChannelDecodeLRP(ctx, srcdata, srcdatalen, respcode, dstdata, dstdatalen);
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

    // ISO commands
    if (cmdSet == DCCISO) {
        bool res = DesfireISOChannelValidCmd(cmd);
        if (!res)
            return false;
    }

    bool found = false;
    for (int i = 0; i < ARRAYLEN(AllowedChannelModes); i++)
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

            // ev2 like ev1
            if (secureChannel == DACEV2 &&
                    AllowedChannelModes[i].secureChannel == DACEV1 &&
                    (AllowedChannelModes[i].cmdSet == cmdSet || (AllowedChannelModes[i].cmdSet == DCCNative && cmdSet == DCCNativeISO)) &&
                    AllowedChannelModes[i].commMode == commMode) {

                found = true;
                break;
            }
        }

    if (!found)
        PrintAndLogEx(WARNING, "Wrong communication mode. Check settings. command: %02x", cmd);

    return found;
}

