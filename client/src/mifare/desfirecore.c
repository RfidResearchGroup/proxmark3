//-----------------------------------------------------------------------------
// Copyright (C) 2010 Romain Tartiere.
// Copyright (C) 2014 Iceman
// Copyright (C) 2021 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency Desfire core functions
//-----------------------------------------------------------------------------
// Info from here and many other soursec from the internet
// https://github.com/revk/DESFireAES
// https://github.com/step21/desfire_rfid
// https://github.com/patsys/desfire-python/blob/master/Desfire/DESFire.py
//-----------------------------------------------------------------------------

#include "desfirecore.h"
#include <stdlib.h>
#include <string.h>
#include <util.h>
#include "ui.h"
#include "protocols.h"
#include "cmdhf14a.h"
#include "iso7816/apduinfo.h"     // APDU manipulation / errorcodes
#include "iso7816/iso7816core.h"  // APDU logging
#include "util_posix.h"           // msleep
#include "mifare/desfire_crypto.h"

void DesfireClearContext(DesfireContext *ctx) {
    ctx->keyNum = 0;
    ctx->keyType = T_DES;
    memset(ctx->key, 0, sizeof(ctx->key));
    
    ctx->authChannel = DACNone;
    ctx->cmdChannel = DCCNative;
    ctx->commMode = DCMNone;

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

static int DESFIRESendApdu(bool activate_field, sAPDU apdu, uint8_t *result, uint32_t max_result_len, uint32_t *result_len, uint16_t *sw) {
    if (result_len) *result_len = 0;
    if (sw) *sw = 0;

    uint16_t isw = 0;
    int res = 0;

    if (activate_field) {
        DropField();
        msleep(50);
    }

    uint8_t data[APDU_RES_LEN] = {0};

    // COMPUTE APDU
    int datalen = 0;
    if (APDUEncodeS(&apdu, false, 0x100, data, &datalen)) { // 100 == with Le
        PrintAndLogEx(ERR, "APDU encoding error.");
        return PM3_EAPDU_ENCODEFAIL;
    }

    if (GetAPDULogging())
        PrintAndLogEx(SUCCESS, ">>>> %s", sprint_hex(data, datalen));

    res = ExchangeAPDU14a(data, datalen, activate_field, true, result, max_result_len, (int *)result_len);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (GetAPDULogging())
        PrintAndLogEx(SUCCESS, "<<<< %s", sprint_hex(result, *result_len));

    if (*result_len < 2) {
        return PM3_SUCCESS;
    }

    *result_len -= 2;
    isw = (result[*result_len] << 8) + result[*result_len + 1];
    if (sw)
        *sw = isw;

    if (isw != 0x9000 && 
        isw != DESFIRE_GET_ISO_STATUS(MFDES_S_OPERATION_OK) && 
        isw != DESFIRE_GET_ISO_STATUS(MFDES_S_SIGNATURE) && 
        isw != DESFIRE_GET_ISO_STATUS(MFDES_S_ADDITIONAL_FRAME) && 
        isw != DESFIRE_GET_ISO_STATUS(MFDES_S_NO_CHANGES)) {
        if (GetAPDULogging()) {
            if (isw >> 8 == 0x61) {
                PrintAndLogEx(ERR, "APDU chaining len: 0x%02x -->", isw & 0xff);
            } else {
                PrintAndLogEx(ERR, "APDU(%02x%02x) ERROR: [0x%4X] %s", apdu.CLA, apdu.INS, isw, GetAPDUCodeDescription(isw >> 8, isw & 0xff));
                return PM3_EAPDU_FAIL;
            }
        }
        return PM3_EAPDU_FAIL;
    }
    return PM3_SUCCESS;
}

static int DesfireExchangeNative(bool activate_field, DesfireContext *ctx, uint8_t cmd, uint8_t *data, size_t datalen, uint8_t *resp, size_t *resplen, bool enable_chaining) {
    
    return PM3_SUCCESS;
}

static int DesfireExchangeISO(bool activate_field, DesfireContext *ctx, uint8_t cmd, uint8_t *data, size_t datalen, uint8_t *resp, size_t *resplen, bool enable_chaining) {
    if (resplen) 
        *resplen = 0;

    // TODO !!!
    size_t splitbysize = 0;

    uint16_t sw = 0;
    uint8_t buf[255 * 5]  = {0x00};
    uint32_t buflen = 0;
    uint32_t pos = 0;
    uint32_t i = 1;

    sAPDU apdu = {0};
    apdu.CLA = MFDES_NATIVE_ISO7816_WRAP_CLA; //0x90
    apdu.INS = cmd;
    apdu.Lc = datalen;
    apdu.P1 = 0;
    apdu.P2 = 0;
    apdu.data = data;

    int res = DESFIRESendApdu(activate_field, apdu, buf, sizeof(buf), &buflen, &sw);
    if (res != PM3_SUCCESS) {
        //PrintAndLogEx(DEBUG, "error DESFIRESendApdu %s", GetErrorString(res, &sw));
        return res;
    }
    if (resp)
        memcpy(resp, buf, buflen);

    pos += buflen;
    if (!enable_chaining) {
        if (sw == DESFIRE_GET_ISO_STATUS(MFDES_ADDITIONAL_FRAME)) {
            if (resplen) 
                *resplen = pos;
            return PM3_SUCCESS;
        }
        return res;
    }

    while (sw == DESFIRE_GET_ISO_STATUS(MFDES_ADDITIONAL_FRAME)) {
        apdu.CLA = MFDES_NATIVE_ISO7816_WRAP_CLA; //0x90
        apdu.INS = MFDES_ADDITIONAL_FRAME; //0xAF
        apdu.Lc = 0;
        apdu.P1 = 0;
        apdu.P2 = 0;
        apdu.data = NULL;

        res = DESFIRESendApdu(false, apdu, buf, sizeof(buf), &buflen, &sw);
        if (res != PM3_SUCCESS) {
            //PrintAndLogEx(DEBUG, "error DESFIRESendApdu %s", GetErrorString(res, &sw));
            return res;
        }

        if (resp != NULL) {
            if (splitbysize) {
                memcpy(&resp[i * splitbysize], buf, buflen);
                i += 1;
            } else {
                memcpy(&resp[pos], buf, buflen);
            }
        }
        pos += buflen;

        if (sw != DESFIRE_GET_ISO_STATUS(MFDES_ADDITIONAL_FRAME)) break;
    }

    if (resplen)
        *resplen = (splitbysize) ? i : pos;
    return PM3_SUCCESS;    
}

int DesfireExchangeEx(bool activate_field, DesfireContext *ctx, uint8_t cmd, uint8_t *data, size_t datalen, uint8_t *resp, size_t *resplen, bool enable_chaining) {
    int res = PM3_SUCCESS;
    
    switch(ctx->cmdChannel) {
        case DCCNative:
            res = DesfireExchangeNative(activate_field, ctx, cmd, data, datalen, resp, resplen, enable_chaining);
        break;
        case DCCNativeISO:
            res = DesfireExchangeISO(activate_field, ctx, cmd, data, datalen, resp, resplen, enable_chaining);
        break;
        case DCCISO:
            return PM3_EAPDU_FAIL;
        break;
    }   
    
    return res;
}

int DesfireExchange(DesfireContext *ctx, uint8_t cmd, uint8_t *data, size_t datalen, uint8_t *resp, size_t *resplen) {
    return DesfireExchangeEx(false, ctx, cmd, data, datalen, resp, resplen, true);
}

int DesfireSelectAID(DesfireContext *ctx, uint8_t *aid1, uint8_t *aid2) {
    if (aid1 == NULL)
        return PM3_EINVARG;
    
    uint8_t data[6] = {0};
    memcpy(data, aid1, 3);
    if (aid2 != NULL) 
        memcpy(&data[3], aid2, 3);
    uint8_t resp[257] = {0};
    size_t resplen = 0;
    int res = DesfireExchangeEx(true, ctx, MFDES_SELECT_APPLICATION, data, (aid2 == NULL) ? 3 : 6, resp, &resplen, true);
    if (res == PM3_SUCCESS && resplen != 0)
        return PM3_ECARDEXCHANGE;
    return res;
}

int DesfireSelectAIDHex(DesfireContext *ctx, uint32_t aid1, bool select_two, uint32_t aid2) {
    uint8_t data[6] = {0};
    // TODO !!!!
    data[0] = aid1 & 0xff;
    data[1] = (aid1 >> 8) & 0xff;
    data[2] = (aid1 >> 16) & 0xff;
    
    data[3] = aid2 & 0xff;
    data[4] = (aid2 >> 8) & 0xff;
    data[5] = (aid2 >> 16) & 0xff;
    
    return DesfireSelectAID(ctx, data, (select_two) ? &data[3] : NULL);
}

