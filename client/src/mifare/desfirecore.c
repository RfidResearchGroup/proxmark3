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
// Info from here and many other sources from the public internet sites
// https://github.com/revk/DESFireAES
// https://github.com/step21/desfire_rfid
// https://github.com/patsys/desfire-python/blob/master/Desfire/DESFire.py
//-----------------------------------------------------------------------------

#include "desfirecore.h"
#include <stdlib.h>
#include <string.h>
#include <util.h>
#include "aes.h"
#include "ui.h"
#include "crc.h"
#include "crc16.h"        // crc16 ccitt
#include "crc32.h"
#include "protocols.h"
#include "commonutil.h"
#include "cmdhf14a.h"
#include "iso7816/apduinfo.h"      // APDU manipulation / errorcodes
#include "iso7816/iso7816core.h"   // APDU logging
#include "util_posix.h"            // msleep
#include "mifare/desfire_crypto.h"
#include "desfiresecurechan.h"

const CLIParserOption DesfireAlgoOpts[] = {
    {T_DES,    "des"},
    {T_3DES,   "2tdea"},
    {T_3K3DES, "3tdea"},
    {T_AES,    "aes"},
    {0,    NULL},
};
const size_t DesfireAlgoOptsLen = ARRAY_LENGTH(DesfireAlgoOpts);

const CLIParserOption DesfireKDFAlgoOpts[] = {
    {MFDES_KDF_ALGO_NONE,      "none"},
    {MFDES_KDF_ALGO_AN10922,   "an10922"},
    {MFDES_KDF_ALGO_GALLAGHER, "gallagher"},
    {0,    NULL},
};
const size_t DesfireKDFAlgoOptsLen = ARRAY_LENGTH(DesfireKDFAlgoOpts);

const CLIParserOption DesfireCommunicationModeOpts[] = {
    {DCMPlain,     "plain"},
    {DCMMACed,     "mac"},
    {DCMEncrypted, "encrypt"},
    {0,    NULL},
};
const size_t DesfireCommunicationModeOptsLen = ARRAY_LENGTH(DesfireCommunicationModeOpts);

const CLIParserOption DesfireCommandSetOpts[] = {
    {DCCNative,    "native"},
    {DCCNativeISO, "niso"},
    {DCCISO,       "iso"},
    {0,    NULL},
};
const size_t DesfireCommandSetOptsLen = ARRAY_LENGTH(DesfireCommandSetOpts);

const CLIParserOption DesfireSecureChannelOpts[] = {
    {DACd40, "d40"},
    {DACEV1, "ev1"},
    {DACEV2, "ev2"},
    {0,    NULL},
};
const size_t DesfireSecureChannelOptsLen = ARRAY_LENGTH(DesfireSecureChannelOpts);

static const char *getstatus(uint16_t *sw) {
    if (sw == NULL) return "--> sw argument error. This should never happen !";
    if (((*sw >> 8) & 0xFF) == 0x91) {
        switch (*sw & 0xFF) {
            case MFDES_E_OUT_OF_EEPROM:
                return "Out of Eeprom, insufficient NV-Memory to complete command";
            case MFDES_E_ILLEGAL_COMMAND_CODE:
                return "Command code not supported";

            case MFDES_E_INTEGRITY_ERROR:
                return "CRC or MAC does not match data / Padding bytes invalid";

            case MFDES_E_NO_SUCH_KEY:
                return "Invalid key number specified";

            case MFDES_E_LENGTH:
                return "Length of command string invalid";

            case MFDES_E_PERMISSION_DENIED:
                return "Current configuration/status does not allow the requested command";

            case MFDES_E_PARAMETER_ERROR:
                return "Value of the parameter(s) invalid";

            case MFDES_E_APPLICATION_NOT_FOUND:
                return "Requested AID not present on PICC";

            case MFDES_E_APPL_INTEGRITY:
                return "Application integrity error, application will be disabled";

            case MFDES_E_AUTHENTIFICATION_ERROR:
                return "Current authentication status does not allow the requested command";

            case MFDES_E_BOUNDARY:
                return "Attempted to read/write data from/to beyond the file's/record's limit";

            case MFDES_E_PICC_INTEGRITY:
                return "PICC integrity error, PICC will be disabled";

            case MFDES_E_COMMAND_ABORTED:
                return "Previous command was not fully completed / Not all Frames were requested or provided by the PCD";

            case MFDES_E_PICC_DISABLED:
                return "PICC was disabled by an unrecoverable error";

            case MFDES_E_COUNT:
                return "Application count is limited to 28, not addition CreateApplication possible";

            case MFDES_E_DUPLICATE:
                return "Duplicate entry: File/Application/ISO Text does already exist";

            case MFDES_E_EEPROM:
                return "Eeprom error due to loss of power, internal backup/rollback mechanism activated";

            case MFDES_E_FILE_NOT_FOUND:
                return "Specified file number does not exist";

            case MFDES_E_FILE_INTEGRITY:
                return "File integrity error, file will be disabled";

            default:
                return "Unknown error";
        }
    }
    return "Unknown error";
}

const char *DesfireGetErrorString(int res, uint16_t *sw) {
    switch (res) {
        case PM3_EAPDU_FAIL:
            return getstatus(sw);
        case PM3_EUNDEF:
            return "Undefined error";
        case PM3_EINVARG:
            return "Invalid argument(s)";
        case PM3_EDEVNOTSUPP:
            return "Operation not supported by device";
        case PM3_ETIMEOUT:
            return "Operation timed out";
        case PM3_EOPABORTED:
            return "Operation aborted (by user)";
        case PM3_ENOTIMPL:
            return "Not (yet) implemented";
        case PM3_ERFTRANS:
            return "Error while RF transmission";
        case PM3_EIO:
            return "Input / output error";
        case PM3_EOVFLOW:
            return "Buffer overflow";
        case PM3_ESOFT:
            return "Software error";
        case PM3_EFLASH:
            return "Flash error";
        case PM3_EMALLOC:
            return "Memory allocation error";
        case PM3_EFILE:
            return "File error";
        case PM3_ENOTTY:
            return "Generic TTY error";
        case PM3_EINIT:
            return "Initialization error";
        case PM3_EWRONGANSWER:
            return "Expected a different answer error";
        case PM3_EOUTOFBOUND:
            return "Memory out-of-bounds error";
        case PM3_ECARDEXCHANGE:
            return "Exchange with card error";
        case PM3_EAPDU_ENCODEFAIL:
            return "Failed to create APDU";
        case PM3_ENODATA:
            return "No data";
        case PM3_EFATAL:
            return "Fatal error";
        default:
            break;
    }
    return "";
}

uint32_t DesfireAIDByteToUint(uint8_t *data) {
    return data[0] + (data[1] << 8) + (data[2] << 16);
}

void DesfireAIDUintToByte(uint32_t aid, uint8_t *data) {
    data[0] = aid & 0xff;
    data[1] = (aid >> 8) & 0xff;
    data[2] = (aid >> 16) & 0xff;
}

void DesfirePrintContext(DesfireContext *ctx) {
    PrintAndLogEx(INFO, "Key num: %d Key algo: %s Key[%d]: %s",
                  ctx->keyNum,
                  CLIGetOptionListStr(DesfireAlgoOpts, ctx->keyType),
                  desfire_get_key_length(ctx->keyType),
                  sprint_hex(ctx->key,
                             desfire_get_key_length(ctx->keyType)));

    if (ctx->kdfAlgo != MFDES_KDF_ALGO_NONE)
        PrintAndLogEx(INFO, "KDF algo: %s KDF input[%d]: %s", CLIGetOptionListStr(DesfireKDFAlgoOpts, ctx->kdfAlgo), ctx->kdfInputLen, sprint_hex(ctx->kdfInput, ctx->kdfInputLen));

    PrintAndLogEx(INFO, "Secure channel: %s Command set: %s Communication mode: %s",
                  CLIGetOptionListStr(DesfireSecureChannelOpts, ctx->secureChannel),
                  CLIGetOptionListStr(DesfireCommandSetOpts, ctx->cmdSet),
                  CLIGetOptionListStr(DesfireCommunicationModeOpts, ctx->commMode));

    if (DesfireIsAuthenticated(ctx)) {
        PrintAndLogEx(INFO, "Session key MAC [%d]: %s ",
                      desfire_get_key_length(ctx->keyType),
                      sprint_hex(ctx->sessionKeyMAC, desfire_get_key_length(ctx->keyType)));
        PrintAndLogEx(INFO, "    ENC: %s",
                      sprint_hex(ctx->sessionKeyEnc, desfire_get_key_length(ctx->keyType)));
        PrintAndLogEx(INFO, "    IV [%zu]: %s",
                      desfire_get_key_block_length(ctx->keyType),
                      sprint_hex(ctx->IV, desfire_get_key_block_length(ctx->keyType)));

    }
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

static int DESFIRESendRaw(bool activate_field, uint8_t *data, size_t datalen, uint8_t *result, uint32_t max_result_len, uint32_t *result_len, uint8_t *respcode) {
    *result_len = 0;
    if (respcode) *respcode = 0xff;

    if (activate_field) {
        DropField();
        msleep(50);
    }

    if (GetAPDULogging())
        PrintAndLogEx(SUCCESS, "raw>> %s", sprint_hex(data, datalen));

    int res = ExchangeRAW14a(data, datalen, activate_field, true, result, max_result_len, (int *)result_len, true);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (GetAPDULogging())
        PrintAndLogEx(SUCCESS, "raw<< %s", sprint_hex(result, *result_len));

    if (*result_len < 1) {
        return PM3_SUCCESS;
    }

    *result_len -= 1 + 2;
    uint8_t rcode = result[0];
    if (respcode) *respcode = rcode;
    memmove(&result[0], &result[1], *result_len);

    if (rcode != MFDES_S_OPERATION_OK &&
            rcode != MFDES_S_SIGNATURE &&
            rcode != MFDES_S_ADDITIONAL_FRAME &&
            rcode != MFDES_S_NO_CHANGES) {
        if (GetAPDULogging())
            PrintAndLogEx(ERR, "Command (%02x) ERROR: 0x%02x", data[0], rcode);
        return PM3_EAPDU_FAIL;
    }
    return PM3_SUCCESS;
}

static int DesfireExchangeNative(bool activate_field, DesfireContext *ctx, uint8_t cmd, uint8_t *data, size_t datalen, uint8_t *respcode, uint8_t *resp, size_t *resplen, bool enable_chaining, size_t splitbysize) {
    if (resplen)
        *resplen = 0;
    if (respcode)
        *respcode = 0xff;

    uint8_t buf[255 * 5]  = {0x00};
    uint32_t buflen = 0;
    uint32_t pos = 0;
    uint32_t i = 1;

    uint8_t rcode = 0xff;
    uint8_t cdata[255]  = {0};
    uint32_t cdatalen = 0;
    cdata[0] = cmd;
    memcpy(&cdata[1], data, datalen);
    cdatalen = datalen + 1;

    int res = DESFIRESendRaw(activate_field, cdata, cdatalen, buf, sizeof(buf), &buflen, &rcode);
    if (res != PM3_SUCCESS) {
        uint16_t ssw = DESFIRE_GET_ISO_STATUS(rcode);
        PrintAndLogEx(DEBUG, "error DESFIRESendRaw %s", DesfireGetErrorString(res, &ssw));
        return res;
    }

    if (resp) {
        if (splitbysize) {
            resp[0] = buflen;
            memcpy(&resp[1], buf, buflen);
        } else {
            memcpy(resp, buf, buflen);
        }
    }
    if (respcode != NULL)
        *respcode = rcode;

    pos += buflen;
    if (!enable_chaining) {
        if (rcode == MFDES_S_OPERATION_OK ||
                rcode == MFDES_ADDITIONAL_FRAME) {
            if (resplen)
                *resplen = pos;
        }
        return PM3_SUCCESS;
    }

    while (rcode == MFDES_ADDITIONAL_FRAME) {
        cdata[0] = MFDES_ADDITIONAL_FRAME; //0xAF

        res = DESFIRESendRaw(false, cdata, 1, buf, sizeof(buf), &buflen, &rcode);
        if (res != PM3_SUCCESS) {
            uint16_t ssw = DESFIRE_GET_ISO_STATUS(rcode);
            PrintAndLogEx(DEBUG, "error DESFIRESendRaw %s", DesfireGetErrorString(res, &ssw));
            return res;
        }

        if (respcode != NULL)
            *respcode = rcode;

        if (resp != NULL) {
            if (splitbysize) {
                resp[i * splitbysize] = buflen;
                memcpy(&resp[i * splitbysize + 1], buf, buflen);
                i += 1;
            } else {
                memcpy(&resp[pos], buf, buflen);
            }
        }
        pos += buflen;

        if (rcode != MFDES_ADDITIONAL_FRAME) break;
    }

    if (resplen)
        *resplen = (splitbysize) ? i : pos;

    return PM3_SUCCESS;
}

static int DesfireExchangeISO(bool activate_field, DesfireContext *ctx, uint8_t cmd, uint8_t *data, size_t datalen, uint8_t *respcode, uint8_t *resp, size_t *resplen, bool enable_chaining, size_t splitbysize) {
    if (resplen)
        *resplen = 0;
    if (respcode)
        *respcode = 0xff;

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
        PrintAndLogEx(DEBUG, "error DESFIRESendApdu %s", DesfireGetErrorString(res, &sw));
        return res;
    }

    if (respcode != NULL && ((sw & 0xff00) == 0x9100))
        *respcode = sw & 0xff;

    if (resp) {
        if (splitbysize) {
            resp[0] = buflen;
            memcpy(&resp[1], buf, buflen);
        } else {
            memcpy(resp, buf, buflen);
        }
    }

    pos += buflen;
    if (!enable_chaining) {
        if (sw == DESFIRE_GET_ISO_STATUS(MFDES_S_OPERATION_OK) ||
                sw == DESFIRE_GET_ISO_STATUS(MFDES_ADDITIONAL_FRAME)) {
            if (resplen)
                *resplen = pos;
        }
        return PM3_SUCCESS;
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
            PrintAndLogEx(DEBUG, "error DESFIRESendApdu %s", DesfireGetErrorString(res, &sw));
            return res;
        }

        if (respcode != NULL && ((sw & 0xff00) == 0x9100))
            *respcode = sw & 0xff;

        if (resp != NULL) {
            if (splitbysize) {
                resp[i * splitbysize] = buflen;
                memcpy(&resp[i * splitbysize + 1], buf, buflen);
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

// move data from blockdata [format: <length, data><length, data>...] to single data block
static void DesfireJoinBlockToBytes(uint8_t *blockdata, size_t blockdatacount, size_t blockdatasize, uint8_t *dstdata, size_t *dstdatalen) {
    *dstdatalen = 0;
    for (int i = 0; i < blockdatacount; i++) {
        memcpy(&dstdata[*dstdatalen], &blockdata[i * blockdatasize + 1], blockdata[i * blockdatasize]);
        *dstdatalen += blockdata[i * blockdatasize];
    }
}

// move data from single data block to blockdata [format: <length, data><length, data>...]
// lengths in the blockdata is not changed. result - in the blockdata
static void DesfireSplitBytesToBlock(uint8_t *blockdata, size_t *blockdatacount, size_t blockdatasize, uint8_t *dstdata, size_t dstdatalen) {
    size_t len = 0;
    for (int i = 0; i < *blockdatacount; i++) {
        size_t tlen = len + blockdata[i * blockdatasize];
        if (tlen > dstdatalen)
            tlen = dstdatalen;
        if (len == tlen) {
            *blockdatacount = i;
            break;
        }
        memcpy(&blockdata[i * blockdatasize + 1], &dstdata[len], tlen - len);
        len = tlen;
    }
}

int DesfireExchangeEx(bool activate_field, DesfireContext *ctx, uint8_t cmd, uint8_t *data, size_t datalen, uint8_t *respcode, uint8_t *resp, size_t *resplen, bool enable_chaining, size_t splitbysize) {
    int res = PM3_SUCCESS;

    if (!PrintChannelModeWarning(cmd, ctx->secureChannel, ctx->cmdSet, ctx->commMode))
        DesfirePrintContext(ctx);

    uint8_t databuf[250 * 5] = {0};
    size_t databuflen = 0;

    switch (ctx->cmdSet) {
        case DCCNative:
        case DCCNativeISO:
            DesfireSecureChannelEncode(ctx, cmd, data, datalen, databuf, &databuflen);

            if (ctx->cmdSet == DCCNative)
                res = DesfireExchangeNative(activate_field, ctx, cmd, databuf, databuflen, respcode, databuf, &databuflen, enable_chaining, splitbysize);
            else
                res = DesfireExchangeISO(activate_field, ctx, cmd, databuf, databuflen, respcode, databuf, &databuflen, enable_chaining, splitbysize);

            if (splitbysize) {
                uint8_t sdata[250 * 5] = {0};
                size_t sdatalen = 0;
                DesfireJoinBlockToBytes(databuf, databuflen, splitbysize, sdata, &sdatalen);

                //PrintAndLogEx(INFO, "block : %s", sprint_hex(sdata, sdatalen));
                DesfireSecureChannelDecode(ctx, sdata, sdatalen, *respcode, resp, resplen);

                DesfireSplitBytesToBlock(databuf, &databuflen, splitbysize, resp, *resplen);
                memcpy(resp, databuf, databuflen * splitbysize);
                *resplen = databuflen;
            } else {
                DesfireSecureChannelDecode(ctx, databuf, databuflen, *respcode, resp, resplen);
            }
            break;
        case DCCISO:
            return PM3_EAPDU_FAIL;
            break;
    }

    return res;
}

int DesfireExchange(DesfireContext *ctx, uint8_t cmd, uint8_t *data, size_t datalen, uint8_t *respcode, uint8_t *resp, size_t *resplen) {
    return DesfireExchangeEx(false, ctx, cmd, data, datalen, respcode, resp, resplen, true, 0);
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
    uint8_t respcode = 0;

    int res = DesfireExchangeEx(true, ctx, MFDES_SELECT_APPLICATION, data, (aid2 == NULL) ? 3 : 6, &respcode, resp, &resplen, true, 0);
    if (res == PM3_SUCCESS) {
        if (resplen != 0)
            return PM3_ECARDEXCHANGE;

        // select operation fail
        if (respcode != MFDES_S_OPERATION_OK)
            return PM3_EAPDU_FAIL;

        return PM3_SUCCESS;
    }
    return res;
}

int DesfireSelectAIDHex(DesfireContext *ctx, uint32_t aid1, bool select_two, uint32_t aid2) {
    uint8_t data[6] = {0};

    DesfireAIDUintToByte(aid1, data);
    DesfireAIDUintToByte(aid2, &data[3]);

    return DesfireSelectAID(ctx, data, (select_two) ? &data[3] : NULL);
}

int DesfireSelectAndAuthenticate(DesfireContext *dctx, DesfireSecureChannel secureChannel, uint32_t aid, bool verbose) {
    if (verbose)
        DesfirePrintContext(dctx);

    int res = DesfireSelectAIDHex(dctx, aid, false, 0);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire select " _RED_("error") ".");
        return PM3_ESOFT;
    }

    res = DesfireAuthenticate(dctx, secureChannel);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire authenticate " _RED_("error") ". Result: %d", res);
        return PM3_ESOFT;
    }

    if (DesfireIsAuthenticated(dctx)) {
        if (verbose)
            PrintAndLogEx(INFO, "Desfire  " _GREEN_("authenticated"));
    } else {
        return PM3_ESOFT;
    }
    
    return PM3_SUCCESS;
}

int DesfireAuthenticate(DesfireContext *dctx, DesfireSecureChannel secureChannel) {
    // 3 different way to authenticate   AUTH (CRC16) , AUTH_ISO (CRC32) , AUTH_AES (CRC32)
    // 4 different crypto arg1   DES, 3DES, 3K3DES, AES
    // 3 different communication modes,  PLAIN,MAC,CRYPTO

    DesfireClearSession(dctx);

    if (secureChannel == DACNone)
        return PM3_SUCCESS;

    mbedtls_aes_context ctx;

    uint8_t keybytes[24] = {0};
    // Crypt constants
    uint8_t IV[16] = {0};
    uint8_t RndA[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
    uint8_t RndB[16] = {0};
    uint8_t encRndB[16] = {0};
    uint8_t rotRndB[16] = {0};   //RndB'
    uint8_t both[32 + 1] = {0};  // ek/dk_keyNo(RndA+RndB')

    // Part 1
    memcpy(keybytes, dctx->key, desfire_get_key_length(dctx->keyType));

    struct desfire_key dkey = {0};
    desfirekey_t key = &dkey;

    if (dctx->keyType == T_AES) {
        mbedtls_aes_init(&ctx);
        Desfire_aes_key_new(keybytes, key);
    } else if (dctx->keyType == T_3DES) {
        Desfire_3des_key_new_with_version(keybytes, key);
    } else if (dctx->keyType == T_DES) {
        Desfire_des_key_new(keybytes, key);
    } else if (dctx->keyType == T_3K3DES) {
        Desfire_3k3des_key_new_with_version(keybytes, key);
    }

    if (dctx->kdfAlgo == MFDES_KDF_ALGO_AN10922) {
        mifare_kdf_an10922(key, dctx->kdfInput, dctx->kdfInputLen);
        PrintAndLogEx(DEBUG, " Derrived key: " _GREEN_("%s"), sprint_hex(key->data, key_block_size(key)));
    } else if (dctx->kdfAlgo == MFDES_KDF_ALGO_GALLAGHER) {
        // We will overrite any provided KDF input since a gallagher specific KDF was requested.
        dctx->kdfInputLen = 11;

        /*if (mfdes_kdf_input_gallagher(tag->info.uid, tag->info.uidlen, dctx->keyNum, tag->selected_application, dctx->kdfInput, &dctx->kdfInputLen) != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Could not generate Gallagher KDF input");
        }*/

        mifare_kdf_an10922(key, dctx->kdfInput, dctx->kdfInputLen);
        PrintAndLogEx(DEBUG, "    KDF Input: " _YELLOW_("%s"), sprint_hex(dctx->kdfInput, dctx->kdfInputLen));
        PrintAndLogEx(DEBUG, " Derrived key: " _GREEN_("%s"), sprint_hex(key->data, key_block_size(key)));

    }

    uint8_t subcommand = MFDES_AUTHENTICATE;
    if (secureChannel == DACEV1) {
        if (dctx->keyType == T_AES)
            subcommand = MFDES_AUTHENTICATE_AES;
        else
            subcommand = MFDES_AUTHENTICATE_ISO;
    }

    size_t recv_len = 0;
    uint8_t respcode = 0;
    uint8_t recv_data[256] = {0};

    // Let's send our auth command
    int res = DesfireExchangeEx(false, dctx, subcommand, &dctx->keyNum, 1, &respcode, recv_data, &recv_len, false, 0);
    if (res != PM3_SUCCESS) {
        return 1;
    }

    if (!recv_len) {
        return 2;
    }

    if (respcode != MFDES_ADDITIONAL_FRAME) {
        return 3;
    }

    uint32_t expectedlen = 8;
    if (dctx->keyType == T_AES || dctx->keyType == T_3K3DES) {
        expectedlen = 16;
    }

    if (recv_len != expectedlen) {
        return 4;
    }

    // Part 2
    uint32_t rndlen = recv_len;
    memcpy(encRndB, recv_data, rndlen);


    // Part 3
    if (dctx->keyType == T_AES) {
        if (mbedtls_aes_setkey_dec(&ctx, key->data, 128) != 0) {
            return 5;
        }
        mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, rndlen, IV, encRndB, RndB);
    } else if (dctx->keyType == T_DES) {
        if (secureChannel == DACd40)
            des_decrypt(RndB, encRndB, key->data);
        if (secureChannel == DACEV1)
            des_decrypt_cbc(RndB, encRndB, rndlen, key->data, IV);
    } else if (dctx->keyType == T_3DES)
        tdes_nxp_receive(encRndB, RndB, rndlen, key->data, IV, 2);
    else if (dctx->keyType == T_3K3DES) {
        tdes_nxp_receive(encRndB, RndB, rndlen, key->data, IV, 3);
    }

    if (g_debugMode > 1) {
        PrintAndLogEx(DEBUG, "encRndB: %s", sprint_hex(encRndB, 8));
        PrintAndLogEx(DEBUG, "RndB: %s", sprint_hex(RndB, 8));
    }

    // - Rotate RndB by 8 bits
    memcpy(rotRndB, RndB, rndlen);
    rol(rotRndB, rndlen);

    uint8_t encRndA[16] = {0x00};

    // - Encrypt our response
    if (secureChannel == DACd40) {
        if (dctx->keyType == T_DES) {
            des_decrypt(encRndA, RndA, key->data);
            memcpy(both, encRndA, rndlen);

            for (uint32_t x = 0; x < rndlen; x++) {
                rotRndB[x] = rotRndB[x] ^ encRndA[x];
            }

            des_decrypt(encRndB, rotRndB, key->data);
            memcpy(both + rndlen, encRndB, rndlen);
        } else if (dctx->keyType == T_3DES) {
            //TODO
        }
    } else if (secureChannel == DACEV1 && dctx->keyType != T_AES) {
        if (dctx->keyType == T_DES) {
            uint8_t tmp[16] = {0x00};
            memcpy(tmp, RndA, rndlen);
            memcpy(tmp + rndlen, rotRndB, rndlen);
            if (g_debugMode > 1) {
                PrintAndLogEx(DEBUG, "rotRndB: %s", sprint_hex(rotRndB, rndlen));
                PrintAndLogEx(DEBUG, "Both: %s", sprint_hex(tmp, 16));
            }
            des_encrypt_cbc(both, tmp, 16, key->data, IV);
            if (g_debugMode > 1) {
                PrintAndLogEx(DEBUG, "EncBoth: %s", sprint_hex(both, 16));
            }
        } else if (dctx->keyType == T_3DES) {
            uint8_t tmp[16] = {0x00};
            memcpy(tmp, RndA, rndlen);
            memcpy(tmp + rndlen, rotRndB, rndlen);
            if (g_debugMode > 1) {
                PrintAndLogEx(DEBUG, "rotRndB: %s", sprint_hex(rotRndB, rndlen));
                PrintAndLogEx(DEBUG, "Both: %s", sprint_hex(tmp, 16));
            }
            tdes_nxp_send(tmp, both, 16, key->data, IV, 2);
            if (g_debugMode > 1) {
                PrintAndLogEx(DEBUG, "EncBoth: %s", sprint_hex(both, 16));
            }
        } else if (dctx->keyType == T_3K3DES) {
            uint8_t tmp[32] = {0x00};
            memcpy(tmp, RndA, rndlen);
            memcpy(tmp + rndlen, rotRndB, rndlen);
            if (g_debugMode > 1) {
                PrintAndLogEx(DEBUG, "rotRndB: %s", sprint_hex(rotRndB, rndlen));
                PrintAndLogEx(DEBUG, "Both3k3: %s", sprint_hex(tmp, 32));
            }
            tdes_nxp_send(tmp, both, 32, key->data, IV, 3);
            if (g_debugMode > 1) {
                PrintAndLogEx(DEBUG, "EncBoth: %s", sprint_hex(both, 32));
            }
        }
    } else if (secureChannel == DACEV1 && dctx->keyType == T_AES) {
        uint8_t tmp[32] = {0x00};
        memcpy(tmp, RndA, rndlen);
        memcpy(tmp + rndlen, rotRndB, rndlen);
        if (g_debugMode > 1) {
            PrintAndLogEx(DEBUG, "rotRndB: %s", sprint_hex(rotRndB, rndlen));
            PrintAndLogEx(DEBUG, "Both3k3: %s", sprint_hex(tmp, 32));
        }
        if (dctx->keyType == T_AES) {
            if (mbedtls_aes_setkey_enc(&ctx, key->data, 128) != 0) {
                return 6;
            }
            mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, 32, IV, tmp, both);
            if (g_debugMode > 1) {
                PrintAndLogEx(DEBUG, "EncBoth: %s", sprint_hex(both, 32));
            }
        }
    }

    uint32_t bothlen = 16;
    if (dctx->keyType == T_AES || dctx->keyType == T_3K3DES) {
        bothlen = 32;
    }

    res = DesfireExchangeEx(false, dctx, MFDES_ADDITIONAL_FRAME, both, bothlen, &respcode, recv_data, &recv_len, false, 0);
    if (res != PM3_SUCCESS) {
        return 7;
    }

    if (!recv_len) {
        return 8;
    }

    if (respcode != MFDES_S_OPERATION_OK) {
        return 9;
    }

    // Part 4
    memcpy(encRndA, recv_data, rndlen);

    struct desfire_key sesskey = {0};

    Desfire_session_key_new(RndA, RndB, key, &sesskey);
    memcpy(dctx->sessionKeyEnc, sesskey.data, desfire_get_key_length(dctx->keyType));

    //PrintAndLogEx(INFO, "encRndA : %s", sprint_hex(encRndA, rndlen));
    //PrintAndLogEx(INFO, "IV : %s", sprint_hex(IV, rndlen));
    if (dctx->keyType == T_DES) {
        if (secureChannel == DACd40)
            des_decrypt(encRndA, encRndA, key->data);
        if (secureChannel == DACEV1)
            des_decrypt_cbc(encRndA, encRndA, rndlen, key->data, IV);
    } else if (dctx->keyType == T_3DES)
        tdes_nxp_receive(encRndA, encRndA, rndlen, key->data, IV, 2);
    else if (dctx->keyType == T_3K3DES)
        tdes_nxp_receive(encRndA, encRndA, rndlen, key->data, IV, 3);
    else if (dctx->keyType == T_AES) {
        if (mbedtls_aes_setkey_dec(&ctx, key->data, 128) != 0) {
            return 10;
        }
        mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, rndlen, IV, encRndA, encRndA);
    }

    rol(RndA, rndlen);
    //PrintAndLogEx(INFO, "Expected_RndA : %s", sprint_hex(RndA, rndlen));
    //PrintAndLogEx(INFO, "Generated_RndA : %s", sprint_hex(encRndA, rndlen));
    for (uint32_t x = 0; x < rndlen; x++) {
        if (RndA[x] != encRndA[x]) {
            if (g_debugMode > 1) {
                PrintAndLogEx(DEBUG, "Expected_RndA : %s", sprint_hex(RndA, rndlen));
                PrintAndLogEx(DEBUG, "Generated_RndA : %s", sprint_hex(encRndA, rndlen));
            }
            return 11;
        }
    }

    // If the 3Des key first 8 bytes = 2nd 8 Bytes then we are really using Singe Des
    // As such we need to set the session key such that the 2nd 8 bytes = 1st 8 Bytes
    if (dctx->keyType == T_3DES) {
        if (memcmp(key->data, &key->data[8], 8) == 0)
            memcpy(&dctx->sessionKeyEnc[8], dctx->sessionKeyEnc, 8);
    }

    if (secureChannel == DACEV1) {
        cmac_generate_subkeys(&sesskey, MCD_RECEIVE);
        //key->cmac_sk1 and key->cmac_sk2
        //memcpy(dctx->sessionKeyEnc, sesskey.data, desfire_get_key_length(dctx->keyType));
    }

    memset(dctx->IV, 0, DESFIRE_MAX_KEY_SIZE);
    dctx->secureChannel = secureChannel;
    memcpy(dctx->sessionKeyMAC, dctx->sessionKeyEnc, desfire_get_key_length(dctx->keyType));
    PrintAndLogEx(INFO, "Session key : %s", sprint_hex(dctx->sessionKeyEnc, desfire_get_key_length(dctx->keyType)));

    return PM3_SUCCESS;
}

int DesfireFormatPICC(DesfireContext *dctx) {
    uint8_t respcode = 0xff;
    uint8_t resp[257] = {0};
    size_t resplen = 0;
    int res = DesfireExchange(dctx, MFDES_FORMAT_PICC, NULL, 0, &respcode, resp, &resplen);
    if (res != PM3_SUCCESS)
        return res;
    if (respcode != MFDES_S_OPERATION_OK || resplen != 0)
        return PM3_EAPDU_FAIL;
    return PM3_SUCCESS;
}

int DesfireGetUID(DesfireContext *dctx, uint8_t *resp, size_t *resplen) {
    uint8_t respcode = 0xff;
    int res = DesfireExchange(dctx, MFDES_GET_UID, NULL, 0, &respcode, resp, resplen);
    if (res != PM3_SUCCESS)
        return res;
    if (respcode != MFDES_S_OPERATION_OK)
        return PM3_EAPDU_FAIL;
    return PM3_SUCCESS;
}

int DesfireGetAIDList(DesfireContext *dctx, uint8_t *resp, size_t *resplen) {
    uint8_t respcode = 0xff;
    int res = DesfireExchange(dctx, MFDES_GET_APPLICATION_IDS, NULL, 0, &respcode, resp, resplen);
    if (res != PM3_SUCCESS)
        return res;
    if (respcode != MFDES_S_OPERATION_OK)
        return PM3_EAPDU_FAIL;
    return PM3_SUCCESS;
}

int DesfireGetDFList(DesfireContext *dctx, uint8_t *resp, size_t *resplen) {
    uint8_t respcode = 0xff;
    int res = DesfireExchangeEx(false, dctx, MFDES_GET_DF_NAMES, NULL, 0, &respcode, resp, resplen, true, 24);
    if (res != PM3_SUCCESS)
        return res;
    if (respcode != MFDES_S_OPERATION_OK)
        return PM3_EAPDU_FAIL;
    return PM3_SUCCESS;
}

int DesfireCreateApplication(DesfireContext *dctx, uint8_t *appdata, size_t appdatalen) {
    uint8_t respcode = 0xff;
    uint8_t resp[257] = {0};
    size_t resplen = 0;
    int res = DesfireExchangeEx(false, dctx, MFDES_CREATE_APPLICATION, appdata, appdatalen, &respcode, resp, &resplen, true, 0);
    if (res != PM3_SUCCESS)
        return res;
    if (respcode != MFDES_S_OPERATION_OK || resplen != 0)
        return PM3_EAPDU_FAIL;
    return PM3_SUCCESS;
}

int DesfireDeleteApplication(DesfireContext *dctx, uint32_t aid) {
    uint8_t respcode = 0xff;
    uint8_t data[3] = {0};
    DesfireAIDUintToByte(aid, data);
    uint8_t resp[257] = {0};
    size_t resplen = 0;
    int res = DesfireExchangeEx(false, dctx, MFDES_DELETE_APPLICATION, data, sizeof(data), &respcode, resp, &resplen, true, 0);
    if (res != PM3_SUCCESS)
        return res;
    if (respcode != MFDES_S_OPERATION_OK || resplen != 0)
        return PM3_EAPDU_FAIL;
    return PM3_SUCCESS;
}

int DesfireGetKeySettings(DesfireContext *dctx, uint8_t *resp, size_t *resplen) {
    uint8_t respcode = 0xff;
    int res = DesfireExchange(dctx, MFDES_GET_KEY_SETTINGS, NULL, 0, &respcode, resp, resplen);
    if (res != PM3_SUCCESS)
        return res;
    if (respcode != MFDES_S_OPERATION_OK)
        return PM3_EAPDU_FAIL;
    return PM3_SUCCESS;
}

int DesfireGetKeyVersion(DesfireContext *dctx, uint8_t *data, size_t len, uint8_t *resp, size_t *resplen) {
    uint8_t respcode = 0xff;
    int res = DesfireExchange(dctx, MFDES_GET_KEY_VERSION, data, len, &respcode, resp, resplen);
    if (res != PM3_SUCCESS)
        return res;
    if (respcode != MFDES_S_OPERATION_OK)
        return PM3_EAPDU_FAIL;
    return PM3_SUCCESS;
}

int DesfireChangeKeySettings(DesfireContext *dctx, uint8_t *data, size_t len) {
    uint8_t respcode = 0xff;
    uint8_t resp[257] = {0};
    size_t resplen = 0;
    int res = DesfireExchange(dctx, MFDES_CHANGE_KEY_SETTINGS, data, len, &respcode, resp, &resplen);
    if (res != PM3_SUCCESS)
        return res;
    if (respcode != MFDES_S_OPERATION_OK || resplen != 0)
        return PM3_EAPDU_FAIL;
    return PM3_SUCCESS;
}

static void PrintKeyType(uint8_t keytype) {
    switch (keytype) {
        case 00:
            PrintAndLogEx(SUCCESS, "Key: 2TDEA");
            break;
        case 01:
            PrintAndLogEx(SUCCESS, "Key: 3TDEA");
            break;
        case 02:
            PrintAndLogEx(SUCCESS, "Key: AES");
            break;
        default:
            PrintAndLogEx(SUCCESS, "Key: unknown: 0x%02x", keytype);
            break;
    }
}

static void PrintKeySettingsPICC(uint8_t keysettings, uint8_t numkeys, bool print2ndbyte) {
    PrintAndLogEx(SUCCESS, "PICC level rights:");
    PrintAndLogEx(SUCCESS, "[%c...] CMK Configuration changeable   : %s", (keysettings & (1 << 3)) ? '1' : '0', (keysettings & (1 << 3)) ? _GREEN_("YES") : "NO (frozen)");
    PrintAndLogEx(SUCCESS, "[.%c..] CMK required for create/delete : %s", (keysettings & (1 << 2)) ? '1' : '0', (keysettings & (1 << 2)) ? _GREEN_("NO") : "YES");
    PrintAndLogEx(SUCCESS, "[..%c.] Directory list access with CMK : %s", (keysettings & (1 << 1)) ? '1' : '0', (keysettings & (1 << 1)) ? _GREEN_("NO") : "YES");
    PrintAndLogEx(SUCCESS, "[...%c] CMK is changeable              : %s", (keysettings & (1 << 0)) ? '1' : '0', (keysettings & (1 << 0)) ? _GREEN_("YES") : "NO (frozen)");
    PrintAndLogEx(SUCCESS, "");

    if (print2ndbyte)
        PrintAndLogEx(SUCCESS, "key count: %d", numkeys & 0x0f);
}

static void PrintKeySettingsApp(uint8_t keysettings, uint8_t numkeys, bool print2ndbyte) {
    // Access rights.
    PrintAndLogEx(SUCCESS, "Application level rights:");
    uint8_t rights = ((keysettings >> 4) & 0x0F);
    switch (rights) {
        case 0x0:
            PrintAndLogEx(SUCCESS, "-- AMK authentication is necessary to change any key (default)");
            break;
        case 0xE:
            PrintAndLogEx(SUCCESS, "-- Authentication with the key to be changed (same KeyNo) is necessary to change a key");
            break;
        case 0xF:
            PrintAndLogEx(SUCCESS, "-- All keys (except AMK,see Bit0) within this application are frozen");
            break;
        default:
            PrintAndLogEx(SUCCESS,
                          "-- Authentication with the specified key is necessary to change any key.\n"
                          "A change key and a PICC master key (CMK) can only be changed after authentication with the master key.\n"
                          "For keys other then the master or change key, an authentication with the same key is needed."
                         );
            break;
    }

    PrintAndLogEx(SUCCESS, "[%c...] AMK Configuration changeable   : %s", (keysettings & (1 << 3)) ? '1' : '0', (keysettings & (1 << 3)) ? _GREEN_("YES") : "NO (frozen)");
    PrintAndLogEx(SUCCESS, "[.%c..] AMK required for create/delete : %s", (keysettings & (1 << 2)) ? '1' : '0', (keysettings & (1 << 2)) ? "NO" : "YES");
    PrintAndLogEx(SUCCESS, "[..%c.] Directory list access with AMK : %s", (keysettings & (1 << 1)) ? '1' : '0', (keysettings & (1 << 1)) ? "NO" : "YES");
    PrintAndLogEx(SUCCESS, "[...%c] AMK is changeable              : %s", (keysettings & (1 << 0)) ? '1' : '0', (keysettings & (1 << 0)) ? _GREEN_("YES") : "NO (frozen)");
    PrintAndLogEx(SUCCESS, "");

    if (print2ndbyte) {
        PrintKeyType(numkeys >> 6);
        PrintAndLogEx(SUCCESS, "key count: %d", numkeys & 0x0f);
    }
}

void PrintKeySettings(uint8_t keysettings, uint8_t numkeys, bool applevel, bool print2ndbyte) {
    if (applevel)
        PrintKeySettingsApp(keysettings, numkeys, print2ndbyte);
    else
        PrintKeySettingsPICC(keysettings, numkeys, print2ndbyte);
}
