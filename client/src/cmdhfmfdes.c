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
// High frequency MIFARE Desfire commands
//-----------------------------------------------------------------------------
// Code heavily modified by B.Kerler :)

#include "cmdhfmfdes.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "jansson.h"
#include "commonutil.h"             // ARRAYLEN
#include "cmdparser.h"              // command_t
#include "comms.h"
#include "ui.h"
#include "cmdhf14a.h"
#include "aes.h"
#include "crypto/libpcrypto.h"
#include "protocols.h"
#include "cmdtrace.h"
#include "cliparser.h"
#include "iso7816/apduinfo.h"       // APDU manipulation / errorcodes
#include "iso7816/iso7816core.h"    // APDU logging
#include "util_posix.h"             // msleep
#include "mifare/desfirecore.h"
#include "mifare/desfiretest.h"
#include "mifare/desfiresecurechan.h"
#include "mifare/mifaredefault.h"   // default keys
#include "crapto1/crapto1.h"
#include "fileutils.h"
//#include "nfc/ndef.h"               // NDEF
#include "mifare/mad.h"
#include "mifare/mifaredefault.h"
#include "generator.h"
#include "mifare/aiddesfire.h"
#include "mifare/prime.h"
#include "util.h"
#include "crypto/originality.h"
#include "x509_crt.h"
#include "mbedtls/oid.h"
#include "mbedtls/sha256.h"

#define MAX_KEY_LEN        24
#define MAX_KEYS_LIST_LEN  1024
#define MFDES_BRUTEAID_RESELECT_ATTEMPTS 5
#define MFDES_BRUTEAID_RESELECT_WAIT_MS  200
#define MFDES_BRUTEAID_MAD_START         0xF0000FU
#define MFDES_BRUTEAID_MAD_STEP          0x10U
#define MFDES_BRUTEFID_RESELECT_ATTEMPTS 3
#define MFDES_BRUTEFID_RESELECT_WAIT_MS 500
#define MFDES_BRUTEDAMSLOT_RESELECT_ATTEMPTS 3
#define MFDES_BRUTEDAMSLOT_RESELECT_WAIT_MS 500
#define MFDES_PC_KEY_LEN                16U
#define MFDES_PC_CHALLENGE_LEN          8U
#define MFDES_PC_MAX_ROUNDS             8U
#define MFDES_PC_MAC_LEN                8U

// DUOX ISO Internal Authenticate
#define DUOX_INTAUTH_CHALLENGE_LEN      16
#define DUOX_INTAUTH_SIG_LEN            64
#define DUOX_VDE_CHALLENGE_LEN          32
#define DUOX_VDE_SIG_LEN                64
#define DUOX_MAX_KEY_INPUT              8192
// TLV tags for ISO Internal Authenticate
#define DUOX_TAG_OPTSA                  0x80
#define DUOX_TAG_DYNAMIC_AUTH_DATA      0x7C
#define DUOX_TAG_CHALLENGE              0x81
#define DUOX_TAG_SIGNATURE              0x82
#define DUOX_INTAUTH_MSG_PREFIX         0xF0
#define DUOX_VDE_DEFAULT_AID            0x1010F6U

// LEAF Verified Open Application
#define LEAF_VERIFIED_DEFAULT_AID       0xF51CD6U  // 0xD61CF5 in user-facing (wire bytes D6 1C F5)
#define LEAF_VERIFIED_CERT_FILE         0x02
#define LEAF_VERIFIED_MAX_CERT_LEN      4096

// LEAF Root CA public key (P-256, uncompressed: 04 || X(32) || Y(32))
// https://github.com/LEAF-Community/leaf-verified-device-onboarding-guide/blob/82b51a1958a0f9eedaa2f97b7f533490bc108463/detect_and_select.py#L95
static const uint8_t kLeafRootP256PubKey[65] = {
    0x04,
    0x2D, 0x27, 0x81, 0xBE, 0x41, 0xC2, 0x27, 0x58, 0xA6, 0x13, 0x81, 0x0F, 0x67, 0xEC, 0x78, 0xDF,
    0x11, 0x76, 0xC4, 0x76, 0x5B, 0x21, 0x2B, 0x49, 0x21, 0x8C, 0x6C, 0x58, 0x40, 0x8A, 0x5A, 0xDA,
    0x3D, 0x99, 0x73, 0x20, 0x9D, 0x82, 0x28, 0x91, 0x3A, 0x88, 0x16, 0x97, 0x3C, 0xFE, 0x5C, 0x9E,
    0xBF, 0xD8, 0xC6, 0x69, 0x75, 0x32, 0xCD, 0xD5, 0xB5, 0x3E, 0xE1, 0x34, 0xD2, 0xF1, 0x1B, 0x3C
};

static const uint8_t kDuoxVDEDefaultDFName[] = {
    0xA0, 0x00, 0x00, 0x08, 0x45, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

#define status(x) ( ((uint16_t)(0x91 << 8)) + (uint16_t)x )
/*
static uint8_t desdefaultkeys[3][8] = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, //Official
    {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47},
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
};

static uint8_t aesdefaultkeys[5][16] = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, //Official, TRF7970A
    {0x79, 0x70, 0x25, 0x53, 0x79, 0x70, 0x25, 0x53, 0x79, 0x70, 0x25, 0x53, 0x79, 0x70, 0x25, 0x53}, // TRF7970A
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, // TRF7970A
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
    {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f}
};

static uint8_t k3kdefaultkeys[1][24] = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
*/
typedef struct mfdes_authinput {
    uint8_t mode;
    uint8_t algo;
    uint8_t keyno;
    uint8_t keylen;
    uint8_t key[24];
    uint8_t kdfAlgo;
    uint8_t kdfInputLen;
    uint8_t kdfInput[31];
} PACKED mfdes_authinput_t;

typedef struct mfdes_auth_res {
    uint8_t sessionkeylen;
    uint8_t sessionkey[24];
} PACKED mfdes_auth_res_t;

typedef struct mfdes_data {
    uint8_t fileno;  //01
    uint8_t offset[3];
    uint8_t length[3];
    uint8_t *data;
} PACKED mfdes_data_t;

typedef struct mfdes_value {
    uint8_t fileno;  //01
    uint8_t value[16];
} PACKED mfdes_value_t;

typedef struct mfdes_file {
    uint8_t fileno;  //01
    uint8_t fid[2];  //03E1
    uint8_t comset;  //00
    uint8_t access_rights[2]; ///EEEE
    uint8_t filesize[3]; //0F0000
} PACKED mfdes_file_t;

typedef struct mfdes_linear {
    uint8_t fileno;  //01
    uint8_t fid[2];  //03E1
    uint8_t comset;  //00
    uint8_t access_rights[2]; ///EEEE
    uint8_t recordsize[3];
    uint8_t maxnumrecords[3];
} PACKED mfdes_linear_t;

typedef struct mfdes_value_file {
    uint8_t fileno;  //01
    uint8_t comset;  //00
    uint8_t access_rights[2]; ///EEEE
    uint8_t lowerlimit[4];
    uint8_t upperlimit[4];
    uint8_t value[4];
    uint8_t limitedcreditenabled;
} PACKED mfdes_value_file_t;

typedef enum {
    MFDES_DATA_FILE = 0,
    MFDES_RECORD_FILE,
    MFDES_VALUE_FILE
} MFDES_FILE_TYPE_T;

typedef enum {
    DESFIRE_UNKNOWN_PROD = 0,
    DESFIRE_PHYSICAL,
    DESFIRE_LIGHT_PHYSICAL,
    DESFIRE_MICROCONTROLLER,
    DESFIRE_JAVACARD,
    DESFIRE_HCE,
} nxp_producttype_t;

typedef struct dfname {
    uint8_t aid[3];
    uint8_t fid[2];
    uint8_t name[16];
} PACKED dfname_t;

typedef struct aidhdr {
    uint8_t aid[3];
    uint8_t keysetting1;
    uint8_t keysetting2;
    uint8_t fid[2];
    uint8_t name[16];
} PACKED aidhdr_t;

typedef struct {
    const uint32_t aidnum;
    const char *aid;
    const char *comment;
} mfdesCommonAID_t;

/*
PACS application id(s) - HID Factory, CP1000 Standard, Mobile, Custom and Elite
We have HID Factory,  Field Encoder == CP1000 (?)
No mobile, Custom or Elite
*/

static const mfdesCommonAID_t commonAids[] = {
    { 0x53494F, "\x53\x49\x4F", "SIO DESFire EV1 - HID Factory" },
    { 0xD3494F, "\xD3\x49\x4F", "SIO DESFire EV1 - Field Encoder" },
    { 0xD9494F, "\xD9\x49\x4F", "SIO DESFire EV1 - Field Encoder" },
    { 0xF484E3, "\xF4\x84\xE3", "SE Enhanced" },
    { 0xF484E4, "\xF4\x84\xE4", "SE Enhanced" },
    { 0xF4812F, "\xf4\x81\x2f", "Gallagher card data application" },
    { 0xF48120, "\xf4\x81\x20", "Gallagher card application directory" }, // Can be 0xF48120 - 0xF4812B, but I've only ever seen 0xF48120
    { 0xF47300, "\xf4\x73\x00", "Inner Range card application" },
    { 0xF51CD6, "\xF5\x1C\xD6", "LEAF Verified Open Application" },
};

typedef enum {
    MFDES_BRUTEAID_PRESET_FULL = 0,
    MFDES_BRUTEAID_PRESET_ASCII = 1,
    MFDES_BRUTEAID_PRESET_NUMBERS = 2,
    MFDES_BRUTEAID_PRESET_LETTERS = 3,
    MFDES_BRUTEAID_PRESET_DICTIONARY = 4,
    MFDES_BRUTEAID_PRESET_MAD = 5,
} mfdes_bruteaid_preset_t;

static const CLIParserOption mfdesBruteAIDPresetOpts[] = {
    {MFDES_BRUTEAID_PRESET_FULL, "full"},
    {MFDES_BRUTEAID_PRESET_ASCII, "ascii"},
    {MFDES_BRUTEAID_PRESET_NUMBERS, "numbers"},
    {MFDES_BRUTEAID_PRESET_LETTERS, "letters"},
    {MFDES_BRUTEAID_PRESET_DICTIONARY, "dictionary"},
    {MFDES_BRUTEAID_PRESET_MAD, "mad"},
    {0, NULL},
};

static int CmdHelp(const char *Cmd);

static int CLIGetUint32Hex(CLIParserContext *ctx, uint8_t paramnum, uint32_t defaultValue, uint32_t *value, bool *valuePresent, uint8_t nlen, const char *lengthErrorStr) {
    *value = defaultValue;
    if (valuePresent != NULL)
        *valuePresent = false;

    int res = arg_get_u32_hexstr_def_nlen(ctx, paramnum, defaultValue, value, nlen, true);

    if (valuePresent != NULL)
        *valuePresent = (res == 1);

    if (res == 2) {
        PrintAndLogEx(ERR, lengthErrorStr);
        return PM3_EINVARG;
    }
    if (res == 0) {
        return PM3_EINVARG;
    }

    return PM3_SUCCESS;
}

static const char *getAidCommentStr(uint32_t aid) {
    for (int i = 0; i < ARRAYLEN(commonAids); i++) {
        if (aid == commonAids[i].aidnum) {
            return commonAids[i].comment;
        }
    }
    return "";
}

nxp_cardtype_t getCardType(uint8_t type, uint8_t major, uint8_t minor) {

    // DESFire MF3ICD40
    if (type == 0x01 && major == 0x00 && minor == 0x02)
        return DESFIRE_MF3ICD40;

    // DESFire EV1
    if (type == 0x01 && major == 0x01 && minor == 0x00)
        return DESFIRE_EV1;

    // DESFire EV2
    if (type == 0x01 && major == 0x12 && minor == 0x00)
        return DESFIRE_EV2;

    if (type == 0x01 && major == 0x22 && minor == 0x00)
        return DESFIRE_EV2_XL;

    // DESFire EV3
    if (type == 0x01 && major == 0x33 && minor == 0x00)
        return DESFIRE_EV3;

    if (type == 0x81 && major == 0x43 && minor == 0x01)
        return DESFIRE_EV3;

    // Duox
    if (type == 0x01 && major == 0xA0 && minor == 0x00)
        return DUOX;

    // DESFire Light
    if (type == 0x08 && major == 0x30 && minor == 0x00)
        return DESFIRE_LIGHT;

    // combo card DESFire / EMV
    if (type == 0x81 && major == 0x42 && minor == 0x00)
        return DESFIRE_EV2;

    // Apple Wallet DESFire Applet
    // - v62.1 encountered on iPhone
    // - v62.0 encountered on Apple Watch
    if (type == 0x91 && major == 0x62 && (minor == 0x01 || minor == 0x00))
        return DESFIRE_EV2;

    // Plus EV1
    if (type == 0x02 && major == 0x11 && minor == 0x00)
        return PLUS_EV1;

    // Plus Ev2
    if (type == 0x02 && major == 0x22 && minor == 0x00)
        return PLUS_EV2;

    // NTAG 413 DNA
    if (major == 0x10 && minor == 0x00)
        return NTAG413DNA;

    // NTAG 424
    if (type == 0x04 && major == 0x30 && minor == 0x00)
        return NTAG424;

    return NXP_UNKNOWN;
}

// ref:  https://www.nxp.com/docs/en/application-note/AN12343.pdf  p7
static nxp_producttype_t getProductType(const uint8_t *versionhw) {

    uint8_t product = versionhw[1];

    if (product == 0x01)
        return DESFIRE_PHYSICAL;
    if (product == 0x08)
        return DESFIRE_LIGHT_PHYSICAL;
    if (product == 0x81 || product == 0x83)
        return DESFIRE_MICROCONTROLLER;
    if (product == 0x91)
        return DESFIRE_JAVACARD;
    if (product == 0xA1)
        return DESFIRE_HCE;
    return DESFIRE_UNKNOWN_PROD;
}

static const char *getProductTypeStr(const uint8_t *versionhw) {

    uint8_t product = versionhw[1];

    if (product == 0x01) {
        return "MIFARE DESFire native IC (physical card)";
    }

    if (product == 0x08) {
        return "MIFARE DESFire Light native IC (physical card)";
    }

    if (product == 0x81 || product == 0x83) {
        return "MIFARE DESFire implementation on microcontroller (physical card)";
    }

    if (product == 0x91) {
        return "MIFARE DESFire applet on Java card / secure element";
    }

    if (product == 0xA1) {
        return "MIFARE DESFire HCE (MIFARE 2GO)";
    }

    return "UNKNOWN PROD";
}

int mfdes_get_info(mfdes_info_res_t *info) {

    PacketResponseNG resp;
    SendCommandNG(CMD_HF_DESFIRE_INFO, NULL, 0);
    if (WaitForResponseTimeout(CMD_HF_DESFIRE_INFO, &resp, 1500) == false) {
        PrintAndLogEx(WARNING, "command execution time out");
        DropField();
        return PM3_ETIMEOUT;
    }

    memcpy(info, resp.data.asBytes, sizeof(mfdes_info_res_t));

    if (resp.status != PM3_SUCCESS) {

        switch (info->isOK) {
            case 1:
                PrintAndLogEx(WARNING, "Can't select card");
                break;
            case 2:
                PrintAndLogEx(WARNING, "Card is most likely not DESFire. Wrong size UID");
                break;
            case 3:
            default:
                PrintAndLogEx(WARNING, _RED_("Command unsuccessful"));
                break;
        }
        return PM3_ESOFT;
    }

    return PM3_SUCCESS;
}

// --- GET SIGNATURE
int desfire_print_signature(uint8_t *uid, uint8_t uidlen, uint8_t *signature, size_t signature_len) {

    if (uid == NULL) {
        PrintAndLogEx(DEBUG, "UID is NULL");
        return PM3_EINVARG;
    }

    if (signature == NULL) {
        PrintAndLogEx(DEBUG, "SIGNATURE is NULL");
        return PM3_EINVARG;
    }

    int index = originality_check_verify(uid, uidlen, signature, signature_len, PK_MFDES);
    return originality_check_print(signature, signature_len, index);
}

static void swap24(uint8_t *data) {
    if (data == NULL) {
        return;
    }
    uint8_t tmp = data[0];
    data[0] = data[2];
    data[2] = tmp;
}

// default parameters
static uint8_t defaultKeyNum = 0;
static DesfireCryptoAlgorithm defaultAlgoId = T_3DES;  // Real DESFire cards seem to use 2TDEA by default
static uint8_t defaultKey[DESFIRE_MAX_KEY_SIZE] = {0};
static int defaultKdfAlgo = MFDES_KDF_ALGO_NONE;
static int defaultKdfInputLen = 0;
static uint8_t defaultKdfInput[50] = {0};
static DesfireSecureChannel defaultSecureChannel = DACEV1;
static DesfireCommandSet defaultCommSet = DCCNativeISO;
static DesfireCommunicationMode defaultCommMode = DCMPlain;
static uint32_t transactionCounter = 0;

static int CmdDesGetSessionParameters(CLIParserContext *ctx, DesfireContext_t *dctx,
                                      uint8_t keynoid, uint8_t algoid, uint8_t keyid,
                                      uint8_t kdfid, uint8_t kdfiid,
                                      uint8_t cmodeid, uint8_t ccsetid, uint8_t schannid,
                                      uint8_t appid,
                                      uint8_t appisoid,
                                      uint8_t dfnameid,
                                      int *securechannel,
                                      DesfireCommunicationMode defcommmode,
                                      uint32_t *id,
                                      DesfireISOSelectWay *selectway) {

    uint8_t keynum = defaultKeyNum;
    int algores = defaultAlgoId;
    uint8_t key[DESFIRE_MAX_KEY_SIZE] = {0};
    memcpy(key, defaultKey, DESFIRE_MAX_KEY_SIZE);

    int kdfAlgo = defaultKdfAlgo;

    int kdfInputLen = defaultKdfInputLen;
    uint8_t kdfInput[50] = {0};
    memcpy(kdfInput, defaultKdfInput, defaultKdfInputLen);

    int commmode = defaultCommMode;
    if (defcommmode != DCMNone) {
        commmode = defcommmode;
    }

    int commset = defaultCommSet;
    int secchann = defaultSecureChannel;

    if (keynoid) {
        keynum = arg_get_int_def(ctx, keynoid, keynum);
    }

    if (algoid) {
        if (CLIGetOptionList(arg_get_str(ctx, algoid), DesfireAlgoOpts, &algores)) {
            return PM3_ESOFT;
        }
    }

    if (keyid) {
        int keylen = 0;
        uint8_t keydata[200] = {0};
        if (CLIParamHexToBuf(arg_get_str(ctx, keyid), keydata, sizeof(keydata), &keylen)) {
            return PM3_ESOFT;
        }

        if (keylen && keylen != desfire_get_key_length(algores)) {
            PrintAndLogEx(ERR, "%s key must have %d bytes length instead of %d.", CLIGetOptionListStr(DesfireAlgoOpts, algores), desfire_get_key_length(algores), keylen);
            return PM3_EINVARG;
        }

        if (keylen) {
            memcpy(key, keydata, keylen);
        }
    }

    if (kdfid) {
        if (CLIGetOptionList(arg_get_str(ctx, kdfid), DesfireKDFAlgoOpts, &kdfAlgo)) {
            return PM3_ESOFT;
        }
    }

    if (kdfiid) {
        int datalen = kdfInputLen;
        uint8_t data[200] = {0};
        if (CLIParamHexToBuf(arg_get_str(ctx, kdfiid), data, sizeof(data), &datalen)) {
            return PM3_ESOFT;
        }

        if (datalen) {
            kdfInputLen = datalen;
            memcpy(kdfInput, data, datalen);
        }
    }

    if (cmodeid) {
        if (CLIGetOptionList(arg_get_str(ctx, cmodeid), DesfireCommunicationModeOpts, &commmode))
            return PM3_ESOFT;
    }

    if (ccsetid) {
        if (CLIGetOptionList(arg_get_str(ctx, ccsetid), DesfireCommandSetOpts, &commset))
            return PM3_ESOFT;
    }

    if (schannid) {
        if (CLIGetOptionList(arg_get_str(ctx, schannid), DesfireSecureChannelOpts, &secchann))
            return PM3_ESOFT;
    }

    // Handle dfname parameter
    if (dfnameid && id) {
        uint8_t dfname_data[16] = {0};
        int dfname_len = 0;
        if (CLIParamHexToBuf(arg_get_str(ctx, dfnameid), dfname_data, sizeof(dfname_data), &dfname_len) == 0 && dfname_len > 0) {

            if (dfname_len <= 16) {

                DesfireSetDFName(dctx, dfname_data, dfname_len);
                if (selectway) {
                    *selectway = ISWDFName;
                }

            } else {
                PrintAndLogEx(ERR, "DF name length must be between 1-16 bytes, got %d", dfname_len);
                return PM3_EINVARG;
            }
        }
    }

    if (appid && id) {
        *id = 0x000000;
        if (CLIGetUint32Hex(ctx, appid, 0x000000, id, NULL, 3, "AID must have 3 bytes length")) {
            return PM3_EINVARG;
        }

        if (selectway) {
            *selectway = ISW6bAID;
        }
    }

    if (appisoid && id) {
        uint32_t xisoid = 0x0000;
        bool isoidpresent = false;
        if (CLIGetUint32Hex(ctx, appisoid, 0x0000, &xisoid, &isoidpresent, 2, "Application ISO ID (for EF) must have 2 bytes length")) {
            return PM3_EINVARG;
        }

        if (isoidpresent) {
            *id = xisoid & 0xffff;
            if (selectway) {
                *selectway = ISWIsoID;
            }
        }
    }

    DesfireSetKey(dctx, keynum, algores, key);
    DesfireSetKdf(dctx, kdfAlgo, kdfInput, kdfInputLen);
    DesfireSetCommandSet(dctx, commset);
    DesfireSetCommMode(dctx, commmode);
    if (securechannel) {
        *securechannel = secchann;
    }

    return PM3_SUCCESS;
}

static int DesfirePCRun(DesfireContext_t *dctx, const uint8_t proximity_key[MFDES_PC_KEY_LEN], uint8_t rounds, bool verbose) {
    if (dctx == NULL || proximity_key == NULL || rounds < 1 || rounds > MFDES_PC_MAX_ROUNDS) {
        return PM3_EINVARG;
    }

    int res = PM3_SUCCESS;
    pcrypto_rng_t rng = {0};
    bool rng_initialized = false;

    const uint8_t rng_personalization[] = "hf_mfdes_pc";
    res = pcrypto_rng_init(&rng, rng_personalization, sizeof(rng_personalization) - 1);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to initialize random generator for proximity check");
        return res;
    }
    rng_initialized = true;

    uint8_t prepare_resp[APDU_RES_LEN] = {0};
    size_t prepare_resp_len = 0;
    uint8_t respcode = 0xFF;
    res = DesfireExchangeEx(true, dctx, MFDES_PREPARE_PC, NULL, 0, &respcode, prepare_resp, &prepare_resp_len, true, 0);
    if (res != PM3_SUCCESS) {
        uint16_t sw = status(respcode);
        PrintAndLogEx(ERR, "Prepare proximity check command failed. Result: %d %s", res, DesfireGetErrorString(res, &sw));
        goto out;
    }

    uint8_t options[3] = {0};
    size_t options_len = MIN((size_t)3, prepare_resp_len);
    if (options_len > 0) {
        memcpy(options, prepare_resp, options_len);
    }

    bool prepare_extension_present = (prepare_resp_len > 3);
    uint8_t prepare_extension = prepare_extension_present ? prepare_resp[3] : 0x00;

    if (verbose) {
        PrintAndLogEx(INFO, "Prepare response [%zu] : %s", prepare_resp_len, sprint_hex(prepare_resp, prepare_resp_len));
        PrintAndLogEx(INFO, "Prepare options[%zu]   : %s", options_len, sprint_hex(options, options_len));
        if (prepare_extension_present) {
            PrintAndLogEx(INFO, "Prepare extension      : %02X", prepare_extension);
        }
    }

    uint8_t random_challenge[MFDES_PC_CHALLENGE_LEN] = {0};
    res = pcrypto_rng_fill(&rng, random_challenge, sizeof(random_challenge));
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to generate random challenge");
        goto out;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "Random challenge       : %s", sprint_hex(random_challenge, sizeof(random_challenge)));
    }

    size_t split_size = MFDES_PC_CHALLENGE_LEN / rounds;
    if (split_size == 0) {
        split_size = 1;
    }

    uint8_t challenge_response[MFDES_PC_CHALLENGE_LEN * 2] = {0};
    size_t challenge_response_len = 0;
    size_t challenge_offset = 0;

    for (uint8_t round = 0; round < rounds; round++) {
        size_t remaining = MFDES_PC_CHALLENGE_LEN - challenge_offset;
        size_t challenge_part_len = ((round + 1) == rounds) ? remaining : MIN(split_size, remaining);
        if (challenge_part_len == 0) {
            PrintAndLogEx(ERR, "Invalid challenge split state at round %u", (unsigned int)round + 1);
            res = PM3_ESOFT;
            goto out;
        }

        uint8_t round_payload[1 + MFDES_PC_CHALLENGE_LEN] = {0};
        round_payload[0] = (uint8_t)challenge_part_len;
        memcpy(&round_payload[1], &random_challenge[challenge_offset], challenge_part_len);

        uint8_t round_resp[APDU_RES_LEN] = {0};
        size_t round_resp_len = 0;
        respcode = 0xFF;

        res = DesfireExchange(dctx, MFDES_PROXIMITY_CHECK, round_payload, challenge_part_len + 1, &respcode, round_resp, &round_resp_len);
        if (res != PM3_SUCCESS) {
            uint16_t sw = status(respcode);
            PrintAndLogEx(ERR, "Proximity check round %u command failed. Result: %d %s", (unsigned int)round + 1, res, DesfireGetErrorString(res, &sw));
            goto out;
        }

        size_t response_slice_len = MIN(round_resp_len, challenge_part_len);
        memcpy(&challenge_response[challenge_response_len], round_resp, response_slice_len);
        challenge_response_len += response_slice_len;
        memcpy(&challenge_response[challenge_response_len], &random_challenge[challenge_offset], challenge_part_len);
        challenge_response_len += challenge_part_len;

        if (verbose) {
            PrintAndLogEx(INFO, "Round %u challenge[%zu]: %s", (unsigned int)round + 1, challenge_part_len, sprint_hex(&random_challenge[challenge_offset], challenge_part_len));
            PrintAndLogEx(INFO, "Round %u response [%zu]: %s", (unsigned int)round + 1, round_resp_len, sprint_hex(round_resp, round_resp_len));
        }

        challenge_offset += challenge_part_len;
    }

    bool include_prepare_extension = prepare_extension_present;

    uint8_t verify_cmd_input[1 + 3 + 1 + (MFDES_PC_CHALLENGE_LEN * 2)] = {0};
    size_t verify_cmd_input_len = 0;
    verify_cmd_input[verify_cmd_input_len++] = MFDES_VERIFY_PC;
    if (options_len > 0) {
        memcpy(&verify_cmd_input[verify_cmd_input_len], options, options_len);
        verify_cmd_input_len += options_len;
    }
    if (include_prepare_extension) {
        verify_cmd_input[verify_cmd_input_len++] = prepare_extension;
    }
    memcpy(&verify_cmd_input[verify_cmd_input_len], challenge_response, challenge_response_len);
    verify_cmd_input_len += challenge_response_len;

    uint8_t verify_cmd_mac[MFDES_PC_MAC_LEN] = {0};
    res = aes_cmac8(NULL, (uint8_t *)proximity_key, verify_cmd_input, verify_cmd_mac, (int)verify_cmd_input_len);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to calculate Verify_PC command MAC");
        res = PM3_ESOFT;
        goto out;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "Verify command input[%zu]: %s", verify_cmd_input_len, sprint_hex(verify_cmd_input, verify_cmd_input_len));
        PrintAndLogEx(INFO, "Verify command MAC       : %s", sprint_hex(verify_cmd_mac, sizeof(verify_cmd_mac)));
    }

    uint8_t verify_resp[APDU_RES_LEN] = {0};
    size_t verify_resp_len = 0;
    respcode = 0xFF;
    res = DesfireExchange(dctx, MFDES_VERIFY_PC, verify_cmd_mac, sizeof(verify_cmd_mac), &respcode, verify_resp, &verify_resp_len);
    if (res != PM3_SUCCESS) {
        uint16_t sw = status(respcode);
        PrintAndLogEx(ERR, "Verify proximity check command failed. Result: %d %s", res, DesfireGetErrorString(res, &sw));
        goto out;
    }

    if (verify_resp_len < MFDES_PC_MAC_LEN) {
        PrintAndLogEx(WARNING, "Verify response MAC is not present");
    } else {
        uint8_t verify_resp_input[1 + 3 + 1 + (MFDES_PC_CHALLENGE_LEN * 2)] = {0};
        size_t verify_resp_input_len = 0;
        verify_resp_input[verify_resp_input_len++] = MFDES_S_SIGNATURE;
        if (options_len > 0) {
            memcpy(&verify_resp_input[verify_resp_input_len], options, options_len);
            verify_resp_input_len += options_len;
        }
        if (prepare_extension_present) {
            verify_resp_input[verify_resp_input_len++] = prepare_extension;
        }
        memcpy(&verify_resp_input[verify_resp_input_len], challenge_response, challenge_response_len);
        verify_resp_input_len += challenge_response_len;

        uint8_t expected_resp_mac[MFDES_PC_MAC_LEN] = {0};
        res = aes_cmac8(NULL, (uint8_t *)proximity_key, verify_resp_input, expected_resp_mac, (int)verify_resp_input_len);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Failed to calculate expected verify response MAC");
            res = PM3_ESOFT;
            goto out;
        }

        if (memcmp(verify_resp, expected_resp_mac, MFDES_PC_MAC_LEN) != 0) {
            PrintAndLogEx(WARNING, "Verify response MAC mismatch");
            if (verbose) {
                PrintAndLogEx(INFO, "Expected: %s", sprint_hex(expected_resp_mac, MFDES_PC_MAC_LEN));
                PrintAndLogEx(INFO, "Received: %s", sprint_hex(verify_resp, MFDES_PC_MAC_LEN));
            }
        } else if (verbose) {
            PrintAndLogEx(INFO, "Verify response MAC      : %s", sprint_hex(verify_resp, MFDES_PC_MAC_LEN));
        }
    }

    PrintAndLogEx(SUCCESS, "DESFire proximity check " _GREEN_("passed") ", rounds: %u", rounds);
    res = PM3_SUCCESS;

out:
    if (rng_initialized) {
        pcrypto_rng_free(&rng);
    }
    return res;
}

static int CmdHF14ADesDefault(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes default",
                  "Set default parameters for access to MIFARE DESfire card.",
                  "hf mfdes default -n 0 -t des -k 0000000000000000 --kdf none -> save to the default parameters");

    void *argtable[] = {
        arg_param_begin,
        arg_int0("n",  "keyno", "<dec>", "Key number"),
        arg_str0("t",  "algo", "<DES|2TDEA|3TDEA|AES>", "Crypt algo"),
        arg_str0("k",  "key", "<hex>", "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf", "<none|AN10922|gallagher>", "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi", "<hex>", "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode", "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset", "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL,  "schann", "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, &securechann, DCMNone, NULL, NULL);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    CLIParserFree(ctx);

    // clear out select DF Name length and array when resetting to default the desfire context
    dctx.selectedDFNameLen = 0;
    memset(dctx.selectedDFName, 0, sizeof(dctx.selectedDFName));

    defaultKeyNum = dctx.keyNum;
    defaultAlgoId = dctx.keyType;
    memcpy(defaultKey, dctx.key, DESFIRE_MAX_KEY_SIZE);
    defaultKdfAlgo = dctx.kdfAlgo;
    defaultKdfInputLen = dctx.kdfInputLen;
    memcpy(defaultKdfInput, dctx.kdfInput, sizeof(dctx.kdfInput));
    defaultSecureChannel = securechann;
    defaultCommSet = dctx.cmdSet;
    defaultCommMode = dctx.commMode;

    PrintAndLogEx(INFO, "-----------" _CYAN_("Default parameters") "---------------------------------");

    PrintAndLogEx(INFO, "Key Num     : %d", defaultKeyNum);
    PrintAndLogEx(INFO, "Algo        : %s", CLIGetOptionListStr(DesfireAlgoOpts, defaultAlgoId));
    PrintAndLogEx(INFO, "Key         : %s", sprint_hex(defaultKey, desfire_get_key_length(defaultAlgoId)));
    PrintAndLogEx(INFO, "KDF algo    : %s", CLIGetOptionListStr(DesfireKDFAlgoOpts, defaultKdfAlgo));
    PrintAndLogEx(INFO, "KDF input   : [%d] %s", defaultKdfInputLen, sprint_hex(defaultKdfInput, defaultKdfInputLen));
    PrintAndLogEx(INFO, "Secure chan : %s", CLIGetOptionListStr(DesfireSecureChannelOpts, defaultSecureChannel));
    PrintAndLogEx(INFO, "Command set : %s", CLIGetOptionListStr(DesfireCommandSetOpts, defaultCommSet));
    PrintAndLogEx(INFO, "Comm mode   : %s", CLIGetOptionListStr(DesfireCommunicationModeOpts, defaultCommMode));

    return PM3_SUCCESS;
}

static int CmdHF14ADesInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes info",
                  "Get info from MIFARE DESfire tags",
                  "hf mfdes info");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    SetAPDULogging(false);
    DropField();

    mfdes_info_res_t info;
    int res = mfdes_get_info(&info);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    nxp_cardtype_t cardtype = getCardType(info.versionHW[1], info.versionHW[3], info.versionHW[4]);
    if (cardtype == PLUS_EV1) {
        PrintAndLogEx(INFO, "Card seems to be MIFARE Plus EV1.  Try " _YELLOW_("`hf mfp info`"));
        DropField();
        return PM3_SUCCESS;
    }

    if (cardtype == PLUS_EV2) {
        PrintAndLogEx(INFO, "Card seems to be MIFARE Plus EV2.  Try " _YELLOW_("`hf mfp info`"));
        DropField();
        return PM3_SUCCESS;
    }

    if (cardtype == NTAG424) {
        PrintAndLogEx(INFO, "Card seems to be NTAG 424.  Try " _YELLOW_("`hf ntag424 info`"));
        DropField();
        return PM3_SUCCESS;
    }

    if (cardtype == NXP_UNKNOWN) {
        PrintAndLogEx(INFO, "HW Version.. %s", sprint_hex_inrow(info.versionHW, sizeof(info.versionHW)));
        PrintAndLogEx(INFO, "SW Version.. %s", sprint_hex_inrow(info.versionSW, sizeof(info.versionSW)));
        PrintAndLogEx(INFO, "Version data identification failed. Report to Iceman!");
        DropField();
        return PM3_SUCCESS;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "---------------------------------- " _CYAN_("Tag Information") " ----------------------------------");
    PrintAndLogEx(SUCCESS, "              UID: " _GREEN_("%s"), sprint_hex(info.uid, info.uidlen));
    PrintAndLogEx(SUCCESS, "     Batch number: " _GREEN_("%s"), sprint_hex(info.details + 7, 5));
    PrintAndLogEx(SUCCESS, "  Production date: week " _GREEN_("%02x") " / " _GREEN_("20%02x"), info.details[12], info.details[13]);

    nxp_producttype_t prodtype = getProductType(info.versionHW);
    if (prodtype != DESFIRE_UNKNOWN_PROD) {
        PrintAndLogEx(SUCCESS, "     Product type: %s", getProductTypeStr(info.versionHW));
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Hardware Information"));
    PrintAndLogEx(INFO, "   raw: %s", sprint_hex_inrow(info.versionHW, sizeof(info.versionHW)));

    PrintAndLogEx(INFO, "     Vendor Id: " _YELLOW_("%s"), getTagInfo(info.versionHW[0]));
    PrintAndLogEx(INFO, "          Type: " _YELLOW_("%s"), mifare_prime_get_type_str(info.versionHW[1]));
    PrintAndLogEx(INFO, "       Subtype: " _YELLOW_("0x%02X"), info.versionHW[2]);
    PrintAndLogEx(INFO, "       Version: %s", mifare_prime_get_version_str(info.versionHW[1], info.versionHW[3], info.versionHW[4]));
    PrintAndLogEx(INFO, "  Storage size: %s", mifare_prime_get_card_size_str(info.versionHW[5]));
    PrintAndLogEx(INFO, "      Protocol: %s", mifare_prime_get_protocol_str(info.versionHW[6], true));
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Software Information"));
    PrintAndLogEx(INFO, "   raw: %s", sprint_hex_inrow(info.versionSW, sizeof(info.versionSW)));
    PrintAndLogEx(INFO, "     Vendor Id: " _YELLOW_("%s"), getTagInfo(info.versionSW[0]));
    PrintAndLogEx(INFO, "          Type: " _YELLOW_("%s"), mifare_prime_get_type_str(info.versionSW[1]));
    PrintAndLogEx(INFO, "       Subtype: " _YELLOW_("0x%02X"), info.versionSW[2]);
    PrintAndLogEx(INFO, "       Version: " _YELLOW_("%d.%d"),  info.versionSW[3], info.versionSW[4]);
    PrintAndLogEx(INFO, "  Storage size: %s", mifare_prime_get_card_size_str(info.versionSW[5]));
    PrintAndLogEx(INFO, "      Protocol: %s", mifare_prime_get_protocol_str(info.versionSW[6], false));
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--------------------------------- " _CYAN_("Card capabilities") " ---------------------------------");
    uint8_t major = info.versionSW[3];
    uint8_t minor = info.versionSW[4];

    if (major == 0 && minor == 2)
        PrintAndLogEx(INFO, "\t0.2 - DESFire Light, Originality check, ");

    if (major == 0 && minor == 4)
        PrintAndLogEx(INFO, "\t0.4 - DESFire MF3ICD40, No support for APDU (only native commands)");
    if (major == 0 && minor == 5)
        PrintAndLogEx(INFO, "\t0.5 - DESFire MF3ICD40, Support for wrapping commands inside ISO 7816 style APDUs");
    if (major == 0 && minor == 6)
        PrintAndLogEx(INFO, "\t0.6 - DESFire MF3ICD40, Add ISO/IEC 7816 command set compatibility");

    if (major == 1 && minor == 0)
        PrintAndLogEx(INFO, "\t1.0 - DESFire Ev1 MF3ICDQ1/MF3ICDHQ1, EAL4+");
    if (major == 1 && minor == 3)
        PrintAndLogEx(INFO, "\t1.3 - DESFire Ev1 MF3ICD21/41/81, Support extended APDU commands, EAL4+");
    if (major == 1 && minor == 4)
        PrintAndLogEx(INFO, "\t1.4 - DESFire Ev1 MF3ICD21/41/81, EAL4+");

    if (major == 2 && minor == 0)
        PrintAndLogEx(INFO, "\t2.0 - DESFire Ev2, Originality check, proximity check, EAL5");
    if (major == 2 && minor == 2)
        PrintAndLogEx(INFO, "\t2.2 - DESFire Ev2 XL, Originality check, proximity check, EAL5");

    if (major == 3 && minor == 0)
        PrintAndLogEx(INFO, "\t3.0 - DESFire Ev3, Originality check, proximity check, badass EAL6");

    if (major == 0xA0 && minor == 0)
        PrintAndLogEx(INFO, "\tx.x - DUOX, Originality check, proximity check, EAL6++");


    DesfireContext_t dctx = {0};
    dctx.commMode = DCMPlain;
    dctx.cmdSet = DCCNative;

    res = DesfireAnticollision(false);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    if (cardtype == DESFIRE_EV2 ||  cardtype == DESFIRE_EV2_XL ||
            cardtype == DESFIRE_LIGHT ||
            cardtype == DESFIRE_EV3 ||
            cardtype == NTAG413DNA ||
            cardtype == DUOX) {
        // Signature originality check
        uint8_t signature[250] = {0}; // must be 56
        size_t signature_len = 0;

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "--- " _CYAN_("Tag Signature"));
        res = DesfireReadSignature(&dctx, 0x00, signature, &signature_len);
        if (res == PM3_SUCCESS) {
            if (signature_len == 56)
                desfire_print_signature(info.uid, info.uidlen, signature, signature_len);
            else
                PrintAndLogEx(WARNING, "--- GetSignature returned wrong signature length: %zu", signature_len);
        } else {
            PrintAndLogEx(WARNING, "--- Card doesn't support GetSignature cmd");
        }
    }

    PICCInfo_t PICCInfo = {0};

    uint8_t aidbuf[250] = {0};
    size_t aidbuflen = 0;
    res = DesfireGetAIDList(&dctx, aidbuf, &aidbuflen);
    if (res == PM3_SUCCESS) {
        PICCInfo.appCount = aidbuflen / 3;
    }

    if (aidbuflen > 2) {

        uint8_t j = (aidbuflen / 3);
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(SUCCESS, "--- " _CYAN_("AID list")  " ( " _YELLOW_("%u") " found )", j);

        j = 0;
        for (int i = 0; i < aidbuflen; i += 3, j++) {
            uint32_t aid = DesfireAIDByteToUint(&aidbuf[i]);
            PrintAndLogEx(SUCCESS, _YELLOW_("%06X") ", %s", aid, getAidCommentStr(aid));
        }
        PrintAndLogEx(NORMAL, "");
    }

    DesfireFillPICCInfo(&dctx, &PICCInfo, true);
    DesfirePrintPICCInfo(&dctx, &PICCInfo);

    if (cardtype != DESFIRE_LIGHT) {
        // Free memory on card
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "--- " _CYAN_("Free memory"));
        if (PICCInfo.freemem != 0xffffffff) {
            PrintAndLogEx(SUCCESS, "   Available free memory on card... " _GREEN_("%d") " bytes", PICCInfo.freemem);
        } else {
            PrintAndLogEx(SUCCESS, "   Card doesn't support 'free mem' cmd");
        }
    }

    if (cardtype == DESFIRE_LIGHT) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "--- " _CYAN_("Desfire Light info"));

        if (DesfireSelect(&dctx, ISWIsoID, 0xdf01, NULL) == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "   Card have " _GREEN_("default (0xdf01)") " iso id for application");

            if (DesfireCheckAuthCmd(ISWIsoID, 0xdf01, 0, MFDES_AUTHENTICATE_EV2F, false)) {
                PrintAndLogEx(SUCCESS, "   Card in the " _GREEN_("AES") " mode");
            } else if (DesfireCheckAuthCmd(ISWIsoID, 0xdf01, 0, MFDES_AUTHENTICATE_EV2F, true)) {
                PrintAndLogEx(SUCCESS, "   Card in the " _GREEN_("LRP") " mode");
            }
        } else {
            PrintAndLogEx(SUCCESS, "   Card have " _RED_("not a default") " iso id for application");
        }

        if (DesfireCheckAuthCmd(ISWIsoID, 0x3f00, 1, MFDES_AUTHENTICATE_EV2F, true)) {
            PrintAndLogEx(SUCCESS, "   Card have " _GREEN_("LRP") " key in the MF/key1");
        }
    }

    PrintAndLogEx(NORMAL, "");

    iso14a_card_select_t card;
    res = SelectCard14443A_4(true, false, &card);
    if (res == PM3_SUCCESS) {

        if (card.sak == 0x20) {

            static const uint8_t STANDALONE_DESFIRE[] = { 0x75, 0x77, 0x81, 0x02 };
            static const uint8_t JCOP_DESFIRE[] = { 0x75, 0xf7, 0xb1, 0x02 };
            static const uint8_t JCOP3_DESFIRE[] = { 0x78, 0x77, 0x71, 0x02 };

            if (card.ats_len >= 5) {
                if (0 == memcmp(card.ats + 1, STANDALONE_DESFIRE, 4)) {
                    PrintAndLogEx(INFO, "Standalone DESFire");
                }
                if (0 == memcmp(card.ats + 1, JCOP_DESFIRE, 4)) {
                    PrintAndLogEx(INFO, "JCOP DESFire");
                }
            }
            if (card.ats_len == 4) {
                if (0 == memcmp(card.ats + 1, JCOP3_DESFIRE, 4)) {
                    PrintAndLogEx(INFO, "JCOP3 DESFire");
                }
            }
        }
    }

    /*
        Card Master key (CMK)        0x00 AID = 00 00 00 (card level)
        Application Master Key (AMK) 0x00 AID != 00 00 00
        Application keys (APK)       0x01-0x0D
        Application free             0x0E
        Application never            0x0F

        ACCESS RIGHTS:
        keys 0,1,2,3     C
        keys 4,5,6,7     RW
        keys 8,9,10,11   W
        keys 12,13,14,15 R

    */

    DropField();
    return PM3_SUCCESS;
}

static void DesFill2bPattern(
    uint8_t deskeyList[MAX_KEYS_LIST_LEN][8], uint32_t *deskeyListLen,
    uint8_t aeskeyList[MAX_KEYS_LIST_LEN][16], uint32_t *aeskeyListLen,
    uint8_t k3kkeyList[MAX_KEYS_LIST_LEN][24], uint32_t *k3kkeyListLen, uint32_t *startPattern) {

    for (uint32_t pt = *startPattern; pt < 0x10000; pt++) {
        if (*deskeyListLen != MAX_KEYS_LIST_LEN) {
            deskeyList[*deskeyListLen][0] = (pt >> 8) & 0xff;
            deskeyList[*deskeyListLen][1] = pt & 0xff;
            memcpy(&deskeyList[*deskeyListLen][2], &deskeyList[*deskeyListLen][0], 2);
            memcpy(&deskeyList[*deskeyListLen][4], &deskeyList[*deskeyListLen][0], 4);
            (*deskeyListLen)++;
        }
        if (*aeskeyListLen != MAX_KEYS_LIST_LEN) {
            aeskeyList[*aeskeyListLen][0] = (pt >> 8) & 0xff;
            aeskeyList[*aeskeyListLen][1] = pt & 0xff;
            memcpy(&aeskeyList[*aeskeyListLen][2], &aeskeyList[*aeskeyListLen][0], 2);
            memcpy(&aeskeyList[*aeskeyListLen][4], &aeskeyList[*aeskeyListLen][0], 4);
            memcpy(&aeskeyList[*aeskeyListLen][8], &aeskeyList[*aeskeyListLen][0], 8);
            (*aeskeyListLen)++;
        }
        if (*k3kkeyListLen != MAX_KEYS_LIST_LEN) {
            k3kkeyList[*k3kkeyListLen][0] = (pt >> 8) & 0xff;
            k3kkeyList[*k3kkeyListLen][1] = pt & 0xff;
            memcpy(&k3kkeyList[*k3kkeyListLen][2], &k3kkeyList[*k3kkeyListLen][0], 2);
            memcpy(&k3kkeyList[*k3kkeyListLen][4], &k3kkeyList[*k3kkeyListLen][0], 4);
            memcpy(&k3kkeyList[*k3kkeyListLen][8], &k3kkeyList[*k3kkeyListLen][0], 8);
            memcpy(&k3kkeyList[*k3kkeyListLen][16], &k3kkeyList[*k3kkeyListLen][0], 4);
            (*k3kkeyListLen)++;
        }

        *startPattern = pt;
        if ((*deskeyListLen == MAX_KEYS_LIST_LEN) &&
                (*aeskeyListLen == MAX_KEYS_LIST_LEN) &&
                (*k3kkeyListLen == MAX_KEYS_LIST_LEN)) {
            break;
        }
    }
    (*startPattern)++;
}

static int AuthCheckDesfire(DesfireContext_t *dctx,
                            DesfireSecureChannel secureChannel,
                            const uint8_t *aid,
                            uint8_t deskeyList[MAX_KEYS_LIST_LEN][8], uint32_t deskeyListLen,
                            uint8_t aeskeyList[MAX_KEYS_LIST_LEN][16], uint32_t aeskeyListLen,
                            uint8_t k3kkeyList[MAX_KEYS_LIST_LEN][24], uint32_t k3kkeyListLen,
                            uint8_t cmdKdfAlgo, uint8_t kdfInputLen, uint8_t *kdfInput,
                            uint8_t foundKeys[4][0xE][24 + 1],
                            bool *result,
                            bool verbose) {

    uint32_t curaid = (aid[0] & 0xFF) + ((aid[1] & 0xFF) << 8) + ((aid[2] & 0xFF) << 16);

    int res = DesfireSelectAIDHex(dctx, curaid, false, 0);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "AID 0x%06X does not exist.", curaid);
        DropField();
        return PM3_ESOFT;
    }

    int usedkeys[0xF] = {0};
    bool des = false;
    bool tdes = false;
    bool aes = false;
    bool k3kdes = false;

    uint8_t data[250] = {0};
    size_t datalen = 0;

    res = DesfireGetKeySettings(dctx, data, &datalen);
    if (res != PM3_SUCCESS && datalen < 2) {
        PrintAndLogEx(ERR, "Could not get key settings");
        return res;
    }
    uint8_t num_keys = data[1];
    switch (num_keys >> 6) {
        case 0:
            des = true;
            tdes = true;
            break;
        case 1:
            k3kdes = true;
            break;
        case 2:
            aes = true;
            break;
        default:
            break;
    }

    // always check master key
    usedkeys[0] = 1;

    if (curaid != 0) {
        FileList_t fileList = {{0}};
        size_t filescount = 0;
        bool isopresent = 0;
        res = DesfireFillFileList(dctx, fileList, &filescount, &isopresent);
        if (res == PM3_SUCCESS) {
            if (filescount > 0) {
                for (int i = 0; i < filescount; i++) {
                    if (fileList[i].fileSettings.rAccess < 0x0e)
                        usedkeys[fileList[i].fileSettings.rAccess] = 1;
                    if (fileList[i].fileSettings.wAccess < 0x0e)
                        usedkeys[fileList[i].fileSettings.wAccess] = 1;
                    if (fileList[i].fileSettings.rwAccess < 0x0e)
                        usedkeys[fileList[i].fileSettings.rwAccess] = 1;
                    if (fileList[i].fileSettings.chAccess < 0x0e)
                        usedkeys[fileList[i].fileSettings.chAccess] = 1;
                }
            } else {
                for (int i = 0; i < 0xE; i++)
                    usedkeys[i] = 1;
            }
        } else {
            for (int i = 0; i < 0xE; i++)
                usedkeys[i] = 1;
        }
    }

    if (verbose) {
        PrintAndLogEx(INFO, "Check: %s %s %s %s " NOLF, (des) ? "DES" : "", (tdes) ? "2TDEA" : "", (k3kdes) ? "3TDEA" : "", (aes) ? "AES" : "");
        PrintAndLogEx(NORMAL, "keys: " NOLF);
        for (int i = 0; i < 0xE; i++)
            if (usedkeys[i] == 1)
                PrintAndLogEx(NORMAL, "%02x " NOLF, i);
        PrintAndLogEx(NORMAL, "");
    }

    bool badlen = false;

    if (des) {

        for (uint8_t keyno = 0; keyno < 0xE; keyno++) {

            if (usedkeys[keyno] == 1 && foundKeys[0][keyno][0] == 0) {
                for (uint32_t curkey = 0; curkey < deskeyListLen; curkey++) {
                    DesfireSetKeyNoClear(dctx, keyno, T_DES, deskeyList[curkey]);
                    res = DesfireAuthenticate(dctx, secureChannel, false);
                    if (res == PM3_SUCCESS) {
                        PrintAndLogEx(SUCCESS, "AID 0x%06X, Found DES Key %02u... " _GREEN_("%s"), curaid, keyno, sprint_hex(deskeyList[curkey], 8));
                        foundKeys[0][keyno][0] = 0x01;
                        *result = true;
                        memcpy(&foundKeys[0][keyno][1], deskeyList[curkey], 8);
                        break;
                    } else if (res < 7) {
                        badlen = true;
                        DropField();
                        res = DesfireSelectAIDHex(dctx, curaid, false, 0);
                        if (res != PM3_SUCCESS) {
                            return res;
                        }
                        break;
                    }
                }
                if (badlen == true) {
                    badlen = false;
                    break;
                }
            }
        }
    }

    if (tdes) {

        for (uint8_t keyno = 0; keyno < 0xE; keyno++) {

            if (usedkeys[keyno] == 1 && foundKeys[1][keyno][0] == 0) {
                for (uint32_t curkey = 0; curkey < aeskeyListLen; curkey++) {
                    DesfireSetKeyNoClear(dctx, keyno, T_3DES, aeskeyList[curkey]);
                    res = DesfireAuthenticate(dctx, secureChannel, false);
                    if (res == PM3_SUCCESS) {
                        PrintAndLogEx(SUCCESS, "AID 0x%06X, Found 2TDEA Key %02u... " _GREEN_("%s"), curaid, keyno, sprint_hex_inrow(aeskeyList[curkey], 16));
                        foundKeys[1][keyno][0] = 0x01;
                        *result = true;
                        memcpy(&foundKeys[1][keyno][1], aeskeyList[curkey], 16);
                        break;
                    } else if (res < 7) {
                        badlen = true;
                        DropField();
                        res = DesfireSelectAIDHex(dctx, curaid, false, 0);
                        if (res != PM3_SUCCESS) {
                            return res;
                        }
                        break;
                    }
                }
                if (badlen == true) {
                    badlen = false;
                    break;
                }
            }
        }
    }

    if (aes) {

        for (uint8_t keyno = 0; keyno < 0xE; keyno++) {

            if (usedkeys[keyno] == 1 && foundKeys[2][keyno][0] == 0) {
                for (uint32_t curkey = 0; curkey < aeskeyListLen; curkey++) {
                    DesfireSetKeyNoClear(dctx, keyno, T_AES, aeskeyList[curkey]);
                    res = DesfireAuthenticate(dctx, secureChannel, false);
                    if (res == PM3_SUCCESS) {
                        PrintAndLogEx(SUCCESS, "AID 0x%06X, Found AES Key %02u... " _GREEN_("%s"), curaid, keyno, sprint_hex_inrow(aeskeyList[curkey], 16));
                        foundKeys[2][keyno][0] = 0x01;
                        *result = true;
                        memcpy(&foundKeys[2][keyno][1], aeskeyList[curkey], 16);
                        break;
                    } else if (res < 7) {
                        badlen = true;
                        DropField();
                        res = DesfireSelectAIDHex(dctx, curaid, false, 0);
                        if (res != PM3_SUCCESS) {
                            return res;
                        }
                        break;
                    }
                }
                if (badlen == true) {
                    badlen = false;
                    break;
                }
            }
        }
    }

    if (k3kdes) {

        for (uint8_t keyno = 0; keyno < 0xE; keyno++) {

            if (usedkeys[keyno] == 1 && foundKeys[3][keyno][0] == 0) {
                for (uint32_t curkey = 0; curkey < k3kkeyListLen; curkey++) {
                    DesfireSetKeyNoClear(dctx, keyno, T_3K3DES, k3kkeyList[curkey]);
                    res = DesfireAuthenticate(dctx, secureChannel, false);
                    if (res == PM3_SUCCESS) {
                        PrintAndLogEx(SUCCESS, "AID 0x%06X, Found 3TDEA Key %02u... " _GREEN_("%s"), curaid, keyno, sprint_hex_inrow(k3kkeyList[curkey], 24));
                        foundKeys[3][keyno][0] = 0x01;
                        *result = true;
                        memcpy(&foundKeys[3][keyno][1], k3kkeyList[curkey], 16);
                        break;
                    } else if (res < 7) {
                        badlen = true;
                        DropField();
                        res = DesfireSelectAIDHex(dctx, curaid, false, 0);
                        if (res != PM3_SUCCESS) {
                            return res;
                        }
                        break;
                    }
                }

                if (badlen == true) {
                    break;
                }
            }
        }
    }
    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14aDesChk(const char *Cmd) {
    int res;
    uint8_t deskeyList[MAX_KEYS_LIST_LEN][8] = {{0}};
    uint8_t aeskeyList[MAX_KEYS_LIST_LEN][16] = {{0}};
    uint8_t k3kkeyList[MAX_KEYS_LIST_LEN][MAX_KEY_LEN] = {{0}};
    uint32_t deskeyListLen = 0;
    uint32_t aeskeyListLen = 0;
    uint32_t k3kkeyListLen = 0;
    uint8_t foundKeys[4][0xE][24 + 1] = {{{0}}};

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes chk",
                  "Checks keys with MIFARE DESFire card.",
                  "hf mfdes chk --aid 123456 -k 000102030405060708090a0b0c0d0e0f  -> check key on aid 0x123456\n"
                  "hf mfdes chk -f mfdes_default_keys                     -> check keys against all existing aid on card\n"
                  "hf mfdes chk -f mfdes_default_keys --aid 123456        -> check keys against aid 0x123456\n"
                  "hf mfdes chk --aid 123456 --pattern1b -j keys          -> check all 1-byte keys pattern on aid 0x123456 and save found keys to `keys.json`\n"
                  "hf mfdes chk --aid 123456 --pattern2b --startp2b FA00  -> check all 2-byte keys pattern on aid 0x123456. Start from key FA00FA00...FA00");

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "aid",        "<hex>", "Use specific AID (3 hex bytes, big endian)"),
        arg_str0("k",  "key",        "<hex>", "Key for checking (HEX 16 bytes)"),
        arg_str0("f", "file",        "<fn>",  "Filename of dictionary"),
        arg_lit0(NULL, "pattern1b",  "Check all 1-byte combinations of key (0000...0000, 0101...0101, 0202...0202, ...)"),
        arg_lit0(NULL, "pattern2b",  "Check all 2-byte combinations of key (0000...0000, 0001...0001, 0002...0002, ...)"),
        arg_str0(NULL, "startp2b",   "<pattern>", "Start key (2-byte HEX) for 2-byte search (use with `--pattern2b`)"),
        arg_str0("j",  "json",       "<fn>",  "Json file name to save keys"),
        arg_lit0("v",  "verbose",    "Verbose output"),
        arg_int0(NULL, "kdf",        "<0|1|2>", "Key Derivation Function (KDF) (0=None, 1=AN10922, 2=Gallagher)"),
        arg_str0("i",  "kdfi",       "<hex>", "KDF input (1-31 hex bytes)"),
        arg_lit0("a",  "apdu",       "Show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int aidlength = 0;
    uint8_t aid[3] = {0};
    CLIGetHexWithReturn(ctx, 1, aid, &aidlength);

    swap24(aid);

    uint8_t vkey[16] = {0};
    int vkeylen = 0;
    CLIGetHexWithReturn(ctx, 2, vkey, &vkeylen);

    if (vkeylen > 0) {
        if (vkeylen == 8) {
            memcpy(&deskeyList[deskeyListLen], vkey, 8);
            deskeyListLen++;
        } else if (vkeylen == 16) {
            memcpy(&aeskeyList[aeskeyListLen], vkey, 16);
            aeskeyListLen++;
        } else if (vkeylen == 24) {
            memcpy(&k3kkeyList[k3kkeyListLen], vkey, 16);
            k3kkeyListLen++;
        } else {
            PrintAndLogEx(ERR, "Specified key must have 8, 16 or 24 bytes length.");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }

    uint8_t dict_filename[FILE_PATH_SIZE + 2] = {0};
    int dict_filenamelen = 0;
    if (CLIParamStrToBuf(arg_get_str(ctx, 3), dict_filename, FILE_PATH_SIZE, &dict_filenamelen)) {
        PrintAndLogEx(FAILED, "File name too long or invalid.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool pattern1b = arg_get_lit(ctx, 4);
    bool pattern2b = arg_get_lit(ctx, 5);

    if (pattern1b && pattern2b) {
        PrintAndLogEx(ERR, "Pattern search mode must be 2-byte or 1-byte only.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    if (dict_filenamelen && (pattern1b || pattern2b)) {
        PrintAndLogEx(ERR, "Pattern search mode and dictionary mode can't be used in one command.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t startPattern = 0x0000;
    uint8_t vpattern[2];
    int vpatternlen = 0;
    CLIGetHexWithReturn(ctx, 6, vpattern, &vpatternlen);
    if (vpatternlen > 0) {
        if (vpatternlen <= 2) {
            startPattern = (vpattern[0] << 8) + vpattern[1];
        } else {
            PrintAndLogEx(ERR, "Pattern must be 2-byte length.");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
        if (!pattern2b)
            PrintAndLogEx(WARNING, "Pattern entered, but search mode not is 2-byte search.");
    }

    uint8_t jsonname[250] = {0};
    int jsonnamelen = 0;
    if (CLIParamStrToBuf(arg_get_str(ctx, 7), jsonname, sizeof(jsonname), &jsonnamelen)) {
        PrintAndLogEx(ERR, "Invalid json name.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    jsonname[jsonnamelen] = 0;

    bool verbose = arg_get_lit(ctx, 8);

    // Get KDF input
    uint8_t cmdKDFAlgo  = arg_get_int_def(ctx, 9, 0);

    uint8_t kdfInput[31] = {0};
    int kdfInputLen = 0;
    CLIGetHexWithReturn(ctx, 10, kdfInput, &kdfInputLen);

    bool APDULogging = arg_get_lit(ctx, 11);

    CLIParserFree(ctx);
    SetAPDULogging(APDULogging);

    // 1-byte pattern search mode
    if (pattern1b) {

        for (uint32_t i = 0; i < 0x100; i++) {
            memset(aeskeyList[i], i, 16);
        }

        for (uint32_t i = 0; i < 0x100; i++) {
            memset(deskeyList[i], i, 8);
        }

        for (uint32_t i = 0; i < 0x100; i++) {
            memset(k3kkeyList[i], i, 24);
        }

        aeskeyListLen = 0x100;
        deskeyListLen = 0x100;
        k3kkeyListLen = 0x100;
    }

    // 2-byte pattern search mode
    if (pattern2b) {
        DesFill2bPattern(deskeyList, &deskeyListLen, aeskeyList, &aeskeyListLen, k3kkeyList, &k3kkeyListLen, &startPattern);
    }

    // dictionary mode
    size_t endFilePosition = 0;
    if (dict_filenamelen) {

        res = loadFileDICTIONARYEx((char *)dict_filename, deskeyList, sizeof(deskeyList), NULL, 8, &deskeyListLen, 0, &endFilePosition, true);
        if (res == PM3_SUCCESS && endFilePosition) {
            PrintAndLogEx(SUCCESS, "First part of des dictionary successfully loaded.");
        }

        endFilePosition = 0;
        res = loadFileDICTIONARYEx((char *)dict_filename, aeskeyList, sizeof(aeskeyList), NULL, 16, &aeskeyListLen, 0, &endFilePosition, true);
        if (res == PM3_SUCCESS && endFilePosition) {
            PrintAndLogEx(SUCCESS, "First part of aes dictionary successfully loaded.");
        }

        endFilePosition = 0;
        res = loadFileDICTIONARYEx((char *)dict_filename, k3kkeyList, sizeof(k3kkeyList), NULL, 24, &k3kkeyListLen, 0, &endFilePosition, true);
        if (res == PM3_SUCCESS && endFilePosition) {
            PrintAndLogEx(SUCCESS, "First part of k3kdes dictionary successfully loaded.");
        }

        endFilePosition = 0;
    }

    if (aeskeyListLen == 0 && deskeyListLen == 0 && k3kkeyListLen == 0) {
        PrintAndLogEx(ERR, "No keys provided. Nothing to check.");
        return PM3_EINVARG;
    }

    if (aeskeyListLen != 0) {
        PrintAndLogEx(INFO, "Loaded " _YELLOW_("%"PRIu32) " aes keys", aeskeyListLen);
    }

    if (deskeyListLen != 0) {
        PrintAndLogEx(INFO, "Loaded "  _YELLOW_("%"PRIu32) " des keys", deskeyListLen);
    }

    if (k3kkeyListLen != 0) {
        PrintAndLogEx(INFO, "Loaded " _YELLOW_("%"PRIu32) " k3kdes keys", k3kkeyListLen);
    }

    if (verbose == false) {
        PrintAndLogEx(INFO, "Search keys:");
    }

    bool result = false;
    uint8_t app_ids[78] = {0};
    size_t app_ids_len = 0;

    clearCommandBuffer();

    DesfireContext_t dctx = {0};
    DesfireSetKdf(&dctx, cmdKDFAlgo, kdfInput, kdfInputLen);
    DesfireSetCommandSet(&dctx, DCCNativeISO);
    DesfireSetCommMode(&dctx, DCMPlain);
    DesfireSecureChannel secureChannel = DACEV1;

    // save card UID to dctx
    DesfireGetCardUID(&dctx);

    res = DesfireSelectAIDHex(&dctx, 0x000000, false, 0);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Can't select PICC level.");
        DropField();
        return PM3_ESOFT;
    }


    res = DesfireGetAIDList(&dctx, app_ids, &app_ids_len);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Can't get list of applications on tag");
        DropField();
        return PM3_ESOFT;
    }

    if (aidlength != 0) {
        memcpy(&app_ids[0], aid, 3);
        app_ids_len = 3;
    }

    for (uint32_t x = 0; x < app_ids_len / 3; x++) {

        uint32_t curaid = (app_ids[x * 3] & 0xFF) + ((app_ids[(x * 3) + 1] & 0xFF) << 8) + ((app_ids[(x * 3) + 2] & 0xFF) << 16);
        PrintAndLogEx(ERR, "Checking aid 0x%06X...", curaid);

        res = AuthCheckDesfire(&dctx, secureChannel, &app_ids[x * 3], deskeyList, deskeyListLen, aeskeyList, aeskeyListLen, k3kkeyList, k3kkeyListLen, cmdKDFAlgo, kdfInputLen, kdfInput, foundKeys, &result, (verbose == false));
        if (res == PM3_EOPABORTED) {
            break;
        }

        if (pattern2b && startPattern < 0x10000) {
            if (verbose == false) {
                PrintAndLogEx(NORMAL, "p" NOLF);
            }

            aeskeyListLen = 0;
            deskeyListLen = 0;
            k3kkeyListLen = 0;
            DesFill2bPattern(deskeyList, &deskeyListLen, aeskeyList, &aeskeyListLen, k3kkeyList, &k3kkeyListLen, &startPattern);
            continue;
        }

        if (dict_filenamelen) {
            if (verbose == false) {
                PrintAndLogEx(NORMAL, "d" NOLF);
            }

            uint32_t keycnt = 0;
            res = loadFileDICTIONARYEx((char *)dict_filename, deskeyList, sizeof(deskeyList), NULL, 16, &keycnt, endFilePosition, &endFilePosition, false);
            if (res == PM3_SUCCESS && endFilePosition) {
                deskeyListLen = keycnt;
            }

            keycnt = 0;
            res = loadFileDICTIONARYEx((char *)dict_filename, aeskeyList, sizeof(aeskeyList), NULL, 16, &keycnt, endFilePosition, &endFilePosition, false);
            if (res == PM3_SUCCESS && endFilePosition) {
                aeskeyListLen = keycnt;
            }

            keycnt = 0;
            res = loadFileDICTIONARYEx((char *)dict_filename, k3kkeyList, sizeof(k3kkeyList), NULL, 16, &keycnt, endFilePosition, &endFilePosition, false);
            if (res == PM3_SUCCESS && endFilePosition) {
                k3kkeyListLen = keycnt;
            }

            continue;
        }
    }
    if (verbose == false) {
        PrintAndLogEx(NORMAL, "");
    }

    // save keys to json
    if ((jsonnamelen > 0) && result) {
        DropField();
        // MIFARE DESFire info
        SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_CLEARTRACE, 0, 0, NULL, 0);
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_ACK, &resp, 2500) == false) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply");
            return PM3_ETIMEOUT;
        }

        iso14a_card_select_t card;
        memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

        uint64_t select_status = resp.oldarg[0]; // 0: couldn't read, 1: OK, with ATS, 2: OK, no ATS, 3: proprietary Anticollision

        uint8_t data[10 + 1 + 2 + 1 + 256 + (4 * 0xE * (24 + 1))] = {0};
        uint8_t atslen = 0;
        if (select_status == 1 || select_status == 2) {
            memcpy(data, card.uid, card.uidlen);
            data[10] = card.sak;
            data[11] = card.atqa[1];
            data[12] = card.atqa[0];
            atslen = card.ats_len;
            data[13] = atslen;
            memcpy(&data[14], card.ats, atslen);
        }

        // length: UID(10b)+SAK(1b)+ATQA(2b)+ATSlen(1b)+ATS(atslen)+foundKeys[2][64][AES_KEY_LEN + 1]
        memcpy(&data[14 + atslen], foundKeys, 4 * 0xE * (24 + 1));
        saveFileJSON((char *)jsonname, jsfMfDesfireKeys, data, 0xE, NULL);
    }

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf mfdes", "des -c");
}

static int DesfireAuthCheck(DesfireContext_t *dctx, DesfireISOSelectWay way, uint32_t appID, DesfireSecureChannel secureChannel, uint8_t *key) {
    DesfireSetKeyNoClear(dctx, dctx->keyNum, dctx->keyType, key);

    int res = DesfireAuthenticate(dctx, secureChannel, false);
    if (res == PM3_SUCCESS) {
        memcpy(dctx->key, key, desfire_get_key_length(dctx->keyType));
        return PM3_SUCCESS;
    } else if (res < 7) {
        DropField();
        res = DesfireSelect(dctx, way, appID, NULL);
        if (res != PM3_SUCCESS) {
            return -10;
        }
        return -11;
    }
    return -1;
}


static int CmdHF14aDesDetect(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes detect",
                  "Detect key type and tries to find one from the list.",
                  "hf mfdes detect                            -> detect key 0 from PICC level\n"
                  "hf mfdes detect --schann d40               -> detect key 0 from PICC level via secure channel D40\n"
                  "hf mfdes detect -f mfdes_default_keys      -> detect key 0 from PICC level with help of the standard dictionary\n"
                  "hf mfdes detect --aid 123456 -n 2 --save   -> detect key 2 from app 123456 and if succeed - save params to defaults (`default` command)\n"
                  "hf mfdes detect --isoid df01 --save        -> detect key 0 and save to defaults with card in the LRP mode");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>", "Crypt algo"),
        arg_str0("k",  "key",     "<hex>", "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>", "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>", "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "isoid",   "<hex>", "Application ISO ID (ISO DF ID) (2 hex bytes, big endian)."),
        arg_str0(NULL, "dfname",  "<hex>", "Application ISO DF Name (5-16 hex bytes, big endian)"),
        arg_str0("f", "file",     "<fn>",  "Filename of dictionary"),
        arg_lit0(NULL, "save",    "Save found key and parameters to defaults"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t id = 0x000000;
    DesfireISOSelectWay selectway = ISW6bAID;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, &securechann, DCMMACed, &id, &selectway);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint8_t dict_filename[FILE_PATH_SIZE + 2] = {0};
    int dict_filenamelen = 0;
    if (CLIParamStrToBuf(arg_get_str(ctx, 14), dict_filename, FILE_PATH_SIZE, &dict_filenamelen)) {
        PrintAndLogEx(FAILED, "File name too long or invalid.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool save = arg_get_lit(ctx, 15);

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    // no auth and fill KDF if needs
    res = DesfireSelectAndAuthenticateAppW(&dctx, securechann, selectway, id, true, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(FAILED, "Select or authentication %s " _RED_("failed") ". Result [%d] %s", DesfireWayIDStr(selectway, id), res, DesfireAuthErrorToStr(res));
        return res;
    }

    bool keytypes[4] = {0};
    bool uselrp = false;

    uint8_t data[250] = {0};
    size_t datalen = 0;

    res = DesfireGetKeySettings(&dctx, data, &datalen);
    if (res == PM3_SUCCESS && datalen >= 2) {

        uint8_t num_keys = data[1];

        switch (num_keys >> 6) {
            case 0: {
                keytypes[T_DES] = true;
                keytypes[T_3DES] = true;
                break;
            }
            case 1: {
                keytypes[T_3K3DES] = true;
                break;
            }
            case 2: {
                keytypes[T_AES] = true;
                break;
            }
            default: {
                break;
            }
        }

    } else {
        // if fail - check auth commands
        AuthCommandsChk_t authCmdCheck = {0};
        DesfireCheckAuthCommands(selectway, id, NULL, 0, &authCmdCheck);

        if (authCmdCheck.checked) {

            if (authCmdCheck.auth) {
                keytypes[T_DES] = true;
                keytypes[T_3DES] = true;

                if (authCmdCheck.authISO) {
                    keytypes[T_3K3DES] = true;
                }
            }

            if (authCmdCheck.authAES || authCmdCheck.authEV2) {
                keytypes[T_AES] = true;
            }

            if (authCmdCheck.authLRP) {
                keytypes[T_AES] = true;
                uselrp = true;
                securechann = DACLRP;
            }

        } else {
            // if nothing helps - we check DES only
            keytypes[T_DES] = true;
        }

        res = DesfireSelectAndAuthenticateAppW(&dctx, securechann, selectway, id, true, verbose);
        if (res != PM3_SUCCESS) {
            DropField();
            PrintAndLogEx(FAILED, "Select or authentication %s " _RED_("failed") ". Result [%d] %s", DesfireWayIDStr(selectway, id), res, DesfireAuthErrorToStr(res));
            return res;
        }
    }

    if (verbose) {

        if (DesfireMFSelected(selectway, id)) {
            PrintAndLogEx(INFO, "Check PICC key num: %d (0x%02x)", dctx.keyNum, dctx.keyNum);
        } else {
            PrintAndLogEx(INFO, "Check: %s key num: %d (0x%02x)", DesfireWayIDStr(selectway, id), dctx.keyNum, dctx.keyNum);
        }

        PrintAndLogEx(INFO, "keys: DES: %s 2TDEA: %s 3TDEA: %s AES: %s LRP: %s",
                      keytypes[T_DES] ? _GREEN_("YES") : _RED_("NO"),
                      keytypes[T_3DES] ? _GREEN_("YES") : _RED_("NO"),
                      keytypes[T_3K3DES] ? _GREEN_("YES") : _RED_("NO"),
                      keytypes[T_AES] ? _GREEN_("YES") : _RED_("NO"),
                      uselrp ? _GREEN_("YES") : _RED_("NO")
                     );
    }

    // for key types
    bool found = false;
    size_t errcount = 0;
    for (uint8_t ktype = T_DES; ktype <= T_AES; ktype++) {

        if (keytypes[ktype] == false) {
            continue;
        }

        dctx.keyType = ktype;

        if (verbose) {
            PrintAndLogEx(INFO, "Scan key type: %s", CLIGetOptionListStr(DesfireAlgoOpts, dctx.keyType));
        }

        if (dict_filenamelen == 0) {
            // keys from mifaredefault.h
            for (int i = 0; i < g_mifare_plus_default_keys_len; i++) {

                uint8_t key[DESFIRE_MAX_KEY_SIZE] = {0};
                if (hex_to_bytes(g_mifare_plus_default_keys[i], key, 16) != 16) {
                    continue;
                }

                if (ktype == T_3K3DES) {
                    memcpy(&key[16], key, 8);
                }

                res = DesfireAuthCheck(&dctx, selectway, id, securechann, key);
                if (res == PM3_SUCCESS) {
                    found = true;
                    break; // all the params already in the dctx
                }

                if (res == -10) {

                    if (verbose) {
                        PrintAndLogEx(ERR, "Can't select AID. There is no connection with card.");
                    }

                    found = false;
                    break; // we can't select app after invalid 1st auth stages
                }

                if (res == -11) {

                    if (errcount > 10) {
                        if (verbose) {
                            PrintAndLogEx(ERR, "Too much errors (%zu) from card", errcount);
                        }
                        break;
                    }
                    errcount++;

                } else {
                    errcount = 0;
                }
            }

        } else {
            // keys from file
            uint8_t keyList[MAX_KEYS_LIST_LEN * MAX_KEY_LEN] = {0};
            uint32_t keyListLen = 0;
            size_t keylen = desfire_get_key_length(dctx.keyType);
            size_t endFilePosition = 0;

            while (found == false) {

                res = loadFileDICTIONARYEx((char *)dict_filename, keyList, sizeof(keyList), NULL, keylen, &keyListLen, endFilePosition, &endFilePosition, verbose);
                if (res != 1 && res != PM3_SUCCESS) {
                    break;
                }

                for (int i = 0; i < keyListLen; i++) {

                    res = DesfireAuthCheck(&dctx, selectway, id, securechann, &keyList[i * keylen]);
                    if (res == PM3_SUCCESS) {
                        found = true;
                        break; // all the params already in the dctx
                    }

                    if (res == -10) {
                        if (verbose) {
                            PrintAndLogEx(ERR, "Can't select AID. There is no connection with card.");
                        }

                        found = false;
                        break; // we can't select app after invalid 1st auth stages
                    }

                    if (res == -11) {

                        if (errcount > 10) {
                            if (verbose) {
                                PrintAndLogEx(ERR, "Too much errors (%zu) from card", errcount);
                            }
                            break;
                        }
                        errcount++;

                    } else {
                        errcount = 0;
                    }

                }

                if (endFilePosition == 0) {
                    break;
                }
            }

        }

        if (found) {
            break;
        }
    }

    if (found) {

        if (DesfireMFSelected(selectway, id)) {
            PrintAndLogEx(INFO, _GREEN_("Found") " key num: %d (0x%02x)", dctx.keyNum, dctx.keyNum);
        } else {
            PrintAndLogEx(INFO, "Found key for: %s key num: %d (0x%02x)", DesfireWayIDStr(selectway, id), dctx.keyNum, dctx.keyNum);
        }

        PrintAndLogEx(INFO, "channel " _GREEN_("%s") " key " _GREEN_("%s") " [%d]: " _GREEN_("%s"),
                      CLIGetOptionListStr(DesfireSecureChannelOpts, securechann),
                      CLIGetOptionListStr(DesfireAlgoOpts, dctx.keyType),
                      desfire_get_key_length(dctx.keyType),
                      sprint_hex(dctx.key, desfire_get_key_length(dctx.keyType)));

    } else {
        PrintAndLogEx(INFO, "Key " _RED_("not found"));
    }

    DropField();

    if (found && save) {

        defaultKeyNum = dctx.keyNum;
        defaultAlgoId = dctx.keyType;
        memcpy(defaultKey, dctx.key, DESFIRE_MAX_KEY_SIZE);
        defaultKdfAlgo = dctx.kdfAlgo;
        defaultKdfInputLen = dctx.kdfInputLen;
        memcpy(defaultKdfInput, dctx.kdfInput, sizeof(dctx.kdfInput));
        defaultSecureChannel = securechann;
        defaultCommSet = dctx.cmdSet;

        PrintAndLogEx(INFO, "-----------" _CYAN_("Default parameters") "---------------------------------");
        PrintAndLogEx(INFO, "Key Num....... %d", defaultKeyNum);
        PrintAndLogEx(INFO, "Algo.......... %s", CLIGetOptionListStr(DesfireAlgoOpts, defaultAlgoId));
        PrintAndLogEx(INFO, "Key........... %s", sprint_hex(defaultKey, desfire_get_key_length(defaultAlgoId)));
        PrintAndLogEx(INFO, "KDF algo...... %s", CLIGetOptionListStr(DesfireKDFAlgoOpts, defaultKdfAlgo));
        PrintAndLogEx(INFO, "KDF input..... [%d] %s", defaultKdfInputLen, sprint_hex(defaultKdfInput, defaultKdfInputLen));
        PrintAndLogEx(INFO, "Secure chan... %s", CLIGetOptionListStr(DesfireSecureChannelOpts, defaultSecureChannel));
        PrintAndLogEx(INFO, "Command set... %s", CLIGetOptionListStr(DesfireCommandSetOpts, defaultCommSet));
        PrintAndLogEx(INFO, "Parameters saved to in-memory ( %s )", _GREEN_("ok"));
    }
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

// https://www.nxp.com/docs/en/application-note/AN10787.pdf
// MIFARE Application Directory (MAD)
// test cardholder data 0a53616d706c656d616e00475068696c697000826d00d054656c2b312f313233342f3536373800
static int CmdHF14aDesMAD(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes mad",
                  "Reads and prints MIFARE Application directory (MAD).",
                  "MAD consists of one file with issuer info (AID ffffff) and several files with AID in the special format `faaaav` (a - MAD ID, v - multiple AID over one MAD ID)\n"
                  "The MIFARE DESFire Card Master Key settings have to allow the MIFARE DESFire command GetApplicationIDs without authentication (from datasheet)\n"
                  "\n"
                  "hf mfdes mad      -> shows MAD data\n"
                  "hf mfdes mad -v   -> shows MAD parsed and raw data\n"
                  "hf mfdes mad -a e103 -k d3f7d3f7d3f7d3f7d3f7d3f7d3f7d3f7 -> shows MAD data with custom AID and key");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>", "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID of issuer info file, (3 hex bytes, big endian),  (non-standard feature!)"),
        arg_lit0(NULL, "auth",    "Authenticate to get info from GetApplicationIDs command (non-standard feature!)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);


    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, &securechann, DCMPlain, &appid, NULL);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    bool authen = arg_get_lit(ctx, 12);

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    res = DesfireSelectAndAuthenticateEx(&dctx, securechann, appid, !authen, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    PICCInfo_t PICCInfo = {0};
    AppListS AppList = {{0}};
    DesfireFillAppList(&dctx, &PICCInfo, AppList, false, false, false); // no deep scan, no scan files

    PrintAndLogEx(SUCCESS, "# Applications.... " _GREEN_("%zu"), PICCInfo.appCount);
    if (PICCInfo.freemem == 0xffffffff) {
        PrintAndLogEx(SUCCESS, "Free memory...... " _YELLOW_("n/a"));
    } else {
        PrintAndLogEx(SUCCESS, "Free memory...... " _GREEN_("%d") " bytes", PICCInfo.freemem);
    }

    if ((PICCInfo.keySettings & (1 << 1)) == 0) {
        PrintAndLogEx(WARNING, "Directory list access with CMK... ( " _RED_("Enabled") " )");
        PrintAndLogEx(HINT, "Hint: Try to read MAD with Card Master Key (CMK)");
    }

    PrintAndLogEx(SUCCESS, "----------------------------------------- " _CYAN_("MAD") " ------------------------------------------");
    bool foundFFFFFF = false;
    for (int i = 0; i < PICCInfo.appCount; i++) {
        if (AppList[i].appNum == 0xffffff) {
            foundFFFFFF = true;
            break;
        }
    }

    PrintAndLogEx(SUCCESS, _CYAN_("Issuer"));

    if (foundFFFFFF) {
        res = DesfireSelectAIDHexNoFieldOn(&dctx, 0xffffff);
        if (res == PM3_SUCCESS) {
            uint32_t madver = 0;
            res = DesfireValueFileOperations(&dctx, 0x00, MFDES_GET_VALUE, &madver);
            if (res != PM3_SUCCESS) {
                PrintAndLogEx(SUCCESS, "MAD version... " _RED_("n/a"));
            } else {
                if (madver == 3)
                    PrintAndLogEx(SUCCESS, "MAD version... " _GREEN_("3"));
                else
                    PrintAndLogEx(WARNING, "MAD version... " _YELLOW_("%d"), madver);
            }

            uint8_t data[250] = {0};
            size_t datalen = 0;

            res = DesfireReadFile(&dctx, 01, 0x000000, 0, data, &datalen);
            if (res != PM3_SUCCESS) {
                PrintAndLogEx(SUCCESS, "Card Holder... " _RED_("n/a"));
            } else {
                if (datalen > 0) {
                    PrintAndLogEx(SUCCESS, "Card Holder... ");
                    if (verbose) {
                        print_buffer_with_offset(data, datalen, 0, true);
                        PrintAndLogEx(NORMAL, "");
                    }
                    MADCardHolderInfoDecode(data, datalen, verbose);
                    PrintAndLogEx(NORMAL, "");
                } else {
                    PrintAndLogEx(SUCCESS, "Card Holder... " _YELLOW_("none"));
                }
            }

            res = DesfireReadFile(&dctx, 02, 0x000000, 0, data, &datalen);
            if (res != PM3_SUCCESS) {
                PrintAndLogEx(SUCCESS, "Card Publisher: " _RED_("n/a"));
            } else {
                if (datalen > 0) {
                    PrintAndLogEx(SUCCESS, "Card Publisher: ");
                    print_buffer_with_offset(data, datalen, 0, true);
                    PrintAndLogEx(NORMAL, "");
                } else {
                    PrintAndLogEx(SUCCESS, "Card Publisher: " _YELLOW_("none"));
                }
            }
        } else {
            PrintAndLogEx(WARNING,  _RED_("Can't select") " issuer information app (0xffffff).");
        }
    } else {
        PrintAndLogEx(WARNING, "Issuer information " _RED_("not found") " on the card.");
    }

    size_t madappcount = 0;
    PrintAndLogEx(SUCCESS, "");
    PrintAndLogEx(SUCCESS, _CYAN_("Applications"));
    for (int i = 0; i < PICCInfo.appCount; i++) {
        if ((AppList[i].appNum & 0xf00000) == 0xf00000) {
            DesfirePrintMADAID(AppList[i].appNum, verbose);

            // read file 0, 1, 2
            res = DesfireSelectAIDHexNoFieldOn(&dctx, AppList[i].appNum);
            if (res == PM3_SUCCESS) {
                uint8_t buf[APDU_RES_LEN] = {0};
                size_t buflen = 0;

                res = DesfireGetFileIDList(&dctx, buf, &buflen);
                if (res != PM3_SUCCESS) {
                    PrintAndLogEx(ERR, "Desfire GetFileIDList command " _RED_("error") ". Result: %d", res);
                    DropField();
                    return PM3_ESOFT;
                }

                if (buflen > 0) {
                    for (int j = 0; j < buflen; j++) {
                        PrintAndLogEx(INFO, "  File ID... %02x", buf[j]);
                    }
                }
            }

            madappcount++;
        }
    }

    if (madappcount == 0) {
        PrintAndLogEx(SUCCESS, "There is no MAD applications on the card");
        DropField();
        return PM3_SUCCESS;
    }

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesSelectApp(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes selectapp",
                  "Select application on the card. It selects app if it is a valid one or returns an error.",
                  "hf mfdes selectapp --aid 123456       -> select application 123456\n"
                  "hf mfdes selectapp --mf               -> select master file (PICC level)\n"
                  "hf mfdes selectapp --dfname aid123456 -> select application aid123456 by DF name\n"
                  "hf mfdes selectapp --isoid 1111       -> select application 1111 by ISO ID\n"
                  "hf mfdes selectapp --isoid 1111 --fileisoid 2222   -> select application 1111 file 2222 by ISO ID\n"
                  "hf mfdes selectapp --isoid 01df --fileisoid 00ef   -> select file 00 on the Desfire Light");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID of application for some parameters (3 hex bytes, big endian)"),
        arg_str0(NULL, "dfname",  "<str>", "Application DF Name (string, max 16 chars). Selects application via ISO SELECT command"),
        arg_lit0(NULL, "mf",      "Select MF (master file) via ISO channel"),
        arg_str0(NULL, "isoid",   "<hex>", "Application ISO ID (ISO DF ID) (2 hex bytes, big endian)"),
        arg_str0(NULL, "fileisoid", "<hex>", "Select file inside application by ISO ID (ISO DF ID) (2 hex bytes, big endian)."),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, &securechann, DCMPlain, &appid, NULL);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint8_t dfname[32] = {0};
    int dfnamelen = 16;  // since max length is 16 chars we don't have to test for 32-1 null termination
    CLIGetStrWithReturn(ctx, 12, dfname, &dfnamelen);

    bool selectmf = arg_get_lit(ctx, 13);

    uint32_t isoid = 0x0000;
    bool isoidpresent = false;
    if (CLIGetUint32Hex(ctx, 14, 0x0000, &isoid, &isoidpresent, 2, "ISO ID for EF or DF must have 2 bytes length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t fileisoid = 0x0000;
    bool fileisoidpresent = false;
    if (CLIGetUint32Hex(ctx, 15, 0x0000, &fileisoid, &fileisoidpresent, 2, "ISO ID for EF or DF must have 2 bytes length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    uint8_t resp[250] = {0};
    size_t resplen = 0;

    if (selectmf) {
        res = DesfireISOSelect(&dctx, ISSMFDFEF, NULL, 0, resp, &resplen);
        if (res != PM3_SUCCESS) {
            DropField();
            PrintAndLogEx(FAILED, "ISO Select MF " _RED_("failed"));
            return res;
        }

        if (resplen > 0)
            PrintAndLogEx(FAILED, "Application " _CYAN_("FCI template") " [%zu]%s", resplen, sprint_hex(resp, resplen));

        PrintAndLogEx(SUCCESS, "PICC MF selected " _GREEN_("succesfully"));
    } else if (isoidpresent) {
        uint8_t data[2] = {0};
        Uint2byteToMemLe(data, isoid);
        res = DesfireISOSelect(&dctx, ISSMFDFEF, data, 2, resp, &resplen);
        if (res != PM3_SUCCESS) {
            DropField();
            PrintAndLogEx(FAILED, "ISO Select DF 0x%04x " _RED_("failed"), isoid);
            return res;
        }

        if (resplen > 0)
            PrintAndLogEx(FAILED, "Application " _CYAN_("FCI template") " [%zu]%s", resplen, sprint_hex(resp, resplen));

        PrintAndLogEx(SUCCESS, "PICC DF 0x%04x selected " _GREEN_("succesfully"), isoid);
    } else if (dctx.cmdSet == DCCISO || dfnamelen > 0) {
        if (dfnamelen > 0)
            res = DesfireISOSelectDF(&dctx, (char *)dfname, resp, &resplen);
        else
            res = DesfireISOSelect(&dctx, ISSMFDFEF, NULL, 0, resp, &resplen);
        if (res != PM3_SUCCESS) {
            DropField();
            PrintAndLogEx(FAILED, "ISO Select application `%s` " _RED_("failed"), (char *)dfname);
            return res;
        }

        if (resplen > 0)
            PrintAndLogEx(FAILED, "Application " _CYAN_("FCI template") " [%zu]%s", resplen, sprint_hex(resp, resplen));

        if (dfnamelen > 0)
            PrintAndLogEx(SUCCESS, "Application `%s` selected " _GREEN_("succesfully"), (char *)dfname);
        else
            PrintAndLogEx(SUCCESS, "PICC MF selected " _GREEN_("succesfully"));
    } else {
        res = DesfireSelectAndAuthenticateEx(&dctx, securechann, appid, true, verbose);
        if (res != PM3_SUCCESS) {
            DropField();
            PrintAndLogEx(FAILED, "Select application 0x%06x " _RED_("failed") " ", appid);
            return res;
        }

        PrintAndLogEx(SUCCESS, "Application 0x%06x selected " _GREEN_("succesfully") " ", appid);
    }

    if (fileisoidpresent) {
        res = DesfireSelectEx(&dctx, false, ISWIsoID, fileisoid, NULL);
        if (res != PM3_SUCCESS) {
            DropField();
            PrintAndLogEx(FAILED, "Select file 0x%04x " _RED_("failed") " ", fileisoid);
            return res;
        }

        PrintAndLogEx(SUCCESS, "File 0x%04x selected " _GREEN_("succesfully") " ", fileisoid);
    }

    DropField();
    return res;
}

static int CmdHF14ADesISOSelectISOFID(DesfireContext_t *dctx, uint16_t fileid, uint8_t *resp, size_t *resplen, bool fieldon) {
    // ISO 7816 SELECT FILE command: CLA=00, INS=A4, P1=00, P2=00, Lc=2
    uint8_t data[2] = {0};
    Uint2byteToMemBe(data, fileid);

    return DesfireISOSelectEx(dctx, fieldon, ISSMFDFEF, data, sizeof(data), resp, resplen);
}

static int CmdHF14ADesSelectISOFID(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes selectisofid",
                  "Select file via ISO Select command by 2-byte ISO file identifier.\n"
                  "Optionally preselect an application by AID or DF name before selecting the file.",
                  "hf mfdes selectisofid --isofid e104 -> select file 0xE104\n"
                  "hf mfdes selectisofid --aid 123456 --isofid 00ef -> select file 0x00EF in app 0x123456\n"
                  "hf mfdes selectisofid --dfname D2760000850100 --isofid 00ef --apdu -> select file 0x00EF after DF name selection and show APDU logs");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "dfname",  "<hex>", "Application ISO DF Name (1-16 hex bytes, big endian)"),
        arg_str0(NULL, "isofid",  "<hex>", "File ISO ID (ISO EF ID) (2 hex bytes, big endian)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    DesfireISOSelectWay selectway = ISWDFName;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 4,
                                         &securechann, DCMNone, &appid, &selectway);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint32_t isoid = 0x0000;
    bool isoidpresent = false;
    if (CLIGetUint32Hex(ctx, 5, 0x0000, &isoid, &isoidpresent, 2, "File ISO ID must have 2 hex bytes")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    if (!isoidpresent) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "File ISO ID is required");
        return PM3_EINVARG;
    }

    bool aidpresent = (arg_get_str(ctx, 3)->count > 0);
    bool preselect = aidpresent || (dctx.selectedDFNameLen > 0);
    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    uint8_t resp[250] = {0};
    size_t resplen = 0;
    if (preselect) {
        res = DesfireSelectAndAuthenticateW(&dctx, securechann, selectway, appid, false, 0, true, verbose);
        if (res != PM3_SUCCESS) {
            DropField();
            PrintAndLogEx(FAILED, "Application preselect " _RED_("failed"));
            return res;
        }
    }

    res = CmdHF14ADesISOSelectISOFID(&dctx, isoid, resp, &resplen, !preselect);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(FAILED, "ISO Select file 0x%04x " _RED_("failed"), isoid);
        return res;
    }

    if (resplen > 0 && verbose) {
        PrintAndLogEx(INFO, "File select response [%zu] %s", resplen, sprint_hex(resp, resplen));
    }

    PrintAndLogEx(SUCCESS, "File 0x%04x selected " _GREEN_("succesfully"), isoid);
    DropField();
    return PM3_SUCCESS;
}


typedef struct {
    uint32_t current;
    uint32_t step;
    uint64_t total_count;
    uint64_t generated_count;
} mfdes_bruteaid_generator_full_t;

typedef struct {
    uint8_t alphabet[100];
    size_t alphabet_len;
    size_t idx0;
    size_t idx1;
    size_t idx2;
    uint32_t id_start;
    uint32_t id_end;
    uint32_t step;
    uint64_t ordinal;
    uint64_t total_count;
    uint64_t generated_count;
    bool exhausted;
} mfdes_bruteaid_generator_ascii_t;

typedef struct {
    uint32_t *aids;
    size_t aids_count;
    size_t idx;
    uint32_t step;
    uint64_t ordinal;
    uint64_t total_count;
    uint64_t generated_count;
} mfdes_bruteaid_generator_dictionary_t;

typedef struct {
    mfdes_bruteaid_preset_t preset;
    uint64_t total_count;
    union {
        mfdes_bruteaid_generator_full_t full;
        mfdes_bruteaid_generator_ascii_t ascii;
        mfdes_bruteaid_generator_dictionary_t dictionary;
    } g;
} mfdes_bruteaid_generator_t;

static void mfdesBruteAIDGeneratorFullInit(mfdes_bruteaid_generator_full_t *gen, uint32_t id_start, uint32_t id_end, uint32_t step) {
    memset(gen, 0, sizeof(*gen));
    gen->current = id_start;
    gen->step = step;
    gen->total_count = ((uint64_t)(id_end - id_start) / step) + 1;
}

static bool mfdesBruteAIDGeneratorFullNext(mfdes_bruteaid_generator_full_t *gen, uint32_t *id, float *progress) {
    if (gen->generated_count >= gen->total_count) {
        return false;
    }

    *id = gen->current;
    *progress = (gen->total_count > 1) ? (100.0f * (float)gen->generated_count / (float)(gen->total_count - 1)) : 100.0f;

    gen->generated_count++;
    if (gen->generated_count < gen->total_count) {
        gen->current += gen->step;
    }
    return true;
}

static void mfdesBruteAIDGeneratorAsciiInit(mfdes_bruteaid_generator_ascii_t *gen, uint32_t id_start, uint32_t id_end, uint32_t step) {
    memset(gen, 0, sizeof(*gen));
    gen->id_start = id_start;
    gen->id_end = id_end;
    gen->step = step;

    for (uint8_t b = 0x09; b <= 0x0D; b++) {
        gen->alphabet[gen->alphabet_len++] = b;
    }
    for (uint16_t b = 0x20; b <= 0x7E; b++) {
        gen->alphabet[gen->alphabet_len++] = (uint8_t)b;
    }

    uint64_t all_candidates = 0;
    for (size_t b2 = 0; b2 < gen->alphabet_len; b2++) {
        for (size_t b1 = 0; b1 < gen->alphabet_len; b1++) {
            for (size_t b0 = 0; b0 < gen->alphabet_len; b0++) {
                uint32_t id = ((uint32_t)gen->alphabet[b0]) | ((uint32_t)gen->alphabet[b1] << 8) | ((uint32_t)gen->alphabet[b2] << 16);
                if (id >= id_start && id <= id_end) {
                    all_candidates++;
                }
            }
        }
    }

    gen->total_count = (all_candidates + step - 1) / step;
    gen->exhausted = (gen->total_count == 0);
}

static void mfdesBruteAIDGeneratorNumbersInit(mfdes_bruteaid_generator_ascii_t *gen, uint32_t id_start, uint32_t id_end, uint32_t step) {
    memset(gen, 0, sizeof(*gen));
    gen->id_start = id_start;
    gen->id_end = id_end;
    gen->step = step;

    for (uint8_t b = 0x30; b <= 0x39; b++) {
        gen->alphabet[gen->alphabet_len++] = b;
    }

    uint64_t all_candidates = 0;
    for (size_t b2 = 0; b2 < gen->alphabet_len; b2++) {
        for (size_t b1 = 0; b1 < gen->alphabet_len; b1++) {
            for (size_t b0 = 0; b0 < gen->alphabet_len; b0++) {
                uint32_t id = ((uint32_t)gen->alphabet[b0]) | ((uint32_t)gen->alphabet[b1] << 8) | ((uint32_t)gen->alphabet[b2] << 16);
                if (id >= id_start && id <= id_end) {
                    all_candidates++;
                }
            }
        }
    }

    gen->total_count = (all_candidates + step - 1) / step;
    gen->exhausted = (gen->total_count == 0);
}

static void mfdesBruteAIDGeneratorLettersInit(mfdes_bruteaid_generator_ascii_t *gen, uint32_t id_start, uint32_t id_end, uint32_t step) {
    memset(gen, 0, sizeof(*gen));
    gen->id_start = id_start;
    gen->id_end = id_end;
    gen->step = step;

    for (uint8_t b = 'A'; b <= 'Z'; b++) {
        gen->alphabet[gen->alphabet_len++] = b;
    }
    for (uint8_t b = 'a'; b <= 'z'; b++) {
        gen->alphabet[gen->alphabet_len++] = b;
    }

    uint64_t all_candidates = 0;
    for (size_t b2 = 0; b2 < gen->alphabet_len; b2++) {
        for (size_t b1 = 0; b1 < gen->alphabet_len; b1++) {
            for (size_t b0 = 0; b0 < gen->alphabet_len; b0++) {
                uint32_t id = ((uint32_t)gen->alphabet[b0]) | ((uint32_t)gen->alphabet[b1] << 8) | ((uint32_t)gen->alphabet[b2] << 16);
                if (id >= id_start && id <= id_end) {
                    all_candidates++;
                }
            }
        }
    }

    gen->total_count = (all_candidates + step - 1) / step;
    gen->exhausted = (gen->total_count == 0);
}

static int mfdesBruteAIDGeneratorDictionaryInit(mfdes_bruteaid_generator_dictionary_t *gen, uint32_t id_start, uint32_t id_end, uint32_t step) {
    memset(gen, 0, sizeof(*gen));
    gen->step = step;

    char *path = NULL;
    int res = searchFile(&path, RESOURCES_SUBDIR, "aid_desfire", ".json", true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Cannot locate aid_desfire dictionary file");
        return PM3_EFILE;
    }

    json_error_t error;
    json_t *root = json_load_file(path, 0, &error);
    free(path);
    if (root == NULL) {
        PrintAndLogEx(ERR, "Failed to load aid_desfire dictionary: line %d: %s", error.line, error.text);
        return PM3_ESOFT;
    }

    if (json_is_array(root) == false) {
        PrintAndLogEx(ERR, "Invalid aid_desfire dictionary format (root must be array)");
        json_decref(root);
        return PM3_ESOFT;
    }

    size_t max_count = json_array_size(root);
    if (max_count == 0) {
        json_decref(root);
        return PM3_SUCCESS;
    }

    if (max_count > (SIZE_MAX / (2 * sizeof(uint32_t)))) {
        json_decref(root);
        return PM3_EMALLOC;
    }

    size_t alloc_count = max_count * 2;
    gen->aids = calloc(alloc_count, sizeof(uint32_t));
    if (gen->aids == NULL) {
        json_decref(root);
        return PM3_EMALLOC;
    }

    for (size_t i = 0; i < max_count; i++) {
        json_t *entry = json_array_get(root, i);
        if (json_is_object(entry) == false) {
            continue;
        }

        json_t *aid_j = json_object_get(entry, "AID");
        if (json_is_string(aid_j) == false) {
            continue;
        }

        const char *aid_str = json_string_value(aid_j);
        if (aid_str == NULL || strlen(aid_str) != 6) {
            continue;
        }

        bool is_hex = true;
        for (int c = 0; c < 6; c++) {
            if (isxdigit((uint8_t)aid_str[c]) == 0) {
                is_hex = false;
                break;
            }
        }
        if (is_hex == false) {
            continue;
        }

        uint32_t aid = 0;
        if (sscanf(aid_str, "%x", &aid) != 1) {
            continue;
        }
        aid &= 0xFFFFFF;

        // People may fill in AID values in different byte orders
        // so we will try both big endian and little endian variants of the AID
        uint32_t aid_variants[] = {
            aid,
            ((aid & 0x0000FFU) << 16) | (aid & 0x00FF00U) | ((aid & 0xFF0000U) >> 16)
        };

        for (size_t v = 0; v < ARRAYLEN(aid_variants); v++) {
            uint32_t candidate = aid_variants[v];
            if (candidate < id_start || candidate > id_end) {
                continue;
            }

            bool exists = false;
            for (size_t j = 0; j < gen->aids_count; j++) {
                if (gen->aids[j] == candidate) {
                    exists = true;
                    break;
                }
            }
            if (exists == false) {
                gen->aids[gen->aids_count++] = candidate;
            }
        }
    }
    json_decref(root);

    gen->total_count = (gen->aids_count + step - 1) / step;
    return PM3_SUCCESS;
}

static bool mfdesBruteAIDGeneratorAsciiNext(mfdes_bruteaid_generator_ascii_t *gen, uint32_t *id, float *progress) {
    while (gen->exhausted == false) {
        uint32_t candidate = ((uint32_t)gen->alphabet[gen->idx0]) |
                             ((uint32_t)gen->alphabet[gen->idx1] << 8) |
                             ((uint32_t)gen->alphabet[gen->idx2] << 16);

        gen->idx0++;
        if (gen->idx0 >= gen->alphabet_len) {
            gen->idx0 = 0;
            gen->idx1++;
            if (gen->idx1 >= gen->alphabet_len) {
                gen->idx1 = 0;
                gen->idx2++;
                if (gen->idx2 >= gen->alphabet_len) {
                    gen->exhausted = true;
                }
            }
        }

        if (candidate < gen->id_start || candidate > gen->id_end) {
            continue;
        }

        if ((gen->ordinal++ % gen->step) != 0) {
            continue;
        }

        *id = candidate;
        *progress = (gen->total_count > 1) ? (100.0f * (float)gen->generated_count / (float)(gen->total_count - 1)) : 100.0f;

        gen->generated_count++;
        if (gen->generated_count >= gen->total_count) {
            gen->exhausted = true;
        }
        return true;
    }

    return false;
}

static bool mfdesBruteAIDGeneratorDictionaryNext(mfdes_bruteaid_generator_dictionary_t *gen, uint32_t *id, float *progress) {
    while (gen->idx < gen->aids_count) {
        uint32_t candidate = gen->aids[gen->idx++];
        if ((gen->ordinal++ % gen->step) != 0) {
            continue;
        }

        *id = candidate;
        *progress = (gen->total_count > 1) ? (100.0f * (float)gen->generated_count / (float)(gen->total_count - 1)) : 100.0f;

        gen->generated_count++;
        return true;
    }

    return false;
}

static void mfdesBruteAIDGeneratorFree(mfdes_bruteaid_generator_t *gen) {
    if (gen->preset == MFDES_BRUTEAID_PRESET_DICTIONARY) {
        free(gen->g.dictionary.aids);
        gen->g.dictionary.aids = NULL;
        gen->g.dictionary.aids_count = 0;
    }
}

static int mfdesBruteAIDGeneratorInit(mfdes_bruteaid_generator_t *gen, mfdes_bruteaid_preset_t preset, uint32_t id_start, uint32_t id_end, uint32_t step) {
    memset(gen, 0, sizeof(*gen));
    gen->preset = preset;

    if (preset == MFDES_BRUTEAID_PRESET_ASCII) {
        mfdesBruteAIDGeneratorAsciiInit(&gen->g.ascii, id_start, id_end, step);
        gen->total_count = gen->g.ascii.total_count;
    } else if (preset == MFDES_BRUTEAID_PRESET_NUMBERS) {
        mfdesBruteAIDGeneratorNumbersInit(&gen->g.ascii, id_start, id_end, step);
        gen->total_count = gen->g.ascii.total_count;
    } else if (preset == MFDES_BRUTEAID_PRESET_LETTERS) {
        mfdesBruteAIDGeneratorLettersInit(&gen->g.ascii, id_start, id_end, step);
        gen->total_count = gen->g.ascii.total_count;
    } else if (preset == MFDES_BRUTEAID_PRESET_DICTIONARY) {
        int res = mfdesBruteAIDGeneratorDictionaryInit(&gen->g.dictionary, id_start, id_end, step);
        if (res != PM3_SUCCESS) {
            return res;
        }
        gen->total_count = gen->g.dictionary.total_count;
    } else if (preset == MFDES_BRUTEAID_PRESET_MAD) {
        mfdesBruteAIDGeneratorFullInit(&gen->g.full, id_start, id_end, MFDES_BRUTEAID_MAD_STEP);
        gen->total_count = gen->g.full.total_count;
    } else {
        mfdesBruteAIDGeneratorFullInit(&gen->g.full, id_start, id_end, step);
        gen->total_count = gen->g.full.total_count;
    }
    return PM3_SUCCESS;
}

static bool mfdesBruteAIDGeneratorNext(mfdes_bruteaid_generator_t *gen, uint32_t *id, float *progress) {
    if (gen->preset == MFDES_BRUTEAID_PRESET_ASCII ||
            gen->preset == MFDES_BRUTEAID_PRESET_NUMBERS ||
            gen->preset == MFDES_BRUTEAID_PRESET_LETTERS) {
        return mfdesBruteAIDGeneratorAsciiNext(&gen->g.ascii, id, progress);
    } else if (gen->preset == MFDES_BRUTEAID_PRESET_DICTIONARY) {
        return mfdesBruteAIDGeneratorDictionaryNext(&gen->g.dictionary, id, progress);
    }
    return mfdesBruteAIDGeneratorFullNext(&gen->g.full, id, progress);
}

static int DesfireGetDelegatedInfoNoFieldOn(DesfireContext_t *dctx, uint16_t damslot, uint8_t *resp, size_t *resplen) {
    uint8_t data[2] = {0};
    Uint2byteToMemLe(data, damslot);

    uint8_t xresp[16] = {0};
    size_t xresplen = 0;
    uint8_t respcode = 0xFF;

    int res = DesfireExchangeEx(false, dctx, MFDES_GET_DELEGATE_INFO, data, sizeof(data), &respcode, xresp, &xresplen, true, 0);
    if (res != PM3_SUCCESS) {
        if (res == PM3_EAPDU_FAIL && respcode == 0xFF && xresplen == 0) {
            return PM3_ECARDEXCHANGE;
        }
        return res;
    }

    if (respcode == 0xFF) {
        return PM3_ECARDEXCHANGE;
    }

    if (respcode != MFDES_S_OPERATION_OK) {
        return PM3_EAPDU_FAIL;
    }

    if (xresplen != 8) {
        return PM3_EAPDU_FAIL;
    }

    if (resplen) {
        *resplen = xresplen;
    }

    if (resp) {
        memcpy(resp, xresp, xresplen);
    }

    return PM3_SUCCESS;
}

static int CmdHF14ADesBruteApps(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes bruteaid",
                  "Recover AIDs by bruteforce.\n"
                  "WARNING: This command takes a loooong time",
                  "hf mfdes bruteaid                    -> Search all apps\n"
                  "hf mfdes bruteaid --preset mad            -> Search MAD range preset (default start F0000F, step 16; can override start)\n"
                  "hf mfdes bruteaid --preset ascii          -> Search with ASCII printable + whitespace bytes only\n"
                  "hf mfdes bruteaid --preset numbers        -> Search with numeric bytes ('0'..'9') only\n"
                  "hf mfdes bruteaid --preset letters        -> Search with letter bytes ('A'..'Z','a'..'z') only\n"
                  "hf mfdes bruteaid --preset dictionary     -> Search AIDs from `aid_desfire` dictionary (direct + inverted byte order)");

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "start", "<hex>", "Starting App ID as hex bytes (3 bytes, big endian)"),
        arg_str0(NULL, "end",   "<hex>", "Last App ID as hex bytes (3 bytes, big endian)"),
        arg_int0("i",  "step",  "<dec>", "Increment step when bruteforcing"),
        arg_str0(NULL, "preset", "<full|ascii|numbers|letters|dictionary|mad>", "Bruteforce candidate preset (`full` default, `ascii` printable + whitespace, `numbers` = '0'..'9', `letters` = 'A'..'Z'+'a'..'z', `dictionary` = aid_desfire list with direct + inverted byte order, `mad` = step 16 with default start F0000F unless --start is provided)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &securechann, DCMNone, NULL, NULL);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint8_t startAid[3] = {0};
    uint8_t endAid[3] = {0xFF, 0xFF, 0xFF};
    int startLen = 0;
    int endLen = 0;
    CLIGetHexWithReturn(ctx, 1, startAid, &startLen);
    CLIGetHexWithReturn(ctx, 2, endAid, &endLen);
    int idIncrementArg = arg_get_int_def(ctx, 3, 1);

    int preset = MFDES_BRUTEAID_PRESET_FULL;
    if (CLIGetOptionList(arg_get_str(ctx, 4), mfdesBruteAIDPresetOpts, &preset)) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    CLIParserFree(ctx);

    if (idIncrementArg <= 0) {
        PrintAndLogEx(ERR, "Increment step should be greater than zero");
        return PM3_EINVARG;
    }
    uint32_t idIncrement = (uint32_t)idIncrementArg;

    // tru select PICC
    res = DesfireSelectAIDHex(&dctx, 0x000000, false, 0);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(FAILED, "Desfire PICC level select " _RED_("failed") ". Maybe wrong card or no card in the field.");
        return res;
    }

    reverse_array(startAid, 3);
    reverse_array(endAid, 3);

    uint32_t idStart = DesfireAIDByteToUint(startAid);
    uint32_t idEnd = DesfireAIDByteToUint(endAid);

    // TODO: We need to check the tag version, EV1 should stop after 26 apps are found
    if (preset == MFDES_BRUTEAID_PRESET_MAD) {
        if (startLen == 0) {
            idStart = MFDES_BRUTEAID_MAD_START;
        }
        idIncrement = MFDES_BRUTEAID_MAD_STEP;
    }

    if (idStart > idEnd) {
        PrintAndLogEx(ERR, "Start should be lower than end. start: %06x end: %06x", idStart, idEnd);
        return PM3_EINVARG;
    }

    const char *preset_name = CLIGetOptionListStr(mfdesBruteAIDPresetOpts, preset);
    if (preset_name == NULL) {
        preset_name = "unknown";
    }

    mfdes_bruteaid_generator_t generator = {0};
    res = mfdesBruteAIDGeneratorInit(&generator, (mfdes_bruteaid_preset_t)preset, idStart, idEnd, idIncrement);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    if (generator.total_count == 0) {
        PrintAndLogEx(WARNING, "No AID candidates in selected range/preset");
        mfdesBruteAIDGeneratorFree(&generator);
        DropField();
        return PM3_SUCCESS;
    }

    if (preset == MFDES_BRUTEAID_PRESET_ASCII ||
            preset == MFDES_BRUTEAID_PRESET_NUMBERS ||
            preset == MFDES_BRUTEAID_PRESET_LETTERS ||
            preset == MFDES_BRUTEAID_PRESET_DICTIONARY) {
        PrintAndLogEx(INFO, "Bruteforcing with preset " _YELLOW_("%s") " candidates " _YELLOW_("%llu"),
                      preset_name, (unsigned long long)generator.total_count);
    } else {
        PrintAndLogEx(INFO, "Bruteforcing with preset " _YELLOW_("%s") " range " _YELLOW_("%06x") "-" _YELLOW_("%06x") " step " _YELLOW_("%u") " candidates " _YELLOW_("%llu"),
                      preset_name, idStart, idEnd, idIncrement, (unsigned long long)generator.total_count);
    }
    if (preset == MFDES_BRUTEAID_PRESET_FULL) {
        PrintAndLogEx(INFO, "Enumerating through all AIDs manually, this will take a while!");
    }
    if (preset == MFDES_BRUTEAID_PRESET_DICTIONARY) {
        PrintAndLogEx(INFO, "Dictionary source: `aid_desfire` (direct + inverted byte order)");
    }

    uint32_t id = 0;
    float progress = 0;
    while (mfdesBruteAIDGeneratorNext(&generator, &id, &progress)) {
        if (kbd_enter_pressed()) {
            break;
        }

        PrintAndLogEx(INPLACE, "Brute DESFire AID Progress " _YELLOW_("%0.1f") " %%   current AID: %06X", progress, id);

        res = DesfireSelectAIDHexNoFieldOn(&dctx, id);
        if (res == PM3_ECARDEXCHANGE || res == PM3_ETIMEOUT || res == PM3_ERFTRANS) {
            for (int attempt = 1; attempt <= MFDES_BRUTEAID_RESELECT_ATTEMPTS; attempt++) {
                PROMPT_CLEARLINE;
                PrintAndLogEx(WARNING, "No card response while checking AID " _YELLOW_("%06X") ". Reselecting card (%d/%d)...",
                              id, attempt, MFDES_BRUTEAID_RESELECT_ATTEMPTS);

                msleep(MFDES_BRUTEAID_RESELECT_WAIT_MS);

                res = DesfireSelectAIDHex(&dctx, 0x000000, false, 0);
                if (res != PM3_SUCCESS) {
                    if (res == PM3_ECARDEXCHANGE || res == PM3_ETIMEOUT || res == PM3_ERFTRANS) {
                        continue;
                    }
                    break;
                }

                res = DesfireSelectAIDHexNoFieldOn(&dctx, id);
                if (res == PM3_SUCCESS || res == PM3_EAPDU_FAIL ||
                        (res != PM3_ECARDEXCHANGE && res != PM3_ETIMEOUT && res != PM3_ERFTRANS)) {
                    break;
                }
            }

            if (res == PM3_ECARDEXCHANGE || res == PM3_ETIMEOUT || res == PM3_ERFTRANS) {
                PrintAndLogEx(FAILED, "Card is not responding after %d reselect attempts. Aborting at AID " _YELLOW_("%06X"),
                              MFDES_BRUTEAID_RESELECT_ATTEMPTS, id);
                mfdesBruteAIDGeneratorFree(&generator);
                DropField();
                return res;
            }
        }

        if (res == PM3_SUCCESS) {
            PROMPT_CLEARLINE;
            PrintAndLogEx(SUCCESS, "Found New DESFire AID " _GREEN_("%06X"), id);
        }
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, _GREEN_("Done!"));
    mfdesBruteAIDGeneratorFree(&generator);
    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesBruteISOFIDs(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes bruteisofid",
                  "Recover ISO file IDs by bruteforce.\n"
                  "WARNING: This command takes a loooong time",
                  "hf mfdes bruteisofid --aid 123456     -> bruteforce ISO file IDs for application 123456\n"
                  "hf mfdes bruteisofid --start 0000 --end 0fff -> bruteforce specific file ISO ID range");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "isoid",   "<hex>", "Application ISO ID (ISO DF ID) (2 hex bytes, big endian)"),
        arg_str0(NULL, "dfname",  "<hex>", "Application ISO DF Name (5-16 hex bytes, big endian)"),
        arg_str0(NULL, "start",   "<hex>", "Starting File ISO ID (2 hex bytes, big endian)"),
        arg_str0(NULL, "end",     "<hex>", "Last File ISO ID (2 hex bytes, big endian)"),
        arg_int0(NULL, "step",    "<dec>", "Increment step when bruteforcing"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    DesfireISOSelectWay selectway = ISW6bAID;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 0, 0, 0, 0, 0, 0, 0, 0, 3, 4, 5,
                                         &securechann, DCMNone, &appid, &selectway);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint32_t isoidStart = 0x0000;
    if (CLIGetUint32Hex(ctx, 6, 0x0000, &isoidStart, NULL, 2, "File ISO ID start must have 2 hex bytes")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t isoidEnd = 0xFFFF;
    if (CLIGetUint32Hex(ctx, 7, 0xFFFF, &isoidEnd, NULL, 2, "File ISO ID end must have 2 hex bytes")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int stepArg = arg_get_int_def(ctx, 8, 1);
    CLIParserFree(ctx);

    if (stepArg <= 0) {
        PrintAndLogEx(ERR, "Increment step should be greater than zero");
        return PM3_EINVARG;
    }
    uint32_t step = (uint32_t)stepArg;

    if (isoidStart > isoidEnd) {
        PrintAndLogEx(ERR, "Start should be lower than or equal to end. start: %04x end: %04x", isoidStart, isoidEnd);
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);

    res = DesfireSelectAndAuthenticateW(&dctx, securechann, selectway, appid, false, 0, true, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(FAILED, "Select or authentication %s " _RED_("failed") ". Result [%d] %s", DesfireWayIDStr(selectway, appid), res, DesfireAuthErrorToStr(res));
        return res;
    }

    uint64_t totalCount = ((isoidEnd - isoidStart) / step) + 1;
    uint64_t tested = 0;
    uint64_t found = 0;

    PrintAndLogEx(INFO, "Bruteforcing file ISO IDs range " _YELLOW_("%04x") "-" _YELLOW_("%04x") " step " _YELLOW_("%u") " candidates " _YELLOW_("%llu"),
                  isoidStart, isoidEnd, step, (unsigned long long)totalCount);

    if (totalCount > 0x7fffffffULL) {
        PrintAndLogEx(INFO, "Enumerating through all File IDs manually, this will take a while!");
    }

    for (uint32_t isofid = isoidStart;; isofid += step) {
        if (kbd_enter_pressed()) {
            break;
        }

        tested++;
        float progress = (totalCount > 0) ? ((float)tested / (float)totalCount) * 100.0f : 100.0f;
        PrintAndLogEx(INPLACE, "Brute DESFire ISO File ID Progress " _YELLOW_("%0.1f") " %%   current ID: %04X", progress, isofid);

        uint8_t resp[250] = {0};
        size_t resplen = 0;
        uint8_t *resp_p = verbose ? resp : NULL;
        size_t *resplen_p = verbose ? &resplen : NULL;
        res = CmdHF14ADesISOSelectISOFID(&dctx, isofid, resp_p, resplen_p, false);

        if (res == PM3_ECARDEXCHANGE || res == PM3_ETIMEOUT || res == PM3_ERFTRANS) {
            for (int attempt = 1; attempt <= MFDES_BRUTEFID_RESELECT_ATTEMPTS; attempt++) {
                PROMPT_CLEARLINE;
                PrintAndLogEx(WARNING, "No card response while checking ISO ID " _YELLOW_("%04X") ". Reselecting card (%d/%d)...",
                              isofid, attempt, MFDES_BRUTEFID_RESELECT_ATTEMPTS);

                msleep(MFDES_BRUTEFID_RESELECT_WAIT_MS);

                res = DesfireSelectAndAuthenticateW(&dctx, securechann, selectway, appid, false, 0, true, verbose);
                if (res != PM3_SUCCESS) {
                    continue;
                }

                res = CmdHF14ADesISOSelectISOFID(&dctx, isofid, resp_p, resplen_p, false);
                if (res == PM3_SUCCESS || res == PM3_EAPDU_FAIL ||
                        (res != PM3_ECARDEXCHANGE && res != PM3_ETIMEOUT && res != PM3_ERFTRANS)) {
                    break;
                }
            }

            if (res == PM3_ECARDEXCHANGE || res == PM3_ETIMEOUT || res == PM3_ERFTRANS) {
                PrintAndLogEx(FAILED, "Card is not responding after %d reselect attempts. Aborting at ISO ID " _YELLOW_("%04X"),
                              MFDES_BRUTEFID_RESELECT_ATTEMPTS, isofid);
                DropField();
                return res;
            }
        }

        if (res == PM3_SUCCESS) {
            found++;
            PROMPT_CLEARLINE;
            PrintAndLogEx(SUCCESS, "Found new ISO file ID " _GREEN_("0x%04X"), isofid);
            if (verbose && resplen > 0) {
                PrintAndLogEx(INFO, "Response [%zu] " _CYAN_("%s"), resplen, sprint_hex(resp, resplen));
            }
        } else {
            // Non-success status means no file with this identifier
        }

        if (isoidEnd - isofid < step) {
            break;
        }
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "Done! Found " _GREEN_("%llu") " matching file ISO ID candidate(s)",
                  (unsigned long long)found);
    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesBruteDAMSlots(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes brutedamslot",
                  "Recover DAM slot to delegated AID mappings by bruteforce.\n"
                  "WARNING: This command takes a loooong time",
                  "hf mfdes brutedamslot                                  -> bruteforce all DAM slots\n"
                  "hf mfdes brutedamslot --start 0000 --end 00ff         -> bruteforce specific DAM slot range\n"
                  "hf mfdes brutedamslot --step 16                        -> bruteforce DAM slots with step 16\n"
                  "hf mfdes brutedamslot --no-auth                        -> execute without authentication");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number (default: 0 / PICC key)"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "start",   "<hex>", "Starting DAM slot (2 hex bytes, little endian on card)"),
        arg_str0(NULL, "end",     "<hex>", "Last DAM slot (2 hex bytes, little endian on card)"),
        arg_int0(NULL, "step",    "<dec>", "Increment step when bruteforcing DAM slots"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 14);

    int keynum = arg_get_int_def(ctx, 3, 0x00);
    if (keynum < 0 || keynum > 0xFF) {
        CLIParserFree(ctx);
        PrintAndLogEx(ERR, "Key number must be in range 0..255");
        return PM3_EINVARG;
    }

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 0, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0,
                                         &securechann, (noauth) ? DCMPlain : DCMMACed, NULL, NULL);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    dctx.keyNum = keynum & 0xFF;

    uint32_t damslotStart = 0x0000;
    if (CLIGetUint32Hex(ctx, 11, 0x0000, &damslotStart, NULL, 2, "DAM slot start must have 2 hex bytes")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t damslotEnd = 0xFFFF;
    if (CLIGetUint32Hex(ctx, 12, 0xFFFF, &damslotEnd, NULL, 2, "DAM slot end must have 2 hex bytes")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int stepArg = arg_get_int_def(ctx, 13, 1);

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    if (stepArg <= 0) {
        PrintAndLogEx(ERR, "Increment step should be greater than zero");
        return PM3_EINVARG;
    }
    uint32_t step = (uint32_t)stepArg;

    if (damslotStart > damslotEnd) {
        PrintAndLogEx(ERR, "Start should be lower than or equal to end. start: %04x end: %04x", damslotStart, damslotEnd);
        return PM3_EINVARG;
    }

    res = DesfireSelectAndAuthenticateEx(&dctx, securechann, 0x000000, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    uint64_t totalCount = ((damslotEnd - damslotStart) / step) + 1;
    uint64_t tested = 0;
    uint64_t found = 0;

    PrintAndLogEx(INFO, "Bruteforcing DAM slots range " _YELLOW_("%04x") "-" _YELLOW_("%04x") " step " _YELLOW_("%u") " candidates " _YELLOW_("%llu"),
                  damslotStart, damslotEnd, step, (unsigned long long)totalCount);

    for (uint32_t damslot = damslotStart;; damslot += step) {
        if (kbd_enter_pressed()) {
            break;
        }

        tested++;
        float progress = (totalCount > 0) ? ((float)tested / (float)totalCount) * 100.0f : 100.0f;
        PrintAndLogEx(INPLACE, "Brute DESFire DAM slot Progress " _YELLOW_("%0.1f") " %%   current slot: %04X", progress, damslot);

        uint8_t resp[16] = {0};
        size_t resplen = 0;
        res = DesfireGetDelegatedInfoNoFieldOn(&dctx, damslot & 0xffff, resp, &resplen);

        if (res == PM3_ECARDEXCHANGE || res == PM3_ETIMEOUT || res == PM3_ERFTRANS) {
            for (int attempt = 1; attempt <= MFDES_BRUTEDAMSLOT_RESELECT_ATTEMPTS; attempt++) {
                PROMPT_CLEARLINE;
                PrintAndLogEx(WARNING, "No card response while checking DAM slot " _YELLOW_("%04X") ". Reselecting card (%d/%d)...",
                              damslot, attempt, MFDES_BRUTEDAMSLOT_RESELECT_ATTEMPTS);

                msleep(MFDES_BRUTEDAMSLOT_RESELECT_WAIT_MS);

                res = DesfireSelectAndAuthenticateEx(&dctx, securechann, 0x000000, noauth, verbose);
                if (res != PM3_SUCCESS) {
                    if (res != PM3_ECARDEXCHANGE && res != PM3_ETIMEOUT && res != PM3_ERFTRANS) {
                        res = PM3_ECARDEXCHANGE;
                    }
                    continue;
                }

                res = DesfireGetDelegatedInfoNoFieldOn(&dctx, damslot & 0xffff, resp, &resplen);
                if (res == PM3_SUCCESS || res == PM3_EAPDU_FAIL ||
                        (res != PM3_ECARDEXCHANGE && res != PM3_ETIMEOUT && res != PM3_ERFTRANS)) {
                    break;
                }
            }

            if (res == PM3_ECARDEXCHANGE || res == PM3_ETIMEOUT || res == PM3_ERFTRANS) {
                PrintAndLogEx(FAILED, "Card is not responding after %d reselect attempts. Aborting at DAM slot " _YELLOW_("%04X"),
                              MFDES_BRUTEDAMSLOT_RESELECT_ATTEMPTS, damslot);
                DropField();
                return res;
            }
        }

        if (res == PM3_EAPDU_FAIL && noauth == false) {
            bool restored = false;
            int authres = DesfireAuthenticate(&dctx, securechann, verbose);

            // An APDU-level failure on GetDelegatedInfo drops the authenticated state.
            // Try to restore auth in-place first, then fall back to a full reselect.
            if (authres == PM3_SUCCESS && DesfireIsAuthenticated(&dctx)) {
                restored = true;
            }

            for (int attempt = 1; attempt <= MFDES_BRUTEDAMSLOT_RESELECT_ATTEMPTS && restored == false; attempt++) {
                PROMPT_CLEARLINE;
                PrintAndLogEx(WARNING, "Lost authentication after DAM slot " _YELLOW_("%04X") ". Reselecting card (%d/%d)...",
                              damslot, attempt, MFDES_BRUTEDAMSLOT_RESELECT_ATTEMPTS);

                msleep(MFDES_BRUTEDAMSLOT_RESELECT_WAIT_MS);

                authres = DesfireSelectAndAuthenticateEx(&dctx, securechann, 0x000000, false, verbose);
                if (authres == PM3_SUCCESS && DesfireIsAuthenticated(&dctx)) {
                    restored = true;
                    break;
                }
            }

            if (restored == false) {
                PROMPT_CLEARLINE;
                PrintAndLogEx(FAILED, "Failed to restore authentication after DAM slot " _YELLOW_("%04X"),
                              damslot);
                DropField();
                return PM3_ECARDEXCHANGE;
            }
        }

        if (res == PM3_SUCCESS) {
            uint32_t delegatedaid = MemLeToUint3byte(&resp[5]);
            PROMPT_CLEARLINE;
            if (delegatedaid == 0x000000) {
                PrintAndLogEx(SUCCESS, "DAM slot 0x%04X ver 0x%02X AID " _YELLOW_("0x%06X (empty)"),
                              damslot, resp[0], delegatedaid);
            } else {
                PrintAndLogEx(SUCCESS, "DAM slot 0x%04X ver 0x%02X AID " _GREEN_("0x%06X"),
                              damslot, resp[0], delegatedaid);
            }
            found++;
            if (verbose && resplen > 0) {
                PrintAndLogEx(INFO, "Response [%zu] " _CYAN_("%s"), resplen, sprint_hex(resp, resplen));
            }
        }

        if (damslotEnd - damslot < step) {
            break;
        }
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "Done! Found " _GREEN_("%llu") " matching DAM slot candidate(s)",
                  (unsigned long long)found);
    DropField();
    return PM3_SUCCESS;
}

// MIAFRE DESFire Authentication
// keys:
// NR  DESC     KEYLENGTH
// ------------------------
// 1 = DES      8
// 2 = 3DES     16
// 3 = 3K 3DES  24
// 4 = AES      16
static int CmdHF14ADesAuth(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes auth",
                  "Select application on the card. It selects app if it is a valid one or returns an error.",
                  "hf mfdes auth  -n 0 -t des -k 0000000000000000 --kdf none       -> select PICC level and authenticate with key num=0, key type=des, key=00..00 and key derivation = none\n"
                  "hf mfdes auth  -n 0 -t aes -k 00000000000000000000000000000000  -> select PICC level and authenticate with key num=0, key type=aes, key=00..00 and key derivation = none\n"
                  "hf mfdes auth  -n 0 -t des -k 0000000000000000 --save           -> select PICC level and authenticate and in case of successful authentication - save channel parameters to defaults\n"
                  "hf mfdes auth --aid 123456    -> select application 123456 and authenticate via parameters from `default` command\n"
                  "hf mfdes auth --dfname D2760000850100 -n 0 -t aes -k 00000000000000000000000000000000 -> select DF by name and authenticate");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>", "Crypt algo"),
        arg_str0("k",  "key",     "<hex>", "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>", "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID of application for some parameters (3 hex bytes, big endian)"),
        arg_str0(NULL, "isoid",   "<hex>", "Application ISO ID (ISO DF ID) (2 hex bytes, big endian)"),
        arg_str0(NULL, "dfname",  "<hex>", "Application ISO DF Name (5-16 hex bytes, big endian)"),
        arg_lit0(NULL, "save",    "saves channels parameters to defaults if authentication succeeds"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t id = 0x000000;
    DesfireISOSelectWay selectway = ISW6bAID;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, &securechann, DCMPlain, &id, &selectway);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    bool save = arg_get_lit(ctx, 14);

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    res = DesfireSelectAndAuthenticateAppW(&dctx, securechann, selectway, id, false, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(FAILED, "Select or authentication %s " _RED_("failed") ". Result [%d] %s", DesfireWayIDStr(selectway, id), res, DesfireAuthErrorToStr(res));
        return res;
    }

    if (dctx.selectedDFNameLen > 0) {
        PrintAndLogEx(SUCCESS, "DF selected and authenticated " _GREEN_("successfully"));
    } else if (DesfireMFSelected(selectway, id)) {
        PrintAndLogEx(SUCCESS, "PICC selected and authenticated " _GREEN_("succesfully"));
    } else {
        PrintAndLogEx(SUCCESS, "Application " _CYAN_("%s") " selected and authenticated " _GREEN_("succesfully"), DesfireWayIDStr(selectway, id));
    }

    PrintAndLogEx(SUCCESS, _CYAN_("Context: "));
    DesfirePrintContext(&dctx);

    if (save) {
        defaultKeyNum = dctx.keyNum;
        defaultAlgoId = dctx.keyType;
        memcpy(defaultKey, dctx.key, DESFIRE_MAX_KEY_SIZE);
        defaultKdfAlgo = dctx.kdfAlgo;
        defaultKdfInputLen = dctx.kdfInputLen;
        memcpy(defaultKdfInput, dctx.kdfInput, sizeof(dctx.kdfInput));
        defaultSecureChannel = securechann;
        defaultCommSet = dctx.cmdSet;
        defaultCommMode = dctx.commMode;

        PrintAndLogEx(SUCCESS, "Context saved to defaults " _GREEN_("succesfully") ". You can check them by command " _YELLOW_("hf mfdes default"));
    }

    DropField();
    return res;
}

static int CmdHF14ADesSetConfiguration(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes setconfig",
                  "Set card configuration. \n"
                  "WARNING! Danger zone!\n"
                  "Needs to provide card's master key and works if not blocked by config.",
                  "More about options MF2DLHX0.pdf.\n"
                  "Options list:\n"
                  "  00h PICC configuration.\n"
                  "  02h ATS update.\n"
                  "  03h SAK update\n"
                  "  04h Secure Messaging Configuration.\n"
                  "  05h Capability data. (here change for LRP in the Desfire Light [enable 00000000010000000000])\n"
                  "  06h DF Name renaming (one-time)\n"
                  "  08h File renaming (one-time)\n"
                  "  09h Value file configuration (one-time)\n"
                  "  0Ah Failed authentication counter setting [disable 00ffffffff]\n"
                  "  0Bh HW configuration\n"
                  "\n"
                  "hf mfdes setconfig --param 03 --data 0428               -> set SAK\n"
                  "hf mfdes setconfig --param 02 --data 0875778102637264   -> set ATS (first byte - length)\n"
                  "hf mfdes setconfig --isoid df01 -t aes --schann ev2 --param 05 --data 00000000020000000000 -> set LRP mode enable for Desfire Light\n"
                  "hf mfdes setconfig --isoid df01 -t aes --schann ev2 --param 0a --data 00ffffffff           -> Disable failed auth counters for Desfire Light\n"
                  "hf mfdes setconfig --isoid df01 -t aes --schann lrp --param 0a --data 00ffffffff           -> Disable failed auth counters for Desfire Light via lrp");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>", "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>", "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID of application for some parameters (3 hex bytes, big endian)"),
        arg_str0(NULL, "isoid",   "<hex>", "Application ISO ID (ISO DF ID) (2 hex bytes, big endian)."),
        arg_str0("p",  "param",   "<hex>", "Parameter id (1 hex byte)"),
        arg_str0("d",  "data",    "<hex>", "Data for parameter (1..30 hex bytes)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t id = 0x000000;
    DesfireISOSelectWay selectway = ISW6bAID;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, &securechann, DCMEncrypted, &id, &selectway);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint32_t paramid = 0;
    if (CLIGetUint32Hex(ctx, 13, 0, &paramid, NULL, 1, "Parameter ID must have 1 bytes length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t param[250] = {0};
    int paramlen = sizeof(param);
    CLIGetHexWithReturn(ctx, 14, param, &paramlen);
    if (paramlen == 0) {
        PrintAndLogEx(ERR, "Parameter must have a data.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    if (paramlen > 50) {
        PrintAndLogEx(ERR, "Parameter data length must be less than 50 instead of %d.", paramlen);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    if (verbose) {
        if (DesfireMFSelected(selectway, id)) {
            PrintAndLogEx(INFO, _CYAN_("PICC") " param ID: 0x%02x param[%d]: %s",
                          paramid,
                          paramlen,
                          sprint_hex(param, paramlen)
                         );
        } else {
            PrintAndLogEx(INFO, _CYAN_("%s %06x") " param ID: 0x%02x param[%d]: %s",
                          DesfireSelectWayToStr(selectway),
                          id,
                          paramid,
                          paramlen,
                          sprint_hex(param, paramlen)
                         );
        }
    }

    res = DesfireSelectAndAuthenticateAppW(&dctx, securechann, selectway, id, false, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(FAILED, "Select or authentication ( %s ) Result [%d] %s %s",
                      DesfireWayIDStr(selectway, id),
                      res,
                      DesfireAuthErrorToStr(res),
                      _RED_("failed")
                     );
        return res;
    }

    res = DesfireSetConfiguration(&dctx, paramid, param, paramlen);
    if (res == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Set configuration 0x%02x ( %s )", paramid, _GREEN_("ok"));
    } else {
        PrintAndLogEx(FAILED, "Set configuration 0x%02x ( %s )", paramid, _RED_("failed"));
    }

    DropField();
    return res;
}

static int CmdHF14ADesChangeKey(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes changekey",
                  "Change PICC/Application key. Needs to provide keynum/key for a valid authentication (may get from default parameters).",
                  "Change crypto algorithm for PICC key is possible, \n"
                  "but for APP keys crypto algorithm is set by createapp command and can't be changed wo application delete\n"
                  "\n"
                  "hf mfdes changekey --aid 123456    -> execute with default factory setup. change des key 0 in the app 123456 from 00..00 to 00..00\n"
                  "hf mfdes changekey --isoid df01 -t aes --schann lrp --newkeyno 01    -> change key 01 via lrp channel"
                  "hf mfdes changekey -t des --newalgo aes --newkey 11223344556677889900112233445566 --newver a5      -> change card master key to AES one\n"
                  "hf mfdes changekey --aid 123456 -t aes --key 00000000000000000000000000000000 --newkey 11223344556677889900112233445566 -> change app master key\n"
                  "hf mfdes changekey --aid 123456 -t des -n 0 --newkeyno 1 --oldkey 5555555555555555 --newkey 1122334455667788  -> change key 1 with auth from key 0\n"
                  "hf mfdes changekey --aid 123456 -t 3tdea --newkey 112233445566778899001122334455667788990011223344            -> change 3tdea key 0 from default 00..00 to provided");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>", "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>", "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID of application (3 hex bytes, big endian)"),
        arg_str0(NULL, "isoid",   "<hex>", "Application ISO ID (ISO DF ID) (2 hex bytes, big endian)."),
        arg_str0(NULL, "oldalgo", "<DES|2TDEA|3TDEA|AES>", "Old key crypto algorithm"),
        arg_str0(NULL, "oldkey",  "<old key>", "Old key (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_int0(NULL, "newkeyno", "<dec>", "Key number for change"),
        arg_str0(NULL, "newalgo", "<DES|2TDEA|3TDEA|AES>", "New key crypto algorithm"),
        arg_str0(NULL, "newkey",  "<hex>", "New key (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "newver",  "<hex>", "Version of new key (1 hex byte)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t id = 0x000000;
    DesfireISOSelectWay selectway = ISW6bAID;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, &securechann, DCMEncrypted, &id, &selectway);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    int oldkeytype = dctx.keyType;
    if (CLIGetOptionList(arg_get_str(ctx, 13), DesfireAlgoOpts, &oldkeytype)) {
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    uint8_t oldkey[DESFIRE_MAX_KEY_SIZE] = {0};
    uint8_t keydata[200] = {0};
    int oldkeylen = sizeof(keydata);
    CLIGetHexWithReturn(ctx, 14, keydata, &oldkeylen);
    if (oldkeylen && oldkeylen != desfire_get_key_length(oldkeytype)) {
        PrintAndLogEx(ERR, "%s old key must have %d bytes length instead of %d.", CLIGetOptionListStr(DesfireAlgoOpts, oldkeytype), desfire_get_key_length(oldkeytype), oldkeylen);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    if (oldkeylen)
        memcpy(oldkey, keydata, oldkeylen);

    uint8_t newkeynum = arg_get_int_def(ctx, 15, 0);

    int newkeytype = oldkeytype;
    if (CLIGetOptionList(arg_get_str(ctx, 16), DesfireAlgoOpts, &newkeytype)) {
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    uint8_t newkey[DESFIRE_MAX_KEY_SIZE] = {0};
    memset(keydata, 0x00, sizeof(keydata));
    int keylen = sizeof(keydata);
    CLIGetHexWithReturn(ctx, 17, keydata, &keylen);
    if (keylen && keylen != desfire_get_key_length(newkeytype)) {
        PrintAndLogEx(ERR, "%s new key must have %d bytes length instead of %d.", CLIGetOptionListStr(DesfireAlgoOpts, newkeytype), desfire_get_key_length(newkeytype), keylen);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    if (keylen)
        memcpy(newkey, keydata, keylen);

    uint32_t newkeyver = 0x100;
    if (CLIGetUint32Hex(ctx, 18, 0x100, &newkeyver, NULL, 1, "Key version must have 1 bytes length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    // if we change the same key
    if (oldkeylen == 0 && newkeynum == dctx.keyNum) {
        oldkeytype = dctx.keyType;
        memcpy(oldkey, dctx.key, desfire_get_key_length(dctx.keyType));
    }

    if (DesfireMFSelected(selectway, id)) {
        if (verbose)
            PrintAndLogEx(WARNING, "Changing the PICC level keys");
        PrintAndLogEx(INFO, _CYAN_("Changing PICC key"));
    } else {
        PrintAndLogEx(INFO, _CYAN_("Changing key for ") _YELLOW_("%s"), DesfireWayIDStr(selectway, id));
    }

    PrintAndLogEx(INFO, "auth key %d: %s [%d] %s", dctx.keyNum, CLIGetOptionListStr(DesfireAlgoOpts, dctx.keyType), desfire_get_key_length(dctx.keyType), sprint_hex(dctx.key, desfire_get_key_length(dctx.keyType)));
    PrintAndLogEx(INFO, "changing key number  " _YELLOW_("0x%02x") " (%d)", newkeynum, newkeynum);
    PrintAndLogEx(INFO, "old key: %s [%d] %s", CLIGetOptionListStr(DesfireAlgoOpts, oldkeytype), desfire_get_key_length(oldkeytype), sprint_hex(oldkey, desfire_get_key_length(oldkeytype)));
    PrintAndLogEx(INFO, "new key: %s [%d] %s", CLIGetOptionListStr(DesfireAlgoOpts, newkeytype), desfire_get_key_length(newkeytype), sprint_hex(newkey, desfire_get_key_length(newkeytype)));
    if (newkeyver < 0x100 || newkeytype == T_AES)
        PrintAndLogEx(INFO, "new key version: 0x%02x", newkeyver & 0x00);

    res = DesfireSelectAndAuthenticateAppW(&dctx, securechann, selectway, id, false, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(FAILED, "Select or authentication %s " _RED_("failed") ". Result [%d] %s", DesfireWayIDStr(selectway, id), res, DesfireAuthErrorToStr(res));
        return res;
    }

    DesfireSetCommMode(&dctx, DCMEncryptedPlain);
    res = DesfireChangeKey(&dctx, (DesfireMFSelected(selectway, id)) && (newkeynum == 0) && (dctx.keyNum == 0), newkeynum, newkeytype, newkeyver, newkey, oldkeytype, oldkey, true);
    if (res == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Change key ( " _GREEN_("ok") " )");
    } else {
        PrintAndLogEx(FAILED, "Change key ( " _RED_("failed") " )");
    }
    DesfireSetCommMode(&dctx, DCMEncrypted);

    DropField();
    return res;
}

static int CmdHF14ADesCreateApp(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes createapp",
                  "Create application. Master key needs to be provided.",
                  "option rawdata have priority over the rest settings, and options ks1 and ks2 have priority over corresponded key settings\n"
                  "\n"\
                  "KeySetting 1 (AMK Setting, ks1):\n"\
                  "  0:   Allow change master key. 1 - allow, 0 - frozen\n"\
                  "  1:   Free Directory list access without master key\n"\
                  "       0: AMK auth needed for GetFileSettings and GetKeySettings\n"\
                  "       1: No AMK auth needed for GetFileIDs, GetISOFileIDs, GetFileSettings, GetKeySettings\n"\
                  "  2:   Free create/delete without master key\n"\
                  "       0:  CreateFile/DeleteFile only with AMK auth\n"\
                  "       1:  CreateFile/DeleteFile always\n"\
                  "  3:   Configuration changeable\n"\
                  "       0: Configuration frozen\n"\
                  "       1: Configuration changeable if authenticated with AMK (default)\n"\
                  "  4-7: ChangeKey Access Rights\n"\
                  "       0: Application master key needed (default)\n"\
                  "       0x1..0xD: Auth with specific key needed to change any key\n"\
                  "       0xE: Auth with the key to be changed (same KeyNo) is necessary to change a key\n"\
                  "       0xF: All Keys within this application are frozen\n"\
                  "\n"\
                  "KeySetting 2 (ks2):\n"\
                  "  0..3: Number of keys stored within the application (max. 14 keys)\n"\
                  "  4:    ks3 is present\n"\
                  "  5:    Use of 2 byte ISO FID, 0: No, 1: Yes\n"\
                  "  6..7: Crypto Method 00: DES|2TDEA, 01: 3TDEA, 10: AES, 11: RFU\n"\
                  "  Example:\n"\
                  "       2E = with FID, DES|2TDEA, 14 keys\n"\
                  "       6E = with FID, 3TDEA, 14 keys\n"\
                  "       AE = with FID, AES, 14 keys\n"\
                  "\n"\
                  "hf mfdes createapp --rawdata 5634122F2E4523616964313233343536      -> execute create by rawdata\n"\
                  "hf mfdes createapp --aid 123456 --fid 2345 --dfname aid123456      -> app aid, iso file id, and iso df name is specified\n"
                  "hf mfdes createapp --aid 123456 --fid 2345 --dfname aid123456 --dstalgo aes -> with algorithm for key AES");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "rawdata", "<hex>", "Raw data that sends to command"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID for create. Mandatory. (3 hex bytes, big endian)"),
        arg_str0(NULL, "fid",     "<hex>", "ISO file ID. Forbidden values: 0000 3F00, 3FFF, FFFF. (2 hex bytes, big endian)"),
        arg_str0(NULL, "dfname",  "<str>", "ISO DF Name (1..16 chars)"),
        arg_str0(NULL, "dfhex",   "<hex>", "ISO DF Name as hex (1..16 bytes)"),
        arg_str0(NULL, "ks1",     "<hex>", "Key settings 1 (1 hex byte). Application Master Key Settings (def: 0x0F)"),
        arg_str0(NULL, "ks2",     "<hex>", "Key settings 2 (1 hex byte). (def: 0x0E)"),
        arg_str0(NULL, "dstalgo", "<DES|2TDEA|3TDEA|AES>",  "Application key crypt algo (def: DES)"),
        arg_int0(NULL, "numkeys", "<dec>",  "Number of keys 0x00..0x0e (def: 0x0E)"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 12, 0, 0, &securechann, DCMMACed, &appid, NULL);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint8_t rawdata[250] = {0};
    int rawdatalen = sizeof(rawdata);
    CLIGetHexWithReturn(ctx, 11, rawdata, &rawdatalen);

    uint32_t fileid = 0x0000;
    bool fileidpresent = false;
    if (CLIGetUint32Hex(ctx, 13, 0x0000, &fileid, &fileidpresent, 2, "ISO file ID must have 2 bytes length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t dfname[32] = {0};
    int dfnamelen = 16;  // since max length is 16 chars we don't have to test for 32-1 null termination
    CLIGetStrWithReturn(ctx, 14, dfname, &dfnamelen);

    if (dfnamelen == 0) { // no text DF Name supplied
        dfnamelen = 16;
        CLIGetHexWithReturn(ctx, 15, dfname, &dfnamelen);
    }

    uint32_t ks1 = 0x0f;
    if (CLIGetUint32Hex(ctx, 16, 0x0f, &ks1, NULL, 1, "Key settings 1 must have 1 byte length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t ks2 = 0x0e;
    bool ks2present = false;
    if (CLIGetUint32Hex(ctx, 17, 0x0e, &ks2, &ks2present, 1, "Key settings 2 must have 1 byte length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int dstalgo = T_DES;
    if (CLIGetOptionList(arg_get_str(ctx, 18), DesfireAlgoOpts, &dstalgo)) {
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    int keycount = arg_get_int_def(ctx, 19, 0x0e);
    bool noauth = arg_get_lit(ctx, 20);

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    if (rawdatalen == 0 && appid == 0x000000) {
        PrintAndLogEx(ERR, "Creating the root aid (0x000000) is " _RED_("forbidden"));
        return PM3_ESOFT;
    }

    if (rawdatalen == 0 && (fileidpresent || (ks2 & 0x20) != 0) &&  fileid == 0x0000) {
        PrintAndLogEx(ERR, "Creating the application with ISO file ID 0x0000 is " _RED_("forbidden"));
        return PM3_ESOFT;
    }

    if (keycount > 0x0e || keycount < 1) {
        PrintAndLogEx(ERR, "Key count must be in the range 1..14");
        return PM3_ESOFT;
    }

    if (dfnamelen > 16) {
        PrintAndLogEx(ERR, "DF name must be a maximum of 16 bytes in length");
        return PM3_EINVARG;
    }

    res = DesfireSelectAndAuthenticateEx(&dctx, securechann, 0x000000, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    uint8_t data[250] = {0};
    size_t datalen = 0;
    if (rawdatalen > 0) {
        memcpy(data, rawdata, rawdatalen);
        datalen = rawdatalen;
    } else {
        DesfireAIDUintToByte(appid, &data[0]);
        data[3] = ks1 & 0xff;
        data[4] = ks2 & 0xff;

        if (!ks2present) {
            if (keycount > 0) {
                data[4] &= 0xf0;
                data[4] |= keycount & 0x0f;
            }
            uint8_t kt = DesfireKeyAlgoToType(dstalgo);
            data[4] &= 0x3f;
            data[4] |= (kt & 0x03) << 6;
        }

        datalen = 5;
        if (fileidpresent || (data[4] & 0x20) != 0) {
            Uint2byteToMemLe(&data[5], fileid);
            data[4] |= 0x20; // set bit FileID in the ks2
            memcpy(&data[7], dfname, dfnamelen);
            datalen = 7 + dfnamelen;
        }
    }

    if (verbose) {
        PrintAndLogEx(INFO, "---------------------------");
        PrintAndLogEx(INFO, _CYAN_("Creating Application using:"));
        PrintAndLogEx(INFO, "AID          0x%02X%02X%02X", data[2], data[1], data[0]);
        PrintAndLogEx(INFO, "Key Set 1    0x%02X", data[3]);
        PrintAndLogEx(INFO, "Key Set 2    0x%02X", data[4]);
        PrintAndLogEx(INFO, "ISO file ID  %s", (data[4] & 0x20) ? "enabled" : "disabled");
        if ((data[4] & 0x20)) {
            PrintAndLogEx(INFO, "ISO file ID  0x%04x", MemLeToUint2byte(&data[5]));
            PrintAndLogEx(INFO, "DF Name[%02d]  %s | %s\n", dfnamelen, sprint_ascii(dfname, dfnamelen), sprint_hex(dfname, dfnamelen));
        }
        PrintKeySettings(data[3], data[4], true, true);
        PrintAndLogEx(INFO, "---------------------------");
    }

    res = DesfireCreateApplication(&dctx, data, datalen);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire CreateApplication command " _RED_("error") ". Result: %d", res);
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Desfire application %06x successfully " _GREEN_("created"), appid);

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesCreateDelegateApp(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes createdelegateapp",
                  "Create delegated application (CreateDelegatedApplication / 0xC9). Master key needs to be provided.",
                  "Command is built from fields and sends two frames: C9 + AF continuation.\n"
                  "Authentication is always performed with DAM key number 0x10.\n"
                  "EncK and DAMMAC are calculated from supplied key material.\n"
                  "\n"
                  "Structured mode examples:\n"
                  "hf mfdes createdelegateapp --aid 123456 --damslot 0001 --damslotver 00 --quota 0010 --ks1 0F --ks2 AE --algo 2TDEA --key 00000000000000000000000000000000 --damenckey 00112233445566778899AABBCCDDEEFF --dammackey 8899AABBCCDDEEFF0011223344556677 --dstkey 00112233445566778899AABBCCDDEEFF --dstkeyver 00\n"
                  "hf mfdes createdelegateapp --aid 123456 --damslot 0001 --quota 0010 --ks1 0F --dstalgo aes --numkeys 14 --ks3 01 --fid E110 --dfname D2760000850101 --algo 2TDEA --key 00000000000000000000000000000000 --damenckey 00112233445566778899AABBCCDDEEFF --dammackey 8899AABBCCDDEEFF0011223344556677 --dstkey 00112233445566778899AABBCCDDEEFF --dstkeyver 00");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID for create. Mandatory in structured mode. (3 hex bytes, big endian)"),
        arg_str0(NULL, "damslot", "<hex>", "DAM slot number (2 hex bytes, little endian on card)"),
        arg_str0(NULL, "damslotver", "<hex>", "DAM slot version (1 hex byte, def: 00)"),
        arg_str0(NULL, "quota",   "<hex>", "Quota in blocks (2 hex bytes, little endian on card, def: 0000)"),
        arg_str0(NULL, "ks1",     "<hex>", "Key settings 1 (1 hex byte, def: 0x0F)"),
        arg_str0(NULL, "ks2",     "<hex>", "Key settings 2 (1 hex byte, def: 0x0E)"),
        arg_str0(NULL, "ks3",     "<hex>", "Key settings 3 (1 hex byte, optional)"),

        arg_str0(NULL, "fid",     "<hex>", "ISO file ID (2 hex bytes, big endian), optional"),
        arg_str0(NULL, "dfname",  "<hex>", "ISO DF Name (1..16 bytes, hex), optional"),

        arg_str0(NULL, "dstalgo", "<DES|2TDEA|3TDEA|AES>",  "Application key crypt algo (used when ks2 omitted, def: DES)"),
        arg_int0(NULL, "numkeys", "<dec>",  "Number of keys 0x01..0x0e (used when ks2 omitted, def: 0x01)"),
        arg_str0(NULL, "damenckey", "<hex>", "DAM ENC key (16 bytes for AES/2TDEA, 24 bytes for 3TDEA)"),
        arg_str0(NULL, "dammackey", "<hex>", "DAM MAC key (16 bytes for AES/2TDEA, 24 bytes for 3TDEA)"),
        arg_str0(NULL, "dstkey", "<hex>", "Initial delegated-app key (16 bytes for 2TDEA/AES, 24 bytes for 3TDEA)"),
        arg_str0(NULL, "dstkeyver", "<hex>", "Initial delegated-app key version (1 hex byte, def: 00)"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 0, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, &securechann, DCMMACed, &appid, NULL);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    dctx.keyNum = 0x10;

    uint32_t damslot = 0x0000;
    bool damslotpresent = false;
    if (CLIGetUint32Hex(ctx, 11, 0x0000, &damslot, &damslotpresent, 2, "DAM slot number must have 2 bytes length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t damslotver = 0x00;
    if (CLIGetUint32Hex(ctx, 12, 0x00, &damslotver, NULL, 1, "DAM slot version must have 1 byte length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t quota = 0x0000;
    if (CLIGetUint32Hex(ctx, 13, 0x0000, &quota, NULL, 2, "Quota must have 2 bytes length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t ks1 = 0x0f;
    if (CLIGetUint32Hex(ctx, 14, 0x0f, &ks1, NULL, 1, "Key settings 1 must have 1 byte length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t ks2 = 0x0e;
    bool ks2present = false;
    if (CLIGetUint32Hex(ctx, 15, 0x0e, &ks2, &ks2present, 1, "Key settings 2 must have 1 byte length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t ks3 = 0x00;
    bool ks3present = false;
    if (CLIGetUint32Hex(ctx, 16, 0x00, &ks3, &ks3present, 1, "Key settings 3 must have 1 byte length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t fileid = 0x0000;
    bool fileidpresent = false;
    if (CLIGetUint32Hex(ctx, 17, 0x0000, &fileid, &fileidpresent, 2, "ISO file ID must have 2 bytes length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t dfname[32] = {0};
    int dfnamelen = 16;
    CLIGetHexWithReturn(ctx, 18, dfname, &dfnamelen);
    if (dfnamelen > 16) {
        CLIParserFree(ctx);
        PrintAndLogEx(ERR, "DF name must be a maximum of 16 bytes in length");
        return PM3_EINVARG;
    }

    int dstalgo = T_DES;
    if (CLIGetOptionList(arg_get_str(ctx, 19), DesfireAlgoOpts, &dstalgo)) {
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    int keycount = arg_get_int_def(ctx, 20, 0x01);

    uint8_t damenc[DESFIRE_MAX_KEY_SIZE] = {0};
    int damenclen = sizeof(damenc);
    CLIGetHexWithReturn(ctx, 21, damenc, &damenclen);

    uint8_t mac_key[DESFIRE_MAX_KEY_SIZE] = {0};
    int mac_key_len = sizeof(mac_key);
    CLIGetHexWithReturn(ctx, 22, mac_key, &mac_key_len);

    uint8_t dstkey[DESFIRE_MAX_KEY_SIZE] = {0};
    int dstkeylen = sizeof(dstkey);
    CLIGetHexWithReturn(ctx, 23, dstkey, &dstkeylen);

    uint32_t dstkeyver = 0x00;
    if (CLIGetUint32Hex(ctx, 24, 0x00, &dstkeyver, NULL, 1, "Delegated-app key version must have 1 byte length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool noauth = arg_get_lit(ctx, 25);

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    uint8_t data[250] = {0};
    size_t datalen = 0;
    uint8_t contdata[250] = {0};
    size_t contdatalen = 0;

    if (appid == 0x000000) {
        PrintAndLogEx(ERR, "Creating the root aid (0x000000) is " _RED_("forbidden"));
        return PM3_ESOFT;
    }

    if (!damslotpresent) {
        PrintAndLogEx(ERR, "DAM slot number is mandatory");
        return PM3_EINVARG;
    }

    if (keycount > 0x0e || keycount < 1) {
        PrintAndLogEx(ERR, "Key count must be in the range 1..14");
        return PM3_EINVARG;
    }

    if (dfnamelen > 0 && !fileidpresent) {
        PrintAndLogEx(ERR, "ISO DF Name requires --fid");
        return PM3_EINVARG;
    }

    DesfireCryptoAlgorithm damalgo = dctx.keyType;
    if (damalgo != T_3DES && damalgo != T_3K3DES && damalgo != T_AES) {
        PrintAndLogEx(ERR, "DAM keys support only --algo 2TDEA, 3TDEA or AES");
        return PM3_EINVARG;
    }

    int expecteddamkeylen = desfire_get_key_length(damalgo);

    if (damenclen != expecteddamkeylen) {
        PrintAndLogEx(ERR, "DAM ENC key must have exactly %d bytes for --algo %s", expecteddamkeylen, CLIGetOptionListStr(DesfireAlgoOpts, damalgo));
        return PM3_EINVARG;
    }

    if (mac_key_len != expecteddamkeylen) {
        PrintAndLogEx(ERR, "DAM MAC key must have exactly %d bytes for --algo %s", expecteddamkeylen, CLIGetOptionListStr(DesfireAlgoOpts, damalgo));
        return PM3_EINVARG;
    }

    if (dstkeylen == 0) {
        PrintAndLogEx(ERR, "Initial delegated-app key is mandatory");
        return PM3_EINVARG;
    }

    DesfireAIDUintToByte(appid, &data[0]);
    Uint2byteToMemLe(&data[3], damslot & 0xffff);
    data[5] = damslotver & 0xff;
    Uint2byteToMemLe(&data[6], quota & 0xffff);
    data[8] = ks1 & 0xff;
    data[9] = ks2 & 0xff;

    if (!ks2present) {
        data[9] &= 0xf0;
        data[9] |= keycount & 0x0f;
        uint8_t kt = DesfireKeyAlgoToType(dstalgo);
        data[9] &= 0x3f;
        data[9] |= (kt & 0x03) << 6;
    }

    datalen = 10;

    if (ks3present) {
        data[9] |= 0x10;
        data[datalen++] = ks3 & 0xff;
    }

    if (fileidpresent) {
        Uint2byteToMemLe(&data[datalen], fileid & 0xffff);
        datalen += 2;
        if (dfnamelen > 0) {
            memcpy(&data[datalen], dfname, dfnamelen);
            datalen += dfnamelen;
        }
    }

    if (datalen > DESFIRE_TX_FRAME_MAX_LEN) {
        PrintAndLogEx(ERR, "First frame is too long (%zu > %d)", datalen, DESFIRE_TX_FRAME_MAX_LEN);
        return PM3_EINVARG;
    }

    uint8_t keytype = (data[9] >> 6) & 0x03;
    int expecteddstkeylen = desfire_get_key_length(DesfireKeyTypeToAlgo(keytype));

    if (dstkeylen != expecteddstkeylen) {
        PrintAndLogEx(ERR, "Initial delegated-app key length must be %d bytes for key type 0x%02x (got %d)", expecteddstkeylen, keytype, dstkeylen);
        return PM3_EINVARG;
    }

    uint8_t cryptogram[32] = {0};
    uint8_t cryptogram_plain[32] = {0};
    // Delegated app key blob format:
    // 7-byte random prefix + dst key + dst key version, then zero padding to 32 bytes.
    for (size_t i = 0; i < 7; i++) {
        cryptogram_plain[i] = (uint8_t)(rand() & 0xFF);
    }
    memcpy(&cryptogram_plain[7], dstkey, dstkeylen);
    cryptogram_plain[7 + dstkeylen] = dstkeyver & 0xFF;

    DesfireContext_t damctx = {0};
    DesfireSetKey(&damctx, 0, damalgo, damenc);
    uint8_t cryptogram_iv[DESFIRE_MAX_CRYPTO_BLOCK_SIZE] = {0};
    DesfireCryptoEncDecEx(&damctx, DCOMainKey, cryptogram_plain, sizeof(cryptogram_plain), cryptogram, true, true, cryptogram_iv);

    uint8_t mac_input[1 + DESFIRE_TX_FRAME_MAX_LEN + sizeof(cryptogram)] = {0};
    size_t mac_input_len = 1 + datalen + sizeof(cryptogram);
    mac_input[0] = MFDES_CREATE_DELEGATE_APP;
    memcpy(&mac_input[1], data, datalen);
    memcpy(&mac_input[1 + datalen], cryptogram, sizeof(cryptogram));

    uint8_t mac[8] = {0};
    uint8_t fullcmac[DESFIRE_MAX_CRYPTO_BLOCK_SIZE] = {0};
    DesfireSetKey(&damctx, 0, damalgo, mac_key);
    DesfireClearIV(&damctx);
    DesfireCryptoCMACEx(&damctx, DCOMainKey, mac_input, mac_input_len, 0, fullcmac);
    if (damalgo == T_AES) {
        for (size_t i = 0; i < sizeof(mac); i++) {
            mac[i] = fullcmac[i * 2 + 1];
        }
    } else {
        memcpy(mac, fullcmac, sizeof(mac));
    }

    memcpy(contdata, cryptogram, sizeof(cryptogram));
    memcpy(&contdata[sizeof(cryptogram)], mac, sizeof(mac));
    contdatalen = sizeof(cryptogram) + sizeof(mac);

    if (contdatalen > DESFIRE_TX_FRAME_MAX_LEN) {
        PrintAndLogEx(ERR, "Continuation frame is too long (%zu > %d)", contdatalen, DESFIRE_TX_FRAME_MAX_LEN);
        return PM3_EINVARG;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "---------------------------");
        PrintAndLogEx(INFO, _CYAN_("Creating Delegated Application using:"));
        PrintAndLogEx(INFO, "AID             0x%02X%02X%02X", data[2], data[1], data[0]);
        PrintAndLogEx(INFO, "DAM algo        %s", CLIGetOptionListStr(DesfireAlgoOpts, damalgo));
        if (datalen >= 10) {
            PrintAndLogEx(INFO, "DAM slot        0x%04x", MemLeToUint2byte(&data[3]));
            PrintAndLogEx(INFO, "DAM slot ver    0x%02x", data[5]);
            PrintAndLogEx(INFO, "Quota           0x%04x (%d units)", MemLeToUint2byte(&data[6]), MemLeToUint2byte(&data[6]));
            PrintAndLogEx(INFO, "Key Set 1       0x%02X", data[8]);
            PrintAndLogEx(INFO, "Key Set 2       0x%02X", data[9]);
            PrintKeySettings(data[8], data[9], true, true);
        }
        PrintAndLogEx(INFO, "Part1 payload   [%zu]  %s", datalen, sprint_hex(data, datalen));
        PrintAndLogEx(INFO, "Cryptogram      %s", sprint_hex(cryptogram, sizeof(cryptogram)));
        PrintAndLogEx(INFO, "MAC             %s", sprint_hex(mac, sizeof(mac)));
        PrintAndLogEx(INFO, "Part2 payload   [%zu]  %s", contdatalen, sprint_hex(contdata, contdatalen));
        PrintAndLogEx(INFO, "---------------------------");
    }

    res = DesfireSelectAndAuthenticateEx(&dctx, securechann, 0x000000, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    res = DesfireCreateDelegatedApplication(&dctx, data, datalen, contdata, contdatalen);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire CreateDelegatedApplication command " _RED_("error") ". Result: %d", res);
        DropField();
        return res;
    }

    PrintAndLogEx(SUCCESS, "Desfire delegated application %06x successfully " _GREEN_("created"), MemLeToUint3byte(data));

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesGetDelegateAppInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes getdelegateappinfo",
                  "Get delegated application information for DAM slot (GetDelegatedInfo / 0x69).",
                  "By default authentication is performed with PICC key number 0x00.\n"
                  "Use --keyno to pick another key number, or --no-auth to skip authentication.\n"
                  "hf mfdes getdelegateappinfo --damslot 0001 --algo 2TDEA --key 00000000000000000000000000000000\n"
                  "hf mfdes getdelegateappinfo --damslot 0001 --no-auth");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number (default: 0 / PICC key)"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "damslot", "<hex>", "DAM slot number (2 hex bytes, little endian on card)"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 12);

    int keynum = arg_get_int_def(ctx, 3, 0x00);
    if (keynum < 0 || keynum > 0xFF) {
        CLIParserFree(ctx);
        PrintAndLogEx(ERR, "Key number must be in range 0..255");
        return PM3_EINVARG;
    }

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 0, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, &securechann, (noauth) ? DCMPlain : DCMMACed, NULL, NULL);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    dctx.keyNum = keynum & 0xFF;

    uint32_t damslot = 0x0000;
    bool damslotpresent = false;
    if (CLIGetUint32Hex(ctx, 11, 0x0000, &damslot, &damslotpresent, 2, "DAM slot number must have 2 bytes length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    if (!damslotpresent) {
        PrintAndLogEx(ERR, "DAM slot number is mandatory");
        return PM3_EINVARG;
    }

    res = DesfireSelectAndAuthenticateEx(&dctx, securechann, 0x000000, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    uint8_t resp[16] = {0};
    size_t resplen = 0;
    res = DesfireGetDelegatedInfoNoFieldOn(&dctx, damslot & 0xffff, resp, &resplen);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire GetDelegatedInfo command " _RED_("error") ". Result: %d", res);
        DropField();
        return PM3_ESOFT;
    }

    if (verbose)
        PrintAndLogEx(SUCCESS, "received data[%zu]: %s", resplen, sprint_hex(resp, resplen));

    uint16_t quota = MemLeToUint2byte(&resp[1]);
    uint16_t freeblocks = MemLeToUint2byte(&resp[3]);
    uint32_t delegatedaid = MemLeToUint3byte(&resp[5]);

    PrintAndLogEx(SUCCESS, "DAM slot....... 0x%04x", damslot & 0xffff);
    PrintAndLogEx(SUCCESS, "DAM slot ver... 0x%02x", resp[0]);
    PrintAndLogEx(SUCCESS, "Quota limit.... 0x%04x (%u blocks)", quota, (unsigned int)quota);
    PrintAndLogEx(SUCCESS, "Free blocks.... 0x%04x (%u blocks)", freeblocks, (unsigned int)freeblocks);
    PrintAndLogEx(SUCCESS, "Delegated AID.. 0x%06x", delegatedaid);

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesDeleteApp(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes deleteapp",
                  "Delete application by its 3-byte AID. Master key needs to be provided. ",
                  "hf mfdes deleteapp --aid 123456    -> execute with default factory setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID to delete (3 hex bytes, big endian)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, &securechann, DCMMACed, &appid, NULL);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    if (appid == 0x000000) {
        PrintAndLogEx(WARNING, "Deleting the root aid (0x000000) is " _RED_("forbidden"));
        return PM3_ESOFT;
    }

    res = DesfireSelectAndAuthenticate(&dctx, securechann, 0x000000, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    res = DesfireDeleteApplication(&dctx, appid);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire DeleteApplication command " _RED_("error") ". Result: %d", res);
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Desfire application %06x " _GREEN_("deleted"), appid);

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesGetUID(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes getuid",
                  "Get UID from card. Get the real UID if the random UID bit is on and get the same UID as in anticollision if not. Any card's key needs to be provided. ",
                  "hf mfdes getuid                              -> execute with default factory setup\n"
                  "hf mfdes getuid --isoid df01 -t aes --schan lrp   -> for desfire lights default settings\n"
                  "hf mfdes getuid --dfname D2760000850100 -> select DF by name and get UID");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "isoid",   "<hex>", "Application ISO ID (ISO DF ID) (2 hex bytes, big endian)"),
        arg_str0(NULL, "dfname",  "<hex>", "Application ISO DF Name (5-16 hex bytes, big endian)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t id = 0x000000;
    DesfireISOSelectWay selectway = ISW6bAID;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, &securechann, DCMEncrypted, &id, &selectway);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    res = DesfireSelectAndAuthenticateAppW(&dctx, securechann, selectway, id, false, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(FAILED, "Select or authentication %s " _RED_("failed") ". Result [%d] %s", DesfireWayIDStr(selectway, id), res, DesfireAuthErrorToStr(res));
        return res;
    }

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t buflen = 0;

    res = DesfireGetUID(&dctx, buf, &buflen);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire GetUID command " _RED_("error") ". Result: %d", res);
        DropField();
        return PM3_ESOFT;
    }

    if (verbose)
        PrintAndLogEx(SUCCESS, "received data[%zu]: %s", buflen, sprint_hex(buf, buflen));

    if (buflen > 0) {
        if (buf[0] != 0) {
            PrintAndLogEx(SUCCESS, "Desfire UID[%zu]: " _GREEN_("%s"), buflen, sprint_hex(buf, buflen));
        } else {
            if (buf[1] == 0x04) {
                PrintAndLogEx(SUCCESS, "Desfire UID4: " _GREEN_("%s"), sprint_hex(&buf[2], 4));
            } else if (buf[1] == 0x0a) {
                PrintAndLogEx(SUCCESS, "Desfire UID10: " _GREEN_("%s"), sprint_hex(&buf[2], 10));
            } else {
                PrintAndLogEx(WARNING, "Card returned wrong uid length: %d (0x%02x)", buf[1], buf[1]);
            }
        }
    } else {
        PrintAndLogEx(WARNING, "Card returned no data");
    }

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesPC(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes pc",
                  "Perform DESFire proximity check flow (Prepare_PC -> Proximity_Check -> Verify_PC).\n"
                  "This command uses plain communication with a dedicated 16-byte AES proximity key.",
                  "hf mfdes pc --key 00000000000000000000000000000000\n"
                  "hf mfdes pc --key 00112233445566778899aabbccddeeff --rounds 4\n"
                  "hf mfdes pc --key 00112233445566778899aabbccddeeff -c native -a");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",   "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_str1("k",  "key",    "<hex>", "Key (AES-128, exactly 16 bytes)"),
        arg_int0("r",  "rounds", "<dec>", "Number of rounds (1..8), default 8"),
        arg_str0("c",  "ccset",  "<native|niso>", "Communication command set (default from `hf mfdes default`)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    uint8_t proximity_key[MFDES_PC_KEY_LEN] = {0};
    int proximity_key_len = 0;
    CLIGetHexWithReturn(ctx, 3, proximity_key, &proximity_key_len);
    if (proximity_key_len != MFDES_PC_KEY_LEN) {
        PrintAndLogEx(ERR, "Proximity key must have 16 bytes length.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int rounds = arg_get_int_def(ctx, 4, MFDES_PC_MAX_ROUNDS);
    if (rounds < 1 || rounds > MFDES_PC_MAX_ROUNDS) {
        PrintAndLogEx(ERR, "Rounds must be in range 1..8.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int cmdset = defaultCommSet;
    if (CLIGetOptionList(arg_get_str(ctx, 5), DesfireCommandSetOpts, &cmdset)) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    if (cmdset == DCCISO) {
        PrintAndLogEx(ERR, "`ccset=iso` is not supported for this command. Use `native` or `niso`.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    DesfireContext_t dctx = {0};
    DesfireSetCommandSet(&dctx, cmdset);
    DesfireSetCommMode(&dctx, DCMPlain);
    DesfireSetSecureChannel(&dctx, DACNone);

    int res = DesfirePCRun(&dctx, proximity_key, rounds, verbose);
    DropField();
    return res;
}

static int CmdHF14ADesFormatPICC(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes formatpicc",
                  "Format card. Can be done only if enabled in the configuration. Master key needs to be provided. ",
                  "hf mfdes formatpicc    -> execute with default factory setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID of delegated application (3 hex bytes, big endian)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, &securechann, DCMMACed, &appid, NULL);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    res = DesfireSelectAndAuthenticate(&dctx, securechann, appid, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    res = DesfireFormatPICC(&dctx);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire FormatPICC command " _RED_("error") ". Result: %d", res);
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Desfire format: " _GREEN_("done!"));

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesGetFreeMem(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes getfreemem",
                  "Get card's free memory. Can be done with or without authentication. Master key may be provided.",
                  "hf mfdes getfreemem    -> execute with default factory setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_str0(NULL, "dfname",  "<hex>", "Application ISO DF Name (5-16 hex bytes, big endian)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    bool noauth = arg_get_lit(ctx, 11);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t id = 0x000000;
    DesfireISOSelectWay selectway = ISW6bAID;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 12, &securechann, (noauth) ? DCMPlain : DCMMACed, &id, &selectway);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    res = DesfireSelectAndAuthenticateAppW(&dctx, securechann, selectway, id, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    uint32_t freemem = 0;

    res = DesfireGetFreeMem(&dctx, &freemem);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire GetFreeMem command " _RED_("error") ". Result: %d", res);
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Free memory [0x%06x] %d bytes", freemem, freemem);

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesChKeySettings(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes chkeysettings",
                  "Change key settings for card level or application level.\n"
                  "WARNING: card level changes may block the card!",
                  "hf mfdes chkeysettings -d 0f         -> set picc key settings with default key/channel setup\n"\
                  "hf mfdes chkeysettings --aid 123456 -d 0f     -> set app 123456 key settings with default key/channel setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0("d",  "data",    "<HEX>", "Key settings (1 hex byte)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, &securechann, DCMEncrypted, &appid, NULL);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint32_t ksett32 = 0;
    if (CLIGetUint32Hex(ctx, 12, 0x0f, &ksett32, NULL, 1, "Key settings must have 1 byte length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    if (verbose) {
        PrintAndLogEx(SUCCESS, "\nNew key settings:");
        PrintKeySettings(ksett32, 0, (appid != 0x000000), false);
    }

    res = DesfireSelectAndAuthenticate(&dctx, securechann, appid, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    uint8_t keysett = ksett32 & 0xff;
    res = DesfireChangeKeySettings(&dctx, &keysett, 1);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire ChangeKeySettings command " _RED_("error") ". Result: %d", res);
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "Key settings " _GREEN_("changed"));

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesGetKeyVersions(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes getkeyversions",
                  "Get key versions for card level or application level.",
                  "--keynum parameter: App level: key number. PICC level: 00..0d - keys count, 21..23 vc keys, default 0x00.\n"\
                  "hf mfdes getkeyversions --keynum 00    -> get picc master key version with default key/channel setup\n"\
                  "hf mfdes getkeyversions --aid 123456 --keynum 0d    -> get app 123456 all key versions with default key/channel setup\n"
                  "hf mfdes getkeyversions --aid 123456 --keynum 0d --no-auth    -> get key version without authentication\n"\
                  "hf mfdes getkeyversions --dfname D2760000850100 --keynum 00 -> select DF by name and get key versions");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number for authentication"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "isoid",   "<hex>", "Application ISO ID (ISO DF ID) (2 hex bytes, big endian)."),
        arg_str0(NULL, "dfname",  "<hex>", "Application ISO DF Name (5-16 hex bytes, big endian)"),
        arg_str0(NULL, "keynum",  "<hex>", "Key number/count (1 hex byte). (def: 0x00)"),
        arg_str0(NULL, "keyset",  "<hex>", "Keyset number (1 hex byte)"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),

        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 16);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t id = 0x000000;
    DesfireISOSelectWay selectway = ISW6bAID;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, &securechann, DCMMACed, &id, &selectway);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint32_t keynum32 = 0x00;
    if (CLIGetUint32Hex(ctx, 14, 0x00, &keynum32, NULL, 1, "Key number must have 1 byte length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t keysetnum32 = 0x00;
    bool keysetpresent = false;
    if (CLIGetUint32Hex(ctx, 15, 0x00, &keysetnum32, &keysetpresent, 1, "Keyset number must have 1 byte length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    if (keysetpresent && DesfireMFSelected(selectway, id)) {
        PrintAndLogEx(WARNING, "Keyset only at Application level");
        keysetpresent = false;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    res = DesfireSelectAndAuthenticateAppW(&dctx, securechann, selectway, id, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(FAILED, "Select or authentication %s " _RED_("failed") ". Result [%d] %s", DesfireWayIDStr(selectway, id), res, DesfireAuthErrorToStr(res));
        return res;
    }

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t buflen = 0;

    uint8_t data[2] = {0};
    data[0] = keynum32 & 0xff;
    if (keysetpresent) {
        data[0] |= 0x40;
        data[1] = keysetnum32 & 0xff;
    }

    res = DesfireGetKeyVersion(&dctx, data, (keysetpresent) ? 2 : 1, buf, &buflen);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire GetKeyVersion command " _RED_("error") ". Result: %d", res);
        DropField();
        return PM3_ESOFT;
    }

    if (verbose)
        PrintAndLogEx(INFO, "GetKeyVersion[%zu]: %s", buflen, sprint_hex(buf, buflen));

    if (buflen > 0) {
        PrintAndLogEx(INFO, "----------------------- " _CYAN_("Key Versions") " -----------------------");
        for (int i = 0; i < buflen; i++)
            PrintAndLogEx(INFO, "Key 0x%02x version 0x%02x", i, buf[i]);
    } else {
        PrintAndLogEx(INFO, "No key versions returned.");
    }

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesGetKeySettings(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes getkeysettings",
                  "Get key settings for card level or application level.",
                  "hf mfdes getkeysettings  -> get picc key settings with default key/channel setup\n"\
                  "hf mfdes getkeysettings --aid 123456 -> get app 123456 key settings with default key/channel setup\n"\
                  "hf mfdes getkeysettings --dfname D2760000850100 -> select DF by name and get key settings");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "dfname",  "<hex>", "Application ISO DF Name (5-16 hex bytes, big endian)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    DesfireISOSelectWay selectway = ISW6bAID;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 12, &securechann, DCMMACed, &appid, &selectway);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    res = DesfireSelectAndAuthenticate(&dctx, securechann, appid, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t buflen = 0;

    res = DesfireGetKeySettings(&dctx, buf, &buflen);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire GetKeySettings command " _RED_("error") ". Result: %d", res);
        DropField();
        return PM3_ESOFT;
    }

    if (verbose)
        PrintAndLogEx(INFO, "GetKeySettings[%zu]: %s", buflen, sprint_hex(buf, buflen));

    if (buflen < 2) {
        PrintAndLogEx(ERR, "Command GetKeySettings returned wrong length: %zu", buflen);
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "----------------------- " _CYAN_("Key settings") " -----------------------");
    PrintKeySettings(buf[0], buf[1], (appid != 0x000000), true);
    if (buflen > 2)
        PrintAndLogEx(INFO, "ak ver: %d", buf[2]);
    if (buflen > 3)
        PrintAndLogEx(INFO, "num keysets: %d", buf[3]);
    if (buflen > 4)
        PrintAndLogEx(INFO, "max keysize: %d", buf[4]);
    if (buflen > 5)
        PrintAndLogEx(INFO, "app key settings: 0x%02x", buf[5]);

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesGetAIDs(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes getaids",
                  "Get Application IDs list from card. Master key needs to be provided or flag --no-auth set.",
                  "hf mfdes getaids -n 0 -t des -k 0000000000000000 --kdf none -> execute with default factory setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 11);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, &securechann, DCMMACed, NULL, NULL);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    res = DesfireSelectAndAuthenticateEx(&dctx, securechann, 0x000000, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t buflen = 0;

    res = DesfireGetAIDList(&dctx, buf, &buflen);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire GetAIDList command " _RED_("error") ". Result: %d", res);
        DropField();
        return PM3_ESOFT;
    }

    if (buflen >= 3) {

        uint8_t j = (buflen / 3);
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(SUCCESS, "--- " _CYAN_("AID list")  " ( " _YELLOW_("%u") " found )", j);
        for (int i = 0; i < buflen; i += 3) {
            uint32_t aid  = DesfireAIDByteToUint(&buf[i]);
            PrintAndLogEx(SUCCESS, _YELLOW_("%06X") " %s", aid, getAidCommentStr(aid));
        }
        PrintAndLogEx(NORMAL, "");
    } else {
        PrintAndLogEx(INFO, "There is no applications on the card");
    }

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesGetAppNames(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes getappnames",
                  "Get Application IDs, ISO IDs and DF names from card. Master key needs to be provided or flag --no-auth set.",
                  "hf mfdes getappnames -n 0 -t des -k 0000000000000000 --kdf none   -> execute with default factory setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 11);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, &securechann, DCMMACed, NULL, NULL);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    res = DesfireSelectAndAuthenticateEx(&dctx, securechann, 0x000000, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t buflen = 0;

    // result bytes: 3, 2, 1-16. total record size = 24
    res = DesfireGetDFList(&dctx, buf, &buflen);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire GetDFList command " _RED_("error") ". Result: %d", res);
        DropField();
        return PM3_ESOFT;
    }

    if (buflen > 0) {
        PrintAndLogEx(INFO, "----------------------- " _CYAN_("File list") " -----------------------");
        for (int i = 0; i < buflen; i++)
            PrintAndLogEx(INFO, "AID: %06x ISO file id: %02x%02x ISO DF name[%zu]: %s",
                          DesfireAIDByteToUint(&buf[i * 24 + 1]),
                          buf[i * 24 + 1 + 3], buf[i * 24 + 1 + 4],
                          strlen((char *)&buf[i * 24 + 1 + 5]),
                          &buf[i * 24 + 1 + 5]);
    } else {
        PrintAndLogEx(INFO, "There is no applications on the card");
    }

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesGetFileIDs(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes getfileids",
                  "Get File IDs list from card. Master key needs to be provided or flag --no-auth set.",
                  "hf mfdes getfileids --aid 123456 -> execute with defaults from `default` command\n"
                  "hf mfdes getfileids -n 0 -t des -k 0000000000000000 --kdf none --aid 123456   -> execute with default factory setup\n"
                  "hf mfdes getfileids --dfname D2760000850100 -> select DF by name and get file IDs");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "isoid",   "<hex>", "Application ISO ID (ISO DF ID) (2 hex bytes, big endian)."),
        arg_str0(NULL, "dfname",  "<hex>", "Application ISO DF Name (5-16 hex bytes, big endian)"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 14);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t id = 0x000000;
    DesfireISOSelectWay selectway = ISW6bAID;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, &securechann, DCMMACed, &id, &selectway);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    res = DesfireSelectAndAuthenticateAppW(&dctx, securechann, selectway, id, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(FAILED, "Select or authentication %s " _RED_("failed") ". Result [%d] %s", DesfireWayIDStr(selectway, id), res, DesfireAuthErrorToStr(res));
        return res;
    }


    uint8_t buf[APDU_RES_LEN] = {0};
    size_t buflen = 0;

    res = DesfireGetFileIDList(&dctx, buf, &buflen);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire GetFileIDList command " _RED_("error") ". Result: %d", res);
        DropField();
        return PM3_ESOFT;
    }

    if (buflen > 0) {
        PrintAndLogEx(INFO, "---- " _CYAN_("File ID list") " ----");
        for (int i = 0; i < buflen; i++)
            PrintAndLogEx(INFO, "File ID: %02x", buf[i]);
    } else {
        PrintAndLogEx(INFO, "There are no files in the application %06x", id);
    }

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesGetFileISOIDs(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes getfileisoids",
                  "Get File IDs list from card. Master key needs to be provided or flag --no-auth set.",
                  "hf mfdes getfileisoids --aid 123456    -> execute with defaults from `default` command\n"
                  "hf mfdes getfileisoids -n 0 -t des -k 0000000000000000 --kdf none --aid 123456    -> execute with default factory setup\n"
                  "hf mfdes getfileisoids --isoid df01     -> get iso file ids from Desfire Light with factory card settings\n"
                  "hf mfdes getfileisoids --isoid df01 --schann lrp -t aes     -> get iso file ids from Desfire Light via lrp channel with default key authentication\n"
                  "hf mfdes getfileisoids --dfname D2760000850100 -> select DF by name and get file ISO IDs");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "isoid",   "<hex>", "Application ISO ID (ISO DF ID) (2 hex bytes, big endian)."),
        arg_str0(NULL, "dfname",  "<hex>", "Application ISO DF Name (5-16 hex bytes, big endian)"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 14);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t id = 0x000000;
    DesfireISOSelectWay selectway = ISW6bAID;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, &securechann, DCMMACed, &id, &selectway);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    res = DesfireSelectAndAuthenticateAppW(&dctx, securechann, selectway, id, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(FAILED, "Select or authentication %s " _RED_("failed") ". Result [%d] %s", DesfireWayIDStr(selectway, id), res, DesfireAuthErrorToStr(res));
        return res;
    }

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t buflen = 0;

    res = DesfireGetFileISOIDList(&dctx, buf, &buflen);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire GetFileISOIDList command " _RED_("error") ". Result: %d", res);
        DropField();
        return PM3_ESOFT;
    }

    if (buflen > 1) {
        PrintAndLogEx(INFO, "---- " _CYAN_("File ISO ID list") " ----");
        for (int i = 0; i < buflen; i += 2)
            PrintAndLogEx(INFO, "File ID: %04x", MemLeToUint2byte(&buf[i]));
    } else {
        PrintAndLogEx(INFO, "There are no files in the application %06x", id);
    }

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesGetFileSettings(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes getfilesettings",
                  "Get File Settings from file from application. Master key needs to be provided or flag --no-auth set (depend on cards settings).",
                  "hf mfdes getfilesettings --aid 123456 --fid 01     -> execute with defaults from `default` command\n"
                  "hf mfdes getfilesettings --isoid df01 --fid 00 --no-auth     -> get file settings with select by iso id\n"
                  "hf mfdes getfilesettings -n 0 -t des -k 0000000000000000 --kdf none --aid 123456 --fid 01    -> execute with default factory setup\n"
                  "hf mfdes getfilesettings --dfname D2760000850100 --fid 01 -> select DF by name and get file settings");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "isoid",   "<hex>", "Application ISO ID (ISO DF ID) (2 hex bytes, big endian)"),
        arg_str0(NULL, "dfname",  "<hex>", "Application ISO DF Name (5-16 hex bytes, big endian)"),
        arg_str0(NULL, "fid",     "<hex>", "File ID (1 hex byte). (def: 1)"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 15);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t id = 0x000000;
    DesfireISOSelectWay selectway = ISW6bAID;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, &securechann, DCMMACed, &id, &selectway);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint32_t fileid = 1;
    if (CLIGetUint32Hex(ctx, 14, 1, &fileid, NULL, 1, "File ID must have 1 byte length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    res = DesfireSelectAndAuthenticateAppW(&dctx, securechann, selectway, id, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(FAILED, "Select or authentication %s " _RED_("failed") ". Result [%d] %s", DesfireWayIDStr(selectway, id), res, DesfireAuthErrorToStr(res));
        return res;
    }

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t buflen = 0;

    res = DesfireGetFileSettings(&dctx, fileid, buf, &buflen);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire GetFileSettings command " _RED_("error") ". Result: %d", res);
        DropField();
        return PM3_ESOFT;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "%s file %02x settings[%zu]: %s", DesfireWayIDStr(selectway, id), fileid, buflen, sprint_hex(buf, buflen));
    }

    DesfirePrintFileSettings(buf, buflen);

    PrintAndLogEx(NORMAL, "");
    DropField();
    return PM3_SUCCESS;
}

static int DesfireCreateFileParameters(
    CLIParserContext *ctx,
    uint8_t pfileid, uint8_t pisofileid,
    uint8_t amodeid, uint8_t frightsid,
    uint8_t r_modeid, uint8_t w_modeid, uint8_t rw_modeid, uint8_t ch_modeid,
    uint8_t *data, size_t *datalen) {

    *datalen = 0;

    uint32_t fileid = 1;
    if (pfileid) {
        if (CLIGetUint32Hex(ctx, pfileid, 1, &fileid, NULL, 1, "File ID must have 1 byte length"))
            return PM3_EINVARG;
    }

    uint32_t isofileid = 0;
    if (pisofileid) {
        if (CLIGetUint32Hex(ctx, pisofileid, 0, &isofileid, NULL, 2, "ISO file ID must have 2 bytes length"))
            return PM3_EINVARG;
    }

    data[0] = fileid;
    *datalen = 1;

    if (isofileid > 0) {
        Uint2byteToMemLe(&data[1], isofileid);
        *datalen += 2;
    }

    uint8_t *settings = &data[*datalen];

    // file access mode
    int cmode = DCMNone;
    if (amodeid) {
        if (CLIGetOptionList(arg_get_str(ctx, amodeid), DesfireCommunicationModeOpts, &cmode)) {
            return PM3_ESOFT;
        }

        if (cmode == DCMPlain)
            settings[0] = 0x00;
        if (cmode == DCMMACed)
            settings[0] = 0x01;
        if (cmode == DCMEncrypted)
            settings[0] = 0x03;
        (*datalen)++;
    }

    // file rights
    uint32_t frights = 0xeeee;
    bool userawfrights = false;
    if (frightsid) {
        if (CLIGetUint32Hex(ctx, frightsid, 0xeeee, &frights, &userawfrights, 2, "File rights must have 2 bytes length")) {
            return PM3_EINVARG;
        }
    }
    settings[1] = frights & 0xff;
    settings[2] = (frights >> 8) & 0xff;

    if (userawfrights == false) {
        int r_mode = 0x0e;
        if (r_modeid) {
            if (CLIGetOptionList(arg_get_str(ctx, r_modeid), DesfireFileAccessModeOpts, &r_mode))
                return PM3_ESOFT;
        }

        int w_mode = 0x0e;
        if (w_modeid) {
            if (CLIGetOptionList(arg_get_str(ctx, w_modeid), DesfireFileAccessModeOpts, &w_mode))
                return PM3_ESOFT;
        }

        int rw_mode = 0x0e;
        if (rw_modeid) {
            if (CLIGetOptionList(arg_get_str(ctx, rw_modeid), DesfireFileAccessModeOpts, &rw_mode))
                return PM3_ESOFT;
        }

        int ch_mode = 0x0e;
        if (ch_modeid) {
            if (CLIGetOptionList(arg_get_str(ctx, ch_modeid), DesfireFileAccessModeOpts, &ch_mode))
                return PM3_ESOFT;
        }

        DesfireEncodeFileAcessMode(&settings[1], r_mode, w_mode, rw_mode, ch_mode) ;
    }
    *datalen += 2;

    return PM3_SUCCESS;
}

static int CmdHF14ADesChFileSettings(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes chfilesettings",
                  "Get File Settings from file from application. Master key needs to be provided or flag --no-auth set (depend on cards settings).",
                  "hf mfdes chfilesettings --aid 123456 --fid 01 --amode plain --rrights free --wrights free --rwrights free --chrights key0 -> change file settings app=123456, file=01 with defaults from `default` command\n"
                  "hf mfdes chfilesettings -n 0 -t des -k 0000000000000000 --kdf none --aid 123456 --fid 01 --rawdata 00EEEE -> execute with default factory setup\n"
                  "hf mfdes chfilesettings --aid 123456 --fid 01 --rawdata 810000021f112f22 -> change file settings with additional rights for keys 1 and 2\n"
                  "hf mfdes chfilesettings --isoid df01 --fid 00 --amode plain --rawrights eee0 --schann lrp -t aes -> change file settings via lrp channel");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "isoid",   "<hex>", "Application ISO ID (ISO DF ID) (2 hex bytes, big endian)"),
        arg_str0(NULL, "fid",     "<hex>", "File ID (1 hex byte)"),
        arg_str0(NULL, "rawdata", "<hex>", "File settings (HEX > 5 bytes). Have priority over the other settings"),
        arg_str0(NULL, "amode",   "<plain|mac|encrypt>", "File access mode"),
        arg_str0(NULL, "rawrights", "<hex>", "Access rights for file (2 hex bytes) R/W/RW/Chg, 0x0 - 0xD Key, 0xE Free, 0xF Denied"),
        arg_str0(NULL, "rrights",  "<key0..13|free|deny>", "Read file access mode: the specified key, free, deny"),
        arg_str0(NULL, "wrights",  "<key0..13|free|deny>", "Write file access mode: the specified key, free, deny"),
        arg_str0(NULL, "rwrights", "<key0..13|free|deny>", "Read/Write file access mode: the specified key, free, deny"),
        arg_str0(NULL, "chrights", "<key0..13|free|deny>", "Change file settings access mode: the specified key, free, deny"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 21);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t id = 0x000000;
    DesfireISOSelectWay selectway = ISW6bAID;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, &securechann, DCMEncrypted, &id, &selectway);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint8_t data[250] = {0};
    uint8_t *settings = &data[1];
    size_t datalen = 0;

    res = DesfireCreateFileParameters(ctx, 13, 0, 15, 16, 17, 18, 19, 20, data, &datalen);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint8_t sdata[250] = {0};
    int sdatalen = sizeof(sdata);
    CLIGetHexWithReturn(ctx, 14, sdata, &sdatalen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    if (sdatalen > 18) {
        PrintAndLogEx(ERR, "File settings length must be less than 18 instead of %d.", sdatalen);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    // rawdata have priority over all the rest methods
    if (sdatalen > 0) {
        memcpy(settings, sdata, sdatalen);
        datalen = 1 + sdatalen;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    uint8_t fileid = data[0];

    res = DesfireSelectAndAuthenticateAppW(&dctx, securechann, selectway, id, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(FAILED, "Select or authentication %s " _RED_("failed") ". Result [%d] %s", DesfireWayIDStr(selectway, id), res, DesfireAuthErrorToStr(res));
        return res;
    }

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t buflen = 0;

    // check current file settings
    DesfireCommunicationMode commMode = dctx.commMode;
    DesfireSetCommMode(&dctx, DCMMACed);
    res = DesfireGetFileSettings(&dctx, fileid, buf, &buflen);
    if (res == PM3_SUCCESS && buflen > 5) {
        uint8_t chright = 0;
        DesfireDecodeFileAcessMode(&buf[2], NULL, NULL, NULL, &chright) ;
        if (verbose)
            PrintAndLogEx(INFO, "Current access right for change file settings: %s", GetDesfireAccessRightStr(chright));

        if (chright == 0x0f)
            PrintAndLogEx(WARNING, "Change file settings disabled");

        if (chright == 0x0e && (!(commMode == DCMPlain || commMode == DCMMACed || noauth)))
            PrintAndLogEx(WARNING, "File settings have free access for change. Change command must be sent via plain communications mode or without authentication (--no-auth option)");

        if (chright < 0x0e && dctx.keyNum != chright)
            PrintAndLogEx(WARNING, "File settings must be changed with auth key=0x%02x but current auth with key 0x%02x", chright, dctx.keyNum);

        if (chright < 0x0e && commMode != DCMEncrypted)
            PrintAndLogEx(WARNING, "File settings must be changed via encryted (full) communication mode");
    }
    DesfireSetCommMode(&dctx, commMode);

    // print the new file settings
    if (verbose)
        PrintAndLogEx(INFO, "%s file %02x settings[%zu]: %s", DesfireWayIDStr(selectway, id), fileid, datalen - 1, sprint_hex(settings, datalen - 1));

    DesfirePrintSetFileSettings(settings, datalen - 1);

    // set file settings
    data[0] = fileid;
    res = DesfireChangeFileSettings(&dctx, data, datalen);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire ChangeFileSettings command " _RED_("error") ". Result: %d", res);
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "File settings changed " _GREEN_("successfully"));

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesCreateFile(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes createfile",
                  "Create Standard/Backup file in the application. Application master key needs to be provided or flag --no-auth set (depend on application settings).",
                  "--rawtype/--rawdata have priority over the other settings. and with these parameters you can create any file. file id comes from parameters, all the rest data must be in the --rawdata parameter\n"
                  "--rawrights have priority over the separate rights settings.\n"
                  "Key/mode/etc of the authentication depends on application settings\n"
                  "hf mfdes createfile --aid 123456 --fid 01 --isofid 0001 --size 000010 -> create file with iso id. Authentication with defaults from `default` command\n"
                  "hf mfdes createfile --aid 123456 --fid 01 --rawtype 01 --rawdata 000100EEEE000100 -> create file via sending rawdata to the card. Can be used to create any type of file. Authentication with defaults from `default` command\n"
                  "hf mfdes createfile --aid 123456 --fid 01 --amode plain --rrights free --wrights free --rwrights free --chrights key0 -> create file app=123456, file=01 and mentioned rights with defaults from `default` command\n"
                  "hf mfdes createfile -n 0 -t des -k 0000000000000000 --kdf none --aid 123456 --fid 01 --rawtype 00 --rawdata 00EEEE000100 -> execute with default factory setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "fid",     "<hex>", "File ID (1 hex byte)"),
        arg_str0(NULL, "isofid",  "<hex>", "ISO File ID (2 hex bytes)"),
        arg_str0(NULL, "rawtype", "<hex>", "Raw file type (1 hex byte)"),
        arg_str0(NULL, "rawdata", "<hex>", "Raw file settings (hex > 5 bytes)"),
        arg_str0(NULL, "amode",   "<plain|mac|encrypt>", "File access mode"),
        arg_str0(NULL, "rawrights", "<hex>", "Access rights for file (2 hex bytes) R/W/RW/Chg, 0x0 - 0xD Key, 0xE Free, 0xF Denied"),
        arg_str0(NULL, "rrights",  "<key0..key13|free|deny>", "Read file access mode: the specified key, free, deny"),
        arg_str0(NULL, "wrights",  "<key0..key13|free|deny>", "Write file access mode: the specified key, free, deny"),
        arg_str0(NULL, "rwrights", "<key0..key13|free|deny>", "Read/Write file access mode: the specified key, free, deny"),
        arg_str0(NULL, "chrights", "<key0..key13|free|deny>", "Change file settings access mode: the specified key, free, deny"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_str0(NULL, "size", "<hex>", "File size (3 hex bytes, big endian)"),
        arg_lit0(NULL, "backup", "Create backupfile instead of standard file"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 22);
    bool backup = arg_get_lit(ctx, 24);
    uint8_t filetype = (backup) ? 0x01 : 0x00; // backup / standard data file

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, &securechann, DCMMACed, &appid, NULL);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    if (appid == 0x000000) {
        PrintAndLogEx(ERR, "Can't create files at card level.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t data[250] = {0};
    size_t datalen = 0;

    res = DesfireCreateFileParameters(ctx, 12, 13, 16, 17, 18, 19, 20, 21, data, &datalen);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint32_t rawftype = 0x00;
    bool useraw = false;
    if (CLIGetUint32Hex(ctx, 14, 0x00, &rawftype, &useraw, 1, "Raw file type must have 1 byte length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t sdata[250] = {0};
    int sdatalen = sizeof(sdata);
    CLIGetHexWithReturn(ctx, 15, sdata, &sdatalen);
    if (sdatalen > 20) {
        PrintAndLogEx(ERR, "Rawdata length must be less than 20 bytes instead of %d.", sdatalen);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    if (useraw && sdatalen > 0) {
        filetype = rawftype;
        memcpy(&data[1], sdata, sdatalen);
        datalen = 1 + sdatalen;
    } else {
        useraw = false;
    }

    if (useraw == false) {
        uint32_t filesize = 0;
        if (CLIGetUint32Hex(ctx, 23, 0, &filesize, NULL, 3, "File size must have 3 bytes length")) {
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }

        if (filesize == 0) {
            PrintAndLogEx(ERR, "File size must be greater than 0");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }

        Uint3byteToMemLe(&data[datalen], filesize);
        datalen += 3;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    res = DesfireSelectAndAuthenticateEx(&dctx, securechann, appid, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    if (verbose)
        PrintAndLogEx(INFO, "App: %06x. File num: 0x%02x type: 0x%02x data[%zu]: %s", appid, data[0], filetype, datalen, sprint_hex(data, datalen));
    DesfirePrintCreateFileSettings(filetype, data, datalen);


    res = DesfireCreateFile(&dctx, filetype, data, datalen, useraw == false);  // check length only if we nont use raw mode
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire CreateFile command " _RED_("error") ". Result: %d", res);
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "%s file %02x in the app %06x created " _GREEN_("successfully"), GetDesfireFileType(filetype), data[0], appid);

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesCreateValueFile(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes createvaluefile",
                  "Create Value file in the application. Application master key needs to be provided or flag --no-auth set (depend on application settings).",
                  "--rawrights have priority over the separate rights settings.\n"
                  "Key/mode/etc of the authentication depends on application settings\n"
                  "hf mfdes createvaluefile --aid 123456 --fid 01 --lower 00000010 --upper 00010000 --value 00000100 -> create file with parameters. Rights from default. Authentication with defaults from `default` command\n"
                  "hf mfdes createvaluefile --aid 123456 --fid 01 --amode plain --rrights free --wrights free --rwrights free --chrights key0 -> create file app=123456, file=01 and mentioned rights with defaults from `default` command\n"
                  "hf mfdes createvaluefile -n 0 -t des -k 0000000000000000 --kdf none --aid 123456 --fid 01 -> execute with default factory setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo (deft: 2TDEA)"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "fid",     "<hex>", "File ID (1 hex byte)"),
        arg_str0(NULL, "amode",   "<plain|mac|encrypt>", "File access mode"),
        arg_str0(NULL, "rawrights", "<hex>", "Access rights for file (2 hex bytes) R/W/RW/Chg, 0x0 - 0xD Key, 0xE Free, 0xF Denied"),
        arg_str0(NULL, "rrights",  "<key0..key13|free|deny>", "Read file access mode: the specified key, free, deny"),
        arg_str0(NULL, "wrights",  "<key0..key13|free|deny>", "Write file access mode: the specified key, free, deny"),
        arg_str0(NULL, "rwrights", "<key0..key13|free|deny>", "Read/Write file access mode: the specified key, free, deny"),
        arg_str0(NULL, "chrights", "<key0..key13|free|deny>", "Change file settings access mode: the specified key, free, deny"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_str0(NULL, "lower",   "<hex>", "Lower limit (4 hex bytes, big endian)"),
        arg_str0(NULL, "upper",   "<hex>", "Upper limit (4 hex bytes, big endian)"),
        arg_str0(NULL, "value",   "<hex>", "Value (4 hex bytes, big endian)"),
        arg_int0(NULL, "lcredit", "<dec>", "Limited Credit enabled (Bit 0 = Limited Credit, 1 = FreeValue)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 19);

    uint8_t filetype = 0x02; // value file

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, &securechann, DCMMACed, &appid, NULL);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    if (appid == 0x000000) {
        PrintAndLogEx(ERR, "Can't create files at card level.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t data[250] = {0};
    size_t datalen = 0;

    res = DesfireCreateFileParameters(ctx, 12, 0, 13, 14, 15, 16, 17, 18, data, &datalen);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint32_t lowerlimit = 0;
    if (CLIGetUint32Hex(ctx, 20, 0, &lowerlimit, NULL, 4, "Lower limit value must have 4 bytes length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t upperlimit = 0;
    if (CLIGetUint32Hex(ctx, 21, 0, &upperlimit, NULL, 4, "Upper limit value must have 4 bytes length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t value = 0;
    if (CLIGetUint32Hex(ctx, 22, 0, &value, NULL, 4, "Value must have 4 bytes length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t lcredit = arg_get_int_def(ctx, 23, 0);

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);


    Uint4byteToMemLe(&data[datalen], lowerlimit);
    datalen += 4;
    Uint4byteToMemLe(&data[datalen], upperlimit);
    datalen += 4;
    Uint4byteToMemLe(&data[datalen], value);
    datalen += 4;
    data[datalen] = lcredit;
    datalen++;

    res = DesfireSelectAndAuthenticateEx(&dctx, securechann, appid, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    if (verbose)
        PrintAndLogEx(INFO, "App: %06x. File num: 0x%02x type: 0x%02x data[%zu]: %s", appid, data[0], filetype, datalen, sprint_hex(data, datalen));
    DesfirePrintCreateFileSettings(filetype, data, datalen);


    res = DesfireCreateFile(&dctx, filetype, data, datalen, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire CreateFile command " _RED_("error") ". Result: %d", res);
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Value file %02x in the app %06x created " _GREEN_("successfully"), data[0], appid);

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesCreateRecordFile(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes createrecordfile",
                  "Create Linear/Cyclic Record file in the application. Application master key needs to be provided or flag --no-auth set (depend on application settings).",
                  "--rawrights have priority over the separate rights settings.\n"
                  "Key/mode/etc of the authentication depends on application settings\n"
                  "hf mfdes createrecordfile --aid 123456 --fid 01 --size 000010 --maxrecord 000010 --cyclic -> create cyclic record file with parameters. Rights from default. Authentication with defaults from `default` command\n"
                  "hf mfdes createrecordfile --aid 123456 --fid 01 --amode plain --rrights free --wrights free --rwrights free --chrights key0 --size 000010 --maxrecord 000010 -> create linear record file app=123456, file=01 and mentioned rights with defaults from `default` command\n"
                  "hf mfdes createrecordfile -n 0 -t des -k 0000000000000000 --kdf none --aid 123456 --fid 01 --size 000010 --maxrecord 000010 -> execute with default factory setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "fid",     "<hex>", "File ID (1 hex byte)"),
        arg_str0(NULL, "isofid",  "<hex>", "ISO File ID (2 hex bytes)"),
        arg_str0(NULL, "amode",   "<plain|mac|encrypt>", "File access mode"),
        arg_str0(NULL, "rawrights", "<hex>", "Access rights for file (2 hex bytes) R/W/RW/Chg, 0x0 - 0xD Key, 0xE Free, 0xF Denied"),
        arg_str0(NULL, "rrights",  "<key0..key13|free|deny>", "Read file access mode: the specified key, free, deny"),
        arg_str0(NULL, "wrights",  "<key0..key13|free|deny>", "Write file access mode: the specified key, free, deny"),
        arg_str0(NULL, "rwrights", "<key0..key13|free|deny>", "Read/Write file access mode: the specified key, free, deny"),
        arg_str0(NULL, "chrights", "<key0..key13|free|deny>", "Change file settings access mode: the specified key, free, deny"),
        arg_lit0(NULL, "no-auth",   "Execute without authentication"),
        arg_str0(NULL, "size",      "<hex>", "Record size (3 hex bytes, big endian, 000001 to FFFFFF)"),
        arg_str0(NULL, "maxrecord", "<hex>", "Max. Number of Records (3 hex bytes, big endian)"),
        arg_lit0(NULL, "cyclic", "Create cyclic record file instead of linear record file"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 20);

    bool cyclic = arg_get_lit(ctx, 23);
    uint8_t filetype = (cyclic) ? 0x04 : 0x03; // linear(03) / cyclic(04) record file

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, &securechann, DCMMACed, &appid, NULL);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    if (appid == 0x000000) {
        PrintAndLogEx(ERR, "Can't create files at card level.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t data[250] = {0};
    size_t datalen = 0;

    res = DesfireCreateFileParameters(ctx, 12, 13, 14, 15, 16, 17, 18, 19, data, &datalen);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint32_t size = 0;
    if (CLIGetUint32Hex(ctx, 21, 0, &size, NULL, 3, "Record size must have 3 bytes length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t maxrecord = 0;
    if (CLIGetUint32Hex(ctx, 22, 0, &maxrecord, NULL, 3, "Max number of records must have 3 bytes length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);


    Uint3byteToMemLe(&data[datalen], size);
    datalen += 3;
    Uint3byteToMemLe(&data[datalen], maxrecord);
    datalen += 3;

    res = DesfireSelectAndAuthenticateEx(&dctx, securechann, appid, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    if (verbose)
        PrintAndLogEx(INFO, "App: %06x. File num: 0x%02x type: 0x%02x data[%zu]: %s", appid, data[0], filetype, datalen, sprint_hex(data, datalen));
    DesfirePrintCreateFileSettings(filetype, data, datalen);


    res = DesfireCreateFile(&dctx, filetype, data, datalen, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire CreateFile command " _RED_("error") ". Result: %d", res);
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "%s file %02x in the app %06x created " _GREEN_("successfully"), GetDesfireFileType(filetype), data[0], appid);

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesCreateTrMACFile(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes createmacfile",
                  "Create Transaction MAC file in the application. Application master key needs to be provided or flag --no-auth set (depend on application settings).",
                  "--rawrights have priority over the separate rights settings.\n"
                  "Key/mode/etc of the authentication depends on application settings\n"
                  "Write right should be always 0xF. Read-write right should be 0xF if you not need to submit CommitReaderID command each time transaction starts\n"
                  "\n"
                  "hf mfdes createmacfile --aid 123456 --fid 01 --rawrights 0FF0 --mackey 00112233445566778899aabbccddeeff --mackeyver 01 -> create transaction mac file with parameters. Rights from default. Authentication with defaults from `default` command\n"
                  "hf mfdes createmacfile --aid 123456 --fid 01 --amode plain --rrights free --wrights deny --rwrights free --chrights key0 --mackey 00112233445566778899aabbccddeeff -> create file app=123456, file=01, with key, and mentioned rights with defaults from `default` command\n"
                  "hf mfdes createmacfile -n 0 -t des -k 0000000000000000 --kdf none --aid 123456 --fid 01 -> execute with default factory setup. key and keyver == 0x00..00\n"
                  "hf mfdes createmacfile --isoid df01 --fid 0f --schann lrp -t aes --rawrights 0FF0 --mackey 00112233445566778899aabbccddeeff --mackeyver 01 -> create transaction mac file via lrp channel\n"
                  "hf mfdes createmacfile --isoid df01 --fid 0f --schann lrp -t aes --rawrights 0F10 --mackey 00112233445566778899aabbccddeeff --mackeyver 01 -> create transaction mac file via lrp channel with CommitReaderID command enable");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",      "Show APDU requests and responses"),
        arg_lit0("v",  "verbose",   "Verbose output"),
        arg_int0("n",  "keyno",     "<dec>", "Key number"),
        arg_str0("t",  "algo",      "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",       "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",       "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",      "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",     "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",     "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",    "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",       "<hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "isoid",     "<hex>", "Application ISO ID (ISO DF ID) (2 hex bytes, big endian)"),
        arg_str0(NULL, "fid",       "<hex>", "File ID (1 hex byte)"),
        arg_str0(NULL, "amode",     "<plain|mac|encrypt>", "File access mode"),
        arg_str0(NULL, "rawrights", "<hex>", "Access rights for file (2 hex bytes) R/W/RW/Chg, 0x0 - 0xD Key, 0xE Free, 0xF Denied"),
        arg_str0(NULL, "rrights",   "<key0..key13|free|deny>", "Read file access mode: the specified key, free, deny"),
        arg_str0(NULL, "wrights",   "<key0..key13|free|deny>", "Write file access mode: the specified key, free, deny"),
        arg_str0(NULL, "rwrights",  "<key0..key13|free|deny>", "Read/Write file access mode: the specified key, free, deny"),
        arg_str0(NULL, "chrights",  "<key0..key13|free|deny>", "Change file settings access mode: the specified key, free, deny"),
        arg_lit0(NULL, "no-auth",   "Execute without authentication"),
        arg_str0(NULL, "mackey",    "<hex>", "AES-128 key for MAC (16 hex bytes, big endian). (def: all zeros)"),
        arg_str0(NULL, "mackeyver", "<hex>", "AES key version for MAC (1 hex byte). (def: 0x0)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 20);

    uint8_t filetype = 0x05; // transaction mac file

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t id = 0x000000;
    DesfireISOSelectWay selectway = ISW6bAID;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, &securechann, DCMEncrypted, &id, &selectway);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    if (DesfireMFSelected(selectway, id)) {
        PrintAndLogEx(ERR, "Can't create files at card level.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t data[250] = {0};
    size_t datalen = 0;

    res = DesfireCreateFileParameters(ctx, 13, 0, 14, 15, 16, 17, 18, 19, data, &datalen);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint8_t sdata[250] = {0};
    int sdatalen = sizeof(sdata);
    CLIGetHexWithReturn(ctx, 21, sdata, &sdatalen);
    if (sdatalen != 0 && sdatalen != 16) {
        PrintAndLogEx(ERR, "AES-128 key must be 16 bytes instead of %d.", sdatalen);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t keyver = 0x00;
    if (CLIGetUint32Hex(ctx, 22, 0x00, &keyver, NULL, 1, "Key version must have 1 bytes length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    data[datalen] = 0x02; // AES key
    datalen++;
    if (sdatalen > 0)
        memcpy(&data[datalen], sdata, sdatalen);
    datalen += 16;
    data[datalen] = keyver & 0xff;
    datalen++;

    res = DesfireSelectAndAuthenticateAppW(&dctx, securechann, selectway, id, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(FAILED, "Select or authentication %s " _RED_("failed") ". Result [%d] %s", DesfireWayIDStr(selectway, id), res, DesfireAuthErrorToStr(res));
        return res;
    }

    if (verbose)
        PrintAndLogEx(INFO, "%s. File num: 0x%02x type: 0x%02x data[%zu]: %s", DesfireWayIDStr(selectway, id), data[0], filetype, datalen, sprint_hex(data, datalen));

    DesfirePrintCreateFileSettings(filetype, data, datalen);

    res = DesfireCreateFile(&dctx, filetype, data, datalen, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire CreateFile command " _RED_("error") ". Result: %d", res);
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "%s file %02x in the %s created " _GREEN_("successfully"), GetDesfireFileType(filetype), data[0], DesfireWayIDStr(selectway, id));

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesDeleteFile(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes deletefile",
                  "Delete file from application. Master key needs to be provided or flag --no-auth set (depend on cards settings).",
                  "hf mfdes deletefile --aid 123456 --fid 01 -> delete file for: app=123456, file=01 with defaults from `default` command\n"
                  "hf mfdes deletefile --isoid df01 --fid 0f --schann lrp -t aes -> delete file for lrp channel");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "isoid",   "<hex>", "Application ISO ID (ISO DF ID) (2 hex bytes, big endian)"),
        arg_str0(NULL, "fid",     "<hex>", "File ID (1 hex byte)"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 14);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t id = 0x000000;
    DesfireISOSelectWay selectway = ISW6bAID;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, &securechann, DCMMACed, &id, &selectway);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint32_t fnum = 1;
    if (CLIGetUint32Hex(ctx, 13, 1, &fnum, NULL, 1, "File ID must have 1 byte length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    if (fnum > 0x1F) {
        PrintAndLogEx(ERR, "File number range is invalid (exp 0x00 - 0x1f), got 0x%02x", fnum);
        return PM3_EINVARG;
    }

    res = DesfireSelectAndAuthenticateAppW(&dctx, securechann, selectway, id, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(FAILED, "Select or authentication %s " _RED_("failed") ". Result [%d] %s", DesfireWayIDStr(selectway, id), res, DesfireAuthErrorToStr(res));
        return res;
    }

    res = DesfireDeleteFile(&dctx, fnum);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire DeleteFile command " _RED_("error") ". Result: %d", res);
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "File %02x in the %s deleted " _GREEN_("successfully"), fnum, DesfireWayIDStr(selectway, id));

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesValueOperations(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes value",
                  "Get File Settings from file from application. Master key needs to be provided or flag --no-auth set (depend on cards settings).",
                  "hf mfdes value --aid 123456 --fid 01  -> get value app=123456, file=01 with defaults from `default` command\n"
                  "hf mfdes value --aid 123456 --fid 01 --op credit -d 00000001 -> credit value app=123456, file=01 with defaults from `default` command\n"
                  "hf mfdes value -n 0 -t des -k 0000000000000000 --kdf none --aid 123456 --fid 01 -> get value with default factory setup\n"
                  "hf mfdes val --isoid df01 --fid 03 --schann lrp -t aes -n 1 --op credit --d 00000001 -m encrypt -> credit value in the lrp encrypted mode\n"
                  "hf mfdes val --isoid df01 --fid 03 --schann lrp -t aes -n 1 --op get -m plain -> get value in plain (nevertheless of mode) works for desfire light (look SetConfiguration option 0x09)");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo (deft: 2TDEA)"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "isoid",   "<hex>", "Application ISO ID (ISO DF ID) (2 hex bytes, big endian)"),
        arg_str0(NULL, "fid",     "<hex>", "File ID (1 hex byte)"),
        arg_str0("o",  "op",      "<get/credit/limcredit/debit/clear>", "Operation: get(default)/credit/limcredit(limited credit)/debit/clear. Additional operation clear: get-getopt-debit to min value"),
        arg_str0("d",  "data",    "<hex>", "Value for operation (HEX 4 bytes)"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 16);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t id = 0x000000;
    DesfireISOSelectWay selectway = ISW6bAID;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, &securechann, DCMPlain, &id, &selectway);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint32_t fileid = 1;
    if (CLIGetUint32Hex(ctx, 13, 1, &fileid, NULL, 1, "File ID must have 1 byte length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int op = MFDES_GET_VALUE;
    if (CLIGetOptionList(arg_get_str(ctx, 14), DesfireValueFileOperOpts, &op)) {
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    uint32_t value = 0;
    if (CLIGetUint32Hex(ctx, 15, 0, &value, NULL, 4, "Value must have 4 byte length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    // iso chaining works in the lrp mode
    dctx.isoChaining |= (dctx.secureChannel == DACLRP);

    // select
    res = DesfireSelectAndAuthenticateAppW(&dctx, securechann, selectway, id, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(FAILED, "Select or authentication ( %s )" _RED_("failed") " Result [%d] %s", DesfireWayIDStr(selectway, id), res, DesfireAuthErrorToStr(res));
        return res;
    }

    if (verbose)
        PrintAndLogEx(INFO, "%s file %02x operation: %s value: 0x%08x", DesfireWayIDStr(selectway, id), fileid, CLIGetOptionListStr(DesfireValueFileOperOpts, op), value);

    if (op != 0xff) {
        res = DesfireValueFileOperations(&dctx, fileid, op, &value);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Desfire ValueFileOperations (0x%02x) command ( " _RED_("error") " ) Result: %d", op, res);
            DropField();
            return PM3_ESOFT;
        }
        if (verbose)
            PrintAndLogEx(INFO, "Operation ( %s )" _GREEN_("ok"), CLIGetOptionListStr(DesfireValueFileOperOpts, op));

        if (op == MFDES_GET_VALUE) {
            PrintAndLogEx(SUCCESS, "Value: " _GREEN_("%d (0x%08x)"), value, value);
        } else {
            DesfireSetCommMode(&dctx, DCMMACed);
            res = DesfireCommitTransaction(&dctx, false, 0);
            if (res != PM3_SUCCESS) {
                PrintAndLogEx(ERR, "Desfire CommitTransaction command ( " _RED_("error") ") Result: %d", res);
                DropField();
                return PM3_ESOFT;
            }
            if (verbose)
                PrintAndLogEx(INFO, "Commit ( " _GREEN_("ok") " )");

            PrintAndLogEx(SUCCESS, "Value changed " _GREEN_("successfully"));
        }
    } else {
        DesfireCommunicationMode fileCommMode = dctx.commMode;

        res = DesfireValueFileOperations(&dctx, fileid, MFDES_GET_VALUE, &value);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Desfire GetValue command ( " _RED_("error") ") Result: %d", res);
            DropField();
            return PM3_ESOFT;
        }
        if (verbose)
            PrintAndLogEx(INFO, _YELLOW_("GetValue") " command is " _GREEN_("ok") ". Current value: 0x%08x", value);

        uint8_t buf[250] = {0};
        size_t buflen = 0;

        DesfireSetCommMode(&dctx, DCMMACed);
        res = DesfireGetFileSettings(&dctx, fileid, buf, &buflen);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Desfire GetFileSettings command ( " _RED_("error") " ) Result: %d", res);
            DropField();
            return PM3_ESOFT;
        }

        if (verbose)
            PrintAndLogEx(INFO, _YELLOW_("GetFileSettings") " is " _GREEN_("ok") " . File settings[%zu]: %s", buflen, sprint_hex(buf, buflen));

        if (buflen < 8 || buf[0] != 0x02) {
            PrintAndLogEx(ERR, "Desfire GetFileSettings command returns " _RED_("wrong") " data");
            DropField();
            return PM3_ESOFT;
        }

        int32_t minvalue = (int)MemLeToUint4byte(&buf[4]);
        uint32_t delta = ((int64_t)value > minvalue) ? value - minvalue : 0;
        if (verbose) {
            PrintAndLogEx(INFO, "value: 0x%08x (%d)", value, value);
            PrintAndLogEx(INFO, "minimum value: 0x%08x (%d)", minvalue, minvalue);
            PrintAndLogEx(INFO, "delta value  : 0x%08x (%d)", delta, delta);
        }

        if (delta > 0) {
            DesfireSetCommMode(&dctx, fileCommMode);

            uint32_t maxdelta = 0x7fffffff;
            if (delta > maxdelta) {
                res = DesfireValueFileOperations(&dctx, fileid, MFDES_DEBIT, &maxdelta);
                if (res != PM3_SUCCESS) {
                    PrintAndLogEx(ERR, "Desfire Debit maxdelta operation ( " _RED_("error") " ) Result: %d", res);
                    DropField();
                    return PM3_ESOFT;
                }

                delta -= maxdelta;
                if (verbose) {
                    PrintAndLogEx(INFO, "Value maxdelta debited " _GREEN_("ok"));
                    PrintAndLogEx(INFO, "delta value  : 0x%08x (%d)", delta, delta);
                }
            }

            res = DesfireValueFileOperations(&dctx, fileid, MFDES_DEBIT, &delta);
            if (res != PM3_SUCCESS) {
                PrintAndLogEx(ERR, "Desfire Debit operation ( " _RED_("error") " ) Result: %d", res);
                DropField();
                return PM3_ESOFT;
            }

            if (verbose)
                PrintAndLogEx(INFO, "Value debited " _GREEN_("ok"));

            DesfireSetCommMode(&dctx, DCMMACed);
            res = DesfireCommitTransaction(&dctx, false, 0);
            if (res != PM3_SUCCESS) {
                PrintAndLogEx(ERR, "Desfire CommitTransaction command ( " _RED_("error") " ) Result: %d", res);
                DropField();
                return PM3_ESOFT;
            }

            if (verbose)
                PrintAndLogEx(INFO, "Transaction :" _GREEN_("committed"));
        } else {
            if (verbose)
                PrintAndLogEx(INFO, "Nothing to clear. Value already in the minimum level.");
        }

        PrintAndLogEx(SUCCESS, "Value cleared " _GREEN_("successfully"));
    }

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesClearRecordFile(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes clearrecfile",
                  "Clear record file. Master key needs to be provided or flag --no-auth set (depend on cards settings).",
                  "hf mfdes clearrecfile --aid 123456 --fid 01 -> clear record file for: app=123456, file=01 with defaults from `default` command\n"
                  "hf mfdes clearrecfile --isoid df01 --fid 01 --schann lrp -t aes -n 3 -> clear record file for lrp channel with key number 3");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "isoid",   "<hex>", "Application ISO ID (ISO DF ID) (2 hex bytes, big endian)"),
        arg_str0(NULL, "fid",     "<hex>", "File ID for clearing (1 hex byte)"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 14);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t id = 0x000000;
    DesfireISOSelectWay selectway = ISW6bAID;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, &securechann, DCMMACed, &id, &selectway);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint32_t fnum = 1;
    if (CLIGetUint32Hex(ctx, 13, 1, &fnum, NULL, 1, "File ID must have 1 byte length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    if (fnum > 0x1F) {
        PrintAndLogEx(ERR, "File number range is invalid (exp 0x00 - 0x1f), got 0x%02x", fnum);
        return PM3_EINVARG;
    }

    res = DesfireSelectAndAuthenticateAppW(&dctx, securechann, selectway, id, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(FAILED, "Select or authentication %s " _RED_("failed") ". Result [%d] %s", DesfireWayIDStr(selectway, id), res, DesfireAuthErrorToStr(res));
        return res;
    }

    res = DesfireClearRecordFile(&dctx, fnum);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire ClearRecordFile command " _RED_("error") ". Result: %d", res);
        DropField();
        return PM3_ESOFT;
    }

    if (verbose)
        PrintAndLogEx(INFO, "File cleared");

    DesfireSetCommMode(&dctx, DCMMACed);
    res = DesfireCommitTransaction(&dctx, false, 0);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire CommitTransaction command " _RED_("error") ". Result: %d", res);
        DropField();
        return PM3_ESOFT;
    }

    if (verbose)
        PrintAndLogEx(INFO, "Transaction committed");

    PrintAndLogEx(SUCCESS, "File %02x in the %s cleared " _GREEN_("successfully"), fnum, DesfireWayIDStr(selectway, id));

    DropField();
    return PM3_SUCCESS;
}

static int DesfileReadISOFileAndPrint(DesfireContext_t *dctx,
                                      bool select_current_file, uint8_t fnum,
                                      uint16_t fisoid, int filetype,
                                      uint32_t offset, uint32_t length,
                                      bool noauth, bool verbose) {

    if (filetype == RFTAuto) {
        PrintAndLogEx(ERR, "ISO mode needs to specify file type");
        return PM3_EINVARG;
    }

    if (filetype == RFTValue) {
        PrintAndLogEx(ERR, "ISO mode can't read Value file type");
        return PM3_EINVARG;
    }

    if (filetype == RFTMAC) {
        PrintAndLogEx(ERR, "ISO mode can't read Transaction MAC file type");
        return PM3_EINVARG;
    }

    if (select_current_file)
        PrintAndLogEx(INFO, "------------------------------- " _CYAN_("File ISO %04x data") " -------------------------------", fisoid);
    else
        PrintAndLogEx(INFO, "---------------------------- " _CYAN_("File ISO short %02x data") " ----------------------------", fnum);

    uint8_t resp[2048] = {0};
    size_t resplen = 0;
    int res;

    if (filetype == RFTData) {
        res = DesfireISOReadBinary(dctx, !select_current_file, (select_current_file) ? 0x00 : fnum, offset, length, resp, &resplen);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Desfire ISOReadBinary command " _RED_("error") ". Result: %d", res);
            DropField();
            return PM3_ESOFT;
        }

        if (resplen > 0) {
            if (select_current_file)
                PrintAndLogEx(SUCCESS, "Read %zu bytes from file 0x%04x offset %u", resplen, fisoid, offset);
            else
                PrintAndLogEx(SUCCESS, "Read %zu bytes from file 0x%02x offset %u", resplen, fnum, offset);
            print_buffer_with_offset(resp, resplen, offset, true);
        } else {
            if (select_current_file)
                PrintAndLogEx(SUCCESS, "Read operation returned no data from file %04x", fisoid);
            else
                PrintAndLogEx(SUCCESS, "Read operation returned no data from file %02x", fnum);
        }
    }

    if (filetype == RFTRecord) {
        size_t reclen = 0;
        res = DesfireISOReadRecords(dctx, offset, false, (select_current_file) ? 0x00 : fnum, 0, resp, &resplen);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Desfire ISOReadRecords (one record) command " _RED_("error") ". Result: %d", res);
            DropField();
            return PM3_ESOFT;
        }
        reclen = resplen;

        if (verbose)
            PrintAndLogEx(INFO, "Record length %zu", reclen);

        if (length != 1) {
            res = DesfireISOReadRecords(dctx, offset, true, (select_current_file) ? 0x00 : fnum, 0, resp, &resplen);
            if (res != PM3_SUCCESS) {
                PrintAndLogEx(ERR, "Desfire ISOReadRecords (one record) command " _RED_("error") ". Result: %d", res);
                DropField();
                return PM3_ESOFT;
            }
        }

        if (resplen > 0) {
            size_t reccount = resplen / reclen;
            if (select_current_file)
                PrintAndLogEx(SUCCESS, "Read %zu bytes from file 0x%04x from record %d record count %zu record length %zu", resplen, fisoid, offset, reccount, reclen);
            else
                PrintAndLogEx(SUCCESS, "Read %zu bytes from file 0x%02x from record %d record count %zu record length %zu", resplen, fnum, offset, reccount, reclen);
            if (reccount > 1)
                PrintAndLogEx(SUCCESS, "Lastest record at the bottom.");
            for (int i = 0; i < reccount; i++) {
                if (i != 0)
                    PrintAndLogEx(SUCCESS, "Record %zu", reccount - (i + offset + 1));
                print_buffer_with_offset(&resp[i * reclen], reclen, offset, (i == 0));
            }
        } else {
            if (select_current_file)
                PrintAndLogEx(SUCCESS, "Read operation returned no data from file %04x", fisoid);
            else
                PrintAndLogEx(SUCCESS, "Read operation returned no data from file %02x", fnum);
        }
    }

    return PM3_SUCCESS;
}

static int DesfileReadFileAndPrint(DesfireContext_t *dctx,
                                   uint8_t fnum, int filetype,
                                   uint32_t offset, uint32_t length,
                                   uint32_t maxdatafilelength, bool noauth, bool verbose) {

    int res;
    // length of record for record file
    size_t reclen = 0;

    // iso chaining works in the lrp mode
    dctx->isoChaining |= (dctx->secureChannel == DACLRP);

    // get file settings
    if (filetype == RFTAuto) {
        FileSettings_t fsettings;

        DesfireCommunicationMode commMode = dctx->commMode;
        DesfireSetCommMode(dctx, DCMMACed);
        res = DesfireFileSettingsStruct(dctx, fnum, &fsettings);
        DesfireSetCommMode(dctx, commMode);

        if (res == PM3_SUCCESS) {
            switch (fsettings.fileType) {
                case 0x00:
                case 0x01: {
                    filetype = RFTData;
                    break;
                }
                case 0x02: {
                    filetype = RFTValue;
                    break;
                }
                case 0x03:
                case 0x04: {
                    filetype = RFTRecord;
                    reclen = fsettings.recordSize;
                    break;
                }
                case 0x05: {
                    filetype = RFTMAC;
                    break;
                }
                default: {
                    break;
                }
            }

            commMode = fsettings.commMode;
            // lrp needs to point exact mode
            if (dctx->secureChannel == DACLRP) {
                // read right == free
                if (fsettings.rAccess == 0xe)
                    commMode = DCMPlain;
                // get value access == free
                if (filetype == RFTValue && (fsettings.limitedCredit & 0x02) != 0)
                    commMode = DCMPlain;
            }

            // calc max length
            if (filetype == RFTData && maxdatafilelength && (maxdatafilelength < fsettings.fileSize)) {
                length = maxdatafilelength;
            }

            DesfireSetCommMode(dctx, commMode);

            if (fsettings.fileCommMode != 0 && noauth)
                PrintAndLogEx(WARNING, "File needs communication mode `%s` but there is no authentication", CLIGetOptionListStr(DesfireCommunicationModeOpts, fsettings.commMode));

            if ((fsettings.rAccess < 0x0e && fsettings.rAccess != dctx->keyNum) && (fsettings.rwAccess < 0x0e && fsettings.rwAccess != dctx->keyNum))
                PrintAndLogEx(WARNING, "File needs to be authenticated with key 0x%02x or 0x%02x but current authentication key is 0x%02x", fsettings.rAccess, fsettings.rwAccess, dctx->keyNum);

            if (fsettings.rAccess == 0x0f && fsettings.rwAccess == 0x0f)
                PrintAndLogEx(WARNING, "File access denied. All read access rights is 0x0F");

            if (verbose) {
                PrintAndLogEx(INFO, _CYAN_("File type:") " %s  Option: %s  comm mode: %s",
                              GetDesfireFileType(fsettings.fileType),
                              CLIGetOptionListStr(DesfireReadFileTypeOpts, filetype),
                              CLIGetOptionListStr(DesfireCommunicationModeOpts, fsettings.commMode)
                             );
            }
        } else {
            PrintAndLogEx(WARNING, "GetFileSettings error. Can't get file type.");
        }
    }

    PrintAndLogEx(INFO, "------------------------------- " _CYAN_("File %02x data") " -------------------------------", fnum);

    uint8_t *resp  = calloc(DESFIRE_BUFFER_SIZE, 1);
    if (resp == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        DropField();
        return PM3_EMALLOC;
    }
    size_t resplen = 0;

    if (filetype == RFTData) {
        res = DesfireReadFile(dctx, fnum, offset, length, resp, &resplen);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Desfire ReadFile command " _RED_("error") ". Result: %d", res);
            DropField();
            free(resp);
            return PM3_ESOFT;
        }

        if (resplen > 0) {
            PrintAndLogEx(SUCCESS, "Read %zu bytes from file 0x%02x offset %u", resplen, fnum, offset);
            print_buffer_with_offset(resp, resplen, offset, true);
        } else {
            PrintAndLogEx(SUCCESS, "Read operation returned no data from file %d", fnum);
        }
    }

    if (filetype == RFTValue) {
        uint32_t value = 0;
        res = DesfireValueFileOperations(dctx, fnum, MFDES_GET_VALUE, &value);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Desfire GetValue operation " _RED_("error") ". Result: %d", res);
            DropField();
            free(resp);
            return PM3_ESOFT;
        }
        PrintAndLogEx(SUCCESS, "Read file 0x%02x value: %d (0x%08x)", fnum, value, value);
    }

    if (filetype == RFTRecord) {
        resplen = 0;
        if (reclen == 0) {
            res = DesfireReadRecords(dctx, fnum, offset, 1, resp, &resplen);
            if (res != PM3_SUCCESS) {
                PrintAndLogEx(ERR, "Desfire ReadRecords (len=1) command " _RED_("error") ". Result: %d", res);
                DropField();
                free(resp);
                return PM3_ESOFT;
            }
            reclen = resplen;
        }

        if (verbose)
            PrintAndLogEx(INFO, "Record length %zu", reclen);

        // if we got one record via the DesfireReadRecords before -- we not need to get it 2nd time
        if (length != 1 || resplen == 0) {
            res = DesfireReadRecords(dctx, fnum, offset, length, resp, &resplen);
            if (res != PM3_SUCCESS) {
                PrintAndLogEx(ERR, "Desfire ReadRecords command " _RED_("error") ". Result: %d", res);
                DropField();
                free(resp);
                return PM3_ESOFT;
            }
        }

        if (resplen > 0 && reclen > 0) {
            size_t reccount = resplen / reclen;
            PrintAndLogEx(SUCCESS, "Read %zu bytes from file 0x%02x from record %d record count %zu record length %zu", resplen, fnum, offset, reccount, reclen);
            if (reccount > 1) {
                PrintAndLogEx(SUCCESS, "Lastest record at the bottom.");
            }

            for (int i = 0; i < reccount; i++) {
                if (i != 0) {
                    PrintAndLogEx(SUCCESS, "Record %zu", reccount - (i + offset + 1));
                }
                print_buffer_with_offset(&resp[i * reclen], reclen, offset, (i == 0));
            }
        } else {
            PrintAndLogEx(SUCCESS, "Read operation returned no data from file %d", fnum);
        }
    }

    if (filetype == RFTMAC) {
        res = DesfireReadFile(dctx, fnum, 0, 0, resp, &resplen);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Desfire ReadFile command " _RED_("error") ". Result: %d", res);
            DropField();
            free(resp);
            return PM3_ESOFT;
        }

        if (resplen > 0) {
            if (resplen != 12) {
                PrintAndLogEx(WARNING, "Read wrong %zu bytes from file 0x%02x offset %u", resplen, fnum, offset);
                print_buffer_with_offset(resp, resplen, offset, true);
            } else {
                uint32_t cnt = MemLeToUint4byte(&resp[0]);
                transactionCounter = cnt;
                if (dctx->secureChannel != DACLRP) {
                    PrintAndLogEx(SUCCESS, "Transaction counter: %d (0x%08x)", cnt, cnt);
                } else {
                    // For composing TMC the two subparts are concatenated as follows: actTMC || sesTMC. Both subparts are represented LSB first.
                    // MF2DLHX0.pdf, 10.3.2.1 Transaction MAC Counter, page 41
                    uint32_t actTMC = MemLeToUint2byte(&resp[0]);
                    uint32_t sessTMC = MemLeToUint2byte(&resp[2]);
                    PrintAndLogEx(SUCCESS, "Session tr counter : %d (0x%04x)", sessTMC, sessTMC);
                    PrintAndLogEx(SUCCESS, "Actual tr counter  : %d (0x%04x)", actTMC, actTMC);
                }
                PrintAndLogEx(SUCCESS, "Transaction MAC    : %s", sprint_hex(&resp[4], 8));
            }
        } else {
            PrintAndLogEx(SUCCESS, "Read operation returned no data from file %d", fnum);
        }
    }

    free(resp);
    return PM3_SUCCESS;
}

static int CmdHF14ADesReadData(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes read",
                  "Read data from file. Key needs to be provided or flag --no-auth set (depend on file settings).",
                  "It reads file via all command sets. \n"
                  "For ISO command set it can be read by specifying full 2-byte iso id or 1-byte short iso id (first byte of the full iso id). ISO id lays in the data in BIG ENDIAN format.\n"
                  "ISO record commands: offset - record number (0-current, 1..ff-number, 1-lastest), length - if 0 - all records, if 1 - one\n"
                  "\n"
                  "hf mfdes read --aid 123456 --fid 01 -> read file: app=123456, file=01, offset=0, all the data. use default channel settings from `default` command\n"
                  "hf mfdes read --aid 123456 --fid 01 --type record --offset 000000 --length 000001 -> read one last record from record file. use default channel settings from `default` command\n"
                  "hf mfdes read --aid 123456 --fid 10 --type data -c iso -> read file via ISO channel: app=123456, short iso id=10, offset=0.\n"
                  "hf mfdes read --aid 123456 --fileisoid 1000 --type data -c iso -> read file via ISO channel: app=123456, iso id=1000, offset=0. Select via native ISO wrapper\n"
                  "hf mfdes read --isoid 0102 --fileisoid 1000 --type data -c iso -> read file via ISO channel: app iso id=0102, iso id=1000, offset=0. Select via ISO commands\n"
                  "hf mfdes read --isoid 0102 --fileisoid 1100 --type record -c iso --offset 000005 --length 000001 -> get one record (number 5) from file 1100 via iso commands\n"
                  "hf mfdes read --isoid 0102 --fileisoid 1100 --type record -c iso --offset 000005 --length 000000 -> get all record (from 5 to 1) from file 1100 via iso commands\n"
                  "hf mfdes read --isoid df01 --fid 00 --schann lrp -t aes --length 000010 -> read via lrp channel\n"
                  "hf mfdes read --isoid df01 --fid 00 --schann ev2 -t aes --length 000010 --isochain -> read Desfire Light via ev2 channel");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL,  "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "fid",     "<hex>", "File ID (1 hex byte)"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_str0(NULL, "type",    "<auto|data|value|record|mac>", "File Type, Auto - check file settings and then read. (def: auto)"),
        arg_str0("o", "offset",   "<hex>", "File Offset (3 hex bytes, big endian). For records - record number (0 - lastest record). (def: 0)"),
        arg_str0("l", "length",   "<hex>", "Length to read (3 hex bytes, big endian -> 000000 = Read all data). For records - records count (0 - all). (def: 0)"),
        arg_str0(NULL, "isoid",     "<hex>", "Application ISO ID (ISO DF ID) (2 hex bytes, big endian)"),
        arg_str0(NULL, "fileisoid", "<hex>", "File ISO ID (ISO DF ID) (2 hex bytes, big endian). Works only for ISO read commands"),
        arg_lit0(NULL, "isochain", "use iso chaining commands. Switched on by default if secure channel = lrp"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 13);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t id = 0x000000;
    DesfireISOSelectWay selectway = ISW6bAID;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 17, 0, &securechann, DCMMACed, &id, &selectway);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint32_t fnum = 1;
    if (CLIGetUint32Hex(ctx, 12, 1, &fnum, NULL, 1, "File ID must have 1 byte length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int op = RFTAuto;
    if (CLIGetOptionList(arg_get_str(ctx, 14), DesfireReadFileTypeOpts, &op)) {
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    uint32_t offset = 0;
    if (CLIGetUint32Hex(ctx, 15, 0, &offset, NULL, 3, "Offset must have 3 byte length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t length = 0;
    if (CLIGetUint32Hex(ctx, 16, 0, &length, NULL, 3, "Length parameter must have 3 byte length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t fileisoid = 0x0000;
    bool fileisoidpresent = false;
    if (CLIGetUint32Hex(ctx, 18, 0x0000, &fileisoid, &fileisoidpresent, 2, "File ISO ID (for DF) must have 2 bytes length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    dctx.isoChaining = arg_get_lit(ctx, 19);

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    if (fnum > 0x1F) {
        PrintAndLogEx(ERR, "File number range is invalid (exp 0x00 - 0x1f), got 0x%02x", fnum);
        return PM3_EINVARG;
    }

    res = DesfireSelectAndAuthenticateW(&dctx, securechann, selectway, id, fileisoidpresent, fileisoid, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(FAILED, "Select or authentication %s " _RED_("failed") ". Result [%d] %s", DesfireWayIDStr(selectway, id), res, DesfireAuthErrorToStr(res));
        return res;
    }

    if (dctx.cmdSet != DCCISO)
        res = DesfileReadFileAndPrint(&dctx, fnum, op, offset, length, 0, noauth, verbose);
    else
        res = DesfileReadISOFileAndPrint(&dctx, fileisoidpresent, fnum, fileisoid, op, offset, length, noauth, verbose);

    DropField();
    return res;
}

static int DesfileWriteISOFile(DesfireContext_t *dctx,
                               bool select_current_file, uint8_t fnum,
                               uint16_t fisoid, int filetype,
                               uint32_t offset, uint8_t *data,
                               uint32_t datalen, bool verbose) {

    if (filetype == RFTAuto) {
        PrintAndLogEx(ERR, "ISO mode needs to specify file type");
        return PM3_EINVARG;
    }

    if (filetype == RFTValue) {
        PrintAndLogEx(ERR, "ISO mode can't write Value file type");
        return PM3_EINVARG;
    }

    if (filetype == RFTMAC) {
        PrintAndLogEx(ERR, "ISO mode can't write Transaction MAC file type");
        return PM3_EINVARG;
    }

    if (dctx->commMode != DCMPlain) {
        PrintAndLogEx(ERR, "ISO mode can write only in plain mode");
        return PM3_EINVARG;
    }

    int res;
    if (filetype == RFTData) {
        res = DesfireISOUpdateBinary(dctx, !select_current_file, (select_current_file) ? 0x00 : fnum, offset, data, datalen);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Desfire ISOUpdateBinary command " _RED_("error") ". Result: %d", res);
            return PM3_ESOFT;
        }

        if (select_current_file)
            PrintAndLogEx(INFO, "Write data file %04x " _GREEN_("success"), fisoid);
        else
            PrintAndLogEx(INFO, "Write data file %02x " _GREEN_("success"), fnum);
    }

    if (filetype == RFTRecord) {
        res = DesfireISOAppendRecord(dctx, (select_current_file) ? 0x00 : fnum, data, datalen);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Desfire WriteRecord command " _RED_("error") ". Result: %d", res);
            return PM3_ESOFT;
        }
        if (select_current_file)
            PrintAndLogEx(INFO, "Write record to file %04x " _GREEN_("success"), fisoid);
        else
            PrintAndLogEx(INFO, "Write record to file %02x " _GREEN_("success"), fnum);
    }

    return PM3_SUCCESS;
}

static int CmdHF14ADesWriteData(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes write",
                  "Write data from file. Key needs to be provided or flag --no-auth set (depend on file settings).",
                  "In the mode with CommitReaderID to decode previous reader id command needs to read transaction counter via dump/read command and specify --trkey\n"
                  "\n"
                  "hf mfdes write --aid 123456 --fid 01 -d 01020304 -> AID 123456, file=01, offset=0, get file type from card. use default channel settings from `default` command\n"
                  "hf mfdes write --aid 123456 --fid 01 --type data -d 01020304 --offset 000100 -> write data to std file with offset 0x100\n"
                  "hf mfdes write --aid 123456 --fid 01 --type data -d 01020304 --commit -> write data to backup file with commit\n"
                  "hf mfdes write --aid 123456 --fid 01 --type value -d 00000001 -> increment value file\n"
                  "hf mfdes write --aid 123456 --fid 01 --type value -d 00000001 --debit -> decrement value file\n"
                  "hf mfdes write --aid 123456 --fid 01 -d 01020304 -> write data to file with `auto` type\n"
                  "hf mfdes write --aid 123456 --fid 01 --type record -d 01020304 -> write data to record file\n"
                  "hf mfdes write --aid 123456 --fid 01 --type record -d 01020304 --updaterec 0 -> update record in the record file. record 0 - lastest record.\n"
                  "hf mfdes write --aid 123456 --fid 01 --type record --offset 000000 -d 11223344 -> write record to record file. use default channel settings from `default` command\n"
                  "hf mfdes write --isoid 1234 --fileisoid 1000 --type data -c iso -d 01020304 -> write data to std/backup file via iso commandset\n"
                  "hf mfdes write --isoid 1234 --fileisoid 2000 --type record -c iso -d 01020304 -> send record to record file via iso commandset\n"
                  "hf mfdes write --aid 123456 --fid 01 -d 01020304 --readerid 010203 -> write data to file with CommitReaderID command before write and CommitTransaction after write\n"
                  "hf mfdes write --isoid df01 --fid 04 -d 01020304 --trkey 00112233445566778899aabbccddeeff --readerid 5532 -t aes --schann lrp -> advanced CommitReaderID via lrp channel sample");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "fid",     "<hex>", "File ID (1 hex byte)"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_str0(NULL, "type",    "<auto|data|value|record|mac>", "File Type, Auto - check file settings and then write. (def: auto)"),
        arg_str0("o",  "offset",  "<hex>", "File Offset (3 hex bytes, big endian). For records - record number (0 - lastest record). (def: 0)"),
        arg_str0("d",  "data",    "<hex>", "data for write (data/record file), credit/debit(value file)"),
        arg_lit0(NULL, "debit",   "use for value file debit operation instead of credit"),
        arg_lit0(NULL, "commit",  "commit needs for backup file only. For the other file types and in the `auto` mode - command set it automatically"),
        arg_int0(NULL, "updaterec", "<dec>", "Record number for update record command. Updates record instead of write. Lastest record - 0"),
        arg_str0(NULL, "isoid",  "<hex>", "Application ISO ID (ISO DF ID) (2 hex bytes, big endian)"),
        arg_str0(NULL, "fileisoid", "<hex>", "File ISO ID (ISO DF ID) (2 hex bytes, big endian). Works only for ISO write commands"),
        arg_str0(NULL, "readerid",  "<hex>", "reader id for CommitReaderID command. If present - the command issued before write command"),
        arg_str0(NULL, "trkey",     "<hex>", "key for decode previous reader id"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 13);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t id = 0x000000;
    DesfireISOSelectWay selectway = ISW6bAID;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 20, 0, &securechann, DCMMACed, &id, &selectway);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint32_t fnum = 1;
    if (CLIGetUint32Hex(ctx, 12, 1, &fnum, NULL, 1, "File ID must have 1 byte length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int op = RFTAuto;
    if (CLIGetOptionList(arg_get_str(ctx, 14), DesfireReadFileTypeOpts, &op)) {
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    uint32_t offset = 0;
    if (CLIGetUint32Hex(ctx, 15, 0, &offset, NULL, 3, "Offset must have 3 byte length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t data[1024] = {0};
    int datalen = sizeof(data);
    CLIGetHexWithReturn(ctx, 16, data, &datalen);
    if (datalen == 0) {
        PrintAndLogEx(ERR, "Data for write must be present.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool debit = arg_get_lit(ctx, 17);
    bool commit = arg_get_lit(ctx, 18);

    int updaterecno = arg_get_int_def(ctx, 19, -1);

    uint32_t fileisoid = 0x0000;
    bool fileisoidpresent = false;
    if (CLIGetUint32Hex(ctx, 21, 0x0000, &fileisoid, &fileisoidpresent, 2, "File ISO ID (for DF) must have 2 bytes length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t readerid[250] = {0};
    int readeridlen = sizeof(readerid);
    CLIGetHexWithReturn(ctx, 22, readerid, &readeridlen);
    if (readeridlen > 16) {
        PrintAndLogEx(ERR, "ReaderID must be up to 16 bytes length.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t trkey[250] = {0};
    int trkeylen = sizeof(trkey);
    CLIGetHexWithReturn(ctx, 23, trkey, &trkeylen);
    if (trkeylen > 0 && trkeylen != 16) {
        PrintAndLogEx(ERR, "Transaction key must be 16 bytes length.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    if (fnum > 0x1F) {
        PrintAndLogEx(ERR, "File number range is invalid (exp 0x00 - 0x1f), got 0x%02x", fnum);
        return PM3_EINVARG;
    }

    // get uid
    if (trkeylen > 0)
        DesfireGetCardUID(&dctx);

    res = DesfireSelectAndAuthenticateW(&dctx, securechann, selectway, id, fileisoidpresent, fileisoid, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(FAILED, "Select or authentication %s " _RED_("failed") ". Result [%d] %s", DesfireWayIDStr(selectway, id), res, DesfireAuthErrorToStr(res));
        return res;
    }

    // ISO command set
    if (dctx.cmdSet == DCCISO) {
        if (op == RFTRecord && updaterecno >= 0) {
            PrintAndLogEx(ERR, "ISO mode can't update record. Only append.");
            DropField();
            return PM3_EINVARG;
        }

        res = DesfileWriteISOFile(&dctx, fileisoidpresent, fnum, fileisoid, op, offset, data, datalen, verbose);
        DropField();
        return res;
    }

    // get file settings
    if (op == RFTAuto) {
        FileSettings_t fsettings;

        DesfireCommunicationMode commMode = dctx.commMode;
        DesfireSetCommMode(&dctx, DCMMACed);
        res = DesfireFileSettingsStruct(&dctx, fnum, &fsettings);
        DesfireSetCommMode(&dctx, commMode);

        if (res == PM3_SUCCESS) {
            switch (fsettings.fileType) {
                case 0x00:
                case 0x01: {
                    op = RFTData;
                    if (!commit)
                        commit = (fsettings.fileType == 0x01);
                    break;
                }
                case 0x02: {
                    op = RFTValue;
                    commit = true;
                    break;
                }
                case 0x03:
                case 0x04: {
                    op = RFTRecord;
                    commit = true;
                    if (datalen > fsettings.recordSize)
                        PrintAndLogEx(WARNING, "Record size (%d) " _RED_("is less") " than data length (%d)", fsettings.recordSize, datalen);
                    break;
                }
                case 0x05: {
                    op = RFTMAC;
                    commit = false;
                    break;
                }
                default: {
                    break;
                }
            }

            DesfireSetCommMode(&dctx, fsettings.commMode);

            if (fsettings.fileCommMode != 0 && noauth)
                PrintAndLogEx(WARNING, "File needs communication mode `%s` but there is no authentication", CLIGetOptionListStr(DesfireCommunicationModeOpts, fsettings.commMode));

            if ((fsettings.rAccess < 0x0e && fsettings.rAccess != dctx.keyNum) && (fsettings.rwAccess < 0x0e && fsettings.rwAccess != dctx.keyNum))
                PrintAndLogEx(WARNING, "File needs to be authenticated with key 0x%02x or 0x%02x but current authentication key is 0x%02x", fsettings.rAccess, fsettings.rwAccess, dctx.keyNum);

            if (fsettings.rAccess == 0x0f && fsettings.rwAccess == 0x0f)
                PrintAndLogEx(WARNING, "File access denied. All read access rights is 0x0f.");

            if (verbose)
                PrintAndLogEx(INFO, "Got file type: %s. Option: %s. comm mode: %s",
                              GetDesfireFileType(fsettings.fileType),
                              CLIGetOptionListStr(DesfireReadFileTypeOpts, op),
                              CLIGetOptionListStr(DesfireCommunicationModeOpts, fsettings.commMode));
        } else {
            PrintAndLogEx(WARNING, "GetFileSettings error. Can't get file type.");
        }
    }

    // CommitReaderID command
    bool readeridpushed = false;
    if (readeridlen > 0) {
        uint8_t resp[250] = {0};
        size_t resplen = 0;

        DesfireCommunicationMode commMode = dctx.commMode;
        DesfireSetCommMode(&dctx, DCMMACed);
        res = DesfireCommitReaderID(&dctx, readerid, readeridlen, resp, &resplen);
        DesfireSetCommMode(&dctx, commMode);

        if (res == PM3_SUCCESS) {
            PrintAndLogEx(INFO, _GREEN_("Commit Reader ID: "));
            PrintAndLogEx(INFO, "Prev reader id encoded [%zu]: %s", resplen, sprint_hex(resp, resplen));

            if (trkeylen > 0) {
                uint8_t prevReaderID[CRYPTO_AES_BLOCK_SIZE] = {0};
                DesfireDecodePrevReaderID(&dctx, trkey, transactionCounter, resp, prevReaderID);
                PrintAndLogEx(INFO, "Prev reader id: %s", sprint_hex(prevReaderID, CRYPTO_AES_BLOCK_SIZE));
            }

            readeridpushed = true;
            if (verbose)
                PrintAndLogEx(INFO, "CommitReaderID ( " _GREEN_("ok") " )");
        } else
            PrintAndLogEx(WARNING, "Desfire CommitReaderID command " _RED_("error") ". Result: %d", res);
    }

    // iso chaining works in the lrp mode
    dctx.isoChaining |= (dctx.secureChannel == DACLRP);

    // write
    if (op == RFTData) {
        res = DesfireWriteFile(&dctx, fnum, offset, datalen, data);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Desfire WriteFile command " _RED_("error") ". Result: %d", res);
            DropField();
            return PM3_ESOFT;
        }

        if (verbose)
            PrintAndLogEx(INFO, "Write data file %02x " _GREEN_("success"), fnum);
    }

    if (op == RFTValue) {
        if (datalen != 4) {
            PrintAndLogEx(ERR, "Value " _RED_("should be") " 4 byte length instead of %d", datalen);
            DropField();
            return PM3_EINVARG;
        }

        uint32_t value = MemBeToUint4byte(data);
        uint8_t vop = (debit) ? MFDES_DEBIT : MFDES_CREDIT;
        res = DesfireValueFileOperations(&dctx, fnum, vop, &value);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Desfire %s operation " _RED_("error") ". Result: %d", CLIGetOptionListStr(DesfireValueFileOperOpts, vop), res);
            DropField();
            return PM3_ESOFT;
        }

        if (verbose)
            PrintAndLogEx(INFO, "%s value file %02x (%s)  " _GREEN_("success"), (debit) ? "Debit" : "Credit", fnum, CLIGetOptionListStr(DesfireValueFileOperOpts, vop));
        commit = true;
    }

    if (op == RFTRecord) {
        if (updaterecno < 0) {
            res = DesfireWriteRecord(&dctx, fnum, offset, datalen, data);
            if (res != PM3_SUCCESS) {
                PrintAndLogEx(ERR, "Desfire WriteRecord command " _RED_("error") ". Result: %d", res);
                DropField();
                return PM3_ESOFT;
            }
            if (verbose)
                PrintAndLogEx(INFO, "Write record file %02x " _GREEN_("success"), fnum);
        } else {
            res = DesfireUpdateRecord(&dctx, fnum, updaterecno, offset, datalen, data);
            if (res != PM3_SUCCESS) {
                PrintAndLogEx(ERR, "Desfire UpdateRecord command " _RED_("error") ". Result: %d", res);
                DropField();
                return PM3_ESOFT;
            }
            if (verbose)
                PrintAndLogEx(INFO, "Update record %06x in the file %02x " _GREEN_("success"), updaterecno, fnum);
        }

        commit = true;
    }

    if (op == RFTMAC) {
        PrintAndLogEx(ERR, "Can't " _RED_("write") " to transaction MAC file");
        DropField();
        return PM3_EINVARG;
    }

    // commit phase
    if (commit || readeridpushed) {
        uint8_t resp[250] = {0};
        size_t resplen = 0;
        DesfireSetCommMode(&dctx, DCMMACed);
        res = DesfireCommitTransactionEx(&dctx, readeridpushed, 0x01, resp, &resplen);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Desfire CommitTransaction command " _RED_("error") ". Result: %d", res);
            DropField();
            return PM3_ESOFT;
        }

        if (verbose) {
            if (readeridpushed)
                PrintAndLogEx(INFO, "TMC and TMV[%zu]: %s", resplen, sprint_hex(resp, resplen));
            PrintAndLogEx(INFO, "Commit ( " _GREEN_("ok") " )");
        }

        if (resplen == 4 + 8) {
            PrintAndLogEx(INFO, _GREEN_("Commit result:"));
            uint32_t cnt = MemLeToUint4byte(&resp[0]);
            transactionCounter = cnt;
            if (dctx.secureChannel != DACLRP) {
                PrintAndLogEx(SUCCESS, "Transaction counter: %d (0x%08x)", cnt, cnt);
            } else {
                // For composing TMC the two subparts are concatenated as follows: actTMC || sesTMC. Both subparts are represented LSB first.
                // MF2DLHX0.pdf, 10.3.2.1 Transaction MAC Counter, page 41
                uint32_t actTMC = MemLeToUint2byte(&resp[0]);
                uint32_t sessTMC = MemLeToUint2byte(&resp[2]);
                PrintAndLogEx(SUCCESS, "Session tr counter : %d (0x%04x)", sessTMC, sessTMC);
                PrintAndLogEx(SUCCESS, "Actual tr counter  : %d (0x%04x)", actTMC, actTMC);
            }
            PrintAndLogEx(SUCCESS, "Transaction MAC    : %s", sprint_hex(&resp[4], 8));
        }
    }

    PrintAndLogEx(INFO, "Write %s file %02x " _GREEN_("success"), CLIGetOptionListStr(DesfireReadFileTypeOpts, op), fnum);

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesLsFiles(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes lsfiles",
                  "This commands List files inside application AID / ISOID.\n"
                  "Master key needs to be provided or flag --no-auth set (depend on cards settings).",
                  "hf mfdes lsfiles --aid 123456            -> AID 123456, list files using `default` command creds\n"
                  "hf mfdes lsfiles --isoid df01 --no-auth  -> list files for DESFire light\n"
                  "hf mfdes lsfiles --dfname D2760000850100 -> select DF by name and list files");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "isoid",   "<hex>", "Application ISO ID (ISO DF ID) (2 hex bytes, big endian)"),
        arg_str0(NULL, "dfname",  "<hex>", "Application ISO DF Name (5-16 hex bytes, big endian)"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 14);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t id = 0x000000;
    DesfireISOSelectWay selectway = ISW6bAID;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, &securechann, DCMMACed, &id, &selectway);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    res = DesfireSelectAndAuthenticateAppW(&dctx, securechann, selectway, id, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(FAILED, "Select or authentication %s " _RED_("failed") ". Result [%d] %s", DesfireWayIDStr(selectway, id), res, DesfireAuthErrorToStr(res));
        return res;
    }

    FileList_t FileList = {{0}};
    size_t filescount = 0;
    bool isopresent = false;
    res = DesfireFillFileList(&dctx, FileList, &filescount, &isopresent);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    if (filescount == 0) {
        PrintAndLogEx(INFO, "There are no files in the %s", DesfireWayIDStr(selectway, id));
        DropField();
        return PM3_SUCCESS;
    }

    PrintAndLogEx(INFO, "------------------------------------------ " _CYAN_("File list") " -----------------------------------------------------");
    for (int i = 0; i < filescount; i++)
        DesfirePrintFileSettingsTable((i == 0), FileList[i].fileNum, isopresent, FileList[i].fileISONum, &FileList[i].fileSettings);

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesLsApp(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes lsapp",
                  "Show application list. Master key needs to be provided or flag --no-auth set (depend on cards settings).",
                  "hf mfdes lsapp           -> show application list with defaults from `default` command\n"
                  "hf mfdes lsapp --files   -> show application list and show each file type/settings/etc\n"
                  "hf mfdes lsapp --dfname D2760000850100 -> list apps after selecting DF by name");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_lit0(NULL, "no-deep", "not to check authentication commands that avail for any application"),
        arg_lit0(NULL, "files",   "scan files and print file settings"),
        arg_str0(NULL, "dfname",  "<hex>", "Application ISO DF Name (5-16 hex bytes, big endian)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 11);
    bool nodeep = arg_get_lit(ctx, 12);
    bool scanfiles = arg_get_lit(ctx, 13);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 14, &securechann, (noauth) ? DCMPlain : DCMMACed, NULL, NULL);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "It may take up to " _YELLOW_("15") " seconds. Processing...");

    res = DesfireSelectAndAuthenticateEx(&dctx, securechann, 0x000000, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    PICCInfo_t PICCInfo = {0};
    AppListS AppList = {{0}};
    DesfireFillAppList(&dctx, &PICCInfo, AppList, !nodeep, scanfiles, true);

    PrintAndLogEx(NORMAL, "");

    // print zone
    DesfirePrintPICCInfo(&dctx, &PICCInfo);
    DesfirePrintAppList(&dctx, &PICCInfo, AppList);

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesDump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes dump",
                  "For each application show fil list and then file content. Key needs to be provided for authentication or flag --no-auth set (depend on cards settings).",
                  "hf mfdes dump --aid 123456     -> show file dump for: app=123456 with channel defaults from `default` command/n"
                  "hf mfdes dump --isoid df01 --schann lrp -t aes --length 000090    -> lrp default settings with length limit");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_int0("n",  "keyno",   "<dec>", "Key number"),
        arg_str0("t",  "algo",    "<DES|2TDEA|3TDEA|AES>",  "Crypt algo"),
        arg_str0("k",  "key",     "<hex>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "kdf",     "<none|AN10922|gallagher>",   "Key Derivation Function (KDF)"),
        arg_str0("i",  "kdfi",    "<hex>",  "KDF input (1-31 hex bytes)"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communicaton mode"),
        arg_str0("c",  "ccset",   "<native|niso|iso>", "Communicaton command set"),
        arg_str0(NULL, "schann",  "<d40|ev1|ev2|lrp>", "Secure channel"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "isoid",   "<hex>", "Application ISO ID (ISO DF ID) (2 hex bytes, big endian)"),
        arg_str0(NULL, "dfname",  "<hex>", "Application ISO DF Name (5-16 hex bytes, big endian)"),
        arg_str0("l", "length",   "<hex>", "Maximum length for read data files (3 hex bytes, big endian)"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 15);

    DesfireContext_t dctx = {0};
    int securechann = defaultSecureChannel;
    uint32_t id = 0x000000;
    DesfireISOSelectWay selectway = ISW6bAID;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, &securechann, (noauth) ? DCMPlain : DCMMACed, &id, &selectway);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint32_t maxlength = 0;
    if (CLIGetUint32Hex(ctx, 14, 0, &maxlength, NULL, 3, "Length parameter must have 3 byte length")) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    res = DesfireSelectAndAuthenticateAppW(&dctx, securechann, selectway, id, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(FAILED, "Select or authentication %s " _RED_("failed") ". Result [%d] %s", DesfireWayIDStr(selectway, id), res, DesfireAuthErrorToStr(res));
        return res;
    }

    FileList_t FileList = {{0}};
    size_t filescount = 0;
    bool isopresent = false;
    res = DesfireFillFileList(&dctx, FileList, &filescount, &isopresent);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "Application " _CYAN_("%s") " have " _GREEN_("%zu") " files", DesfireWayIDStr(selectway, id), filescount);

    if (selectway == ISW6bAID)
        DesfirePrintAIDFunctions(id);

    if (filescount == 0) {
        PrintAndLogEx(INFO, "There is no files in the application %s", DesfireWayIDStr(selectway, id));
        DropField();
        return res;
    }

    res = PM3_SUCCESS;
    for (int i = 0; i < filescount; i++) {
        if (res != PM3_SUCCESS) {
            DesfireSetCommMode(&dctx, DCMPlain);
            res = DesfireSelectAndAuthenticateAppW(&dctx, securechann, selectway, id, noauth, verbose);
            if (res != PM3_SUCCESS) {
                DropField();
                return res;
            }
        }

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "--------------------------------- " _CYAN_("File %02x") " ----------------------------------", FileList[i].fileNum);
        PrintAndLogEx(SUCCESS, "File ID         : " _GREEN_("%02x"), FileList[i].fileNum);
        if (isopresent) {
            if (FileList[i].fileISONum != 0)
                PrintAndLogEx(SUCCESS, "File ISO ID     : %04x", FileList[i].fileISONum);
            else
                PrintAndLogEx(SUCCESS, "File ISO ID     : " _YELLOW_("n/a"));
        }
        DesfirePrintFileSettingsExtended(&FileList[i].fileSettings);

        res = DesfileReadFileAndPrint(&dctx, FileList[i].fileNum, RFTAuto, 0, 0, maxlength, noauth, verbose);
    }

    DropField();
    return PM3_SUCCESS;
}

// Generate `len` random bytes using the CSPRNG.
static int duox_gen_random(uint8_t *buf, size_t len, const char *pers) {
    pcrypto_rng_t rng = {0};
    int res = pcrypto_rng_init(&rng, (const uint8_t *)pers, strlen(pers));
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to initialize RNG");
        return res;
    }
    res = pcrypto_rng_fill(&rng, buf, len);
    pcrypto_rng_free(&rng);
    if (res != PM3_SUCCESS)
        PrintAndLogEx(ERR, "Failed to generate random bytes");
    return res;
}

// Build and send ISO Internal Authenticate (INS 88), then parse the TLV response.
// Assumes the application is already selected (field on). Calls DropField before returning.
// On PM3_SUCCESS: out_card_random[DUOX_INTAUTH_CHALLENGE_LEN] and out_sig_rs[DUOX_INTAUTH_SIG_LEN] are filled.
static int duox_intauth_exchange(bool apdu_logging, bool verbose, uint8_t keynum,
                                  const uint8_t *challenge,
                                  uint8_t *out_card_random, uint8_t *out_sig_rs) {
    // Build ISO Internal Authenticate APDU
    //
    // Data field:
    //   80 00           - OptsA TLV (tag=0x80, len=0x00, empty value)
    //   7C 12           - Dynamic Authentication Data wrapper (tag=0x7C, len=18)
    //     81 10 [16B]   - Challenge TLV (tag=0x81, len=16, value=RndA)
    //
    // APDU: CLA=00 INS=88 P1=00 P2=00 Lc=16 [data] Le=00
    static const uint8_t optsa_tlv[] = {DUOX_TAG_OPTSA, 0x00};
    uint8_t apdu_data[22];
    size_t apdu_data_len = 0;

    memcpy(apdu_data, optsa_tlv, 2);
    apdu_data_len += 2;
    apdu_data[apdu_data_len++] = DUOX_TAG_DYNAMIC_AUTH_DATA;
    apdu_data[apdu_data_len++] = 2 + DUOX_INTAUTH_CHALLENGE_LEN;
    apdu_data[apdu_data_len++] = DUOX_TAG_CHALLENGE;
    apdu_data[apdu_data_len++] = DUOX_INTAUTH_CHALLENGE_LEN;
    memcpy(apdu_data + apdu_data_len, challenge, DUOX_INTAUTH_CHALLENGE_LEN);
    apdu_data_len += DUOX_INTAUTH_CHALLENGE_LEN;

    // Encode full APDU: 00 88 00 [keynum] [Lc] [data] 00
    sAPDU_t apdu = {0x00, ISO7816_INTERNAL_AUTHENTICATION, 0x00, keynum, apdu_data_len, apdu_data};
    uint8_t encoded[50] = {0};
    int encoded_len = 0;
    if (APDUEncodeS(&apdu, false, APDU_INCLUDE_LE_00, encoded, &encoded_len)) {
        PrintAndLogEx(ERR, "APDU encoding error");
        DropField();
        return PM3_ESOFT;
    }

    if (apdu_logging)
        PrintAndLogEx(SUCCESS, ">>>> %s", sprint_hex(encoded, encoded_len));

    uint8_t response[PM3_CMD_DATA_SIZE] = {0};
    int resplen = 0;
    int res = ExchangeAPDU14a(encoded, encoded_len, false, true, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "APDU exchange " _RED_("failed") " (%d)", res);
        DropField();
        return res;
    }

    if (apdu_logging)
        PrintAndLogEx(SUCCESS, "<<<< %s", sprint_hex(response, resplen));

    DropField();

    // Check status word
    if (resplen < 2) {
        PrintAndLogEx(ERR, "Response too short");
        return PM3_ESOFT;
    }

    uint16_t sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Internal Authenticate " _RED_("failed") " (SW=%04X)", sw);
        return PM3_ESOFT;
    }

    // Strip SW from response data
    int resp_data_len = resplen - 2;
    PrintAndLogEx(SUCCESS, "Internal Authenticate " _GREEN_("ok") " (SW=%04X)", sw);

    if (verbose)
        PrintAndLogEx(INFO, "Response data: %s", sprint_hex(response, resp_data_len));

    // Parse TLV response
    // Expected: 7C [len] 81 10 [card_random(16)] 82 [sig_len] [signature]
    uint8_t *resp = response;
    if (resp_data_len < 4 || resp[0] != DUOX_TAG_DYNAMIC_AUTH_DATA) {
        PrintAndLogEx(ERR, "Invalid response: missing 0x7C tag");
        return PM3_ESOFT;
    }

    uint8_t outer_len = resp[1];
    if (outer_len + 2 > resp_data_len) {
        PrintAndLogEx(ERR, "Invalid response: truncated 0x7C data");
        return PM3_ESOFT;
    }

    uint8_t *inner = resp + 2;
    int inner_len = outer_len;
    int idx = 0;

    bool card_random_found = false;
    bool signature_found = false;

    while (idx < inner_len) {
        if (idx + 2 > inner_len) break;
        uint8_t tag = inner[idx++];
        uint8_t tlen = inner[idx++];
        if (idx + tlen > inner_len) break;

        if (tag == DUOX_TAG_CHALLENGE && tlen == DUOX_INTAUTH_CHALLENGE_LEN) {
            memcpy(out_card_random, inner + idx, DUOX_INTAUTH_CHALLENGE_LEN);
            card_random_found = true;
        } else if (tag == DUOX_TAG_SIGNATURE) {
            // Signature: raw r||s. Some implementations may return 0x44 bytes with padding.
            if (tlen >= DUOX_INTAUTH_SIG_LEN) {
                memcpy(out_sig_rs, inner + idx + (tlen - DUOX_INTAUTH_SIG_LEN), DUOX_INTAUTH_SIG_LEN);
                signature_found = true;
            }
        }
        idx += tlen;
    }
    if (!card_random_found) {
        PrintAndLogEx(ERR, "Failed to parse card random (tag 0x81) from response");
        return PM3_ESOFT;
    }
    if (!signature_found) {
        PrintAndLogEx(ERR, "Failed to parse signature (tag 0x82) from response");
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "Card random.. " _YELLOW_("%s"), sprint_hex_inrow(out_card_random, DUOX_INTAUTH_CHALLENGE_LEN));
    PrintAndLogEx(INFO, "Signature r.. " _YELLOW_("%s"), sprint_hex_inrow(out_sig_rs, DUOX_INTAUTH_SIG_LEN / 2));
    PrintAndLogEx(INFO, "Signature s.. " _YELLOW_("%s"), sprint_hex_inrow(out_sig_rs + DUOX_INTAUTH_SIG_LEN / 2, DUOX_INTAUTH_SIG_LEN / 2));
    return PM3_SUCCESS;
}

// Build the Internal Authenticate verify message (F0F0 || OptsA || RndB || RndA)
// and verify the ECDSA-P256-SHA256 signature. Returns PM3_SUCCESS if valid.
static int duox_intauth_verify_sig(bool verbose, const uint8_t *pubkey_point,
                                    const uint8_t *challenge, const uint8_t *card_random,
                                    const uint8_t *sig_rs) {                                        
    // Message = F0F0 || OptsA TLV || RndB (card random) || RndA (our challenge)
    static const uint8_t optsa_tlv[] = {DUOX_TAG_OPTSA, 0x00};
    uint8_t message[2 + 2 + DUOX_INTAUTH_CHALLENGE_LEN + DUOX_INTAUTH_CHALLENGE_LEN];
    message[0] = DUOX_INTAUTH_MSG_PREFIX;
    message[1] = DUOX_INTAUTH_MSG_PREFIX;
    memcpy(message + 2, optsa_tlv, 2);
    memcpy(message + 4, card_random, DUOX_INTAUTH_CHALLENGE_LEN);
    memcpy(message + 20, challenge, DUOX_INTAUTH_CHALLENGE_LEN);

    if (verbose)
        PrintAndLogEx(INFO, "Verify msg... %s", sprint_hex_inrow(message, sizeof(message)));
    
    return ecdsa_signature_r_s_verify(
        MBEDTLS_ECP_DP_SECP256R1,
        (uint8_t *)pubkey_point,
        message,
        (int)sizeof(message),
        (uint8_t *)sig_rs,
        DUOX_INTAUTH_SIG_LEN,
        true // hash message with SHA-256 before verifying
    );
}

static int CmdHF14ADesIntAuth(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes intauth",
                  "Perform ISO Internal Authenticate (ECDSA challenge-response) on MIFARE DUOX.\n"
                  "Card signs a fresh challenge to prove it possesses its private key.\n"
                  "Optionally verifies the card's ECDSA-P256 signature with a given public key.",
                  "hf mfdes intauth                                    -> authenticate with default AID (000000), random challenge\n"
                  "hf mfdes intauth --aid D61CF5                       -> explicit AID\n"
                  "hf mfdes intauth --dfname D2760000850100            -> select by DF name\n"
                  "hf mfdes intauth -d 00112233445566778899AABBCCDDEEFF -> explicit 16-byte challenge\n"
                  "hf mfdes intauth -p 04AABB...                       -> verify signature with given EC public key (hex, PEM, DER, file path)\n"
                  "hf mfdes intauth -n 1                               -> use key number 1\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",      "Show APDU requests and responses"),            // 1
        arg_lit0("v",  "verbose",   "Verbose output"),                              // 2
        arg_str0("d",  "challenge", "<hex>", "Challenge / RndA (16 bytes, random if omitted)"), // 3
        arg_str0("p",  "pubkey",    "<hex|pem|der|path>", "EC public key for signature verification"), // 4
        arg_str0(NULL, "aid",       "<hex>", "Application ID (3 bytes, default 000000)"), // 5
        arg_int0("n",  "keynum",   "<dec>", "Key number (P2, default 0)"),          // 6
        arg_str0(NULL, "dfname",   "<hex>", "Application ISO DF Name (1-16 hex bytes)"), // 7
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    // Parse challenge
    uint8_t challenge[DUOX_INTAUTH_CHALLENGE_LEN] = {0};
    int challenge_len = 0;
    CLIGetHexWithReturn(ctx, 3, challenge, &challenge_len);
    bool challenge_provided = (challenge_len > 0);

    if (challenge_provided && challenge_len != DUOX_INTAUTH_CHALLENGE_LEN) {
        PrintAndLogEx(ERR, "Challenge must be exactly 16 bytes, got %d", challenge_len);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    // Parse public key input (flexible: hex, PEM, DER, file path)
    char pubkey_input[DUOX_MAX_KEY_INPUT] = {0};
    int pubkey_input_len = 0;
    CLIParamStrToBuf(arg_get_str(ctx, 4), (uint8_t *)pubkey_input, sizeof(pubkey_input) - 1, &pubkey_input_len);
    bool pubkey_provided = (pubkey_input_len > 0);

    // Parse AID
    uint8_t aid_bytes[3] = {0x00, 0x00, 0x00};
    int aid_len = 0;
    CLIGetHexWithReturn(ctx, 5, aid_bytes, &aid_len);
    if (aid_len > 0 && aid_len != 3) {
        PrintAndLogEx(ERR, "AID must be exactly 3 bytes, got %d", aid_len);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int keynum = arg_get_int_def(ctx, 6, 0);
    if (keynum < 0 || keynum > 255) {
        PrintAndLogEx(ERR, "Key number must be 0..255");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t dfname[16] = {0};
    int dfnamelen = 0;
    if (CLIParamHexToBuf(arg_get_str(ctx, 7), dfname, sizeof(dfname), &dfnamelen)) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    if (dfnamelen > 16) {
        PrintAndLogEx(ERR, "DF name must be 1-16 bytes, got %d", dfnamelen);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    // Load and validate public key if provided
    uint8_t pubkey_point[65] = {0}; // 04 || X || Y
    if (pubkey_provided) {
        int pk_res = ensure_ec_public_key(pubkey_input, MBEDTLS_ECP_DP_SECP256R1, pubkey_point, sizeof(pubkey_point));
        if (pk_res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Failed to load EC public key");
            PrintAndLogEx(INFO, "Accepted formats: raw hex (64/65/33 bytes), PEM, DER, base64, or file path");
            return pk_res;
        }
    }

    // Generate random challenge if not provided
    if (!challenge_provided) {
        int res = duox_gen_random(challenge, sizeof(challenge), "hf_mfdes_intauth");
        if (res != PM3_SUCCESS) return res;
    }

    // AID is stored little-endian in DESFire protocol
    uint32_t aid = (aid_bytes[2] << 16) | (aid_bytes[1] << 8) | aid_bytes[0];

    PrintAndLogEx(INFO, "--- " _CYAN_("ISO Internal Authenticate"));
    PrintAndLogEx(INFO, "Challenge.... " _YELLOW_("%s"), sprint_hex_inrow(challenge, DUOX_INTAUTH_CHALLENGE_LEN));
    if (verbose) {
        if (dfnamelen > 0)
            PrintAndLogEx(INFO, "DF name...... " _YELLOW_("%s"), sprint_hex_inrow(dfname, dfnamelen));
        else
            PrintAndLogEx(INFO, "AID.......... " _YELLOW_("%02X%02X%02X"), aid_bytes[0], aid_bytes[1], aid_bytes[2]);
        PrintAndLogEx(INFO, "Key number... " _YELLOW_("%d"), keynum);
    }

    // Step 1: Anticollision + select application using DESFire framework
    DesfireContext_t dctx = {0};
    dctx.commMode = DCMPlain;
    dctx.cmdSet = DCCNativeISO;

    int res = DesfireAnticollision(false);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Anticollision " _RED_("failed"));
        DropField();
        return res;
    }

    if (dfnamelen > 0) {
        uint8_t resp[250] = {0};
        size_t resplen = 0;
        res = DesfireISOSelect(&dctx, ISSDFName, dfname, dfnamelen, resp, &resplen);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Select DF name " _RED_("failed"));
            DropField();
            return res;
        }
    } else {
        res = DesfireSelectAIDHex(&dctx, aid, false, 0);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Select application %06X " _RED_("failed"), aid);
            DropField();
            return res;
        }
    }
    if (verbose)
        PrintAndLogEx(SUCCESS, "Application selected " _GREEN_("ok"));
    // Step 2: Build ISO Internal Authenticate APDU
    // Step 3: Parse TLV response

    uint8_t card_random[DUOX_INTAUTH_CHALLENGE_LEN] = {0};
    uint8_t signature_rs[DUOX_INTAUTH_SIG_LEN] = {0};
    res = duox_intauth_exchange(APDULogging, verbose, (uint8_t)keynum, challenge, card_random, signature_rs);
    if (res != PM3_SUCCESS)
        return res;

    // Step 4: Verify signature if public key provided
    if (pubkey_provided) {
        PrintAndLogEx(INFO, "--- " _CYAN_("Signature Verification"));
        int sig_res = duox_intauth_verify_sig(verbose, pubkey_point, challenge, card_random, signature_rs);
        if (sig_res == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "ECDSA signature " _GREEN_("verified"));
        } else {
            PrintAndLogEx(ERR, "ECDSA signature " _RED_("verification failed"));
        }
    }

    return PM3_SUCCESS;
}

static int CmdHF14ADesVdeSign(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes vdesign",
                  "Perform VDE_ECDSASign on MIFARE DUOX EV charging application.\n"
                  "Card signs a 32-byte challenge with the EV charging key (KeyNo 0x00).\n"
                  "Optionally verifies the returned ECDSA signature with a BrainpoolP256r1 public key.",
                  "hf mfdes vdesign                                             -> sign random 32-byte challenge using default EV DF name\n"
                  "hf mfdes vdesign --aid 1010F6                                -> select EV app by native AID\n"
                  "hf mfdes vdesign --dfname A0000008450000000000000000000001   -> select EV app by ISO DF name\n"
                  "hf mfdes vdesign -d 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF -> explicit 32-byte challenge\n"
                  "hf mfdes vdesign -p 04A7C6...                                -> verify signature with given EC public key (hex, PEM, DER, file path)\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",      "Show APDU requests and responses"),            // 1
        arg_lit0("v",  "verbose",   "Verbose output"),                              // 2
        arg_str0("d",  "challenge", "<hex>", "Challenge to sign (32 bytes, random if omitted)"), // 3
        arg_str0("p",  "pubkey",    "<hex|pem|der|path>", "BrainpoolP256r1 public key for signature verification"), // 4
        arg_str0(NULL, "aid",       "<hex>", "Application ID (3 bytes, native DESFire select)"), // 5
        arg_str0(NULL, "dfname",    "<hex>", "Application ISO DF Name (1-16 hex bytes, default EV DF name)"), // 6
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    uint8_t challenge[DUOX_VDE_CHALLENGE_LEN] = {0};
    int challenge_len = 0;
    CLIGetHexWithReturn(ctx, 3, challenge, &challenge_len);
    bool challenge_provided = (challenge_len > 0);
    if (challenge_provided && challenge_len != DUOX_VDE_CHALLENGE_LEN) {
        PrintAndLogEx(ERR, "Challenge must be exactly 32 bytes, got %d", challenge_len);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    char pubkey_input[DUOX_MAX_KEY_INPUT] = {0};
    int pubkey_input_len = 0;
    CLIParamStrToBuf(arg_get_str(ctx, 4), (uint8_t *)pubkey_input, sizeof(pubkey_input) - 1, &pubkey_input_len);
    bool pubkey_provided = (pubkey_input_len > 0);

    uint8_t aid_bytes[3] = {0};
    int aid_len = 0;
    CLIGetHexWithReturn(ctx, 5, aid_bytes, &aid_len);
    bool aid_provided = (aid_len > 0);
    if (aid_provided && aid_len != 3) {
        PrintAndLogEx(ERR, "AID must be exactly 3 bytes, got %d", aid_len);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t dfname[16] = {0};
    int dfnamelen = 0;
    if (CLIParamHexToBuf(arg_get_str(ctx, 6), dfname, sizeof(dfname), &dfnamelen)) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    bool dfname_provided = (dfnamelen > 0);
    if (dfnamelen > 16) {
        PrintAndLogEx(ERR, "DF name must be 1-16 bytes, got %d", dfnamelen);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    uint8_t pubkey_point[65] = {0}; // 04 || X || Y
    if (pubkey_provided) {
        int pk_res = ensure_ec_public_key(pubkey_input, MBEDTLS_ECP_DP_BP256R1, pubkey_point, sizeof(pubkey_point));
        if (pk_res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Failed to load BrainpoolP256r1 public key");
            PrintAndLogEx(INFO, "Accepted formats: raw hex (64/65/33 bytes), PEM, DER, base64, or file path");
            return pk_res;
        }
    }

    if (!challenge_provided) {
        int res = duox_gen_random(challenge, sizeof(challenge), "hf_mfdes_vdesign");
        if (res != PM3_SUCCESS) return res;
    }

    uint32_t aid = DUOX_VDE_DEFAULT_AID;
    if (aid_provided) {
        aid = ((uint32_t)aid_bytes[2] << 16) | ((uint32_t)aid_bytes[1] << 8) | aid_bytes[0];
    }

    const uint8_t *selected_dfname = NULL;
    uint8_t selected_dfname_len = 0;
    if (dfname_provided) {
        selected_dfname = dfname;
        selected_dfname_len = dfnamelen;
    } else if (!aid_provided) {
        selected_dfname = kDuoxVDEDefaultDFName;
        selected_dfname_len = ARRAYLEN(kDuoxVDEDefaultDFName);
    }

    PrintAndLogEx(INFO, "--- " _CYAN_("VDE_ECDSASign"));
    if (verbose) {
        if (selected_dfname_len > 0) {
            PrintAndLogEx(INFO, "DF name...... " _YELLOW_("%s"), sprint_hex_inrow(selected_dfname, selected_dfname_len));
            if (!dfname_provided)
                PrintAndLogEx(INFO, "Selection..... " _YELLOW_("default EV charging DF name"));
        } else {
            PrintAndLogEx(INFO, "AID.......... " _YELLOW_("%02X%02X%02X"), aid_bytes[0], aid_bytes[1], aid_bytes[2]);
        }
    }

    DesfireContext_t dctx = {0};
    dctx.commMode = DCMPlain;
    dctx.cmdSet = DCCNativeISO;

    int res = DesfireAnticollision(false);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Anticollision " _RED_("failed"));
        DropField();
        return res;
    }

    if (selected_dfname_len > 0) {
        uint8_t resp[250] = {0};
        size_t resplen = 0;
        res = DesfireISOSelect(&dctx, ISSDFName, (uint8_t *)selected_dfname, selected_dfname_len, resp, &resplen);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Select DF name " _RED_("failed"));
            DropField();
            return res;
        }
    } else {
        res = DesfireSelectAIDHex(&dctx, aid, false, 0);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Select application %06X " _RED_("failed"), aid);
            DropField();
            return res;
        }
    }
    if (verbose)
        PrintAndLogEx(SUCCESS, "Application selected " _GREEN_("ok"));
    PrintAndLogEx(INFO, "Challenge.... " _YELLOW_("%s"), sprint_hex_inrow(challenge, sizeof(challenge)));

    sAPDU_t apdu = {0x80, 0x03, 0x0C, 0x09, sizeof(challenge), challenge};
    uint8_t encoded[64] = {0};
    int encoded_len = 0;
    if (APDUEncodeS(&apdu, false, APDU_INCLUDE_LE_00, encoded, &encoded_len)) {
        PrintAndLogEx(ERR, "APDU encoding error");
        DropField();
        return PM3_ESOFT;
    }

    if (APDULogging)
        PrintAndLogEx(SUCCESS, ">>>> %s", sprint_hex(encoded, encoded_len));

    uint8_t response[PM3_CMD_DATA_SIZE] = {0};
    int resplen = 0;
    res = ExchangeAPDU14a(encoded, encoded_len, false, true, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "APDU exchange " _RED_("failed") " (%d)", res);
        DropField();
        return res;
    }

    if (APDULogging)
        PrintAndLogEx(SUCCESS, "<<<< %s", sprint_hex(response, resplen));

    DropField();

    if (resplen < 2) {
        PrintAndLogEx(ERR, "Response too short");
        return PM3_ESOFT;
    }

    uint16_t sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "VDE_ECDSASign " _RED_("failed") " (%04X - %s)", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return PM3_ESOFT;
    }

    int resp_data_len = resplen - 2;
    if (resp_data_len != DUOX_VDE_SIG_LEN) {
        PrintAndLogEx(ERR, "Unexpected signature length: %d bytes", resp_data_len);
        return PM3_ESOFT;
    }

    uint8_t signature_rs[DUOX_VDE_SIG_LEN] = {0};
    memcpy(signature_rs, response, sizeof(signature_rs));

    PrintAndLogEx(SUCCESS, "VDE_ECDSASign " _GREEN_("ok") " (SW=%04X)", sw);
    if (verbose)
        PrintAndLogEx(INFO, "Signature.... %s", sprint_hex_inrow(signature_rs, sizeof(signature_rs)));
    PrintAndLogEx(INFO, "Signature r.. " _YELLOW_("%s"), sprint_hex_inrow(signature_rs, DUOX_VDE_SIG_LEN / 2));
    PrintAndLogEx(INFO, "Signature s.. " _YELLOW_("%s"), sprint_hex_inrow(signature_rs + (DUOX_VDE_SIG_LEN / 2), DUOX_VDE_SIG_LEN / 2));

    if (pubkey_provided) {
        PrintAndLogEx(INFO, "--- " _CYAN_("Signature Verification"));
        if (verbose)
            PrintAndLogEx(INFO, "Verify msg... %s", sprint_hex_inrow(challenge, sizeof(challenge)));

        int sig_res = ecdsa_signature_r_s_verify(
            MBEDTLS_ECP_DP_BP256R1,
            pubkey_point,
            challenge,
            (int)sizeof(challenge),
            signature_rs,
            sizeof(signature_rs),
            true
        );

        if (sig_res == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "ECDSA signature " _GREEN_("verified"));
        } else {
            PrintAndLogEx(ERR, "ECDSA signature " _RED_("verification failed"));
        }
    }

    return PM3_SUCCESS;
}

// Look up an attribute in a DN by OID. Returns pointer to mbedtls value buf or NULL.
static const mbedtls_x509_buf *leaf_dn_find_oid(const mbedtls_x509_name *dn, const char *oid_buf, size_t oid_len) {
    while (dn != NULL) {
        if (dn->oid.len == oid_len && memcmp(dn->oid.p, oid_buf, oid_len) == 0)
            return &dn->val;
        dn = dn->next;
    }
    return NULL;
}

static int CmdHF14ADesLeaf(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes leaf",
                  "Read and verify a LEAF Verified credential on a MIFARE DUOX card.\n"
                  "Selects the LEAF Verified Open Application, reads the X.509 certificate\n"
                  "from file 0x02, verifies it was signed by the LEAF Root CA, performs ISO\n"
                  "Internal Authenticate, and verifies the card signature with the public key\n"
                  "embedded in the certificate.",
                  "hf mfdes leaf                              -> verify with default AID D61CF5\n"
                  "hf mfdes leaf -v                           -> verbose output\n"
                  "hf mfdes leaf --aid D61CF5                 -> override AID\n"
                  "hf mfdes leaf -d 00112233445566778899AABBCCDDEEFF -> explicit 16-byte challenge\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",      "Show APDU requests and responses"),            // 1
        arg_lit0("v",  "verbose",   "Verbose output"),                              // 2
        arg_str0("d",  "challenge", "<hex>", "Challenge / RndA (16 bytes, random if omitted)"), // 3
        arg_str0(NULL, "aid",       "<hex>", "Application ID (3 bytes, default D61CF5)"),       // 4
        arg_int0("n",  "keynum",    "<dec>", "Key number (P2, default 0)"),                     // 5
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    uint8_t challenge[DUOX_INTAUTH_CHALLENGE_LEN] = {0};
    int challenge_len = 0;
    CLIGetHexWithReturn(ctx, 3, challenge, &challenge_len);
    bool challenge_provided = (challenge_len > 0);
    if (challenge_provided && challenge_len != DUOX_INTAUTH_CHALLENGE_LEN) {
        PrintAndLogEx(ERR, "Challenge must be exactly 16 bytes, got %d", challenge_len);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t aid_bytes[3] = {0xD6, 0x1C, 0xF5}; // little-endian default D61CF5
    int aid_len = 0;
    CLIGetHexWithReturn(ctx, 4, aid_bytes, &aid_len);
    if (aid_len > 0 && aid_len != 3) {
        PrintAndLogEx(ERR, "AID must be exactly 3 bytes, got %d", aid_len);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int keynum = arg_get_int_def(ctx, 5, 0);
    if (keynum < 0 || keynum > 255) {
        PrintAndLogEx(ERR, "Key number must be 0..255");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    if (!challenge_provided) {
        int res = duox_gen_random(challenge, sizeof(challenge), "hf_mfdes_leaf");
        if (res != PM3_SUCCESS) return res;
    }

    // aid_bytes default {0xD6,0x1C,0xF5} = wire bytes for AID "D61CF5".
    // DesfireSelectAIDHex expects LE uint32: byte[2]<<16 | byte[1]<<8 | byte[0].
    uint32_t aid = (aid_bytes[2] << 16) | (aid_bytes[1] << 8) | aid_bytes[0];

    PrintAndLogEx(INFO, "--- " _CYAN_("LEAF Verified Credential Check"));
    PrintAndLogEx(INFO, "AID.......... " _YELLOW_("%02X%02X%02X"), aid_bytes[0], aid_bytes[1], aid_bytes[2]);
    PrintAndLogEx(INFO, "Challenge.... " _YELLOW_("%s"), sprint_hex_inrow(challenge, sizeof(challenge)));

    // Step 1: Anticollision + select application
    DesfireContext_t dctx = {0};
    dctx.commMode = DCMPlain;
    dctx.cmdSet = DCCNativeISO;

    int res = DesfireAnticollision(false);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Anticollision " _RED_("failed"));
        DropField();
        return res;
    }

    res = DesfireSelectAIDHex(&dctx, aid, false, 0);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Select application %06X " _RED_("failed"), aid);
        DropField();
        return res;
    }
    if (verbose)
        PrintAndLogEx(SUCCESS, "Application selected " _GREEN_("ok"));

    // Step 2: Read X.509 certificate from file 0x02 (length=0 reads to EOF)
    uint8_t cert_buf[LEAF_VERIFIED_MAX_CERT_LEN] = {0};
    size_t cert_len = 0;
    res = DesfireReadFile(&dctx, LEAF_VERIFIED_CERT_FILE, 0, 0, cert_buf, &cert_len);
    if (res != PM3_SUCCESS || cert_len == 0) {
        PrintAndLogEx(ERR, "Read certificate file 0x%02X " _RED_("failed") " (%d)", LEAF_VERIFIED_CERT_FILE, res);
        DropField();
        return PM3_ESOFT;
    }
    PrintAndLogEx(SUCCESS, "Certificate read " _GREEN_("ok") " (%zu bytes)", cert_len);
    if (verbose)
        print_hex_break(cert_buf, cert_len, 32);

    // Step 3: Parse certificate
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    int xres = mbedtls_x509_crt_parse_der(&cert, cert_buf, cert_len);
    if (xres != 0) {
        PrintAndLogEx(ERR, "X.509 parse " _RED_("failed") " (-0x%04x)", -xres);
        mbedtls_x509_crt_free(&cert);
        DropField();
        return PM3_ESOFT;
    }

    // Print certificate details
    PrintAndLogEx(INFO, "--- " _CYAN_("Certificate"));

    char dnbuf[256] = {0};
    mbedtls_x509_dn_gets(dnbuf, sizeof(dnbuf), &cert.subject);
    PrintAndLogEx(INFO, "Subject...... " _YELLOW_("%s"), dnbuf);
    mbedtls_x509_dn_gets(dnbuf, sizeof(dnbuf), &cert.issuer);
    PrintAndLogEx(INFO, "Issuer....... " _YELLOW_("%s"), dnbuf);

    const mbedtls_x509_buf *open_id = leaf_dn_find_oid(&cert.subject,
                                      MBEDTLS_OID_AT_SERIAL_NUMBER,
                                      MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_SERIAL_NUMBER));
    if (open_id != NULL && open_id->len > 0) {
        char idbuf[128] = {0};
        size_t cp = (open_id->len < sizeof(idbuf) - 1) ? open_id->len : sizeof(idbuf) - 1;
        memcpy(idbuf, open_id->p, cp);
        PrintAndLogEx(INFO, "Open ID...... " _YELLOW_("%s"), idbuf);
    }

    PrintAndLogEx(INFO, "Valid from... " _YELLOW_("%04d-%02d-%02d %02d:%02d:%02d"),
                  cert.valid_from.year, cert.valid_from.mon, cert.valid_from.day,
                  cert.valid_from.hour, cert.valid_from.min, cert.valid_from.sec);
    PrintAndLogEx(INFO, "Valid to..... " _YELLOW_("%04d-%02d-%02d %02d:%02d:%02d"),
                  cert.valid_to.year, cert.valid_to.mon, cert.valid_to.day,
                  cert.valid_to.hour, cert.valid_to.min, cert.valid_to.sec);

    if (cert.serial.len > 0)
        PrintAndLogEx(INFO, "Serial....... " _YELLOW_("%s"), sprint_hex_inrow(cert.serial.p, cert.serial.len));

    uint8_t fp[32] = {0};
    if (mbedtls_sha256_ret(cert_buf, cert_len, fp, 0) == 0)
        PrintAndLogEx(INFO, "SHA-256...... " _YELLOW_("%s"), sprint_hex_inrow(fp, sizeof(fp)));

    // Step 4: Verify certificate signature against LEAF Root CA public key.
    // The certificate uses ECDSA-SHA256 over secp256r1; ecdsa_signature_verify
    // accepts the DER-encoded signature stored in cert.sig.
    PrintAndLogEx(INFO, "--- " _CYAN_("Root CA Verification"));
    bool root_ok = false;
    int rres = ecdsa_signature_verify(
                   MBEDTLS_ECP_DP_SECP256R1,
                   (uint8_t *)kLeafRootP256PubKey,
                   cert.tbs.p,
                   (int)cert.tbs.len,
                   cert.sig.p,
                   cert.sig.len,
                   true);
    if (rres == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Root signature " _GREEN_("verified") " (LEAF Root CA P-256)");
        root_ok = true;
    } else {
        PrintAndLogEx(ERR, "Root signature " _RED_("verification failed") " (%d)", rres);
    }

    // Extract card public key (P-256, uncompressed)
    uint8_t card_pubkey[65] = {0};
    int kres = ecdsa_public_key_from_pk(&cert.pk, MBEDTLS_ECP_DP_SECP256R1, card_pubkey, sizeof(card_pubkey));
    mbedtls_x509_crt_free(&cert);
    if (kres != 0) {
        PrintAndLogEx(ERR, "Failed to extract card public key (-0x%04x)", -kres);
        DropField();
        return PM3_ESOFT;
    }
    if (verbose)
        PrintAndLogEx(INFO, "Card pubkey.. %s", sprint_hex_inrow(card_pubkey, sizeof(card_pubkey)));

    // Step 5: ISO Internal Authenticate
    PrintAndLogEx(INFO, "--- " _CYAN_("ISO Internal Authenticate"));
    uint8_t card_random[DUOX_INTAUTH_CHALLENGE_LEN] = {0};
    uint8_t signature_rs[DUOX_INTAUTH_SIG_LEN] = {0};
    res = duox_intauth_exchange(APDULogging, verbose, (uint8_t)keynum, challenge, card_random, signature_rs);
    if (res != PM3_SUCCESS)
        return res;

    // Step 6: Verify card signature with extracted public key.
    PrintAndLogEx(INFO, "--- " _CYAN_("Signature Verification"));
    bool card_ok = false;
    int sig_res = duox_intauth_verify_sig(verbose, card_pubkey, challenge, card_random, signature_rs);
    if (sig_res == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Card signature " _GREEN_("verified"));
        card_ok = true;
    } else {
        PrintAndLogEx(ERR, "Card signature " _RED_("verification failed"));
    }

    PrintAndLogEx(NORMAL, "");
    if (root_ok && card_ok) {
        PrintAndLogEx(SUCCESS, "LEAF Verified credential " _GREEN_("AUTHENTIC"));
    } else {
        PrintAndLogEx(ERR, "LEAF Verified credential " _RED_("FAILED") " (root=%s, card=%s)",
                      root_ok ? "ok" : "fail", card_ok ? "ok" : "fail");
    }

    return (root_ok && card_ok) ? PM3_SUCCESS : PM3_ESOFT;
}

static int CmdHF14ADesTest(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes test",
                  "Regression crypto tests",
                  "hf mfdes test");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    DesfireTest(true);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",             CmdHelp,                     AlwaysAvailable, "This help"},
    {"list",             CmdHF14ADesList,             AlwaysAvailable, "List DESFire (ISO 14443A) history"},
    {"-----------",      CmdHelp,                     IfPm3Iso14443a,  "---------------------- " _CYAN_("General") " ----------------------"},
    {"auth",             CmdHF14ADesAuth,             IfPm3Iso14443a,  "MIFARE DesFire Authentication"},
    {"chk",              CmdHF14aDesChk,              IfPm3Iso14443a,  "Check keys"},
    {"default",          CmdHF14ADesDefault,          IfPm3Iso14443a,  "Set defaults for all the commands"},
    {"detect",           CmdHF14aDesDetect,           IfPm3Iso14443a,  "Detect key type and tries to find one from the list"},
    {"formatpicc",       CmdHF14ADesFormatPICC,       IfPm3Iso14443a,  "Format PICC"},
    {"freemem",          CmdHF14ADesGetFreeMem,       IfPm3Iso14443a,  "Get free memory size"},
    {"getuid",           CmdHF14ADesGetUID,           IfPm3Iso14443a,  "Get uid from card"},
    {"pc",               CmdHF14ADesPC,               IfPm3Iso14443a,  "Run proximity check"},
    {"info",             CmdHF14ADesInfo,             IfPm3Iso14443a,  "Tag information"},
    {"mad",              CmdHF14aDesMAD,              IfPm3Iso14443a,  "Prints MAD records / files from the card"},
    {"setconfig",        CmdHF14ADesSetConfiguration, IfPm3Iso14443a,  "Set card configuration"},
    {"-----------",      CmdHelp,                     IfPm3Iso14443a,  "-------------------- " _CYAN_("Applications") " -------------------"},
    {"lsapp",            CmdHF14ADesLsApp,            IfPm3Iso14443a,  "Show all applications with files list"},
    {"getaids",          CmdHF14ADesGetAIDs,          IfPm3Iso14443a,  "Get Application IDs list"},
    {"getappnames",      CmdHF14ADesGetAppNames,      IfPm3Iso14443a,  "Get Applications list"},
    {"bruteaid",         CmdHF14ADesBruteApps,        IfPm3Iso14443a,  "Recover AIDs by bruteforce"},
    {"brutedamslot",     CmdHF14ADesBruteDAMSlots,    IfPm3Iso14443a,  "Recover DAM slots to delegated AIDs by bruteforce"},
    {"createapp",        CmdHF14ADesCreateApp,        IfPm3Iso14443a,  "Create Application"},
    {"createdelegateapp", CmdHF14ADesCreateDelegateApp, IfPm3Iso14443a, "Create Delegated Application"},
    {"getdelegateappinfo", CmdHF14ADesGetDelegateAppInfo, IfPm3Iso14443a,  "Get Delegated Application info by DAM slot"},
    {"deleteapp",        CmdHF14ADesDeleteApp,        IfPm3Iso14443a,  "Delete Application"},
    {"selectapp",        CmdHF14ADesSelectApp,        IfPm3Iso14443a,  "Select Application ID"},
    {"selectisofid",     CmdHF14ADesSelectISOFID,     IfPm3Iso14443a,  "Select file by ISO ID"},
    {"-----------",      CmdHelp,                     IfPm3Iso14443a,  "------------------------ " _CYAN_("Keys") " -----------------------"},
    {"changekey",        CmdHF14ADesChangeKey,        IfPm3Iso14443a,  "Change Key"},
    {"chkeysettings",    CmdHF14ADesChKeySettings,    IfPm3Iso14443a,  "Change Key Settings"},
    {"getkeysettings",   CmdHF14ADesGetKeySettings,   IfPm3Iso14443a,  "Get Key Settings"},
    {"getkeyversions",   CmdHF14ADesGetKeyVersions,   IfPm3Iso14443a,  "Get Key Versions"},
    {"-----------",      CmdHelp,                     IfPm3Iso14443a,  "----------------------- " _CYAN_("Files") " -----------------------"},
    {"bruteisofid",      CmdHF14ADesBruteISOFIDs,     IfPm3Iso14443a,  "Recover file ISO IDs by bruteforce"},
    {"getfileids",       CmdHF14ADesGetFileIDs,       IfPm3Iso14443a,  "Get File IDs list"},
    {"getfileisoids",    CmdHF14ADesGetFileISOIDs,    IfPm3Iso14443a,  "Get File ISO IDs list"},
    {"lsfiles",          CmdHF14ADesLsFiles,          IfPm3Iso14443a,  "Show all files list"},
    {"dump",             CmdHF14ADesDump,             IfPm3Iso14443a,  "Dump all files"},
    {"createfile",       CmdHF14ADesCreateFile,       IfPm3Iso14443a,  "Create Standard/Backup File"},
    {"createvaluefile",  CmdHF14ADesCreateValueFile,  IfPm3Iso14443a,  "Create Value File"},
    {"createrecordfile", CmdHF14ADesCreateRecordFile, IfPm3Iso14443a,  "Create Linear/Cyclic Record File"},
    {"createmacfile",    CmdHF14ADesCreateTrMACFile,  IfPm3Iso14443a,  "Create Transaction MAC File"},
    {"deletefile",       CmdHF14ADesDeleteFile,       IfPm3Iso14443a,  "Delete File"},
    {"getfilesettings",  CmdHF14ADesGetFileSettings,  IfPm3Iso14443a,  "Get file settings"},
    {"chfilesettings",   CmdHF14ADesChFileSettings,   IfPm3Iso14443a,  "Change file settings"},
    {"read",             CmdHF14ADesReadData,         IfPm3Iso14443a,  "Read data from standard/backup/record/value/mac file"},
    {"write",            CmdHF14ADesWriteData,        IfPm3Iso14443a,  "Write data to standard/backup/record/value file"},
    {"value",            CmdHF14ADesValueOperations,  IfPm3Iso14443a,  "Operations with value file (get/credit/limited credit/debit/clear)"},
    {"clearrecfile",     CmdHF14ADesClearRecordFile,  IfPm3Iso14443a,  "Clear record File"},
    {"-----------",      CmdHelp,                     IfPm3Iso14443a,  "----------------------- " _CYAN_("DUOX") " ------------------------"},
    {"intauth",          CmdHF14ADesIntAuth,          IfPm3Iso14443a,  "ISO Internal Authenticate (ECDSA challenge-response)"},
    {"vdesign",          CmdHF14ADesVdeSign,          IfPm3Iso14443a,  "VDE ECDSASign (EV charging signature over 32-byte challenge)"},
    {"leaf",             CmdHF14ADesLeaf,             IfPm3Iso14443a,  "LEAF Verified credential read + cert + auth check"},
    {"-----------",      CmdHelp,                     IfPm3Iso14443a,  "----------------------- " _CYAN_("System") " -----------------------"},
    {"test",             CmdHF14ADesTest,             AlwaysAvailable, "Regression crypto tests"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFMFDes(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
