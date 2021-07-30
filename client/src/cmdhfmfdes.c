//-----------------------------------------------------------------------------
// Copyright (C) 2014 Iceman
// Copyright (C) 2021 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency MIFARE Desfire commands
//-----------------------------------------------------------------------------
// Code heavily modified by B.Kerler :)

#include "cmdhfmfdes.h"

#include <stdio.h>
#include <string.h>

#include "commonutil.h"  // ARRAYLEN
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "cmdhf14a.h"
#include "aes.h"
#include "crypto/libpcrypto.h"
#include "protocols.h"
#include "cmdtrace.h"
#include "cliparser.h"
#include "iso7816/apduinfo.h"   // APDU manipulation / errorcodes
#include "iso7816/iso7816core.h"    // APDU logging
#include "util_posix.h"     // msleep
#include "mifare/desfire_crypto.h"
#include "mifare/desfirecore.h"
#include "mifare/desfiretest.h"
#include "mifare/desfiresecurechan.h"
#include "mifare/mifaredefault.h"  // default keys
#include "crapto1/crapto1.h"
#include "fileutils.h"
#include "nfc/ndef.h"           // NDEF
#include "mifare/mad.h"
#include "generator.h"
#include "aiddesfire.h"
#include "util.h"

#define MAX_KEY_LEN        24
#define MAX_KEYS_LIST_LEN  1024

#define status(x) ( ((uint16_t)(0x91<<8)) + (uint16_t)x )

#ifndef DropFieldDesfire
#define DropFieldDesfire() { \
        clearCommandBuffer(); \
        SendCommandNG(CMD_HF_DROPFIELD, NULL, 0); \
        tag->rf_field_on = false; \
        PrintAndLogEx(DEBUG, "field dropped"); \
    }
#endif

struct desfire_key default_key = {0};

uint8_t desdefaultkeys[3][8] = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, //Official
    {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47},
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
};

uint8_t aesdefaultkeys[5][16] = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, //Official, TRF7970A
    {0x79, 0x70, 0x25, 0x53, 0x79, 0x70, 0x25, 0x53, 0x79, 0x70, 0x25, 0x53, 0x79, 0x70, 0x25, 0x53}, // TRF7970A
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, // TRF7970A
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
    {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f}
};

uint8_t k3kdefaultkeys[1][24] = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

struct desfire_tag mf_state = {.session_key = NULL, .authentication_scheme = AS_LEGACY, .authenticated_key_no = NOT_YET_AUTHENTICATED, .crypto_buffer = NULL, .crypto_buffer_size = 0, .selected_application = 0};
static desfiretag_t tag = &mf_state;

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

static mfdes_authinput_t currentauth[0xF] = {{.keyno = -1}, {.keyno = -1}, {.keyno = -1}, {.keyno = -1}, {.keyno = -1}, {.keyno = -1}, {.keyno = -1}, {.keyno = -1}, {.keyno = -1}, {.keyno = -1}, {.keyno = -1}, {.keyno = -1}, {.keyno = -1}, {.keyno = -1}, {.keyno = -1}};

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

typedef struct mfdes_info_res {
    uint8_t isOK;
    uint8_t uid[7];
    uint8_t uidlen;
    uint8_t versionHW[7];
    uint8_t versionSW[7];
    uint8_t details[14];
} PACKED mfdes_info_res_t;

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

// NXP Appnote AN10787 - Application Directory (MAD)
typedef enum {
    CL_ADMIN = 0,
    CL_MISC1,
    CL_MISC2,
    CL_MISC3,
    CL_MISC4,
    CL_MISC5,
    CL_MISC6,
    CL_MISC7,
    CL_AIRLINES = 8,
    CL_FERRY,
    CL_RAIL,
    CL_MISC,
    CL_TRANSPORT,
    CL_SECURITY = 0x14,
    CL_CITYTRAFFIC = 0x18,
    CL_CZECH_RAIL,
    CL_BUS,
    CL_MMT,
    CL_TAXI = 0x28,
    CL_TOLL = 0x30,
    CL_GENERIC_TRANS,
    CL_COMPANY_SERVICES = 0x38,
    CL_CITYCARD = 0x40,
    CL_ACCESS_CONTROL_1 = 0x47,
    CL_ACCESS_CONTROL_2,
    CL_VIGIK = 0x49,
    CL_NED_DEFENCE = 0x4A,
    CL_BOSCH_TELECOM = 0x4B,
    CL_EU = 0x4C,
    CL_SKI_TICKET = 0x50,
    CL_SOAA = 0x55,
    CL_ACCESS2 = 0x56,
    CL_FOOD = 0x60,
    CL_NONFOOD = 0x68,
    CL_HOTEL = 0x70,
    CL_LOYALTY = 0x71,
    CL_AIRPORT = 0x75,
    CL_CAR_RENTAL = 0x78,
    CL_NED_GOV = 0x79,
    CL_ADMIN2 = 0x80,
    CL_PURSE = 0x88,
    CL_TV = 0x90,
    CL_CRUISESHIP = 0x91,
    CL_IOPTA = 0x95,
    CL_METERING = 0x97,
    CL_TELEPHONE = 0x98,
    CL_HEALTH = 0xA0,
    CL_WAREHOUSE = 0xA8,
    CL_BANKING = 0xB8,
    CL_ENTERTAIN = 0xC0,
    CL_PARKING = 0xC8,
    CL_FLEET = 0xC9,
    CL_FUEL = 0xD0,
    CL_INFO = 0xD8,
    CL_PRESS = 0xE0,
    CL_NFC = 0xE1,
    CL_COMPUTER = 0xE8,
    CL_MAIL = 0xF0,
    CL_AMISC = 0xF8,
    CL_AMISC1 = 0xF9,
    CL_AMISC2 = 0xFA,
    CL_AMISC3 = 0xFB,
    CL_AMISC4 = 0xFC,
    CL_AMISC5 = 0xFD,
    CL_AMISC6 = 0xFE,
    CL_AMISC7 = 0xFF,
} aidcluster_h;

static const char *cluster_to_text(uint8_t cluster) {
    switch (cluster) {
        case CL_ADMIN:
            return "card administration";
        case CL_MISC1:
        case CL_MISC2:
        case CL_MISC3:
        case CL_MISC4:
        case CL_MISC5:
        case CL_MISC6:
        case CL_MISC7:
            return "miscellaneous applications";
        case CL_AIRLINES:
            return "airlines";
        case CL_FERRY:
            return "ferry traffic";
        case CL_RAIL:
            return "railway services";
        case CL_MISC:
            return "miscellaneous applications";
        case CL_TRANSPORT:
            return "transport";
        case CL_SECURITY:
            return "security solutions";
        case CL_CITYTRAFFIC:
            return "city traffic";
        case CL_CZECH_RAIL:
            return "Czech Railways";
        case CL_BUS:
            return "bus services";
        case CL_MMT:
            return "multi modal transit";
        case CL_TAXI:
            return "taxi";
        case CL_TOLL:
            return "road toll";
        case CL_GENERIC_TRANS:
            return "generic transport";
        case CL_COMPANY_SERVICES:
            return "company services";
        case CL_CITYCARD:
            return "city card services";
        case CL_ACCESS_CONTROL_1:
        case CL_ACCESS_CONTROL_2:
            return "access control & security";
        case CL_VIGIK:
            return "VIGIK";
        case CL_NED_DEFENCE:
            return "Ministry of Defence, Netherlands";
        case CL_BOSCH_TELECOM:
            return "Bosch Telecom, Germany";
        case CL_EU:
            return "European Union Institutions";
        case CL_SKI_TICKET:
            return "ski ticketing";
        case CL_SOAA:
            return "SOAA standard for offline access standard";
        case CL_ACCESS2:
            return "access control & security";
        case CL_FOOD:
            return "food";
        case CL_NONFOOD:
            return "non-food trade";
        case CL_HOTEL:
            return "hotel";
        case CL_LOYALTY:
            return "loyalty";
        case CL_AIRPORT:
            return "airport services";
        case CL_CAR_RENTAL:
            return "car rental";
        case CL_NED_GOV:
            return "Dutch government";
        case CL_ADMIN2:
            return "administration services";
        case CL_PURSE:
            return "electronic purse";
        case CL_TV:
            return "television";
        case CL_CRUISESHIP:
            return "cruise ship";
        case CL_IOPTA:
            return "IOPTA";
        case CL_METERING:
            return "metering";
        case CL_TELEPHONE:
            return "telephone";
        case CL_HEALTH:
            return "health services";
        case CL_WAREHOUSE:
            return "warehouse";
        case CL_BANKING:
            return "banking";
        case CL_ENTERTAIN:
            return "entertainment & sports";
        case CL_PARKING:
            return "car parking";
        case CL_FLEET:
            return "fleet management";
        case CL_FUEL:
            return "fuel, gasoline";
        case CL_INFO:
            return "info services";
        case CL_PRESS:
            return "press";
        case CL_NFC:
            return "NFC Forum";
        case CL_COMPUTER:
            return "computer";
        case CL_MAIL:
            return "mail";
        case CL_AMISC:
        case CL_AMISC1:
        case CL_AMISC2:
        case CL_AMISC3:
        case CL_AMISC4:
        case CL_AMISC5:
        case CL_AMISC6:
        case CL_AMISC7:
            return "miscellaneous applications";
        default:
            break;
    }
    return "reserved";
}

typedef enum {
    DESFIRE_UNKNOWN = 0,
    DESFIRE_MF3ICD40,
    DESFIRE_EV1,
    DESFIRE_EV2,
    DESFIRE_EV3,
    DESFIRE_LIGHT,
    PLUS_EV1,
    NTAG413DNA,
} nxp_cardtype_t;

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

static int CmdHelp(const char *Cmd);

/*
  The 7 MSBits (= n) code the storage size itself based on 2^n,
  the LSBit is set to '0' if the size is exactly 2^n
    and set to '1' if the storage size is between 2^n and 2^(n+1).
    For this version of DESFire the 7 MSBits are set to 0x0C (2^12 = 4096) and the LSBit is '0'.
*/
static char *getCardSizeStr(uint8_t fsize) {

    static char buf[40] = {0x00};
    char *retStr = buf;

    uint16_t usize = 1 << (((uint16_t)fsize >> 1) + 1);
    uint16_t lsize = 1 << ((uint16_t)fsize >> 1);

    // is  LSB set?
    if (fsize & 1)
        snprintf(retStr, sizeof(buf), "0x%02X ( " _GREEN_("%d - %d bytes") " )", fsize, usize, lsize);
    else
        snprintf(retStr, sizeof(buf), "0x%02X ( " _GREEN_("%d bytes") " )", fsize, lsize);
    return buf;
}

static char *getProtocolStr(uint8_t id, bool hw) {

    static char buf[50] = {0x00};
    char *retStr = buf;

    if (id == 0x04) {
        snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("ISO 14443-3 MIFARE, 14443-4") " )", id);
    } else if (id == 0x05) {
        if (hw)
            snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("ISO 14443-2, 14443-3") " )", id);
        else
            snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("ISO 14443-3, 14443-4") " )", id);
    } else {
        snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("Unknown") " )", id);
    }
    return buf;
}

static char *getVersionStr(uint8_t major, uint8_t minor) {

    static char buf[40] = {0x00};
    char *retStr = buf;

    if (major == 0x00)
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire MF3ICD40") " )", major, minor);
    else if (major == 0x01 && minor == 0x00)
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire EV1") " )", major, minor);
    else if (major == 0x12 && minor == 0x00)
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire EV2") " )", major, minor);
    else if (major == 0x42 && minor == 0x00)
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire EV2") " )", major, minor);
    else if (major == 0x33 && minor == 0x00)
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire EV3") " )", major, minor);
    else if (major == 0x30 && minor == 0x00)
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire Light") " )", major, minor);
    else if (major == 0x10 && minor == 0x00)
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("NTAG413DNA") " )", major, minor);
    else
        snprintf(retStr, sizeof(buf), "%x.%x ( " _YELLOW_("Unknown") " )", major, minor);
    return buf;

//04 01 01 01 00 1A 05
}

static int DESFIRESendApdu(bool activate_field, bool leavefield_on, sAPDU apdu, uint8_t *result, uint32_t max_result_len, uint32_t *result_len, uint16_t *sw) {

    *result_len = 0;
    if (sw) *sw = 0;

    uint16_t isw = 0;
    int res = 0;

    if (activate_field) {
        DropFieldDesfire();
        msleep(50);
    }

    // select?
    uint8_t data[APDU_RES_LEN] = {0};

    // COMPUTE APDU
    int datalen = 0;
    //if (APDUEncodeS(&apdu, false, IncludeLe ? 0x100 : 0x00, data, &datalen)) {
    if (APDUEncodeS(&apdu, false, 0x100, data, &datalen)) {
        PrintAndLogEx(ERR, "APDU encoding error.");
        return PM3_EAPDU_ENCODEFAIL;
    }

    if (GetAPDULogging() || (g_debugMode > 1))
        PrintAndLogEx(SUCCESS, ">>>> %s", sprint_hex(data, datalen));

    res = ExchangeAPDU14a(data, datalen, activate_field, leavefield_on, result, max_result_len, (int *)result_len);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (activate_field) {
        PrintAndLogEx(DEBUG, "field up");
        tag->rf_field_on = true;
    }

    if (GetAPDULogging() || (g_debugMode > 1))
        PrintAndLogEx(SUCCESS, "<<<< %s", sprint_hex(result, *result_len));

    if (*result_len < 2) {
        return PM3_SUCCESS;
    }

    *result_len -= 2;
    isw = (result[*result_len] << 8) + result[*result_len + 1];
    if (sw)
        *sw = isw;

    if (isw != 0x9000 && isw != status(MFDES_S_OPERATION_OK) && isw != status(MFDES_S_SIGNATURE) && isw != status(MFDES_S_ADDITIONAL_FRAME) && isw != status(MFDES_S_NO_CHANGES)) {
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

static int send_desfire_cmd(sAPDU *apdu, bool select, uint8_t *dest, uint32_t *recv_len, uint16_t *sw, uint32_t splitbysize, bool readalldata) {
    if (apdu == NULL) {
        PrintAndLogEx(DEBUG, "APDU=NULL");
        return PM3_EINVARG;
    }
    if (sw == NULL) {
        PrintAndLogEx(DEBUG, "SW=NULL");
        return PM3_EINVARG;
    }
    if (recv_len == NULL) {
        PrintAndLogEx(DEBUG, "RECV_LEN=NULL");
        return PM3_EINVARG;
    }

    *sw = 0;
    uint8_t data[255 * 5]  = {0x00};
    uint32_t resplen = 0;
    uint32_t pos = 0;
    uint32_t i = 1;
    int res = DESFIRESendApdu(select, true, *apdu, data, sizeof(data), &resplen, sw);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "%s", DesfireGetErrorString(res, sw));
        DropFieldDesfire();
        return res;
    }
    if (dest != NULL) {
        memcpy(dest, data, resplen);
    }

    pos += resplen;
    if (!readalldata) {
        if (*sw == status(MFDES_ADDITIONAL_FRAME)) {
            *recv_len = pos;
            return PM3_SUCCESS;
        }
        return res;
    }

    while (*sw == status(MFDES_ADDITIONAL_FRAME)) {
        apdu->INS = MFDES_ADDITIONAL_FRAME; //0xAF
        apdu->Lc = 0;
        apdu->P1 = 0;
        apdu->P2 = 0;

        res = DESFIRESendApdu(false, true, *apdu, data, sizeof(data), &resplen, sw);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(DEBUG, "%s", DesfireGetErrorString(res, sw));
            DropFieldDesfire();
            return res;
        }

        if (dest != NULL) {
            if (splitbysize) {
                memcpy(&dest[i * splitbysize], data, resplen);
                i += 1;
            } else {
                memcpy(&dest[pos], data, resplen);
            }
        }
        pos += resplen;

        if (*sw != status(MFDES_ADDITIONAL_FRAME)) break;
    }

    *recv_len = (splitbysize) ? i : pos;
    return PM3_SUCCESS;
}

static nxp_cardtype_t getCardType(uint8_t major, uint8_t minor) {

    if (major == 0x00)
        return DESFIRE_MF3ICD40;
    if (major == 0x01 && minor == 0x00)
        return DESFIRE_EV1;
    if (major == 0x12 && minor == 0x00)
        return DESFIRE_EV2;
    if (major == 0x33 && minor == 0x00)
        return DESFIRE_EV3;
    if (major == 0x30 && minor == 0x00)
        return DESFIRE_LIGHT;
    if (major == 0x11 &&  minor == 0x00)
        return PLUS_EV1;
    if (major == 0x10 && minor == 0x00)
        return NTAG413DNA;
    return DESFIRE_UNKNOWN;
}

static int mfdes_get_info(mfdes_info_res_t *info) {
    SendCommandNG(CMD_HF_DESFIRE_INFO, NULL, 0);
    PacketResponseNG resp;

    if (WaitForResponseTimeout(CMD_HF_DESFIRE_INFO, &resp, 1500) == false) {
        PrintAndLogEx(WARNING, "Command execute timeout");
        DropFieldDesfire();
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

static int handler_desfire_auth(mfdes_authinput_t *payload, mfdes_auth_res_t *rpayload) {
    // 3 different way to authenticate   AUTH (CRC16) , AUTH_ISO (CRC32) , AUTH_AES (CRC32)
    // 4 different crypto arg1   DES, 3DES, 3K3DES, AES
    // 3 different communication modes,  PLAIN,MAC,CRYPTO
    tag->authenticated_key_no = NOT_YET_AUTHENTICATED;
    tag->session_key = NULL;

    mbedtls_aes_context ctx;

    uint8_t keybytes[24];
    // Crypt constants
    uint8_t IV[16] = {0x00};
    uint8_t RndA[16] = {0x00};
    uint8_t RndB[16] = {0x00};
    uint8_t encRndB[16] = {0x00};
    uint8_t rotRndB[16] = {0x00}; //RndB'
    uint8_t both[32 + 1] = {0x00}; // ek/dk_keyNo(RndA+RndB')

    // Generate Random Value
    uint32_t ng = msclock();
    uint32_t value = prng_successor(ng, 32);
    num_to_bytes(value, 4, &RndA[0]);
    value = prng_successor(ng, 32);
    num_to_bytes(value, 4, &RndA[4]);
    value = prng_successor(ng, 32);
    num_to_bytes(value, 4, &RndA[8]);
    value = prng_successor(ng, 32);
    num_to_bytes(value, 4, &RndA[12]);

    // Part 1
    memcpy(keybytes, payload->key, payload->keylen);

    struct desfire_key dkey = {0};
    desfirekey_t key = &dkey;

    if (payload->algo == MFDES_ALGO_AES) {
        mbedtls_aes_init(&ctx);
        Desfire_aes_key_new(keybytes, key);
    } else if (payload->algo == MFDES_ALGO_3DES) {
        Desfire_3des_key_new_with_version(keybytes, key);
    } else if (payload->algo == MFDES_ALGO_DES) {
        Desfire_des_key_new(keybytes, key);
    } else if (payload->algo == MFDES_ALGO_3K3DES) {
        Desfire_3k3des_key_new_with_version(keybytes, key);
    }

    if (payload->kdfAlgo == MFDES_KDF_ALGO_AN10922) {
        mifare_kdf_an10922(key, payload->kdfInput, payload->kdfInputLen);
        PrintAndLogEx(DEBUG, " Derrived key: " _GREEN_("%s"), sprint_hex(key->data, key_block_size(key)));
    } else if (payload->kdfAlgo == MFDES_KDF_ALGO_GALLAGHER) {
        // We will overrite any provided KDF input since a gallagher specific KDF was requested.
        payload->kdfInputLen = 11;

        if (mfdes_kdf_input_gallagher(tag->info.uid, tag->info.uidlen, payload->keyno, tag->selected_application, payload->kdfInput, &payload->kdfInputLen) != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Could not generate Gallagher KDF input");
        }

        mifare_kdf_an10922(key, payload->kdfInput, payload->kdfInputLen);
        PrintAndLogEx(DEBUG, "    KDF Input: " _YELLOW_("%s"), sprint_hex(payload->kdfInput, payload->kdfInputLen));
        PrintAndLogEx(DEBUG, " Derrived key: " _GREEN_("%s"), sprint_hex(key->data, key_block_size(key)));

    }

    uint8_t subcommand = MFDES_AUTHENTICATE;
    tag->authentication_scheme = AS_LEGACY;

    if (payload->mode == MFDES_AUTH_AES) {
        subcommand = MFDES_AUTHENTICATE_AES;
        tag->authentication_scheme = AS_NEW;
    } else if (payload->mode == MFDES_AUTH_ISO) {
        subcommand = MFDES_AUTHENTICATE_ISO;
        tag->authentication_scheme = AS_NEW;
    }

    uint32_t recv_len = 0;
    uint16_t sw = 0;
    uint8_t recv_data[256] = {0};

    if (payload->mode != MFDES_AUTH_PICC) {
        // Let's send our auth command
        uint8_t data[] = {payload->keyno};
        sAPDU apdu = {0x90, subcommand, 0x00, 0x00, 0x01, data};
        int res = send_desfire_cmd(&apdu, false, recv_data, &recv_len, &sw, 0, false);
        if (res != PM3_SUCCESS) {
            return 1;
        }
    }
    // else {
    /*
    cmd[0] = AUTHENTICATE;
    cmd[1] = payload->keyno;
    len = DesfireAPDU(cmd, 2, resp);
    */
    //}

    if (!recv_len) {
        return 2;
    }

    if (sw != status(MFDES_ADDITIONAL_FRAME)) {
        return 3;
    }

    uint32_t expectedlen = 8;
    if (payload->algo == MFDES_ALGO_AES || payload->algo == MFDES_ALGO_3K3DES) {
        expectedlen = 16;
    }

    if (recv_len != expectedlen) {
        return 4;
    }
    uint32_t rndlen = recv_len;

    // Part 2
    if (payload->mode != MFDES_AUTH_PICC) {
        memcpy(encRndB, recv_data, rndlen);
    } else {
        memcpy(encRndB, recv_data + 2, rndlen);
    }

    // Part 3
    if (payload->algo == MFDES_ALGO_AES) {
        if (mbedtls_aes_setkey_dec(&ctx, key->data, 128) != 0) {
            return 5;
        }
        mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, rndlen, IV, encRndB, RndB);
    } else if (payload->algo == MFDES_ALGO_DES)
        des_decrypt(RndB, encRndB, key->data);
    else if (payload->algo == MFDES_ALGO_3DES)
        tdes_nxp_receive(encRndB, RndB, rndlen, key->data, IV, 2);
    else if (payload->algo == MFDES_ALGO_3K3DES) {
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
    if (payload->mode == MFDES_AUTH_DES || payload->mode == MFDES_AUTH_PICC) {
        des_decrypt(encRndA, RndA, key->data);
        memcpy(both, encRndA, rndlen);

        for (uint32_t x = 0; x < rndlen; x++) {
            rotRndB[x] = rotRndB[x] ^ encRndA[x];
        }

        des_decrypt(encRndB, rotRndB, key->data);
        memcpy(both + rndlen, encRndB, rndlen);
    } else if (payload->mode == MFDES_AUTH_ISO) {
        if (payload->algo == MFDES_ALGO_3DES) {
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
        } else if (payload->algo == MFDES_ALGO_3K3DES) {
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
    } else if (payload->mode == MFDES_AUTH_AES) {
        uint8_t tmp[32] = {0x00};
        memcpy(tmp, RndA, rndlen);
        memcpy(tmp + rndlen, rotRndB, rndlen);
        if (g_debugMode > 1) {
            PrintAndLogEx(DEBUG, "rotRndB: %s", sprint_hex(rotRndB, rndlen));
            PrintAndLogEx(DEBUG, "Both3k3: %s", sprint_hex(tmp, 32));
        }
        if (payload->algo == MFDES_ALGO_AES) {
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
    if (payload->algo == MFDES_ALGO_AES || payload->algo == MFDES_ALGO_3K3DES) {
        bothlen = 32;
    }
    if (payload->mode != MFDES_AUTH_PICC) {
        sAPDU apdu = {0x90, MFDES_ADDITIONAL_FRAME, 0x00, 0x00, bothlen, both};
        int res = send_desfire_cmd(&apdu, false, recv_data, &recv_len, &sw, 0, false);
        if (res != PM3_SUCCESS) {
            return 7;
        }
    } else {
        /*cmd[0] = ADDITIONAL_FRAME;
        memcpy(cmd + 1, both, 16);
        len = DesfireAPDU(cmd, 1 + 16, resp);

        if (res != PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "Sending auth command %02X " _RED_("failed"),subcommand);
            return PM3_ESOFT;
        }*/
    }

    if (!recv_len) {
        return 8;
    }

    if (payload->mode != MFDES_AUTH_PICC) {
        if (sw != status(MFDES_S_OPERATION_OK)) {
            return 9;
        }
    } else {
        /*if (resp[1] != 0x00) {
            PrintAndLogEx(ERR,"Authentication failed. Card timeout.");
            return PM3_ESOFT;
        }*/
    }

    // Part 4
    // tag->session_key = &default_key;
    struct desfire_key *p = realloc(tag->session_key, sizeof(struct desfire_key));
    if (!p) {
        PrintAndLogEx(FAILED, "Cannot allocate memory for session keys");
        free(tag->session_key);
        return PM3_EMALLOC;
    }
    tag->session_key = p;

    memset(tag->session_key, 0x00, sizeof(struct desfire_key));

    Desfire_session_key_new(RndA, RndB, key, tag->session_key);

    if (payload->mode != MFDES_AUTH_PICC) {
        memcpy(encRndA, recv_data, rndlen);
    } else {
        memcpy(encRndA, recv_data + 2, rndlen);
    }

    if (payload->mode == MFDES_AUTH_DES || payload->mode == MFDES_AUTH_ISO || payload->mode == MFDES_AUTH_PICC) {
        if (payload->algo == MFDES_ALGO_DES)
            des_decrypt(encRndA, encRndA, key->data);
        else if (payload->algo == MFDES_ALGO_3DES)
            tdes_nxp_receive(encRndA, encRndA, rndlen, key->data, IV, 2);
        else if (payload->algo == MFDES_ALGO_3K3DES)
            tdes_nxp_receive(encRndA, encRndA, rndlen, key->data, IV, 3);
    } else if (payload->mode == MFDES_AUTH_AES) {
        if (mbedtls_aes_setkey_dec(&ctx, key->data, 128) != 0) {
            return 10;
        }
        mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, rndlen, IV, encRndA, encRndA);
    }

    rol(RndA, rndlen);
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
    if (payload->algo == MFDES_ALGO_3DES) {
        if (memcmp(key->data, &key->data[8], 8) == 0)
            memcpy(&tag->session_key->data[8], tag->session_key->data, 8);
    }

    rpayload->sessionkeylen = payload->keylen;
    memcpy(rpayload->sessionkey, tag->session_key->data, rpayload->sessionkeylen);
    memset(tag->ivect, 0, MAX_CRYPTO_BLOCK_SIZE);
    tag->authenticated_key_no = payload->keyno;

    if (tag->authentication_scheme == AS_NEW) {
        cmac_generate_subkeys(tag->session_key, MCD_RECEIVE);
    }
    return PM3_SUCCESS;
}

// -- test if card supports 0x0A
static int test_desfire_authenticate(void) {
    uint8_t data[] = {0x00};
    sAPDU apdu = {0x90, MFDES_AUTHENTICATE, 0x00, 0x00, 0x01, data}; // 0x0A, KEY 0
    uint32_t recv_len = 0;
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, true, NULL, &recv_len, &sw, 0, false);
    if (res == PM3_SUCCESS)
        if (sw == status(MFDES_ADDITIONAL_FRAME)) {
            DropFieldDesfire();
            return res;
        }
    return res;
}

// -- test if card supports 0x1A
static int test_desfire_authenticate_iso(void) {
    uint8_t data[] = {0x00};
    sAPDU apdu = {0x90, MFDES_AUTHENTICATE_ISO, 0x00, 0x00, 0x01, data}; // 0x1A, KEY 0
    uint32_t recv_len = 0;
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, true, NULL, &recv_len, &sw, 0, false);
    if (res == PM3_SUCCESS)
        if (sw == status(MFDES_ADDITIONAL_FRAME)) {
            DropFieldDesfire();
            return res;
        }
    return res;
}

// -- test if card supports 0xAA
static int test_desfire_authenticate_aes(void) {
    uint8_t data[] = {0x00};
    sAPDU apdu = {0x90, MFDES_AUTHENTICATE_AES, 0x00, 0x00, 0x01, data}; // 0xAA, KEY 0
    uint32_t recv_len = 0;
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, true, NULL, &recv_len, &sw, 0, false);
    if (res == PM3_SUCCESS)
        if (sw == status(MFDES_ADDITIONAL_FRAME)) {
            DropFieldDesfire();
            return res;
        }
    return res;
}

// --- GET FREE MEM
static int desfire_print_freemem(uint32_t free_mem) {
    PrintAndLogEx(SUCCESS, "   Available free memory on card         : " _GREEN_("%d bytes"), free_mem);
    return PM3_SUCCESS;
}

static int handler_desfire_freemem(uint32_t *free_mem) {
    if (free_mem == NULL) return PM3_EINVARG;

    uint8_t data[] = {0x00};
    sAPDU apdu = {0x90, MFDES_GET_FREE_MEMORY, 0x00, 0x00, 0x00, data}; // 0x6E
    *free_mem = 0;
    uint32_t recv_len = 0;
    uint16_t sw = 0;
    uint8_t fmem[4] = {0};

    size_t plen = apdu.Lc;
    uint8_t *p = mifare_cryto_preprocess_data(tag, (uint8_t *)apdu.data, &plen, 0, MDCM_PLAIN | CMAC_COMMAND);
    apdu.Lc = (uint8_t)plen;
    apdu.data = p;

    int res = send_desfire_cmd(&apdu, true, fmem, &recv_len, &sw, 0, true);

    if (res != PM3_SUCCESS)
        return res;

    size_t dlen = recv_len;
    p = mifare_cryto_postprocess_data(tag, apdu.data, &dlen, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);
    (void)p;
    if (sw != status(MFDES_S_OPERATION_OK))
        return PM3_ESOFT;

    *free_mem = le24toh(fmem);
    return res;
}

/*static int mifare_desfire_change_key(uint8_t key_no, uint8_t *new_key, uint8_t new_algo, uint8_t *old_key, uint8_t old_algo, uint8_t aes_version) {

    if (new_key == NULL || old_key == NULL) {
        return PM3_EINVARG;
    }

    // AID == 000000  6bits LSB needs to be 0
    key_no &= 0x0F;


        Desfire treats Des keys as TDes but with the first half = 2nd half
        As such, we should be able to convert the Des to TDes then run the code as TDes

    if (new_algo == MFDES_ALGO_DES) {
        memcpy(&new_key[8], new_key, 8);
        new_algo = MFDES_ALGO_3DES;
    }

    if (old_algo == MFDES_ALGO_DES) {
        memcpy(&old_key[8], old_key, 8);
        old_algo = MFDES_ALGO_3DES;
    }

    *
     * Because new crypto methods can be setup only at application creation,
     * changing the card master key to one of them require a key_no tweak.
     *
    if (0x000000 == tag->selected_application) {

        // PICC master key, 6bits LSB needs to be 0
        key_no = 0x00;

        // PICC master key, keyalgo specific 2bit MSB
        switch (new_algo) {
            // case MFDES_ALGO_DES: // not needed as we patched des to 3des above. (coverty deadcode)
            case MFDES_ALGO_3DES:
                break;            // 00xx xxx
            case MFDES_ALGO_3K3DES:
                key_no |= 0x40;   // 01xx xxx
                break;
            case MFDES_ALGO_AES:
                key_no |= 0x80;   // 10xx xxx
                break;
        }
    }
    *
    keyno   1b
    key     8b
    cpy     8b
    crc     2b
    padding
    *

    // Variable length ciphered key data 24-42 bytes plus padding..
    uint8_t data[64] = {key_no};
    sAPDU apdu = {0x90, MFDES_CHANGE_KEY, 0x00, 0x00, 0x01, data}; // 0xC4

    size_t cmdcnt = 0;
    uint8_t csPkt[100] = {0x00}; // temp storage for AES/3K3Des packet to calculate checksum  (size ????)

    uint8_t new_key_length = 16;
    switch (new_algo) {
        *
                // We have converted the DES to 3DES above,so this will never hit
                case MFDES_ALGO_DES:
                    memcpy(data + cmdcnt + 1, new_key, new_key_length);
                    memcpy(data + cmdcnt + 1 + new_key_length, new_key, new_key_length);
                    break;
        *
        case MFDES_ALGO_3DES:
        case MFDES_ALGO_AES:
            new_key_length = 16;
            memcpy(data + cmdcnt + 1, new_key, new_key_length);
            break;
        case MFDES_ALGO_3K3DES:
            new_key_length = 24;
            memcpy(data + cmdcnt + 1, new_key, new_key_length);
            break;
    }

    if ((tag->authenticated_key_no & 0x0f) != (key_no & 0x0f)) {
        if (old_key) {
            for (uint32_t n = 0; n < new_key_length; n++) {
                data[cmdcnt + 1 + n] ^= old_key[n];
            }
        }
    }

    cmdcnt += new_key_length;

    if (new_algo == MFDES_ALGO_AES) {
        data[cmdcnt + 1] = aes_version;
        cmdcnt += 1;
    }

    if ((tag->authenticated_key_no & 0x0f) != (key_no & 0x0f)) {
        switch (tag->authentication_scheme) {
            case AS_LEGACY:
                iso14443a_crc_append(data + 1, cmdcnt);
                cmdcnt += 2;

//              iso14443a_crc(new_key, new_key_length, data + cmdcnt);
//              Add offset + 1 for key no. at start
                iso14443a_crc(new_key, new_key_length, data + 1 + cmdcnt);
                cmdcnt += 2;
                break;
            case AS_NEW:
                if (new_algo == MFDES_ALGO_AES) {
                    // AES Checksum must cover : C4<KeyNo>    <PrevKey XOR Newkey>          <NewKeyVer>
                    //                           C4  01   A0B08090E0F0C0D02030001060704050      03
                    // 19 bytes
                    //uint8_t csPkt[30] = {0x00};
                    csPkt[0] = MFDES_CHANGE_KEY;
                    memcpy(&csPkt[1], data, 18);

                    desfire_crc32(csPkt, 19, data + 1 + cmdcnt);
                } else if (new_algo == MFDES_ALGO_3K3DES) {
                    // 3K3Des checksum must cover : C4 <KeyNo> <PrevKey XOR NewKey>
                    csPkt[0] = MFDES_CHANGE_KEY;
                    memcpy(&csPkt[1], data, 25);
                    desfire_crc32(csPkt, 26, data + 1 + cmdcnt);
                } else {
                    desfire_crc32_append(data + 1, cmdcnt);
                }
                cmdcnt += 4;

                desfire_crc32(new_key, new_key_length, data + 1 + cmdcnt);
                cmdcnt += 4;
                break;
        }
    } else {
        switch (tag->authentication_scheme) {
            case AS_LEGACY:
                iso14443a_crc_append(data + 1, cmdcnt);
                cmdcnt += 2;
                break;
            case AS_NEW:
                if (new_algo == MFDES_ALGO_AES) {
                    // AES Checksum must cover : C4<KeyNo>    <Newkey data>                 <NewKeyVer>
                    //                           C4  01   A0B08090E0F0C0D02030001060704050      03
                    csPkt[0] = MFDES_CHANGE_KEY;
                    memcpy(&csPkt[1], data, 18);
                    desfire_crc32(csPkt, 19, data + 1 + cmdcnt);
                } else if (new_algo == MFDES_ALGO_3K3DES) {
                    // 3K3Des checksum must cover : C4 <KeyNo> <Newkey Data>
                    csPkt[0] = MFDES_CHANGE_KEY;
                    memcpy(&csPkt[1], data, 25);
                    desfire_crc32(csPkt, 26, data + 1 + cmdcnt);
                } else {
                    desfire_crc32_append(data + 1, cmdcnt);
                }
                cmdcnt += 4;
                //  desfire_crc32_append(data, cmdcnt);
                //  cmdcnt += 4;
                break;
        }
    }

    uint8_t *p = mifare_cryto_preprocess_data(tag, data + 1, (size_t *)&cmdcnt, 0, MDCM_ENCIPHERED | ENC_COMMAND | NO_CRC);
    apdu.Lc = (uint8_t)cmdcnt + 1;
    // apdu.data = p;
    // the above data pointed to from p did not have the key no. at the start, so copy preprocessed data after the key no.
    memcpy(&data[1], p, cmdcnt);
    apdu.data = data;

    uint32_t recv_len = 0;
    uint16_t sw = 0;

    //  If we call send_desfire with 2nd option (turn field on), it will turn off then on
    //  leading to loosing the authentication on the aid, so lets not turn on here.
    //    int res = send_desfire_cmd(&apdu, true, NULL, &recv_len, &sw, 0, true);
    int res = send_desfire_cmd(&apdu, false, NULL, &recv_len, &sw, 0, true);

    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("can't change key -> %s"), DesfireGetErrorString(res, &sw));
        DropFieldDesfire();
        return res;
    }

    size_t sn = recv_len;


    if ((new_algo == MFDES_ALGO_AES) || (new_algo == MFDES_ALGO_3K3DES)) {
        // AES expects us to Calculate CMAC for status byte : OK 0x00  (0x91 00)
        // As such if we get this far without an error, we should be good
        // Since we are dropping the field, we dont need to maintain the CMAC etc.
        // Setting sn = 1 will allow the post process to just exit (as status only)

        // Simular 3K3Des has some work to validate, but as long as the reply code was 00
        // e.g. 02  fe  ec  77  ca  13  e0  c2  06  [91  00 (OK)]  69  67

        sn = 1;
    }

    p = mifare_cryto_postprocess_data(tag, data, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);

    // Should be finished processing the changekey so lets ensure the field is dropped.
    DropFieldDesfire();

    if (!p) {
        *
            Note in my testing on an EV1, the AES password did change, with the number of returned bytes was 8, expected 9 <status><8 byte cmac>
            As such !p is true and the code reports "Error on changing key"; so comment back to user until its fixed.

            Note: as at 19 May 2021, with the sn = 1 patch above, this should no longer be reachable!
        *
        if (new_algo == MFDES_ALGO_AES) {
            PrintAndLogEx(WARNING, "AES Key may have been changed, please check new password with the auth command.");
        }

        return PM3_ESOFT;
    }

    *
     * If we changed the current authenticated key, we are not authenticated
     * anymore.
     *
    if (key_no == tag->authenticated_key_no) {
        free(tag->session_key);
        tag->session_key = NULL;
    }

    return PM3_SUCCESS;
}*/

// --- GET SIGNATURE
static int desfire_print_signature(uint8_t *uid, uint8_t uidlen, uint8_t *signature, size_t signature_len, nxp_cardtype_t card_type) {
    (void)card_type;

    if (uid == NULL) {
        PrintAndLogEx(DEBUG, "UID=NULL");
        return PM3_EINVARG;
    }
    if (signature == NULL) {
        PrintAndLogEx(DEBUG, "SIGNATURE=NULL");
        return PM3_EINVARG;
    }
    // ref:  MIFARE Desfire Originality Signature Validation
    // See tools/recover_pk.py to recover Pk from UIDs and signatures
#define PUBLIC_DESFIRE_ECDA_KEYLEN 57
    const ecdsa_publickey_t nxp_desfire_public_keys[] = {
        {"NTAG424DNA, DESFire EV2", "048A9B380AF2EE1B98DC417FECC263F8449C7625CECE82D9B916C992DA209D68422B81EC20B65A66B5102A61596AF3379200599316A00A1410"},
        {"NTAG413DNA, DESFire EV1", "04BB5D514F7050025C7D0F397310360EEC91EAF792E96FC7E0F496CB4E669D414F877B7B27901FE67C2E3B33CD39D1C797715189AC951C2ADD"},
        {"DESFire EV2", "04B304DC4C615F5326FE9383DDEC9AA892DF3A57FA7FFB3276192BC0EAA252ED45A865E3B093A3D0DCE5BE29E92F1392CE7DE321E3E5C52B3A"},
        {"DESFire EV3", "041DB46C145D0A36539C6544BD6D9B0AA62FF91EC48CBC6ABAE36E0089A46F0D08C8A715EA40A63313B92E90DDC1730230E0458A33276FB743"},
        {"NTAG424DNA, NTAG424DNATT, DESFire Light EV2", "04B304DC4C615F5326FE9383DDEC9AA892DF3A57FA7FFB3276192BC0EAA252ED45A865E3B093A3D0DCE5BE29E92F1392CE7DE321E3E5C52B3B"},
        {"DESFire Light", "040E98E117AAA36457F43173DC920A8757267F44CE4EC5ADD3C54075571AEBBF7B942A9774A1D94AD02572427E5AE0A2DD36591B1FB34FCF3D"},
        {"MIFARE Plus EV1", "044409ADC42F91A8394066BA83D872FB1D16803734E911170412DDF8BAD1A4DADFD0416291AFE1C748253925DA39A5F39A1C557FFACD34C62E"},
        {"MIFARE Pluc Evx", "04BB49AE4447E6B1B6D21C098C1538B594A11A4A1DBF3D5E673DEACDEB3CC512D1C08AFA1A2768CE20A200BACD2DC7804CD7523A0131ABF607"},
    };


    uint32_t i;
    bool is_valid = false;

    for (i = 0; i < ARRAYLEN(nxp_desfire_public_keys); i++) {

        int dl = 0;
        uint8_t key[PUBLIC_DESFIRE_ECDA_KEYLEN];
        param_gethex_to_eol(nxp_desfire_public_keys[i].value, 0, key, PUBLIC_DESFIRE_ECDA_KEYLEN, &dl);

        int res = ecdsa_signature_r_s_verify(MBEDTLS_ECP_DP_SECP224R1, key, uid, uidlen, signature, signature_len, false);
        is_valid = (res == 0);
        if (is_valid)
            break;
    }
//    PrintAndLogEx(NORMAL, "");
//    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Signature"));
    if (is_valid == false || i == ARRAYLEN(nxp_desfire_public_keys)) {
        PrintAndLogEx(INFO, "    Elliptic curve parameters: NID_secp224r1");
        PrintAndLogEx(INFO, "             TAG IC Signature: %s", sprint_hex_inrow(signature, 16));
        PrintAndLogEx(INFO, "                             : %s", sprint_hex_inrow(signature + 16, 16));
        PrintAndLogEx(INFO, "                             : %s", sprint_hex_inrow(signature + 32, 16));
        PrintAndLogEx(INFO, "                             : %s", sprint_hex_inrow(signature + 48, signature_len - 48));
        PrintAndLogEx(SUCCESS, "       Signature verification: " _RED_("failed"));
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, " IC signature public key name: " _GREEN_("%s"), nxp_desfire_public_keys[i].desc);
    PrintAndLogEx(INFO, "IC signature public key value: %.32s", nxp_desfire_public_keys[i].value);
    PrintAndLogEx(INFO, "                             : %.32s", nxp_desfire_public_keys[i].value + 32);
    PrintAndLogEx(INFO, "                             : %.32s", nxp_desfire_public_keys[i].value + 64);
    PrintAndLogEx(INFO, "                             : %.32s", nxp_desfire_public_keys[i].value + 96);
    PrintAndLogEx(INFO, "    Elliptic curve parameters: NID_secp224r1");
    PrintAndLogEx(INFO, "             TAG IC Signature: %s", sprint_hex_inrow(signature, 16));
    PrintAndLogEx(INFO, "                             : %s", sprint_hex_inrow(signature + 16, 16));
    PrintAndLogEx(INFO, "                             : %s", sprint_hex_inrow(signature + 32, 16));
    PrintAndLogEx(INFO, "                             : %s", sprint_hex_inrow(signature + 48, signature_len - 48));
    PrintAndLogEx(SUCCESS, "       Signature verification: " _GREEN_("successful"));
    return PM3_SUCCESS;
}

static int handler_desfire_signature(uint8_t *signature, size_t *signature_len) {

    if (signature == NULL) {
        PrintAndLogEx(DEBUG, "SIGNATURE=NULL");
        return PM3_EINVARG;
    }
    if (signature_len == NULL) {
        PrintAndLogEx(DEBUG, "SIGNATURE_LEN=NULL");
        return PM3_EINVARG;
    }

    uint8_t c[] = {0x00};
    sAPDU apdu = {0x90, MFDES_READSIG, 0x00, 0x00, sizeof(c), c}; // 0x3C

    uint32_t recv_len = 0;
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, true, signature, &recv_len, &sw, 0, true);
    if (res == PM3_SUCCESS) {
        if (recv_len != 56) {
            *signature_len = 0;
            res = PM3_ESOFT;
        } else {
            *signature_len = recv_len;
        }
    }
    DropFieldDesfire();
    return res;
}

// --- KEY VERSION
static int desfire_print_keyversion(uint8_t key_idx, uint8_t key_version) {
    PrintAndLogEx(SUCCESS, "   Key [%u]  Version : %d (0x%02x)", key_idx, key_version, key_version);
    return PM3_SUCCESS;
}

static int handler_desfire_keyversion(uint8_t curr_key, uint8_t *num_versions) {
    if (num_versions == NULL) {
        PrintAndLogEx(DEBUG, "NUM_VERSIONS=NULL");
        return PM3_EINVARG;
    }
    sAPDU apdu = {0x90, MFDES_GET_KEY_VERSION, 0x00, 0x00, 0x01, &curr_key}; //0x64
    uint32_t recv_len = 0;
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, false, num_versions, &recv_len, &sw, 0, true);

    if (res != PM3_SUCCESS)
        return res;

    if (sw != status(MFDES_S_OPERATION_OK))
        return PM3_ESOFT;

    return res;
}

// --- KEY SETTING  Application Master Key
static int desfire_print_amk_keysetting(uint8_t key_settings, uint8_t num_keys, int algo) {
    PrintAndLogEx(SUCCESS, "  AID Key settings           : 0x%02x", key_settings);
    // 2 MSB denotes
    const char *str =                 "  Max key number and type    : %d, " _YELLOW_("%s");

    if (algo == MFDES_ALGO_DES)
        PrintAndLogEx(SUCCESS, str, num_keys & 0x3F, "(3)DES");
    else if (algo == MFDES_ALGO_AES)
        PrintAndLogEx(SUCCESS, str, num_keys & 0x3F, "AES");
    else if (algo == MFDES_ALGO_3K3DES)
        PrintAndLogEx(SUCCESS, str, num_keys & 0x3F, "3K3DES");

    //PrintAndLogEx(SUCCESS, "  Max number of keys in AID  : %d", num_keys & 0x3F);
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    PrintAndLogEx(SUCCESS, "  Changekey Access rights");

    // Access rights.
    uint8_t rights = ((key_settings >> 4) & 0x0F);
    switch (rights) {
        case 0x0:
            PrintAndLogEx(SUCCESS, "  -- AMK authentication is necessary to change any key (default)");
            break;
        case 0xE:
            PrintAndLogEx(SUCCESS, "  -- Authentication with the key to be changed (same KeyNo) is necessary to change a key");
            break;
        case 0xF:
            PrintAndLogEx(SUCCESS, "  -- All keys (except AMK,see Bit0) within this application are frozen");
            break;
        default:
            PrintAndLogEx(SUCCESS,
                          "  -- Authentication with the specified key is necessary to change any key.\n"
                          "A change key and a PICC master key (CMK) can only be changed after authentication with the master key.\n"
                          "For keys other then the master or change key, an authentication with the same key is needed."
                         );
            break;
    }

    PrintAndLogEx(SUCCESS, "   [%c...] AMK Configuration changeable   : %s", (key_settings & (1 << 3)) ? '1' : '0', (key_settings & (1 << 3)) ? _GREEN_("YES") : "NO (frozen)");
    PrintAndLogEx(SUCCESS, "   [.%c..] AMK required for create/delete : %s", (key_settings & (1 << 2)) ? '1' : '0', (key_settings & (1 << 2)) ? "NO" : "YES");
    PrintAndLogEx(SUCCESS, "   [..%c.] Directory list access with AMK : %s", (key_settings & (1 << 1)) ? '1' : '0', (key_settings & (1 << 1)) ? "NO" : "YES");
    PrintAndLogEx(SUCCESS, "   [...%c] AMK is changeable              : %s", (key_settings & (1 << 0)) ? '1' : '0', (key_settings & (1 << 0)) ? _GREEN_("YES") : "NO (frozen)");
    return PM3_SUCCESS;
}

// --- KEY SETTING  PICC Master Key (CMK)
static int desfire_print_piccmk_keysetting(uint8_t key_settings, uint8_t num_keys, int algo) {
    //PrintAndLogEx(INFO, "--- " _CYAN_("PICC Master Key (CMK) settings"));
    // number of Master keys (0x01)
    PrintAndLogEx(SUCCESS, "   Number of Masterkeys                  : " _YELLOW_("%u"), (num_keys & 0x3F));
    const char *str = "   Operation of PICC master key          : " _YELLOW_("%s");

    if (algo == MFDES_ALGO_DES)
        PrintAndLogEx(SUCCESS, str, "(3)DES");
    else if (algo == MFDES_ALGO_AES)
        PrintAndLogEx(SUCCESS, str, "AES");
    else if (algo == MFDES_ALGO_3K3DES)
        PrintAndLogEx(SUCCESS, str, "3K3DES");

    uint8_t cmk_num_versions = 0;
    if (handler_desfire_keyversion(0, &cmk_num_versions) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "   PICC Master key Version               : " _YELLOW_("%d (0x%02x)"), cmk_num_versions, cmk_num_versions);
    }

    PrintAndLogEx(INFO, "   ----------------------------------------------------------");

    // Authentication tests
    int res = test_desfire_authenticate();
    if (res == PM3_SUCCESS)
        PrintAndLogEx(SUCCESS, "   [0x0A] Authenticate      : %s", (res == PM3_SUCCESS) ? _YELLOW_("YES") : "NO");

    res = test_desfire_authenticate_iso();
    if (res == PM3_SUCCESS)
        PrintAndLogEx(SUCCESS, "   [0x1A] Authenticate ISO  : %s", (res == PM3_SUCCESS) ? _YELLOW_("YES") : "NO");

    res = test_desfire_authenticate_aes();
    if (res == PM3_SUCCESS)
        PrintAndLogEx(SUCCESS, "   [0xAA] Authenticate AES  : %s", (res == PM3_SUCCESS) ? _YELLOW_("YES") : "NO");

    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    PrintAndLogEx(INFO, " Key setting: 0x%02X [%c%c%c%c]",
                  key_settings,
                  (key_settings & (1 << 3)) ? '1' : '0',
                  (key_settings & (1 << 2)) ? '1' : '0',
                  (key_settings & (1 << 1)) ? '1' : '0',
                  (key_settings & (1 << 0)) ? '1' : '0'
                 );

    PrintAndLogEx(SUCCESS, "   [%c...] CMK Configuration changeable   : %s", (key_settings & (1 << 3)) ? '1' : '0', (key_settings & (1 << 3)) ? _GREEN_("YES") : "NO (frozen)");
    PrintAndLogEx(SUCCESS, "   [.%c..] CMK required for create/delete : %s", (key_settings & (1 << 2)) ? '1' : '0', (key_settings & (1 << 2)) ? _GREEN_("NO") : "YES");
    PrintAndLogEx(SUCCESS, "   [..%c.] Directory list access with CMK : %s", (key_settings & (1 << 1)) ? '1' : '0', (key_settings & (1 << 1)) ? _GREEN_("NO") : "YES");
    PrintAndLogEx(SUCCESS, "   [...%c] CMK is changeable              : %s", (key_settings & (1 << 0)) ? '1' : '0', (key_settings & (1 << 0)) ? _GREEN_("YES") : "NO (frozen)");
    return PM3_SUCCESS;
}

static int handler_desfire_getkeysettings(uint8_t *key_settings, uint8_t *num_keys) {
    if (key_settings == NULL) {
        PrintAndLogEx(DEBUG, "KEY_SETTINGS=NULL");
        return PM3_EINVARG;
    }
    if (num_keys == NULL) {
        PrintAndLogEx(DEBUG, "NUM_KEYS=NULL");
        return PM3_EINVARG;
    }
    sAPDU apdu = {0x90, MFDES_GET_KEY_SETTINGS, 0x00, 0x00, 0x00, NULL}; //0x45

    uint32_t recv_len = 0;
    uint16_t sw = 0;
    uint8_t data[2] = {0};
    int res = send_desfire_cmd(&apdu, false, data, &recv_len, &sw, 0, true);

    if (res != PM3_SUCCESS)
        return res;
    if (sw != status(MFDES_S_OPERATION_OK))
        return PM3_ESOFT;

    *key_settings = data[0];
    *num_keys = data[1];
    return res;
}

// --- GET APPIDS
static int handler_desfire_appids(uint8_t *dest, uint32_t *app_ids_len) {
    if (dest == NULL) {
        PrintAndLogEx(DEBUG, "DEST=NULL");
        return PM3_EINVARG;
    }
    if (app_ids_len == NULL) {
        PrintAndLogEx(DEBUG, "APP_IDS_LEN=NULL");
        return PM3_EINVARG;
    }

    sAPDU apdu = {0x90, MFDES_GET_APPLICATION_IDS, 0x00, 0x00, 0x00, NULL}; //0x6a
    uint32_t recv_len = 0;
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, true, dest, &recv_len, &sw, 0, true);

    if (res != PM3_SUCCESS)
        return res;

    if (sw != status(MFDES_S_OPERATION_OK))
        return PM3_ESOFT;

    *app_ids_len = (uint8_t)(recv_len & 0xFF);
    return res;
}

// --- GET DF NAMES
static int handler_desfire_dfnames(dfname_t *dest, uint8_t *dfname_count) {

    if (g_debugMode > 1) {
        if (dest == NULL) PrintAndLogEx(ERR, "DEST = NULL");
        if (dfname_count == NULL) PrintAndLogEx(ERR, "DFNAME_COUNT = NULL");
    }

    if (dest == NULL || dfname_count == NULL)
        return PM3_EINVARG;

    *dfname_count = 0;
    sAPDU apdu = {0x90, MFDES_GET_DF_NAMES, 0x00, 0x00, 0x00, NULL}; //0x6d
    uint32_t recv_len = 0;
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, true, (uint8_t *)dest, &recv_len, &sw, sizeof(dfname_t), true);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (sw != status(MFDES_S_OPERATION_OK))
        return PM3_ESOFT;

    *dfname_count = recv_len;
    return res;
}

static int handler_desfire_select_application(uint8_t *aid) {
    if (g_debugMode > 1) {
        if (aid == NULL) {
            PrintAndLogEx(ERR, "AID=NULL");
        }
    }
    if (aid == NULL) {
        return PM3_EINVARG;
    }

    sAPDU apdu = {0x90, MFDES_SELECT_APPLICATION, 0x00, 0x00, 0x03, aid}; //0x5a
    uint32_t recv_len = 0;
    uint16_t sw = 0;

    int res = send_desfire_cmd(&apdu, !tag->rf_field_on, NULL, &recv_len, &sw, sizeof(dfname_t), true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING,
                      _RED_("   Can't select AID 0x%X -> %s"),
                      (aid[2] << 16) + (aid[1] << 8) + aid[0],
                      DesfireGetErrorString(res, &sw)
                     );
        DropFieldDesfire();
        return res;
    }
    memcpy(&tag->selected_application, aid, 3);
    return PM3_SUCCESS;
}

static int key_setting_to_algo(uint8_t aid[3], uint8_t *key_setting, mifare_des_authalgo_t *algo, uint8_t *num_keys) {
    int res = handler_desfire_select_application(aid);
    if (res != PM3_SUCCESS) return res;

    *num_keys = 0;
    res = handler_desfire_getkeysettings(key_setting, num_keys);
    if (res == PM3_SUCCESS) {
        switch (*num_keys >> 6) {
            case 0:
                *algo = MFDES_ALGO_DES;
                break;
            case 1:
                *algo = MFDES_ALGO_3K3DES;
                break;
            case 2:
                *algo = MFDES_ALGO_AES;
                break;
        }
    }
    return res;
}

static int handler_desfire_fileids(uint8_t *dest, uint32_t *file_ids_len) {
    if (g_debugMode > 1) {
        if (dest == NULL) PrintAndLogEx(ERR, "DEST=NULL");
        if (file_ids_len == NULL) PrintAndLogEx(ERR, "FILE_IDS_LEN=NULL");
    }
    if (dest == NULL || file_ids_len == NULL) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_GET_FILE_IDS, 0x00, 0x00, 0x00, NULL}; //0x6f
    uint32_t recv_len = 0;
    uint16_t sw = 0;
    *file_ids_len = 0;
    int res = send_desfire_cmd(&apdu, false, dest, &recv_len, &sw, 0, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't get file ids -> %s"), DesfireGetErrorString(res, &sw));
        DropFieldDesfire();
        return res;
    }
    *file_ids_len = recv_len;
    return res;
}

// none, verified
static int handler_desfire_filesettings(uint8_t file_id, uint8_t *dest, uint32_t *destlen) {
    if (g_debugMode > 1) {
        if (dest == NULL) PrintAndLogEx(ERR, "DEST=NULL");
        if (destlen == NULL) PrintAndLogEx(ERR, "DESTLEN=NULL");
    }
    if (dest == NULL || destlen == NULL) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_GET_FILE_SETTINGS, 0x00, 0x00, 0x01, &file_id}; // 0xF5
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, false, dest, destlen, &sw, 0, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't get file settings -> %s"), DesfireGetErrorString(res, &sw));
        DropFieldDesfire();
        return res;
    }
    return res;
}

static int getKeySettings(uint8_t *aid) {
    if (aid == NULL) return PM3_EINVARG;

    uint8_t num_keys = 0;
    uint8_t key_setting = 0;
    int res = 0;
    if (memcmp(aid, "\x00\x00\x00", 3) == 0) {

        // CARD MASTER KEY
        //PrintAndLogEx(INFO, "--- " _CYAN_("CMK - PICC, Card Master Key settings"));

        // KEY Settings - AMK
        mifare_des_authalgo_t algo = MFDES_ALGO_DES;
        res = key_setting_to_algo(aid, &key_setting, &algo, &num_keys);

        if (res == PM3_SUCCESS) {
            desfire_print_piccmk_keysetting(key_setting, num_keys, algo);
        } else {
            PrintAndLogEx(WARNING, _RED_("   Can't read PICC Master key settings"));
        }

    } else {

        // AID - APPLICATION MASTER KEYS
        //PrintAndLogEx(SUCCESS, "--- " _CYAN_("AMK - Application Master Key settings"));
        res = handler_desfire_select_application(aid);
        if (res != PM3_SUCCESS) return res;

        // KEY Settings - AMK
        mifare_des_authalgo_t algo = MFDES_ALGO_DES;
        res = key_setting_to_algo(aid, &key_setting, &algo, &num_keys);
        if (res == PM3_SUCCESS) {
            desfire_print_amk_keysetting(key_setting, num_keys, algo);
        } else {
            PrintAndLogEx(WARNING, _RED_("   Can't read Application Master key settings"));
        }

        // KEY VERSION  - AMK
        uint8_t num_version = 0;
        if (handler_desfire_keyversion(0, &num_version) == PM3_SUCCESS) {
            PrintAndLogEx(INFO, "-------------------------------------------------------------");
            PrintAndLogEx(INFO, "  Application keys");
            desfire_print_keyversion(0, num_version);
        } else {
            PrintAndLogEx(WARNING, "   Can't read AID master key version. Trying all keys");
        }

        // From 0x01 to numOfKeys.  We already got 0x00. (AMK)
        num_keys &= 0x3F;
        if (num_keys > 1) {
            for (uint8_t i = 0x01; i < num_keys; ++i) {
                if (handler_desfire_keyversion(i, &num_version) == PM3_SUCCESS) {
                    desfire_print_keyversion(i, num_version);
                } else {
                    PrintAndLogEx(WARNING, "   Can't read key %d  (0x%02x) version", i, i);
                }
            }
        }
    }

    DropFieldDesfire();
    return PM3_SUCCESS;
}

static void swap24(uint8_t *data) {
    if (data == NULL) return;
    uint8_t tmp = data[0];
    data[0] = data[2];
    data[2] = tmp;
};

static int desfire_authenticate(int cmdAuthMode, int cmdAuthAlgo, uint8_t *aid, uint8_t *key, int cmdKeyNo, uint8_t cmdKdfAlgo, uint8_t kdfInputLen, uint8_t *kdfInput, mfdes_auth_res_t *rpayload) {
    switch (cmdAuthMode) {
        case MFDES_AUTH_DES:
            if (cmdAuthAlgo != MFDES_ALGO_DES && cmdAuthAlgo != MFDES_ALGO_3DES) {
                PrintAndLogEx(NORMAL, "Crypto algo not valid for the auth des mode");
                return PM3_EINVARG;
            }
            break;
        case MFDES_AUTH_ISO:
            if (cmdAuthAlgo != MFDES_ALGO_3DES && cmdAuthAlgo != MFDES_ALGO_3K3DES) {
                PrintAndLogEx(NORMAL, "Crypto algo not valid for the auth iso mode");
                return PM3_EINVARG;
            }
            break;
        case MFDES_AUTH_AES:
            if (cmdAuthAlgo != MFDES_ALGO_AES) {
                PrintAndLogEx(NORMAL, "Crypto algo not valid for the auth aes mode");
                return PM3_EINVARG;
            }
            break;
        case MFDES_AUTH_PICC:
            if (cmdAuthAlgo != MFDES_AUTH_DES) {
                PrintAndLogEx(NORMAL, "Crypto algo not valid for the auth picc mode");
                return PM3_EINVARG;
            }
            break;
        default:
            PrintAndLogEx(WARNING, "Wrong Auth mode (%d) -> (1=normal, 2=iso, 3=aes)", cmdAuthMode);
            return PM3_EINVARG;
    }

    int keylength = 16;

    switch (cmdAuthAlgo) {
        case MFDES_ALGO_3DES:
            keylength = 16;
            break;
        case MFDES_ALGO_3K3DES:
            keylength = 24;
            break;
        case MFDES_ALGO_AES:
            keylength = 16;
            break;
        default:
            cmdAuthAlgo = MFDES_ALGO_DES;
            keylength = 8;
            break;
    }

    switch (cmdKdfAlgo) {
        case MFDES_KDF_ALGO_AN10922:
            // TODO: 2TDEA and 3TDEA keys use an input length of 1-15 bytes
            if (cmdAuthAlgo != MFDES_ALGO_AES) {
                PrintAndLogEx(FAILED, "Crypto algo not valid for the KDF AN10922 algo.");
                return PM3_EINVARG;
            }
            if (kdfInputLen < 1 || kdfInputLen > 31) {
                PrintAndLogEx(FAILED, "KDF AN10922 algo requires an input of length 1-31 bytes.");
                return PM3_EINVARG;
            }
            break;
        case MFDES_KDF_ALGO_GALLAGHER:
            // TODO: 2TDEA and 3TDEA keys use an input length of 1-15 bytes
            if (cmdAuthAlgo != MFDES_ALGO_AES) {
                PrintAndLogEx(FAILED, "Crypto algo not valid for the KDF AN10922 algo.");
                return PM3_EINVARG;
            }
            break;
        // KDF input arg is ignored as it'll be generated.
        case MFDES_KDF_ALGO_NONE:
            break;
        default:
            PrintAndLogEx(WARNING, "KDF algo %d is not supported.", cmdKdfAlgo);
            return PM3_EINVARG;
    }

    // KEY
    int res = handler_desfire_select_application(aid);
    if (res != PM3_SUCCESS) return res;

    if (memcmp(aid, "\x00\x00\x00", 3) != 0) {
        uint8_t file_ids[33] = {0};
        uint32_t file_ids_len = 0;
        res = handler_desfire_fileids(file_ids, &file_ids_len);
        if (res != PM3_SUCCESS) return res;
    }

    mfdes_authinput_t payload;
    payload.keylen = keylength;
    memcpy(payload.key, key, keylength);
    payload.mode = cmdAuthMode;
    payload.algo = cmdAuthAlgo;
    payload.keyno = cmdKeyNo;
    payload.kdfAlgo = cmdKdfAlgo;
    payload.kdfInputLen = kdfInputLen;
    memcpy(payload.kdfInput, kdfInput, kdfInputLen);

    int error = handler_desfire_auth(&payload, rpayload);
    if (error == PM3_SUCCESS) {
        memcpy(&currentauth[payload.keyno], &payload, sizeof(mfdes_authinput_t));
    }

    return error;
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

    DropFieldDesfire();

    mfdes_info_res_t info;
    int res = mfdes_get_info(&info);
    if (res != PM3_SUCCESS) {
        return res;
    }

    nxp_cardtype_t cardtype = getCardType(info.versionHW[3], info.versionHW[4]);
    if (cardtype == PLUS_EV1) {
        PrintAndLogEx(INFO, "Card seems to be MIFARE Plus EV1.  Try " _YELLOW_("`hf mfp info`"));
        return PM3_SUCCESS;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    PrintAndLogEx(SUCCESS, "              UID: " _GREEN_("%s"), sprint_hex(info.uid, info.uidlen));
    PrintAndLogEx(SUCCESS, "     Batch number: " _GREEN_("%s"), sprint_hex(info.details + 7, 5));
    PrintAndLogEx(SUCCESS, "  Production date: week " _GREEN_("%02x") " / " _GREEN_("20%02x"), info.details[12], info.details[13]);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Hardware Information"));
    PrintAndLogEx(INFO, "   raw: %s", sprint_hex_inrow(info.versionHW, sizeof(info.versionHW)));

    PrintAndLogEx(INFO, "     Vendor Id: " _YELLOW_("%s"), getTagInfo(info.versionHW[0]));
    PrintAndLogEx(INFO, "          Type: " _YELLOW_("0x%02X"), info.versionHW[1]);
    PrintAndLogEx(INFO, "       Subtype: " _YELLOW_("0x%02X"), info.versionHW[2]);
    PrintAndLogEx(INFO, "       Version: %s", getVersionStr(info.versionHW[3], info.versionHW[4]));
    PrintAndLogEx(INFO, "  Storage size: %s", getCardSizeStr(info.versionHW[5]));
    PrintAndLogEx(INFO, "      Protocol: %s", getProtocolStr(info.versionHW[6], true));
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Software Information"));
    PrintAndLogEx(INFO, "   raw: %s", sprint_hex_inrow(info.versionSW, sizeof(info.versionSW)));
    PrintAndLogEx(INFO, "     Vendor Id: " _YELLOW_("%s"), getTagInfo(info.versionSW[0]));
    PrintAndLogEx(INFO, "          Type: " _YELLOW_("0x%02X"), info.versionSW[1]);
    PrintAndLogEx(INFO, "       Subtype: " _YELLOW_("0x%02X"), info.versionSW[2]);
    PrintAndLogEx(INFO, "       Version: " _YELLOW_("%d.%d"),  info.versionSW[3], info.versionSW[4]);
    PrintAndLogEx(INFO, "  Storage size: %s", getCardSizeStr(info.versionSW[5]));
    PrintAndLogEx(INFO, "      Protocol: %s", getProtocolStr(info.versionSW[6], false));

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Card capabilities"));
    uint8_t major = info.versionSW[3];
    uint8_t minor = info.versionSW[4];
    if (major == 0 && minor == 4)
        PrintAndLogEx(INFO, "\t0.4 - DESFire MF3ICD40, No support for APDU (only native commands)");
    if (major == 0 && minor == 5)
        PrintAndLogEx(INFO, "\t0.5 - DESFire MF3ICD40, Support for wrapping commands inside ISO 7816 style APDUs");
    if (major == 0 && minor == 6)
        PrintAndLogEx(INFO, "\t0.6 - DESFire MF3ICD40, Add ISO/IEC 7816 command set compatibility");
    if (major == 1 && minor == 3)
        PrintAndLogEx(INFO, "\t1.3 - DESFire Ev1 MF3ICD21/41/81, Support extended APDU commands, EAL4+");
    if (major == 1 && minor == 4)
        PrintAndLogEx(INFO, "\t1.4 - DESFire Ev1 MF3ICD21/41/81, EAL4+");
    if (major == 2 && minor == 0)
        PrintAndLogEx(INFO, "\t2.0 - DESFire Ev2, Originality check, proximity check, EAL5");
    if (major == 3 && minor == 0)
        PrintAndLogEx(INFO, "\t3.0 - DESFire Ev3, Originality check, proximity check, badass EAL6 ?");

    if (major == 0 && minor == 2)
        PrintAndLogEx(INFO, "\t0.2 - DESFire Light, Originality check, ");

    if (cardtype == DESFIRE_EV2 ||
            cardtype == DESFIRE_LIGHT ||
            cardtype == DESFIRE_EV3 ||
            cardtype == NTAG413DNA) {
        // Signature originality check
        uint8_t signature[56] = {0};
        size_t signature_len = 0;

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "--- " _CYAN_("Tag Signature"));
        if (handler_desfire_signature(signature, &signature_len) == PM3_SUCCESS) {
            desfire_print_signature(info.uid, info.uidlen, signature, signature_len, cardtype);
        } else {
            PrintAndLogEx(WARNING, "--- Card doesn't support GetSignature cmd");
        }
    }

    // Master Key settings
    uint8_t master_aid[3] = {0x00, 0x00, 0x00};
    getKeySettings(master_aid);

    if (cardtype != DESFIRE_LIGHT) {
        // Free memory on card
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "--- " _CYAN_("Free memory"));
        uint32_t free_mem = 0;
        if (handler_desfire_freemem(&free_mem) == PM3_SUCCESS) {
            desfire_print_freemem(free_mem);
        } else {
            PrintAndLogEx(SUCCESS, "   Card doesn't support 'free mem' cmd");
        }
        PrintAndLogEx(INFO, "-------------------------------------------------------------");
    }


    iso14a_card_select_t card;
    res = SelectCard14443A_4(true, false, &card);
    if (res == PM3_SUCCESS) {
        static const char STANDALONE_DESFIRE[] = { 0x75, 0x77, 0x81, 0x02};
        static const char JCOP_DESFIRE[] = { 0x75, 0xf7, 0xb1, 0x02 };
        static const char JCOP3_DESFIRE[] = { 0x78, 0x77, 0x71, 0x02 };

        if (card.sak == 0x20) {

            if (card.ats_len >= 5) {
                if (str_startswith((const char *)card.ats + 1, STANDALONE_DESFIRE)) {
                    PrintAndLogEx(INFO, "Standalone DESFire");
                }
                if (str_startswith((const char *)card.ats + 1, JCOP_DESFIRE)) {
                    PrintAndLogEx(INFO, "JCOP DESFire");
                }
            }
            if (card.ats_len == 4) {
                if (str_startswith((const char *)card.ats + 1, JCOP3_DESFIRE)) {
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

    DropFieldDesfire();
    return PM3_SUCCESS;
}

static void DecodeFileType(uint8_t filetype) {
    switch (filetype) {
        case 0x00:
            PrintAndLogEx(INFO, "     File Type: 0x%02X -> Standard Data File", filetype);
            break;
        case 0x01:
            PrintAndLogEx(INFO, "     File Type: 0x%02X -> Backup Data File", filetype);
            break;
        case 0x02:
            PrintAndLogEx(INFO, "     File Type: 0x%02X -> Value Files with Backup", filetype);
            break;
        case 0x03:
            PrintAndLogEx(INFO, "     File Type: 0x%02X -> Linear Record Files with Backup", filetype);
            break;
        case 0x04:
            PrintAndLogEx(INFO, "     File Type: 0x%02X -> Cyclic Record Files with Backup", filetype);
            break;
        default:
            PrintAndLogEx(INFO, "     File Type: 0x%02X", filetype);
            break;
    }
}

static void DecodeComSet(uint8_t comset) {
    switch (comset) {
        case 0x00:
            PrintAndLogEx(INFO, "     Com.Setting: 0x%02X -> Plain", comset);
            break;
        case 0x01:
            PrintAndLogEx(INFO, "     Com.Setting: 0x%02X -> Plain + MAC", comset);
            break;
        case 0x03:
            PrintAndLogEx(INFO, "     Com.Setting: 0x%02X -> Enciphered", comset);
            break;
        default:
            PrintAndLogEx(INFO, "     Com.Setting: 0x%02X", comset);
            break;
    }
}

static char *DecodeAccessValue(uint8_t value) {

    char *car = (char *)calloc(255, sizeof(char));
    if (car == NULL)
        return NULL;

    switch (value) {
        case 0xE:
            strcat(car, "(Free Access)");
            break;
        case 0xF:
            strcat(car, "(Denied Access)");
            break;
        default:
            snprintf(car, 255, "(Access Key: %d)", value);
            break;
    }
    return car;
}

static void DecodeAccessRights(uint16_t accrights) {
    int change_access_rights = accrights & 0xF;
    int read_write_access = (accrights >> 4) & 0xF;
    int write_access = (accrights >> 8) & 0xF;
    int read_access = (accrights >> 12) & 0xF;
    char *car = DecodeAccessValue(change_access_rights);
    if (car == NULL) return;

    char *rwa = DecodeAccessValue(read_write_access);
    if (rwa == NULL) {
        free(car);
        return;
    }

    char *wa = DecodeAccessValue(write_access);
    if (wa == NULL) {
        free(car);
        free(rwa);
        return;
    }

    char *ra = DecodeAccessValue(read_access);
    if (ra == NULL) {
        free(car);
        free(rwa);
        free(wa);
        return;
    }

    PrintAndLogEx(INFO, "     Access Rights: 0x%04X - Change %s - RW %s - W %s - R %s", accrights, car, rwa, wa, ra);
    free(car);
    free(rwa);
    free(wa);
    free(ra);
}

static int DecodeFileSettings(uint8_t *src, int src_len, int maclen) {
    uint8_t filetype = src[0];
    uint8_t comset = src[1];

    uint16_t accrights = (src[3] << 8) + src[2];
    if (src_len == 1 + 1 + 2 + 3 + maclen) {
        int filesize = (src[6] << 16) + (src[5] << 8) + src[4];
        DecodeFileType(filetype);
        DecodeComSet(comset);
        DecodeAccessRights(accrights);
        PrintAndLogEx(INFO, "     Filesize: %d (0x%X)", filesize, filesize);
        return PM3_SUCCESS;
    } else if (src_len == 1 + 1 + 2 + 4 + 4 + 4 + 1 + maclen) {
        int lowerlimit = (src[7] << 24) + (src[6] << 16) + (src[5] << 8) + src[4];
        int upperlimit = (src[11] << 24) + (src[10] << 16) + (src[9] << 8) + src[8];
        int limitcredvalue = (src[15] << 24) + (src[14] << 16) + (src[13] << 8) + src[12];
        uint8_t limited_credit_enabled = src[17];
        DecodeFileType(filetype);
        DecodeComSet(comset);
        DecodeAccessRights(accrights);
        PrintAndLogEx(INFO, "     Lower limit: %d (0x%X) - Upper limit: %d (0x%X) - limited credit value: %d (0x%X) - limited credit enabled: %d", lowerlimit, lowerlimit, upperlimit, upperlimit, limitcredvalue, limitcredvalue, limited_credit_enabled);
        return PM3_SUCCESS;
    } else if (src_len == 1 + 1 + 2 + 3 + 3 + 3 + maclen) {
        uint32_t recordsize = (src[6] << 16) + (src[5] << 8) + src[4];
        uint32_t maxrecords = (src[9] << 16) + (src[8] << 8) + src[7];
        uint32_t currentrecord = (src[12] << 16) + (src[11] << 8) + src[10];
        DecodeFileType(filetype);
        DecodeComSet(comset);
        DecodeAccessRights(accrights);
        PrintAndLogEx(INFO, "     Record size: %d (0x%X) - MaxNumberRecords: %d (0x%X) - Current Number Records: %d (0x%X)", recordsize, recordsize, maxrecords, maxrecords, currentrecord, currentrecord);
        return PM3_SUCCESS;
    }
    return PM3_ESOFT;
}

static int CmdHF14ADesEnumApplications(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes enum",
                  "Enumerate all AID's on MIFARE DESfire tag",
                  "hf mfdes enum");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    DropFieldDesfire();

    uint8_t aid[3] = {0};
    uint8_t app_ids[78] = {0};
    uint32_t app_ids_len = 0;

    uint8_t file_ids[33] = {0};
    uint32_t file_ids_len = 0;

    dfname_t dfnames[255];
    uint8_t dfname_count = 0;

    if (handler_desfire_appids(app_ids, &app_ids_len) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Can't get list of applications on tag");
        DropFieldDesfire();
        return PM3_ESOFT;
    }

    if (handler_desfire_dfnames(dfnames, &dfname_count) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("Can't get DF Names"));
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "-- MIFARE DESFire Enumerate applications --------------------");
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    PrintAndLogEx(SUCCESS, " Tag report " _GREEN_("%d") " application%c", app_ids_len / 3, (app_ids_len == 3) ? ' ' : 's');

    for (uint32_t i = 0; i < app_ids_len; i += 3) {

        aid[0] = app_ids[i];
        aid[1] = app_ids[i + 1];
        aid[2] = app_ids[i + 2];

        PrintAndLogEx(NORMAL, "");

        if (memcmp(aid, "\x00\x00\x00", 3) == 0) {
            // CARD MASTER KEY
            PrintAndLogEx(INFO, "--- " _CYAN_("CMK - PICC, Card Master Key settings"));
        } else {
            PrintAndLogEx(SUCCESS, "--- " _CYAN_("AMK - Application Master Key settings"));
        }

        PrintAndLogEx(SUCCESS, "  AID : " _GREEN_("%02X%02X%02X"), aid[2], aid[1], aid[0]);
        if ((aid[2] >> 4) == 0xF) {
            uint16_t short_aid = ((aid[2] & 0xF) << 12) | (aid[1] << 4) | (aid[0] >> 4);
            PrintAndLogEx(SUCCESS, "  AID mapped to MIFARE Classic AID (MAD): " _YELLOW_("%02X"), short_aid);
            PrintAndLogEx(SUCCESS, "  MAD AID Cluster  0x%02X      : " _YELLOW_("%s"), short_aid >> 8, cluster_to_text(short_aid >> 8));
            MADDFDecodeAndPrint(short_aid);
        } else {
            AIDDFDecodeAndPrint(aid);
        }
        for (uint8_t m = 0; m < dfname_count; m++) {
            if (dfnames[m].aid[0] == aid[0] && dfnames[m].aid[1] == aid[1] && dfnames[m].aid[2] == aid[2]) {
                PrintAndLogEx(SUCCESS, "  -  DF " _YELLOW_("%02X%02X") " Name : " _YELLOW_("%s"), dfnames[m].fid[1], dfnames[m].fid[0], dfnames[m].name);
            }
        }

        int res = getKeySettings(aid);
        if (res != PM3_SUCCESS) continue;

        res = handler_desfire_select_application(aid);
        if (res != PM3_SUCCESS) continue;

        res = handler_desfire_fileids(file_ids, &file_ids_len);
        if (res != PM3_SUCCESS) continue;

        PrintAndLogEx(SUCCESS, " Tag report " _GREEN_("%d") " file%c", file_ids_len, (file_ids_len == 1) ? ' ' : 's');
        for (int j = (int)file_ids_len - 1; j >= 0; j--) {
            PrintAndLogEx(SUCCESS, "   Fileid %d (0x%02x)", file_ids[j], file_ids[j]);

            uint8_t filesettings[20] = {0};
            uint32_t fileset_len = 0;
            uint32_t maclen = 0; // To be implemented

            res = handler_desfire_filesettings(file_ids[j], filesettings, &fileset_len);
            if (res != PM3_SUCCESS) continue;

            if (DecodeFileSettings(filesettings, fileset_len, maclen) != PM3_SUCCESS) {
                PrintAndLogEx(INFO, "  Settings [%u] %s", fileset_len, sprint_hex(filesettings, fileset_len));
            }
        }

    }
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    DropFieldDesfire();
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

static int AuthCheckDesfire(uint8_t *aid,
                            uint8_t deskeyList[MAX_KEYS_LIST_LEN][8], uint32_t deskeyListLen,
                            uint8_t aeskeyList[MAX_KEYS_LIST_LEN][16], uint32_t aeskeyListLen,
                            uint8_t k3kkeyList[MAX_KEYS_LIST_LEN][24], uint32_t k3kkeyListLen,
                            uint8_t cmdKdfAlgo, uint8_t kdfInputLen, uint8_t *kdfInput,
                            uint8_t foundKeys[4][0xE][24 + 1], bool *result) {

    uint32_t curaid = (aid[0] & 0xFF) + ((aid[1] & 0xFF) << 8) + ((aid[2] & 0xFF) << 16);

    int res = handler_desfire_select_application(aid);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "AID 0x%06X does not exist.", curaid);
        return res;
    }

    int usedkeys[0xF] = {0};
    bool des = false;
    bool tdes = false;
    bool aes = false;
    bool k3kdes = false;

    uint8_t num_keys = 0;
    uint8_t key_setting = 0;
    res = handler_desfire_getkeysettings(&key_setting, &num_keys);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Could not get key settings");
        return res;
    }

    if (memcmp(aid, "\x00\x00\x00", 3) != 0) {
        uint8_t file_ids[33] = {0};
        uint32_t file_ids_len = 0;
        // Get File IDs
        if (handler_desfire_fileids(file_ids, &file_ids_len) == PM3_SUCCESS) {

            for (int j = (int)file_ids_len - 1; j >= 0; j--) {

                uint8_t filesettings[20] = {0};
                uint32_t fileset_len = 0;

                res = handler_desfire_filesettings(file_ids[j], filesettings, &fileset_len);
                if (res == PM3_SUCCESS) {

                    uint16_t accrights = (filesettings[3] << 8) + filesettings[2];
                    uint8_t change_access_rights = accrights & 0xF;
                    uint8_t read_write_access = (accrights >> 4) & 0xF;
                    uint8_t write_access = (accrights >> 8) & 0xF;
                    uint8_t read_access = (accrights >> 12) & 0xF;

                    if (change_access_rights == 0xE) change_access_rights = 0x0;
                    if (read_write_access == 0xE) read_write_access = 0x0;
                    if (write_access == 0xE) write_access = 0x0;
                    if (read_access == 0xE) read_access = 0x0;

                    usedkeys[change_access_rights] = 1;
                    usedkeys[read_write_access] = 1;
                    usedkeys[write_access] = 1;
                    usedkeys[read_access] = 1;

                    if (res == PM3_SUCCESS) {
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
                    }
                }
            }

            if (file_ids_len == 0) {
                for (uint8_t z = 0; z < 0xE; z++) {
                    usedkeys[z] = 1;
                    des = true;
                    tdes = true;
                    aes = true;
                    k3kdes = true;
                }
            }
        }
    } else {
        des = true;
    }

    int error;
    bool badlen = false;

    if (des) {

        for (uint8_t keyno = 0; keyno < 0xE; keyno++) {

            if (usedkeys[keyno] == 1 && foundKeys[0][keyno][0] == 0) {
                for (uint32_t curkey = 0; curkey < deskeyListLen; curkey++) {
                    mfdes_auth_res_t rpayload;
                    error = desfire_authenticate(MFDES_AUTH_DES, MFDES_ALGO_DES, aid, deskeyList[curkey], keyno, 0, 0, NULL, &rpayload);
                    if (error == PM3_SUCCESS) {
                        PrintAndLogEx(SUCCESS, "AID 0x%06X, Found DES Key %u        : " _GREEN_("%s"), curaid, keyno, sprint_hex(deskeyList[curkey], 8));
                        foundKeys[0][keyno][0] = 0x01;
                        *result = true;
                        memcpy(&foundKeys[0][keyno][1], deskeyList[curkey], 8);
                        break;
                    } else if (error < 7) {
                        badlen = true;
                        DropFieldDesfire();
                        res = handler_desfire_select_application(aid);
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
                    mfdes_auth_res_t rpayload;
                    error = desfire_authenticate(MFDES_AUTH_DES, MFDES_ALGO_3DES, aid, aeskeyList[curkey], keyno, 0, 0, NULL, &rpayload);
                    if (error == PM3_SUCCESS) {
                        PrintAndLogEx(SUCCESS, "AID 0x%06X, Found 3DES Key %u        : " _GREEN_("%s"), curaid, keyno, sprint_hex(aeskeyList[curkey], 16));
                        foundKeys[1][keyno][0] = 0x01;
                        *result = true;
                        memcpy(&foundKeys[1][keyno][1], aeskeyList[curkey], 16);
                        break;
                    } else if (error < 7) {
                        badlen = true;
                        DropFieldDesfire();
                        res = handler_desfire_select_application(aid);
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
                    mfdes_auth_res_t rpayload;
                    error = desfire_authenticate(MFDES_AUTH_AES, MFDES_ALGO_AES, aid, aeskeyList[curkey], keyno, cmdKdfAlgo, kdfInputLen, kdfInput, &rpayload);
                    if (error == PM3_SUCCESS) {
                        PrintAndLogEx(SUCCESS, "AID 0x%06X, Found AES Key %u        : " _GREEN_("%s"), curaid, keyno, sprint_hex(aeskeyList[curkey], 16));
                        foundKeys[2][keyno][0] = 0x01;
                        *result = true;
                        memcpy(&foundKeys[2][keyno][1], aeskeyList[curkey], 16);
                        break;
                    } else if (error < 7) {
                        badlen = true;
                        DropFieldDesfire();
                        res = handler_desfire_select_application(aid);
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
                    mfdes_auth_res_t rpayload;
                    error = desfire_authenticate(MFDES_AUTH_ISO, MFDES_ALGO_3K3DES, aid, k3kkeyList[curkey], keyno, 0, 0, NULL, &rpayload);
                    if (error == PM3_SUCCESS) {
                        PrintAndLogEx(SUCCESS, "AID 0x%06X, Found 3K3 Key %u        : " _GREEN_("%s"), curaid, keyno, sprint_hex(k3kkeyList[curkey], 24));
                        foundKeys[3][keyno][0] = 0x01;
                        *result = true;
                        memcpy(&foundKeys[3][keyno][1], k3kkeyList[curkey], 16);
                        break;
                    } else if (error < 7) {
                        badlen = true;
                        DropFieldDesfire();
                        res = handler_desfire_select_application(aid);
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
    DropFieldDesfire();
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
                  "hf mfdes chk -a 123456 -k 000102030405060708090a0b0c0d0e0f -> check key on aid 0x123456\n"
                  "hf mfdes chk -d mfdes_default_keys -> check keys from dictionary against all existing aid on card\n"
                  "hf mfdes chk -d mfdes_default_keys -a 123456 -> check keys from dictionary against aid 0x123456\n"
                  "hf mfdes chk -a 123456 --pattern1b -j keys -> check all 1-byte keys pattern on aid 0x123456 and save found keys to json\n"
                  "hf mfdes chk -a 123456 --pattern2b --startp2b FA00 -> check all 2-byte keys pattern on aid 0x123456. Start from key FA00FA00...FA00");

    void *argtable[] = {
        arg_param_begin,
        arg_strx0("a",  "aid",      "<aid>", "Use specific AID (3 hex bytes, big endian)"),
        arg_str0("k",  "key",       "<Key>", "Key for checking (HEX 16 bytes)"),
        arg_str0("d",  "dict",      "<file>", "File with keys dictionary"),
        arg_lit0(NULL,  "pattern1b", "Check all 1-byte combinations of key (0000...0000, 0101...0101, 0202...0202, ...)"),
        arg_lit0(NULL,  "pattern2b", "Check all 2-byte combinations of key (0000...0000, 0001...0001, 0002...0002, ...)"),
        arg_str0(NULL,  "startp2b",  "<Pattern>", "Start key (2-byte HEX) for 2-byte search (use with `--pattern2b`)"),
        arg_str0("j",  "json",      "<file>",  "Json file to save keys"),
        arg_lit0("v",  "verbose",   "Verbose mode."),
        arg_int0("f",  "kdf",     "<kdf>", "Key Derivation Function (KDF) (0=None, 1=AN10922, 2=Gallagher)"),
        arg_str0("i",  "kdfi",    "<kdfi>", "KDF input (HEX 1-31 bytes)"),
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
    uint8_t kdfInput[31] = {0};
    int kdfInputLen = 0;
    uint8_t cmdKDFAlgo  = arg_get_int_def(ctx, 9, 0);
    CLIGetHexWithReturn(ctx, 10, kdfInput, &kdfInputLen);

    CLIParserFree(ctx);

    // 1-byte pattern search mode
    if (pattern1b) {
        for (uint32_t i = 0; i < 0x100; i++)
            memset(aeskeyList[i], i, 16);
        for (uint32_t i = 0; i < 0x100; i++)
            memset(deskeyList[i], i, 8);
        for (uint32_t i = 0; i < 0x100; i++)
            memset(k3kkeyList[i], i, 24);
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
        if (res == PM3_SUCCESS && endFilePosition)
            PrintAndLogEx(SUCCESS, "First part of des dictionary successfully loaded.");

        endFilePosition = 0;
        res = loadFileDICTIONARYEx((char *)dict_filename, aeskeyList, sizeof(aeskeyList), NULL, 16, &aeskeyListLen, 0, &endFilePosition, true);
        if (res == PM3_SUCCESS && endFilePosition)
            PrintAndLogEx(SUCCESS, "First part of aes dictionary successfully loaded.");

        endFilePosition = 0;
        res = loadFileDICTIONARYEx((char *)dict_filename, k3kkeyList, sizeof(k3kkeyList), NULL, 24, &k3kkeyListLen, 0, &endFilePosition, true);
        if (res == PM3_SUCCESS && endFilePosition)
            PrintAndLogEx(SUCCESS, "First part of k3kdes dictionary successfully loaded.");

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

    if (verbose == false)
        PrintAndLogEx(INFO, "Search keys:");

    bool result = false;
    uint8_t app_ids[78] = {0};
    uint32_t app_ids_len = 0;

    clearCommandBuffer();

    mfdes_info_res_t info = {0};
    res = mfdes_get_info(&info);
    if (res != PM3_SUCCESS) {
        return res;
    }
    // TODO: Store this UID someowhere not global
    memcpy(tag->info.uid, info.uid, info.uidlen);
    tag->info.uidlen = info.uidlen;

    if (handler_desfire_appids(app_ids, &app_ids_len) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Can't get list of applications on tag");
        DropFieldDesfire();
        return PM3_ESOFT;
    }

    if (aidlength != 0) {
        memcpy(&app_ids[0], aid, 3);
        app_ids_len = 3;
    }

    for (uint32_t x = 0; x < app_ids_len / 3; x++) {

        uint32_t curaid = (app_ids[x * 3] & 0xFF) + ((app_ids[(x * 3) + 1] & 0xFF) << 8) + ((app_ids[(x * 3) + 2] & 0xFF) << 16);
        PrintAndLogEx(ERR, "Checking aid 0x%06X...", curaid);

        res = AuthCheckDesfire(&app_ids[x * 3], deskeyList, deskeyListLen, aeskeyList, aeskeyListLen, k3kkeyList, k3kkeyListLen, cmdKDFAlgo, kdfInputLen, kdfInput, foundKeys, &result);
        if (res == PM3_EOPABORTED) {
            break;
        }

        if (pattern2b && startPattern < 0x10000) {
            if (verbose == false)
                PrintAndLogEx(NORMAL, "p" NOLF);

            aeskeyListLen = 0;
            deskeyListLen = 0;
            k3kkeyListLen = 0;
            DesFill2bPattern(deskeyList, &deskeyListLen, aeskeyList, &aeskeyListLen, k3kkeyList, &k3kkeyListLen, &startPattern);
            continue;
        }

        if (dict_filenamelen) {
            if (verbose == false)
                PrintAndLogEx(NORMAL, "d" NOLF);

            uint32_t keycnt = 0;
            res = loadFileDICTIONARYEx((char *)dict_filename, deskeyList, sizeof(deskeyList), NULL, 16, &keycnt, endFilePosition, &endFilePosition, false);
            if (res == PM3_SUCCESS && endFilePosition)
                deskeyListLen = keycnt;

            keycnt = 0;
            res = loadFileDICTIONARYEx((char *)dict_filename, aeskeyList, sizeof(aeskeyList), NULL, 16, &keycnt, endFilePosition, &endFilePosition, false);
            if (res == PM3_SUCCESS && endFilePosition)
                aeskeyListLen = keycnt;

            keycnt = 0;
            res = loadFileDICTIONARYEx((char *)dict_filename, k3kkeyList, sizeof(k3kkeyList), NULL, 16, &keycnt, endFilePosition, &endFilePosition, false);
            if (res == PM3_SUCCESS && endFilePosition)
                k3kkeyListLen = keycnt;

            continue;
        }
    }
    if (verbose == false)
        PrintAndLogEx(NORMAL, "");

    // save keys to json
    if ((jsonnamelen > 0) && result) {
        // MIFARE DESFire info
        SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT, 0, 0, NULL, 0);

        PacketResponseNG resp;
        WaitForResponse(CMD_ACK, &resp);

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

    return PM3_SUCCESS;
}

static int CmdHF14ADesList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf mfdes", "des");
}

/*
static int CmdHF14aDesNDEFRead(const char *Cmd) {
    DropFieldDesfire();

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes ndefread",
                  "Prints NFC Data Exchange Format (NDEF)",
                  "hf mfdes ndefread -> shows NDEF data\n"
                  "hf mfdes ndefread -v -> shows NDEF parsed and raw data\n"
                  "hf mfdes ndefread -a e103 -k d3f7d3f7d3f7d3f7d3f7d3f7d3f7d3f7 -> shows NDEF data with custom AID and key");

    void *argtable[] = {
        arg_param_begin,
        arg_litn("v",  "verbose",  0, 2, "show technical data"),
        arg_str0(NULL, "aid",      "<aid>", "replace default aid for NDEF"),
        arg_str0("k",  "key",      "<key>", "replace default key for NDEF"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool verbose = arg_get_lit(ctx, 1);
    bool verbose2 = arg_get_lit(ctx, 1) > 1;
    uint8_t aid[2] = {0};
    int aidlen;
    CLIGetHexWithReturn(ctx, 2, aid, &aidlen);
    uint8_t key[16] = {0};
    int keylen;
    CLIGetHexWithReturn(ctx, 3, key, &keylen);

    CLIParserFree(ctx);

    uint32_t ndefAID = 0xEEEE10;
    if (aidlen == 2) {
        ndefAID = (aid[0] << 16) | (aid[1] << 8) | aid[2];
    }

    // set default NDEF key
    uint8_t ndefkey[16] = {0};
    memcpy(ndefkey, g_mifarep_ndef_key, 16);

    // user supplied key
    if (keylen == 16) {
        memcpy(ndefkey, key, 16);
    }

    int file_ids_len = 0;

    for (int j = (int)file_ids_len - 1; j >= 0; j--) {
        PrintAndLogEx(SUCCESS, "\n\n   Fileid %d (0x%02x)", file_ids[j], file_ids[j]);

        uint8_t filesettings[20] = {0};
        uint32_t fileset_len = 0;

        int res = handler_desfire_filesettings(file_ids[j], filesettings, &fileset_len);
        if (res != PM3_SUCCESS) continue;

        int maclen = 0; // To be implemented

        if (fileset_len == 1 + 1 + 2 + 3 + maclen) {
            int filesize = (filesettings[6] << 16) + (filesettings[5] << 8) + filesettings[4];
            mfdes_data_t fdata;
            fdata.fileno = file_ids[j];
            memset(fdata.offset, 0, 3);
            memset(fdata.length, 0, 3);

            uint8_t *data = (uint8_t *)calloc(filesize, sizeof(uint8_t));
            if (data == NULL) {
                DropFieldDesfire();
                return PM3_EMALLOC;
            }

            fdata.data = data;
            res = handler_desfire_readdata(&fdata, MFDES_DATA_FILE, filesettings[1]);
            if (res == PM3_SUCCESS) {
                uint32_t len = le24toh(fdata.length);
                NDEFDecodeAndPrint(data, datalen, verbose);

            } else {
                PrintAndLogEx(ERR, "Couldn't read value. Error %d", res);
                res = handler_desfire_select_application(aid);
                if (res != PM3_SUCCESS) continue;
            }

            free(data);
        }
    }

    if (!datalen) {
        PrintAndLogEx(ERR, "no NDEF data");
        return PM3_SUCCESS;
    }

    if (verbose2) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "--- " _CYAN_("DESFire NDEF raw") " ----------------");
        print_buffer(data, datalen, 1);
    }

    PrintAndLogEx(HINT, "Try " _YELLOW_("`hf mfdes ndefread -vv`") " for more details");
    return PM3_SUCCESS;
}
*/
/*
static int CmdHF14aDesMAD(const char *Cmd) {
    DropFieldDesfire();

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes mad",
                  "Prints MIFARE Application directory (MAD)",
                  "hf mfdes mad      -> shows MAD data\n"
                  "hf mfdes mad -v   -> shows MAD parsed and raw data\n"
                  "hf mfdes mad -a e103 -k d3f7d3f7d3f7d3f7d3f7d3f7d3f7d3f7 -> shows MAD data with custom AID and key");

    void *argtable[] = {
        arg_param_begin,
        arg_litn("v",  "verbose",  0, 2, "show technical data"),
        arg_str0(NULL, "aid",      "<aid>", "replace default aid for MAD"),
        arg_str0("k",  "key",      "<key>", "replace default key for MAD"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    CLIParserFree(ctx);

    PrintAndLogEx(HINT, "Try " _YELLOW_("`hf mfdes mad -v`") " for more details");
    return PM3_SUCCESS;
}
*/

/*static int CmdTest(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    uint8_t IV[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t key[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    uint8_t encRndB[8] = {0x1A, 0xBE, 0x10, 0x8D, 0x09, 0xE0, 0x18, 0x13};
    uint8_t RndB[8] = {0};
    uint8_t RndA[8] = {0x6E, 0x6A, 0xEB, 0x86, 0x6E, 0x6A, 0xEB, 0x86};
    tdes_nxp_receive(encRndB, RndB, 8, key, IV, 2);
    uint8_t rotRndB[8] = {0};
    memcpy(rotRndB, RndB, 8);
    rol(rotRndB, 8);
    uint8_t tmp[16] = {0x00};
    uint8_t both[16] = {0x00};
    memcpy(tmp, RndA, 8);
    memcpy(tmp + 8, rotRndB, 8);
    PrintAndLogEx(INFO, "3keyenc: %s", sprint_hex(tmp, 16));
    PrintAndLogEx(SUCCESS, "  Res        : " _GREEN_("%s"), sprint_hex(IV, 8));
    tdes_nxp_send(tmp, both, 16, key, IV, 2);
    PrintAndLogEx(SUCCESS, "  Res        : " _GREEN_("%s"), sprint_hex(both, 16));
    return PM3_SUCCESS;
}
*/
static uint8_t defaultKeyNum = 0;
static enum DESFIRE_CRYPTOALGO defaultAlgoId = T_DES;
static uint8_t defaultKey[DESFIRE_MAX_KEY_SIZE] = {0};
static int defaultKdfAlgo = MFDES_KDF_ALGO_NONE;
static int defaultKdfInputLen = 0;
static uint8_t defaultKdfInput[50] = {0};
static DesfireSecureChannel defaultSecureChannel = DACEV1;
static DesfireCommandSet defaultCommSet = DCCNativeISO;
static DesfireCommunicationMode defaultCommMode = DCMPlain;

static int CmdDesGetSessionParameters(CLIParserContext *ctx, DesfireContext *dctx,
                                      uint8_t keynoid, uint8_t algoid, uint8_t keyid,
                                      uint8_t kdfid, uint8_t kdfiid,
                                      uint8_t cmodeid, uint8_t ccsetid, uint8_t schannid,
                                      uint8_t appid,
                                      int *securechannel,
                                      DesfireCommunicationMode defcommmode,
                                      uint32_t *aid) {

    uint8_t keynum = defaultKeyNum;
    int algores = defaultAlgoId;
    uint8_t key[DESFIRE_MAX_KEY_SIZE] = {0};
    memcpy(key, defaultKey, DESFIRE_MAX_KEY_SIZE);
    int kdfAlgo = defaultKdfAlgo;
    int kdfInputLen = defaultKdfInputLen;
    uint8_t kdfInput[50] = {0};
    memcpy(kdfInput, defaultKdfInput, defaultKdfInputLen);
    int commmode = defaultCommMode;
    if (defcommmode != DCMNone)
        commmode = defcommmode;
    int commset = defaultCommSet;
    int secchann = defaultSecureChannel;

    if (keynoid) {
        keynum = arg_get_int_def(ctx, keynoid, keynum);
    }

    if (algoid) {
        if (CLIGetOptionList(arg_get_str(ctx, algoid), DesfireAlgoOpts, &algores))
            return PM3_ESOFT;
    }

    if (keyid) {
        int keylen = 0;
        uint8_t keydata[200] = {0};
        if (CLIParamHexToBuf(arg_get_str(ctx, keyid), keydata, sizeof(keydata), &keylen))
            return PM3_ESOFT;
        if (keylen && keylen != desfire_get_key_length(algores)) {
            PrintAndLogEx(ERR, "%s key must have %d bytes length instead of %d.", CLIGetOptionListStr(DesfireAlgoOpts, algores), desfire_get_key_length(algores), keylen);
            return PM3_EINVARG;
        }
        if (keylen)
            memcpy(key, keydata, keylen);
    }

    if (kdfid) {
        if (CLIGetOptionList(arg_get_str(ctx, kdfid), DesfireKDFAlgoOpts, &kdfAlgo))
            return PM3_ESOFT;
    }

    if (kdfiid) {
        int datalen = kdfInputLen;
        uint8_t data[200] = {0};
        if (CLIParamHexToBuf(arg_get_str(ctx, kdfiid), data, sizeof(data), &datalen))
            return PM3_ESOFT;
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

    if (appid && aid) {
        *aid = 0x000000;
        int res = arg_get_u32_hexstr_def_nlen(ctx, appid, 0x000000, aid, 3, true);
        if (res == 0)
            return PM3_ESOFT;
        if (res == 2) {
            PrintAndLogEx(ERR, "AID length must have 3 bytes length");
            return PM3_EINVARG;
        }
    }

    DesfireSetKey(dctx, keynum, algores, key);
    DesfireSetKdf(dctx, kdfAlgo, kdfInput, kdfInputLen);
    DesfireSetCommandSet(dctx, commset);
    DesfireSetCommMode(dctx, commmode);
    if (securechannel)
        *securechannel = secchann;

    return PM3_SUCCESS;
}

static int CmdHF14ADesDefault(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes default",
                  "Set default parameters for access to desfire card.",
                  "hf mfdes default -n 0 -t des -k 0000000000000000 -f none -> save to the default parameters");

    void *argtable[] = {
        arg_param_begin,
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 1, 2, 3, 4, 5, 6, 7, 8, 0, &securechann, DCMNone, NULL);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    CLIParserFree(ctx);

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

static int CmdHF14ADesSelectApp(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes selectapp",
                  "Select application on the card. It selects app if it is a valid one or returns an error.",
                  "hf mfdes selectapp --aid 123456 -> select application 123456");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_str0(NULL, "aid",     "<app id hex>", "Application ID of application for some parameters (3 hex bytes, big endian)"),
        arg_str0(NULL, "dfname",  "<df name str>", "Application DF Name (string, max 16 chars). Selects application via ISO SELECT command"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, &securechann, DCMPlain, &appid);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }
    
    uint8_t dfname[32] = {0};
    int dfnamelen = 16;
    CLIGetStrWithReturn(ctx, 12, dfname, &dfnamelen);

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    if (dfnamelen > 0) { // dctx.cmdSet == DCCISO ?
        uint8_t resp[250] = {0};
        size_t resplen = 0;
        res = DesfireISOSelect(&dctx, (char *)dfname, resp, &resplen);
        if (res != PM3_SUCCESS) {
            DropField();
            PrintAndLogEx(FAILED, "ISO Select application " _RED_("failed"));
            return res;
        }

        if (resplen > 0)
            PrintAndLogEx(FAILED, "Application " _CYAN_("FCI template") " [%zu]%s", resplen, sprint_hex(resp, resplen));
        
        PrintAndLogEx(SUCCESS, "Application `%s` selected " _GREEN_("succesfully") " ", (char *)dfname);
    } else {    
        res = DesfireSelectAndAuthenticateEx(&dctx, securechann, appid, true, verbose);
        if (res != PM3_SUCCESS) {
            DropField();
            PrintAndLogEx(FAILED, "Select application 0x%06x " _RED_("failed") " ", appid);
            return res;
        }
        
        PrintAndLogEx(SUCCESS, "Application 0x%06x selected " _GREEN_("succesfully") " ", appid);
    }
    

    DropField();
    return res;
}

static int CmdHF14ADesBruteApps(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes bruteaid",
                  "Recover AIDs by bruteforce.\n"
                  "WARNING: This command takes a loooong time",
                  "hf mfdes bruteaid                    -> Search all apps\n"
                  "hf mfdes bruteaid -s F0000F -i 16    -> Search MAD range manually");

    void *argtable[] = {
        arg_param_begin,
        arg_strx0("s",  "start", "<hex>", "Starting App ID as hex bytes (3 bytes, big endian)"),
        arg_strx0("e",  "end",   "<hex>", "Last App ID as hex bytes (3 bytes, big endian)"),
        arg_int0("i",   "step",  "<dec>", "Increment step when bruteforcing"),
        arg_lit0("m",   "mad",   "Only bruteforce the MAD range"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 0, 0, 0, 0, 0, 0, 0, 0, 0, &securechann, DCMNone, NULL);
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
    uint32_t idIncrement = arg_get_int_def(ctx, 3, 1);
    bool mad = arg_get_lit(ctx, 4);
    
    CLIParserFree(ctx);
    
    // tru select PICC
    res = DesfireSelectAIDHex(&dctx, 0x000000, false, 0);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(FAILED, "Desfire PICC level select " _RED_("failed") ". Maybe wrong card or no card in the field.");
        return res;
    }
    
    // TODO: We need to check the tag version, EV1 should stop after 26 apps are found
    if (mad) {
        idIncrement = 0x10;
        startAid[0] = 0xF0;
        startAid[1] = 0x00;
        startAid[2] = 0x0F;
    }
    uint32_t idStart = DesfireAIDByteToUint(startAid);
    uint32_t idEnd = DesfireAIDByteToUint(endAid);
    if (idStart > idEnd) {
        PrintAndLogEx(ERR, "Start should be lower than end. start: %06x end: %06x", idStart, idEnd);
        return PM3_EINVARG;
    }
    PrintAndLogEx(INFO, "Bruteforce from %06x to %06x", idStart, idEnd);
    PrintAndLogEx(INFO, "Enumerating through all AIDs manually, this will take a while!");
    for (uint32_t id = idStart; id <= idEnd && id >= idStart; id += idIncrement) {
        if (kbd_enter_pressed()) break;
        
        int progress = ((id - idStart) * 100) / ((idEnd - idStart));
        PrintAndLogEx(INPLACE, "Progress: %d %%, current AID: %06X", progress, id);
        
        res = DesfireSelectAIDHexNoFieldOn(&dctx, id);
        
        if (res == PM3_SUCCESS) {
            printf("\33[2K\r"); // clear current line before printing
            PrintAndLogEx(SUCCESS, "Got new APPID %06X", id);
        }
    }
    
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, _GREEN_("Done"));
    DropField();
    return PM3_SUCCESS;
}

// MIAFRE DESFire Authentication
// keys:
// NR  DESC     KEYLENGHT
// ------------------------
// 1 = DES      8
// 2 = 3DES     16
// 3 = 3K 3DES  24
// 4 = AES      16
static int CmdHF14ADesAuth(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes auth",
                  "Select application on the card. It selects app if it is a valid one or returns an error.",
                  "hf mfdes auth  -n 0 -t des -k 0000000000000000 -f none -> select PICC level and authenticate with key num=0, key type=des, key=00..00 and key derivation = none\n"
                  "hf mfdes auth  -n 0 -t aes -k 00000000000000000000000000000000 -> select PICC level and authenticate with key num=0, key type=aes, key=00..00 and key derivation = none\n"
                  "hf mfdes auth  -n 0 -t des -k 0000000000000000 --save -> select PICC level and authenticate and in case of successful authentication - save channel parameters to defaults\n"
                  "hf mfdes auth --aid 123456 -> select application 123456 and authenticate via parameters from `default` command");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_str0(NULL, "aid",     "<app id hex>", "Application ID of application for some parameters (3 hex bytes, big endian)"),
        arg_lit0(NULL, "save",    "saves channels parameters to defaults if authentication succeeds"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, &securechann, DCMPlain, &appid);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    bool save = arg_get_lit(ctx, 12);

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    res = DesfireSelectAndAuthenticateEx(&dctx, securechann, appid, false, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(FAILED, "Select or authentication 0x%06x " _RED_("failed") ". Result [%d] %s", appid, res, DesfireAuthErrorToStr(res));
        return res;
    }
    
    if (appid == 0x000000)
        PrintAndLogEx(SUCCESS, "PICC selected and authenticated " _GREEN_("succesfully"));
    else
        PrintAndLogEx(SUCCESS, "Application " _CYAN_("%06x") " selected and authenticated " _GREEN_("succesfully"), appid);

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
                  "Set card configuration. WARNING! Danger zone! Needs to provide card's master key and works if not blocked by config.",
                  "hf mfdes setconfig --param 03 --data 0428 -> set parameter 03\n"
                  "hf mfdes setconfig --param 02 --data 0875778102637264 -> set parameter 02");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_str0(NULL, "aid",     "<app id hex>", "Application ID of application for some parameters (3 hex bytes, big endian)"),
        arg_str0("p",  "param",   "<HEX 1 byte>", "Parameter id (HEX 1 byte)"),
        arg_str0("d",  "data",    "<data HEX>", "Data for parameter (HEX 1..30 bytes)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, &securechann, DCMEncrypted, &appid);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint32_t paramid = 0;
    res = arg_get_u32_hexstr_def_nlen(ctx, 12, 0, &paramid, 1, true);
    if (res == 2) {
        PrintAndLogEx(ERR, "Parameter ID must have 1 bytes length");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t param[250] = {0};
    int paramlen = sizeof(param);
    CLIGetHexWithReturn(ctx, 13, param, &paramlen);
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
        if (appid == 0x000000)
            PrintAndLogEx(INFO, _CYAN_("PICC") " param ID: 0x%02x param[%d]: %s", paramid, paramlen, sprint_hex(param, paramlen));
        else
            PrintAndLogEx(INFO, _CYAN_("Application %06x") " param ID: 0x%02x param[%d]: %s", appid, paramid, paramlen, sprint_hex(param, paramlen));
    }

    res = DesfireSelectAndAuthenticate(&dctx, securechann, appid, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    DesfireSetCommMode(&dctx, DCMEncryptedPlain);
    res = DesfireSetConfiguration(&dctx, paramid, param, paramlen);
    if (res == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Set configuration 0x%02x " _GREEN_("ok") " ", paramid);
    } else {
        PrintAndLogEx(FAILED, "Set configuration 0x%02x " _RED_("failed") " ", paramid);
    }
    DesfireSetCommMode(&dctx, DCMEncrypted);

    DropField();
    return res;
}

static int CmdHF14ADesChangeKey(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes changekey",
                  "Change PICC/Application key. Needs to provide keynum/key for a valid authentication (may get from default parameters).",
                  "hf mfdes changekey --aid 123456 -> execute with default factory setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_str0(NULL, "aid",     "<app id hex>", "Application ID of application (3 hex bytes, big endian)"),
        arg_str0(NULL, "oldalgo", "<DES/2TDEA/3TDEA/AES>", "Old key crypto algorithm: DES, 2TDEA, 3TDEA, AES"),
        arg_str0(NULL, "oldkey",  "<old key>", "Old key (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_int0(NULL, "newkeyno", "<keyno>", "Key number for change"),
        arg_str0(NULL, "newalgo", "<DES/2TDEA/3TDEA/AES>", "New key crypto algorithm: DES, 2TDEA, 3TDEA, AES"),
        arg_str0(NULL, "newkey",  "<new key>", "New key (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0(NULL, "newver",  "<version hex>", "New key's version (1 hex byte)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, &securechann, DCMEncrypted, &appid);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    int oldkeytype = dctx.keyType;
    if (CLIGetOptionList(arg_get_str(ctx, 12), DesfireAlgoOpts, &oldkeytype)) {
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    uint8_t oldkey[DESFIRE_MAX_KEY_SIZE] = {0};
    uint8_t keydata[200] = {0};
    int oldkeylen = sizeof(keydata);
    CLIGetHexWithReturn(ctx, 13, keydata, &oldkeylen);
    if (oldkeylen && oldkeylen != desfire_get_key_length(oldkeytype)) {
        PrintAndLogEx(ERR, "%s old key must have %d bytes length instead of %d.", CLIGetOptionListStr(DesfireAlgoOpts, oldkeytype), desfire_get_key_length(oldkeytype), oldkeylen);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    if (oldkeylen)
        memcpy(oldkey, keydata, oldkeylen);

    uint8_t newkeynum = arg_get_int_def(ctx, 14, 0);

    int newkeytype = oldkeytype;
    if (CLIGetOptionList(arg_get_str(ctx, 15), DesfireAlgoOpts, &newkeytype)) {
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    uint8_t newkey[DESFIRE_MAX_KEY_SIZE] = {0};
    memset(keydata, 0x00, sizeof(keydata));
    int keylen = sizeof(keydata);
    CLIGetHexWithReturn(ctx, 16, keydata, &keylen);
    if (keylen && keylen != desfire_get_key_length(newkeytype)) {
        PrintAndLogEx(ERR, "%s new key must have %d bytes length instead of %d.", CLIGetOptionListStr(DesfireAlgoOpts, newkeytype), desfire_get_key_length(newkeytype), keylen);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    if (keylen)
        memcpy(newkey, keydata, keylen);

    uint32_t newkeyver = 0x100;
    res = arg_get_u32_hexstr_def_nlen(ctx, 17, 0x100, &newkeyver, 1, true);
    if (res == 2) {
        PrintAndLogEx(ERR, "Key version must have 1 bytes length");
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

    if (appid == 0x000000) {
        PrintAndLogEx(WARNING, "Changing the root aid (0x000000)");
    }

    if (appid)
        PrintAndLogEx(INFO, _CYAN_("Changing key in the application: ") _YELLOW_("%06x"), appid);
    else
        PrintAndLogEx(INFO, _CYAN_("Changing PICC key"));
    PrintAndLogEx(INFO, "auth key %d: %s [%d] %s", dctx.keyNum, CLIGetOptionListStr(DesfireAlgoOpts, dctx.keyType), desfire_get_key_length(dctx.keyType), sprint_hex(dctx.key, desfire_get_key_length(dctx.keyType)));
    PrintAndLogEx(INFO, "changing key number  " _YELLOW_("0x%02x") " (%d)", newkeynum, newkeynum);
    PrintAndLogEx(INFO, "old key: %s [%d] %s", CLIGetOptionListStr(DesfireAlgoOpts, oldkeytype), desfire_get_key_length(oldkeytype), sprint_hex(oldkey, desfire_get_key_length(oldkeytype)));
    PrintAndLogEx(INFO, "new key: %s [%d] %s", CLIGetOptionListStr(DesfireAlgoOpts, newkeytype), desfire_get_key_length(newkeytype), sprint_hex(newkey, desfire_get_key_length(newkeytype)));
    if (newkeyver < 0x100 || newkeytype == T_AES)
        PrintAndLogEx(INFO, "new key version: 0x%02x", newkeyver & 0x00);

    res = DesfireSelectAndAuthenticate(&dctx, securechann, appid, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    DesfireSetCommMode(&dctx, DCMEncryptedPlain);
    res = DesfireChangeKey(&dctx, (appid == 0x000000) && (newkeynum == 0) && (dctx.keyNum == 0), newkeynum, newkeytype, newkeyver, newkey, oldkeytype, oldkey, true);
    if (res == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Change key " _GREEN_("ok") " ");
    } else {
        PrintAndLogEx(FAILED, "Change key " _RED_("failed") " ");
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
                  "  3:   Configuration changable\n"\
                  "       0: Configuration frozen\n"\
                  "       1: Configuration changable if authenticated with AMK (default)\n"\
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
                  "  6..7: Crypto Method 00: DES/2TDEA, 01: 3TDEA, 10: AES, 11: RFU\n"\
                  "  Example:\n"\
                  "       2E = with FID, DES/2TDEA, 14 keys\n"\
                  "       6E = with FID, 3TDEA, 14 keys\n"\
                  "       AE = with FID, AES, 14 keys\n"\
                  "\n"\
                  "hf mfdes createapp --rawdata 5634122F2E4523616964313233343536 -> execute create by rawdata\n"\
                  "hf mfdes createapp --aid 123456 --fid 2345 --dfname aid123456 -> app aid, iso file id, and iso df name is specified\n"
                  "hf mfdes createapp --aid 123456 --fid 2345 --dfname aid123456 --dstalgo aes -> with algorithm for key AES");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_str0(NULL, "rawdata", "<rawdata hex>", "Rawdata that sends to command"),
        arg_str0(NULL, "aid",     "<app id hex>", "Application ID for create. Mandatory. (3 hex bytes, big endian)"),
        arg_str0(NULL, "fid",     "<file id hex>", "ISO file ID. Forbidden values: 0000 3F00, 3FFF, FFFF. (2 hex bytes, big endian). If specified - enable iso file id over all the files in the app."),
        arg_str0(NULL, "dfname",  "<df name str>", "ISO DF Name 1..16 chars string"),
        arg_str0(NULL, "ks1",     "<key settings HEX>", "Key settings 1 (HEX 1 byte). Application Master Key Settings. default 0x0f"),
        arg_str0(NULL, "ks2",     "<key settings HEX>", "Key settings 2 (HEX 1 byte). default 0x0e"),
        arg_str0(NULL, "dstalgo", "<DES/2TDEA/3TDEA/AES>",  "Application key crypt algo: DES, 2TDEA, 3TDEA, AES. default DES"),
        arg_int0(NULL, "numkeys", "<number of keys>",  "Keys count. 0x00..0x0e. default 0x0e"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 12, &securechann, DCMPlain, &appid);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint8_t rawdata[250] = {0};
    int rawdatalen = sizeof(rawdata);
    CLIGetHexWithReturn(ctx, 11, rawdata, &rawdatalen);

    uint32_t fileid = 0x0000;
    res = arg_get_u32_hexstr_def_nlen(ctx, 13, 0x0000, &fileid, 2, true);
    bool fileidpresent = (res == 1);
    if (res == 2) {
        PrintAndLogEx(ERR, "ISO file ID must have 2 bytes length");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t dfname[250] = {0};
    int dfnamelen = 16;
    CLIGetStrWithReturn(ctx, 14, dfname, &dfnamelen);

    uint32_t ks1 = 0x0f;
    res = arg_get_u32_hexstr_def_nlen(ctx, 15, 0x0f, &ks1, 1, true);
    if (res == 2) {
        PrintAndLogEx(ERR, "Key settings 1 must have 1 byte length");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t ks2 = 0x0e;
    res = arg_get_u32_hexstr_def_nlen(ctx, 16, 0x0e, &ks2, 1, true);
    bool ks2present = (res == 1);
    if (res == 2) {
        PrintAndLogEx(ERR, "Key settings 2 must have 1 byte length");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int dstalgo = T_DES;
    if (CLIGetOptionList(arg_get_str(ctx, 17), DesfireAlgoOpts, &dstalgo)) {
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    int keycount = arg_get_int_def(ctx, 18, 0x0e);

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

    res = DesfireSelectAndAuthenticate(&dctx, securechann, 0x000000, verbose);
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
            data[5] = fileid & 0xff;
            data[6] = (fileid >> 8) & 0xff;
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
            PrintAndLogEx(INFO, "FID           0x%02x%02x", data[6], data[5]);
            PrintAndLogEx(INFO, "DF Name[%02zu]  %s\n", strnlen((char *)&data[7], 16), (char *)&data[7]);
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

static int CmdHF14ADesDeleteApp(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes deleteapp",
                  "Delete application by its 3-byte AID. Master key needs to be provided. ",
                  "hf mfdes deleteapp --aid 123456 -> execute with default factory setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_str0(NULL, "aid",     "<app id hex>", "Application ID of delegated application (3 hex bytes, big endian)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, &securechann, DCMPlain, &appid);
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

    res = DesfireSelectAndAuthenticate(&dctx, securechann, appid, verbose);
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
                  "Get UID from card. Get the real UID if the random UID bit is on and get the same UID as in anticollision if not. Master key needs to be provided. ",
                  "hf mfdes getuid -> execute with default factory setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 0, &securechann, DCMEncrypted, NULL);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    res = DesfireSelectAndAuthenticate(&dctx, securechann, 0x000000, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
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

    PrintAndLogEx(SUCCESS, "Desfire UID[%zu]: %s", buflen, sprint_hex(buf, buflen));

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesFormatPICC(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes formatpicc",
                  "Format card. Can be done only if enabled in the configuration. Master key needs to be provided. ",
                  "hf mfdes formatpicc -> execute with default factory setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_str0(NULL, "aid",     "<app id hex>", "Application ID of delegated application (3 hex bytes, big endian)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, &securechann, DCMMACed, &appid);
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

    PrintAndLogEx(SUCCESS, "Desfire format: " _GREEN_("done"));

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesGetFreeMem(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes getfreemem",
                  "Get card's free memory. Can be done with ot without authentication. Master key may be provided.",
                  "hf mfdes getfreemem -> execute with default factory setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_lit0(NULL, "no-auth", "execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    bool noauth = arg_get_lit(ctx, 11);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 0, &securechann, (noauth) ? DCMPlain : DCMMACed, NULL);
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
                  "Change key settings for card level or application level. WARNING: card level changes may block the card!",
                  "hf mfdes chkeysettings -d 0f -> set picc key settings with default key/channel setup\n"\
                  "hf mfdes chkeysettings --aid 123456 -d 0f -> set app 123456 key settings with default key/channel setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_str0(NULL, "aid",     "<app id hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0("d",  "data",    "<key settings HEX>", "Key settings (HEX 1 byte)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, &securechann, DCMEncrypted, &appid);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint32_t ksett32 = 0;
    res = arg_get_u32_hexstr_def_nlen(ctx, 12, 0x0f, &ksett32, 1, false);
    if (res == 0) {
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }
    if (res == 2) {
        PrintAndLogEx(ERR, "Key settings must have 1 byte length");
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
                  "hf mfdes getkeyversions --keynum 00 -> get picc master key version with default key/channel setup\n"\
                  "hf mfdes getkeyversions --aid 123456 --keynum 0d -> get app 123456 all key versions with default key/channel setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number for authentication"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_str0(NULL, "aid",     "<app id hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "keynum",  "<key number HEX>", "Key number/count (HEX 1 byte). Default 0x00."),
        arg_str0(NULL, "keyset",  "<keyset num HEX>", "Keyset number (HEX 1 byte)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, &securechann, DCMPlain, &appid); // DCMMACed
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint32_t keynum32 = 0x00;
    res = arg_get_u32_hexstr_def_nlen(ctx, 12, 0x00, &keynum32, 1, false);
    if (res == 0) {
        keynum32 = 0x00;
    }
    if (res == 2) {
        PrintAndLogEx(ERR, "Key number must have 1 byte length");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t keysetnum32 = 0x00;
    bool keysetpresent = true;
    res = arg_get_u32_hexstr_def_nlen(ctx, 13, 0x00, &keysetnum32, 1, false);
    if (res == 0) {
        keysetpresent = false;
    }
    if (res == 2) {
        PrintAndLogEx(ERR, "Keyset number must have 1 byte length");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    if (keysetpresent && appid == 0x000000) {
        PrintAndLogEx(WARNING, "Keyset only at Application level");
        keysetpresent = false;
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
                  "hf mfdes getkeysettings --aid 123456 -> get app 123456 key settings with default key/channel setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_str0(NULL, "aid",     "<app id hex>", "Application ID (3 hex bytes, big endian)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, &securechann, DCMMACed, &appid);
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
                  "hf mfdes getaids -n 0 -t des -k 0000000000000000 -f none -> execute with default factory setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_lit0(NULL, "no-auth", "execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 11);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 0, &securechann, DCMMACed, NULL);
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
        PrintAndLogEx(INFO, "---- " _CYAN_("AID list") " ----");
        for (int i = 0; i < buflen; i += 3)
            PrintAndLogEx(INFO, "AID: %06x", DesfireAIDByteToUint(&buf[i]));
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
                  "hf mfdes getappnames -n 0 -t des -k 0000000000000000 -f none -> execute with default factory setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_lit0(NULL, "no-auth", "execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 11);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 0, &securechann, DCMMACed, NULL);
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
                  "hf mfdes getfileids -n 0 -t des -k 0000000000000000 -f none --aid 123456 -> execute with default factory setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_str0(NULL, "aid",     "<app id hex>", "Application ID (3 hex bytes, big endian)"),
        arg_lit0(NULL, "no-auth", "execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 12);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, &securechann, DCMMACed, &appid);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    res = DesfireSelectAndAuthenticateEx(&dctx, securechann, appid, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
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
        PrintAndLogEx(INFO, "There is no files in the application %06x", appid);
    }

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesGetFileISOIDs(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes getfileisoids",
                  "Get File IDs list from card. Master key needs to be provided or flag --no-auth set.",
                  "hf mfdes getfileisoids --aid 123456 -> execute with defaults from `default` command\n"
                  "hf mfdes getfileisoids -n 0 -t des -k 0000000000000000 -f none --aid 123456 -> execute with default factory setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_str0(NULL, "aid",     "<app id hex>", "Application ID (3 hex bytes, big endian)"),
        arg_lit0(NULL, "no-auth", "execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 12);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, &securechann, DCMMACed, &appid);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    res = DesfireSelectAndAuthenticateEx(&dctx, securechann, appid, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
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
            PrintAndLogEx(INFO, "File ID: %02x%02x", buf[i], buf[i + 1]);
    } else {
        PrintAndLogEx(INFO, "There is no files in the application %06x", appid);
    }

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesGetFileSettings(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes getfilesettings",
                  "Get File Settings from file from application. Master key needs to be provided or flag --no-auth set (depend on cards settings).",
                  "hf mfdes getfilesettings --aid 123456 --fid 01 -> execute with defaults from `default` command\n"
                  "hf mfdes getfilesettings -n 0 -t des -k 0000000000000000 -f none --aid 123456 --fid 01 -> execute with default factory setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_str0(NULL, "aid",     "<app id hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "fid",     "<file id hex>", "File ID (1 hex byte). default: 1"),
        arg_lit0(NULL, "no-auth", "execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 13);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, &securechann, DCMPlain, &appid);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint32_t fileid = 1;
    res = arg_get_u32_hexstr_def_nlen(ctx, 12, 1, &fileid, 1, true);
    if (res == 2) {
        PrintAndLogEx(ERR, "File ID must have 1 byte length");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    res = DesfireSelectAndAuthenticateEx(&dctx, securechann, appid, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
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

    if (verbose)
        PrintAndLogEx(INFO, "app %06x file %02x settings[%zu]: %s", appid, fileid, buflen, sprint_hex(buf, buflen));

    DesfirePrintFileSettings(buf, buflen);

    DropField();
    return PM3_SUCCESS;
}

static int DesfireCreateFileParameters(
    CLIParserContext *ctx,

    uint8_t pfileid, uint8_t pisofileid,
    uint8_t amodeid,
    uint8_t frightsid,
    uint8_t r_modeid, uint8_t w_modeid, uint8_t rw_modeid, uint8_t ch_modeid,

    uint8_t *data,
    size_t *datalen
) {
    *datalen = 0;
    int res = 0;

    uint32_t fileid = 1;
    if (pfileid) {
        res = arg_get_u32_hexstr_def_nlen(ctx, pfileid, 1, &fileid, 1, true);
        if (res == 2) {
            PrintAndLogEx(ERR, "File ID must have 1 byte length");
            return PM3_EINVARG;
        }
    }

    uint32_t isofileid = 0;
    if (pisofileid) {
        res = arg_get_u32_hexstr_def_nlen(ctx, pisofileid, 0, &isofileid, 2, true);
        if (res == 2) {
            PrintAndLogEx(ERR, "ISO file ID must have 2 bytes length");
            return PM3_EINVARG;
        }
    }

    data[0] = fileid;
    *datalen = 1;

    if (isofileid > 0) {
        data[1] = (isofileid >> 8) & 0xff;
        data[2] = isofileid & 0xff;
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
        res = arg_get_u32_hexstr_def_nlen(ctx, frightsid, 0xeeee, &frights, 2, true);
        userawfrights = (res == 1);
        if (res == 2) {
            PrintAndLogEx(ERR, "File rights must have 2 bytes length");
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
                  "hf mfdes chfilesettings -n 0 -t des -k 0000000000000000 -f none --aid 123456 --fid 01 --rawdata 00EEEE -> execute with default factory setup\n"
                  "hf mfdes chfilesettings --aid 123456 --fid 01 --rawdata 810000021f112f22 -> change file settings with additional rights for keys 1 and 2");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_str0(NULL, "aid",     "<app id hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "fid",     "<file id hex>", "File ID (1 hex byte)"),
        arg_str0(NULL, "rawdata", "<file settings HEX>", "File settings (HEX > 5 bytes). Have priority over the other settings."),
        arg_str0(NULL, "amode",   "<plain/mac/encrypt>", "File access mode: plain/mac/encrypt"),
        arg_str0(NULL, "rawrights", "<access rights HEX>", "Access rights for file (HEX 2 byte) R/W/RW/Chg, 0x0 - 0xD Key, 0xE Free, 0xF Denied"),
        arg_str0(NULL, "rrights", "<key0/../key13/free/deny>", "Read file access mode: the specified key, free, deny"),
        arg_str0(NULL, "wrights", "<key0/../key13/free/deny>", "Write file access mode: the specified key, free, deny"),
        arg_str0(NULL, "rwrights", "<key0/../key13/free/deny>", "Read/Write file access mode: the specified key, free, deny"),
        arg_str0(NULL, "chrights", "<key0/../key13/free/deny>", "Change file settings access mode: the specified key, free, deny"),
        arg_lit0(NULL, "no-auth", "execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 20);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, &securechann, DCMEncrypted, &appid);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint8_t data[250] = {0};
    uint8_t *settings = &data[1];
    size_t datalen = 0;

    res = DesfireCreateFileParameters(ctx, 12, 0, 14, 15, 16, 17, 18, 19, data, &datalen);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint8_t sdata[250] = {0};
    int sdatalen = sizeof(sdata);
    CLIGetHexWithReturn(ctx, 13, sdata, &sdatalen);
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

    res = DesfireSelectAndAuthenticateEx(&dctx, securechann, appid, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t buflen = 0;

    // check current file settings
    DesfireCommunicationMode commMode = dctx.commMode;
    DesfireSetCommMode(&dctx, DCMPlain);
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
        PrintAndLogEx(INFO, "app %06x file %02x settings[%zu]: %s", appid, fileid, datalen - 1, sprint_hex(settings, datalen - 1));

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
                  "hf mfdes createfile --aid 123456 --fid 01 --rawtype 01 --rawdata 000100EEEE000100 -> create file via sending rawdata to the card. Can be used to create any type of file. Authentication with defaults from `default` command\n"
                  "hf mfdes createfile --aid 123456 --fid 01 --amode plain --rrights free --wrights free --rwrights free --chrights key0 -> create file app=123456, file=01 and mentioned rights with defaults from `default` command\n"
                  "hf mfdes createfile -n 0 -t des -k 0000000000000000 -f none --aid 123456 --fid 01 --rawtype 00 --rawdata 00EEEE000100 -> execute with default factory setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_str0(NULL, "aid",     "<app id hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "fid",     "<file id hex>", "File ID (1 hex byte)"),
        arg_str0(NULL, "isofid",  "<iso file id hex>", "ISO File ID (2 hex bytes)"),
        arg_str0(NULL, "rawtype", "<file type HEX 1b>", "Raw file type (HEX 1 byte)"),
        arg_str0(NULL, "rawdata", "<file settings HEX>", "Raw file settings (HEX > 5 bytes)"),
        arg_str0(NULL, "amode",   "<plain/mac/encrypt>", "File access mode: plain/mac/encrypt"),
        arg_str0(NULL, "rawrights", "<access rights HEX>", "Access rights for file (HEX 2 byte) R/W/RW/Chg, 0x0 - 0xD Key, 0xE Free, 0xF Denied"),
        arg_str0(NULL, "rrights", "<key0/../key13/free/deny>", "Read file access mode: the specified key, free, deny"),
        arg_str0(NULL, "wrights", "<key0/../key13/free/deny>", "Write file access mode: the specified key, free, deny"),
        arg_str0(NULL, "rwrights", "<key0/../key13/free/deny>", "Read/Write file access mode: the specified key, free, deny"),
        arg_str0(NULL, "chrights", "<key0/../key13/free/deny>", "Change file settings access mode: the specified key, free, deny"),
        arg_lit0(NULL, "no-auth", "execute without authentication"),
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

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, &securechann, DCMPlain, &appid);
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
    res = arg_get_u32_hexstr_def_nlen(ctx, 14, 0x00, &rawftype, 1, true);
    bool useraw = (res == 1);
    if (res == 2) {
        PrintAndLogEx(ERR, "Raw file type must have 1 byte length");
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
        res = arg_get_u32_hexstr_def_nlen(ctx, 23, 0, &filesize, 3, true);
        if (res == 2) {
            PrintAndLogEx(ERR, "File size must have 3 bytes length");
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
                  "hf mfdes createvaluefile -n 0 -t des -k 0000000000000000 -f none --aid 123456 --fid 01 -> execute with default factory setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_str0(NULL, "aid",     "<app id hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "fid",     "<file id hex>", "File ID (1 hex byte)"),
        arg_str0(NULL, "amode",   "<plain/mac/encrypt>", "File access mode: plain/mac/encrypt"),
        arg_str0(NULL, "rawrights", "<access rights HEX>", "Access rights for file (HEX 2 byte) R/W/RW/Chg, 0x0 - 0xD Key, 0xE Free, 0xF Denied"),
        arg_str0(NULL, "rrights", "<key0/../key13/free/deny>", "Read file access mode: the specified key, free, deny"),
        arg_str0(NULL, "wrights", "<key0/../key13/free/deny>", "Write file access mode: the specified key, free, deny"),
        arg_str0(NULL, "rwrights", "<key0/../key13/free/deny>", "Read/Write file access mode: the specified key, free, deny"),
        arg_str0(NULL, "chrights", "<key0/../key13/free/deny>", "Change file settings access mode: the specified key, free, deny"),
        arg_lit0(NULL, "no-auth", "execute without authentication"),
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

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, &securechann, DCMPlain, &appid);
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
    res = arg_get_u32_hexstr_def_nlen(ctx, 20, 0, &lowerlimit, 4, true);
    if (res == 2) {
        PrintAndLogEx(ERR, "Lower limit value must have 4 bytes length");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t upperlimit = 0;
    res = arg_get_u32_hexstr_def_nlen(ctx, 21, 0, &upperlimit, 4, true);
    if (res == 2) {
        PrintAndLogEx(ERR, "Upper limit value must have 4 bytes length");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t value = 0;
    res = arg_get_u32_hexstr_def_nlen(ctx, 22, 0, &value, 4, true);
    if (res == 2) {
        PrintAndLogEx(ERR, "Lower limit value must have 4 bytes length");
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
                  "hf mfdes createrecordfile -n 0 -t des -k 0000000000000000 -f none --aid 123456 --fid 01 --size 000010 --maxrecord 000010 -> execute with default factory setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_str0(NULL, "aid",     "<app id hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "fid",     "<file id hex>", "File ID (1 hex byte)"),
        arg_str0(NULL, "isofid",  "<iso file id hex>", "ISO File ID (2 hex bytes)"),
        arg_str0(NULL, "amode",   "<plain/mac/encrypt>", "File access mode: plain/mac/encrypt"),
        arg_str0(NULL, "rawrights", "<access rights HEX>", "Access rights for file (HEX 2 byte) R/W/RW/Chg, 0x0 - 0xD Key, 0xE Free, 0xF Denied"),
        arg_str0(NULL, "rrights", "<key0/../key13/free/deny>", "Read file access mode: the specified key, free, deny"),
        arg_str0(NULL, "wrights", "<key0/../key13/free/deny>", "Write file access mode: the specified key, free, deny"),
        arg_str0(NULL, "rwrights", "<key0/../key13/free/deny>", "Read/Write file access mode: the specified key, free, deny"),
        arg_str0(NULL, "chrights", "<key0/../key13/free/deny>", "Change file settings access mode: the specified key, free, deny"),
        arg_lit0(NULL, "no-auth", "execute without authentication"),
        arg_str0(NULL, "size",    "<hex>", "Record size (3 hex bytes, big endian, 000001 to FFFFFF)"),
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

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, &securechann, DCMPlain, &appid);
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
    res = arg_get_u32_hexstr_def_nlen(ctx, 21, 0, &size, 3, true);
    if (res == 2) {
        PrintAndLogEx(ERR, "Record size must have 3 bytes length");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t maxrecord = 0;
    res = arg_get_u32_hexstr_def_nlen(ctx, 22, 0, &maxrecord, 3, true);
    if (res == 2) {
        PrintAndLogEx(ERR, "Max number of records must have 3 bytes length");
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
                  "hf mfdes createmacfile --aid 123456 --fid 01 --mackey --rawrights 1F30 00112233445566778899aabbccddeeff --mackeyver 01 -> create transaction mac file with parameters. Rights from default. Authentication with defaults from `default` command\n"
                  "hf mfdes createmacfile --aid 123456 --fid 01 --amode plain --rrights free --wrights deny --rwrights free --chrights key0 --mackey 00112233445566778899aabbccddeeff -> create file app=123456, file=01, with key, and mentioned rights with defaults from `default` command\n"
                  "hf mfdes createmacfile -n 0 -t des -k 0000000000000000 -f none --aid 123456 --fid 01 -> execute with default factory setup. key and keyver == 0x00..00");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",      "show APDU requests and responses"),
        arg_lit0("v",  "verbose",   "show technical data"),
        arg_int0("n",  "keyno",     "<keyno>", "Key number"),
        arg_str0("t",  "algo",      "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",       "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",       "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",      "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",     "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",     "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",    "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_str0(NULL, "aid",       "<app id hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "fid",       "<file id hex>", "File ID (1 hex byte)"),
        arg_str0(NULL, "amode",     "<plain/mac/encrypt>", "File access mode: plain/mac/encrypt"),
        arg_str0(NULL, "rawrights", "<access rights HEX>", "Access rights for file (HEX 2 byte) R/W/RW/Chg, 0x0 - 0xD Key, 0xE Free, 0xF Denied"),
        arg_str0(NULL, "rrights",   "<key0/../key13/free/deny>", "Read file access mode: the specified key, free, deny"),
        arg_str0(NULL, "wrights",   "<key0/../key13/free/deny>", "Write file access mode: the specified key, free, deny"),
        arg_str0(NULL, "rwrights",  "<key0/../key13/free/deny>", "Read/Write file access mode: the specified key, free, deny"),
        arg_str0(NULL, "chrights",  "<key0/../key13/free/deny>", "Change file settings access mode: the specified key, free, deny"),
        arg_lit0(NULL, "no-auth",   "execute without authentication"),
        arg_str0(NULL, "mackey",    "<hex>", "AES-128 key for MAC (16 hex bytes, big endian). Default 0x00..00"),
        arg_str0(NULL, "mackeyver", "<ver hex 1b>", "AES key version for MAC (1 hex byte). Default 0x00"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 19);

    uint8_t filetype = 0x05; // transaction mac file

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, &securechann, DCMEncrypted, &appid);
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

    uint8_t sdata[250] = {0};
    int sdatalen = sizeof(sdata);
    CLIGetHexWithReturn(ctx, 20, sdata, &sdatalen);
    if (sdatalen != 0 && sdatalen != 16) {
        PrintAndLogEx(ERR, "AES-128 key must be 16 bytes instead of %d.", sdatalen);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t keyver = 0x00;
    res = arg_get_u32_hexstr_def_nlen(ctx, 21, 0x00, &keyver, 1, true);
    if (res == 2) {
        PrintAndLogEx(ERR, "Key version must be 1 byte length");
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

static int CmdHF14ADesDeleteFile(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes deletefile",
                  "Delete file from application. Master key needs to be provided or flag --no-auth set (depend on cards settings).",
                  "hf mfdes deletefile --aid 123456 --fid 01 -> delete file for: app=123456, file=01 with defaults from `default` command");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_str0(NULL, "aid",     "<app id hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "fid",     "<file id hex>", "File ID (1 hex byte)"),
        arg_lit0(NULL, "no-auth", "execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 13);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, &securechann, DCMPlain, &appid);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint32_t fnum = 1;
    res = arg_get_u32_hexstr_def_nlen(ctx, 12, 1, &fnum, 1, true);
    if (res == 2) {
        PrintAndLogEx(ERR, "File ID must have 1 byte length");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    if (fnum > 0x1F) {
        PrintAndLogEx(ERR, "File number range is invalid (exp 0 - 31), got %d", fnum);
        return PM3_EINVARG;
    }

    res = DesfireSelectAndAuthenticateEx(&dctx, securechann, appid, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    res = DesfireDeleteFile(&dctx, fnum);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire DeleteFile command " _RED_("error") ". Result: %d", res);
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "File %02x in the app %06x deleted " _GREEN_("successfully"), fnum, appid);

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesValueOperations(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes value",
                  "Get File Settings from file from application. Master key needs to be provided or flag --no-auth set (depend on cards settings).",
                  "hf mfdes value --aid 123456 --fid 01  -> get value app=123456, file=01 with defaults from `default` command\n"
                  "hf mfdes value --aid 123456 --fid 01 --op credit -d 00000001 -> credit value app=123456, file=01 with defaults from `default` command\n"
                  "hf mfdes value -n 0 -t des -k 0000000000000000 -f none --aid 123456 --fid 01 -> get value with default factory setup");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_str0(NULL, "aid",     "<app id hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "fid",     "<file id hex>", "File ID (1 hex byte)"),
        arg_str0("o",  "op",      "<get/credit/limcredit/debit/clear>", "Operation: get(default)/credit/limcredit(limited credit)/debit/clear. Operation clear: get-getopt-debit to min value"),
        arg_str0("d",  "data",    "<value HEX>", "Value for operation (HEX 4 bytes)"),
        arg_lit0(NULL, "no-auth", "execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 15);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, &securechann, DCMPlain, &appid);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint32_t fileid = 1;
    res = arg_get_u32_hexstr_def_nlen(ctx, 12, 1, &fileid, 1, true);
    if (res == 2) {
        PrintAndLogEx(ERR, "File ID must have 1 byte length");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int op = MFDES_GET_VALUE;
    if (CLIGetOptionList(arg_get_str(ctx, 13), DesfireValueFileOperOpts, &op)) {
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    uint32_t value = 0;
    res = arg_get_u32_hexstr_def_nlen(ctx, 14, 0, &value, 4, true);
    if (res == 2) {
        PrintAndLogEx(ERR, "Value must have 4 byte length");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    res = DesfireSelectAndAuthenticateEx(&dctx, securechann, appid, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    if (verbose)
        PrintAndLogEx(INFO, "app %06x file %02x operation: %s value: 0x%08x", appid, fileid, CLIGetOptionListStr(DesfireValueFileOperOpts, op), value);

    if (op != 0xff) {
        res = DesfireValueFileOperations(&dctx, fileid, op, &value);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Desfire ValueFileOperations (0x%02x) command " _RED_("error") ". Result: %d", op, res);
            DropField();
            return PM3_ESOFT;
        }

        if (op == MFDES_GET_VALUE) {
            PrintAndLogEx(SUCCESS, "Value: " _GREEN_("%d (0x%08x)"), value, value);
        } else {
            res = DesfireCommitTransaction(&dctx, false, 0);
            if (res != PM3_SUCCESS) {
                PrintAndLogEx(ERR, "Desfire CommitTransaction command " _RED_("error") ". Result: %d", res);
                DropField();
                return PM3_ESOFT;
            }

            PrintAndLogEx(SUCCESS, "Value changed " _GREEN_("successfully"));
        }
    } else {
        res = DesfireValueFileOperations(&dctx, fileid, MFDES_GET_VALUE, &value);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Desfire GetValue command " _RED_("error") ". Result: %d", res);
            DropField();
            return PM3_ESOFT;
        }
        if (verbose)
            PrintAndLogEx(INFO, "current value: 0x%08x", value);

        uint8_t buf[250] = {0};
        size_t buflen = 0;

        res = DesfireGetFileSettings(&dctx, fileid, buf, &buflen);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Desfire GetFileSettings command " _RED_("error") ". Result: %d", res);
            DropField();
            return PM3_ESOFT;
        }

        if (verbose)
            PrintAndLogEx(INFO, "file settings[%zu]: %s", buflen, sprint_hex(buf, buflen));

        if (buflen < 8 || buf[0] != 0x02) {
            PrintAndLogEx(ERR, "Desfire GetFileSettings command returns " _RED_("wrong") " data");
            DropField();
            return PM3_ESOFT;
        }

        uint32_t minvalue = MemLeToUint4byte(&buf[4]);
        uint32_t delta = (value > minvalue) ? value - minvalue : 0;
        if (verbose) {
            PrintAndLogEx(INFO, "minimum value: 0x%08x", minvalue);
            PrintAndLogEx(INFO, "delta value  : 0x%08x", delta);
        }

        if (delta > 0) {
            res = DesfireValueFileOperations(&dctx, fileid, MFDES_DEBIT, &delta);
            if (res != PM3_SUCCESS) {
                PrintAndLogEx(ERR, "Desfire Debit operation " _RED_("error") ". Result: %d", res);
                DropField();
                return PM3_ESOFT;
            }

            if (verbose)
                PrintAndLogEx(INFO, "Value debited");

            res = DesfireCommitTransaction(&dctx, false, 0);
            if (res != PM3_SUCCESS) {
                PrintAndLogEx(ERR, "Desfire CommitTransaction command " _RED_("error") ". Result: %d", res);
                DropField();
                return PM3_ESOFT;
            }

            if (verbose)
                PrintAndLogEx(INFO, "Transaction commited");
        } else {
            if (verbose)
                PrintAndLogEx(INFO, "Nothing to clear. Vallue allready in the minimum level.");
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
                  "hf mfdes clearrecfile --aid 123456 --fid 01 -> clear record file for: app=123456, file=01 with defaults from `default` command");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_str0(NULL, "aid",     "<app id hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "fid",     "<file id hex>", "File ID for clearing (1 hex byte)"),
        arg_lit0(NULL, "no-auth", "execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 13);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, &securechann, DCMPlain, &appid);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint32_t fnum = 1;
    res = arg_get_u32_hexstr_def_nlen(ctx, 12, 1, &fnum, 1, true);
    if (res == 2) {
        PrintAndLogEx(ERR, "File ID must have 1 byte length");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    if (fnum > 0x1F) {
        PrintAndLogEx(ERR, "File number range is invalid (exp 0 - 31), got %d", fnum);
        return PM3_EINVARG;
    }

    res = DesfireSelectAndAuthenticateEx(&dctx, securechann, appid, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    res = DesfireClearRecordFile(&dctx, fnum);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire ClearRecordFile command " _RED_("error") ". Result: %d", res);
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "File %02x in the app %06x cleared " _GREEN_("successfully"), fnum, appid);

    DropField();
    return PM3_SUCCESS;
}


static int DesfileReadFileAndPrint(DesfireContext *dctx, uint8_t fnum, int filetype, uint32_t offset, uint32_t length, bool noauth, bool verbose) {
    int res = 0;
    // length of record for record file
    size_t reclen = 0;

    // get file settings
    if (filetype == RFTAuto) {
        FileSettingsS fsettings;

        DesfireCommunicationMode commMode = dctx->commMode;
        DesfireSetCommMode(dctx, DCMPlain);
        res = DesfireGetFileSettingsStruct(dctx, fnum, &fsettings);
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

            DesfireSetCommMode(dctx, fsettings.commMode);

            if (fsettings.fileCommMode != 0 && noauth)
                PrintAndLogEx(WARNING, "File needs communication mode `%s` but there is no authentication", CLIGetOptionListStr(DesfireCommunicationModeOpts, fsettings.commMode));

            if ((fsettings.rAccess < 0x0e && fsettings.rAccess != dctx->keyNum) || (fsettings.rwAccess < 0x0e && fsettings.rwAccess != dctx->keyNum))
                PrintAndLogEx(WARNING, "File needs to be authenticated with key 0x%02x or 0x%02x but current authentication key is 0x%02x", fsettings.rAccess, fsettings.rwAccess, dctx->keyNum);

            if (fsettings.rAccess == 0x0f && fsettings.rwAccess == 0x0f)
                PrintAndLogEx(WARNING, "File access denied. All read access rights is 0x0f.");

            if (verbose)
                PrintAndLogEx(INFO, "Got file type: %s. Option: %s. comm mode: %s",
                              GetDesfireFileType(fsettings.fileType),
                              CLIGetOptionListStr(DesfireReadFileTypeOpts, filetype),
                              CLIGetOptionListStr(DesfireCommunicationModeOpts, fsettings.commMode));
        } else {
            PrintAndLogEx(WARNING, "GetFileSettings error. Can't get file type.");
        }
    }

    PrintAndLogEx(INFO, "------------------------------- " _CYAN_("File %02x data") " -------------------------------", fnum);

    uint8_t resp[2048] = {0};
    size_t resplen = 0;

    if (filetype == RFTData) {
        res = DesfireReadFile(dctx, fnum, offset, length, resp, &resplen);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Desfire ReadFile command " _RED_("error") ". Result: %d", res);
            DropField();
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
                return PM3_ESOFT;
            }
        }

        if (resplen > 0) {
            size_t reccount = resplen / reclen;
            PrintAndLogEx(SUCCESS, "Read %zu bytes from file 0x%02x from record %d record count %zu record length %zu", resplen, fnum, offset, reccount, reclen);
            if (reccount > 1)
                PrintAndLogEx(SUCCESS, "Lastest record at the bottom.");
            for (int i = 0; i < reccount; i++) {
                if (i != 0)
                    PrintAndLogEx(SUCCESS, "Record %zu", reccount - (i + offset + 1));
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
            return PM3_ESOFT;
        }

        if (resplen > 0) {
            if (resplen != 12) {
                PrintAndLogEx(WARNING, "Read wrong %zu bytes from file 0x%02x offset %u", resplen, fnum, offset);
                print_buffer_with_offset(resp, resplen, offset, true);
            } else {
                uint32_t cnt = MemLeToUint4byte(&resp[0]);
                PrintAndLogEx(SUCCESS, "Transaction counter: %d (0x%08x)", cnt, cnt);
                PrintAndLogEx(SUCCESS, "Transaction MAC    : %s", sprint_hex(&resp[4], 8));
            }
        } else {
            PrintAndLogEx(SUCCESS, "Read operation returned no data from file %d", fnum);
        }
    }

    return PM3_SUCCESS;
}

static int CmdHF14ADesReadData(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes read",
                  "Read data from file. Key needs to be provided or flag --no-auth set (depend on file settings).",
                  "hf mfdes read --aid 123456 --fid 01 -> read file: app=123456, file=01, offset=0, all the data. use default channel settings from `default` command\n"
                  "hf mfdes read --aid 123456 --fid 01 --type record --offset 000000 --length 000001 -> read one last record from record file. use default channel settings from `default` command");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_str0(NULL, "aid",     "<app id hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "fid",     "<file id hex>", "File ID (1 hex byte)"),
        arg_lit0(NULL, "no-auth", "execute without authentication"),
        arg_str0(NULL, "type",    "<auto/data/value/record/mac>", "File Type auto/data(Standard/Backup)/value/record(linear/cyclic)/mac). Auto - check file settings and then read. Default: auto"),
        arg_str0("o", "offset",   "<hex>", "File Offset (3 hex bytes, big endian). For records - record number (0 - lastest record). Default 0"),
        arg_str0("l", "length",   "<hex>", "Length to read (3 hex bytes, big endian -> 000000 = Read all data). For records - records count (0 - all). Default 0."),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 13);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, &securechann, DCMPlain, &appid);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint32_t fnum = 1;
    res = arg_get_u32_hexstr_def_nlen(ctx, 12, 1, &fnum, 1, true);
    if (res == 2) {
        PrintAndLogEx(ERR, "File ID must have 1 byte length");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int op = RFTAuto;
    if (CLIGetOptionList(arg_get_str(ctx, 14), DesfireReadFileTypeOpts, &op)) {
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    uint32_t offset = 0;
    res = arg_get_u32_hexstr_def_nlen(ctx, 15, 0, &offset, 3, true);
    if (res == 2) {
        PrintAndLogEx(ERR, "Offset must have 3 byte length");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint32_t length = 0;
    res = arg_get_u32_hexstr_def_nlen(ctx, 16, 0, &length, 3, true);
    if (res == 2) {
        PrintAndLogEx(ERR, "Length must have 3 byte length");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    if (fnum > 0x1F) {
        PrintAndLogEx(ERR, "File number range is invalid (exp 0 - 31), got %d", fnum);
        return PM3_EINVARG;
    }

    res = DesfireSelectAndAuthenticateEx(&dctx, securechann, appid, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    res = DesfileReadFileAndPrint(&dctx, fnum, op, offset, length, noauth, verbose);

    DropField();
    return res;
}

static int CmdHF14ADesWriteData(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes write",
                  "Write data from file. Key needs to be provided or flag --no-auth set (depend on file settings).",
                  "hf mfdes write --aid 123456 --fid 01 -d 01020304 -> write file: app=123456, file=01, offset=0, get file type from card. use default channel settings from `default` command\n"
                  "hf mfdes write --aid 123456 --fid 01 --type data -d 01020304 --0ffset 000100 -> write data to std file with offset 0x100\n"
                  "hf mfdes write --aid 123456 --fid 01 --type data -d 01020304 --commit -> write data to backup file with commit\n"
                  "hf mfdes write --aid 123456 --fid 01 --type value -d 00000001 -> increment value file\n"
                  "hf mfdes write --aid 123456 --fid 01 --type value -d 00000001 --debit -> decrement value file\n"
                  "hf mfdes write --aid 123456 --fid 01 -d 01020304 -> write data to record file with `auto` type\n"
                  "hf mfdes write --aid 123456 --fid 01 --type record -d 01020304 -> write data to record file\n"
                  "hf mfdes write --aid 123456 --fid 01 --type record -d 01020304 --updaterec 0 -> update record in the record file. record 0 - lastest record.\n"
                  "hf mfdes write --aid 123456 --fid 01 --type record --offset 000000 -d 11223344 -> write record to record file. use default channel settings from `default` command");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_str0(NULL, "aid",     "<app id hex>", "Application ID (3 hex bytes, big endian)"),
        arg_str0(NULL, "fid",     "<file id hex>", "File ID (1 hex byte)"),
        arg_lit0(NULL, "no-auth", "execute without authentication"),
        arg_str0(NULL, "type",    "<auto/data/value/record/mac>", "File Type auto/data(Standard/Backup)/value/record(linear/cyclic)/mac). Auto - check file settings and then write. Default: auto"),
        arg_str0("o",  "offset",  "<hex>", "File Offset (3 hex bytes, big endian). For records - record number (0 - lastest record). Default 0"),
        arg_str0("d",  "data",    "<hex>", "data for write (data/record file), credit/debit(value file)"),
        arg_lit0(NULL, "debit",   "use for value file debit operation instead of credit"),
        arg_lit0(NULL, "commit",  "commit needs for backup file only. For the other file types and in the `auto` mode - command set it automatically."),
        arg_int0(NULL, "updaterec", "<record number dec>", "Record number for update record command. Updates record instead of write. Lastest record - 0"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 13);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, &securechann, DCMPlain, &appid);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    uint32_t fnum = 1;
    res = arg_get_u32_hexstr_def_nlen(ctx, 12, 1, &fnum, 1, true);
    if (res == 2) {
        PrintAndLogEx(ERR, "File ID must have 1 byte length");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int op = RFTAuto;
    if (CLIGetOptionList(arg_get_str(ctx, 14), DesfireReadFileTypeOpts, &op)) {
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    uint32_t offset = 0;
    res = arg_get_u32_hexstr_def_nlen(ctx, 15, 0, &offset, 3, true);
    if (res == 2) {
        PrintAndLogEx(ERR, "Offset must have 3 byte length");
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

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    if (fnum > 0x1F) {
        PrintAndLogEx(ERR, "File number range is invalid (exp 0 - 31), got %d", fnum);
        return PM3_EINVARG;
    }

    res = DesfireSelectAndAuthenticateEx(&dctx, securechann, appid, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    // get file settings
    if (op == RFTAuto) {
        FileSettingsS fsettings;

        DesfireCommunicationMode commMode = dctx.commMode;
        DesfireSetCommMode(&dctx, DCMPlain);
        res = DesfireGetFileSettingsStruct(&dctx, fnum, &fsettings);
        DesfireSetCommMode(&dctx, commMode);

        if (res == PM3_SUCCESS) {
            switch (fsettings.fileType) {
                case 0x00:
                case 0x01: {
                    op = RFTData;
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

            if (verbose)
                PrintAndLogEx(INFO, "Got file type: %s. Option: %s. comm mode: %s",
                              GetDesfireFileType(fsettings.fileType),
                              CLIGetOptionListStr(DesfireReadFileTypeOpts, op),
                              CLIGetOptionListStr(DesfireCommunicationModeOpts, fsettings.commMode));
        } else {
            PrintAndLogEx(WARNING, "GetFileSettings error. Can't get file type.");
        }
    }

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
    if (commit) {
        res = DesfireCommitTransaction(&dctx, false, 0);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Desfire CommitTransaction command " _RED_("error") ". Result: %d", res);
            DropField();
            return PM3_ESOFT;
        }

        if (verbose)
            PrintAndLogEx(INFO, "Commit " _GREEN_("OK"));
    }

    PrintAndLogEx(INFO, "Write %s file %02x " _GREEN_("success"), CLIGetOptionListStr(DesfireReadFileTypeOpts, op), fnum);

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesLsFiles(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes lsfiles",
                  "Show file list. Master key needs to be provided or flag --no-auth set (depend on cards settings).",
                  "hf mfdes lsfiles --aid 123456 -> show file list for: app=123456 with defaults from `default` command");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_str0(NULL, "aid",     "<app id hex>", "Application ID (3 hex bytes, big endian)"),
        arg_lit0(NULL, "no-auth", "execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 12);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, &securechann, DCMPlain, &appid);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    res = DesfireSelectAndAuthenticateEx(&dctx, securechann, appid, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    FileListS FileList = {0};
    size_t filescount = 0;
    bool isopresent = false;
    res = DesfireFillFileList(&dctx, FileList, &filescount, &isopresent);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    if (filescount == 0) {
        PrintAndLogEx(INFO, "There is no files in the application %06x", appid);
        DropField();
        return res;
    }

    PrintAndLogEx(INFO, "---------------------------- " _CYAN_("File list") " -----------------------(r w rw ch)-----");
    for (int i = 0; i < filescount; i++) {
        PrintAndLogEx(SUCCESS, "ID: " _GREEN_("%02x ") NOLF, FileList[i].fileNum);
        if (isopresent) {
            if (FileList[i].fileISONum != 0)
                PrintAndLogEx(NORMAL, "ISO ID: " _CYAN_("%04x ") NOLF, FileList[i].fileISONum);
            else
                PrintAndLogEx(NORMAL, "ISO ID: " _YELLOW_("n/a  ") NOLF);
        }

        DesfirePrintFileSettingsOneLine(&FileList[i].fileSettings);
    }

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesDump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdes dump",
                  "For each application show fil list and then file content. Key needs to be provided for authentication or flag --no-auth set (depend on cards settings).",
                  "hf mfdes dump --aid 123456 -> show file dump for: app=123456 with channel defaults from `default` command");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyno",   "<keyno>", "Key number"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>",  "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<Key>",   "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),
        arg_str0("f",  "kdf",     "<none/AN10922/gallagher>",   "Key Derivation Function (KDF): None, AN10922, Gallagher"),
        arg_str0("i",  "kdfi",    "<kdfi>",  "KDF input (HEX 1-31 bytes)"),
        arg_str0("m",  "cmode",   "<plain/mac/encrypt>", "Communicaton mode: plain/mac/encrypt"),
        arg_str0("c",  "ccset",   "<native/niso/iso>", "Communicaton command set: native/niso/iso"),
        arg_str0("s",  "schann",  "<d40/ev1/ev2>", "Secure channel: d40/ev1/ev2"),
        arg_str0(NULL, "aid",     "<app id hex>", "Application ID (3 hex bytes, big endian)"),
        arg_lit0(NULL, "no-auth", "execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool noauth = arg_get_lit(ctx, 12);

    DesfireContext dctx;
    int securechann = defaultSecureChannel;
    uint32_t appid = 0x000000;
    int res = CmdDesGetSessionParameters(ctx, &dctx, 3, 4, 5, 6, 7, 8, 9, 10, 11, &securechann, DCMPlain, &appid);
    if (res) {
        CLIParserFree(ctx);
        return res;
    }

    SetAPDULogging(APDULogging);
    CLIParserFree(ctx);

    res = DesfireSelectAndAuthenticateEx(&dctx, securechann, appid, noauth, verbose);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    FileListS FileList = {0};
    size_t filescount = 0;
    bool isopresent = false;
    res = DesfireFillFileList(&dctx, FileList, &filescount, &isopresent);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "Application " _CYAN_("%06x") " have " _GREEN_("%zu") " files", appid, filescount);

    uint8_t aid[3] = {0};
    DesfireAIDUintToByte(appid, aid);
    if ((aid[2] >> 4) == 0xF) {
        uint16_t short_aid = ((aid[2] & 0xF) << 12) | (aid[1] << 4) | (aid[0] >> 4);
        PrintAndLogEx(SUCCESS, "  AID mapped to MIFARE Classic AID (MAD): " _YELLOW_("%02X"), short_aid);
        PrintAndLogEx(SUCCESS, "  MAD AID Cluster  0x%02X      : " _YELLOW_("%s"), short_aid >> 8, cluster_to_text(short_aid >> 8));
        MADDFDecodeAndPrint(short_aid);
    } else {
        AIDDFDecodeAndPrint(aid);
    }

    if (filescount == 0) {
        PrintAndLogEx(INFO, "There is no files in the application %06x", appid);
        DropField();
        return res;
    }

    res = PM3_SUCCESS;
    for (int i = 0; i < filescount; i++) {
        if (res != PM3_SUCCESS) {
            DesfireSetCommMode(&dctx, DCMPlain);
            res = DesfireSelectAndAuthenticateEx(&dctx, securechann, appid, noauth, verbose);
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

        res = DesfileReadFileAndPrint(&dctx, FileList[i].fileNum, RFTAuto, 0, 0, noauth, verbose);
    }

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesTest(const char *Cmd) {
    DesfireTest(true);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",             CmdHelp,                     AlwaysAvailable, "This help"},
    {"-----------",      CmdHelp,                     IfPm3Iso14443a,  "---------------------- " _CYAN_("general") " ----------------------"},
    {"default",          CmdHF14ADesDefault,          IfPm3Iso14443a,  "Set defaults for all the commands"},
    {"auth",             CmdHF14ADesAuth,             IfPm3Iso14443a,  "MIFARE DesFire Authentication"},
    {"chk",              CmdHF14aDesChk,              IfPm3Iso14443a,  "[old]Check keys"},
    {"enum",             CmdHF14ADesEnumApplications, IfPm3Iso14443a,  "[old]Tries enumerate all applications"},
    {"formatpicc",       CmdHF14ADesFormatPICC,       IfPm3Iso14443a,  "Format PICC"},
    {"freemem",          CmdHF14ADesGetFreeMem,       IfPm3Iso14443a,  "Get free memory size"},
    {"getuid",           CmdHF14ADesGetUID,           IfPm3Iso14443a,  "Get uid from card"},
    {"setconfig",        CmdHF14ADesSetConfiguration, IfPm3Iso14443a,  "Set card configuration"},
    {"info",             CmdHF14ADesInfo,             IfPm3Iso14443a,  "[old]Tag information"},
    {"list",             CmdHF14ADesList,             AlwaysAvailable, "List DESFire (ISO 14443A) history"},
//    {"ndefread",             CmdHF14aDesNDEFRead,             IfPm3Iso14443a,  "Prints NDEF records from card"},
//    {"mad",             CmdHF14aDesMAD,             IfPm3Iso14443a,  "Prints MAD records from card"},
    {"-----------",      CmdHelp,                     IfPm3Iso14443a,  "------------------------ " _CYAN_("Keys") " -----------------------"},
    {"changekey",        CmdHF14ADesChangeKey,        IfPm3Iso14443a,  "Change Key"},
    {"chkeysettings",    CmdHF14ADesChKeySettings,    IfPm3Iso14443a,  "Change Key Settings"},
    {"getkeysettings",   CmdHF14ADesGetKeySettings,   IfPm3Iso14443a,  "Get Key Settings"},
    {"getkeyversions",   CmdHF14ADesGetKeyVersions,   IfPm3Iso14443a,  "Get Key Versions"},
    {"-----------",      CmdHelp,                     IfPm3Iso14443a,  "-------------------- " _CYAN_("Applications") " -------------------"},
    {"bruteaid",         CmdHF14ADesBruteApps,        IfPm3Iso14443a,  "Recover AIDs by bruteforce"},
    {"createapp",        CmdHF14ADesCreateApp,        IfPm3Iso14443a,  "Create Application"},
    {"deleteapp",        CmdHF14ADesDeleteApp,        IfPm3Iso14443a,  "Delete Application"},
    {"selectapp",        CmdHF14ADesSelectApp,        IfPm3Iso14443a,  "Select Application ID"},
    {"getaids",          CmdHF14ADesGetAIDs,          IfPm3Iso14443a,  "Get Application IDs list"},
    {"getappnames",      CmdHF14ADesGetAppNames,      IfPm3Iso14443a,  "Get Applications list"},
    {"-----------",      CmdHelp,                     IfPm3Iso14443a,  "----------------------- " _CYAN_("Files") " -----------------------"},
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
    {"-----------",      CmdHelp,                     IfPm3Iso14443a,  "----------------------- " _CYAN_("System") " -----------------------"},
    {"test",             CmdHF14ADesTest,             AlwaysAvailable, "Test crypto"},
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

/*
    ToDo:

    ISO/IEC 7816 Cmds
    -----------------
    'A4' Select
    'B0' Read Binary
    'D6' Update Binary
    'B2' Read Records
    'E2' Append Records
    '84' Get Challenge
    '88' Internal Authenticate
    '82' External Authenticate
*/
