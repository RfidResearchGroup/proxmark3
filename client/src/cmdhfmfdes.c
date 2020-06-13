//-----------------------------------------------------------------------------
// Copyright (C) 2014 Iceman
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
#include "mbedtls/aes.h"
#include "crypto/libpcrypto.h"
#include "protocols.h"
#include "cmdtrace.h"
#include "cliparser.h"
#include "emv/apduinfo.h"   // APDU manipulation / errorcodes
#include "emv/emvcore.h"    // APDU logging
#include "util_posix.h"     // msleep
#include "mifare/desfire_crypto.h"
#include "crapto1/crapto1.h"
#include "fileutils.h"

#define MAX_KEY_LEN        24
#define MAX_KEYS_LIST_LEN  1024

struct desfire_key default_key = {0};

uint8_t desdefaultkeys[3][8]= {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, //Official
                               {0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47},
                               {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07}};

uint8_t aesdefaultkeys[5][16]= {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, //Official, TRF7970A
                                {0x79, 0x70, 0x25, 0x53, 0x79, 0x70, 0x25, 0x53, 0x79, 0x70, 0x25, 0x53, 0x79, 0x70, 0x25, 0x53}, // TRF7970A
                                {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, // TRF7970A
                                {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
                                {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f}};

uint8_t k3kdefaultkeys[1][24]= {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}};

struct desfire_tag mf_state={.session_key=NULL,.authentication_scheme=AS_LEGACY,.authenticated_key_no=NOT_YET_AUTHENTICATED,.crypto_buffer=NULL,.crypto_buffer_size=0,.selected_application=0};
static desfiretag_t tag=&mf_state;

typedef struct {
    uint8_t mode;
    uint8_t algo;
    uint8_t keyno;
    uint8_t keylen;
    uint8_t key[24];
} PACKED mfdes_authinput_t;

static mfdes_authinput_t currentauth[0xF]={{.keyno=-1},{.keyno=-1},{.keyno=-1},{.keyno=-1},{.keyno=-1},{.keyno=-1},{.keyno=-1},{.keyno=-1},{.keyno=-1},{.keyno=-1},{.keyno=-1},{.keyno=-1},{.keyno=-1},{.keyno=-1},{.keyno=-1}};

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

#define status(x) ( ((uint16_t)(0x91<<8)) + (uint16_t)x )

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

static char *cluster_to_text(uint8_t cluster) {
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
} nxp_cardtype_t;

typedef struct {
    uint8_t aid[3];
    uint8_t fid[2];
    uint8_t name[16];
} dfname_t;

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

    uint16_t usize = 1 << ((fsize >> 1) + 1);
    uint16_t lsize = 1 << (fsize >> 1);

    // is  LSB set?
    if (fsize & 1)
        sprintf(retStr, "0x%02X (" _YELLOW_("%d - %d bytes") ")", fsize, usize, lsize);
    else
        sprintf(retStr, "0x%02X (" _YELLOW_("%d bytes") ")", fsize, lsize);
    return buf;
}

static char *getProtocolStr(uint8_t id, bool hw) {

    static char buf[50] = {0x00};
    char *retStr = buf;

    if (id == 0x04) {
        sprintf(retStr, "0x%02X (" _YELLOW_("ISO 14443-3 MIFARE, 14443-4") ")", id);
    } else if (id == 0x05) {
        if (hw)
            sprintf(retStr, "0x%02X (" _YELLOW_("ISO 14443-2, 14443-3") ")", id);
        else
            sprintf(retStr, "0x%02X (" _YELLOW_("ISO 14443-3, 14443-4") ")", id);
    } else {
        sprintf(retStr, "0x%02X (" _YELLOW_("Unknown") ")", id);
    }
    return buf;
}

static char *getVersionStr(uint8_t major, uint8_t minor) {

    static char buf[40] = {0x00};
    char *retStr = buf;

    if (major == 0x00)
        sprintf(retStr, "%x.%x (" _YELLOW_("DESFire MF3ICD40") ")", major, minor);
    else if (major == 0x01 && minor == 0x00)
        sprintf(retStr, "%x.%x (" _YELLOW_("DESFire EV1") ")", major, minor);
    else if (major == 0x12 && minor == 0x00)
        sprintf(retStr, "%x.%x (" _YELLOW_("DESFire EV2") ")", major, minor);
//    else if (major == 0x13 && minor == 0x00)
//        sprintf(retStr, "%x.%x (" _YELLOW_("DESFire EV3") ")", major, minor);
    else if (major == 0x30 && minor == 0x00)
        sprintf(retStr, "%x.%x (" _YELLOW_("DESFire Light") ")", major, minor);
    else
        sprintf(retStr, "%x.%x (" _YELLOW_("Unknown") ")", major, minor);
    return buf;
}


int DESFIRESendApdu(bool activate_field, bool leavefield_on, sAPDU apdu, uint8_t *result, int max_result_len, int *result_len, uint16_t *sw) {

    *result_len = 0;
    if (sw) *sw = 0;

    uint16_t isw = 0;
    int res = 0;

    if (activate_field) {
        DropField();
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

    res = ExchangeAPDU14a(data, datalen, activate_field, leavefield_on, result, max_result_len, result_len);
    if (res) {
        return res;
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

static char *getstatus(uint16_t *sw) {
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
                return "Attempted to read/write data from/to beyong the file's/record's limit";

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

static char *GetErrorString(int res, uint16_t *sw) {
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
        case PM3_EWRONGANSVER:
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

static int send_desfire_cmd(sAPDU *apdu, bool select, uint8_t *dest, int *recv_len, uint16_t *sw, int splitbysize, bool readalldata) {
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
    int resplen = 0;
    int pos = 0;
    int i = 1;
    int res = DESFIRESendApdu(select, true, *apdu, data, sizeof(data), &resplen, sw);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "%s", GetErrorString(res, sw));
        DropField();
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
            PrintAndLogEx(DEBUG, "%s", GetErrorString(res, sw));
            DropField();
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
//  if (major == 0x13 && minor == 0x00)
//        return DESFIRE_EV3;
    if (major == 0x30 && minor == 0x00)
        return DESFIRE_LIGHT;
    if (major == 0x11 &&  minor == 0x00)
        return PLUS_EV1;

    return DESFIRE_UNKNOWN;
}

int handler_desfire_auth(mfdes_authinput_t *payload, mfdes_auth_res_t *rpayload) {
    // 3 different way to authenticate   AUTH (CRC16) , AUTH_ISO (CRC32) , AUTH_AES (CRC32)
    // 4 different crypto arg1   DES, 3DES, 3K3DES, AES
    // 3 different communication modes,  PLAIN,MAC,CRYPTO
    tag->authenticated_key_no=NOT_YET_AUTHENTICATED;
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

    uint8_t subcommand = MFDES_AUTHENTICATE;
    tag->authentication_scheme=AS_LEGACY;

    if (payload->mode == MFDES_AUTH_AES)
    {
        subcommand = MFDES_AUTHENTICATE_AES;
        tag->authentication_scheme=AS_NEW;
    }
    else if (payload->mode == MFDES_AUTH_ISO) {
        subcommand = MFDES_AUTHENTICATE_ISO;
        tag->authentication_scheme = AS_NEW;
    }

    int recv_len = 0;
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
    } else if (payload->mode == MFDES_AUTH_PICC) {
        /*cmd[0] = AUTHENTICATE;
        cmd[1] = payload->keyno;
        len = DesfireAPDU(cmd, 2, resp);
         */
    }

    if (!recv_len) {
        return 2;
    }

    if (sw != status(MFDES_ADDITIONAL_FRAME)) {
        return 3;
    }

    int expectedlen = 8;
    if (payload->algo == MFDES_ALGO_AES || payload->algo == MFDES_ALGO_3K3DES) {
        expectedlen = 16;
    }

    if (recv_len != expectedlen) {
        return 4;
    }
    int rndlen = recv_len;

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
        PrintAndLogEx(INFO, "encRndB: %s", sprint_hex(encRndB, 8));
        PrintAndLogEx(INFO, "RndB: %s", sprint_hex(RndB, 8));
    }

    // - Rotate RndB by 8 bits
    memcpy(rotRndB, RndB, rndlen);
    rol(rotRndB, rndlen);

    uint8_t encRndA[16] = {0x00};

    // - Encrypt our response
    if (payload->mode == MFDES_AUTH_DES || payload->mode == MFDES_AUTH_PICC) {
        des_decrypt(encRndA, RndA, key->data);
        memcpy(both, encRndA, rndlen);

        for (int x = 0; x < rndlen; x++) {
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
                PrintAndLogEx(INFO, "rotRndB: %s", sprint_hex(rotRndB, rndlen));
                PrintAndLogEx(INFO, "Both: %s", sprint_hex(tmp, 16));
            }
            tdes_nxp_send(tmp, both, 16, key->data, IV, 2);
            if (g_debugMode > 1) {
                PrintAndLogEx(INFO, "EncBoth: %s", sprint_hex(both, 16));
            }
        } else if (payload->algo == MFDES_ALGO_3K3DES) {
            uint8_t tmp[32] = {0x00};
            memcpy(tmp, RndA, rndlen);
            memcpy(tmp + rndlen, rotRndB, rndlen);
            if (g_debugMode > 1) {
                PrintAndLogEx(INFO, "rotRndB: %s", sprint_hex(rotRndB, rndlen));
                PrintAndLogEx(INFO, "Both3k3: %s", sprint_hex(tmp, 32));
            }
            tdes_nxp_send(tmp, both, 32, key->data, IV, 3);
            if (g_debugMode > 1) {
                PrintAndLogEx(INFO, "EncBoth: %s", sprint_hex(both, 32));
            }
        }
    } else if (payload->mode == MFDES_AUTH_AES) {
        uint8_t tmp[32] = {0x00};
        memcpy(tmp, RndA, rndlen);
        memcpy(tmp + rndlen, rotRndB, rndlen);
        if (g_debugMode > 1) {
            PrintAndLogEx(INFO, "rotRndB: %s", sprint_hex(rotRndB, rndlen));
            PrintAndLogEx(INFO, "Both3k3: %s", sprint_hex(tmp, 32));
        }
        if (payload->algo == MFDES_ALGO_AES) {
            if (mbedtls_aes_setkey_enc(&ctx, key->data, 128) != 0) {
                return 6;
            }
            mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, 32, IV, tmp, both);
            if (g_debugMode > 1) {
                PrintAndLogEx(INFO, "EncBoth: %s", sprint_hex(both, 32));
            }
        }
    }

    int bothlen = 16;
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
    tag->session_key=&default_key;
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
    for (int x = 0; x < rndlen; x++) {
        if (RndA[x] != encRndA[x]) {
            if (g_debugMode > 1) {
                PrintAndLogEx(INFO, "Expected_RndA : %s", sprint_hex(RndA, rndlen));
                PrintAndLogEx(INFO, "Generated_RndA : %s", sprint_hex(encRndA, rndlen));
            }
            return 11;
        }
    }

    rpayload->sessionkeylen = payload->keylen;
    memcpy(rpayload->sessionkey, tag->session_key->data, rpayload->sessionkeylen);
    memset(tag->ivect, 0, MAX_CRYPTO_BLOCK_SIZE);
    tag->authenticated_key_no=payload->keyno;
    if (tag->authentication_scheme==AS_NEW) {
        cmac_generate_subkeys(tag->session_key);
    }
    return PM3_SUCCESS;
}

void AuthToError(int error) {
    switch (error) {
        case 1:
            PrintAndLogEx(SUCCESS, "Sending auth command failed");
            break;
        case 2:
            PrintAndLogEx(ERR, "Authentication failed. No data received");
            break;
        case 3:
            PrintAndLogEx(ERR, "Authentication failed. Invalid key number.");
            break;
        case 4:
            PrintAndLogEx(ERR, "Authentication failed. Length of answer %d doesn't match algo length %d.");
            break;
        case 5:
            PrintAndLogEx(ERR, "mbedtls_aes_setkey_dec failed");
            break;
        case 6:
            PrintAndLogEx(ERR, "mbedtls_aes_setkey_enc failed");
            break;
        case 7:
            PrintAndLogEx(SUCCESS, "Sending auth command failed");
            break;
        case 8:
            PrintAndLogEx(ERR, "Authentication failed. Card timeout.");
            break;
        case 9:
            PrintAndLogEx(ERR, "Authentication failed.");
            break;
        case 10:
            PrintAndLogEx(ERR, "mbedtls_aes_setkey_dec failed");
            break;
        case 11:
            PrintAndLogEx(ERR, "Authentication failed. Cannot verify Session Key.");
            break;
        default:
            break;
    }
}


// -- test if card supports 0x0A
static int test_desfire_authenticate() {
    uint8_t data[] = {0x00};
    sAPDU apdu = {0x90, MFDES_AUTHENTICATE, 0x00, 0x00, 0x01, data}; // 0x0A, KEY 0
    int recv_len = 0;
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, true, NULL, &recv_len, &sw, 0, false);
    if (res == PM3_SUCCESS)
        if (sw == status(MFDES_ADDITIONAL_FRAME)) {
            DropField();
            return res;
        }
    return res;
}

// -- test if card supports 0x1A
static int test_desfire_authenticate_iso() {
    uint8_t data[] = {0x00};
    sAPDU apdu = {0x90, MFDES_AUTHENTICATE_ISO, 0x00, 0x00, 0x01, data}; // 0x1A, KEY 0
    int recv_len = 0;
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, true, NULL, &recv_len, &sw, 0, false);
    if (res == PM3_SUCCESS)
        if (sw == status(MFDES_ADDITIONAL_FRAME)) {
            DropField();
            return res;
        }
    return res;
}

// -- test if card supports 0xAA
static int test_desfire_authenticate_aes() {
    uint8_t data[] = {0x00};
    sAPDU apdu = {0x90, MFDES_AUTHENTICATE_AES, 0x00, 0x00, 0x01, data}; // 0xAA, KEY 0
    int recv_len = 0;
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, true, NULL, &recv_len, &sw, 0, false);
    if (res == PM3_SUCCESS)
        if (sw == status(MFDES_ADDITIONAL_FRAME)) {
            DropField();
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

    sAPDU apdu = {0x90, MFDES_GET_FREE_MEMORY, 0x00, 0x00, 0x00, NULL}; // 0x6E
    *free_mem = 0;
    int recv_len = 0;
    uint16_t sw = 0;
    uint8_t fmem[4] = {0};

    size_t plen=apdu.Lc;
    uint8_t *p=mifare_cryto_preprocess_data(tag,(uint8_t *)apdu.data,&plen,0,MDCM_PLAIN|CMAC_COMMAND);
    apdu.Lc=(uint8_t)plen;
    apdu.data=p;

    int res = send_desfire_cmd(&apdu, true, fmem, &recv_len, &sw, 0, true);

    if (res != PM3_SUCCESS)
        return res;

    size_t dlen=recv_len;
    p=mifare_cryto_postprocess_data(tag, apdu.data, &dlen, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);

    if (sw != status(MFDES_S_OPERATION_OK))
        return PM3_ESOFT;

    *free_mem = le24toh(fmem);
    return res;
}

static int mifare_desfire_change_key(uint8_t key_no, uint8_t* new_key, int new_algo, uint8_t* old_key, int old_algo, int aes_version)
{
    key_no &= 0x0F;

    /*
     * Because new crypto methods can be setup only at application creation,
     * changing the card master key to one of them require a key_no tweak.
     */
    if (0x000000 == tag->selected_application) {
        switch (new_algo) {
            case MFDES_ALGO_DES:
                break;
            case MFDES_ALGO_3K3DES:
                key_no |= 0x40;
                break;
            case MFDES_ALGO_AES:
                key_no |= 0x80;
                break;
        }
    }

    uint8_t data[24*4] = {key_no};
    sAPDU apdu = {0x90, MFDES_CHANGE_KEY, 0x00, 0x00, 0x01, data}; // 0xC4

    int new_key_length;
    switch (new_algo) {
        case MFDES_ALGO_DES:
        case MFDES_ALGO_AES:
            new_key_length = 16;
            break;
        case MFDES_ALGO_3K3DES:
            new_key_length = 24;
            break;
    }

    int __cmd_n=0;
    memcpy(data + __cmd_n + 1, new_key, new_key_length);

    if ((tag->authenticated_key_no & 0x0f) != (key_no & 0x0f)) {
        if (old_key) {
            for (int n = 0; n < new_key_length; n++) {
                data[__cmd_n + 1 + n] ^= old_key[n];
            }
        }
    }

    __cmd_n += new_key_length;

    if (new_algo == MFDES_ALGO_AES){
        data[__cmd_n+1] = aes_version;
        __cmd_n+=1;
    }

    if ((tag->authenticated_key_no & 0x0f) != (key_no & 0x0f)) {
        switch (tag->authentication_scheme) {
            case AS_LEGACY:
                iso14443a_crc_append(data + 1, __cmd_n);
                __cmd_n += 2;
                iso14443a_crc(new_key, new_key_length, data + __cmd_n);
                __cmd_n += 2;
                break;
            case AS_NEW:
                desfire_crc32_append(data+1, __cmd_n);
                __cmd_n += 4;

                desfire_crc32(new_key, new_key_length, data + __cmd_n);
                __cmd_n += 4;
                break;
        }
    } else {
        switch (tag->authentication_scheme) {
            case AS_LEGACY:
                iso14443a_crc_append(data + 1, __cmd_n);
                __cmd_n += 2;
                break;
            case AS_NEW:
                desfire_crc32_append(data, __cmd_n);
                __cmd_n += 4;
                break;
        }
    }

    uint8_t *p = mifare_cryto_preprocess_data(tag, data+1, (size_t*)&__cmd_n, 0, MDCM_ENCIPHERED | ENC_COMMAND | NO_CRC);
    apdu.Lc=(uint8_t)__cmd_n+1;
    apdu.data=p;

    int recv_len = 0;
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, true, NULL, &recv_len, &sw, 0, true);

    if (res != PM3_SUCCESS)
    {
            PrintAndLogEx(WARNING, _RED_("   Can't change key -> %s"),GetErrorString(res, &sw));
            DropField();
            return res;
    }

    size_t sn = recv_len;
    p = mifare_cryto_postprocess_data(tag, data, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);

    if (!p)
        return PM3_ESOFT;

    /*
     * If we changed the current authenticated key, we are not authenticated
     * anymore.
     */
    if (key_no == tag->authenticated_key_no) {
        free(tag->session_key);
        tag->session_key = NULL;
    }

    return 0;
}

// --- GET SIGNATURE
static int desfire_print_signature(uint8_t *uid, uint8_t *signature, size_t signature_len, nxp_cardtype_t card_type) {
    (void)card_type;

    if (uid == NULL) {
        PrintAndLogEx(DEBUG, "UID=NULL");
        return PM3_EINVARG;
    }
    if (signature == NULL) {
        PrintAndLogEx(DEBUG, "SIGNATURE=NULL");
        return PM3_EINVARG;
    }
    // DESFire Ev3  - wanted
    // ref:  MIFARE Desfire Originality Signature Validation

#define PUBLIC_DESFIRE_ECDA_KEYLEN 57
    const ecdsa_publickey_t nxp_desfire_public_keys[] = {
        {"NTAG424DNA, DESFire EV2", "048A9B380AF2EE1B98DC417FECC263F8449C7625CECE82D9B916C992DA209D68422B81EC20B65A66B5102A61596AF3379200599316A00A1410"},
        {"NTAG413DNA, DESFire EV1", "04BB5D514F7050025C7D0F397310360EEC91EAF792E96FC7E0F496CB4E669D414F877B7B27901FE67C2E3B33CD39D1C797715189AC951C2ADD"},
        {"DESFire EV2",             "04B304DC4C615F5326FE9383DDEC9AA892DF3A57FA7FFB3276192BC0EAA252ED45A865E3B093A3D0DCE5BE29E92F1392CE7DE321E3E5C52B3A"},
        {"NTAG424DNA, NTAG424DNATT, DESFire Light EV2", "04B304DC4C615F5326FE9383DDEC9AA892DF3A57FA7FFB3276192BC0EAA252ED45A865E3B093A3D0DCE5BE29E92F1392CE7DE321E3E5C52B3B"},
        {"DESFire Light",       "040E98E117AAA36457F43173DC920A8757267F44CE4EC5ADD3C54075571AEBBF7B942A9774A1D94AD02572427E5AE0A2DD36591B1FB34FCF3D"},
        {"Mifare Plus EV1",         "044409ADC42F91A8394066BA83D872FB1D16803734E911170412DDF8BAD1A4DADFD0416291AFE1C748253925DA39A5F39A1C557FFACD34C62E"}
    };

    uint8_t i;
    int res;
    bool is_valid = false;

    for (i = 0; i < ARRAYLEN(nxp_desfire_public_keys); i++) {

        int dl = 0;
        uint8_t key[PUBLIC_DESFIRE_ECDA_KEYLEN];
        param_gethex_to_eol(nxp_desfire_public_keys[i].value, 0, key, PUBLIC_DESFIRE_ECDA_KEYLEN, &dl);

        res = ecdsa_signature_r_s_verify(MBEDTLS_ECP_DP_SECP224R1, key, uid, 7, signature, signature_len, false);
        is_valid = (res == 0);
        if (is_valid)
            break;
    }
    if (is_valid == false) {
        PrintAndLogEx(SUCCESS, "Signature verification " _RED_("failed"));
        return PM3_ESOFT;
    }

//    PrintAndLogEx(NORMAL, "");
//    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Signature"));
    PrintAndLogEx(INFO, " IC signature public key name: " _GREEN_("%s"), nxp_desfire_public_keys[i].desc);
    PrintAndLogEx(INFO, "IC signature public key value: %.32s", nxp_desfire_public_keys[i].value);
    PrintAndLogEx(INFO, "                             : %.32s", nxp_desfire_public_keys[i].value + 16);
    PrintAndLogEx(INFO, "                             : %.32s", nxp_desfire_public_keys[i].value + 32);
    PrintAndLogEx(INFO, "                             : %.32s", nxp_desfire_public_keys[i].value + 48);
    PrintAndLogEx(INFO, "    Elliptic curve parameters: NID_secp224r1");
    PrintAndLogEx(INFO, "             TAG IC Signature: %s", sprint_hex_inrow(signature, 16));
    PrintAndLogEx(INFO, "                             : %s", sprint_hex_inrow(signature + 16, 16));
    PrintAndLogEx(INFO, "                             : %s", sprint_hex_inrow(signature + 32, 16));
    PrintAndLogEx(INFO, "                             : %s", sprint_hex_inrow(signature + 48, signature_len - 48));
    PrintAndLogEx(SUCCESS, "           Signature verified: " _GREEN_("successful"));
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

    int recv_len = 0;
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
    DropField();
    return res;
}

// --- KEY SETTING
static int desfire_print_keysetting(uint8_t key_settings, mifare_des_authalgo_t algo) {

    PrintAndLogEx(SUCCESS, "  AID Key settings           : 0x%02x", key_settings);
    // 2 MSB denotes
    const char *str =                 "  Max key number and type    : %d, " _YELLOW_("%s");

    if (algo==MFDES_ALGO_DES) PrintAndLogEx(SUCCESS, str, "(3)DES");
    else if (algo==MFDES_ALGO_AES) PrintAndLogEx(SUCCESS, str, "AES");
    else if (algo==MFDES_ALGO_3K3DES) PrintAndLogEx(SUCCESS, str, "3K3DES");

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
            PrintAndLogEx(SUCCESS, "  -- Authentication with the specified key is necessary to change any key.\nA change key and a PICC master key (CMK) can only be changed after authentication with the master key.\nFor keys other then the master or change key, an authentication with the same key is needed.");
            break;
    }

    PrintAndLogEx(SUCCESS, "   [0x08] Configuration changeable       : %s", (key_settings & (1 << 3)) ? _GREEN_("YES") : "NO");
    PrintAndLogEx(SUCCESS, "   [0x04] AMK required for create/delete : %s", (key_settings & (1 << 2)) ? "NO" : "YES");
    PrintAndLogEx(SUCCESS, "   [0x02] Directory list access with AMK : %s", (key_settings & (1 << 1)) ? "NO" : "YES");
    PrintAndLogEx(SUCCESS, "   [0x01] AMK is changeable              : %s", (key_settings & (1 << 0)) ? _GREEN_("YES") : "NO");
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

    int recv_len = 0;
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
    int recv_len = 0;
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, false, num_versions, &recv_len, &sw, 0, true);

    if (res != PM3_SUCCESS)
        return res;

    if (sw != status(MFDES_S_OPERATION_OK))
        return PM3_ESOFT;

    return res;
}

static int handler_desfire_getuid(uint8_t *uid) {
    if (uid == NULL) {
        PrintAndLogEx(DEBUG, "UID=NULL");
        return PM3_EINVARG;
    }
    sAPDU apdu = {0x90, MFDES_GET_UID, 0x00, 0x00, 0x00, NULL}; //0x51
    int recv_len = 0;
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, false, uid, &recv_len, &sw, 0, true);

    if (res != PM3_SUCCESS)
        return res;

    if (sw != status(MFDES_S_OPERATION_OK))
        return PM3_ESOFT;

    return res;
}

static int handler_desfire_commit_transaction() {
    sAPDU apdu = {0x90, MFDES_COMMIT_TRANSACTION, 0x00, 0x00, 0x00, NULL}; //0xC7
    int recv_len = 0;
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, false, NULL, &recv_len, &sw, 0, true);

    if (res != PM3_SUCCESS)
        return res;

    if (sw != status(MFDES_S_OPERATION_OK))
        return PM3_ESOFT;

    return res;
}

/*static int handler_desfire_abort_transaction() {
    sAPDU apdu = {0x90, MFDES_ABORT_TRANSACTION, 0x00, 0x00, 0x00, NULL}; //0xA7
    int recv_len = 0;
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, false, NULL, &recv_len, &sw, 0, true);

    if (res != PM3_SUCCESS)
        return res;

    if (sw != status(MFDES_S_OPERATION_OK))
        return PM3_ESOFT;

    return res;
}*/

// --- GET APPIDS
static int handler_desfire_appids(uint8_t *dest, uint8_t *app_ids_len) {
    if (dest == NULL) {
        PrintAndLogEx(DEBUG, "DEST=NULL");
        return PM3_EINVARG;
    }
    if (app_ids_len == NULL) {
        PrintAndLogEx(DEBUG, "APP_IDS_LEN=NULL");
        return PM3_EINVARG;
    }

    sAPDU apdu = {0x90, MFDES_GET_APPLICATION_IDS, 0x00, 0x00, 0x00, NULL}; //0x6a
    int recv_len = 0;
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, true, dest, &recv_len, &sw, 0, true);

    if (res != PM3_SUCCESS)
        return res;

    if (sw != status(MFDES_S_OPERATION_OK))
        return PM3_ESOFT;

    *app_ids_len = (uint8_t)recv_len & 0xFF;
    return res;
}

// --- GET DF NAMES
static int handler_desfire_dfnames(dfname_t *dest, uint8_t *dfname_count) {
    *dfname_count=0;
    if (g_debugMode > 1) {
        if (dest == NULL) PrintAndLogEx(ERR, "DEST=NULL");
        if (dfname_count == NULL) PrintAndLogEx(ERR, "DFNAME_COUNT=NULL");
    }
    if (dest == NULL || dfname_count == NULL) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_GET_DF_NAMES, 0x00, 0x00, 0x00, NULL}; //0x6d
    int recv_len = 0;
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, true, (uint8_t *)dest, &recv_len, &sw, sizeof(dfname_t), true);
    if (res != PM3_SUCCESS){
        if (sw == status(MFDES_E_ILLEGAL_COMMAND_CODE)) return PM3_SUCCESS;
        return res;
    }

    if (sw != status(MFDES_S_OPERATION_OK))
        return PM3_ESOFT;
    *dfname_count = recv_len;
    return res;
}

static int handler_desfire_select_application(uint8_t *aid) {
    if (g_debugMode > 1) {
        if (aid == NULL) PrintAndLogEx(ERR, "AID=NULL");
    }
    if (aid == NULL) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_SELECT_APPLICATION, 0x00, 0x00, 0x03, aid}; //0x5a
    int recv_len = 0;
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, true, NULL, &recv_len, &sw, sizeof(dfname_t), true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't select AID 0x%X -> %s"), (aid[2] << 16) + (aid[1] << 8) + aid[0], GetErrorString(res, &sw));
        DropField();
        return res;
    }
    memcpy(&tag->selected_application,aid,3);
    return PM3_SUCCESS;
}

static int key_setting_to_algo(uint8_t aid[3],uint8_t* key_setting, mifare_des_authalgo_t* algo){
    int res = handler_desfire_select_application(aid);
    if (res != PM3_SUCCESS) return res;

    uint8_t num_keys = 0;
    res = handler_desfire_getkeysettings(key_setting, &num_keys);
    if (res==PM3_SUCCESS){
        switch (num_keys >> 6){
            case 0:
                *algo=MFDES_ALGO_DES;
                break;
            case 1:
                *algo=MFDES_ALGO_3K3DES;
                break;
            case 2:
                *algo=MFDES_ALGO_AES;
                break;
        }
    }
    return res;
}

static int handler_desfire_fileids(uint8_t *dest, uint8_t *file_ids_len) {
    if (g_debugMode > 1) {
        if (dest == NULL) PrintAndLogEx(ERR, "DEST=NULL");
        if (file_ids_len == NULL) PrintAndLogEx(ERR, "FILE_IDS_LEN=NULL");
    }
    if (dest == NULL || file_ids_len == NULL) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_GET_FILE_IDS, 0x00, 0x00, 0x00, NULL}; //0x6f
    int recv_len = 0;
    uint16_t sw = 0;
    *file_ids_len = 0;
    int res = send_desfire_cmd(&apdu, false, dest, &recv_len, &sw, 0, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't get file ids -> %s"), GetErrorString(res, &sw));
        DropField();
        return res;
    }
    *file_ids_len = recv_len;
    return res;
}

// none, verified
static int handler_desfire_filesettings(uint8_t file_id, uint8_t *dest, int *destlen) {
    if (g_debugMode > 1) {
        if (dest == NULL) PrintAndLogEx(ERR, "DEST=NULL");
        if (destlen == NULL) PrintAndLogEx(ERR, "DESTLEN=NULL");
    }
    if (dest == NULL || destlen == NULL) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_GET_FILE_SETTINGS, 0x00, 0x00, 0x01, &file_id}; // 0xF5
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, false, dest, destlen, &sw, 0, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't get file settings -> %s"), GetErrorString(res, &sw));
        DropField();
        return res;
    }
    return res;
}

typedef struct {
    uint8_t aid[3];
    uint8_t keysetting1;
    uint8_t keysetting2;
    uint8_t fid[2];
    uint8_t name[16];
} aidhdr_t;

static int handler_desfire_createapp(aidhdr_t *aidhdr, bool usename, bool usefid) {
    if (aidhdr == NULL) return PM3_EINVARG;

    sAPDU apdu = {0x90, MFDES_CREATE_APPLICATION, 0x00, 0x00, sizeof(aidhdr_t), (uint8_t *)aidhdr}; // 0xCA

    if (!usename) {
        apdu.Lc = apdu.Lc - 16;
    }
    if (!usefid) {
        apdu.Lc = apdu.Lc - 2;
    }
    uint8_t *data = NULL;
    if (!usefid && usename) {
        data = (uint8_t *)malloc(apdu.Lc);
        apdu.data = data;
        memcpy(data, aidhdr, apdu.Lc);
        memcpy(&data[3 + 1 + 1], aidhdr->name, 16);
    }

    uint16_t sw = 0;
    int recvlen = 0;
    int res = send_desfire_cmd(&apdu, false, NULL, &recvlen, &sw, 0, true);
    if (data != NULL) free(data);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't create aid -> %s"), GetErrorString(res, &sw));
        DropField();
        return res;
    }

    return res;
}

static int handler_desfire_deleteapp(uint8_t *aid) {
    if (aid == NULL) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_DELETE_APPLICATION, 0x00, 0x00, 3, aid}; // 0xDA
    uint16_t sw = 0;
    int recvlen = 0;
    int res = send_desfire_cmd(&apdu, false, NULL, &recvlen, &sw, 0, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't delete aid -> %s"), GetErrorString(res, &sw));
        DropField();
        return res;
    }
    return res;
}

static int handler_desfire_credit(mfdes_value_t *value, uint8_t cs) {
    sAPDU apdu = {0x90, MFDES_CREDIT, 0x00, 0x00, 1 + 4, (uint8_t *)value}; // 0x0C
    uint16_t sw = 0;
    int recvlen = 0;

    size_t plen=apdu.Lc;
    uint8_t *p=mifare_cryto_preprocess_data(tag,(uint8_t *)apdu.data,&plen,0,cs | MAC_COMMAND | CMAC_COMMAND | ENC_COMMAND);
    apdu.Lc=(uint8_t)plen;
    apdu.data=p;

    int res = send_desfire_cmd(&apdu, false, NULL, &recvlen, &sw, 0, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't credit value -> %s"), GetErrorString(res, &sw));
        DropField();
        return res;
    }
    return res;
}

static int handler_desfire_limitedcredit(mfdes_value_t *value, uint8_t cs) {
    sAPDU apdu = {0x90, MFDES_LIMITED_CREDIT, 0x00, 0x00, 1 + 4, (uint8_t *)value}; // 0x1C
    uint16_t sw = 0;
    int recvlen = 0;

    size_t plen=apdu.Lc;
    uint8_t *p=mifare_cryto_preprocess_data(tag,(uint8_t *)apdu.data,&plen,0,cs | MAC_COMMAND | CMAC_COMMAND | ENC_COMMAND);
    apdu.Lc=(uint8_t)plen;
    apdu.data=p;

    int res = send_desfire_cmd(&apdu, false, NULL, &recvlen, &sw, 0, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't credit limited value -> %s"), GetErrorString(res, &sw));
        DropField();
        return res;
    }
    return res;
}

static int handler_desfire_debit(mfdes_value_t *value, uint8_t cs) {
    sAPDU apdu = {0x90, MFDES_DEBIT, 0x00, 0x00, 1 + 4, (uint8_t *)value}; // 0xDC
    uint16_t sw = 0;
    int recvlen = 0;

    size_t plen=apdu.Lc;
    uint8_t *p=mifare_cryto_preprocess_data(tag,(uint8_t *)apdu.data,&plen,0,cs | MAC_COMMAND | CMAC_COMMAND | ENC_COMMAND);
    apdu.Lc=(uint8_t)plen;
    apdu.data=p;

    int res = send_desfire_cmd(&apdu, false, NULL, &recvlen, &sw, 0, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't debit value -> %s"), GetErrorString(res, &sw));
        DropField();
        return res;
    }
    return res;
}

static int handler_desfire_readdata(mfdes_data_t *data, MFDES_FILE_TYPE_T type, uint8_t cs) {
    if (data->fileno > 0x1F) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_READ_DATA, 0x00, 0x00, 1 + 3 + 3, (uint8_t *)data}; // 0xBD
    if (type == MFDES_RECORD_FILE) apdu.INS = MFDES_READ_RECORDS; //0xBB

    uint16_t sw = 0;
    int resplen = 0;

    size_t plen=apdu.Lc;
    uint8_t *p=mifare_cryto_preprocess_data(tag,(uint8_t *)data,&plen,0,MDCM_PLAIN|CMAC_COMMAND);
    apdu.Lc=(uint8_t)plen;
    apdu.data=p;

    int res = send_desfire_cmd(&apdu, false, data->data, &resplen, &sw, 0, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't read data -> %s"), GetErrorString(res, &sw));
        DropField();
        return res;
    }

    size_t dlen=resplen;
    p=mifare_cryto_postprocess_data(tag, data->data, &dlen, cs|CMAC_COMMAND|CMAC_VERIFY|MAC_VERIFY);
    if (dlen!=-1) resplen=dlen;
    memcpy(data->length, &resplen, 3);


    return res;
}


static int handler_desfire_getvalue(mfdes_value_t *value, int *resplen, uint8_t cs) {
    if (value->fileno > 0x1F) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_GET_VALUE, 0x00, 0x00, 0x01, &value->fileno}; // 0xBD
    uint16_t sw = 0;
    *resplen = 0;

    size_t plen=apdu.Lc;
    uint8_t *p=mifare_cryto_preprocess_data(tag,(uint8_t *)apdu.data,&plen,0,MDCM_PLAIN|CMAC_COMMAND);
    apdu.Lc=(uint8_t)plen;
    apdu.data=p;

    int res = send_desfire_cmd(&apdu, false, value->value, resplen, &sw, 0, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't read data -> %s"), GetErrorString(res, &sw));
        DropField();
        return res;
    }
    size_t dlen=(size_t)resplen;
    p=mifare_cryto_postprocess_data(tag, value->value, &dlen, cs|CMAC_COMMAND|CMAC_VERIFY|MAC_VERIFY);
    return res;
}

static int handler_desfire_writedata(mfdes_data_t *data, MFDES_FILE_TYPE_T type, uint8_t cs) {
    /*                  LC  FN  OF  OF  OF  LN  LN  LN  DD  DD  DD
        90  3d  00  00  16  01  00  00  00  0f  00  00  00  0f  20  00  3b  00  34  04  06  e1  04  0f  fe  00  00  00
        90  3d  00  00  09  02  00  00  00  02  00  00  00  00  00
    */

    if (data->fileno > 0x1F) return PM3_EINVARG;
    int datatowrite = le24toh(data->length);
    int offset = le24toh(data->offset);
    int datasize;
    int pos = 0;
    int recvlen = 0;
    int res = PM3_SUCCESS;
    uint16_t sw = 0;
    uint8_t tmp[59] = {0};
    mfdes_data_t sdata;
    sAPDU apdu = {0x90, MFDES_WRITE_DATA, 0x00, 0x00, 0, (uint8_t *) &sdata}; // 0x3D
    tmp[0] = data->fileno;
    apdu.data = tmp;
    if (type == MFDES_RECORD_FILE) apdu.INS = MFDES_WRITE_RECORD;

    while (datatowrite > 0) {
        if (datatowrite > 52)
            datasize = 52;
        else
            datasize = datatowrite;

        tmp[1] = offset & 0xFF;
        tmp[2] = (offset >> 8) & 0xFF;
        tmp[3] = (offset >> 16) & 0xFF;
        tmp[4] = datasize & 0xFF;
        tmp[5] = (datasize >> 8) & 0xFF;
        tmp[6] = (datasize >> 16) & 0xFF;


        size_t plen=datasize;
        uint8_t *p=mifare_cryto_preprocess_data(tag,(uint8_t *)&data->data[pos],&plen,0,cs | MAC_COMMAND | CMAC_COMMAND | ENC_COMMAND);
        if (plen!=-1) datasize=(uint8_t)plen;
        memcpy(&tmp[7], p, datasize);

        apdu.Lc = datasize + 1 + 3 + 3;


        res = send_desfire_cmd(&apdu, false, NULL, &recvlen, &sw, 0, true);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, _RED_("   Can't write data -> %s"), GetErrorString(res, &sw));
            DropField();
            return res;
        }
        offset += datasize;
        datatowrite -= datasize;
        pos += datasize;
    }
    if (type == MFDES_RECORD_FILE) {
        if (handler_desfire_commit_transaction() != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, _RED_("   Can't commit transaction -> %s"), GetErrorString(res, &sw));
            DropField();
            return res;
        }
    }
    return res;
}


static int handler_desfire_deletefile(uint8_t fileno) {
    if (fileno > 0x1F) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_DELETE_FILE, 0x00, 0x00, 1, &fileno}; // 0xDF
    uint16_t sw = 0;
    int recvlen = 0;
    int res = send_desfire_cmd(&apdu, false, NULL, &recvlen, &sw, 0, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't delete file -> %s"), GetErrorString(res, &sw));
        DropField();
        return res;
    }
    return res;
}

static int handler_desfire_clearrecordfile(uint8_t fileno) {
    if (fileno > 0x1F) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_CLEAR_RECORD_FILE, 0x00, 0x00, 1, &fileno}; // 0xEB
    uint16_t sw = 0;
    int recvlen = 0;
    int res = send_desfire_cmd(&apdu, false, NULL, &recvlen, &sw, 0, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't clear record file -> %s"), GetErrorString(res, &sw));
        DropField();
        return res;
    } else {
        res = handler_desfire_commit_transaction();
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, _RED_("   Can't commit transaction -> %s"), GetErrorString(res, &sw));
            DropField();
            return res;
        }
    }
    return res;
}

static int handler_desfire_create_value_file(mfdes_value_file_t *value) {
    if (value->fileno > 0x1F) return PM3_EINVARG;

    sAPDU apdu = {0x90, MFDES_CREATE_VALUE_FILE, 0x00, 0x00, sizeof(mfdes_value_file_t), (uint8_t *)value}; // 0xCc

    uint16_t sw = 0;
    int recvlen = 0;
    int res = send_desfire_cmd(&apdu, false, NULL, &recvlen, &sw, 0, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't create value -> %s"), GetErrorString(res, &sw));
        DropField();
        return res;
    }
    return res;
}

static int handler_desfire_create_std_file(mfdes_file_t *file) {
    if (file->fileno > 0x1F) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_CREATE_STD_DATA_FILE, 0x00, 0x00, sizeof(mfdes_file_t), (uint8_t *)file}; // 0xCD

    uint16_t sw = 0;
    int recvlen = 0;
    int res = send_desfire_cmd(&apdu, false, NULL, &recvlen, &sw, 0, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't create file -> %s"), GetErrorString(res, &sw));
        DropField();
        return res;
    }
    return res;
}

static int handler_desfire_create_linearrecordfile(mfdes_linear_t *file) {
    if (file->fileno > 0x1F) return PM3_EINVARG;
    if (memcmp(file->recordsize, "\x00\x00\x00", 3) == 0) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_CREATE_LINEAR_RECORD_FILE, 0x00, 0x00, sizeof(mfdes_linear_t), (uint8_t *)file}; // 0xC1

    uint16_t sw = 0;
    int recvlen = 0;
    int res = send_desfire_cmd(&apdu, false, NULL, &recvlen, &sw, 0, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't create linear record file -> %s"), GetErrorString(res, &sw));
        DropField();
        return res;
    }
    return res;
}

static int handler_desfire_create_cyclicrecordfile(mfdes_linear_t *file) {
    if (memcmp(file->recordsize, "\x00\x00\x00", 3) == 0) return PM3_EINVARG;
    if (file->fileno > 0x1F) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_CREATE_CYCLIC_RECORD_FILE, 0x00, 0x00, sizeof(mfdes_linear_t), (uint8_t *)file}; // 0xC0

    uint16_t sw = 0;
    int recvlen = 0;
    int res = send_desfire_cmd(&apdu, false, NULL, &recvlen, &sw, 0, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't create cyclic record file -> %s"), GetErrorString(res, &sw));
        DropField();
        return res;
    }
    return res;
}

static int handler_desfire_create_backup_file(mfdes_file_t *file) {
    if (file->fileno > 0x1F) return PM3_EINVARG;

    sAPDU apdu = {0x90, MFDES_CREATE_BACKUP_DATA_FILE, 0x00, 0x00, sizeof(mfdes_file_t), (uint8_t *)file}; // 0xCB

    uint16_t sw = 0;
    int recvlen = 0;
    int res = send_desfire_cmd(&apdu, false, NULL, &recvlen, &sw, 0, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't create backup file -> %s"), GetErrorString(res, &sw));
        DropField();
        return res;
    }
    return res;
}

int getKeySettings(uint8_t *aid) {
    if (aid == NULL) return PM3_EINVARG;

    int res = 0;
    if (memcmp(aid, "\x00\x00\x00", 3) == 0) {

        // CARD MASTER KEY
        //PrintAndLogEx(INFO, "--- " _CYAN_("CMK - PICC, Card Master Key settings"));

        // KEY Settings - AMK
        uint8_t num_keys = 0;
        uint8_t key_setting = 0;
        mifare_des_authalgo_t algo;
        res=key_setting_to_algo(aid,&key_setting,&algo);

        if (res == PM3_SUCCESS) {
            // number of Master keys (0x01)
            PrintAndLogEx(SUCCESS, "   Number of Masterkeys                  : " _YELLOW_("%u"), (num_keys & 0x3F));

            PrintAndLogEx(SUCCESS, "   [0x08] Configuration changeable       : %s", (key_setting & (1 << 3)) ? _GREEN_("YES") : "NO");
            PrintAndLogEx(SUCCESS, "   [0x04] CMK required for create/delete : %s", (key_setting & (1 << 2)) ? _GREEN_("YES") : "NO");
            PrintAndLogEx(SUCCESS, "   [0x02] Directory list access with CMK : %s", (key_setting & (1 << 1)) ? _GREEN_("YES") : "NO");
            PrintAndLogEx(SUCCESS, "   [0x01] CMK is changeable              : %s", (key_setting & (1 << 0)) ? _GREEN_("YES") : "NO");
        } else {
            PrintAndLogEx(WARNING, _RED_("   Can't read Application Master key settings"));
        }

        const char *str = "   Operation of PICC master key          : " _YELLOW_("%s");

        if (algo==MFDES_ALGO_DES) PrintAndLogEx(SUCCESS, str, "(3)DES");
        else if (algo==MFDES_ALGO_AES) PrintAndLogEx(SUCCESS, str, "AES");
        else if (algo==MFDES_ALGO_3K3DES) PrintAndLogEx(SUCCESS, str, "3K3DES");

        uint8_t cmk_num_versions = 0;
        if (handler_desfire_keyversion(0, &cmk_num_versions) == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "   PICC Master key Version               : " _YELLOW_("%d (0x%02x)"), cmk_num_versions, cmk_num_versions);
            PrintAndLogEx(INFO, "   ----------------------------------------------------------");
        }

        // Authentication tests
        res = test_desfire_authenticate();
        if (res == PM3_ETIMEOUT) return res;
        PrintAndLogEx(SUCCESS, "   [0x0A] Authenticate      : %s", (res == PM3_SUCCESS) ? _YELLOW_("YES") : "NO");

        res = test_desfire_authenticate_iso();
        if (res == PM3_ETIMEOUT) return res;
        PrintAndLogEx(SUCCESS, "   [0x1A] Authenticate ISO  : %s", (res == PM3_SUCCESS) ? _YELLOW_("YES") : "NO");

        res = test_desfire_authenticate_aes();
        if (res == PM3_ETIMEOUT) return res;
        PrintAndLogEx(SUCCESS, "   [0xAA] Authenticate AES  : %s", (res == PM3_SUCCESS) ? _YELLOW_("YES") : "NO");

        PrintAndLogEx(INFO, "-------------------------------------------------------------");

    } else {

        // AID - APPLICATION MASTER KEYS
        //PrintAndLogEx(SUCCESS, "--- " _CYAN_("AMK - Application Master Key settings"));
        res = handler_desfire_select_application(aid);
        if (res != PM3_SUCCESS) return res;

        // KEY Settings - AMK
        uint8_t num_keys = 0;
        uint8_t key_setting = 0;
        mifare_des_authalgo_t algo;
        res=key_setting_to_algo(aid,&key_setting,&algo);
        if (res == PM3_SUCCESS) {
            desfire_print_keysetting(key_setting, algo);
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

    DropField();
    return PM3_SUCCESS;
}

static void swap32(uint8_t *data) {
    if (data == NULL) return;
    uint8_t tmp = data[0];
    data[0] = data[3];
    data[3] = tmp;
    tmp = data[2];
    data[2] = data[1];
    data[1] = tmp;
};

static void swap24(uint8_t *data) {
    if (data == NULL) return;
    uint8_t tmp = data[0];
    data[0] = data[2];
    data[2] = tmp;
};

static void swap16(uint8_t *data) {
    if (data == NULL) return;
    uint8_t tmp = data[0];
    data[0] = data[1];
    data[1] = tmp;
};

int desfire_authenticate(int cmdAuthMode, int cmdAuthAlgo, uint8_t* aid, uint8_t* key, int cmdKeyNo, mfdes_auth_res_t* rpayload)
{
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

    int keylength=16;

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

    // KEY
    int res = handler_desfire_select_application(aid);
    if (res != PM3_SUCCESS) return res;

    if (memcmp(aid, "\x00\x00\x00", 3) != 0) {
        uint8_t file_ids[33] = {0};
        uint8_t file_ids_len = 0;
        res = handler_desfire_fileids(file_ids, &file_ids_len);
        if (res != PM3_SUCCESS) return res;
    }

    mfdes_authinput_t payload;
    payload.keylen = keylength;
    memcpy(payload.key, key, keylength);
    payload.mode = cmdAuthMode;
    payload.algo = cmdAuthAlgo;
    payload.keyno = cmdKeyNo;

    int error = handler_desfire_auth(&payload, rpayload);
    if (error == PM3_SUCCESS) {
        memcpy(&currentauth[payload.keyno], &payload, sizeof(mfdes_authinput_t));
    }
    return error;
}

static int CmdHF14ADesGetUID(const char *Cmd) {
    (void)Cmd;

    uint8_t uid[16]={0};
    int res = handler_desfire_getuid(uid);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(ERR, "Error on getting uid.");
        return res;
    }
    PrintAndLogEx(SUCCESS, "    UID: " _GREEN_("%s"), sprint_hex(uid, sizeof(uid)));
    return res;
}

static int CmdHF14ADesSelectApp(const char *Cmd) {
    CLIParserInit("hf mfdes selectaid",
                  "Select Application ID",
                  "Usage:\n\thf mfdes selectaid -a 123456\n"
    );

    void *argtable[] = {
            arg_param_begin,
            arg_strx0("aA",  "aid",    "<aid>", "App ID to select as hex bytes (3 bytes,big endian)"),
            arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, false);
    int aidlength = 3;
    uint8_t aid[3] = {0};
    CLIGetHexWithReturn(1, aid, &aidlength);
    CLIParserFree();

    swap24(aid);

    if (aidlength != 3) {
        PrintAndLogEx(ERR, "AID must have 3 bytes length");
        return PM3_EINVARG;
    }

    int res = handler_desfire_select_application(aid);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(ERR, "Error on selecting aid.");
        return res;
    }
    PrintAndLogEx(SUCCESS, "Successfully selected aid.");
    return res;
}


static int CmdHF14ADesCreateApp(const char *Cmd) {
    CLIParserInit("hf mfdes createaid",
                  "Create Application ID",
                  "Usage:\n\thf mfdes createaid -a 123456 -f 1111 -k 0E -l 2E -n Test\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_strx0("aA",  "aid",    "<aid>", "App ID to create as hex bytes ("),
        arg_strx0("fF",  "fid",    "<fid>", "File ID to create (optional)"),
        arg_strx0("kK",  "keysetting1",    "<keysetting1>", "Key Setting 1 (Application Master Key Settings)"),
        arg_strx0("lL",  "keysetting2",    "<keysetting2>", "Key Setting 2"),
        arg_str0("nN",  "name",    "<name>", "App ISO-4 Name (optional)"),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, false);
    /* KeySetting 1 (AMK Setting):
       0:   Allow change master key
       1:   Free Directory list access without master key
            0: AMK auth needed for GetFileSettings and GetKeySettings
            1: No AMK auth needed for GetFileIDs, GetISOFileIDs, GetFileSettings, GetKeySettings
       2:   Free create/delete without master key
            0:  CreateFile/DeleteFile only with AMK auth
            1:  CreateFile/DeleteFile always
       3:   Configuration changable
            0: Configuration frozen
            1: Configuration changable if authenticated with AMK (default)
       4-7: ChangeKey Access Rights
            0: Application master key needed (default)
            0x1..0xD: Auth with specific key needed to change any key
            0xE: Auth with the key to be changed (same KeyNo) is necessary to change a key
            0xF: All Keys within this application are frozen

    */
    /* KeySetting 2:
       0..3: Number of keys stored within the application (max. 14 keys)
       4:    RFU
       5:    Use of 2 byte ISO FID, 0: No, 1: Yes
       6..7: Crypto Method 00: DES/3DES, 01: 3K3DES, 10: AES
       Example:
            2E = FID, DES, 14 keys
            6E = FID, 3K3DES, 14 keys
            AE = FID, AES, 14 keys
    */
    int aidlength = 3;
    int fidlength = 2;
    uint8_t aid[3] = {0};
    uint8_t fid[2] = {0};
    uint8_t name[16] = {0};
    uint8_t keysetting1 = 0;
    uint8_t keysetting2 = 0;
    int keylen1 = 1;
    int keylen2 = 1;
    int namelen = 16;
    CLIGetHexWithReturn(1, aid, &aidlength);
    CLIGetHexWithReturn(2, fid, &fidlength);
    CLIGetHexWithReturn(3, &keysetting1, &keylen1);
    CLIGetHexWithReturn(4, &keysetting2, &keylen2);
    CLIGetStrWithReturn(5, name, &namelen);
    CLIParserFree();

    swap24(aid);
    swap16(fid);

    if (aidlength != 3) {
        PrintAndLogEx(ERR, "AID must have 3 bytes length");
        return PM3_EINVARG;
    }

    if (fidlength != 2 && fidlength!=0) {
        PrintAndLogEx(ERR, "FID must have 2 bytes length");
        return PM3_EINVARG;
    }

    bool usefid = (fidlength != 0);

    if (keylen1 != 1) {
        PrintAndLogEx(ERR, "Keysetting1 must have 1 byte length");
        return PM3_EINVARG;
    }

    if (keylen2 != 1) {
        PrintAndLogEx(ERR, "Keysetting2 must have 1 byte length");
        return PM3_EINVARG;
    }

    if (namelen > 16) {
        PrintAndLogEx(ERR, "Name has a max. of 16 bytes length");
        return PM3_EINVARG;
    }
    bool usename = true;
    if (namelen == 0) usename = false;

    //90 ca 00 00 0e 3cb849 09 22 10e1 d27600 00850101 00
    /*char name[]="Test";
    uint8_t aid[]={0x12,0x34,0x56};
    uint8_t fid[]={0x11,0x22};
    uint8_t keysetting1=0xEE;
    uint8_t keysetting2=0xEE;*/

    if (memcmp(aid, "\x00\x00\x00", 3) == 0) {
        PrintAndLogEx(WARNING, _RED_("   Creating root aid 000000 is forbidden"));
        return PM3_ESOFT;
    }

    aidhdr_t aidhdr;
    memcpy(aidhdr.aid, aid, sizeof(aid));
    aidhdr.keysetting1 = keysetting1;
    aidhdr.keysetting2 = keysetting2;

    if (usefid) memcpy(aidhdr.fid, fid, sizeof(fid));

    if (usename) memcpy(aidhdr.name, name, sizeof(name));

    uint8_t rootaid[3] = {0x00, 0x00, 0x00};
    int res = handler_desfire_select_application(rootaid);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
     }

    res = handler_desfire_createapp(&aidhdr, usename, usefid);
    DropField();
    PrintAndLogEx(SUCCESS, "Successfully created aid.");
    return res;
}

static int CmdHF14ADesDeleteApp(const char *Cmd) {
    CLIParserInit("hf mfdes deleteaid",
                  "Delete Application ID",
                  "Usage:\n\t-a aid (3 hex bytes, big endian)\n\n"
                  "Example:\n\thf mfdes deleteaid -a 123456\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_strx0("aA",  "aid",    "<aid>", "App ID to delete"),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, false);
    int aidlength = 3;
    uint8_t aid[3] = {0};
    CLIGetHexWithReturn(1, aid, &aidlength);
    CLIParserFree();
    swap24(aid);
    if (aidlength != 3) {
        PrintAndLogEx(ERR, "AID must have 3 bytes length.");
        return PM3_EINVARG;
    }

    if (memcmp(aid, "\x00\x00\x00", 3) == 0) {
        PrintAndLogEx(WARNING, _RED_("   Deleting root aid 000000 is forbidden."));
        return PM3_ESOFT;
    }

    uint8_t rootaid[3] = {0x00, 0x00, 0x00};
    int res = handler_desfire_select_application(rootaid);
    if (res != PM3_SUCCESS) { DropField(); return res;}
    res = handler_desfire_deleteapp(aid);
    DropField();
    PrintAndLogEx(SUCCESS, "Successfully deleted aid.");
    return res;
}

static int selectfile(uint8_t* aid, int fileno, uint8_t* cs){
    if (handler_desfire_select_application(aid)!=PM3_SUCCESS) {
        PrintAndLogEx(ERR, _RED_("   Couldn't select aid."));
        return PM3_ESOFT;
    }

    uint8_t filesettings[20] = {0};
    int fileset_len = 0;
    int res = handler_desfire_filesettings(fileno, filesettings, &fileset_len);

    if (tag->session_key!=NULL)
    {
        mfdes_auth_res_t rpayload;
        int keyno=(filesettings[0]>>4)&0xF;
        if (keyno!=0xE && currentauth[keyno].keyno==keyno) {
            if (handler_desfire_auth(&currentauth[keyno], &rpayload) != PM3_SUCCESS) {
                PrintAndLogEx(ERR, _RED_("   Couldn't authenticate key."));
                return PM3_ESOFT;
            }
        } else if (keyno!=0xE)
        {
            PrintAndLogEx(ERR, _RED_("   Please authenticate first."));
            return PM3_ESOFT;
        }
    }
    *cs=filesettings[1];
    return res;
}


static int CmdHF14ADesClearRecordFile(const char *Cmd) {
    CLIParserInit("hf mfdes clearrecord",
                  "Clear record file",
                  "Usage:\n\t"
                  "hf mfdes clearrecord -n 01\n"
                  "Make sure to select aid or authenticate aid before running this command.\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_strx0("nN", "fileno", "<fileno>", "File Number (1 hex byte, 0x00 - 0x1F)"),
        arg_strx0("aA", "aid", "<aid>", "App ID to select as hex bytes (3 bytes,big endian,optional)"),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, false);

    int filenolen = 0;
    uint8_t fileno[1] = {0};
    CLIGetHexWithReturn(1, fileno, &filenolen);
    int aidlength = 3;
    uint8_t aid[3] = {0};
    CLIGetHexWithReturn(2, aid, &aidlength);
    swap24(aid);
    CLIParserFree();

    if (filenolen != 1) {
        PrintAndLogEx(ERR, "Fileno must have 1 bytes length.");
        return PM3_EINVARG;
    }

    if (fileno[0] > 0x1F) {
        PrintAndLogEx(ERR, "Fileno must be lower 0x1F.");
        return PM3_EINVARG;
    }

    if (aidlength != 3 && aidlength != 0) {
        PrintAndLogEx(ERR, _RED_("   The given aid must have 3 bytes (big endian)."));
        return PM3_ESOFT;
    } else if (aidlength == 0) {
        if (memcmp(&tag->selected_application, aid, 3) == 0) {
            PrintAndLogEx(ERR, _RED_("   You need to select an aid first."));
            return PM3_ESOFT;
        }
        memcpy(aid,(uint8_t *)&tag->selected_application,3);
    }
    uint8_t cs=0;
    if (selectfile(aid,fileno[0],&cs)!=PM3_SUCCESS)
    {
        PrintAndLogEx(ERR, _RED_("   Error on selecting file."));
        return PM3_ESOFT;
    }

    int res = handler_desfire_clearrecordfile(fileno[0]);
    if (res == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Successfully cleared record file.");
    } else {
        PrintAndLogEx(ERR, "Error on deleting file : %d", res);
    }
    DropField();
    return res;
}

static int CmdHF14ADesDeleteFile(const char *Cmd) {
    CLIParserInit("hf mfdes deletefile",
                  "Delete File",
                  "Usage:\n\t"
                  "hf mfdes deletefile -n 01\n"
                  "Make sure to select aid or authenticate aid before running this command.\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_strx0("nN", "fileno", "<fileno>", "File Number (1 hex byte, 0x00 - 0x1F)"),
        arg_strx0("aA", "aid", "<aid>", "App ID to select as hex bytes (3 bytes,big endian,optional)"),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, false);
    int filenolen = 0;
    uint8_t fileno[1] = {0};
    CLIGetHexWithReturn(1, fileno, &filenolen);
    int aidlength = 3;
    uint8_t aid[3] = {0};
    CLIGetHexWithReturn(2, aid, &aidlength);
    swap24(aid);
    CLIParserFree();

    if (filenolen != 1) {
        PrintAndLogEx(ERR, "Fileno must have 1 bytes length.");
        return PM3_EINVARG;
    }

    if (fileno[0] > 0x1F) {
        PrintAndLogEx(ERR, "Fileno must be lower 0x1F.");
        return PM3_EINVARG;
    }

    if (aidlength != 3 && aidlength != 0) {
        PrintAndLogEx(ERR, _RED_("   The given aid must have 3 bytes (big endian)."));
        return PM3_ESOFT;
    } else if (aidlength == 0) {
        if (memcmp(&tag->selected_application, aid, 3) == 0) {
            PrintAndLogEx(ERR, _RED_("   You need to select an aid first."));
            return PM3_ESOFT;
        }
        memcpy(aid,(uint8_t *)&tag->selected_application,3);
    }
    uint8_t cs=0;
    if (selectfile(aid,fileno[0],&cs)!=PM3_SUCCESS)
    {
        PrintAndLogEx(ERR, _RED_("   Error on selecting file."));
        return PM3_ESOFT;
    }

    int res = handler_desfire_deletefile(fileno[0]);
    if (res == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Successfully deleted file..");
    } else {
        PrintAndLogEx(ERR, "Error on deleting file : %d", res);
    }
    DropField();
    return res;
}

static int CmdHF14ADesCreateFile(const char *Cmd) {
    CLIParserInit("hf mfdes createfile",
                  "Create Standard/Backup File",
                  "Usage:"
                  "\n\thf mfdes createfile -f 0001 -n 01 -c 0 -r EEEE -s 000100 -a 123456\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_strx0("nN", "fileno", "<fileno>", "File Number (1 hex byte, 0x00 - 0x1F)"),
        arg_strx0("fF", "fileid", "<fileid>", "ISO FID (2 hex bytes, big endian)"),
        arg_int0("cC", "com.set", "<comset>", "Communication setting (0=Plain,1=Plain+MAC,3=Enciphered)"),
        arg_strx0("rR", "accessrights", "<accessrights>", "Access rights (2 hex bytes -> RW/Chg/R/W, 0-D Key, E Free, F Denied)"),
        arg_strx0("sS", "filesize", "<filesize>", "File size (3 hex bytes, big endian)"),
        arg_lit0("bB", "backup", "Create backupfile instead of standard file"),
        arg_strx0("aA", "aid", "<aid>", "App ID to select as hex bytes (3 bytes,big endian)"),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, false);
    int filenolen = 0;
    uint8_t fileno[1] = {0};
    CLIGetHexWithReturn(1, fileno, &filenolen);

    int fidlength = 0;
    uint8_t fid[2] = {0};
    CLIParamHexToBuf(arg_get_str(2), fid, 2, &fidlength);

    uint8_t comset = arg_get_int(3);
    int arlength = 0;
    uint8_t ar[2] = {0};
    CLIGetHexWithReturn(4, ar, &arlength);

    int fsizelen = 0;
    uint8_t filesize[3] = {0};
    CLIGetHexWithReturn(5, filesize, &fsizelen);

    bool isbackup = arg_get_lit(6);
    int aidlength = 3;
    uint8_t aid[3] = {0};
    CLIGetHexWithReturn(7, aid, &aidlength);
    swap24(aid);
    CLIParserFree();

    swap16(fid);
    swap24(filesize);

    if (filenolen != 1) {
        PrintAndLogEx(ERR, "File number is missing.");
        return PM3_EINVARG;
    }

    if (fileno[0] > 0x1F) {
        PrintAndLogEx(ERR, "File number range is invalid (0x00-0x1F).");
        return PM3_EINVARG;
    }
    if (comset != 0 && comset != 1 && comset != 3) {
        PrintAndLogEx(ERR, "Communication setting must be either 0=Plain, 1=Plain+MAC or 3=Encrypt.");
        return PM3_EINVARG;
    }

    if (arlength != 2) {
        PrintAndLogEx(ERR, "Access rights must have 2 hex bytes length.");
        return PM3_EINVARG;
    }

    if (fsizelen != 3) {
        PrintAndLogEx(ERR, "Filesize must have 3 hex bytes length.");
        return PM3_EINVARG;
    }

    if (fidlength != 2) {
        PrintAndLogEx(ERR, "ISO File id must have 2 hex bytes length.");
        return PM3_EINVARG;
    }

    mfdes_file_t ft;
    memcpy(ft.fid, fid, 2);
    memcpy(ft.filesize, filesize, 3);
    ft.fileno = fileno[0];
    ft.comset = comset;
    memcpy(ft.access_rights, ar, 2);

    if (aidlength != 3 && aidlength != 0) {
        PrintAndLogEx(ERR, _RED_("   The given aid must have 3 bytes (big endian)."));
        DropField();
        return PM3_ESOFT;
    } else if (aidlength == 0) {
        if (memcmp(&tag->selected_application, aid, 3) == 0) {
            PrintAndLogEx(ERR, _RED_("   You need to select an aid first."));
            DropField();
            return PM3_ESOFT;
        }
        memcpy(aid,(uint8_t *)&tag->selected_application,3);
    }

    int res=handler_desfire_select_application(aid);
    if (res!=PM3_SUCCESS){
        PrintAndLogEx(ERR, "Couldn't select aid. Error %d", res);
        DropField();
        return res;
    }


    if (isbackup) res = handler_desfire_create_backup_file(&ft);
    else res = handler_desfire_create_std_file(&ft);

    if (res == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Successfully created standard/backup file.");
    } else {
        PrintAndLogEx(ERR, "Couldn't create standard/backup file. Error %d", res);
    }
    DropField();
    return res;
}

static int CmdHF14ADesGetValueData(const char *Cmd) {
    CLIParserInit("hf mfdes getvalue",
                  "Get value from value file",
                  "Usage:"
                  "\n\thf mfdes getvalue -n 03\n"
                  "Make sure to select aid or authenticate aid before running this command.\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_strx0("nN", "fileno", "<fileno>", "File Number (1 hex byte, 0x00 - 0x1F)"),
        arg_strx0("aA", "aid", "<aid>", "App ID to select as hex bytes (3 bytes,big endian)"),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, false);

    int filenolen = 0;
    uint8_t fileno[1] = {0};
    CLIGetHexWithReturn(1, fileno, &filenolen);
    int aidlength = 3;
    uint8_t aid[3] = {0};
    CLIGetHexWithReturn(2, aid, &aidlength);
    swap24(aid);

    CLIParserFree();

    if (filenolen != 1) {
        PrintAndLogEx(ERR, "File number is missing");
        return PM3_EINVARG;
    }

    if (fileno[0] > 0x1F) {
        PrintAndLogEx(ERR, "File number range is invalid (0x00-0x1F)");
        return PM3_EINVARG;
    }

    mfdes_value_t value;
    value.fileno = fileno[0];

    if (aidlength != 3 && aidlength != 0) {
        PrintAndLogEx(ERR, _RED_("   The given aid must have 3 bytes (big endian)."));
        return PM3_ESOFT;
    } else if (aidlength == 0) {
        if (memcmp(&tag->selected_application, aid, 3) == 0) {
            PrintAndLogEx(ERR, _RED_("   You need to select an aid first."));
            return PM3_ESOFT;
        }
        memcpy(aid,(uint8_t *)&tag->selected_application,3);
    }
    uint8_t cs=0;
    if (selectfile(aid,value.fileno,&cs)!=PM3_SUCCESS)
    {
        PrintAndLogEx(ERR, _RED_("   Error on selecting file."));
        return PM3_ESOFT;
    }

    int len = 0;
    int res = handler_desfire_getvalue(&value, &len, cs);
    if (res == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Successfully read value from File %u:", fileno[0]);
        PrintAndLogEx(NORMAL, "\nOffset  | Data                                            | Ascii");
        PrintAndLogEx(NORMAL, "----------------------------------------------------------------------------");
        for (int i = 0; i < len; i += 16) {
            PrintAndLogEx(NORMAL, "%02d/0x%02X | %s| %s", i, i, sprint_hex(&value.value[i], len > 16 ? 16 : len), sprint_ascii(&value.value[i], len > 16 ? 16 : len));
        }
    } else {
        PrintAndLogEx(ERR, "Couldn't read value. Error %d", res);
    }
    DropField();
    return res;
}


static int CmdHF14ADesReadData(const char *Cmd) {
    CLIParserInit("hf mfdes readdata",
                  "Read data from File",
                  "Usage:"
                  "\n\thf mfdes readdata -n 01 -t 0 -o 000000 -l 000000 -a 123456\n"
                  "\thf mfdes readdata -n 01 -t 0 (Read all data from standard file, fileno 01)\n"
                  "Make sure to select aid or authenticate aid before running this command.\n"
    );

    void *argtable[] = {
            arg_param_begin,
            arg_strx0("nN", "fileno", "<fileno>", "File Number (1 hex byte, 0x00 - 0x1F)"),
            arg_strx0("oO", "offset", "<offset>", "File Offset (3 hex bytes, big endian), optional"),
            arg_strx0("lL", "length", "<length>",
                      "Length to read (3 hex bytes, big endian -> 000000 = Read all data),optional"),
            arg_int0("tT", "type", "<type>", "File Type (0=Standard/Backup, 1=Record)"),
            arg_strx0("aA", "aid", "<aid>", "App ID to select as hex bytes (3 bytes,big endian,optional)"),
            arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, false);
    int filenolen = 0;
    uint8_t fileno[1] = {0};
    CLIGetHexWithReturn(1, fileno, &filenolen);

    int offsetlength = 0;
    uint8_t offset[3] = {0};
    CLIParamHexToBuf(arg_get_str(2), offset, 3, &offsetlength);

    int flength = 0;
    uint8_t filesize[3] = {0};
    CLIParamHexToBuf(arg_get_str(3), filesize, 3, &flength);

    int type = arg_get_int(4);

    int aidlength = 3;
    uint8_t aid[3] = {0};
    CLIGetHexWithReturn(5, aid, &aidlength);
    swap24(aid);
    CLIParserFree();

    if (type > 1) {
        PrintAndLogEx(ERR, "Invalid file type (0=Standard/Backup, 1=Record)");
        return PM3_EINVARG;
    }

    if (offsetlength != 3 && offsetlength != 0) {
        PrintAndLogEx(ERR, "Offset needs 3 hex bytes");
        return PM3_EINVARG;
    }

    if (filenolen != 1) {
        PrintAndLogEx(ERR, "File number is missing");
        return PM3_EINVARG;
    }

    if (fileno[0] > 0x1F) {
        PrintAndLogEx(ERR, "File number range is invalid (0x00-0x1F)");
        return PM3_EINVARG;
    }

    swap24(filesize);
    swap24(offset);

    mfdes_data_t ft;
    memcpy(ft.offset, offset, 3);
    memcpy(ft.length, filesize, 3);
    ft.fileno = fileno[0];

    int bytestoread = le24toh(filesize);

    if (bytestoread == 0) bytestoread = 0xFFFFFF;

    if (aidlength != 3 && aidlength != 0) {
        PrintAndLogEx(ERR, _RED_("   The given aid must have 3 bytes (big endian)."));
        return PM3_ESOFT;
    } else if (aidlength == 0) {
        if (memcmp(&tag->selected_application, aid, 3) == 0) {
            PrintAndLogEx(ERR, _RED_("   You need to select an aid first."));
            return PM3_ESOFT;
        }
        memcpy(aid,(uint8_t *)&tag->selected_application,3);
    }
    uint8_t cs=0;
    if (selectfile(aid,ft.fileno,&cs)!=PM3_SUCCESS)
    {
        PrintAndLogEx(ERR, _RED_("   Error on selecting file."));
        return PM3_ESOFT;
    }

    uint8_t *data = (uint8_t *)calloc(bytestoread, sizeof(uint8_t));
    int res=PM3_ESOFT;
    if (data != NULL) {
        ft.data = data;
        res = handler_desfire_readdata(&ft, type,cs);
        if (res == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "Successfully read data from file %d:", ft.fileno);
            PrintAndLogEx(NORMAL, "\nOffset  | Data                                            | Ascii");
            PrintAndLogEx(NORMAL, "----------------------------------------------------------------------------");
            int len = le24toh(ft.length);
            for (int i = 0; i < len; i += 16) {
                int l=len-i;
                PrintAndLogEx(NORMAL, "%02d/0x%02X | %s| %s", i, i, sprint_hex(&ft.data[i], l > 16 ? 16 : l), sprint_ascii(&ft.data[i], l > 16 ? 16 : l));
            }
        } else {
            PrintAndLogEx(ERR, "Couldn't read data. Error %d", res);
            DropField();
            return res;
        }
        free(data);
    }
    DropField();
    return res;
}

static int CmdHF14ADesChangeValue(const char *Cmd) {
    CLIParserInit("hf mfdes changevalue",
                  "Change value (credit/limitedcredit/debit)",
                  "Usage:"
                  "\n\thf mfdes changevalue -n 03 -m 0 -d 00000001\n"
                  "Make sure to select aid or authenticate aid before running this command.\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_strx0("nN", "fileno", "<fileno>", "File Number (1 hex byte, 0x00 - 0x1F)"),
        arg_strx0("dD", "value", "<value>", "Value to increase (4 hex bytes, big endian)"),
        arg_int0("mM", "mode", "<mode>", "Mode (0=Credit, 1=LimitedCredit, 2=Debit)"),
        arg_strx0("aA", "aid", "<aid>", "App ID to select as hex bytes (3 bytes,big endian)"),
        arg_param_end
    };

    mfdes_value_t value;
    CLIExecWithReturn(Cmd, argtable, false);

    int filenolen = 0;
    uint8_t fileno[1] = {0};
    CLIGetHexWithReturn(1, fileno, &filenolen);
    value.fileno = fileno[0];

    int vlength = 0x0;
    CLIParamHexToBuf(arg_get_str(2), value.value, 4, &vlength);

    int mode = arg_get_int(3);
    int aidlength = 3;
    uint8_t aid[3] = {0};
    CLIGetHexWithReturn(4, aid, &aidlength);
    swap24(aid);

    CLIParserFree();

    if (mode > 2) {
        PrintAndLogEx(ERR, "Invalid mode (0=Credit, 1=LimitedCredit, 2=Debit).");
        return PM3_EINVARG;
    }

    if (vlength != 4) {
        PrintAndLogEx(ERR, "Value needs 4 hex bytes.");
        return PM3_EINVARG;
    }
    swap32(value.value);

    if (filenolen != 1) {
        PrintAndLogEx(ERR, "File number is missing.");
        return PM3_EINVARG;
    }

    if (value.fileno > 0x1F) {
        PrintAndLogEx(ERR, "File number range is invalid (0x00-0x1F).");
        return PM3_EINVARG;
    }

    if (aidlength != 3 && aidlength != 0) {
        PrintAndLogEx(ERR, _RED_("   The given aid must have 3 bytes (big endian)."));
        return PM3_ESOFT;
    } else if (aidlength == 0) {
        if (memcmp(&tag->selected_application, aid, 3) == 0) {
            PrintAndLogEx(ERR, _RED_("   You need to select an aid first."));
            return PM3_ESOFT;
        }
        memcpy(aid,(uint8_t *)&tag->selected_application,3);
    }
    uint8_t cs=0;
    if (selectfile(aid,fileno[0],&cs)!=PM3_SUCCESS)
    {
        PrintAndLogEx(ERR, _RED_("   Error on selecting file."));
        return PM3_ESOFT;
    }


    int res=PM3_ESOFT;
    if (mode == 0) {
        res = handler_desfire_credit(&value,cs);
    } else if (mode == 1) {
        res = handler_desfire_limitedcredit(&value,cs);
    } else if (mode == 2) {
        res = handler_desfire_debit(&value,cs);
    }

    if (res == PM3_SUCCESS) {
        if (handler_desfire_commit_transaction() == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "Successfully changed value in value file.");
        } else {
            PrintAndLogEx(ERR, "Couldn't commit the transaction. Error %d", res);
        }
    } else {
        PrintAndLogEx(ERR, "Couldn't change value in value file. Error %d", res);
    }
    DropField();
    return res;
}


static int CmdHF14ADesWriteData(const char *Cmd) {

    CLIParserInit("hf mfdes writedata",
                  "Write data to File",
                  "Usage:"
                  "\n\thf mfdes writedata -n 01 -t 0 -o 000000 -d 3132333435363738\n"
                  "Make sure to select aid or authenticate aid before running this command.\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_strx0("nN", "fileno", "<fileno>", "File Number (1 hex byte, 0x00 - 0x1F)"),
        arg_strx0("oO", "offset", "<offset>", "File Offset (3 hex bytes, big endian), optional"),
        arg_strx0("dD", "data", "<data>", "Data to write (hex bytes, 0xFFFF bytes max.)"),
        arg_int0("type", "type", "<type>", "File Type (0=Standard/Backup, 1=Record)"),
        arg_strx0("aA", "aid", "<aid>", "App ID to select as hex bytes (3 bytes,big endian, optional)"),
        arg_param_end
    };

    CLIExecWithReturn(Cmd, argtable, false);

    int filenolen = 0;
    uint8_t fileno[1] = {0};
    CLIGetHexWithReturn(1, fileno, &filenolen);

    int offsetlength = 0;
    uint8_t offset[3] = {0};
    CLIParamHexToBuf(arg_get_str(2), offset, 3, &offsetlength);

    int dlength = 0xFFFF;
    uint8_t *data = (uint8_t *)calloc(0xFFFF, sizeof(uint8_t));
    if (data == NULL) {
        PrintAndLogEx(ERR, "failed to allocate memory");
        return PM3_EMALLOC;
    }
    CLIParamHexToBuf(arg_get_str(3), data, 0xFFFF, &dlength);

    int type = arg_get_int(4);
    int aidlength = 3;
    uint8_t aid[3] = {0};
    CLIGetHexWithReturn(5, aid, &aidlength);
    swap24(aid);

    CLIParserFree();

    swap24(offset);

    if (type < 0 || type > 1) {
        PrintAndLogEx(ERR, "Unknown type (0=Standard/Backup, 1=Record)");
        if (data) free(data);
        return PM3_EINVARG;
    }

    if (dlength == 0) {
        PrintAndLogEx(ERR, "Data needs some hex bytes to write");
        if (data) free(data);
        return PM3_EINVARG;
    }

    if (offsetlength != 3 && offsetlength != 0) {
        PrintAndLogEx(ERR, "Offset needs 3 hex bytes");
        if (data) free(data);
        return PM3_EINVARG;
    }

    if (filenolen != 1) {
        PrintAndLogEx(ERR, "File number is missing");
        if (data) free(data);
        return PM3_EINVARG;
    }

    if (fileno[0] > 0x1F) {
        PrintAndLogEx(ERR, "File number range is invalid (0x00-0x1F)");
        if (data) free(data);
        return PM3_EINVARG;
    }

    mfdes_data_t ft;

    memcpy(ft.offset, offset, 3);
    htole24(dlength, ft.length);
    ft.fileno = fileno[0];

    if (aidlength != 3 && aidlength != 0) {
        PrintAndLogEx(ERR, _RED_("   The given aid must have 3 bytes (big endian)."));
        return PM3_ESOFT;
    } else if (aidlength == 0) {
        if (memcmp(&tag->selected_application, aid, 3) == 0) {
            PrintAndLogEx(ERR, _RED_("   You need to select an aid first."));
            return PM3_ESOFT;
        }
        memcpy(aid,(uint8_t *)&tag->selected_application,3);
    }
    uint8_t cs=0;
    if (selectfile(aid,fileno[0],&cs)!=PM3_SUCCESS)
    {
        PrintAndLogEx(ERR, _RED_("   Error on selecting file."));
        return PM3_ESOFT;
    }

    int res=PM3_ESOFT;
    if (data != NULL) {
        ft.data = data;
        res = handler_desfire_writedata(&ft, type,cs);
        if (res == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "Successfully wrote data");
        } else {
            PrintAndLogEx(ERR, "Couldn't read data. Error %d", res);
        }
        free(data);
    }
    DropField();
    return res;
}


static int CmdHF14ADesCreateRecordFile(const char *Cmd) {
    CLIParserInit("hf mfdes createrecordfile",
                  "Create Linear/Cyclic Record File",
                  "Usage:"
                  "\n\thf mfdes createrecordfile -f 1122 -n 02 -c 0 -r EEEE -s 000010 -m 000005 -a 123456\n"
                  "Make sure to select aid or authenticate aid before running this command.\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_strx0("nN", "fileno", "<fileno>", "File Number (1 hex byte, 0x00 - 0x1F)"),
        arg_strx0("fF", "fileid", "<fileid>", "ISO FID (2 hex bytes, big endian)"),
        arg_int0("cC", "com.set", "<comset>", "Communication setting (0=Plain,1=Plain+MAC,3=Enciphered)"),
        arg_strx0("rR", "accessrights", "<accessrights>", "Access rights (2 hex bytes -> RW/Chg/R/W, 0-D Key, E Free, F Denied)"),
        arg_strx0("sS", "recordsize", "<recordsize>", "Record size (3 hex bytes, big endian, 000001 to FFFFFF)"),
        arg_strx0("mM", "maxnumrecord", "<maxnumrecord>", "Max. Number of Records (3 hex bytes, big endian)"),
        arg_lit0("bB", "cyclic", "Create cyclic record file instead of linear record file"),
        arg_strx0("aA", "aid", "<aid>", "App ID to select as hex bytes (3 bytes,big endian,optional)"),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, false);
    int filenolen = 0;
    uint8_t fileno[1] = {0};
    CLIGetHexWithReturn(1, fileno, &filenolen);

    int fidlength = 0;
    uint8_t fid[2] = {0};
    CLIParamHexToBuf(arg_get_str(2), fid, 2, &fidlength);

    uint8_t comset = arg_get_int(3);
    int arlength = 0;
    uint8_t ar[2] = {0};
    CLIGetHexWithReturn(4, ar, &arlength);

    int rsizelen = 0;
    uint8_t recordsize[3] = {0};
    CLIGetHexWithReturn(5, recordsize, &rsizelen);

    int msizelen = 0;
    uint8_t maxnumrecords[3] = {0};
    CLIGetHexWithReturn(6, maxnumrecords, &msizelen);

    bool cyclic = arg_get_lit(7);
    int aidlength = 3;
    uint8_t aid[3] = {0};
    CLIGetHexWithReturn(8, aid, &aidlength);
    swap24(aid);
    CLIParserFree();

    swap16(fid);
    swap24(recordsize);
    swap24(maxnumrecords);

    if (msizelen != 3) {
        PrintAndLogEx(ERR, "Maximum number of records must have 3 hex bytes length.");
        return PM3_EINVARG;
    }

    if (memcmp("\x00\x00\x00", maxnumrecords, 3) == 0x0) {
        PrintAndLogEx(ERR, "Maximum number of records is invalid (0x000001-0xFFFFFF).");
        return PM3_EINVARG;
    }

    if (filenolen != 1) {
        PrintAndLogEx(ERR, "File number is missing.");
        return PM3_EINVARG;
    }

    if (fileno[0] > 0x1F) {
        PrintAndLogEx(ERR, "File number range is invalid (0x00-0x1F).");
        return PM3_EINVARG;
    }

    if (comset != 0 && comset != 1 && comset != 3) {
        PrintAndLogEx(ERR, "Communication setting must be either 0=Plain, 1=Plain+MAC or 3=Encrypt.");
        return PM3_EINVARG;
    }

    if (arlength != 2) {
        PrintAndLogEx(ERR, "Access rights must have 2 hex bytes length.");
        return PM3_EINVARG;
    }

    if (rsizelen != 3) {
        PrintAndLogEx(ERR, "Recordsize must have 3 hex bytes length.");
        return PM3_EINVARG;
    }

    if (fidlength != 2) {
        PrintAndLogEx(ERR, "ISO File id must have 2 hex bytes length.");
        return PM3_EINVARG;
    }

    mfdes_linear_t ft;
    ft.fileno = fileno[0];
    memcpy(ft.fid, fid, 2);
    ft.comset = comset;
    memcpy(ft.access_rights, ar, 2);
    memcpy(ft.recordsize, recordsize, 3);
    memcpy(ft.maxnumrecords, maxnumrecords, 3);

    if (aidlength != 3 && aidlength != 0) {
        PrintAndLogEx(ERR, _RED_("   The given aid must have 3 bytes (big endian)."));
        return PM3_ESOFT;
    } else if (aidlength == 0) {
        if (memcmp(&tag->selected_application, aid, 3) == 0) {
            PrintAndLogEx(ERR, _RED_("   You need to select an aid first."));
            return PM3_ESOFT;
        }
        memcpy(aid,(uint8_t *)&tag->selected_application,3);
    }
    if (handler_desfire_select_application(aid)!=PM3_SUCCESS)
    {
        PrintAndLogEx(ERR, _RED_("   Error on selecting aid."));
        return PM3_ESOFT;
    }

    int res=PM3_SUCCESS;
    if (cyclic) res = handler_desfire_create_cyclicrecordfile(&ft);
    else res = handler_desfire_create_linearrecordfile(&ft);
    if (res == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Successfully created linear/cyclic record file.");
    } else {
        PrintAndLogEx(ERR, "Couldn't create linear/cyclic record file. Error %d", res);
    }
    DropField();
    return res;
}

static int CmdHF14ADesCreateValueFile(const char *Cmd) {
    CLIParserInit("hf mfdes createvaluefile",
                  "Create Value File",
                  "Usage:"
                  "\n\thf mfdes createvaluefile -n 03 -c 0 -r EEEE -l 00000000 -u 00002000 -v 00000001 -m 02 -a 123456\n"
                  "Make sure to select aid or authenticate aid before running this command.\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_strx0("nN", "fileno", "<fileno>", "File Number (1 hex byte, 0x00 - 0x1F)"),
        arg_int0("cC", "com.set", "<comset>", "Communication setting (0=Plain,1=Plain+MAC,3=Enciphered)"),
        arg_strx0("rR", "accessrights", "<accessrights>", "Access rights (2 hex bytes -> RW/Chg/R/W, 0-D Key, E Free, F Denied)"),
        arg_strx0("lL", "lowerlimit", "<lowerlimit>", "Lower limit (4 hex bytes, big endian)"),
        arg_strx0("uU", "upperlimit", "<upperlimit>", "Upper limit (4 hex bytes, big endian)"),
        arg_strx0("vV", "value", "<value>", "Value (4 hex bytes, big endian)"),
        arg_strx0("mM", "limitcredit", "<limitcredit>", "Limited Credit enabled (1 hex byte [Bit 0=LimitedCredit, 1=FreeValue])"),
        arg_strx0("aA", "aid", "<aid>", "App ID to select as hex bytes (3 bytes,big endian,optional)"),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, false);
    int filenolen = 0;
    uint8_t fileno[1] = {0};
    CLIGetHexWithReturn(1, fileno, &filenolen);

    uint8_t comset = arg_get_int(2);
    int arlength = 0;
    uint8_t ar[2] = {0};
    CLIGetHexWithReturn(3, ar, &arlength);

    int lllen = 0;
    uint8_t lowerlimit[4] = {0};
    CLIGetHexWithReturn(4, lowerlimit, &lllen);

    int ullen = 0;
    uint8_t upperlimit[4] = {0};
    CLIGetHexWithReturn(5, upperlimit, &ullen);

    int vllen = 0;
    uint8_t value[4] = {0};
    CLIGetHexWithReturn(6, value, &vllen);

    int limitedlen = 0;
    uint8_t limited[1] = {0};
    CLIGetHexWithReturn(7, limited, &limitedlen);
    int aidlength = 3;
    uint8_t aid[3] = {0};
    CLIGetHexWithReturn(8, aid, &aidlength);
    swap24(aid);
    CLIParserFree();

    swap32(lowerlimit);
    swap32(upperlimit);
    swap32(value);

    if (filenolen != 1) {
        PrintAndLogEx(ERR, "File number is missing");
        return PM3_EINVARG;
    }

    if (fileno[0] > 0x1F) {
        PrintAndLogEx(ERR, "File number range is invalid (0x00-0x1F)");
        return PM3_EINVARG;
    }

    if (comset != 0 && comset != 1 && comset != 3) {
        PrintAndLogEx(ERR, "Communication setting must be either 0=Plain, 1=Plain+MAC or 3=Encrypt");
        return PM3_EINVARG;
    }

    if (arlength != 2) {
        PrintAndLogEx(ERR, "Access rights must have 2 hex bytes length");
        return PM3_EINVARG;
    }

    if (lllen != 4) {
        PrintAndLogEx(ERR, "Lower limit must have 4 hex bytes length");
        return PM3_EINVARG;
    }

    if (ullen != 4) {
        PrintAndLogEx(ERR, "Upper limit must have 4 hex bytes length");
        return PM3_EINVARG;
    }

    if (vllen != 4) {
        PrintAndLogEx(ERR, "Value must have 4 hex bytes length");
        return PM3_EINVARG;
    }

    if (limitedlen != 1) {
        PrintAndLogEx(WARNING, "Limited Credit Enabled must have 1 hex byte");
        return PM3_EINVARG;
    }

    mfdes_value_file_t ft;
    ft.fileno = fileno[0];
    ft.comset = comset;
    memcpy(ft.access_rights, ar, 2);
    memcpy(ft.lowerlimit, lowerlimit, 4);
    memcpy(ft.upperlimit, upperlimit, 4);
    memcpy(ft.value, value, 4);
    ft.limitedcreditenabled = limited[0];

    if (aidlength != 3 && aidlength != 0) {
        PrintAndLogEx(ERR, _RED_("   The given aid must have 3 bytes (big endian)."));
        return PM3_ESOFT;
    } else if (aidlength == 0) {
        if (memcmp(&tag->selected_application, aid, 3) == 0) {
            PrintAndLogEx(ERR, _RED_("   You need to select an aid first."));
            return PM3_ESOFT;
        }
        memcpy(aid,(uint8_t *)&tag->selected_application,3);
    }

    if (handler_desfire_select_application(aid)!=PM3_SUCCESS)
    {
        PrintAndLogEx(ERR, _RED_("   Error on selecting aid."));
        return PM3_ESOFT;
    }

    int res = handler_desfire_create_value_file(&ft);
    if (res == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Successfully created value file.");
    } else {
        PrintAndLogEx(ERR, "Couldn't create value file. Error %d", res);
    }
    DropField();
    return res;
}

static int CmdHF14ADesFormatPICC(const char *Cmd) {
    CLIParserInit("hf mfdes formatpicc",
                  "Formats MIFARE DESFire PICC to factory state",
                  "Usage:"
                  "\n\thf mfdes formatpicc\n"
                  "Make sure to authenticate picc before running this command.\n"
                 );

    sAPDU apdu = {0x90, MFDES_FORMAT_PICC, 0x00, 0x00, 0, NULL}; // 0xDF
    uint16_t sw = 0;
    int recvlen = 0;
    int res = send_desfire_cmd(&apdu, false, NULL, &recvlen, &sw, 0, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't format picc -> %s"), GetErrorString(res, &sw));
        DropField();
        return res;
    } else {
            PrintAndLogEx(INFO, "Card successfully reset");
            return PM3_SUCCESS;
        }
    DropField();
    return PM3_SUCCESS;
}


static int CmdHF14ADesInfo(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    DropField();
    SendCommandNG(CMD_HF_DESFIRE_INFO, NULL, 0);
    PacketResponseNG resp;

    if (!WaitForResponseTimeout(CMD_HF_DESFIRE_INFO, &resp, 1500)) {
        PrintAndLogEx(WARNING, "Command execute timeout");
        DropField();
        return PM3_ETIMEOUT;
    }

    struct p {
        uint8_t isOK;
        uint8_t uid[7];
        uint8_t versionHW[7];
        uint8_t versionSW[7];
        uint8_t details[14];
    } PACKED;

    struct p *package = (struct p *) resp.data.asBytes;

    if (resp.status != PM3_SUCCESS) {
        switch (package->isOK) {
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

    nxp_cardtype_t cardtype = getCardType(package->versionHW[3], package->versionHW[4]);
    if (cardtype == PLUS_EV1) {
        PrintAndLogEx(INFO, "Card seems to be MIFARE Plus EV1.  Try " _YELLOW_("`hf mfp info`"));
        return PM3_SUCCESS;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    PrintAndLogEx(SUCCESS, "              UID: " _GREEN_("%s"), sprint_hex(package->uid, sizeof(package->uid)));
    PrintAndLogEx(SUCCESS, "     Batch number: " _GREEN_("%s"), sprint_hex(package->details + 7, 5));
    PrintAndLogEx(SUCCESS, "  Production date: week " _GREEN_("%02x") " / " _GREEN_("20%02x"), package->details[12], package->details[13]);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Hardware Information"));
    PrintAndLogEx(INFO, "     Vendor Id: " _YELLOW_("%s"), getTagInfo(package->versionHW[0]));
    PrintAndLogEx(INFO, "          Type: " _YELLOW_("0x%02X"), package->versionHW[1]);
    PrintAndLogEx(INFO, "       Subtype: " _YELLOW_("0x%02X"), package->versionHW[2]);
    PrintAndLogEx(INFO, "       Version: %s", getVersionStr(package->versionHW[3], package->versionHW[4]));
    PrintAndLogEx(INFO, "  Storage size: %s", getCardSizeStr(package->versionHW[5]));
    PrintAndLogEx(INFO, "      Protocol: %s", getProtocolStr(package->versionHW[6], true));
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Software Information"));
    PrintAndLogEx(INFO, "     Vendor Id: " _YELLOW_("%s"), getTagInfo(package->versionSW[0]));
    PrintAndLogEx(INFO, "          Type: " _YELLOW_("0x%02X"), package->versionSW[1]);
    PrintAndLogEx(INFO, "       Subtype: " _YELLOW_("0x%02X"), package->versionSW[2]);
    PrintAndLogEx(INFO, "       Version: " _YELLOW_("%d.%d"),  package->versionSW[3], package->versionSW[4]);
    PrintAndLogEx(INFO, "  Storage size: %s", getCardSizeStr(package->versionSW[5]));
    PrintAndLogEx(INFO, "      Protocol: %s", getProtocolStr(package->versionSW[6], false));

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Card capabilities"));
    uint8_t major = package->versionSW[3];
    uint8_t minor = package->versionSW[4];
    if (major == 0 && minor == 4)
        PrintAndLogEx(INFO, "\t0.4 - DESFire MF3ICD40, No support for APDU (only native commands)");
    if (major == 0 && minor == 5)
        PrintAndLogEx(INFO, "\t0.5 - DESFire MF3ICD40, Support for wrapping commands inside ISO 7816 style APDUs");
    if (major == 0 && minor == 6)
        PrintAndLogEx(INFO, "\t0.6 - DESFire MF3ICD40, Add ISO/IEC 7816 command set compatibility");
    if (major == 1 && minor == 3)
        PrintAndLogEx(INFO, "\t1.3 - DESFire Ev1 MF3ICD21/41/81, Support extended APDU commands, EAL4+");
    if (major == 1 && minor == 4)
        PrintAndLogEx(INFO, "\t1.4 - DESFire Ev1 MF3ICD21/41/81, EAL4+, N/A (report to iceman!)");
    if (major == 2 && minor == 0)
        PrintAndLogEx(INFO, "\t2.0 - DESFire Ev2, Originality check, proximity check, EAL5");
//    if (major == 3 && minor == 0)
//        PrintAndLogEx(INFO, "\t3.0 - DESFire Ev3, Originality check, proximity check, badass EAL5");

    if (major == 0 && minor == 2)
        PrintAndLogEx(INFO, "\t0.2 - DESFire Light, Originality check, ");

    if (cardtype == DESFIRE_EV2 || cardtype == DESFIRE_LIGHT || cardtype == DESFIRE_EV3) {
        // Signature originality check
        uint8_t signature[56] = {0};
        size_t signature_len = 0;

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "--- " _CYAN_("Tag Signature"));
        if (handler_desfire_signature(signature, &signature_len) == PM3_SUCCESS) {
            desfire_print_signature(package->uid, signature, signature_len, cardtype);
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
            sprintf(car, "(Access Key: %d)", value);
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
    if (rwa == NULL) return;

    char *wa = DecodeAccessValue(write_access);
    if (wa == NULL) return;

    char *ra = DecodeAccessValue(read_access);
    if (ra == NULL) return;

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
        int recordsize = (src[6] << 16) + (src[5] << 8) + src[4];
        int maxrecords = (src[9] << 16) + (src[8] << 8) + src[7];
        int currentrecord = (src[12] << 16) + (src[11] << 8) + src[10];
        DecodeFileType(filetype);
        DecodeComSet(comset);
        DecodeAccessRights(accrights);
        PrintAndLogEx(INFO, "     Record size: %d (0x%X) - MaxNumberRecords: %d (0x%X) - Current Number Records: %d (0x%X)", recordsize, recordsize, maxrecords, maxrecords, currentrecord, currentrecord);
        return PM3_SUCCESS;
    }
    return PM3_ESOFT;
}

static int CmdHF14ADesDump(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    DropField();
    uint8_t aid[3] = {0};
    uint8_t app_ids[78] = {0};
    uint8_t app_ids_len = 0;

    uint8_t file_ids[33] = {0};
    uint8_t file_ids_len = 0;

    dfname_t dfnames[255];
    uint8_t dfname_count = 0;

    int res = 0;

    if (handler_desfire_appids(app_ids, &app_ids_len) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Can't get list of applications on tag");
        DropField();
        return PM3_ESOFT;
    }

    if (handler_desfire_dfnames(dfnames, &dfname_count) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("Can't get DF Names"));
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "-- Mifare DESFire Dump ----------------------");
    PrintAndLogEx(INFO, "-------------------------------------------------------------");

    for (int i = 0; i < app_ids_len; i += 3) {

        aid[0] = app_ids[i];
        aid[1] = app_ids[i + 1];
        aid[2] = app_ids[i + 2];

        PrintAndLogEx(SUCCESS, "  AID : " _GREEN_("%02X%02X%02X"), aid[2], aid[1], aid[0]);
        PrintAndLogEx(SUCCESS, "  AID Function Cluster 0x%02X: " _YELLOW_("%s"), aid[2], cluster_to_text(aid[2]));

        for (int m = 0; m < dfname_count; m++) {
            if (dfnames[m].aid[0] == aid[0] && dfnames[m].aid[1] == aid[1] && dfnames[m].aid[2] == aid[2]) {
                PrintAndLogEx(SUCCESS, "  -  DF " _YELLOW_("%02X%02X") " Name : " _YELLOW_("%s"), dfnames[m].fid[1], dfnames[m].fid[0], dfnames[m].name);
            }
        }

        uint8_t num_keys = 0;
        uint8_t key_setting = 0;
        res = handler_desfire_getkeysettings(&key_setting, &num_keys);
        if (res != PM3_SUCCESS) return res;

        res = handler_desfire_select_application(aid);

        if (handler_desfire_fileids(file_ids, &file_ids_len) == PM3_SUCCESS) {
            for (int j = file_ids_len - 1; j >= 0; j--) {
                PrintAndLogEx(SUCCESS, "\n\n   Fileid %d (0x%02x)", file_ids[j], file_ids[j]);

                uint8_t filesettings[20] = {0};
                int fileset_len = 0;

                res = handler_desfire_filesettings(file_ids[j], filesettings, &fileset_len);

                if (res == PM3_SUCCESS) {
                    //if (DecodeFileSettings(filesettings, fileset_len, maclen) != PM3_SUCCESS) {
                    if (fileset_len == 1 + 1 + 2 + 3) {
                        int filesize = (filesettings[6] << 16) + (filesettings[5] << 8) + filesettings[4];
                        mfdes_data_t fdata;
                        fdata.fileno = file_ids[j];
                        memset(fdata.offset, 0, 3);
                        //memcpy(fdata.length,&filesettings[4],3);
                        memset(fdata.length, 0, 3);
                        uint8_t *data = (uint8_t *)malloc(filesize);
                        fdata.data = data;
                        if (data) {
                            res = handler_desfire_readdata(&fdata, MFDES_DATA_FILE,filesettings[1]);
                            if (res == PM3_SUCCESS) {
                                PrintAndLogEx(NORMAL, "\nOffset  | Data                                            | Ascii");
                                PrintAndLogEx(NORMAL, "----------------------------------------------------------------------------");
                                int len = le24toh(fdata.length);
                                for (int n = 0; n < len; n += 16) {
                                    PrintAndLogEx(NORMAL, "%02d/0x%02X | %s| %s", n, n, sprint_hex(&fdata.data[n], len > 16 ? 16 : len), sprint_ascii(&fdata.data[n], len > 16 ? 16 : len));
                                }
                                free(data);
                            } else {
                                PrintAndLogEx(ERR, "Couldn't read value. Error %d", res);
                                res = handler_desfire_select_application(aid);
                            }
                        }
                    } else if (fileset_len == 1 + 1 + 2 + 4 + 4 + 4 + 1) {
                        PrintAndLogEx(NORMAL, "\n\nValue file: 0x%0x", file_ids[j]);
                        mfdes_value_t value;
                        value.fileno = file_ids[j];
                        int len = 0;
                        res = handler_desfire_getvalue(&value, &len,filesettings[1]);
                        if (res == PM3_SUCCESS) {
                            PrintAndLogEx(NORMAL, "\nOffset  | Value                                            | Ascii");
                            PrintAndLogEx(NORMAL, "----------------------------------------------------------------------------");
                            for (int n = 0; n < len; n += 16) {
                                PrintAndLogEx(NORMAL, "%02d/0x%02X | %s| %s", n, n, sprint_hex(&value.value[n], len > 16 ? 16 : len), sprint_ascii(&value.value[n], len > 16 ? 16 : len));
                            }
                        } else {
                            PrintAndLogEx(ERR, "Couldn't read value. Error %d", res);
                            res = handler_desfire_select_application(aid);
                        }
                    } else if (fileset_len == 1 + 1 + 2 + 3 + 3 + 3) {
                        int maxrecords = (filesettings[9] << 16) + (filesettings[8] << 8) + filesettings[7];
                        int filesize = (filesettings[6] << 16) + (filesettings[5] << 8) + filesettings[4];
                        mfdes_data_t fdata;
                        fdata.fileno = file_ids[j];
                        memset(fdata.length, 0, 3);
                        //memcpy(fdata.length,&filesettings[4],3);
                        uint8_t *data = (uint8_t *)malloc(filesize);
                        fdata.data = data;
                        if (data) {
                            for (int offset = 0; offset < maxrecords; offset++) {
                                PrintAndLogEx(NORMAL, "\n\nRecord offset: %024x", offset);
                                memset(data, 0, filesize);
                                fdata.offset[0] = offset & 0xFF;
                                fdata.offset[1] = (offset >> 8) & 0xFF;
                                fdata.offset[2] = (offset >> 16) & 0xFF;
                                res = handler_desfire_readdata(&fdata, MFDES_RECORD_FILE,filesettings[1]);
                                if (res == PM3_SUCCESS) {
                                    PrintAndLogEx(NORMAL, "\nOffset  | Data                                            | Ascii");
                                    PrintAndLogEx(NORMAL, "----------------------------------------------------------------------------");
                                    int len = le24toh(fdata.length);
                                    for (int n = 0; n < len; n += 16) {
                                        PrintAndLogEx(NORMAL, "%02d/0x%02X | %s| %s", n, n, sprint_hex(&fdata.data[n], len > 16 ? 16 : len), sprint_ascii(&fdata.data[n], len > 16 ? 16 : len));
                                    }
                                } else {
                                    res = handler_desfire_select_application(aid);
                                }
                            }
                            free(data);
                        }
                    }
                }
            }
        }
    }
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesEnumApplications(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    DropField();
//    uint8_t isOK = 0x00;
    uint8_t aid[3] = {0};
    uint8_t app_ids[78] = {0};
    uint8_t app_ids_len = 0;

    uint8_t file_ids[33] = {0};
    uint8_t file_ids_len = 0;

    dfname_t dfnames[255];
    uint8_t dfname_count = 0;

    int res = 0;

    if (handler_desfire_appids(app_ids, &app_ids_len) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Can't get list of applications on tag");
        DropField();
        return PM3_ESOFT;
    }

    if (handler_desfire_dfnames(dfnames, &dfname_count) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("Can't get DF Names"));
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "-- Mifare DESFire Enumerate applications --------------------");
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    PrintAndLogEx(SUCCESS, " Tag report " _GREEN_("%d") " application%c", app_ids_len / 3, (app_ids_len == 3) ? ' ' : 's');

    for (int i = 0; i < app_ids_len; i += 3) {

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
        PrintAndLogEx(SUCCESS, "  AID Function Cluster 0x%02X: " _YELLOW_("%s"), aid[2], cluster_to_text(aid[2]));

        for (int m = 0; m < dfname_count; m++) {
            if (dfnames[m].aid[0] == aid[0] && dfnames[m].aid[1] == aid[1] && dfnames[m].aid[2] == aid[2]) {
                PrintAndLogEx(SUCCESS, "  -  DF " _YELLOW_("%02X%02X") " Name : " _YELLOW_("%s"), dfnames[m].fid[1], dfnames[m].fid[0], dfnames[m].name);
            }
        }

        res = getKeySettings(aid);
        if (res != PM3_SUCCESS) return res;

        res = handler_desfire_select_application(aid);


        // Get File IDs
        if (handler_desfire_fileids(file_ids, &file_ids_len) == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, " Tag report " _GREEN_("%d") " file%c", file_ids_len, (file_ids_len == 1) ? ' ' : 's');
            for (int j = file_ids_len - 1; j >= 0; j--) {
                PrintAndLogEx(SUCCESS, "   Fileid %d (0x%02x)", file_ids[j], file_ids[j]);

                uint8_t filesettings[20] = {0};
                int fileset_len = 0;
                int maclen = 0; // To be implemented

                res = handler_desfire_filesettings(file_ids[j], filesettings, &fileset_len);
                if (res == PM3_SUCCESS) {
                    if (DecodeFileSettings(filesettings, fileset_len, maclen) != PM3_SUCCESS) {
                        PrintAndLogEx(INFO, "  Settings [%u] %s", fileset_len, sprint_hex(filesettings, fileset_len));
                    }
                }
            }
        }

        /*
                // Get ISO File IDs
                {
                    uint8_t data[] = {GET_ISOFILE_IDS, 0x00, 0x00, 0x00};  // 0x61
                    SendCommandMIX(CMD_HF_DESFIRE_COMMAND, DISCONNECT, sizeof(data), 0, data, sizeof(data));
                }

                if (!WaitForResponseTimeout(CMD_ACK, &respFiles, 1500)) {
                    PrintAndLogEx(WARNING, _RED_("   Timed-out"));
                    continue;
                } else {
                    isOK  = respFiles.data.asBytes[2] & 0xff;
                    if (!isOK) {
                        PrintAndLogEx(WARNING, _RED_("   Can't get ISO file ids"));
                    } else {
                        int respfileLen = resp.oldarg[1] - 3 - 2;
                        for (int j = 0; j < respfileLen; ++j) {
                            PrintAndLogEx(SUCCESS, " ISO  Fileid %d :", resp.data.asBytes[j + 3]);
                        }
                    }
                }
                */
    }
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14ADesChangeKey(const char *Cmd) {
    //DropField();
    // NR  DESC     KEYLENGHT
    // ------------------------
    // 1 = DES      8
    // 2 = 3DES     16
    // 3 = 3K 3DES  24
    // 4 = AES      16
    uint8_t keylength = 8;
    uint8_t newkeylength = 8;

    CLIParserInit("hf mfdes changekey",
                  "Changes Mifare DESFire Key",
                  "Usage:"
                  "\n\thf mfdes changekey -n 0 -t 1 -k 0000000000000000 -u 1 -j 0102030405060708 (DES,keynumber 0)\n"
                  "Make sure to select aid or authenticate aid before running this command.\n"
    );

    void *argtable[] = {
            arg_param_begin,
            arg_int0("nN",  "keyno",  "<keyno>", "Key number used for authentification"),
            arg_int0("tT",  "algo",   "<algo>", "Current key algo (1=DES, 2=3DES(2K2DES), 3=3K3DES, 4=AES)"),
            arg_str0("kK",  "key",     "<Key>", "Current Key (HEX 8-24 bytes)"),
            arg_int0("uU",  "newalgo",   "<newalgo>", "New key algo (1=DES, 2=3DES(2K2DES), 3=3K3DES, 4=AES)"),
            arg_str0("jJ",  "newkey",     "<newkey>", "New Key (HEX 8-24 bytes)"),
            arg_int0("vV",  "aesversion",     "<aesversion>", "Aes version (if aes is used)"),
            arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, false);

    uint8_t cmdKeyNo  = arg_get_int_def(1, 0);
    uint8_t cmdAuthAlgo = arg_get_int_def(2, 0);
    uint8_t key[24] = {0};
    int keylen = 0;
    CLIParamHexToBuf(arg_get_str(3), key, 24, &keylen);
    uint8_t newcmdAuthAlgo = arg_get_int_def(4, 0);
    uint8_t newkey[24] = {0};
    int newkeylen = 0;
    CLIParamHexToBuf(arg_get_str(5), newkey, 24, &newkeylen);
    uint8_t aesversion = arg_get_int_def(6, 0);
    CLIParserFree();

    if (cmdAuthAlgo == MFDES_ALGO_AES) {
        keylength=16;
    } else if (cmdAuthAlgo == MFDES_ALGO_3DES) {
        keylength=16;
    } else if (cmdAuthAlgo == MFDES_ALGO_DES) {
        keylength=8;
    } else if (cmdAuthAlgo == MFDES_ALGO_3K3DES) {
        keylength=24;
    }

    if (newcmdAuthAlgo == MFDES_ALGO_AES) {
        newkeylength=16;
    } else if (newcmdAuthAlgo == MFDES_ALGO_3DES) {
        newkeylength=16;
    } else if (newcmdAuthAlgo == MFDES_ALGO_DES) {
        newkeylength=8;
    } else if (newcmdAuthAlgo == MFDES_ALGO_3K3DES) {
        newkeylength=24;
    }

    if ((keylen < 8) || (keylen > 24)) {
        PrintAndLogEx(ERR, "Specified key must have %d bytes length.", keylen);
        return PM3_EINVARG;
    }

    if ((newkeylen < 8) || (newkeylen > 24)) {
        PrintAndLogEx(ERR, "Specified key must have %d bytes length.", newkeylen);
        return PM3_EINVARG;
    }

    if (keylen != keylength) {
        PrintAndLogEx(WARNING, "Key must include %d HEX symbols", keylength);
        return PM3_EINVARG;
    }

    if (newkeylen != newkeylength) {
        PrintAndLogEx(WARNING, "New key must include %d HEX symbols", keylength);
        return PM3_EINVARG;
    }

    int error=mifare_desfire_change_key(cmdKeyNo,newkey,newcmdAuthAlgo,key,cmdAuthAlgo,aesversion);
    if (error==PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "  Successfully changed key.");
    } else {
        PrintAndLogEx(SUCCESS, "  Error on changing key.");
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}


// MIAFRE DESFire Authentication
//
#define BUFSIZE 256
static int CmdHF14ADesAuth(const char *Cmd) {
    //DropField();
    // NR  DESC     KEYLENGHT
    // ------------------------
    // 1 = DES      8
    // 2 = 3DES     16
    // 3 = 3K 3DES  24
    // 4 = AES      16
    uint8_t keylength = 8;

    CLIParserInit("hf mfdes auth",
                  "Authenticates Mifare DESFire using Key",
                  "Usage:"
                  "\n\thf mfdes auth -m 3 -t 4 -a 808301 -n 0 -k 00000000000000000000000000000000 (AES,keynumber 0, aid 0x803201)"
                  "\n\thf mfdes auth -m 2 -t 2 -a 000000 -n 1 -k 00000000000000000000000000000000 (3DES,keynumber 1, aid 0x000000)"
                  "\n\thf mfdes auth -m 1 -t 1 -a 000000 -n 2 -k 0000000000000000 (DES,keynumber 2, aid 0x000000)"
                  "\n\thf mfdes auth -m 1 -t 1 -a 000000 -n 0 (DES, defaultkey, aid 0x000000)"
                  "\n\thf mfdes auth -m 2 -t 2 -a 000000 -n 0 (3DES, defaultkey, aid 0x000000)"
                  "\n\thf mfdes auth -m 3 -t 4 -a 000000 -n 0 (3K3DES, defaultkey, aid 0x000000)"
                  "\n\thf mfdes auth -m 3 -t 4 -a 000000 -n 0 (AES, defaultkey, aid 0x000000)"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("mM",  "type",   "<type>", "Auth type (1=normal, 2=iso, 3=aes)"),
        arg_int0("tT",  "algo",   "<algo>", "Crypt algo (1=DES, 2=3DES(2K2DES), 3=3K3DES, 4=AES)"),
        arg_strx0("aA",  "aid",    "<aid>", "AID used for authentification (HEX 3 bytes)"),
        arg_int0("nN",  "keyno",  "<keyno>", "Key number used for authentification"),
        arg_str0("kK",  "key",     "<Key>", "Key for checking (HEX 8-24 bytes)"),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, false);

    uint8_t cmdAuthMode = arg_get_int_def(1, 0);
    uint8_t cmdAuthAlgo = arg_get_int_def(2, 0);

    int aidlength = 3;
    uint8_t aid[3] = {0};
    CLIGetHexWithReturn(3, aid, &aidlength);
    swap24(aid);
    uint8_t cmdKeyNo  = arg_get_int_def(4, 0);

    uint8_t key[24] = {0};
    int keylen = 0;
    CLIParamHexToBuf(arg_get_str(5), key, 24, &keylen);
    CLIParserFree();

    if (cmdAuthAlgo == MFDES_ALGO_AES) {
        keylength=16;
    } else if (cmdAuthAlgo == MFDES_ALGO_3DES) {
        keylength=16;
    } else if (cmdAuthAlgo == MFDES_ALGO_DES) {
        keylength=8;
    } else if (cmdAuthAlgo == MFDES_ALGO_3K3DES) {
        keylength=24;
    }
    if (keylen == 0) {
        if (cmdAuthAlgo == MFDES_ALGO_AES) {
            keylen=16;
            memcpy(key,aesdefaultkeys[0],keylen);
        } else if (cmdAuthAlgo == MFDES_ALGO_3DES) {
            keylen=16;
            memcpy(key,aesdefaultkeys[0],keylen);
        } else if (cmdAuthAlgo == MFDES_ALGO_DES) {
            keylen=8;
            memcpy(key,desdefaultkeys[0],keylen);
        } else if (cmdAuthAlgo == MFDES_ALGO_3K3DES) {
            keylen=24;
            memcpy(key,k3kdefaultkeys[0],keylen);
        }
    } else if ((keylen < 8) || (keylen > 24)) {
        PrintAndLogEx(ERR, "Specified key must have %d bytes length.", keylen);
        return PM3_EINVARG;
    }

    if (keylen != keylength) {
        PrintAndLogEx(WARNING, "Key must include %d HEX symbols", keylength);
        return PM3_EINVARG;
    }

    // AID
    if (aidlength != 3) {
        PrintAndLogEx(WARNING, "aid must include %d HEX symbols", 3);
        return PM3_EINVARG;
    }

    mfdes_auth_res_t rpayload;
    int error=desfire_authenticate(cmdAuthMode,cmdAuthAlgo,aid,key,cmdKeyNo,&rpayload);
    if (error==PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "  Key        : " _GREEN_("%s"), sprint_hex(key, keylength));
        PrintAndLogEx(SUCCESS, "  SESSION    : " _GREEN_("%s"), sprint_hex(rpayload.sessionkey, keylength));
        PrintAndLogEx(INFO, "-------------------------------------------------------------");
    } else {
        AuthToError(error);
        return PM3_ESOFT;
    }
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    return PM3_SUCCESS;
}

void DesFill2bPattern(uint8_t deskeyList[MAX_KEYS_LIST_LEN][8], size_t *deskeyListLen, uint8_t aeskeyList[MAX_KEYS_LIST_LEN][16], size_t *aeskeyListLen, uint8_t k3kkeyList[MAX_KEYS_LIST_LEN][24], size_t *k3kkeyListLen, uint32_t *startPattern) {
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
        if ((*deskeyListLen == MAX_KEYS_LIST_LEN) && (*aeskeyListLen == MAX_KEYS_LIST_LEN) && (*k3kkeyListLen == MAX_KEYS_LIST_LEN))
            break;
    }
    (*startPattern)++;
}

static int AuthCheckDesfire(uint8_t *aid, uint8_t deskeyList[MAX_KEYS_LIST_LEN][8], size_t deskeyListLen, uint8_t aeskeyList[MAX_KEYS_LIST_LEN][16], size_t aeskeyListLen, uint8_t k3kkeyList[MAX_KEYS_LIST_LEN][24], size_t k3kkeyListLen, uint8_t foundKeys[4][0xE][24 + 1], bool *result) {
    int res = handler_desfire_select_application(aid);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "AID %X does not exist.");
        return res;
    }

    int usedkeys[0xF] = {0};
    bool des = false;
    bool tdes = false;
    bool aes = false;
    bool k3kdes = false;

    if (memcmp(aid, "\x00\x00\x00", 3) != 0) {
        uint8_t file_ids[33] = {0};
        uint8_t file_ids_len = 0;
        // Get File IDs
        if (handler_desfire_fileids(file_ids, &file_ids_len) == PM3_SUCCESS) {
            for (int j = file_ids_len - 1; j >= 0; j--) {
                uint8_t filesettings[20] = {0};
                int fileset_len = 0;
                res = handler_desfire_filesettings(file_ids[j], filesettings, &fileset_len);
                if (res == PM3_SUCCESS) {
                    uint16_t accrights = (filesettings[3] << 8) + filesettings[2];
                    int change_access_rights = accrights & 0xF;
                    int read_write_access = (accrights >> 4) & 0xF;
                    int write_access = (accrights >> 8) & 0xF;
                    int read_access = (accrights >> 12) & 0xF;
                    if (change_access_rights == 0xE) change_access_rights = 0x0;
                    if (read_write_access == 0xE) read_write_access = 0x0;
                    if (write_access == 0xE) write_access = 0x0;
                    if (read_access == 0xE) read_access = 0x0;
                    usedkeys[change_access_rights] = 1;
                    usedkeys[read_write_access] = 1;
                    usedkeys[write_access] = 1;
                    usedkeys[read_access] = 1;
                    if (res == PM3_SUCCESS) {
                        switch (fileset_len >> 6) {
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
                for (int z = 0; z < 0xE; z++) {
                    usedkeys[z] = 1;
                    des = true;
                    tdes = true;
                    aes = true;
                    k3kdes = true;
                }
            }
        }
    } else des = true;
    int error = PM3_SUCCESS;
    bool badlen = false;

    uint32_t curaid = (aid[0] & 0xFF) + ((aid[1] & 0xFF) << 8) + ((aid[2] & 0xFF) << 16);
    if (des) {
        for (int keyno = 0; keyno < 0xE; keyno++)
            if (usedkeys[keyno] == 1 && foundKeys[0][keyno][0] == 0) {
                for (int curkey = 0; curkey < deskeyListLen; curkey++) {
                    mfdes_auth_res_t rpayload;
                    error=desfire_authenticate(MFDES_AUTH_DES,MFDES_ALGO_DES,aid,deskeyList[curkey],keyno,&rpayload);
                    if (error == PM3_SUCCESS) {
                        PrintAndLogEx(SUCCESS, "AID 0x%06X, Found DES Key %d        : " _GREEN_("%s"), curaid, keyno, sprint_hex(deskeyList[curkey], 8));
                        foundKeys[0][keyno][0] = 0x01;
                        *result = true;
                        memcpy(&foundKeys[0][keyno][1], deskeyList[curkey], 8);
                        break;
                    } else if (error < 7) {
                        badlen = true;
                        DropField();
                        res = handler_desfire_select_application(aid);
                        if (res != PM3_SUCCESS) {
                            PrintAndLogEx(ERR, "AID 0x%06X does not exist", curaid);
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
    if (tdes) {
        for (int keyno = 0; keyno < 0xE; keyno++)
            if (usedkeys[keyno] == 1 && foundKeys[1][keyno][0] == 0) {
                for (int curkey = 0; curkey < aeskeyListLen; curkey++) {
                    mfdes_auth_res_t rpayload;
                    error=desfire_authenticate(MFDES_AUTH_DES,MFDES_ALGO_3DES,aid,aeskeyList[curkey],keyno,&rpayload);

                    if (error == PM3_SUCCESS) {
                        PrintAndLogEx(SUCCESS, "AID 0x%06X, Found 3DES Key %d        : " _GREEN_("%s"), curaid, keyno, sprint_hex(aeskeyList[curkey], 16));
                        foundKeys[1][keyno][0] = 0x01;
                        *result = true;
                        memcpy(&foundKeys[1][keyno][1], aeskeyList[curkey], 16);
                        break;
                    } else if (error < 7) {
                        badlen = true;
                        DropField();
                        res = handler_desfire_select_application(aid);
                        if (res != PM3_SUCCESS) {
                            PrintAndLogEx(ERR, "AID %X does not exist.");
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

    if (aes) {
        for (int keyno = 0; keyno < 0xE; keyno++)
            if (usedkeys[keyno] == 1 && foundKeys[2][keyno][0] == 0) {
                for (int curkey = 0; curkey < aeskeyListLen; curkey++) {
                    mfdes_auth_res_t rpayload;
                    error=desfire_authenticate(MFDES_AUTH_AES,MFDES_ALGO_AES,aid,aeskeyList[curkey],keyno,&rpayload);
                    if (error == PM3_SUCCESS) {
                        PrintAndLogEx(SUCCESS, "AID 0x%06X, Found AES Key %d        : " _GREEN_("%s"), curaid, keyno, sprint_hex(aeskeyList[curkey], 16));
                        foundKeys[2][keyno][0] = 0x01;
                        *result = true;
                        memcpy(&foundKeys[2][keyno][1], aeskeyList[curkey], 16);
                        break;
                    } else if (error < 7) {
                        badlen = true;
                        DropField();
                        res = handler_desfire_select_application(aid);
                        if (res != PM3_SUCCESS) {
                            PrintAndLogEx(ERR, "AID %X does not exist.");
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

    if (k3kdes) {
        for (int keyno = 0; keyno < 0xE; keyno++)
            if (usedkeys[keyno] == 1 && foundKeys[3][keyno][0] == 0) {
                for (int curkey = 0; curkey < k3kkeyListLen; curkey++) {
                    mfdes_auth_res_t rpayload;
                    error=desfire_authenticate(MFDES_AUTH_ISO,MFDES_ALGO_3K3DES,aid,k3kkeyList[curkey],keyno,&rpayload);
                    if (error == PM3_SUCCESS) {
                        PrintAndLogEx(SUCCESS, "AID 0x%06X, Found 3K3 Key %d        : " _GREEN_("%s"), curaid, keyno, sprint_hex(k3kkeyList[curkey], 24));
                        foundKeys[3][keyno][0] = 0x01;
                        *result = true;
                        memcpy(&foundKeys[3][keyno][1], k3kkeyList[curkey], 16);
                        break;
                    } else if (error < 7) {
                        badlen = true;
                        DropField();
                        res = handler_desfire_select_application(aid);
                        if (res != PM3_SUCCESS) {
                            PrintAndLogEx(ERR, "AID %X does not exist.");
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
    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14aDesChk(const char *Cmd) {
    int res;
    uint8_t deskeyList[MAX_KEYS_LIST_LEN][8] = {{0}};
    uint8_t aeskeyList[MAX_KEYS_LIST_LEN][16] = {{0}};
    uint8_t k3kkeyList[MAX_KEYS_LIST_LEN][MAX_KEY_LEN] = {{0}};
    size_t deskeyListLen = 0;
    size_t aeskeyListLen = 0;
    size_t k3kkeyListLen = 0;
    uint8_t foundKeys[4][0xE][24 + 1] = {{{0}}};

    CLIParserInit("hf mfdes chk",
                  "Checks keys with Mifare Desfire card.",
                  "Usage:\n"
                  "    hf mfdes chk -a 123456 -k 000102030405060708090a0b0c0d0e0f -> check key on aid 0x123456\n"
                  "    hf mfdes chk -d mfdes_default_keys -> check keys from dictionary against all existing aid on card\n"
                  "    hf mfdes chk -d mfdes_default_keys -a 123456 -> check keys from dictionary against aid 0x123456\n"
                  "    hf mfdes chk -a 123456 --pattern1b -j keys -> check all 1-byte keys pattern on aid 0x123456 and save found keys to json\n"
                  "    hf mfdes chk -a 123456 --pattern2b --startp2b FA00 -> check all 2-byte keys pattern on aid 0x123456. Start from key FA00FA00...FA00\n");

    void *argtable[] = {
        arg_param_begin,
        arg_strx0("aA",  "aid",      "<aid>", "Use specific AID (3 hex bytes, big endian)"),
        arg_str0("kK",  "key",       "<Key>", "Key for checking (HEX 16 bytes)"),
        arg_str0("dD",  "dict",      "<file>", "File with keys dictionary"),
        arg_lit0(NULL,  "pattern1b", "Check all 1-byte combinations of key (0000...0000, 0101...0101, 0202...0202, ...)"),
        arg_lit0(NULL,  "pattern2b", "Check all 2-byte combinations of key (0000...0000, 0001...0001, 0002...0002, ...)"),
        arg_str0(NULL,  "startp2b",  "<Pattern>", "Start key (2-byte HEX) for 2-byte search (use with `--pattern2b`)"),
        arg_str0("jJ",  "json",      "<file>",  "Json file to save keys"),
        arg_lit0("vV",  "verbose",   "Verbose mode."),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, false);

    int aidlength = 0;
    uint8_t aid[3] = {0};
    CLIGetHexWithReturn(1, aid, &aidlength);
    swap24(aid);
    uint8_t vkey[16] = {0};
    int vkeylen = 0;
    CLIGetHexWithReturn(2, vkey, &vkeylen);

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
            CLIParserFree();
            return PM3_EINVARG;
        }
    }

    uint8_t dict_filename[FILE_PATH_SIZE + 2] = {0};
    int dict_filenamelen = 0;
    if (CLIParamStrToBuf(arg_get_str(3), dict_filename, FILE_PATH_SIZE, &dict_filenamelen)) {
        PrintAndLogEx(FAILED, "File name too long or invalid.");
        CLIParserFree();
        return PM3_EINVARG;
    }

    bool pattern1b = arg_get_lit(4);
    bool pattern2b = arg_get_lit(5);

    if (pattern1b && pattern2b) {
        PrintAndLogEx(ERR, "Pattern search mode must be 2-byte or 1-byte only.");
        CLIParserFree();
        return PM3_EINVARG;
    }

    if (dict_filenamelen && (pattern1b || pattern2b)) {
        PrintAndLogEx(ERR, "Pattern search mode and dictionary mode can't be used in one command.");
        CLIParserFree();
        return PM3_EINVARG;
    }

    uint32_t startPattern = 0x0000;
    uint8_t vpattern[2];
    int vpatternlen = 0;
    CLIGetHexWithReturn(6, vpattern, &vpatternlen);
    if (vpatternlen > 0) {
        if (vpatternlen > 0 && vpatternlen <= 2) {
            startPattern = (vpattern[0] << 8) + vpattern[1];
        } else {
            PrintAndLogEx(ERR, "Pattern must be 2-byte length.");
            CLIParserFree();
            return PM3_EINVARG;
        }
        if (!pattern2b)
            PrintAndLogEx(WARNING, "Pattern entered, but search mode not is 2-byte search.");
    }

    uint8_t jsonname[250] = {0};
    int jsonnamelen = 0;
    if (CLIParamStrToBuf(arg_get_str(7), jsonname, sizeof(jsonname), &jsonnamelen)) {
        PrintAndLogEx(ERR, "Invalid json name.");
        CLIParserFree();
        return PM3_EINVARG;
    }
    jsonname[jsonnamelen] = 0;

    bool verbose = arg_get_lit(8);

    CLIParserFree();

    // 1-byte pattern search mode
    if (pattern1b) {
        for (int i = 0; i < 0x100; i++)
            memset(aeskeyList[i], i, 16);
        for (int i = 0; i < 0x100; i++)
            memset(deskeyList[i], i, 8);
        for (int i = 0; i < 0x100; i++)
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
        uint16_t keycnt = 0;
        res = loadFileDICTIONARYEx((char *)dict_filename, deskeyList, sizeof(deskeyList), NULL, 8, &keycnt, 0, &endFilePosition, true);
        deskeyListLen = keycnt;
        if (endFilePosition)
            PrintAndLogEx(SUCCESS, "First part of des dictionary successfully loaded.");
        endFilePosition = 0;
        res = loadFileDICTIONARYEx((char *)dict_filename, aeskeyList, sizeof(aeskeyList), NULL, 16, &keycnt, 0, &endFilePosition, true);
        aeskeyListLen = keycnt;
        if (endFilePosition)
            PrintAndLogEx(SUCCESS, "First part of aes dictionary successfully loaded.");
        endFilePosition = 0;
        res = loadFileDICTIONARYEx((char *)dict_filename, k3kkeyList, sizeof(k3kkeyList), NULL, 24, &keycnt, 0, &endFilePosition, true);
        k3kkeyListLen = keycnt;
        if (endFilePosition)
            PrintAndLogEx(SUCCESS, "First part of k3kdes dictionary successfully loaded.");
        endFilePosition = 0;

        if (endFilePosition)
            PrintAndLogEx(SUCCESS, "First part of dictionary successfully loaded.");
    }

    if (aeskeyListLen == 0) {
        PrintAndLogEx(ERR, "Aes key list is empty. Nothing to check.");
        return PM3_EINVARG;
    } else {
        PrintAndLogEx(INFO, "Loaded " _YELLOW_("%zu") " aes keys", aeskeyListLen);
    }

    if (deskeyListLen == 0) {
        PrintAndLogEx(ERR, "Des key list is empty. Nothing to check.");
        return PM3_EINVARG;
    } else {
        PrintAndLogEx(INFO, "Loaded " _YELLOW_("%zu") " des keys", deskeyListLen);
    }

    if (k3kkeyListLen == 0) {
        PrintAndLogEx(ERR, "K3k key list is empty. Nothing to check.");
        return PM3_EINVARG;
    } else {
        PrintAndLogEx(INFO, "Loaded " _YELLOW_("%zu") " k3kdes keys", k3kkeyListLen);
    }

    if (!verbose)
        printf("Search keys:\n");

    bool result = false;
    uint8_t app_ids[78] = {0};
    uint8_t app_ids_len = 0;

    if (handler_desfire_appids(app_ids, &app_ids_len) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Can't get list of applications on tag");
        DropField();
        return PM3_ESOFT;
    }

    if (aidlength != 0) {
        memcpy(&app_ids[0], aid, 3);
        app_ids_len = 1;
    }

    for (int x = 0; x < app_ids_len / 3; x++) {
        uint32_t curaid = (app_ids[x * 3] & 0xFF) + ((app_ids[(x * 3) + 1] & 0xFF) << 8) + ((app_ids[(x * 3) + 2] & 0xFF) << 16);
        PrintAndLogEx(ERR, "Checking aid 0x%06X...", curaid);
        res = AuthCheckDesfire(&app_ids[x * 3], deskeyList, deskeyListLen, aeskeyList, aeskeyListLen, k3kkeyList, k3kkeyListLen, foundKeys, &result);
        if (res == PM3_EOPABORTED) {
            break;
        }

        if (pattern2b && startPattern < 0x10000) {
            if (!verbose)
                printf("p");
            aeskeyListLen = 0;
            deskeyListLen = 0;
            k3kkeyListLen = 0;
            DesFill2bPattern(deskeyList, &deskeyListLen, aeskeyList, &aeskeyListLen, k3kkeyList, &k3kkeyListLen, &startPattern);
            continue;
        }
        if (dict_filenamelen && endFilePosition) {
            if (!verbose)
                printf("d");
            uint16_t keycnt = 0;
            res = loadFileDICTIONARYEx((char *)dict_filename, deskeyList, sizeof(deskeyList), NULL, 16, &keycnt, endFilePosition, &endFilePosition, false);
            deskeyListLen = keycnt;
            keycnt = 0;
            res = loadFileDICTIONARYEx((char *)dict_filename, aeskeyList, sizeof(aeskeyList), NULL, 16, &keycnt, endFilePosition, &endFilePosition, false);
            aeskeyListLen = keycnt;
            keycnt = 0;
            res = loadFileDICTIONARYEx((char *)dict_filename, k3kkeyList, sizeof(k3kkeyList), NULL, 16, &keycnt, endFilePosition, &endFilePosition, false);
            k3kkeyListLen = keycnt;
            continue;
        }
    }
    if (!verbose)
        printf("\n");

    // save keys to json
    if ((jsonnamelen > 0) && result) {
        // Mifare Desfire info
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
        saveFileJSON((char *)jsonname, jsfMfDesfireKeys, data, 0xE);
    }

    return PM3_SUCCESS;
}

static int CmdHF14ADesList(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    return CmdTraceList("des");
}

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

static command_t CommandTable[] = {
    {"help",    CmdHelp,                     AlwaysAvailable, "This help"},
    //{"test",    CmdTest,                     AlwaysAvailable, "Test"},
    {"info",    CmdHF14ADesInfo,             IfPm3Iso14443a,  "Tag information"},
    {"list",    CmdHF14ADesList,             AlwaysAvailable, "List DESFire (ISO 14443A) history"},
    {"enum",    CmdHF14ADesEnumApplications, IfPm3Iso14443a,  "Tries enumerate all applications"},
    {"auth",    CmdHF14ADesAuth,             IfPm3Iso14443a,  "Tries a MIFARE DesFire Authentication"},
    {"getuid",    CmdHF14ADesGetUID,        IfPm3Iso14443a,  "Get random uid"},
    {"selectaid",    CmdHF14ADesSelectApp,        IfPm3Iso14443a,  "Select Application ID"},
    {"createaid",    CmdHF14ADesCreateApp,        IfPm3Iso14443a,  "Create Application ID"},
    {"deleteaid",    CmdHF14ADesDeleteApp,        IfPm3Iso14443a,  "Delete Application ID"},
    {"createfile",    CmdHF14ADesCreateFile,        IfPm3Iso14443a,  "Create Standard/Backup File"},
    {"createvaluefile",    CmdHF14ADesCreateValueFile,        IfPm3Iso14443a,  "Create Value File"},
    {"createrecordfile",    CmdHF14ADesCreateRecordFile,        IfPm3Iso14443a,  "Create Linear/Cyclic Record File"},
    {"deletefile",    CmdHF14ADesDeleteFile,        IfPm3Iso14443a,  "Create Delete File"},
    {"clearfile",    CmdHF14ADesClearRecordFile,        IfPm3Iso14443a,  "Clear record File"},
    {"readdata",    CmdHF14ADesReadData,        IfPm3Iso14443a,  "Read data from standard/backup/record file"},
    {"writedata",    CmdHF14ADesWriteData,        IfPm3Iso14443a,  "Write data to standard/backup/record file"},
    {"getvalue",    CmdHF14ADesGetValueData,        IfPm3Iso14443a,  "Get value of file"},
    {"changevalue",    CmdHF14ADesChangeValue,        IfPm3Iso14443a,  "Write value of a value file (credit/debit/clear)"},
    {"changekey",    CmdHF14ADesChangeKey,       IfPm3Iso14443a,  "Change Key"},
    {"formatpicc",    CmdHF14ADesFormatPICC,       IfPm3Iso14443a,  "Format PICC"},
    {"dump",    CmdHF14ADesDump,        IfPm3Iso14443a,  "Dump all files"},
    {"chk",    CmdHF14aDesChk,       IfPm3Iso14443a,  "Check keys"},
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

    Native Cmds
    -----------
    ChangeKeySettings 0x5F
    SetConfiguration
    GetISOFileIDs
    GetCardUID
    ChangeFileSettings

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
