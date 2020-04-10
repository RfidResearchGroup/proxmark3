//-----------------------------------------------------------------------------
// Copyright (C) 2014 Iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency MIFARE Desfire commands
//-----------------------------------------------------------------------------
#include "cmdhfmfdes.h"

#include <stdio.h>
#include <string.h>

#include "commonutil.h"  // ARRAYLEN
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "cmdhw.h"
#include "cmdhf14a.h"
#include "mbedtls/des.h"
#include "crypto/libpcrypto.h"
#include "protocols.h"
#include "mifare.h"         // desfire raw command options
#include "cmdtrace.h"
#include "cliparser/cliparser.h"
#include "emv/apduinfo.h"   // APDU manipulation / errorcodes
#include "emv/emvcore.h"    // APDU logging
#include "util_posix.h"     // msleep
#include "mifare/mifare4.h" // MIFARE Authenticate / MAC

uint8_t key_zero_data[16] = { 0x00 };
uint8_t key_ones_data[16] = { 0x01 };
uint8_t key_defa_data[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
uint8_t key_picc_data[16] = { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f };

#define status(x) ( ((uint16_t)(0x91<<8)) + x )

typedef enum {
    MFDES_AUTH_DES = 1,
    MFDES_AUTH_ISO = 2,
    MFDES_AUTH_AES = 3,
    MFDES_AUTH_PICC = 4
} mifare_des_authmode_t;

typedef enum {
    MFDES_ALGO_DES = 1,
    MFDES_ALGO_3DES = 2,
    MFDES_ALGO_3K3DES = 3,
    MFDES_ALGO_AES = 4
} mifare_des_authalgo_t;

typedef enum {
    UNKNOWN = 0,
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
        sprintf(retStr, "0x%02X ( " _YELLOW_("%d - %d bytes") ")", fsize, usize, lsize);
    else
        sprintf(retStr, "0x%02X ( " _YELLOW_("%d bytes") ")", fsize, lsize);
    return buf;
}

static char *getProtocolStr(uint8_t id, bool hw) {

   static char buf[50] = {0x00};
    char *retStr = buf;

    if (id == 0x04) {
        sprintf(retStr, "0x%02X ( " _YELLOW_("ISO 14443-3 MIFARE, 14443-4") ")", id);
    } else if (id == 0x05) {
      if (hw)
            sprintf(retStr, "0x%02X ( " _YELLOW_("ISO 14443-2, 14443-3") ")", id);
        else
            sprintf(retStr, "0x%02X ( " _YELLOW_("ISO 14443-3, 14443-4") ")", id);
    } else {
        sprintf(retStr, "0x%02X ( " _YELLOW_("Unknown") ")", id);
    }
    return buf;
}

static char *getVersionStr(uint8_t major, uint8_t minor) {

    static char buf[40] = {0x00};
    char *retStr = buf;

    if (major == 0x00)
        sprintf(retStr, "%x.%x ( " _YELLOW_("DESFire MF3ICD40") ")", major, minor);
    else if (major == 0x01 && minor == 0x00)
        sprintf(retStr, "%x.%x ( " _YELLOW_("DESFire EV1") ")", major, minor);
    else if (major == 0x12 && minor == 0x00)
        sprintf(retStr, "%x.%x ( " _YELLOW_("DESFire EV2") ")", major, minor);
//    else if (major == 0x13 && minor == 0x00)
//        sprintf(retStr, "%x.%x ( " _YELLOW_("DESFire EV3") ")", major, minor);
    else if (major == 0x30 && minor == 0x00)
        sprintf(retStr, "%x.%x ( " _YELLOW_("DESFire Light") ")", major, minor);
    else
        sprintf(retStr, "%x.%x ( " _YELLOW_("Unknown") ")", major, minor);
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
    /*if (dest == NULL) {
        PrintAndLogEx(DEBUG, "DEST=NULL");
        return PM3_EINVARG;
    }*/
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
        return res;
    }
    if (dest != NULL) {
        memcpy(dest, data, resplen);
    }

    pos += resplen;
    if (!readalldata) {
        if (*sw == status(MFDES_ADDITIONAL_FRAME)) {
            apdu->INS = MFDES_ABORT_TRANSACTION;
            apdu->Lc = 0;
            apdu->P1 = 0;
            apdu->P2 = 0;
            res = DESFIRESendApdu(false, true, *apdu, data, sizeof(data), &resplen, sw);
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

    *recv_len =  (splitbysize) ? i : pos;
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
    if (major == 0x11 &&  minor == 0x00 )
        return PLUS_EV1;

    return UNKNOWN;
}

// -- test if card supports 0x0A
static int test_desfire_authenticate() {
    uint8_t data[] = {0x00};
    sAPDU apdu = {0x90, MFDES_AUTHENTICATE, 0x00, 0x00, 0x01, data}; // 0x0A, KEY 0
    int recv_len = 0;
    uint16_t sw = 0;
    return send_desfire_cmd(&apdu, false, NULL, &recv_len, &sw, 0, false);
}

// -- test if card supports 0x1A
static int test_desfire_authenticate_iso() {
    uint8_t data[] = {0x00};
    sAPDU apdu = {0x90, MFDES_AUTHENTICATE_ISO, 0x00, 0x00, 0x01, data}; // 0x1A, KEY 0
    int recv_len = 0;
    uint16_t sw = 0;
    return send_desfire_cmd(&apdu, false, NULL, &recv_len, &sw, 0, false);
}

// -- test if card supports 0xAA
static int test_desfire_authenticate_aes() {
    uint8_t data[] = {0x00};
    sAPDU apdu = {0x90, MFDES_AUTHENTICATE_AES, 0x00, 0x00, 0x01, data}; // 0xAA, KEY 0
    int recv_len = 0;
    uint16_t sw = 0;
    return send_desfire_cmd(&apdu, false, NULL, &recv_len, &sw, 0, false);
}

// --- GET FREE MEM
static int desfire_print_freemem(uint32_t free_mem) {
    PrintAndLogEx(SUCCESS, "   Available free memory on card         : " _GREEN_("%d bytes"), free_mem);
    return PM3_SUCCESS;
}

static int get_desfire_freemem(uint32_t *free_mem) {
    if (free_mem == NULL) return PM3_EINVARG;

    sAPDU apdu = {0x90, MFDES_GET_FREE_MEMORY, 0x00, 0x00, 0x00, NULL}; // 0x6E
    *free_mem = 0;
    int recv_len = 0;
    uint16_t sw = 0;
    uint8_t fmem[4] = {0};

    int res = send_desfire_cmd(&apdu, true, fmem, &recv_len, &sw, 0, true);

    if (res != PM3_SUCCESS )
        return res;
    
    if (sw != status(MFDES_S_OPERATION_OK))
        return PM3_ESOFT;
    
    *free_mem = le24toh(fmem);
    return res;
}

// --- GET SIGNATURE
static int desfire_print_signature(uint8_t *uid, uint8_t *signature, size_t signature_len, nxp_cardtype_t card_type) {

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

static int get_desfire_signature(uint8_t *signature, size_t *signature_len) {

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
static int desfire_print_keysetting(uint8_t key_settings, uint8_t num_keys) {

    PrintAndLogEx(SUCCESS, "  AID Key settings           : 0x%02x", key_settings);
    PrintAndLogEx(SUCCESS, "  Max number of keys in AID  : %d", num_keys);
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    PrintAndLogEx(SUCCESS, "  Changekey Access rights");

    // Access rights.
    uint8_t rights = (key_settings >> 4 & 0x0F);
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

static int get_desfire_keysettings(uint8_t *key_settings, uint8_t *num_keys) {
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

    if (res != PM3_SUCCESS )
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

static int get_desfire_keyversion(uint8_t curr_key, uint8_t *num_versions) {
    if (num_versions == NULL) {
        PrintAndLogEx(DEBUG, "NUM_VERSIONS=NULL");
        return PM3_EINVARG;
    }
    sAPDU apdu = {0x90, MFDES_GET_KEY_VERSION, 0x00, 0x00, 0x01, &curr_key}; //0x64
    int recv_len = 0;
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, false, num_versions, &recv_len, &sw, 0, true);
    
    if (res != PM3_SUCCESS )
        return res;

    if (sw != status(MFDES_S_OPERATION_OK))
        return PM3_ESOFT;

    return res;
}

// --- GET APPIDS
static int get_desfire_appids(uint8_t *dest, uint8_t *app_ids_len) {
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
 
    if (res != PM3_SUCCESS )
        return res;

    if (sw != status(MFDES_S_OPERATION_OK))
        return PM3_ESOFT;

    *app_ids_len = (uint8_t)recv_len & 0xFF;
    return res;
}

// --- GET DF NAMES
static int get_desfire_dfnames(dfname_t *dest, uint8_t *dfname_count) {
    if (g_debugMode > 1) {
        if (dest == NULL) PrintAndLogEx(ERR, "DEST=NULL");
        if (dfname_count == NULL) PrintAndLogEx(ERR, "DFNAME_COUNT=NULL");
    }
    if (dest == NULL || dfname_count == NULL) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_GET_DF_NAMES, 0x00, 0x00, 0x00, NULL}; //0x6d
    int recv_len = 0;
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, true, (uint8_t *)dest, &recv_len, &sw, sizeof(dfname_t), true);
    if (res != PM3_SUCCESS)
        return res;
    if (sw != status(MFDES_S_OPERATION_OK))
        return PM3_ESOFT;
    *dfname_count = recv_len;
    return res;
}

static int get_desfire_select_application(uint8_t *aid) {
    if (g_debugMode > 1) {
        if (aid == NULL) PrintAndLogEx(ERR, "AID=NULL");
    }
    if (aid == NULL) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_SELECT_APPLICATION, 0x00, 0x00, 0x03, aid}; //0x5a
    int recv_len = 0;
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, true, NONE, &recv_len, &sw, sizeof(dfname_t), true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't select AID 0x%X -> %s"), (aid[2] << 16) + (aid[1] << 8) + aid[0], GetErrorString(res, &sw));
        DropField();
        return res;
    }
    return PM3_SUCCESS;
}

// none, verified
static int get_desfire_fileids(uint8_t *dest, uint8_t *file_ids_len) {
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
static int get_desfire_filesettings(uint8_t file_id, uint8_t *dest, int *destlen) {
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

static int get_desfire_createapp(aidhdr_t *aidhdr) {
    if (aidhdr == NULL) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_CREATE_APPLICATION, 0x00, 0x00, sizeof(aidhdr_t), (uint8_t *)aidhdr}; // 0xCA
    uint16_t sw = 0;
    int recvlen = 0;
    int res = send_desfire_cmd(&apdu, false, NULL, &recvlen, &sw, 0, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't create aid -> %s"), GetErrorString(res, &sw));
        DropField();
        return res;
    }
    return res;
}

static int get_desfire_deleteapp(uint8_t *aid) {
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

int getKeySettings(uint8_t *aid) {
    if (aid == NULL) return PM3_EINVARG;

    int res = 0;
    if (memcmp(aid, "\x00\x00\x00", 3) == 0) {

        // CARD MASTER KEY
        //PrintAndLogEx(INFO, "--- " _CYAN_("CMK - PICC, Card Master Key settings"));
        res = get_desfire_select_application(aid);
        if (res != PM3_SUCCESS) return res;

        // KEY Settings - AMK
        uint8_t num_keys = 0;
        uint8_t key_setting = 0;
        res = get_desfire_keysettings(&key_setting, &num_keys);
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

        // 2 MSB denotes
        switch (num_keys >> 6) {
            case 0:
                PrintAndLogEx(SUCCESS, str, "(3)DES");
                break;
            case 1:
                PrintAndLogEx(SUCCESS, str, "3K3DES");
                break;
            case 2:
                PrintAndLogEx(SUCCESS, str, "AES");
                break;
            default:
                break;
        }

        uint8_t cmk_num_versions = 0;
        if (get_desfire_keyversion(0, &cmk_num_versions) == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "   PICC Master key Version               : " _YELLOW_("%d (0x%02x)"), cmk_num_versions, cmk_num_versions);
            PrintAndLogEx(INFO, "   ----------------------------------------------------------");
        }

        // Authentication tests
        int res = test_desfire_authenticate();
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
        res = get_desfire_select_application(aid);
        if (res != PM3_SUCCESS) return res;

        // KEY Settings - AMK
        uint8_t num_keys = 0;
        uint8_t key_setting = 0;
        res = get_desfire_keysettings(&key_setting, &num_keys);
        if (res == PM3_SUCCESS) {
            desfire_print_keysetting(key_setting, num_keys);
        } else {
            PrintAndLogEx(WARNING, _RED_("   Can't read Application Master key settings"));
        }

        // KEY VERSION  - AMK
        uint8_t num_version = 0;
        if (get_desfire_keyversion(0, &num_version) == PM3_SUCCESS) {
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
                if (get_desfire_keyversion(i, &num_version) == PM3_SUCCESS) {
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

static void swap24(uint8_t* data){
    if (data==NULL) return;
    uint8_t tmp=data[0];
    data[0]=data[2];
    data[2]=tmp;
};

static void swap16(uint8_t* data){
        if (data==NULL) return;
        uint8_t tmp=data[0];
        data[0]=data[1];
        data[1]=tmp;
};


static int CmdHF14ADesCreateApp(const char *Cmd) {
    CLIParserInit("hf mfdes createaid",
                  "Create Application ID",
                  "Usage:\n\thf mfdes createaid -a 123456 -f 1122 -k 0F -l 2E -n AppName\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_strx0("aA",  "aid",    "<aid>", "App ID to create as hex bytes ("),
        arg_strx0("fF",  "fid",    "<fid>", "File ID to create"),
        arg_strx0("kK",  "keysetting1",    "<keysetting1>", "Key Setting 1 (Application Master Key Settings)"),
        arg_strx0("lL",  "keysetting2",    "<keysetting2>", "Key Setting 2"),
        arg_str0("nN",  "name",    "<name>", "App ISO-4 Name"),
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
       0..3: Number of keys stored within the application (max. 14 keys
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
    swap24(aid);
    CLIGetHexWithReturn(2, fid, &fidlength);
    swap16(fid);
    CLIGetHexWithReturn(3, &keysetting1, &keylen1);
    CLIGetHexWithReturn(4, &keysetting2, &keylen2);
    CLIGetStrWithReturn(5, name, &namelen);
    CLIParserFree();

    if (aidlength < 3) {
        PrintAndLogEx(ERR, "AID must have 3 bytes length.");
        return PM3_SNONCES;
    }

    if (fidlength < 2) {
        PrintAndLogEx(ERR, "FID must have 2 bytes length.");
        return PM3_SNONCES;
    }

    if (keylen1 < 1) {
        PrintAndLogEx(ERR, "Keysetting1 must have 1 byte length.");
        return PM3_SNONCES;
    }

    if (keylen1 < 1) {
        PrintAndLogEx(ERR, "Keysetting2 must have 1 byte length.");
        return PM3_SNONCES;
    }

    if (namelen > 16) {
        PrintAndLogEx(ERR, "Name has a max. of 16 bytes length.");
        return PM3_SNONCES;
    }

    //90 ca 00 00 0e 3cb849 09 22 10e1 d27600 00850101 00
    /*char name[]="Test";
    uint8_t aid[]={0x12,0x34,0x56};
    uint8_t fid[]={0x11,0x22};
    uint8_t keysetting1=0xEE;
    uint8_t keysetting2=0xEE;*/

    if (memcmp(aid, "\x00\x00\x00", 3) == 0) {
        PrintAndLogEx(WARNING, _RED_("   Creating root aid 000000 is forbidden."));
        return PM3_ESOFT;
    }

    aidhdr_t aidhdr;
    memcpy(aidhdr.aid, aid, sizeof(aid));
    aidhdr.keysetting1 = keysetting1;
    aidhdr.keysetting2 = keysetting2;
    memcpy(aidhdr.fid, fid, sizeof(fid));
    memcpy(aidhdr.name, name, sizeof(name));

    uint8_t rootaid[3] = {0x00, 0x00, 0x00};
    int res = get_desfire_select_application(rootaid);
    if (res != PM3_SUCCESS) return res;

    return get_desfire_createapp(&aidhdr);
}

static int CmdHF14ADesDeleteApp(const char *Cmd) {
    CLIParserInit("hf mfdes deleteaid",
                  "Delete Application ID",
                  "Usage:\n\t-a aid (3 bytes)\n\n"
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

    if (aidlength < 3) {
        PrintAndLogEx(ERR, "AID must have 3 bytes length.");
        return PM3_SNONCES;
    }

    if (memcmp(aid, "\x00\x00\x00", 3) == 0) {
        PrintAndLogEx(WARNING, _RED_("   Deleting root aid 000000 is forbidden."));
        return PM3_ESOFT;
    }

    uint8_t rootaid[3] = {0x00, 0x00, 0x00};
    int res = get_desfire_select_application(rootaid);
    if (res != PM3_SUCCESS) return res;
    return get_desfire_deleteapp(aid);
}


static int CmdHF14ADesFormatPICC(const char *Cmd) {
    CLIParserInit("hf mfdes formatpicc",
                  "Formats MIFARE DESFire PICC to factory state",
                  "Usage:\n\t-k PICC key (8 bytes)\n\n"
                  "Example:\n\thf mfdes formatpicc -k 0000000000000000\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("kK",  "key",     "<Key>", "Key for checking (HEX 16 bytes)"),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, false);

    uint8_t key[8] = {0};
    int keylen = 8;
    CLIGetHexWithReturn(1, key, &keylen);
    CLIParserFree();

    if ((keylen < 8) || (keylen > 8)) {
        PrintAndLogEx(ERR, "Specified key must have 8 bytes length.");
        return PM3_SNONCES;
    }

    DropField();
    uint8_t aid[3] = {0};
    int res = get_desfire_select_application(aid);
    if (res != PM3_SUCCESS) return res;
    struct {
        uint8_t mode;
        uint8_t algo;
        uint8_t keyno;
        uint8_t key[24];
        uint8_t keylen;
    } PACKED payload;
    payload.keylen = keylen;
    memcpy(payload.key, key, keylen);
    payload.mode = MFDES_AUTH_PICC;
    payload.algo = MFDES_ALGO_DES;
    payload.keyno = 0;
    SendCommandNG(CMD_HF_DESFIRE_AUTH1, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;

    if (!WaitForResponseTimeout(CMD_HF_DESFIRE_AUTH1, &resp, 3000)) {
        PrintAndLogEx(WARNING, "Client command execute timeout");
        DropField();
        return PM3_ETIMEOUT;
    }

    uint8_t isOK  = (resp.status == PM3_SUCCESS);
    if (isOK) {
        struct {
            uint8_t flags;
            uint8_t datalen;
            uint8_t datain[FRAME_PAYLOAD_SIZE];
        } PACKED payload;
        payload.datain[0] = 0xFC;
        payload.flags = NONE;
        payload.datalen = 1;
        SendCommandNG(CMD_HF_DESFIRE_COMMAND, (uint8_t *)&payload, sizeof(payload));
        if (!WaitForResponseTimeout(CMD_HF_DESFIRE_COMMAND, &resp, 3000)) {
            PrintAndLogEx(WARNING, "Client reset command execute timeout");
            DropField();
            return PM3_ETIMEOUT;
        }
        if (resp.status == PM3_SUCCESS) {
            /*struct r {
                uint8_t len;
                uint8_t data[RECEIVE_SIZE];
            } PACKED;
            struct r *rpayload = (struct r *)&resp.data.asBytes;*/
            PrintAndLogEx(INFO, "Card successfully reset");
            return PM3_SUCCESS;
        }
    } else {
        PrintAndLogEx(WARNING, _RED_("Auth command failed."));
    }

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
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") "---------------------------");
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    PrintAndLogEx(SUCCESS, "              UID: " _GREEN_("%s"), sprint_hex(package->uid, sizeof(package->uid)));
    PrintAndLogEx(SUCCESS, "     Batch number: " _GREEN_("%s"), sprint_hex(package->details + 7, 5));
    PrintAndLogEx(SUCCESS, "  Production date: week " _GREEN_("%02x") "/ " _GREEN_("20%02x"), package->details[12], package->details[13]);
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
        if (get_desfire_signature(signature, &signature_len) == PM3_SUCCESS) {
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
        if (get_desfire_freemem(&free_mem) == PM3_SUCCESS) {
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

    uint16_t accrights = (src[4] << 8) + src[3];
    if (src_len == 1 + 1 + 2 + 3 + maclen) {
        int filesize = (src[7] << 16) + (src[6] << 8) + src[5];
        DecodeFileType(filetype);
        DecodeComSet(comset);
        DecodeAccessRights(accrights);
        PrintAndLogEx(INFO, "     Filesize: %d", filesize);
        return PM3_SUCCESS;
    } else if (src_len == 1 + 1 + 2 + 4 + 4 + 4 + 1 + maclen) {
        int lowerlimit = (src[8] << 24) + (src[7] << 16) + (src[6] << 8) + src[5];
        int upperlimit = (src[12] << 24) + (src[11] << 16) + (src[10] << 8) + src[9];
        int limitcredvalue = (src[16] << 24) + (src[15] << 16) + (src[14] << 8) + src[13];
        uint8_t limited_credit_enabled = src[17];
        DecodeFileType(filetype);
        DecodeComSet(comset);
        DecodeAccessRights(accrights);
        PrintAndLogEx(INFO, "     Lower limit: %d - Upper limit: %d - limited credit value: %d - limited credit enabled: %d", lowerlimit, upperlimit, limitcredvalue, limited_credit_enabled);
        return PM3_SUCCESS;
    }
    return PM3_ESOFT;
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

    if (get_desfire_appids(app_ids, &app_ids_len) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Can't get list of applications on tag");
        DropField();
        return PM3_ESOFT;
    }

    if (get_desfire_dfnames(dfnames, &dfname_count) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("Can't get DF Names"));
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "-- Mifare DESFire Enumerate applications --------------------");
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    PrintAndLogEx(SUCCESS, " Tag report " _GREEN_("%d") "application%c", app_ids_len / 3, (app_ids_len == 3) ? ' ' : 's');

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
        for (int m = 0; m < dfname_count; m++) {
            if (dfnames[m].aid[0] == aid[0] && dfnames[m].aid[1] == aid[1] && dfnames[m].aid[2] == aid[2]) {
                PrintAndLogEx(SUCCESS, "  -  DF " _YELLOW_("%02X%02X") " Name : " _YELLOW_("%s"), dfnames[m].fid[1], dfnames[m].fid[0], dfnames[m].name);
            }
        }

        res = getKeySettings(aid);
        if (res != PM3_SUCCESS) return res;

        res = get_desfire_select_application(aid);


        // Get File IDs
        if (get_desfire_fileids(file_ids, &file_ids_len) == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, " Tag report " _GREEN_("%d") "file%c", file_ids_len, (file_ids_len == 1) ? ' ' : 's');
            for (int j = 0; j < file_ids_len; ++j) {
                PrintAndLogEx(SUCCESS, "   Fileid %d (0x%02x)", file_ids[j], file_ids[j]);

                uint8_t filesettings[20] = {0};
                int fileset_len = 0;
                int res = get_desfire_filesettings(j, filesettings, &fileset_len);
                int maclen = 0; // To be implemented
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

// MIAFRE DESFire Authentication
//
#define BUFSIZE 256
static int CmdHF14ADesAuth(const char *Cmd) {
    int res = 0;
    DropField();
    // NR  DESC     KEYLENGHT
    // ------------------------
    // 1 = DES      8
    // 2 = 3DES     16
    // 3 = 3K 3DES  24
    // 4 = AES      16
    uint8_t keylength = 8;

    CLIParserInit("hf mfdes auth",
                  "Authenticates Mifare DESFire using Key",
                  "Usage:\n\t-m Auth type (1=normal, 2=iso, 3=aes)\n\t-t Crypt algo (1=DES, 2=3DES, 3=3K3DES, 4=aes)\n\t-a aid (3 bytes)\n\t-n keyno\n\t-k key (8-24 bytes)\n\n"
                  "Example:\n\thf mfdes auth -m 3 -t 4 -a 018380 -n 0 -k 404142434445464748494a4b4c4d4e4f\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("mM",  "type",   "Auth type (1=normal, 2=iso, 3=aes, 4=picc)", NULL),
        arg_int0("tT",  "algo",   "Crypt algo (1=DES, 2=3DES, 3=3K3DES, 4=aes)", NULL),
        arg_strx0("aA",  "aid",    "<aid>", "AID used for authentification (HEX 3 bytes)"),
        arg_int0("nN",  "keyno",  "Key number used for authentification", NULL),
        arg_str0("kK",  "key",     "<Key>", "Key for checking (HEX 16 bytes)"),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, false);

    uint8_t cmdAuthMode = arg_get_int_def(1, 0);
    uint8_t cmdAuthAlgo = arg_get_int_def(2, 0);

    int aidlength = 3;
    uint8_t aid[3] = {0};
    CLIGetHexWithReturn(3, aid, &aidlength);
    swap16(aid);
    uint8_t cmdKeyNo  = arg_get_int_def(4, 0);

    uint8_t key[24] = {0};
    int keylen = 0;
    CLIGetHexWithReturn(5, key, &keylen);
    CLIParserFree();

    if ((keylen < 8) || (keylen > 24)) {
        PrintAndLogEx(ERR, "Specified key must have 16 bytes length.");
        return PM3_SNONCES;
    }

    // AID
    if (aidlength != 3) {
        PrintAndLogEx(WARNING, "aid must include %d HEX symbols", 3);
        return PM3_SNONCES;
    }

    switch (cmdAuthMode) {
        case 1:
            if (cmdAuthAlgo != 1 && cmdAuthAlgo != 2) {
                PrintAndLogEx(NORMAL, "Crypto algo not valid for the auth mode");
                return PM3_SNONCES;
            }
            break;
        case 2:
            if (cmdAuthAlgo != 1 && cmdAuthAlgo != 2 && cmdAuthAlgo != 3) {
                PrintAndLogEx(NORMAL, "Crypto algo not valid for the auth mode");
                return PM3_SNONCES;
            }
            break;
        case 3:
            if (cmdAuthAlgo != 4) {
                PrintAndLogEx(NORMAL, "Crypto algo not valid for the auth mode");
                return PM3_SNONCES;
            }
            break;
        default:
            PrintAndLogEx(WARNING, "Wrong Auth mode (%d) -> (1=normal, 2=iso, 3=aes)", cmdAuthMode);
            return PM3_SNONCES;
    }

    switch (cmdAuthAlgo) {
        case 2:
            keylength = 16;
            PrintAndLogEx(NORMAL, "3DES selected");
            break;
        case 3:
            keylength = 24;
            PrintAndLogEx(NORMAL, "3 key 3DES selected");
            break;
        case 4:
            keylength = 16;
            PrintAndLogEx(NORMAL, "AES selected");
            break;
        default:
            cmdAuthAlgo = 1;
            keylength = 8;
            PrintAndLogEx(NORMAL, "DES selected");
            break;
    }

    // KEY
    if (keylen != keylength) {
        PrintAndLogEx(WARNING, "Key must include %d HEX symbols", keylength);
        return PM3_SNONCES;
    }


    res = get_desfire_select_application(aid);
    if (res != PM3_SUCCESS) return res;

    if (memcmp(aid, "\x00\x00\x00", 3) != 0) {
        uint8_t file_ids[33] = {0};
        uint8_t file_ids_len = 0;
        res = get_desfire_fileids(file_ids, &file_ids_len);
        if (res != PM3_SUCCESS) return res;
    }

    struct {
        uint8_t mode;
        uint8_t algo;
        uint8_t keyno;
        uint8_t key[24];
        uint8_t keylen;
    } PACKED payload;
    payload.keylen = keylength;
    memcpy(payload.key, key, keylength);
    payload.mode = cmdAuthMode;
    payload.algo = cmdAuthAlgo;
    payload.keyno = cmdKeyNo;
    SendCommandNG(CMD_HF_DESFIRE_AUTH1, (uint8_t *)&payload, sizeof(payload));

    PacketResponseNG resp;

    if (!WaitForResponseTimeout(CMD_HF_DESFIRE_AUTH1, &resp, 3000)) {
        PrintAndLogEx(WARNING, "Client command execute timeout");
        DropField();
        return PM3_ETIMEOUT;
    }

    uint8_t isOK  = (resp.status == PM3_SUCCESS);
    if (isOK) {
        struct r {
            uint8_t sessionkeylen;
            uint8_t sessionkey[24];
        } PACKED;

        struct r *rpayload = (struct r *)&resp.data.asBytes;
        uint8_t *session_key = rpayload->sessionkey;
        PrintAndLogEx(SUCCESS, "  Key        : " _GREEN_("%s"), sprint_hex(key, keylength));
        PrintAndLogEx(SUCCESS, "  SESSION    : " _GREEN_("%s"), sprint_hex(session_key, keylength));
        PrintAndLogEx(INFO, "-------------------------------------------------------------");
    } else {
        PrintAndLogEx(WARNING, _RED_("Client command failed, reason: %d."), resp.status);
    }
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    return PM3_SUCCESS;
}

static int CmdHF14ADesList(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    return CmdTraceList("des");
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,                     AlwaysAvailable, "This help"},
    {"info",    CmdHF14ADesInfo,             IfPm3Iso14443a,  "Tag information"},
    {"list",    CmdHF14ADesList,             AlwaysAvailable, "List DESFire (ISO 14443A) history"},
    {"enum",    CmdHF14ADesEnumApplications, IfPm3Iso14443a,  "Tries enumerate all applications"},
    {"auth",    CmdHF14ADesAuth,             IfPm3Iso14443a,  "Tries a MIFARE DesFire Authentication"},
    {"createaid",    CmdHF14ADesCreateApp,        IfPm3Iso14443a,  "Create Application ID"},
    {"deleteaid",    CmdHF14ADesDeleteApp,        IfPm3Iso14443a,  "Delete Application ID"},
    {"formatpicc",    CmdHF14ADesFormatPICC,       IfPm3Iso14443a,  "Format PICC"},
//    {"rdbl",    CmdHF14ADesRb,               IfPm3Iso14443a,  "Read MIFARE DesFire block"},
//    {"wrbl",    CmdHF14ADesWb,               IfPm3Iso14443a,  "write MIFARE DesFire block"},
/*
    ISO/IEC 7816 Cmds
    'A4' Select
    'B0' Read Binary
    'D6' Update Binary
    'B2' Read Records
    'E2' Append Records
    '84' Get Challenge
    '88' Internal Authenticate
    '82' External Authenticate

*/
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
