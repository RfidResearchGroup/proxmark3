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
    UNKNOWN = 0,
    MF3ICD40,
    EV1,
    EV2,
    EV3,
    LIGHT,
} desfire_cardtype_t;

typedef struct {
    uint8_t aid[3];
    uint8_t fid[2];
    uint8_t name[16];
} dfname_t;

static int CmdHelp(const char *Cmd);

/*
         uint8_t cmd[3 + 16] = {0xa8, 0x90, 0x90, 0x00};
                int res = ExchangeRAW14a(cmd, sizeof(cmd), false, false, data, sizeof(data), &datalen, false);

                if (!res && datalen > 1 && data[0] == 0x09) {
                    SLmode = 0;
                }

*/

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

    if (isw != 0x9000 && isw != status(MFDES_OPERATION_OK) && isw != status(MFDES_ADDITIONAL_FRAME) && isw != status(MFDES_NO_CHANGES)) {
        if (GetAPDULogging()) {
            if (isw >> 8 == 0x61) {
                PrintAndLogEx(ERR, "APDU chaining len: 0x%02x -->", isw & 0xff);
            } else {
                PrintAndLogEx(ERR, "APDU(%02x%02x) ERROR: [0x%4X] %s", apdu.CLA, apdu.INS, isw, GetAPDUCodeDescription(isw >> 8, isw & 0xff));
                return PM3_EAPDU_FAIL;
            }
        }
    }
    return PM3_SUCCESS;
}

static char* GetErrorString(int res)
{
    switch(res){
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

static int getstatus(int res, uint16_t * sw)
{
    if (sw==NULL) return PM3_EINVARG;

    if (res==PM3_EAPDU_FAIL)
    {
        if (((*sw>>8)&0xFF)==0x91){
            switch (*sw&0xFF){
                case MFDES_E_OUT_OF_EEPROM:
                    PrintAndLogEx(ERR, "APDU error: 0x%02x --> Out of Eeprom, insufficient NV-Memory to complete command", *sw & 0xff);
                    break;
                case MFDES_E_ILLEGAL_COMMAND_CODE:
                    PrintAndLogEx(ERR, "APDU error: 0x%02x --> Command code not supported", *sw & 0xff);
                    break;
                case MFDES_E_INTEGRITY_ERROR:
                    PrintAndLogEx(ERR, "APDU error: 0x%02x --> CRC or MAC does not match data / Padding bytes invalid", *sw & 0xff);
                    break;
                case MFDES_E_NO_SUCH_KEY:
                    PrintAndLogEx(ERR, "APDU error: 0x%02x --> Invalid key number specified", *sw & 0xff);
                    break;
                case MFDES_E_LENGTH:
                    PrintAndLogEx(ERR, "APDU error: 0x%02x --> Length of command string invalid", *sw & 0xff);
                    break;
                case MFDES_E_PERMISSION_DENIED:
                    PrintAndLogEx(ERR, "APDU error: 0x%02x --> Current configuration/status does not allow the requested command", *sw & 0xff);
                    break;
                case MFDES_E_PARAMETER_ERROR:
                    PrintAndLogEx(ERR, "APDU error: 0x%02x --> Value of the parameter(s) invalid", *sw & 0xff);
                    break;
                case MFDES_E_APPLICATION_NOT_FOUND:
                    PrintAndLogEx(ERR, "APDU error: 0x%02x --> Requested AID not present on PICC", *sw & 0xff);
                    break;
                case MFDES_E_APPL_INTEGRITY:
                    PrintAndLogEx(ERR, "APDU error: 0x%02x --> Application integrity error, application will be disabled", *sw & 0xff);
                    break;
                case MFDES_E_AUTHENTIFICATION_ERROR:
                    PrintAndLogEx(ERR, "APDU error: 0x%02x --> Current authentication status does not allow the requested command", *sw & 0xff);
                    break;
                case MFDES_E_BOUNDARY:
                    PrintAndLogEx(ERR, "APDU error: 0x%02x --> Attempted to read/write data from/to beyong the file's/record's limit", *sw & 0xff);
                    break;
                case MFDES_E_PICC_INTEGRITY:
                    PrintAndLogEx(ERR, "APDU error: 0x%02x --> PICC integrity error, PICC will be disabled", *sw & 0xff);
                    break;
                case MFDES_E_COMMAND_ABORTED:
                    PrintAndLogEx(ERR, "APDU error: 0x%02x --> Previous command was not fully completed / Not all Frames were requested or provided by the PCD", *sw & 0xff);
                    break;
                case MFDES_E_PICC_DISABLED:
                    PrintAndLogEx(ERR, "APDU error: 0x%02x --> PICC was disabled by an unrecoverable error", *sw & 0xff);
                    break;
                case MFDES_E_COUNT:
                    PrintAndLogEx(ERR, "APDU error: 0x%02x --> Application count is limited to 28, not addition CreateApplication possible", *sw & 0xff);
                    break;
                case MFDES_E_DUPLICATE:
                    PrintAndLogEx(ERR, "APDU error: 0x%02x --> Duplicate entry: File/Application does already exist", *sw & 0xff);
                    break;
                case MFDES_E_EEPROM:
                    PrintAndLogEx(ERR, "APDU error: 0x%02x --> Eeprom error due to loss of power, internal backup/rollback mechanism activated", *sw & 0xff);
                    break;
                case MFDES_E_FILE_NOT_FOUND:
                    PrintAndLogEx(ERR, "APDU error: 0x%02x --> Specified file number does not exist", *sw & 0xff);
                    break;
                case MFDES_E_FILE_INTEGRITY:
                    PrintAndLogEx(ERR, "APDU error: 0x%02x --> File integrity error, file will be disabled", *sw & 0xff);
                    break;
                default:
                    PrintAndLogEx(ERR, "APDU error: 0x%02x --> Unknown error", *sw & 0xff);
                    break;
        }
      }
    } else {
        PrintAndLogEx(ERR, "%s",GetErrorString(res));
    }
    return res;
}

static int send_desfire_cmd(sAPDU *apdu, bool select, uint8_t *dest, int *recv_len, uint16_t *sw, int splitbysize) {
    if (g_debugMode)
    {
        if (apdu==NULL) PrintAndLogEx(ERR, "APDU=NULL");
        if (dest==NULL) PrintAndLogEx(ERR, "DEST=NULL");
        if (sw==NULL) PrintAndLogEx(ERR, "SW=NULL");
        if (recv_len==NULL) PrintAndLogEx(ERR, "RECV_LEN=NULL");
    }
    if (apdu==NULL || sw==NULL || recv_len==NULL) return PM3_EINVARG;

    *sw = 0;
    uint8_t data[255 * 5]  = {0x00};
    int resplen = 0;
    int pos = 0;
    int i = 1;
    int res = DESFIRESendApdu(select, true, *apdu, data, sizeof(data), &resplen, sw);
    if (res != PM3_SUCCESS) return getstatus(res,sw);
    if (dest != NULL) {
        memcpy(dest, data, resplen);
    }

    pos += resplen;
    while (*sw == status(MFDES_ADDITIONAL_FRAME)) {
        apdu->INS = MFDES_ADDITIONAL_FRAME; //0xAF

        res = DESFIRESendApdu(false, true, *apdu, data, sizeof(data), &resplen, sw);
        if (res != PM3_SUCCESS) return getstatus(res,sw);
        if (dest != NULL) {
            if (splitbysize) {
                memcpy(&dest[i * splitbysize], data, resplen);
                i += 1;
            } else {
                memcpy(&dest[pos], data, resplen);
            }
        }
        pos += resplen;
        if (*sw!=status(MFDES_ADDITIONAL_FRAME)) break;
    }
    if (splitbysize) *recv_len = i;
    else {
        *recv_len = pos;
    }
    return PM3_SUCCESS;

}

static desfire_cardtype_t getCardType(uint8_t major, uint8_t minor) {

    if (major == 0x00)
        return MF3ICD40;
    else if (major == 0x01 && minor == 0x00)
        return EV1;
    else if (major == 0x12 && minor == 0x00)
        return EV2;
//    else if (major == 0x13 && minor == 0x00)
//        return EV3;
    else if (major == 0x30 && minor == 0x00)
        return LIGHT;
    else
        return UNKNOWN;
}

//none, verified
static int test_desfire_authenticate() {
    uint8_t c = 0x00;
    sAPDU apdu = {0x90, MFDES_AUTHENTICATE, 0x00, 0x00, 0x01, &c}; // 0x0A, KEY 0
    int recv_len = 0;
    uint16_t sw = 0;
    return send_desfire_cmd(&apdu, false, NULL, &recv_len, &sw, 0);
}

// none, verified
static int test_desfire_authenticate_iso() {
    uint8_t c = 0x00;
    sAPDU apdu = {0x90, MFDES_AUTHENTICATE_ISO, 0x00, 0x00, 0x01, &c}; // 0x1A, KEY 0
    int recv_len = 0;
    uint16_t sw = 0;
    return send_desfire_cmd(&apdu, false, NULL, &recv_len, &sw, 0);
}

//none, verified
static int test_desfire_authenticate_aes() {
    uint8_t c = 0x00;
    sAPDU apdu = {0x90, MFDES_AUTHENTICATE_AES, 0x00, 0x00, 0x01, &c}; // 0xAA, KEY 0
    int recv_len = 0;
    uint16_t sw = 0;
    return send_desfire_cmd(&apdu, false, NULL, &recv_len, &sw, 0);
}

// --- FREE MEM, verified
static int desfire_print_freemem(uint32_t free_mem) {
    PrintAndLogEx(SUCCESS, "   Available free memory on card         : " _GREEN_("%d bytes"), free_mem);
    return PM3_SUCCESS;
}

// init / disconnect, verified
static int get_desfire_freemem(uint32_t *free_mem) {
    if (free_mem==NULL) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_GET_FREE_MEMORY, 0x00, 0x00, 0x00, NULL}; // 0x6E
    int recv_len = 0;
    uint16_t sw = 0;
    uint8_t fmem[4] = {0};

    int res = send_desfire_cmd(&apdu, true, fmem, &recv_len, &sw, 0);
    if (res == PM3_SUCCESS) {
        *free_mem = le24toh(fmem);
        return res;
    }
    *free_mem = 0;
    return res;
}


// --- GET SIGNATURE, verified
static int desfire_print_signature(uint8_t *uid, uint8_t *signature, size_t signature_len, desfire_cardtype_t card_type) {
    if (g_debugMode)
    {
        if (uid==NULL) PrintAndLogEx(ERR, "UID=NULL");
        if (signature==NULL) PrintAndLogEx(ERR, "SIGNATURE=NULL");
    }
    if (uid==NULL || signature==NULL) return PM3_EINVARG;
    // DESFire Ev3  - wanted
    // ref:  MIFARE Desfire Originality Signature Validation

#define PUBLIC_DESFIRE_ECDA_KEYLEN 57
    const ecdsa_publickey_t nxp_desfire_public_keys[] = {
        {"NTAG424DNA, DESFire EV2", "048A9B380AF2EE1B98DC417FECC263F8449C7625CECE82D9B916C992DA209D68422B81EC20B65A66B5102A61596AF3379200599316A00A1410"},
        {"NTAG413DNA, DESFire EV1", "04BB5D514F7050025C7D0F397310360EEC91EAF792E96FC7E0F496CB4E669D414F877B7B27901FE67C2E3B33CD39D1C797715189AC951C2ADD"},
        {"DESFire EV2",             "04B304DC4C615F5326FE9383DDEC9AA892DF3A57FA7FFB3276192BC0EAA252ED45A865E3B093A3D0DCE5BE29E92F1392CE7DE321E3E5C52B3A"},
        {"NTAG424DNA, NTAG424DNATT, DESFire Light EV2", "04B304DC4C615F5326FE9383DDEC9AA892DF3A57FA7FFB3276192BC0EAA252ED45A865E3B093A3D0DCE5BE29E92F1392CE7DE321E3E5C52B3B"},
        {"DESFire Light EV1",       "040E98E117AAA36457F43173DC920A8757267F44CE4EC5ADD3C54075571AEBBF7B942A9774A1D94AD02572427E5AE0A2DD36591B1FB34FCF3D"},
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

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Signature"));
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

// init / disconnect, verified
static int get_desfire_signature(uint8_t *signature, size_t *signature_len) {
    if (g_debugMode)
    {
        if (signature==NULL) PrintAndLogEx(ERR, "SIGNATURE=NULL");
        if (signature_len==NULL) PrintAndLogEx(ERR, "SIGNATURE_LEN=NULL");
    }
    if (signature==NULL || signature_len==NULL) return PM3_EINVARG;
    uint8_t c = 0x00;
    sAPDU apdu = {0x90, MFDES_READSIG, 0x00, 0x00, 0x01, &c}; // 0x3C
    int recv_len = 0;
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, true, signature, &recv_len, &sw, 0);
    if (res == PM3_SUCCESS) {
        if (recv_len != 56) {
            *signature_len = 0;
            DropField();
            return PM3_ESOFT;
        } else {
            *signature_len = recv_len;

        }
        DropField();
        return PM3_SUCCESS;
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

// none, verified
static int get_desfire_keysettings(uint8_t *key_settings, uint8_t *num_keys) {
    if (g_debugMode)
    {
        if (key_settings==NULL) PrintAndLogEx(ERR, "KEY_SETTINGS=NULL");
        if (num_keys==NULL) PrintAndLogEx(ERR, "NUM_KEYS=NULL");
    }
    if (key_settings==NULL || num_keys==NULL) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_GET_KEY_SETTINGS, 0x00, 0x00, 0x00, NULL}; //0x45
    int recv_len = 0;
    uint16_t sw = 0;
    uint8_t data[2] = {0};
    int res = send_desfire_cmd(&apdu, false, data, &recv_len, &sw, 0);
    if (res != PM3_SUCCESS) return res;

    *key_settings = data[0];
    *num_keys = data[1];
    return PM3_SUCCESS;
}

// --- KEY VERSION
static int desfire_print_keyversion(uint8_t key_idx, uint8_t key_version) {
    PrintAndLogEx(SUCCESS, "   Key [%u]  Version : %d (0x%02x)", key_idx, key_version, key_version);
    return PM3_SUCCESS;
}

// none, verified
static int get_desfire_keyversion(uint8_t curr_key, uint8_t *num_versions) {
    if (g_debugMode)
    {
        if (num_versions==NULL) PrintAndLogEx(ERR, "NUM_VERSIONS=NULL");
    }
    if (num_versions==NULL) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_GET_KEY_VERSION, 0x00, 0x00, 0x01, &curr_key}; //0x64
    int recv_len = 0;
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, false, num_versions, &recv_len, &sw, 0);
    return res;
}


// init / disconnect, verified
static int get_desfire_appids(uint8_t *dest, uint8_t *app_ids_len) {
    if (g_debugMode)
    {
        if (dest==NULL) PrintAndLogEx(ERR, "DEST=NULL");
        if (app_ids_len==NULL) PrintAndLogEx(ERR, "APP_IDS_LEN=NULL");
    }
    if (dest==NULL || app_ids_len==NULL) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_GET_APPLICATION_IDS, 0x00, 0x00, 0x00, NULL}; //0x6a
    int recv_len = 0;
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, true, dest, &recv_len, &sw, 0);
    if (res != PM3_SUCCESS) return res;
    *app_ids_len = (uint8_t)recv_len & 0xFF;
    return res;
}

// init, verified
static int get_desfire_dfnames(dfname_t *dest, uint8_t *dfname_count) {
    if (g_debugMode)
    {
        if (dest==NULL) PrintAndLogEx(ERR, "DEST=NULL");
        if (dfname_count==NULL) PrintAndLogEx(ERR, "DFNAME_COUNT=NULL");
    }
    if (dest==NULL || dfname_count==NULL) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_GET_DF_NAMES, 0x00, 0x00, 0x00, NULL}; //0x6d
    int recv_len = 0;
    uint16_t sw = 0;
    int res = send_desfire_cmd(&apdu, true, (uint8_t *)dest, &recv_len, &sw, sizeof(dfname_t));
    if (res != PM3_SUCCESS) return res;
    *dfname_count = recv_len;
    return res;
}


// init, verified
static int get_desfire_select_application(uint8_t *aid) {
    if (g_debugMode)
    {
        if (aid==NULL) PrintAndLogEx(ERR, "AID=NULL");
    }
    if (aid==NULL) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_SELECT_APPLICATION, 0x00, 0x00, 0x03, aid}; //0x5a
    int recv_len = 0;
    uint16_t sw = 0;
    int res=send_desfire_cmd(&apdu, true, NULL, &recv_len, &sw, sizeof(dfname_t));
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't select AID 0x%X -> %s"),(aid[0]<<16)+(aid[1]<<8)+aid[2],GetErrorString(res));
        DropField();
        return res;
    }
    return PM3_SUCCESS;
}

// none, verified
static int get_desfire_fileids(uint8_t *dest, uint8_t *file_ids_len) {
    if (g_debugMode)
    {
        if (dest==NULL) PrintAndLogEx(ERR, "DEST=NULL");
        if (file_ids_len==NULL) PrintAndLogEx(ERR, "FILE_IDS_LEN=NULL");
    }
    if (dest==NULL || file_ids_len==NULL) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_GET_FILE_IDS, 0x00, 0x00, 0x00, NULL}; //0x6f
    int recv_len = 0;
    uint16_t sw = 0;
    *file_ids_len = 0;
    int res = send_desfire_cmd(&apdu, false, dest, &recv_len, &sw, 0);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't get file ids -> %s"),GetErrorString(res));
        DropField();
        return res;
    }
    *file_ids_len = recv_len;
    return res;
}

// none, verified
static int get_desfire_filesettings(uint8_t file_id, uint8_t *dest, int *destlen) {
    if (g_debugMode)
    {
        if (dest==NULL) PrintAndLogEx(ERR, "DEST=NULL");
        if (destlen==NULL) PrintAndLogEx(ERR, "DESTLEN=NULL");
    }
    if (dest==NULL || destlen==NULL) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_GET_FILE_SETTINGS, 0x00, 0x00, 0x01, &file_id}; // 0xF5
    uint16_t sw = 0;
    int res=send_desfire_cmd(&apdu, false, dest, destlen, &sw, 0);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't get file settings -> %s"),GetErrorString(res));
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

static int get_desfire_createapp(aidhdr_t* aidhdr) {
    if (aidhdr==NULL) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_CREATE_APPLICATION, 0x00, 0x00, sizeof(aidhdr_t), (uint8_t*)aidhdr}; // 0xCA
    uint16_t sw = 0;
    int recvlen=0;
    int res=send_desfire_cmd(&apdu, false, NONE, &recvlen, &sw, 0);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't create aid -> %s"),GetErrorString(res));
        DropField();
        return res;
    }
    return res;
}

static int get_desfire_deleteapp(uint8_t* aid) {
    if (aid==NULL) return PM3_EINVARG;
    sAPDU apdu = {0x90, MFDES_DELETE_APPLICATION, 0x00, 0x00, 3, aid}; // 0xDA
    uint16_t sw = 0;
    int recvlen=0;
    int res=send_desfire_cmd(&apdu, false, NONE, &recvlen, &sw, 0);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't delete aid -> %s"),GetErrorString(res));
        DropField();
        return res;
    }
    return res;
}

static int CmdHF14ADesCreateApp(const char *Cmd) {
    clearCommandBuffer();

    CLIParserInit("hf mfdes createaid",
                  "Create Application ID",
                  "Usage:\n\t-m Auth type (1=normal, 2=iso, 3=aes)\n\t-t Crypt algo (1=DES, 2=3DES, 3=3K3DES, 4=aes)\n\t-a aid (3 bytes)\n\t-n keyno\n\t-k key (8-24 bytes)\n\n"
                  "Example:\n\thf mfdes createaid -a 123456 -f 1122 -k 0F -l 2E -n AppName\n"
    );

    void *argtable[] = {
            arg_param_begin,
            arg_strx0("aA",  "aid",    "<aid>", "App ID to create"),
            arg_strx0("fF",  "fid",    "<fid>", "File ID"),
            arg_strx0("kK",  "keysetting1",    "<keysetting1>", "Key Setting 1 (Application Master Key Settings)"),
            arg_strx0("lL",  "keysetting2",    "<keysetting2>", "Key Setting 2"),
            arg_strx0("nN",  "name",    "<name>", "App ISO-4 Name"),
            arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, true);
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
    uint8_t keysetting1=0;
    uint8_t keysetting2=0;
    int keylen1=1;
    int keylen2=1;
    int namelen=16;
    CLIGetHexWithReturn(1, aid, &aidlength);
    CLIGetHexWithReturn(2, fid, &fidlength);
    CLIGetHexWithReturn(3, &keysetting1, &keylen1);
    CLIGetHexWithReturn(4, &keysetting2, &keylen2);
    CLIGetHexWithReturn(5, name, &namelen);
    CLIParserFree();

    if (aidlength < 3) {
        PrintAndLogEx(ERR, "AID must have 3 bytes length.");
        return PM3_EINVARG;
    }

    if (fidlength < 2) {
        PrintAndLogEx(ERR, "FID must have 2 bytes length.");
        return PM3_EINVARG;
    }

    if (keylen1 < 1) {
        PrintAndLogEx(ERR, "Keysetting1 must have 1 byte length.");
        return PM3_EINVARG;
    }

    if (keylen1 < 1) {
        PrintAndLogEx(ERR, "Keysetting2 must have 1 byte length.");
        return PM3_EINVARG;
    }

    if (namelen > 16) {
        PrintAndLogEx(ERR, "Name has a max. of 16 bytes length.");
        return PM3_EINVARG;
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
    memcpy(aidhdr.aid,aid,sizeof(aid));
    aidhdr.keysetting1=keysetting1;
    aidhdr.keysetting2=keysetting2;
    memcpy(aidhdr.fid,fid,sizeof(fid));
    memcpy(aidhdr.name,name,sizeof(name));

    return get_desfire_createapp(&aidhdr);
}

static int CmdHF14ADesDeleteApp(const char *Cmd) {
    clearCommandBuffer();

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
    CLIExecWithReturn(Cmd, argtable, true);
    int aidlength = 3;
    uint8_t aid[3] = {0};
    CLIGetHexWithReturn(1, aid, &aidlength);
    CLIParserFree();

    if (aidlength < 3) {
        PrintAndLogEx(ERR, "AID must have 3 bytes length.");
        return PM3_EINVARG;
    }

    if (memcmp(aid, "\x00\x00\x00", 3) == 0) {
        PrintAndLogEx(WARNING, _RED_("   Deleting root aid 000000 is forbidden."));
        return PM3_ESOFT;
    }

    return get_desfire_deleteapp(aid);
}


static int CmdHF14ADesFormatPICC(const char *Cmd) {
    (void) Cmd; // Cmd is not used so far

    sAPDU apdu = {0xFC, 0xF3, 0x10, 0x00, 0x00, NONE}; // fc f3 10
    uint16_t sw = 0;
    int recvlen=0;
    int res=send_desfire_cmd(&apdu, false, NONE, &recvlen, &sw, 0);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't create aid -> %s"),GetErrorString(res));
        DropField();
        return res;
    }

    return PM3_SUCCESS;
}


static int CmdHF14ADesInfo(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far

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
                PrintAndLogEx(WARNING, "Card is most likely not Desfire. Its UID has wrong size");
                break;
            case 3:
            default:
                PrintAndLogEx(WARNING, _RED_("Command unsuccessful"));
                break;
        }
        return PM3_ESOFT;
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
    PrintAndLogEx(INFO, "          Type: " _YELLOW_("0x0x%02X"), package->versionHW[1]);
    PrintAndLogEx(INFO, "       Subtype: " _YELLOW_("0x0x%02X"), package->versionHW[2]);
    PrintAndLogEx(INFO, "       Version: %s", getVersionStr(package->versionHW[3], package->versionHW[4]));
    PrintAndLogEx(INFO, "  Storage size: %s", getCardSizeStr(package->versionHW[5]));
    PrintAndLogEx(INFO, "      Protocol: %s", getProtocolStr(package->versionHW[6]));
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Software Information"));
    PrintAndLogEx(INFO, "     Vendor Id: " _YELLOW_("%s"), getTagInfo(package->versionSW[0]));
    PrintAndLogEx(INFO, "          Type: " _YELLOW_("0x0x%02X"), package->versionSW[1]);
    PrintAndLogEx(INFO, "       Subtype: " _YELLOW_("0x0x%02X"), package->versionSW[2]);
    PrintAndLogEx(INFO, "       Version: " _YELLOW_("%d.%d"),  package->versionSW[3], package->versionSW[4]);
    PrintAndLogEx(INFO, "  Storage size: %s", getCardSizeStr(package->versionSW[5]));
    PrintAndLogEx(INFO, "      Protocol: %s", getProtocolStr(package->versionSW[6]));

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

    // Signature originality check
    uint8_t signature[56] = {0};
    size_t signature_len = 0;
    desfire_cardtype_t cardtype = getCardType(package->versionHW[3], package->versionHW[4]);

    if (get_desfire_signature(signature, &signature_len) == PM3_SUCCESS)
        desfire_print_signature(package->uid, signature, signature_len, cardtype);

    // Master Key settings
    uint8_t master_aid[3] = {0x00, 0x00, 0x00};
    getKeySettings(master_aid);

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

/*
  The 7 MSBits (= n) code the storage size itself based on 2^n,
  the LSBit is set to '0' if the size is exactly 2^n
    and set to '1' if the storage size is between 2^n and 2^(n+1).
    For this version of DESFire the 7 MSBits are set to 0x0C (2^12 = 4096) and the LSBit is '0'.
*/
char *getCardSizeStr(uint8_t fsize) {

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

char *getProtocolStr(uint8_t id) {

    static char buf[40] = {0x00};
    char *retStr = buf;

    if (id == 0x05)
        sprintf(retStr, "0x%02X ( " _YELLOW_("ISO 14443-3, 14443-4") ")", id);
    else
        sprintf(retStr, "0x%02X ( " _YELLOW_("Unknown") ")", id);
    return buf;
}

char *getVersionStr(uint8_t major, uint8_t minor) {

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

int getKeySettings(uint8_t *aid) {
    if (aid==NULL) return PM3_EINVARG;
    int res=0;
    if (memcmp(aid, "\x00\x00\x00", 3) == 0) {

        // CARD MASTER KEY
        //PrintAndLogEx(INFO, "--- " _CYAN_("CMK - PICC, Card Master Key settings"));
        res=get_desfire_select_application(aid);
        if (res!=PM3_SUCCESS) return res;

        // KEY Settings - AMK
        uint8_t num_keys = 0;
        uint8_t key_setting = 0;
        res=get_desfire_keysettings(&key_setting, &num_keys);
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
        res=get_desfire_select_application(aid);
        if (res!=PM3_SUCCESS) return res;

        // KEY Settings - AMK
        uint8_t num_keys = 0;
        uint8_t key_setting = 0;
        res=get_desfire_keysettings(&key_setting, &num_keys);
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

static void DecodeFileType(uint8_t filetype){
    switch (filetype)
    {
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

static void DecodeComSet(uint8_t comset){
    switch (comset)
    {
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

static char* DecodeAccessValue(uint8_t value)
{
    char* car=(char*)malloc(255);
    memset(car,0x0,255);
    switch(value){
        case 0xE:
            strcat(car, "(Free Access)");
            break;
        case 0xF:
            strcat(car, "(Denied Access)");
            break;
        default:
            sprintf(car,"(Access Key: %d)",value);
            break;
    }
    return car;
}

static void DecodeAccessRights(uint16_t accrights){
    int change_access_rights=accrights&0xF;
    int read_write_access=(accrights>>4)&0xF;
    int write_access=(accrights>>8)&0xF;
    int read_access=(accrights>>12)&0xF;
    char* car=DecodeAccessValue(change_access_rights);
    char* rwa=DecodeAccessValue(read_write_access);
    char* wa=DecodeAccessValue(write_access);
    char* ra=DecodeAccessValue(read_access);
    PrintAndLogEx(INFO, "     Access Rights: 0x%04X - Change %s - RW %s - W %s - R %s", accrights,car,rwa,wa,ra);
    free(car);
    free(rwa);
    free(wa);
    free(ra);
}

static int DecodeFileSettings(uint8_t* filesettings, int fileset_len, int maclen){
    uint8_t filetype=filesettings[0];
    uint8_t comset=filesettings[1];

    uint16_t accrights=(filesettings[4]<<8)+filesettings[3];
    if (fileset_len==1+1+2+3+maclen)
    {
        int filesize=(filesettings[7]<<16)+(filesettings[6]<<8)+filesettings[5];
        DecodeFileType(filetype);
        DecodeComSet(comset);
        DecodeAccessRights(accrights);
        PrintAndLogEx(INFO, "     Filesize: %d", filesize);
        return PM3_SUCCESS;
    } else if (fileset_len==1+1+2+4+4+4+1+maclen) {
        int lowerlimit=(filesettings[8]<<24)+(filesettings[7]<<16)+(filesettings[6]<<8)+filesettings[5];
        int upperlimit=(filesettings[12]<<24)+(filesettings[11]<<16)+(filesettings[10]<<8)+filesettings[9];
        int limitcredvalue=(filesettings[16]<<24)+(filesettings[15]<<16)+(filesettings[14]<<8)+filesettings[13];
        uint8_t limited_credit_enabled=filesettings[17];
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

//    uint8_t isOK = 0x00;
    uint8_t aid[3] = {0};
    uint8_t app_ids[78] = {0};
    uint8_t app_ids_len = 0;

    uint8_t file_ids[33] = {0};
    uint8_t file_ids_len = 0;

    dfname_t dfnames[255] = {0};
    uint8_t dfname_count = 0;

    int res=0;

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

        PrintAndLogEx(SUCCESS, "  AID : " _GREEN_("%02X %02X %02X"), aid[0], aid[1], aid[2]);
        for (int m = 0; m < dfname_count; m++) {
            if (dfnames[m].aid[0] == aid[0] && dfnames[m].aid[1] == aid[1] && dfnames[m].aid[2] == aid[2]) {
                PrintAndLogEx(SUCCESS, "  -  DF " _YELLOW_("%02X %02X") " Name : " _YELLOW_("%s"), dfnames[m].fid[0], dfnames[m].fid[1], dfnames[m].name);
            }
        }

       res=getKeySettings(aid);
       if (res!=PM3_SUCCESS)
       {
           PrintAndLogEx(WARNING, _RED_("   Can't get Key Settings for AID %X -> %s"),(aid[0]<<16)+(aid[1]<<8)+aid[0],GetErrorString(res));
       }

        res=get_desfire_select_application(aid);
        if (res!=PM3_SUCCESS) return res;

        // Get File IDs
        if (get_desfire_fileids(file_ids, &file_ids_len) == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, " Tag report " _GREEN_("%d") "file%c", file_ids_len, (file_ids_len == 1) ? ' ' : 's');
            for (int j = 0; j < file_ids_len; ++j) {
                PrintAndLogEx(SUCCESS, "   Fileid %d (0x%02x)", file_ids[j], file_ids[j]);

                uint8_t filesettings[20] = {0};
                int fileset_len = 0;
                int res = get_desfire_filesettings(j, filesettings, &fileset_len);
                int maclen=0; // To be implemented
                if (res == PM3_SUCCESS) {
                    if (DecodeFileSettings(filesettings,fileset_len,maclen)!=PM3_SUCCESS){
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
    int res=0;
    clearCommandBuffer();
    // NR  DESC     KEYLENGHT
    // ------------------------
    // 1 = DES      8
    // 2 = 3DES     16
    // 3 = 3K 3DES  24
    // 4 = AES      16
    //SetAPDULogging(true);
    uint8_t keylength = 8;

    CLIParserInit("hf mfdes auth",
                  "Authenticates Mifare DESFire using Key",
                  "Usage:\n\t-m Auth type (1=normal, 2=iso, 3=aes)\n\t-t Crypt algo (1=DES, 2=3DES, 3=3K3DES, 4=aes)\n\t-a aid (3 bytes)\n\t-n keyno\n\t-k key (8-24 bytes)\n\n"
                  "Example:\n\thf mfdes auth -m 3 -t 4 -a 018380 -n 0 -k 404142434445464748494a4b4c4d4e4f\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("mM",  "type",   "Auth type (1=normal, 2=iso, 3=aes)", NULL),
        arg_int0("tT",  "algo",   "Crypt algo (1=DES, 2=3DES, 3=3K3DES, 4=aes)", NULL),
        arg_strx0("aA",  "aid",    "<aid>", "AID used for authentification"),
        arg_int0("nN",  "keyno",  "Key number used for authentification", NULL),
        arg_str0("kK",  "key",     "<Key>", "Key for checking (HEX 16 bytes)"),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, true);

    uint8_t cmdAuthMode = arg_get_int_def(1, 0);
    uint8_t cmdAuthAlgo = arg_get_int_def(2, 0);

    int aidlength = 3;
    uint8_t aid[3] = {0};
    CLIGetHexWithReturn(3, aid, &aidlength);

    uint8_t cmdKeyNo  = arg_get_int_def(4, 0);

    uint8_t key[24] = {0};
    int keylen = 0;
    CLIGetHexWithReturn(5, key, &keylen);
    CLIParserFree();

    if ((keylen < 8) || (keylen > 24)) {
        PrintAndLogEx(ERR, "Specified key must have 16 bytes length.");
        //SetAPDULogging(false);
        return PM3_EINVARG;
    }

    // AID
    if (aidlength != 3) {
        PrintAndLogEx(WARNING, "aid must include %d HEX symbols", 3);
        //SetAPDULogging(false);
        return PM3_EINVARG;
    }

    switch (cmdAuthMode) {
        case 1:
            if (cmdAuthAlgo != 1 && cmdAuthAlgo != 2) {
                PrintAndLogEx(NORMAL, "Crypto algo not valid for the auth mode");
                //SetAPDULogging(false);
                return PM3_EINVARG;
            }
            break;
        case 2:
            if (cmdAuthAlgo != 1 && cmdAuthAlgo != 2 && cmdAuthAlgo != 3) {
                PrintAndLogEx(NORMAL, "Crypto algo not valid for the auth mode");
                //SetAPDULogging(false);
                return PM3_EINVARG;
            }
            break;
        case 3:
            if (cmdAuthAlgo != 4) {
                PrintAndLogEx(NORMAL, "Crypto algo not valid for the auth mode");
                //SetAPDULogging(false);
                return PM3_EINVARG;
            }
            break;
        default:
            PrintAndLogEx(WARNING, "Wrong Auth mode (%d) -> (1=normal, 2=iso, 3=aes)", cmdAuthMode);
            //SetAPDULogging(false);
            return PM3_EINVARG;
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
        return PM3_EINVARG;
    }

    res=get_desfire_select_application(aid);
    if (res!=PM3_SUCCESS) return res;

    uint8_t file_ids[33] = {0};
    uint8_t file_ids_len = 0;
    res = get_desfire_fileids(file_ids, &file_ids_len);
    if (res != PM3_SUCCESS) return res;


    // algo, keylength,
    uint8_t data[25] = {keylength}; // max length: 1 + 24 (3k3DES)
    memcpy(data + 1, key, keylength);
    SendCommandOLD(CMD_HF_DESFIRE_AUTH1, cmdAuthMode, cmdAuthAlgo, cmdKeyNo, data, keylength + 1);
    PacketResponseNG resp;

    if (!WaitForResponseTimeout(CMD_ACK, &resp, 3000)) {
        PrintAndLogEx(WARNING, "Client command execute timeout");
        DropField();
        return PM3_ETIMEOUT;
    }

    uint8_t isOK  = resp.oldarg[0] & 0xff;
    if (isOK) {
        uint8_t *session_key = resp.data.asBytes;

        PrintAndLogEx(SUCCESS, "  Key        : " _GREEN_("%s"), sprint_hex(key, keylength));
        PrintAndLogEx(SUCCESS, "  SESSION    : " _GREEN_("%s"), sprint_hex(session_key, keylength));
        PrintAndLogEx(INFO, "-------------------------------------------------------------");
        //PrintAndLogEx(NORMAL, "  Expected   :B5 21 9E E8 1A A7 49 9D 21 96 68 7E 13 97 38 56");
    } else {
        PrintAndLogEx(WARNING, _RED_("Client command failed."));
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
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFMFDes(const char *Cmd) {
    // flush
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
