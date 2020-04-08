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

static int SendDesfireCmd(uint8_t *c, size_t len, int p0, int p1, int p2, PacketResponseNG *response, int timeout) {

    PacketResponseNG resp;
    if (response == NULL)
        response = &resp;

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_DESFIRE_COMMAND, p0, p1, p2, c, len);

    if (!WaitForResponseTimeout(CMD_ACK, response, timeout)) {
        PrintAndLogEx(WARNING, "[SendDesfireCmd] Timed-out: " _RED_("%s"), sprint_hex(c, len));
        DropField();
        return PM3_ETIMEOUT;
    }

    uint8_t isOK  = response->data.asBytes[0] & 0xff;
    if (!isOK) {
        PrintAndLogEx(WARNING, "[SendDesfireCmd] Unsuccessful: " _RED_("%s"), sprint_hex(c, len));
        return PM3_ESOFT;
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

//ICEMAN: Turn on field method?
//none
static int test_desfire_authenticate() {
    uint8_t c[] = {MFDES_AUTHENTICATE, 0x00, 0x00, 0x01, 0x00, 0x00};  // 0x0A, KEY 0
    SendCommandMIX(CMD_HF_DESFIRE_COMMAND, NONE, sizeof(c), 0, c, sizeof(c));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1000)) {
        DropField();
        return PM3_ETIMEOUT;
    }
    if (resp.length == 13)
        return PM3_SUCCESS;
    return PM3_ESOFT;
}
// none
static int test_desfire_authenticate_iso() {
    uint8_t c[] = {MFDES_AUTHENTICATE_ISO, 0x00, 0x00, 0x01, 0x00, 0x00};  // 0x1A, KEY 0
    SendCommandMIX(CMD_HF_DESFIRE_COMMAND, NONE, sizeof(c), 0, c, sizeof(c));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1000)) {
        DropField();
        return PM3_ETIMEOUT;
    }
    if (resp.length >= 13)
        return PM3_SUCCESS;
    return PM3_ESOFT;
}
//none
static int test_desfire_authenticate_aes() {
    /*  Just left here for future use, from TI TRF7970A sloa213 document
        const static u08_t CustomKey1[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        const static u08_t CustomKey2[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        const static u08_t CustomKey3[16] = {0x79, 0x70, 0x25, 0x53, 0x79, 0x70, 0x25,
        0x53, 0x79, 0x70, 0x25, 0x53, 0x79, 0x70, 0x25, 0x53};
     */
    uint8_t c[] = {MFDES_AUTHENTICATE_AES, 0x00, 0x00, 0x01, 0x00, 0x00};  // 0xAA, KEY 0
    SendCommandMIX(CMD_HF_DESFIRE_COMMAND, NONE, sizeof(c), 0, c, sizeof(c));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1000)) {
        DropField();
        return PM3_ETIMEOUT;
    }
    if (resp.length >= 13)
        return PM3_SUCCESS;
    return PM3_ESOFT;
}

// --- FREE MEM
static int desfire_print_freemem(uint32_t free_mem) {
    PrintAndLogEx(SUCCESS, "   Available free memory on card         : " _GREEN_("%d bytes"), free_mem);
    return PM3_SUCCESS;
}

// init / disconnect
static int get_desfire_freemem(uint32_t *free_mem) {
    uint8_t c[] = {MFDES_GET_FREE_MEMORY, 0x00, 0x00, 0x00};  // 0x6E
    SendCommandMIX(CMD_HF_DESFIRE_COMMAND, (INIT | DISCONNECT), sizeof(c), 0, c, sizeof(c));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        return PM3_ETIMEOUT;
    }

    if (resp.length == 8) {
        *free_mem = le24toh(resp.data.asBytes + 1);
        return PM3_SUCCESS;
    }

    *free_mem = 0;
    return PM3_ESOFT;
}


// --- GET SIGNATURE
static int desfire_print_signature(uint8_t *uid, uint8_t *signature, size_t signature_len, desfire_cardtype_t card_type) {

    // DESFire Ev3  - wanted
    // ref:  MIFARE Desfire Originality Signature Validation

#define PUBLIC_DESFIRE_ECDA_KEYLEN 57
    const ecdsa_publickey_t nxp_desfire_public_keys[] = {
        {"NTAG424DNA, DESFire EV2", "048A9B380AF2EE1B98DC417FECC263F8449C7625CECE82D9B916C992DA209D68422B81EC20B65A66B5102A61596AF3379200599316A00A1410"},
        {"NTAG413DNA, DESFire EV1", "04BB5D514F7050025C7D0F397310360EEC91EAF792E96FC7E0F496CB4E669D414F877B7B27901FE67C2E3B33CD39D1C797715189AC951C2ADD"},
        {"DESFire EV2",             "04B304DC4C615F5326FE9383DDEC9AA892DF3A57FA7FFB3276192BC0EAA252ED45A865E3B093A3D0DCE5BE29E92F1392CE7DE321E3E5C52B3A"},
        {"NTAG424DNA, NTAG424DNATT, DESFire Light EV2", "04B304DC4C615F5326FE9383DDEC9AA892DF3A57FA7FFB3276192BC0EAA252ED45A865E3B093A3D0DCE5BE29E92F1392CE7DE321E3E5C52B3B"},
        {"DESFire Light EV1",       "040E98E117AAA36457F43173DC920A8757267F44CE4EC5ADD3C54075571AEBBF7B942A9774A1D94AD02572427E5AE0A2DD36591B1FB34FCF3D"},
        {"Mifare Plus EV1",             "044409ADC42F91A8394066BA83D872FB1D16803734E911170412DDF8BAD1A4DADFD0416291AFE1C748253925DA39A5F39A1C557FFACD34C62E"}
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
    PrintAndLogEx(INFO, " IC signature public key name: %s", nxp_desfire_public_keys[i].desc);
    PrintAndLogEx(INFO, "IC signature public key value: %.32s", nxp_desfire_public_keys[i].value);
    PrintAndLogEx(INFO, "                             : %.32s", nxp_desfire_public_keys[i].value + 16);
    PrintAndLogEx(INFO, "                             : %.32s", nxp_desfire_public_keys[i].value + 32);
    PrintAndLogEx(INFO, "                             : %.32s", nxp_desfire_public_keys[i].value + 48);
    PrintAndLogEx(INFO, "    Elliptic curve parameters: NID_secp224r1");
    PrintAndLogEx(INFO, "             TAG IC Signature: %s", sprint_hex_inrow(signature, 16));
    PrintAndLogEx(INFO, "                             : %s", sprint_hex_inrow(signature + 16, 16));
    PrintAndLogEx(INFO, "                             : %s", sprint_hex_inrow(signature + 32, 16));
    PrintAndLogEx(INFO, "                             : %s", sprint_hex_inrow(signature + 48, signature_len - 48));
    PrintAndLogEx(SUCCESS, "        Signature verified: " _GREEN_("successful"));
    return PM3_SUCCESS;
}

// init / disconnect
static int get_desfire_signature(uint8_t *signature, size_t *signature_len) {
    uint8_t c[] = {MFDES_READSIG, 0x00, 0x00, 0x01, 0x00, 0x00};  // 0x3C
    SendCommandMIX(CMD_HF_DESFIRE_COMMAND, (INIT | DISCONNECT), sizeof(c), 0, c, sizeof(c));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500))
        return PM3_ETIMEOUT;

    if (resp.length == 61) {
        memcpy(signature, resp.data.asBytes + 1, 56);
        *signature_len = 56;
        return PM3_SUCCESS;
    } else {
        *signature_len = 0;
        return PM3_ESOFT;
    }
}


// --- KEY SETTING
static int desfire_print_keysetting(uint8_t key_settings, uint8_t num_keys) {

    PrintAndLogEx(SUCCESS, "  AID Key settings           : %02x", key_settings);
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

// none
static int get_desfire_keysettings(uint8_t *key_settings, uint8_t *num_keys) {
    PacketResponseNG resp;
    uint8_t c[] = {MFDES_GET_KEY_SETTINGS, 0x00, 0x00, 0x00};  // 0x45
    int ret = SendDesfireCmd(c, sizeof(c), NONE, sizeof(c), 0, &resp, 1500);
    if (ret != PM3_SUCCESS) return ret;

    if (resp.data.asBytes[1] == 0x91 && resp.data.asBytes[2] == 0xae) {
        PrintAndLogEx(WARNING, _RED_("[get_desfire_keysettings] Authentication error"));
        return PM3_ESOFT;
    }
//    PrintAndLogEx(INFO, "ICE: KEYSETTING resp :: %s", sprint_hex(resp.data.asBytes, resp.length));
    *key_settings = resp.data.asBytes[1];
    *num_keys = resp.data.asBytes[2];
    return PM3_SUCCESS;
}

// --- KEY VERSION
static int desfire_print_keyversion(uint8_t key_idx, uint8_t key_version) {
    PrintAndLogEx(SUCCESS, "   Key [%u]  Version : %d (0x%02x)", key_idx, key_version, key_version);
    return PM3_SUCCESS;
}

// none
static int get_desfire_keyversion(uint8_t curr_key, uint8_t *num_versions) {
    PacketResponseNG resp;
    uint8_t c[] = {MFDES_GET_KEY_VERSION, 0x00, 0x00, 0x01, curr_key, 0x00};  // 0x64
    int ret = SendDesfireCmd(c, sizeof(c), NONE, sizeof(c), 0, &resp, 1500);
    if (ret != PM3_SUCCESS) return ret;

    if (resp.data.asBytes[1] == 0x91 && resp.data.asBytes[2] == 0x40) {
        return PM3_ESOFT;
    }

    *num_versions = resp.data.asBytes[1];
    return PM3_SUCCESS;
}


// init
static int get_desfire_select_application(uint8_t *aid) {
    if (aid == NULL) return PM3_ESOFT;

    DropField();
    uint8_t c[] = {MFDES_SELECT_APPLICATION, 0x00, 0x00, 0x03, aid[0], aid[1], aid[2], 0x00};  // 0x5a
    PacketResponseNG resp;
    int ret = SendDesfireCmd(c, sizeof(c), INIT, sizeof(c), 0, &resp, 3000);
    if (ret != PM3_SUCCESS) {
        if (ret == PM3_ESOFT) {
            PrintAndLogEx(WARNING, "[get_desfire_select_application] Can't select AID: " _RED_("%s"), sprint_hex(aid, 3));
        }
        return ret;
    }

    if (resp.data.asBytes[1] == 0x91 && resp.data.asBytes[2] == 0x00) {
        return PM3_SUCCESS;
    }

    return PM3_ESOFT;
}


// init / disconnect
static int get_desfire_appids(uint8_t *dest, uint8_t *app_ids_len) {

    uint8_t c[] = {MFDES_GET_APPLICATION_IDS, 0x00, 0x00, 0x00}; //0x6a
    PacketResponseNG resp;
    int ret = SendDesfireCmd(c, sizeof(c), INIT | CLEARTRACE | DISCONNECT, sizeof(c), 0, &resp, 1500);
    if (ret != PM3_SUCCESS) return ret;

    *app_ids_len = resp.length - 5;

    // resp.length - 2crc, 2status, 1pcb...
    memcpy(dest, resp.data.asBytes + 1, *app_ids_len);

    if (resp.data.asBytes[resp.length - 3] == MFDES_ADDITIONAL_FRAME) {

        c[0] = MFDES_ADDITIONAL_FRAME; //0xAF
        ret = SendDesfireCmd(c, sizeof(c), NONE, sizeof(c), 0, &resp, 1500);
        if (ret != PM3_SUCCESS) return ret;

        memcpy(dest + *app_ids_len, resp.data.asBytes + 1, resp.length - 5);

        *app_ids_len += (resp.length - 5);
    }
    return PM3_SUCCESS;
}

static int get_desfire_dfnames(dfname_t *dest, uint8_t *dfname_count) {
    if (dest == NULL) return PM3_ESOFT;
    uint8_t c[] = {MFDES_GET_DF_NAMES, 0x00, 0x00, 0x00}; //0x6d
    PacketResponseNG resp;
    int ret = SendDesfireCmd(c, sizeof(c), INIT, sizeof(c), 0, &resp, 3000);
    if (ret != PM3_SUCCESS) return ret;

    uint8_t count = 1;
    memcpy(&dest[count - 1], resp.data.asBytes + 1, resp.length - 5);
    if (resp.data.asBytes[resp.length - 3] == MFDES_ADDITIONAL_FRAME) {
        c[0] = MFDES_ADDITIONAL_FRAME; //0xAF

        ret = SendDesfireCmd(c, sizeof(c), NONE, sizeof(c), 0, &resp, 3000);
        if (ret != PM3_SUCCESS) return ret;
        
        
        count++;
        memcpy(&dest[count - 1], resp.data.asBytes + 1, resp.length - 5);
    }
    *dfname_count = count;
    return PM3_SUCCESS;
}


// none
static int get_desfire_fileids(uint8_t *dest, uint8_t *file_ids_len) {
    uint8_t c[] = {MFDES_GET_FILE_IDS, 0x00, 0x00, 0x00};  // 0x6f
    PacketResponseNG resp;
    int ret = SendDesfireCmd(c, sizeof(c), NONE, sizeof(c), 0, &resp, 1500);
    if (ret != PM3_SUCCESS) return ret;

    if (resp.data.asBytes[resp.length - 4] == 0x91 && resp.data.asBytes[resp.length - 3] == 0x00) {
        *file_ids_len = resp.length - 5;
        memcpy(dest, resp.data.asBytes + 1, *file_ids_len);
        return PM3_SUCCESS;
    }

    return PM3_ESOFT;
}

static int get_desfire_filesettings(uint8_t file_id, uint8_t *dest, uint8_t *destlen) {
    uint8_t c[] = {MFDES_GET_FILE_SETTINGS, 0x00, 0x00, 0x01, file_id, 0x00};  // 0xF5
    PacketResponseNG resp;
    int ret = SendDesfireCmd(c, sizeof(c), NONE, sizeof(c), 0, &resp, 1500);
    if (ret != PM3_SUCCESS) return ret;

    if (resp.data.asBytes[resp.length - 4] == 0x91 && resp.data.asBytes[resp.length - 3] == 0x00) {
        *destlen = resp.length - 5;
        memcpy(dest, resp.data.asBytes + 1, *destlen);
        return PM3_SUCCESS;
    }

    return PM3_ESOFT;
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
    PrintAndLogEx(INFO, "          Type: " _YELLOW_("0x%02X"), package->versionHW[1]);
    PrintAndLogEx(INFO, "       Subtype: " _YELLOW_("0x%02X"), package->versionHW[2]);
    PrintAndLogEx(INFO, "       Version: %s", getVersionStr(package->versionHW[3], package->versionHW[4]));
    PrintAndLogEx(INFO, "  Storage size: %s", getCardSizeStr(package->versionHW[5]));
    PrintAndLogEx(INFO, "      Protocol: %s", getProtocolStr(package->versionHW[6]));
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Software Information"));
    PrintAndLogEx(INFO, "     Vendor Id: " _YELLOW_("%s"), getTagInfo(package->versionSW[0]));
    PrintAndLogEx(INFO, "          Type: " _YELLOW_("0x%02X"), package->versionSW[1]);
    PrintAndLogEx(INFO, "       Subtype: " _YELLOW_("0x%02X"), package->versionSW[2]);
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

void getKeySettings(uint8_t *aid) {

    if (memcmp(aid, "\x00\x00\x00", 3) == 0) {

        // CARD MASTER KEY
        //PrintAndLogEx(INFO, "--- " _CYAN_("CMK - PICC, Card Master Key settings"));
        if (get_desfire_select_application(aid) != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, _RED_("   Can't select AID"));
            DropField();
            return;
        }

        // KEY Settings - AMK
        uint8_t num_keys = 0;
        uint8_t key_setting = 0;
        if (get_desfire_keysettings(&key_setting, &num_keys) == PM3_SUCCESS) {
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
        if (res == PM3_ETIMEOUT) return;
        PrintAndLogEx(SUCCESS, "   [0x0A] Authenticate      : %s", (res == PM3_SUCCESS) ? _YELLOW_("YES") : "NO");

        res = test_desfire_authenticate_iso();
        if (res == PM3_ETIMEOUT) return;
        PrintAndLogEx(SUCCESS, "   [0x1A] Authenticate ISO  : %s", (res == PM3_SUCCESS) ? _YELLOW_("YES") : "NO");

        res = test_desfire_authenticate_aes();
        if (res == PM3_ETIMEOUT) return;
        PrintAndLogEx(SUCCESS, "   [0xAA] Authenticate AES  : %s", (res == PM3_SUCCESS) ? _YELLOW_("YES") : "NO");

        PrintAndLogEx(INFO, "-------------------------------------------------------------");

    } else {

        // AID - APPLICATION MASTER KEYS
        //PrintAndLogEx(SUCCESS, "--- " _CYAN_("AMK - Application Master Key settings"));
        if (get_desfire_select_application(aid) != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, _RED_("   Can't select AID"));
            DropField();
            return;
        }

        // KEY Settings - AMK
        uint8_t num_keys = 0;
        uint8_t key_setting = 0;
        if (get_desfire_keysettings(&key_setting, &num_keys) == PM3_SUCCESS) {
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
}

static int CmdHF14ADesEnumApplications(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far

//    uint8_t isOK = 0x00;
    uint8_t aid[3];
    uint8_t app_ids[78] = {0};
    uint8_t app_ids_len = 0;

    uint8_t file_ids[33] = {0};
    uint8_t file_ids_len = 0;

    dfname_t dfnames[255] = {0};
    uint8_t dfname_count = 0;

    if (get_desfire_appids(app_ids, &app_ids_len) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Can't get list of applications on tag");
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

        getKeySettings(aid);


        if (get_desfire_select_application(aid) != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, _RED_("   Can't select AID"));
            DropField();
            return PM3_ESOFT;
        }

        // Get File IDs
        if (get_desfire_fileids(file_ids, &file_ids_len) == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, " Tag report " _GREEN_("%d") "file%c", file_ids_len, (file_ids_len == 1) ? ' ' : 's');
            for (int j = 0; j < file_ids_len; ++j) {
                PrintAndLogEx(SUCCESS, "   Fileid %d (0x%02x)", file_ids[j], file_ids[j]);

                uint8_t filesettings[20] = {0};
                uint8_t fileset_len = 0;
                int res = get_desfire_filesettings(j, filesettings, &fileset_len);
                if (res == PM3_SUCCESS) {
                    PrintAndLogEx(INFO, "  Settings [%u] %s", fileset_len, sprint_hex(filesettings, fileset_len));
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

    if (GetAPDULogging())
        PrintAndLogEx(SUCCESS, ">>>> %s", sprint_hex(data, datalen));

    res = ExchangeAPDU14a(data, datalen, activate_field, leavefield_on, result, max_result_len, result_len);
    if (res) {
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

    if (isw != 0x9000 && isw != 0x9100) {
        if (GetAPDULogging()) {
            if (isw >> 8 == 0x61) {
                PrintAndLogEx(ERR, "APDU chaining len:%02x -->", isw & 0xff);
            } else {
                PrintAndLogEx(ERR, "APDU(%02x%02x) ERROR: [%4X] %s", apdu.CLA, apdu.INS, isw, GetAPDUCodeDescription(isw >> 8, isw & 0xff));
                return PM3_EAPDU_FAIL;
            }
        }
    }
 
    return PM3_SUCCESS;
}

static int CmdHF14ADesTEST(const char *Cmd) {

    uint8_t aid[3];
    uint8_t app_ids[78] = {0};
    int app_ids_len = 0;

//    uint8_t file_ids[33] = {0};
//    uint8_t file_ids_len = 0;

    uint8_t data[255*5]  = {0};
    dfname_t dfnames[255] = {0};
    int dfname_count = 0;
    uint16_t sw = 0;

    SetAPDULogging(true);

    // get application ids        
    sAPDU apdu = {0x90, MFDES_GET_APPLICATION_IDS, 0x00, 0x00, 0x00,  NULL};
    int res = DESFIRESendApdu(true, true, apdu, app_ids, sizeof(app_ids), &app_ids_len, &sw);
    if (res != PM3_SUCCESS)
        goto out;
        
    // get dfnames
    apdu.INS = MFDES_GET_DF_NAMES;
    res = DESFIRESendApdu(true, false, apdu, data, sizeof(data), &dfname_count, &sw);
    if (res != PM3_SUCCESS)
        goto out;
    
     
    // enum test...
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

        PrintAndLogEx(SUCCESS, "  AID : " _GREEN_("%s"), sprint_hex(aid, sizeof(aid)));
        for (int m = 0; m < dfname_count; m++) {
            if (memcmp (dfnames[m].aid, aid, 3) == 0) {
                PrintAndLogEx(SUCCESS, "  -  DF " _YELLOW_("%02X %02X") " Name : " _YELLOW_("%s"),
                        dfnames[m].fid[0], dfnames[m].fid[1],
                        dfnames[m].name
                        );
            }
        }
    }


out:
    SetAPDULogging(false);
    return PM3_SUCCESS;
}
    
// MIAFRE DESFire Authentication
//
#define BUFSIZE 256
static int CmdHF14ADesAuth(const char *Cmd) {

    // NR  DESC     KEYLENGHT
    // ------------------------
    // 1 = DES      8
    // 2 = 3DES     16
    // 3 = 3K 3DES  24
    // 4 = AES      16

    uint8_t keylength = 8;
    uint8_t key[24];
    uint8_t aidlength = 3;
    uint8_t aid[3];

    if (strlen(Cmd) < 3) {
        PrintAndLogEx(NORMAL, "Usage:  hf mfdes auth <1|2|3> <1|2|3|4> <appid> <keyno> <key> ");
        PrintAndLogEx(NORMAL, "            Auth modes");
        PrintAndLogEx(NORMAL, "                 1 = normal, 2 = iso, 3 = aes");
        PrintAndLogEx(NORMAL, "            Crypto");
        PrintAndLogEx(NORMAL, "                 1 = DES 2 = 3DES 3 = 3K3DES 4 = AES");
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(NORMAL, "Examples:");
        PrintAndLogEx(NORMAL, _YELLOW_("         hf mfdes auth 1 1 0 0 11223344"));
        PrintAndLogEx(NORMAL, _YELLOW_("         hf mfdes auth 3 4 018380 0 404142434445464748494a4b4c4d4e4f"));
        return PM3_SUCCESS;
    }
    uint8_t cmdAuthMode = param_get8(Cmd, 0);
    uint8_t cmdAuthAlgo = param_get8(Cmd, 1);
    // AID
    if (param_gethex(Cmd, 2, aid, aidlength * 2)) {
        PrintAndLogEx(WARNING, "aid must include %d HEX symbols", 3);
        return PM3_EINVARG;
    }
    uint8_t cmdKeyNo    = param_get8(Cmd, 3);

    switch (cmdAuthMode) {
        case 1:
            if (cmdAuthAlgo != 1 && cmdAuthAlgo != 2) {
                PrintAndLogEx(NORMAL, "Crypto algo not valid for the auth mode");
                return PM3_EINVARG;
            }
            break;
        case 2:
            if (cmdAuthAlgo != 1 && cmdAuthAlgo != 2 && cmdAuthAlgo != 3) {
                PrintAndLogEx(NORMAL, "Crypto algo not valid for the auth mode");
                return PM3_EINVARG;
            }
            break;
        case 3:
            if (cmdAuthAlgo != 4) {
                PrintAndLogEx(NORMAL, "Crypto algo not valid for the auth mode");
                return PM3_EINVARG;
            }
            break;
        default:
            PrintAndLogEx(WARNING, "Wrong Auth mode");
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

    // key
    if (param_gethex(Cmd, 4, key, keylength * 2)) {
        PrintAndLogEx(WARNING, "Key must include %d HEX symbols", keylength);
        return PM3_EINVARG;
    }

    if (get_desfire_select_application(aid) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, _RED_("   Can't select AID"));
        DropField();
        return PM3_ESOFT;
    }

    uint8_t file_ids[33] = {0};
    uint8_t file_ids_len = 0;
    get_desfire_fileids(file_ids, &file_ids_len);

    // algo, keylength,
    uint8_t data[25] = {keylength}; // max length: 1 + 24 (3k3DES)
    memcpy(data + 1, key, keylength);
    clearCommandBuffer();
    SendCommandOLD(CMD_HF_DESFIRE_AUTH1, cmdAuthMode, cmdAuthAlgo, cmdKeyNo, data, keylength + 1);
    PacketResponseNG resp;

    if (!WaitForResponseTimeout(CMD_ACK, &resp, 3000)) {
        PrintAndLogEx(WARNING, "Client command execute timeout");
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
//    {"rdbl",    CmdHF14ADesRb,               IfPm3Iso14443a,  "Read MIFARE DesFire block"},
//    {"wrbl",    CmdHF14ADesWb,               IfPm3Iso14443a,  "write MIFARE DesFire block"},
    {"test",    CmdHF14ADesTEST,               IfPm3Iso14443a,  "testing command"},
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
