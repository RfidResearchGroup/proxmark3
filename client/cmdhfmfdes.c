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

#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "cmdhf14a.h"
#include "mbedtls/des.h"
#include "crypto/libpcrypto.h"
#include "protocols.h"
#include "mifare.h"         // desfire raw command options

uint8_t key_zero_data[16] = { 0x00 };
uint8_t key_ones_data[16] = { 0x01 };
uint8_t key_defa_data[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
uint8_t key_picc_data[16] = { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f };

static int CmdHelp(const char *Cmd);

static int desfire_print_signature(uint8_t *uid, uint8_t *signature, size_t signature_len) {
    #define PUBLIC_DESFIRE_ECDA_KEYLEN 57

    // ref:  MIFARE Desfire Originality Signature Validation
    uint8_t nxp_desfire_keys[1][PUBLIC_DESFIRE_ECDA_KEYLEN] = {
        // DESFire Light
        {
            0x04, 0x0E, 0x98, 0xE1, 0x17, 0xAA, 0xA3, 0x64,
            0x57, 0xF4, 0x31, 0x73, 0xDC, 0x92, 0x0A, 0x87,
            0x57, 0x26, 0x7F, 0x44, 0xCE, 0x4E, 0xC5, 0xAD,
            0xD3, 0xC5, 0x40, 0x75, 0x57, 0x1A, 0xEB, 0xBF,
            0x7B, 0x94, 0x2A, 0x97, 0x74, 0xA1, 0xD9, 0x4A,
            0xD0, 0x25, 0x72, 0x42, 0x7E, 0x5A, 0xE0, 0xA2,
            0xDD, 0x36, 0x59, 0x1B, 0x1F, 0xB3, 0x4F, 0xCF, 0x3D
        }
        // DESFire Ev2
        
    };

    uint8_t public_key = 0;
    int res = ecdsa_signature_r_s_verify(MBEDTLS_ECP_DP_SECP224R1, nxp_desfire_keys[public_key], uid, 7, signature, signature_len, false);
    bool is_valid = (res == 0);

    PrintAndLogEx(INFO, "  Tag Signature");
    PrintAndLogEx(INFO, "  IC signature public key name  : NXP ???");
    PrintAndLogEx(INFO, "  IC signature public key value : %s", sprint_hex(nxp_desfire_keys[public_key], 16));
    PrintAndLogEx(INFO, "                                : %s", sprint_hex(nxp_desfire_keys[public_key] + 16, 16));
    PrintAndLogEx(INFO, "                                : %s", sprint_hex(nxp_desfire_keys[public_key] + 32, 16));
    PrintAndLogEx(INFO, "                                : %s", sprint_hex(nxp_desfire_keys[public_key] + 48, PUBLIC_DESFIRE_ECDA_KEYLEN - 48));
    PrintAndLogEx(INFO, "      Elliptic curve parameters : NID_secp224r1");
    PrintAndLogEx(INFO, "               TAG IC Signature : %s", sprint_hex(signature, 16));
    PrintAndLogEx(INFO, "                                : %s", sprint_hex(signature + 16, 16));
    PrintAndLogEx(INFO, "                                : %s", sprint_hex(signature + 32, 16));
    PrintAndLogEx(INFO, "                                : %s", sprint_hex(signature + 48, signature_len - 48));
    PrintAndLogEx( (is_valid) ? SUCCESS : WARNING, "  Signature verified %s", (is_valid) ? _GREEN_("successful") : _RED_("failed"));
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    return PM3_SUCCESS;
}
static int get_desfire_signature(uint8_t *signature, size_t *signature_len) {

    PacketResponseNG resp;

    uint8_t c[] = {MFDES_READSIG, 0x00, 0x00, 0x01, 0x00, 0x00};  // 0x3C
    SendCommandMIX(CMD_HF_DESFIRE_COMMAND, (INIT | DISCONNECT), sizeof(c), 0, c, sizeof(c));
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

static int CmdHF14ADesInfo(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far

    SendCommandNG(CMD_HF_DESFIRE_INFO, NULL, 0);
    PacketResponseNG resp;

    if (!WaitForResponseTimeout(CMD_HF_DESFIRE_INFO, &resp, 1500)) {
        PrintAndLogEx(WARNING, "Command execute timeout");
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
    PrintAndLogEx(INFO, "-- Desfire Information --------------------------------------");
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    PrintAndLogEx(SUCCESS, "  UID                : " _GREEN_("%s"), sprint_hex(package->uid, sizeof(package->uid)));
    PrintAndLogEx(SUCCESS, "  Batch number       : " _GREEN_("%s"), sprint_hex(package->details + 7, 5));
    PrintAndLogEx(SUCCESS, "  Production date    : week " _GREEN_("%02x") "/ " _GREEN_("20%02x"), package->details[12], package->details[13]);
    PrintAndLogEx(INFO, "  -----------------------------------------------------------");
    PrintAndLogEx(INFO, "  Hardware Information");
    PrintAndLogEx(SUCCESS, "      Vendor Id      : " _YELLOW_("%s"), getTagInfo(package->versionHW[0]));
    PrintAndLogEx(SUCCESS, "      Type           : " _YELLOW_("0x%02X"), package->versionHW[1]);
    PrintAndLogEx(SUCCESS, "      Subtype        : " _YELLOW_("0x%02X"), package->versionHW[2]);
    PrintAndLogEx(SUCCESS, "      Version        : %s", getVersionStr(package->versionHW[3], package->versionHW[4]));
    PrintAndLogEx(SUCCESS, "      Storage size   : %s", getCardSizeStr(package->versionHW[5]));
    PrintAndLogEx(SUCCESS, "      Protocol       : %s", getProtocolStr(package->versionHW[6]));
    PrintAndLogEx(INFO, "  -----------------------------------------------------------");
    PrintAndLogEx(INFO, "  Software Information");
    PrintAndLogEx(SUCCESS, "      Vendor Id      : " _YELLOW_("%s"), getTagInfo(package->versionSW[0]));
    PrintAndLogEx(SUCCESS, "      Type           : " _YELLOW_("0x%02X"), package->versionSW[1]);
    PrintAndLogEx(SUCCESS, "      Subtype        : " _YELLOW_("0x%02X"), package->versionSW[2]);
    PrintAndLogEx(SUCCESS, "      Version        : " _YELLOW_("%d.%d"),  package->versionSW[3], package->versionSW[4]);
    PrintAndLogEx(SUCCESS, "      storage size   : %s", getCardSizeStr(package->versionSW[5]));
    PrintAndLogEx(SUCCESS, "      Protocol       : %s", getProtocolStr(package->versionSW[6]));
    PrintAndLogEx(INFO, "-------------------------------------------------------------");

    // Signature originality check
    uint8_t signature[56] = {0};
    size_t signature_len = 0;
    
    if (get_desfire_signature(signature, &signature_len) == PM3_SUCCESS) 
        desfire_print_signature(package->uid, signature, signature_len);

    // Master Key settings
    getKeySettings(NULL);

    // Free memory on card
    uint8_t c[] = {GET_FREE_MEMORY, 0x00, 0x00, 0x00};  // 0x6E
    SendCommandMIX(CMD_HF_DESFIRE_COMMAND, (INIT | DISCONNECT), sizeof(c), 0, c, sizeof(c));
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500))
        return PM3_ETIMEOUT;

    PrintAndLogEx(INFO, "  Free memory");    
    // Desfire Light doesn't support FREEMEM (len = 5)
    if (resp.length == 8) {
        uint8_t tmp[3];
        memcpy(tmp, resp.data.asBytes + 1, 3);
        PrintAndLogEx(SUCCESS, "   Available free memory on card       : " _GREEN_("%d bytes"), le24toh(tmp));
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
        sprintf(retStr, "%x.%x ( " _YELLOW_("Desfire MF3ICD40") ")", major, minor);
    else if (major == 0x01 && minor == 0x00)
        sprintf(retStr, "%x.%x ( " _YELLOW_("Desfire EV1") ")", major, minor);
    else if (major == 0x12 && minor == 0x00)
        sprintf(retStr, "%x.%x ( " _YELLOW_("Desfire EV2") ")", major, minor);
    else if (major == 0x30 && minor == 0x00)
        sprintf(retStr, "%x.%x ( " _YELLOW_("Desfire Light") ")", major, minor);
    else
        sprintf(retStr, "%x.%x ( " _YELLOW_("Unknown") ")", major, minor);
    return buf;
}

void getKeySettings(uint8_t *aid) {

    char messStr[512] = {0x00};
    const char *str = messStr;
    uint8_t isOK = 0;
    PacketResponseNG resp;

    if (aid == NULL) {
        
        // CARD MASTER KEY 

        PrintAndLogEx(INFO, "  CMK - PICC, Card Master Key settings");
        PrintAndLogEx(INFO, "-------------------------------------------------------------");
        {
            uint8_t data[] = {GET_KEY_SETTINGS, 0x00, 0x00, 0x00};  // 0x45
            SendCommandMIX(CMD_HF_DESFIRE_COMMAND, INIT | DISCONNECT, sizeof(data), 0, data, sizeof(data));
        }
        if (!WaitForResponseTimeout(CMD_ACK, &resp, 1000)) {return;}
        isOK  = resp.oldarg[0] & 0xff;
        if (!isOK) {
            PrintAndLogEx(WARNING, _RED_("   Can't select master application"));
            return;
        }
        // Not supported  02  91  1c  c4  ca 
        // OK           - 02  0f  01  91  00  7e  fe
        if (resp.length == 7 ) {
            
            // number of Master keys (0x01)
            PrintAndLogEx(SUCCESS, "   Number of Masterkeys      : " _YELLOW_("%u"), resp.data.asBytes[2]);
                        
            str = (resp.data.asBytes[1] & (1 << 3)) ? _GREEN_("YES") : "NO";
            PrintAndLogEx(SUCCESS, "   [0x08] Configuration changeable       : %s", str);

            str = (resp.data.asBytes[1] & (1 << 2)) ? _GREEN_("YES") : "NO";
            PrintAndLogEx(SUCCESS, "   [0x04] CMK required for create/delete : %s", str);

            str = (resp.data.asBytes[1] & (1 << 1)) ? _GREEN_("YES") : "NO";
            PrintAndLogEx(SUCCESS, "   [0x02] Directory list access with CMK : %s", str);

            str = (resp.data.asBytes[1] & (1 << 0)) ? _GREEN_("YES") : "NO";
            PrintAndLogEx(SUCCESS, "   [0x01] CMK is changeable              : %s", str);
        }

        {
            uint8_t data[] = {GET_KEY_VERSION, 0x00, 0x00, 0x01, 0x0, 0x00};  // 0x64
            SendCommandMIX(CMD_HF_DESFIRE_COMMAND, INIT | DISCONNECT, sizeof(data), 0, data, sizeof(data));
        }
        if (!WaitForResponseTimeout(CMD_ACK, &resp, 1000)) { return; }
        isOK  = resp.oldarg[0] & 0xff;
        if (!isOK) {
            PrintAndLogEx(WARNING, _RED_("   Can't read key-version"));
            return;
        }
        if (resp.length == 6) {
            PrintAndLogEx(SUCCESS, "");
            PrintAndLogEx(SUCCESS, "   Master key Version       : " _YELLOW_("%d (0x%02x)"), resp.data.asBytes[3], resp.data.asBytes[3]);
            PrintAndLogEx(INFO, "   ----------------------------------------------------------");
        }
                
        {
            // 0x0A
            uint8_t data[] = {AUTHENTICATE, 0x00, 0x00, 0x01, 0x00, 0x00};  // 0x0A, KEY 0
            SendCommandMIX(CMD_HF_DESFIRE_COMMAND, INIT | DISCONNECT, sizeof(data), 0, data, sizeof(data));
        }
        if (!WaitForResponseTimeout(CMD_ACK, &resp, 1000)) {return;}
        PrintAndLogEx(SUCCESS, "   [0x0A] Authenticate      : %s", (resp.length == 13) ? _YELLOW_("YES") : "NO");

        {
            // 0x1A
            uint8_t data[] = {AUTHENTICATE_ISO, 0x00, 0x00, 0x01, 0x00, 0x00};  // 0x1A, KEY 0
            SendCommandMIX(CMD_HF_DESFIRE_COMMAND, INIT | DISCONNECT, sizeof(data), 0, data, sizeof(data));
        }
        if (!WaitForResponseTimeout(CMD_ACK, &resp, 1000)) {return;}
        PrintAndLogEx(SUCCESS, "   [0x1A] Authenticate ISO  : %s", (resp.length >= 13) ? _YELLOW_("YES") : "NO");

        {
            // 0xAA
            uint8_t data[] = {AUTHENTICATE_AES, 0x00, 0x00, 0x01, 0x00, 0x00};  // 0xAA, KEY 0
            SendCommandMIX(CMD_HF_DESFIRE_COMMAND, INIT | DISCONNECT, sizeof(data), 0, data, sizeof(data));
        }
        if (!WaitForResponseTimeout(CMD_ACK, &resp, 1000)) {return;}
        PrintAndLogEx(SUCCESS, "   [0xAA] Authenticate AES  : %s", (resp.length >= 13) ? _YELLOW_("YES") : "NO");

        PrintAndLogEx(INFO, "-------------------------------------------------------------");

    } else {
        
        // AID - APPLICATION MASTER KEYS
        
        PrintAndLogEx(SUCCESS, " AMK - Application Master Key settings");
        PrintAndLogEx(INFO, " ----------------------------------------------------------");
        PrintAndLogEx(INFO, "   select AID: " _YELLOW_("%s"), sprint_hex(aid, 3) );

        // SELECT AID
        {
            uint8_t data[] = {SELECT_APPLICATION, 0x00, 0x00, 0x03, aid[0], aid[1], aid[2], 0x00};  // 0x5a
            //memcpy(data + 1, aid, 3);
            SendCommandMIX(CMD_HF_DESFIRE_COMMAND, INIT, sizeof(data), 0, data, sizeof(data));
        }

        if (!WaitForResponseTimeout(CMD_ACK, &resp, 3000)) {
            PrintAndLogEx(WARNING, _RED_("   Timed-out"));
            return;
        }
        isOK  = resp.oldarg[0] & 0xff;
        if (!isOK) {
            PrintAndLogEx(WARNING, "   Can't select AID: " _RED_("%s"), sprint_hex(aid, 3));
            return;
        }

        // KEY SETTINGS
        {
            uint8_t data[] = {GET_KEY_SETTINGS, 0x00, 0x00, 0x00};  // 0x45
            SendCommandMIX(CMD_HF_DESFIRE_COMMAND, NONE, sizeof(data), 0, data, sizeof(data));
        }

        if (!WaitForResponseTimeout(CMD_ACK, &resp, 3000)) {
            return;
        }
        isOK  = resp.oldarg[0] & 0xff;
        if (!isOK) {
            PrintAndLogEx(WARNING, _RED_("   Can't read Application Master key settings"));
        } else {
            // Access rights.
            uint8_t rights = (resp.data.asBytes[1] >> 4 & 0x0F);
            switch (rights) {
                case 0x0:
                    str = "AMK authentication is necessary to change any key (default)";
                    break;
                case 0xE:
                    str = "Authentication with the key to be changed (same KeyNo) is necessary to change a key";
                    break;
                case 0xF:
                    str = "All keys (except AMK,see Bit0) within this application are frozen";
                    break;
                default:
                    str = "Authentication with the specified key is necessary to change any key. A change key and a PICC master key (CMK) can only be changed after authentication with the master key. For keys other then the master or change key, an authentication with the same key is needed.";
                    break;
            }
            PrintAndLogEx(SUCCESS, "Changekey Access rights");
            PrintAndLogEx(SUCCESS, "-- " _GREEN_("%s"), str);
            PrintAndLogEx(SUCCESS, "");
            // same as CMK
            str = (resp.data.asBytes[1] & (1 << 3)) ? "YES" : "NO";
            PrintAndLogEx(SUCCESS, "   0x08 Configuration changeable       : %s", str);
            str = (resp.data.asBytes[1] & (1 << 2)) ? "NO" : "YES";
            PrintAndLogEx(SUCCESS, "   0x04 AMK required for create/delete : %s", str);
            str = (resp.data.asBytes[1] & (1 << 1)) ? "NO" : "YES";
            PrintAndLogEx(SUCCESS, "   0x02 Directory list access with AMK : %s", str);
            str = (resp.data.asBytes[1] & (1 << 0)) ? "YES" : "NO";
            PrintAndLogEx(SUCCESS, "   0x01 AMK is changeable              : %s", str);
        }

        // KEY VERSION  - AMK
        {
            uint8_t data[] = {GET_KEY_VERSION, 0x00, 0x00, 0x01, 0x00, 0x00};  // 0x64
            SendCommandMIX(CMD_HF_DESFIRE_COMMAND, DISCONNECT, sizeof(data), 0, data, sizeof(data));
        }

        if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
            PrintAndLogEx(WARNING, _RED_("   Timed-out"));
            return;
        }

        int numOfKeys;

        isOK  = resp.oldarg[0] & 0xff;
        if (isOK == false) {
            PrintAndLogEx(WARNING, "   Can't read Application Master key version. Trying all keys");
            //numOfKeys = MAX_NUM_KEYS;
        } else {
            numOfKeys = resp.data.asBytes[4];
            PrintAndLogEx(SUCCESS, "     Max number of keys  : %d", numOfKeys);
            PrintAndLogEx(SUCCESS, "     Application Master key Version  : %d (0x%02x)", resp.data.asBytes[3], resp.data.asBytes[3]);
            PrintAndLogEx(INFO, "-------------------------------------------------------------");
        }

        // LOOP over numOfKeys that we got before.
        // From 0x01 to numOfKeys.  We already got 0x00. (AMK)
        // TODO (iceman)
        /*
                for (int i = 0x01; i <= 0x0f; ++i) {
                }
        */
    }
}

static int CmdHF14ADesEnumApplications(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far

    uint8_t isOK = 0x00;
    uint8_t aid[3];
    {
        uint8_t data[] = {GET_APPLICATION_IDS, 0x00, 0x00, 0x00}; //0x6a
        SendCommandMIX(CMD_HF_DESFIRE_COMMAND, INIT | CLEARTRACE | DISCONNECT, sizeof(data), 0, data, sizeof(data));
    }
    PacketResponseNG resp;

    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        return PM3_ETIMEOUT;
    }

    isOK  = resp.oldarg[0] & 0xff;
    if (!isOK) {
        PrintAndLogEx(WARNING, _RED_("Command unsuccessful"));
        return PM3_ESOFT;
    }
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "-- Desfire Enumerate Applications ---------------------------");
    PrintAndLogEx(INFO, "-------------------------------------------------------------");

//    PacketResponseNG respAid;
//    PacketResponseNG respFiles;

    uint8_t num = 0;
    int max = resp.oldarg[1] - 3 - 2;
    PrintAndLogEx(INFO," MAX %d", max);

    for (int i = 1; i < max; i += 3) {
        PrintAndLogEx(SUCCESS, " Aid %d : %02X %02X %02X ", num, resp.data.asBytes[i], resp.data.asBytes[i+1], resp.data.asBytes[i+2]);
        num++;

        aid[0] = resp.data.asBytes[i];
        aid[1] = resp.data.asBytes[i + 1];
        aid[2] = resp.data.asBytes[i + 2];
        getKeySettings(aid);

/*
        // Select Application
        {
            uint8_t data[] = {SELECT_APPLICATION, 0x00, 0x00, 0x03, aid[0], aid[1], aid[2], 0x00};  // 0x5a    
            SendCommandMIX(CMD_HF_DESFIRE_COMMAND, NONE, sizeof(data), 0, data, sizeof(data));
        }

        if (!WaitForResponseTimeout(CMD_ACK, &respAid, 1500)) {
            PrintAndLogEx(WARNING, _RED_("   Timed-out"));
            continue;
        }
        isOK  = respAid.data.asBytes[2] & 0xff;
        if (isOK != 0x00) {
            PrintAndLogEx(WARNING, "   Can't select AID: " _RED_("%s"), sprint_hex(resp.data.asBytes + i, 3));
            continue;
        }

        // Get File IDs
        {
            uint8_t data[] = {GET_FILE_IDS, 0x00, 0x00, 0x00};  // 0x6f
            SendCommandMIX(CMD_HF_DESFIRE_COMMAND, NONE, sizeof(data), 0, data, sizeof(data));
        }

        if (!WaitForResponseTimeout(CMD_ACK, &respFiles, 1500)) {
            PrintAndLogEx(WARNING, _RED_("   Timed-out"));
            continue;
        } else {
            isOK  = respFiles.data.asBytes[2] & 0xff;
            if (!isOK) {
                PrintAndLogEx(WARNING, _RED_("   Can't get file ids "));
            } else {
                int respfileLen = resp.oldarg[1] - 3 - 2;
                for (int j = 0; j < respfileLen; ++j) {
                    PrintAndLogEx(SUCCESS, "   Fileid %d :", resp.data.asBytes[j + 3]);
                }
            }
        }

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
    return PM3_SUCCESS;
}

// MIAFRE DesFire Authentication
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
    unsigned char key[24];

    if (strlen(Cmd) < 3) {
        PrintAndLogEx(NORMAL, "Usage:  hf mfdes auth <1|2|3> <1|2|3|4> <keyno> <key> ");
        PrintAndLogEx(NORMAL, "            Auth modes");
        PrintAndLogEx(NORMAL, "                 1 = normal, 2 = iso, 3 = aes");
        PrintAndLogEx(NORMAL, "            Crypto");
        PrintAndLogEx(NORMAL, "                 1 = DES 2 = 3DES 3 = 3K3DES 4 = AES");
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(NORMAL, "Examples:");
        PrintAndLogEx(NORMAL, _YELLOW_("         hf mfdes auth 1 1 0 11223344"));
        PrintAndLogEx(NORMAL, _YELLOW_("         hf mfdes auth 3 4 0 404142434445464748494a4b4c4d4e4f"));
        return PM3_SUCCESS;
    }
    uint8_t cmdAuthMode = param_get8(Cmd, 0);
    uint8_t cmdAuthAlgo = param_get8(Cmd, 1);
    uint8_t cmdKeyNo    = param_get8(Cmd, 2);

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
    if (param_gethex(Cmd, 3, key, keylength * 2)) {
        PrintAndLogEx(WARNING, "Key must include %d HEX symbols", keylength);
        return PM3_EINVARG;
    }

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

static command_t CommandTable[] = {
    {"help",    CmdHelp,                     AlwaysAvailable, "This help"},
    {"info",    CmdHF14ADesInfo,             IfPm3Iso14443a,  "Tag information"},
    {"enum",    CmdHF14ADesEnumApplications, IfPm3Iso14443a,  "Tries enumerate all applications"},
    {"auth",    CmdHF14ADesAuth,             IfPm3Iso14443a,  "Tries a MIFARE DesFire Authentication"},
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
