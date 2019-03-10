//-----------------------------------------------------------------------------
// Copyright (C) 2014 Iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency MIFARE Desfire commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "des.h"
#include "cmdmain.h"
#include "proxmark3.h"
#include "../include/common.h"
#include "../include/mifare.h"
#include "iso14443crc.h"
#include "ui.h"
#include "cmdparser.h"
#include "util.h"
#include "cmdhfmfdes.h"
#include "cmdhf14a.h"


uint8_t CMDPOS = 0;
uint8_t LENPOS = 1;

uint8_t key_zero_data[16] = { 0x00 };
uint8_t key_ones_data[16] = { 0x01 };
uint8_t key_defa_data[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
uint8_t key_picc_data[16] = { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f };

static int CmdHelp(const char *Cmd);

int CmdHF14ADesWb(const char *Cmd) {
    /*  uint8_t blockNo = 0;
        uint8_t keyType = 0;
        uint8_t key[6] = {0, 0, 0, 0, 0, 0};
        uint8_t bldata[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

        char cmdp = 0x00;

        if (strlen(Cmd)<3) {
            PrintAndLogEx(NORMAL, "Usage:  hf mf wrbl    <block number> <key A/B> <key (12 hex symbols)> <block data (32 hex symbols)>");
            PrintAndLogEx(NORMAL, "        sample: hf mf wrbl 0 A FFFFFFFFFFFF 000102030405060708090A0B0C0D0E0F");
            return 0;
        }

        blockNo = param_get8(Cmd, 0);
        cmdp = param_getchar(Cmd, 1);
        if (cmdp == 0x00) {
            PrintAndLogEx(NORMAL, "Key type must be A or B");
            return 1;
        }
        if (cmdp != 'A' && cmdp != 'a') keyType = 1;
        if (param_gethex(Cmd, 2, key, 12)) {
            PrintAndLogEx(NORMAL, "Key must include 12 HEX symbols");
            return 1;
        }
        if (param_gethex(Cmd, 3, bldata, 32)) {
            PrintAndLogEx(NORMAL, "Block data must include 32 HEX symbols");
            return 1;
        }
        PrintAndLogEx(NORMAL, "--block no:%02x key type:%02x key:%s", blockNo, keyType, sprint_hex(key, 6));
        PrintAndLogEx(NORMAL, "--data: %s", sprint_hex(bldata, 16));

      UsbCommand c = {CMD_MIFARE_WRITEBL, {blockNo, keyType, 0}};
        memcpy(c.d.asBytes, key, 6);
        memcpy(c.d.asBytes + 10, bldata, 16);
      SendCommand(&c);

        UsbCommand resp;
        if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
            uint8_t isOK  = resp.arg[0] & 0xff;
            PrintAndLogEx(NORMAL, "isOk:%02x", isOK);
        } else {
            PrintAndLogEx(NORMAL, "Command execute timeout");
        }
     */
    return 0;
}

int CmdHF14ADesRb(const char *Cmd) {
    // uint8_t blockNo = 0;
    // uint8_t keyType = 0;
    // uint8_t key[6] = {0, 0, 0, 0, 0, 0};

    // char cmdp = 0x00;


    // if (strlen(Cmd)<3) {
    // PrintAndLogEx(NORMAL, "Usage:  hf mf rdbl    <block number> <key A/B> <key (12 hex symbols)>");
    // PrintAndLogEx(NORMAL, "        sample: hf mf rdbl 0 A FFFFFFFFFFFF ");
    // return 0;
    // }

    // blockNo = param_get8(Cmd, 0);
    // cmdp = param_getchar(Cmd, 1);
    // if (cmdp == 0x00) {
    // PrintAndLogEx(NORMAL, "Key type must be A or B");
    // return 1;
    // }
    // if (cmdp != 'A' && cmdp != 'a') keyType = 1;
    // if (param_gethex(Cmd, 2, key, 12)) {
    // PrintAndLogEx(NORMAL, "Key must include 12 HEX symbols");
    // return 1;
    // }
    // PrintAndLogEx(NORMAL, "--block no:%02x key type:%02x key:%s ", blockNo, keyType, sprint_hex(key, 6));

    // UsbCommand c = {CMD_MIFARE_READBL, {blockNo, keyType, 0}};
    // memcpy(c.d.asBytes, key, 6);
    // SendCommand(&c);

    // UsbCommand resp;
    // if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
    // uint8_t                isOK  = resp.arg[0] & 0xff;
    // uint8_t              * data  = resp.d.asBytes;

    // if (isOK)
    // PrintAndLogEx(NORMAL, "isOk:%02x data:%s", isOK, sprint_hex(data, 16));
    // else
    // PrintAndLogEx(NORMAL, "isOk:%02x", isOK);
    // } else {
    // PrintAndLogEx(NORMAL, "Command execute timeout");
    // }

    return 0;
}

int CmdHF14ADesInfo(const char *Cmd) {

    UsbCommand c = {CMD_MIFARE_DESFIRE_INFO};
    SendCommand(&c);
    UsbCommand resp;

    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        PrintAndLogEx(WARNING, "Command execute timeout");
        return 0;
    }
    uint8_t isOK  = resp.arg[0] & 0xff;
    if (!isOK) {
        switch (resp.arg[1]) {
            case 1:
                PrintAndLogEx(WARNING, "Can't select card");
                break;
            case 2:
                PrintAndLogEx(WARNING, "Card is most likely not Desfire. Its UID has wrong size");
                break;
            case 3:
            default:
                PrintAndLogEx(WARNING, "Command unsuccessful");
                break;
        }
        return 0;
    }
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "-- Desfire Information --------------------------------------");
    PrintAndLogEx(NORMAL, "-------------------------------------------------------------");
    PrintAndLogEx(NORMAL, "  UID                : %s", sprint_hex(resp.d.asBytes, 7));
    PrintAndLogEx(NORMAL, "  Batch number       : %s", sprint_hex(resp.d.asBytes + 28, 5));
    PrintAndLogEx(NORMAL, "  Production date    : week %02x, 20%02x", resp.d.asBytes[33], resp.d.asBytes[34]);
    PrintAndLogEx(NORMAL, "  -----------------------------------------------------------");
    PrintAndLogEx(NORMAL, "  Hardware Information");
    PrintAndLogEx(NORMAL, "      Vendor Id      : %s", getTagInfo(resp.d.asBytes[7]));
    PrintAndLogEx(NORMAL, "      Type           : 0x%02X", resp.d.asBytes[8]);
    PrintAndLogEx(NORMAL, "      Subtype        : 0x%02X", resp.d.asBytes[9]);
    PrintAndLogEx(NORMAL, "      Version        : %s", GetVersionStr(resp.d.asBytes[10], resp.d.asBytes[11]));
    PrintAndLogEx(NORMAL, "      Storage size   : %s", GetCardSizeStr(resp.d.asBytes[12]));
    PrintAndLogEx(NORMAL, "      Protocol       : %s", GetProtocolStr(resp.d.asBytes[13]));
    PrintAndLogEx(NORMAL, "  -----------------------------------------------------------");
    PrintAndLogEx(NORMAL, "  Software Information");
    PrintAndLogEx(NORMAL, "      Vendor Id      : %s", getTagInfo(resp.d.asBytes[14]));
    PrintAndLogEx(NORMAL, "      Type           : 0x%02X", resp.d.asBytes[15]);
    PrintAndLogEx(NORMAL, "      Subtype        : 0x%02X", resp.d.asBytes[16]);
    PrintAndLogEx(NORMAL, "      Version        : %d.%d", resp.d.asBytes[17], resp.d.asBytes[18]);
    PrintAndLogEx(NORMAL, "      storage size   : %s", GetCardSizeStr(resp.d.asBytes[19]));
    PrintAndLogEx(NORMAL, "      Protocol       : %s", GetProtocolStr(resp.d.asBytes[20]));
    PrintAndLogEx(NORMAL, "-------------------------------------------------------------");

    // Master Key settings
    GetKeySettings(NULL);

    // Free memory on card
    c.cmd = CMD_MIFARE_DESFIRE;
    c.arg[0] = (INIT | DISCONNECT);
    c.arg[1] = 0x01;
    c.d.asBytes[0] = GET_FREE_MEMORY;
    SendCommand(&c);
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500))
        return 0;

    uint8_t tmp[3];
    memcpy(tmp, resp.d.asBytes + 3, 3);

    PrintAndLogEx(NORMAL, "   Available free memory on card       : %d bytes", le24toh(tmp));
    PrintAndLogEx(NORMAL, "-------------------------------------------------------------");

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

    return 1;
}

/*
  The 7 MSBits (= n) code the storage size itself based on 2^n,
  the LSBit is set to '0' if the size is exactly 2^n
    and set to '1' if the storage size is between 2^n and 2^(n+1).
    For this version of DESFire the 7 MSBits are set to 0x0C (2^12 = 4096) and the LSBit is '0'.
*/
char *GetCardSizeStr(uint8_t fsize) {

    static char buf[30] = {0x00};
    char *retStr = buf;

    uint16_t usize = 1 << ((fsize >> 1) + 1);
    uint16_t lsize = 1 << (fsize >> 1);

    // is  LSB set?
    if (fsize & 1)
        sprintf(retStr, "0x%02X (%d - %d bytes)", fsize, usize, lsize);
    else
        sprintf(retStr, "0x%02X (%d bytes)", fsize, lsize);
    return buf;
}

char *GetProtocolStr(uint8_t id) {

    static char buf[30] = {0x00};
    char *retStr = buf;

    if (id == 0x05)
        sprintf(retStr, "0x%02X (ISO 14443-3, 14443-4)", id);
    else
        sprintf(retStr, "0x%02X (Unknown)", id);
    return buf;
}

char *GetVersionStr(uint8_t major, uint8_t minor) {

    static char buf[30] = {0x00};
    char *retStr = buf;

    if (major == 0x00)
        sprintf(retStr, "%d.%d (Desfire MF3ICD40)", major, minor);
    else if (major == 0x01 && minor == 0x00)
        sprintf(retStr, "%d.%d (Desfire EV1)", major, minor);
    else if (major == 0x12 && minor == 0x00)
        sprintf(retStr, "%d.%d (Desfire EV2)", major, minor);
    else
        sprintf(retStr, "%d.%d (Unknown)", major, minor);
    return buf;
}

void GetKeySettings(uint8_t *aid) {

    char messStr[512] = {0x00};
    char *str = messStr;
    uint8_t isOK = 0;
    uint32_t options = NONE;
    UsbCommand c = {CMD_MIFARE_DESFIRE};
    UsbCommand resp;

    //memset(messStr, 0x00, 512);

    if (aid == NULL) {
        PrintAndLogEx(NORMAL, " CMK - PICC, Card Master Key settings ");
        PrintAndLogEx(NORMAL, "");
        c.arg[CMDPOS] = (INIT | DISCONNECT);
        c.arg[LENPOS] =  0x01;
        c.d.asBytes[0] = GET_KEY_SETTINGS;  // 0x45
        SendCommand(&c);
        if (!WaitForResponseTimeout(CMD_ACK, &resp, 1000)) {return;}
        isOK  = resp.arg[0] & 0xff;
        if (!isOK) {
            PrintAndLogEx(WARNING, "   Can't select master application");
            return;
        }

        str = (resp.d.asBytes[3] & (1 << 3)) ? "YES" : "NO";
        PrintAndLogEx(NORMAL, "   [0x08] Configuration changeable       : %s", str);
        str = (resp.d.asBytes[3] & (1 << 2)) ? "NO" : "YES";
        PrintAndLogEx(NORMAL, "   [0x04] CMK required for create/delete : %s", str);
        str = (resp.d.asBytes[3] & (1 << 1)) ? "NO" : "YES";
        PrintAndLogEx(NORMAL, "   [0x02] Directory list access with CMK : %s", str);
        str = (resp.d.asBytes[3] & (1 << 0)) ? "YES" : "NO";
        PrintAndLogEx(NORMAL, "   [0x01] CMK is changeable              : %s", str);

        c.arg[LENPOS] = 0x02; //LEN
        c.d.asBytes[0] = GET_KEY_VERSION; //0x64
        c.d.asBytes[1] = 0x00;
        SendCommand(&c);
        if (!WaitForResponseTimeout(CMD_ACK, &resp, 1000)) { return; }
        isOK  = resp.arg[0] & 0xff;
        if (!isOK) {
            PrintAndLogEx(WARNING, "   Can't read key-version");
            return;
        }
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(NORMAL, "   Max number of keys       : %d", resp.d.asBytes[4]);
        PrintAndLogEx(NORMAL, "   Master key Version       : %d (0x%02x)", resp.d.asBytes[3], resp.d.asBytes[3]);
        PrintAndLogEx(NORMAL, "   ----------------------------------------------------------");

        c.arg[LENPOS] = 0x02; //LEN
        c.d.asBytes[0] = AUTHENTICATE; //0x0A
        c.d.asBytes[1] = 0x00; // KEY 0
        SendCommand(&c);
        if (!WaitForResponseTimeout(CMD_ACK, &resp, 1000)) {return;}
        isOK  = resp.d.asBytes[2] & 0xff;
        PrintAndLogEx(NORMAL, "   [0x0A] Authenticate      : %s", (isOK == 0xAE) ? "NO" : "YES");

        c.d.asBytes[0] = AUTHENTICATE_ISO; //0x1A
        SendCommand(&c);
        if (!WaitForResponseTimeout(CMD_ACK, &resp, 1000)) {return;}
        isOK  = resp.d.asBytes[2] & 0xff;
        PrintAndLogEx(NORMAL, "   [0x1A] Authenticate ISO  : %s", (isOK == 0xAE) ? "NO" : "YES");

        c.d.asBytes[0] = AUTHENTICATE_AES; //0xAA
        SendCommand(&c);
        if (!WaitForResponseTimeout(CMD_ACK, &resp, 1000)) {return;}
        isOK  = resp.d.asBytes[2] & 0xff;
        PrintAndLogEx(NORMAL, "   [0xAA] Authenticate AES  : %s", (isOK == 0xAE) ? "NO" : "YES");
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(NORMAL, "   ----------------------------------------------------------");

    } else {
        PrintAndLogEx(NORMAL, " AMK - Application Master Key settings");

        // SELECT AID
        c.arg[0] = (INIT | CLEARTRACE);
        c.arg[LENPOS] = 0x04;
        c.d.asBytes[0] = SELECT_APPLICATION;  // 0x5a
        memcpy(c.d.asBytes + 1, aid, 3);
        SendCommand(&c);

        if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
            PrintAndLogEx(WARNING, "   Timed-out");
            return;
        }
        isOK  = resp.arg[0] & 0xff;
        if (!isOK) {
            PrintAndLogEx(WARNING, "   Can't select AID: %s", sprint_hex(aid, 3));
            return;
        }

        // KEY SETTINGS
        options = NONE;
        c.arg[0] = options;
        c.arg[LENPOS] = 0x01;
        c.d.asBytes[0] = GET_KEY_SETTINGS; // 0x45
        SendCommand(&c);
        if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
            return;
        }
        isOK  = resp.arg[0] & 0xff;
        if (!isOK) {
            PrintAndLogEx(WARNING, "   Can't read Application Master key settings");
        } else {
            // Access rights.
            uint8_t rights = (resp.d.asBytes[3] >> 4 & 0xff);
            switch (rights) {
                case 0x00:
                    str = "AMK authentication is necessary to change any key (default)";
                    break;
                case 0x0e:
                    str = "Authentication with the key to be changed (same KeyNo) is necessary to change a key";
                    break;
                case 0x0f:
                    str = "All keys (except AMK,see Bit0) within this application are frozen";
                    break;
                default:
                    str = "Authentication with the specified key is necessary to change any ley. A change key and a PICC master key (CMK) can only be changed after authentication with the master key. For keys other then the master or change key, an authentication with the same key is needed.";
                    break;
            }
            PrintAndLogEx(NORMAL, "Changekey Access rights");
            PrintAndLogEx(NORMAL, "-- %s", str);
            PrintAndLogEx(NORMAL, "");
            // same as CMK
            str = (resp.d.asBytes[3] & (1 << 3)) ? "YES" : "NO";
            PrintAndLogEx(NORMAL, "   0x08 Configuration changeable       : %s", str);
            str = (resp.d.asBytes[3] & (1 << 2)) ? "NO" : "YES";
            PrintAndLogEx(NORMAL, "   0x04 AMK required for create/delete : %s", str);
            str = (resp.d.asBytes[3] & (1 << 1)) ? "NO" : "YES";
            PrintAndLogEx(NORMAL, "   0x02 Directory list access with AMK : %s", str);
            str = (resp.d.asBytes[3] & (1 << 0)) ? "YES" : "NO";
            PrintAndLogEx(NORMAL, "   0x01 AMK is changeable              : %s", str);
        }

        // KEY VERSION  - AMK
        c.arg[0] = NONE;
        c.arg[LENPOS] = 0x02;
        c.d.asBytes[0] = GET_KEY_VERSION; //0x64
        c.d.asBytes[1] = 0x00;
        SendCommand(&c);
        if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
            PrintAndLogEx(WARNING, "   Timed-out");
            return;
        }

        int numOfKeys;

        isOK  = resp.arg[0] & 0xff;
        if (!isOK) {
            PrintAndLogEx(WARNING, "   Can't read Application Master key version. Trying all keys");
            numOfKeys = MAX_NUM_KEYS;
        } else {
            numOfKeys = resp.d.asBytes[4];
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(NORMAL, "     Max number of keys  : %d", numOfKeys);
            PrintAndLogEx(NORMAL, "     Application Master key Version  : %d (0x%02x)", resp.d.asBytes[3], resp.d.asBytes[3]);
            PrintAndLogEx(NORMAL, "-------------------------------------------------------------");
        }

        // LOOP over numOfKeys that we got before.
        // From 0x01 to numOfKeys.  We already got 0x00. (AMK)
        for (int i = 0x01; i <= 0x0f; ++i) {

        }


    }
}

int CmdHF14ADesEnumApplications(const char *Cmd) {

    uint8_t isOK = 0x00;
    uint8_t aid[3];
    uint32_t options = (INIT | DISCONNECT);

    UsbCommand c = {CMD_MIFARE_DESFIRE, {options, 0x01 }};
    c.d.asBytes[0] = GET_APPLICATION_IDS;  //0x6a

    SendCommand(&c);
    UsbCommand resp;

    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        return 0;
    }
    isOK  = resp.arg[0] & 0xff;
    if (!isOK) {
        PrintAndLogEx(NORMAL, "Command unsuccessful");
        return 0;
    }
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "-- Desfire Enumerate Applications ---------------------------");
    PrintAndLogEx(NORMAL, "-------------------------------------------------------------");

    UsbCommand respAid;
    UsbCommand respFiles;

    uint8_t num = 0;
    int max = resp.arg[1] - 3 - 2;

    for (int i = 3; i <= max; i += 3) {
        PrintAndLogEx(NORMAL, " Aid %d : %02X %02X %02X ", num, resp.d.asBytes[i], resp.d.asBytes[i + 1], resp.d.asBytes[i + 2]);
        num++;

        aid[0] = resp.d.asBytes[i];
        aid[1] = resp.d.asBytes[i + 1];
        aid[2] = resp.d.asBytes[i + 2];
        GetKeySettings(aid);

        // Select Application
        c.arg[CMDPOS] = INIT;
        c.arg[LENPOS] = 0x04;
        c.d.asBytes[0] = SELECT_APPLICATION;  // 0x5a
        c.d.asBytes[1] = resp.d.asBytes[i];
        c.d.asBytes[2] = resp.d.asBytes[i + 1];
        c.d.asBytes[3] = resp.d.asBytes[i + 2];
        SendCommand(&c);

        if (!WaitForResponseTimeout(CMD_ACK, &respAid, 1500)) {
            PrintAndLogEx(WARNING, "   Timed-out");
            continue;
        }
        isOK  = respAid.d.asBytes[2] & 0xff;
        if (isOK != 0x00) {
            PrintAndLogEx(WARNING, "   Can't select AID: %s", sprint_hex(resp.d.asBytes + i, 3));
            continue;
        }

        // Get File IDs
        c.arg[CMDPOS] = NONE;
        c.arg[LENPOS] = 0x01;
        c.d.asBytes[0] = GET_FILE_IDS; // 0x6f
        SendCommand(&c);

        if (!WaitForResponseTimeout(CMD_ACK, &respFiles, 1500)) {
            PrintAndLogEx(WARNING, "   Timed-out");
            continue;
        } else {
            isOK  = respFiles.d.asBytes[2] & 0xff;
            if (!isOK) {
                PrintAndLogEx(WARNING, "   Can't get file ids ");
            } else {
                int respfileLen = resp.arg[1] - 3 - 2;
                for (int j = 0; j < respfileLen; ++j) {
                    PrintAndLogEx(NORMAL, "   Fileid %d :", resp.d.asBytes[j + 3]);
                }
            }
        }

        // Get ISO File IDs
        c.arg[CMDPOS] = DISCONNECT;
        c.arg[LENPOS] = 0x01;
        c.d.asBytes[0] = GET_ISOFILE_IDS; // 0x61
        SendCommand(&c);

        if (!WaitForResponseTimeout(CMD_ACK, &respFiles, 1500)) {
            PrintAndLogEx(WARNING, "   Timed-out");
            continue;
        } else {
            isOK  = respFiles.d.asBytes[2] & 0xff;
            if (!isOK) {
                PrintAndLogEx(WARNING, "   Can't get ISO file ids ");
            } else {
                int respfileLen = resp.arg[1] - 3 - 2;
                for (int j = 0; j < respfileLen; ++j) {
                    PrintAndLogEx(NORMAL, " ISO  Fileid %d :", resp.d.asBytes[j + 3]);
                }
            }
        }


    }
    PrintAndLogEx(NORMAL, "-------------------------------------------------------------");


    return 1;
}

// MIAFRE DesFire Authentication
//
#define BUFSIZE 256
int CmdHF14ADesAuth(const char *Cmd) {

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
        PrintAndLogEx(NORMAL, "         hf mfdes auth 1 1 0 11223344");
        PrintAndLogEx(NORMAL, "         hf mfdes auth 3 4 0 404142434445464748494a4b4c4d4e4f");
        return 0;
    }
    uint8_t cmdAuthMode = param_get8(Cmd, 0);
    uint8_t cmdAuthAlgo = param_get8(Cmd, 1);
    uint8_t cmdKeyNo    = param_get8(Cmd, 2);

    switch (cmdAuthMode) {
        case 1:
            if (cmdAuthAlgo != 1 && cmdAuthAlgo != 2) {
                PrintAndLogEx(NORMAL, "Crypto algo not valid for the auth mode");
                return 1;
            }
            break;
        case 2:
            if (cmdAuthAlgo != 1 && cmdAuthAlgo != 2 && cmdAuthAlgo != 3) {
                PrintAndLogEx(NORMAL, "Crypto algo not valid for the auth mode");
                return 1;
            }
            break;
        case 3:
            if (cmdAuthAlgo != 4) {
                PrintAndLogEx(NORMAL, "Crypto algo not valid for the auth mode");
                return 1;
            }
            break;
        default:
            PrintAndLogEx(WARNING, "Wrong Auth mode");
            return 1;
            break;
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
        return 1;
    }
    // algo, nyckell�ngd,
    UsbCommand c = {CMD_MIFARE_DESFIRE_AUTH1, { cmdAuthMode, cmdAuthAlgo, cmdKeyNo }};

    c.d.asBytes[0] = keylength;
    memcpy(c.d.asBytes + 1, key, keylength);
    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;

    if (!WaitForResponseTimeout(CMD_ACK, &resp, 3000)) {
        PrintAndLogEx(WARNING, "Client command execute timeout");
        return 0;
    }

    uint8_t isOK  = resp.arg[0] & 0xff;
    if (isOK) {
        uint8_t *data = resp.d.asBytes;

        PrintAndLogEx(NORMAL, "  Key        :%s", sprint_hex(key, keylength));
        PrintAndLogEx(NORMAL, "  SESSION    :%s", sprint_hex(data, keylength));
        PrintAndLogEx(NORMAL, "-------------------------------------------------------------");
        //PrintAndLogEx(NORMAL, "  Expected   :B5 21 9E E8 1A A7 49 9D 21 96 68 7E 13 97 38 56");
    } else {
        PrintAndLogEx(NORMAL, "Client command failed.");
    }
    PrintAndLogEx(NORMAL, "-------------------------------------------------------------");
    return 1;
}


static command_t CommandTable[] = {
    {"help",    CmdHelp,                    1, "This help"},
    {"info",    CmdHF14ADesInfo,            0, "Tag information"},
    {"enum",    CmdHF14ADesEnumApplications, 0, "Tries enumerate all applications"},
    {"auth",    CmdHF14ADesAuth,            0, "Tries a MIFARE DesFire Authentication"},
    {"rdbl",    CmdHF14ADesRb,              0, "Read MIFARE DesFire block"},
    {"wrbl",    CmdHF14ADesWb,              0, "write MIFARE DesFire block"},
    {NULL, NULL, 0, NULL}
};

int CmdHFMFDes(const char *Cmd) {
    // flush
    clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}


