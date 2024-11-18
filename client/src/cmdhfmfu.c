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
// High frequency MIFARE ULTRALIGHT (C) commands
//-----------------------------------------------------------------------------
#include "cmdhfmfu.h"
#include <ctype.h>
#include "cmdparser.h"
#include "commonutil.h"
#include "crypto/libpcrypto.h"
#include "des.h"
#include "aes.h"
#include "cmdhfmf.h"
#include "cmdhf14a.h"
#include "comms.h"
#include "protocols.h"
#include "generator.h"
#include "nfc/ndef.h"
#include "cliparser.h"
#include "cmdmain.h"
#include "amiibo.h"         // amiiboo fcts
#include "base64.h"
#include "fileutils.h"      // saveFile
#include "cmdtrace.h"       // trace list
#include "preferences.h"    // setDeviceDebugLevel

#define MAX_UL_BLOCKS       0x0F
#define MAX_ULC_BLOCKS      0x2F
#define MAX_ULEV1a_BLOCKS   0x13
#define MAX_ULEV1b_BLOCKS   0x28
#define MAX_NTAG_203        0x29
#define MAX_NTAG_210        0x13
#define MAX_NTAG_212        0x28
#define MAX_NTAG_213        0x2C
#define MAX_NTAG_215        0x86
#define MAX_NTAG_216        0xE6
#define MAX_NTAG_I2C_1K     0xE9
#define MAX_NTAG_I2C_2K     0xE9
#define MAX_MY_D_NFC        0xFF
#define MAX_MY_D_MOVE       0x25
#define MAX_MY_D_MOVE_LEAN  0x0F
#define MAX_UL_NANO_40      0x0A
#define MAX_UL_AES          0x37

static int CmdHelp(const char *Cmd);

static uint8_t default_aes_keys[][16] = {
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // all zeroes
    { 0x42, 0x52, 0x45, 0x41, 0x4b, 0x4d, 0x45, 0x49, 0x46, 0x59, 0x4f, 0x55, 0x43, 0x41, 0x4e, 0x21 }, // 3des std key
    { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }, // 0x00-0x0F
    { 0x49, 0x45, 0x4D, 0x4B, 0x41, 0x45, 0x52, 0x42, 0x21, 0x4E, 0x41, 0x43, 0x55, 0x4F, 0x59, 0x46 }, // NFC-key
    { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 }, // all ones
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, // all FF
    { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, // 11 22 33
    { 0x47, 0x45, 0x4D, 0x58, 0x50, 0x52, 0x45, 0x53, 0x53, 0x4F, 0x53, 0x41, 0x4D, 0x50, 0x4C, 0x45 }, // gemalto
    { 0x56, 0x4c, 0x67, 0x56, 0x99, 0x69, 0x64, 0x9f, 0x17, 0xC6, 0xC6, 0x16, 0x01, 0x10, 0x4D, 0xCA }  // Virtual Dorma Kaba
};

static uint8_t default_3des_keys[][16] = {
    { 0x42, 0x52, 0x45, 0x41, 0x4b, 0x4d, 0x45, 0x49, 0x46, 0x59, 0x4f, 0x55, 0x43, 0x41, 0x4e, 0x21 }, // 3des std key
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // all zeroes
    { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }, // 0x00-0x0F
    { 0x49, 0x45, 0x4D, 0x4B, 0x41, 0x45, 0x52, 0x42, 0x21, 0x4E, 0x41, 0x43, 0x55, 0x4F, 0x59, 0x46 }, // NFC-key
    { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 }, // all ones
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, // all FF
    { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, // 11 22 33
    { 0x47, 0x45, 0x4D, 0x58, 0x50, 0x52, 0x45, 0x53, 0x53, 0x4F, 0x53, 0x41, 0x4D, 0x50, 0x4C, 0x45 } // gemalto
};

static uint8_t default_pwd_pack[][4] = {
    {0xFF, 0xFF, 0xFF, 0xFF}, // PACK 0x00,0x00 -- factory default
    {0x4E, 0x45, 0x78, 0x54}, // NExT
    {0xB6, 0xAA, 0x55, 0x8D}, // copykey
};

static uint64_t UL_TYPES_ARRAY[] = {
    MFU_TT_UNKNOWN,           MFU_TT_UL,
    MFU_TT_UL_C,              MFU_TT_UL_EV1_48,
    MFU_TT_UL_EV1_128,        MFU_TT_NTAG,
    MFU_TT_NTAG_203,          MFU_TT_NTAG_210,
    MFU_TT_NTAG_212,          MFU_TT_NTAG_213,
    MFU_TT_NTAG_215,          MFU_TT_NTAG_216,
    MFU_TT_MY_D,              MFU_TT_MY_D_NFC,
    MFU_TT_MY_D_MOVE,         MFU_TT_MY_D_MOVE_NFC,
    MFU_TT_MY_D_MOVE_LEAN,    MFU_TT_NTAG_I2C_1K,
    MFU_TT_NTAG_I2C_2K,       MFU_TT_NTAG_I2C_1K_PLUS,
    MFU_TT_NTAG_I2C_2K_PLUS,  MFU_TT_FUDAN_UL,
    MFU_TT_NTAG_213_F,        MFU_TT_NTAG_216_F,
    MFU_TT_UL_EV1,            MFU_TT_UL_NANO_40,
    MFU_TT_NTAG_213_TT,       MFU_TT_NTAG_213_C,
    MFU_TT_MAGIC_1A,          MFU_TT_MAGIC_1B,
    MFU_TT_MAGIC_NTAG,        MFU_TT_NTAG_210u,
    MFU_TT_UL_MAGIC,          MFU_TT_UL_C_MAGIC,
    MFU_TT_UL_AES
};

static uint8_t UL_MEMORY_ARRAY[ARRAYLEN(UL_TYPES_ARRAY)] = {
//  UNKNOWN,            UL,                 UL_C,                UL_EV1_48,          UL_EV1_128,
    MAX_UL_BLOCKS,      MAX_UL_BLOCKS,      MAX_ULC_BLOCKS,      MAX_ULEV1a_BLOCKS,  MAX_ULEV1b_BLOCKS,
//  NTAG,               NTAG_203,           NTAG_210,            NTAG_212,
    MAX_NTAG_203,       MAX_NTAG_203,       MAX_NTAG_210,        MAX_NTAG_212,
//  NTAG_213,           NTAG_215,           NTAG_216,
    MAX_NTAG_213,       MAX_NTAG_215,       MAX_NTAG_216,
//  MY_D,               MY_D_NFC,           MY_D_MOVE,           MY_D_MOVE_NFC,      MY_D_MOVE_LEAN,
    MAX_UL_BLOCKS,      MAX_MY_D_NFC,       MAX_MY_D_MOVE,       MAX_MY_D_MOVE,      MAX_MY_D_MOVE_LEAN,
//  NTAG_I2C_1K,        NTAG_I2C_2K,        NTAG_I2C_1K_PLUS,    NTAG_I2C_2K_PLUS,
    MAX_NTAG_I2C_1K,    MAX_NTAG_I2C_2K,    MAX_NTAG_I2C_1K,     MAX_NTAG_I2C_2K,
//  FUDAN_UL,           NTAG_213_F,         NTAG_216_F,          UL_EV1,             UL_NANO_40,
    MAX_UL_BLOCKS,      MAX_NTAG_213,       MAX_NTAG_216,        MAX_ULEV1a_BLOCKS,  MAX_UL_NANO_40,
//  NTAG_213_TT,        NTAG_213_C,
    MAX_NTAG_213,       MAX_NTAG_213,
//  MAGIC_1A,           MAGIC_1B,           MAGIC_NTAG,
    MAX_UL_BLOCKS,      MAX_UL_BLOCKS,      MAX_NTAG_216,
//  NTAG_210u,          UL_MAGIC,           UL_C_MAGIC
    MAX_NTAG_210,       MAX_UL_BLOCKS,      MAX_ULC_BLOCKS,      MAX_UL_AES
};

static const ul_family_t ul_family[] = {
    {"UL-C", "UL-C", "\x00\x00\x00\x00\x00\x00\x00\x00"},
    {"UL", "MF0UL1001DUx", "\x00\x04\x03\x01\x00\x00\x0B\x03"},
    {"UL EV1 48", "MF0UL1101DUx", "\x00\x04\x03\x01\x01\x00\x0B\x03"},
    {"UL EV1 48", "MF0ULH1101DUx", "\x00\x04\x03\x02\x01\x00\x0B\x03"},
    {"UL EV1 48", "MF0UL1141DUF", "\x00\x04\x03\x03\x01\x00\x0B\x03"},
    {"UL EV1 128", "MF0UL2101Dxy", "\x00\x04\x03\x01\x01\x00\x0E\x03"},
    {"UL EV1 128", "MF0UL2101DUx", "\x00\x04\x03\x02\x01\x00\x0E\x03"},
    {"UL Ev1 n/a ", "MF0UL3101DUx", "\x00\x04\x03\x01\x01\x00\x11\x03"},
    {"UL Ev1 n/a", "MF0ULH3101DUx", "\x00\x04\x03\x02\x01\x00\x11\x03"},
    {"UL Ev1 n/a", "MF0UL5101DUx", "\x00\x04\x03\x01\x01\x00\x13\x03"},
    {"NTAG 210", "NT2L1011F0DUx", "\x00\x04\x04\x01\x01\x00\x0B\x03"},
    {"NTAG 210", "NT2H1011G0DUD", "\x00\x04\x04\x02\x01\x00\x0B\x03"},
    {"NTAG 212", "NT2L1211F0DUx", "\x00\x04\x04\x01\x01\x00\x0E\x03"},
    {"NTAG 213", "NT2H1311G0DUx", "\x00\x04\x04\x02\x01\x00\x0F\x03"},
    {"NTAG", "NT2H1411G0DUx", "\x00\x04\x04\x02\x01\x01\x11\x03"},
    {"NTAG 215", "NT2H1511G0DUx", "\x00\x04\x04\x02\x01\x00\x11\x03"},
    {"NTAG 215", "NT2H1511F0Dxy", "\x00\x04\x04\x04\x01\x00\x11\x03"},
    {"NTAG 216", "NT2H1611G0DUx", "\x00\x04\x04\x02\x01\x00\x13\x03"},
    {"NTAG 213F", "NT2H1311F0Dxy", "\x00\x04\x04\x04\x01\x00\x0F\x03"},
    {"NTAG 216F", "NT2H1611F0Dxy", "\x00\x04\x04\x04\x01\x00\x13\x03"},
    {"NTAG 213C", "NT2H1311C1DTL", "\x00\x04\x04\x02\x01\x01\x0F\x03"},
    {"NTAG 213TT", "NT2H1311TTDUx", "\x00\x04\x04\x02\x03\x00\x0F\x03"},
    {"NTAG I2C 1k", "NT3H1101W0FHK", "\x00\x04\x04\x05\x02\x00\x13\x03"},
    {"NTAG I2C 1k", "NT3H1101W0FHK_Variant", "\x00\x04\x04\x05\x02\x01\x13\x03"},
    {"NTAG I2C 2k", "NT3H1201W0FHK", "\x00\x04\x04\x05\x02\x00\x15\x03"},
    {"NTAG I2C 2k", "NT3H1201", "\x00\x04\x04\x05\x02\x01\x15\x03"},
    {"NTAG I2C 1k Plus", "NT3H2111", "\x00\x04\x04\x05\x02\x02\x13\x03"},
    {"NTAG I2C 2k Plus", "NT3H2211", "\x00\x04\x04\x05\x02\x02\x15\x03"},
    {"NTAG unk", "nhs", "\x00\x04\x04\x06\x00\x00\x13\x03"},
    {"UL NANO 40", "MF0UN0001DUx 17pF", "\x00\x04\x03\x01\x02\x00\x0B\x03"},
    {"UL NANO", "MF0UN1001DUx 17pF", "\x00\x04\x03\x01\x03\x00\x0B\x03"},
    {"UL NANO 40", "MF0UNH0001DUx 50pF", "\x00\x04\x03\x02\x02\x00\x0B\x03"},
    {"UL NANO", "MF0UNH1001DUx 50pF", "\x00\x04\x03\x02\x03\x00\x0B\x03"},
    {"NTAG 210u", "NT2L1001G0DUx", "\x00\x04\x04\x01\x02\x00\x0B\x03"},
    {"NTAG 210u", "NT2H1001G0DUx", "\x00\x04\x04\x02\x02\x00\x0B\x03"},
    {"UL EV1 128", "Mikron JSC Russia EV1", "\x00\x34\x21\x01\x01\x00\x0E\x03"},
    {"NTAG 213", "Shanghai Feiju NTAG", "\x00\x53\x04\x02\x01\x00\x0F\x03"},
    {"NTAG 215", "Shanghai Feiju NTAG", "\x00\x05\x34\x02\x01\x00\x11\x03"},
    {"UL AES", "MF0AES2001DUD", "\x00\x04\x03\x01\x04\x00\x0F\x03"},
};

static bool compare_ul_family(const uint8_t *d, uint8_t n) {
    if (d == NULL) {
        return false;
    }

    if (n > 8) {
        n = 8;
    }

    for (int i = 0; i < ARRAYLEN(ul_family); ++i) {
        if (memcmp(d, ul_family[i].version, n) == 0) {
            return true;
        }
    }
    return false;
}

//------------------------------------
// get version nxp product type
static const char *getProductTypeStr(uint8_t id) {
    static char buf[20];
    memset(buf, 0, sizeof(buf));

    switch (id) {
        case 3:
            return "Ultralight";
        case 4:
            return "NTAG";
        default:
            snprintf(buf, sizeof(buf), "%02X, unknown", id);
            return buf;
    }
}

static int ul_print_nxp_silicon_info(const uint8_t *card_uid) {

    if (card_uid[0] != 0x04) {
        return PM3_SUCCESS;
    }

    uint8_t uid[7];
    memcpy(&uid, card_uid, 7);

    uint16_t waferCoordX = ((uid[6] & 3) << 8) | uid[1];
    uint16_t waferCoordY = ((uid[6] & 12) << 6) | uid[2];
    uint32_t waferCounter = (
                                (uid[4] << 5) |
                                ((uid[6] & 0xF0) << 17) |
                                (uid[5] << 13) |
                                (uid[3] >> 3)
                            );
    uint8_t testSite = uid[3] & 7;

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Silicon Information"));
    PrintAndLogEx(INFO, "       Wafer Counter: %" PRId32 " ( 0x%02" PRIX32 " )", waferCounter, waferCounter);
    PrintAndLogEx(INFO, "   Wafer Coordinates: x %" PRId16 ", y %" PRId16 " (0x%02" PRIX16 ", 0x%02" PRIX16 ")"
                  , waferCoordX
                  , waferCoordY
                  , waferCoordX
                  , waferCoordY
                 );
    PrintAndLogEx(INFO, "           Test Site: %u", testSite);
    return PM3_SUCCESS;
}

static int get_ulc_3des_key_magic(uint64_t magic_type, uint8_t *key) {

    mf_readblock_ex_t payload = {
        .read_cmd = ISO14443A_CMD_READBLOCK,
        .block_no = 0x2C,
    };

    if ((magic_type & MFU_TT_MAGIC_1A) == MFU_TT_MAGIC_1A) {
        payload.wakeup = MF_WAKE_GEN1A;
        payload.auth_cmd = 0;
    } else if ((magic_type & MFU_TT_MAGIC_1B) == MFU_TT_MAGIC_1B) {
        payload.wakeup = MF_WAKE_GEN1B;
        payload.auth_cmd = 0;
    } else if ((magic_type & MFU_TT_MAGIC_4) == MFU_TT_MAGIC_4) {
        payload.wakeup = MF_WAKE_GDM_ALT;
        payload.auth_cmd = 0;
    } else if ((magic_type & MFU_TT_MAGIC_NTAG21X) == MFU_TT_MAGIC_NTAG21X) {
        payload.wakeup = MF_WAKE_WUPA;
        payload.auth_cmd = 0;
    } else {
        payload.wakeup = MF_WAKE_WUPA;
        payload.auth_cmd = MIFARE_MAGIC_GDM_AUTH_KEY;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_READBL_EX, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_MIFARE_READBL_EX, &resp, 1500) == false) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_SUCCESS && resp.length == MFBLOCK_SIZE) {
        uint8_t *d = resp.data.asBytes;
        reverse_array(d, 8);
        reverse_array(d + 8, 8);
        memcpy(key, d, MFBLOCK_SIZE);
    }

    return resp.status;
}

/*
  The 7 MSBits (=n) code the storage size itself based on 2^n,
  the LSBit is set to '0' if the size is exactly 2^n
  and set to '1' if the storage size is between 2^n and 2^(n+1).
*/
static const char *getUlev1CardSizeStr(uint8_t fsize) {

    static char buf[40];
    memset(buf, 0, sizeof(buf));

    uint16_t usize = 1 << ((fsize >> 1) + 1);
    uint16_t lsize = 1 << (fsize >> 1);

    // is  LSB set?
    if (fsize & 1)
        snprintf(buf, sizeof(buf), "%02X, (%u <-> %u bytes)", fsize, usize, lsize);
    else
        snprintf(buf, sizeof(buf), "%02X, (%u bytes)", fsize, lsize);
    return buf;
}

int ul_read_uid(uint8_t *uid) {
    if (uid == NULL) {
        PrintAndLogEx(WARNING, "NUll parameter UID");
        return PM3_ESOFT;
    }
    // read uid from tag
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_NO_RATS, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 2500) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }
    iso14a_card_select_t card;
    memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

    uint64_t select_status = resp.oldarg[0];
    // 0: couldn't read
    // 1: OK with ATS
    // 2: OK, no ATS
    // 3: proprietary Anticollision
    if (select_status == 0) {
        PrintAndLogEx(DEBUG, "iso14443a card select failed");
        return PM3_ESOFT;
    }
    memcpy(uid, card.uid, 7);

    if (card.uidlen != 7) {
        PrintAndLogEx(WARNING, "Wrong sized UID, expected 7 bytes, got " _RED_("%d"), card.uidlen);
        return PM3_ELENGTH;
    }
    return PM3_SUCCESS;
}

static void ul_switch_on_field(void) {
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_NO_DISCONNECT | ISO14A_NO_RATS, 0, 0, NULL, 0);
}

static int ul_send_cmd_raw(const uint8_t *cmd, uint8_t cmdlen, uint8_t *response, uint16_t responseLength) {
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_APPEND_CRC | ISO14A_NO_RATS, cmdlen, 0, cmd, cmdlen);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500) == false) {
        return PM3_ETIMEOUT;
    }

    if (!resp.oldarg[0] && responseLength) {
        return PM3_EWRONGANSWER;
    }

    uint16_t resplen = (resp.oldarg[0] < responseLength) ? resp.oldarg[0] : responseLength;
    memcpy(response, resp.data.asBytes, resplen);
    return resplen;
}

static bool ul_select(iso14a_card_select_t *card) {

    ul_switch_on_field();

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 2000) == false) {
        PrintAndLogEx(DEBUG, "iso14443a card select timeout");
        DropField();
        return false;
    } else {

        uint16_t len = (resp.oldarg[1] & 0xFFFF);
        if (len == 0) {
            PrintAndLogEx(DEBUG, "iso14443a card select failed");
            DropField();
            return false;
        }

        if (card) {
            memcpy(card, resp.data.asBytes, sizeof(iso14a_card_select_t));
        }
    }
    return true;
}

static bool ul_select_rats(iso14a_card_select_t *card) {

    ul_switch_on_field();

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500) == false) {
        PrintAndLogEx(DEBUG, "iso14443a card select timeout");
        DropField();
        return false;
    } else {

        uint16_t len = (resp.oldarg[1] & 0xFFFF);
        if (len == 0) {
            PrintAndLogEx(DEBUG, "iso14443a card select failed");
            DropField();
            return false;
        }

        if (card) {
            memcpy(card, resp.data.asBytes, sizeof(iso14a_card_select_t));
        }

        if (resp.oldarg[0] == 2) { // 0: couldn't read, 1: OK, with ATS, 2: OK, no ATS, 3: proprietary Anticollision
            // get ATS
            uint8_t rats[] = { 0xE0, 0x80 }; // FSDI=8 (FSD=256), CID=0
            SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_RAW | ISO14A_APPEND_CRC | ISO14A_NO_DISCONNECT, sizeof(rats), 0, rats, sizeof(rats));
            if (WaitForResponseTimeout(CMD_ACK, &resp, 1500) == false) {
                PrintAndLogEx(WARNING, "command execution time out");
                return false;
            }
        }

        if (card) {
            card->ats_len = resp.oldarg[0];
            memcpy(card->ats, resp.data.asBytes, card->ats_len);
        }

    }
    return true;
}

// This read command will at least return 16bytes.
static int ul_read(uint8_t page, uint8_t *response, uint16_t responseLength) {

    uint8_t cmd[] = {ISO14443A_CMD_READBLOCK, page};
    return ul_send_cmd_raw(cmd, sizeof(cmd), response, responseLength);
}

static int ul_comp_write(uint8_t page, const uint8_t *data, uint8_t datalen) {

    if (data == NULL) {
        return PM3_EINVARG;
    }

    uint8_t cmd[18];
    memset(cmd, 0x00, sizeof(cmd));
    datalen = (datalen > 16) ? 16 : datalen;

    cmd[0] = ISO14443A_CMD_WRITEBLOCK;
    cmd[1] = page;
    memcpy(cmd + 2, data, datalen);

    uint8_t response[1] = {0xFF};
    ul_send_cmd_raw(cmd, 2 + datalen, response, sizeof(response));
    // ACK
    if (response[0] == 0x0a) {
        return PM3_SUCCESS;
    }
    // NACK
    return PM3_EWRONGANSWER;
}

static int ulc_requestAuthentication(uint8_t *nonce, uint16_t nonceLength) {

    uint8_t cmd[] = {MIFARE_ULC_AUTH_1, 0x00};
    return ul_send_cmd_raw(cmd, sizeof(cmd), nonce, nonceLength);
}

static int ulev1_requestAuthentication(const uint8_t *pwd, uint8_t *pack, uint16_t packLength) {

    uint8_t cmd[] = {MIFARE_ULEV1_AUTH, pwd[0], pwd[1], pwd[2], pwd[3]};
    int len = ul_send_cmd_raw(cmd, sizeof(cmd), pack, packLength);
    // NACK tables different tags,  but between 0-9 is a NEGATIVE response.
    // ACK == 0xA
    if (len == 1 && pack[0] <= 0x09) {
        return PM3_EWRONGANSWER;
    }
    return len;
}

/*
Default AES key is 00-00h. Both the data and UID one.
Data key is 00, UID is 01. Authenticity is 02h
Auth is 1A[Key ID][CRC] - AF[RndB] - AF[RndA][RndB'] - 00[RndA']
*/
static int ulaes_requestAuthentication(const uint8_t *key, uint8_t keyno, bool switch_off_field) {
    struct p {
        bool turn_off_field;
        uint8_t keyno;
        uint8_t key[16];
    } PACKED payload;

    payload.turn_off_field = switch_off_field;
    payload.keyno = keyno;
    memcpy(payload.key, key, sizeof(payload.key));

    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFAREULAES_AUTH, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_MIFAREULAES_AUTH, &resp, 1500) == false) {
        return PM3_ETIMEOUT;
    }
    if (resp.status != PM3_SUCCESS) {
        return resp.status;
    }
    return PM3_SUCCESS;
}

static int ulc_authentication(const uint8_t *key, bool switch_off_field) {

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_MIFAREUC_AUTH, switch_off_field, 0, 0, key, 16);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500) == false) {
        return PM3_ETIMEOUT;
    }
    if (resp.oldarg[0] == 1) {
        return PM3_SUCCESS;
    }
    return PM3_ESOFT;
}

static int trace_mfuc_try_key(uint8_t *key, int state, uint8_t (*authdata)[16]) {
    uint8_t iv[8] = {0};
    uint8_t RndB[8] = {0};
    uint8_t RndARndB[16] = {0};
    uint8_t RndA[8] = {0};
    mbedtls_des3_context ctx_des3;
    switch (state) {
        case 2:
            mbedtls_des3_set2key_dec(&ctx_des3, key);
            mbedtls_des3_crypt_cbc(&ctx_des3, MBEDTLS_DES_DECRYPT,
                                   8, iv, authdata[0], RndB);
            mbedtls_des3_crypt_cbc(&ctx_des3, MBEDTLS_DES_DECRYPT,
                                   16, iv, authdata[1], RndARndB);
            if ((memcmp(&RndB[1], &RndARndB[8], 7) == 0) &&
                    (RndB[0] == RndARndB[15])) {
                return PM3_SUCCESS;
            }
            break;
        case 3:
            if (key == NULL) {// if no key was found
                return PM3_ESOFT;
            }
            memcpy(iv, authdata[0], 8);
            mbedtls_des3_set2key_dec(&ctx_des3, key);
            mbedtls_des3_crypt_cbc(&ctx_des3, MBEDTLS_DES_DECRYPT,
                                   16, iv, authdata[1], RndARndB);
            mbedtls_des3_crypt_cbc(&ctx_des3, MBEDTLS_DES_DECRYPT,
                                   8, iv, authdata[2], RndA);
            if ((memcmp(&RndARndB[1], RndA, 7) == 0) &&
                    (RndARndB[0] == RndA[7])) {
                return PM3_SUCCESS;
            }
            break;
        default:
            return PM3_EINVARG;
    }
    return PM3_ESOFT;
}

int trace_mfuc_try_default_3des_keys(uint8_t **correct_key, int state, uint8_t (*authdata)[16]) {
    switch (state) {
        case 2:
            for (uint8_t i = 0; i < ARRAYLEN(default_3des_keys); ++i) {
                uint8_t *key = default_3des_keys[i];
                if (trace_mfuc_try_key(key, state, authdata) == PM3_SUCCESS) {
                    *correct_key = key;
                    return PM3_SUCCESS;
                }
            }
            break;
        case 3:
            return trace_mfuc_try_key(*correct_key, state, authdata);
            break;
        default:
            return PM3_EINVARG;
    }
    return PM3_ESOFT;
}

// param override,  means we override hw debug levels.
static int try_default_3des_keys(bool override, uint8_t **correct_key) {

    uint8_t dbg_curr = DBG_NONE;
    if (override) {
        if (getDeviceDebugLevel(&dbg_curr) != PM3_SUCCESS) {
            return PM3_ESOFT;
        }

        if (setDeviceDebugLevel(DBG_NONE, false) != PM3_SUCCESS) {
            return PM3_ESOFT;
        }

    }
    int res = PM3_ESOFT;

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(SUCCESS, "--- " _CYAN_("Known UL-C 3DES keys"));

    for (uint8_t i = 0; i < ARRAYLEN(default_3des_keys); ++i) {
        uint8_t *key = default_3des_keys[i];
        if (ulc_authentication(key, true) == PM3_SUCCESS) {
            *correct_key = key;
            res = PM3_SUCCESS;
            break;
        }
    }

    if (override) {
        setDeviceDebugLevel(dbg_curr, false);
    }
    return res;
}

// param override,  means we override hw debug levels.
static int try_default_aes_keys(bool override) {

    uint8_t dbg_curr = DBG_NONE;
    if (override) {
        if (getDeviceDebugLevel(&dbg_curr) != PM3_SUCCESS) {
            return PM3_ESOFT;
        }

        if (setDeviceDebugLevel(DBG_NONE, false) != PM3_SUCCESS) {
            return PM3_ESOFT;
        }
    }

    int res = PM3_ESOFT;

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "--- " _CYAN_("Known UL-AES keys"));

    for (uint8_t i = 0; i < ARRAYLEN(default_aes_keys); ++i) {
        uint8_t *key = default_aes_keys[i];

        for (uint8_t keyno = 0; keyno < 3; keyno++) {

            if (ulaes_requestAuthentication(key, keyno, true) == PM3_SUCCESS) {

                char keystr[20] = {0};
                switch (keyno) {
                    case 0:
                        sprintf(keystr, "Data key");
                        break;
                    case 1:
                        sprintf(keystr, "UID key");
                        break;
                    case 2:
                        sprintf(keystr, "Authenticity key");
                        break;
                    default:
                        break;
                }
                PrintAndLogEx(SUCCESS, "%02X " _YELLOW_("%s") " - %s ( "_GREEN_("ok") " )"
                              , keyno
                              , keystr
                              , sprint_hex_inrow(key, 16)
                             );

                res = PM3_SUCCESS;
            }
        }
    }

    if (override) {
        setDeviceDebugLevel(dbg_curr, false);
    }
    return res;
}

static int ul_auth_select(iso14a_card_select_t *card, uint64_t tagtype, bool hasAuthKey, uint8_t *authkey, uint8_t *pack, uint8_t packSize) {

    if (hasAuthKey && (tagtype & MFU_TT_UL_C)) {
        //will select card automatically and close connection on error
        if (ulc_authentication(authkey, false) != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "Authentication Failed UL-C");
            return PM3_ESOFT;
        }

    } else {
        if (ul_select(card) == false) {
            return PM3_ESOFT;
        }

        if (hasAuthKey) {
            if (ulev1_requestAuthentication(authkey, pack, packSize) == PM3_EWRONGANSWER) {
                DropField();
                PrintAndLogEx(WARNING, "Authentication Failed UL-EV1/NTAG");
                return PM3_ESOFT;
            }
        }
    }
    return PM3_SUCCESS;
}

static int ntagtt_getTamperStatus(uint8_t *response, uint16_t responseLength) {
    uint8_t cmd[] = {NTAGTT_CMD_READ_TT, 0x00};
    return ul_send_cmd_raw(cmd, sizeof(cmd), response, responseLength);
}

static int ulev1_getVersion(uint8_t *response, uint16_t responseLength) {
    uint8_t cmd[] = {MIFARE_ULEV1_VERSION};
    return ul_send_cmd_raw(cmd, sizeof(cmd), response, responseLength);
}

static int ulev1_readCounter(uint8_t counter, uint8_t *response, uint16_t responseLength) {
    uint8_t cmd[] = {MIFARE_ULEV1_READ_CNT, counter};
    return ul_send_cmd_raw(cmd, sizeof(cmd), response, responseLength);
}

static int ulev1_readTearing(uint8_t counter, uint8_t *response, uint16_t responseLength) {
    uint8_t cmd[] = {MIFARE_ULEV1_CHECKTEAR, counter};
    return ul_send_cmd_raw(cmd, sizeof(cmd), response, responseLength);
}

static int ulev1_readSignature(uint8_t *response, uint16_t responseLength) {
    uint8_t cmd[] = {MIFARE_ULEV1_READSIG, 0x00};
    return ul_send_cmd_raw(cmd, sizeof(cmd), response, responseLength);
}

// Fudan check checks for which error is given for a command with incorrect crc
// NXP UL chip responds with 01, fudan 00.
// other possible checks:
//  send a0 + crc
//  UL responds with 00, fudan doesn't respond
//  or
//  send a200 + crc
//  UL doesn't respond, fudan responds with 00
//  or
//  send 300000 + crc (read with extra byte(s))
//  UL responds with read of page 0, fudan doesn't respond.
//
// make sure field is off before calling this function
static int ul_fudan_check(void) {
    iso14a_card_select_t card;
    if (ul_select(&card) == false) {
        return MFU_TT_UL_ERROR;
    }

    uint8_t cmd[4] = {ISO14443A_CMD_READBLOCK, 0x00, 0x02, 0xa7}; // wrong crc on purpose, should be 0xa8
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_NO_RATS, 4, 0, cmd, sizeof(cmd));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500) == false) {
        return MFU_TT_UL_ERROR;
    }
    if (resp.oldarg[0] != 1) {
        return MFU_TT_UL_ERROR;
    }

    return (resp.data.asBytes[0] == 0)
           ? MFU_TT_FUDAN_UL : MFU_TT_UL; //if response == 0x00 then Fudan, else Genuine NXP
}

static int ul_print_default(uint8_t *data, uint8_t *real_uid) {

    uint8_t uid[7];
    uid[0] = data[0];
    uid[1] = data[1];
    uid[2] = data[2];
    uid[3] = data[4];
    uid[4] = data[5];
    uid[5] = data[6];
    uid[6] = data[7];
    bool mful_uid_layout = true;

    if (memcmp(uid, real_uid, 7) != 0) {
        mful_uid_layout = false;
    }
    PrintAndLogEx(SUCCESS, "       UID: " _GREEN_("%s"), sprint_hex(real_uid, 7));
    PrintAndLogEx(SUCCESS, "    UID[0]: %02X, %s",  real_uid[0], getTagInfo(real_uid[0]));
    if (real_uid[0] == 0x05 && ((real_uid[1] & 0xf0) >> 4) == 2) {   // is infineon and 66RxxP
        uint8_t chip = (data[8] & 0xC7); // 11000111  mask, bit 3,4,5 RFU
        switch (chip) {
            case 0xC2:
                PrintAndLogEx(SUCCESS, "   IC type: SLE 66R04P 770 Bytes");
                break; //77 pages
            case 0xC4:
                PrintAndLogEx(SUCCESS, "   IC type: SLE 66R16P 2560 Bytes");
                break; //256 pages
            case 0xC6:
                PrintAndLogEx(SUCCESS, "   IC type: SLE 66R32P 5120 Bytes");
                break; //512 pages /2 sectors
        }
    }
    if (mful_uid_layout) {
        // CT (cascade tag byte) 0x88 xor SN0 xor SN1 xor SN2
        int crc0 = 0x88 ^ uid[0] ^ uid[1] ^ uid[2];
        if (data[3] == crc0)
            PrintAndLogEx(SUCCESS, "      BCC0: %02X ( " _GREEN_("ok") " )", data[3]);
        else
            PrintAndLogEx(NORMAL, "      BCC0: %02X, crc should be %02X", data[3], crc0);

        int crc1 = uid[3] ^ uid[4] ^ uid[5] ^ uid[6];
        if (data[8] == crc1)
            PrintAndLogEx(SUCCESS, "      BCC1: %02X ( " _GREEN_("ok") " )", data[8]);
        else
            PrintAndLogEx(NORMAL, "      BCC1: %02X, crc should be %02X", data[8], crc1);
        PrintAndLogEx(SUCCESS, "  Internal: %02X ( %s )", data[9], (data[9] == 0x48) ? _GREEN_("default") : _RED_("not default"));
    } else {
        PrintAndLogEx(SUCCESS, "Blocks 0-2: %s", sprint_hex(data + 0, 12));
    }

    PrintAndLogEx(SUCCESS, "      Lock: %s - %s",
                  sprint_hex(data + 10, 2),
                  sprint_bin(data + 10, 2)
                 );

    PrintAndLogEx(SUCCESS, "       OTP: " _YELLOW_("%s") " - %s",
                  sprint_hex(data + 12, 4),
                  sprint_bin(data + 12, 4)
                 );
    return PM3_SUCCESS;
}

static int ndef_get_maxsize(const uint8_t *data) {
    // no NDEF message
    if (data[0] != 0xE1)
        return 0;

    if (data[2] == 0x06)
        return 48;
    else if (data[2] == 0x12)
        return 144;
    else if (data[2] == 0x3E)
        return 496;
    else if (data[2] == 0x6D)
        return 872;
    return 0;
}

static int ndef_print_CC(uint8_t *data) {

    // no NDEF message
    if (data[0] != 0xE1 && data[0] != 0xF1) {
        return PM3_ESOFT;
    }

//NFC Forum Type 1,2,3,4
//
// 4 has 1.1 (11)

// b7, b6 major version
// b5, b4 minor version
// b3, b2 read
// 00 always, 01 rfu, 10 proprietary, 11 rfu
// b1, b0 write
// 00 always, 01 rfo, 10 proprietary, 11 never
    uint8_t cc_write = data[1] & 0x03;
    uint8_t cc_read  = (data[1] & 0x0C) >> 2;
    uint8_t cc_minor = (data[1] & 0x30) >> 4;
    uint8_t cc_major = (data[1] & 0xC0) >> 6;

    const char *wStr;
    switch (cc_write) {
        case 0:
            wStr = "Write access granted without any security";
            break;
        case 1:
            wStr = "RFU";
            break;
        case 2:
            wStr = "Proprietary";
            break;
        case 3:
            wStr = "No write access";
            break;
        default:
            wStr = "Unknown";
            break;
    }
    const char *rStr;
    switch (cc_read) {
        case 0:
            rStr = "Read access granted without any security";
            break;
        case 1:
        case 3:
            rStr = "RFU";
            break;
        case 2:
            rStr = "Proprietary";
            break;
        default:
            rStr = "Unknown";
            break;
    }


    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("NDEF Message"));
    PrintAndLogEx(SUCCESS, "Capability Container: " _YELLOW_("%s"), sprint_hex_inrow(data, 4));
    PrintAndLogEx(SUCCESS, "  %02X: NDEF Magic Number", data[0]);

//    PrintAndLogEx(SUCCESS, "  %02X : version %d.%d supported by tag", data[1], (data[1] & 0xF0) >> 4, data[1] & 0x0F);
    PrintAndLogEx(SUCCESS, "  %02X: version %d.%d supported by tag", data[1], cc_major, cc_minor);
    PrintAndLogEx(SUCCESS, "       : %s / %s", rStr, wStr);

    PrintAndLogEx(SUCCESS, "  %02X: Physical Memory Size: %d bytes", data[2], data[2] * 8);
    if (data[2] == 0x06)
        PrintAndLogEx(SUCCESS, "  %02X: NDEF Memory Size: %d bytes", data[2], 48);
    else if (data[2] == 0x12)
        PrintAndLogEx(SUCCESS, "  %02X: NDEF Memory Size: %d bytes", data[2], 144);
    else if (data[2] == 0x3E)
        PrintAndLogEx(SUCCESS, "  %02X: NDEF Memory Size: %d bytes", data[2], 496);
    else if (data[2] == 0x6D)
        PrintAndLogEx(SUCCESS, "  %02X: NDEF Memory Size: %d bytes", data[2], 872);

    uint8_t msb3   = (data[3] & 0xE0) >> 5;
    uint8_t sf     = (data[3] & 0x10) >> 4;
    uint8_t lb     = (data[3] & 0x08) >> 3;
    uint8_t mlrule = (data[3] & 0x06) >> 1;
    uint8_t mbread = (data[3] & 0x01);

    PrintAndLogEx(SUCCESS, "  %02X: Additional feature information", data[3]);

    uint8_t bits[8 + 1] = {0};
    num_to_bytebits(data[3], 8, bits);
    const char *bs = sprint_bytebits_bin(bits, 8);

    PrintAndLogEx(SUCCESS, "  %s", bs);
    if (msb3 == 0) {
        PrintAndLogEx(SUCCESS, "  %s", sprint_breakdown_bin(C_NONE, bs, 8, 0, 3, "RFU"));
    } else {
        PrintAndLogEx(SUCCESS, "  %s", sprint_breakdown_bin(C_RED, bs, 8, 0, 3, "RFU"));
    }

    if (sf) {
        PrintAndLogEx(SUCCESS, "  %s", sprint_breakdown_bin(C_NONE, bs, 8, 3, 1, "Support special frame"));
    } else {
        PrintAndLogEx(SUCCESS, "  %s", sprint_breakdown_bin(C_NONE, bs, 8, 3, 1, "Don\'t support special frame"));
    }

    if (lb) {
        PrintAndLogEx(SUCCESS, "  %s", sprint_breakdown_bin(C_NONE, bs, 8, 4, 1, "Support lock block"));
    } else {
        PrintAndLogEx(SUCCESS, "  %s", sprint_breakdown_bin(C_NONE, bs, 8, 4, 1, "Don\'t support lock block"));
    }

    if (mlrule == 0) {
        PrintAndLogEx(SUCCESS, "  %s", sprint_breakdown_bin(C_NONE, bs, 8, 5, 2, "RFU"));
    } else {
        PrintAndLogEx(SUCCESS, "  %s", sprint_breakdown_bin(C_RED, bs, 8, 5, 2, "RFU"));
    }

    if (mbread) {
        PrintAndLogEx(SUCCESS, "  %s", sprint_breakdown_bin(C_NONE, bs, 8, 7, 1, "IC support multiple block reads"));
    } else {
        PrintAndLogEx(SUCCESS, "  %s", sprint_breakdown_bin(C_NONE, bs, 8, 7, 1, "IC don\'t support multiple block reads"));
    }
    return PM3_SUCCESS;
}

int ul_print_type(uint64_t tagtype, uint8_t spaces) {

    if (spaces > 10) {
        spaces = 10;
    }

    char typestr[140];
    memset(typestr, 0x00, sizeof(typestr));

    if (tagtype & MFU_TT_UL)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("MIFARE Ultralight (MF0ICU1)"), spaces, "");
    else if (tagtype & MFU_TT_UL_C)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("MIFARE Ultralight C (MF0ULC)"), spaces, "");
    else if (tagtype & MFU_TT_UL_NANO_40)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("MIFARE Ultralight Nano 40bytes (MF0UNH00)"), spaces, "");
    else if (tagtype & MFU_TT_UL_EV1_48)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("MIFARE Ultralight EV1 48bytes (MF0UL1101)"), spaces, "");
    else if (tagtype & MFU_TT_UL_EV1_128)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("MIFARE Ultralight EV1 128bytes (MF0UL2101)"), spaces, "");
    else if (tagtype & MFU_TT_UL_EV1)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("MIFARE Ultralight EV1 UNKNOWN"), spaces, "");
    else if (tagtype & MFU_TT_UL_AES)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("MIFARE Ultralight AES"), spaces, "");
    else if (tagtype & MFU_TT_NTAG)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG UNKNOWN"), spaces, "");
    else if (tagtype & MFU_TT_NTAG_203)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG 203 144bytes (NT2H0301F0DT)"), spaces, "");
    else if (tagtype & MFU_TT_NTAG_210u)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG 210u (micro) 48bytes (NT2L1001G0DU)"), spaces, "");
    else if (tagtype & MFU_TT_NTAG_210)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG 210 48bytes (NT2L1011G0DU)"), spaces, "");
    else if (tagtype & MFU_TT_NTAG_212)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG 212 128bytes (NT2L1211G0DU)"), spaces, "");
    else if (tagtype & MFU_TT_NTAG_213)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG 213 144bytes (NT2H1311G0DU)"), spaces, "");
    else if (tagtype & MFU_TT_NTAG_213_F)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG 213F 144bytes (NT2H1311F0DTL)"), spaces, "");
    else if (tagtype & MFU_TT_NTAG_213_C)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG 213C 144bytes (NT2H1311C1DTL)"), spaces, "");
    else if (tagtype & MFU_TT_NTAG_213_TT)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG 213TT 144bytes (NT2H1311TTDU)"), spaces, "");
    else if (tagtype & MFU_TT_NTAG_215)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG 215 504bytes (NT2H1511G0DU)"), spaces, "");
    else if (tagtype & MFU_TT_NTAG_216)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG 216 888bytes (NT2H1611G0DU)"), spaces, "");
    else if (tagtype & MFU_TT_NTAG_216_F)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG 216F 888bytes (NT2H1611F0DTL)"), spaces, "");
    else if (tagtype & MFU_TT_NTAG_I2C_1K)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG I2C 888bytes (NT3H1101FHK)"), spaces, "");
    else if (tagtype & MFU_TT_NTAG_I2C_2K)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG I2C 1904bytes (NT3H1201FHK)"), spaces, "");
    else if (tagtype & MFU_TT_NTAG_I2C_1K_PLUS)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG I2C plus 888bytes (NT3H2111FHK)"), spaces, "");
    else if (tagtype & MFU_TT_NTAG_I2C_2K_PLUS)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG I2C plus 1912bytes (NT3H2211FHK)"), spaces, "");
    else if (tagtype & MFU_TT_MY_D)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("INFINEON my-d\x99 (SLE 66RxxS)"), spaces, "");
    else if (tagtype & MFU_TT_MY_D_NFC)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("INFINEON my-d\x99 NFC (SLE 66RxxP)"), spaces, "");
    else if (tagtype & MFU_TT_MY_D_MOVE)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("INFINEON my-d\x99 move (SLE 66R01P)"), spaces, "");
    else if (tagtype & MFU_TT_MY_D_MOVE_NFC)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("INFINEON my-d\x99 move NFC (SLE 66R01P)"), spaces, "");
    else if (tagtype & MFU_TT_MY_D_MOVE_LEAN)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("INFINEON my-d\x99 move lean (SLE 66R01L)"), spaces, "");
    else if (tagtype & MFU_TT_FUDAN_UL)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("FUDAN Ultralight Compatible (or other compatible)"), spaces, "");
    else
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("Unknown %06" PRIx64), spaces, "", tagtype);



    bool ismagic = ((tagtype & MFU_TT_MAGIC) == MFU_TT_MAGIC);
    // clear magic flag
    tagtype &= ~(MFU_TT_MAGIC);

    if (ismagic) {
        snprintf(typestr + strlen(typestr), 4, " ( ");
    }

    snprintf(typestr + strlen(typestr), sizeof(typestr) - strlen(typestr), "%s", ((tagtype & MFU_TT_MAGIC_1A) == MFU_TT_MAGIC_1A) ? _GREEN_("Gen 1a") : "");
    snprintf(typestr + strlen(typestr), sizeof(typestr) - strlen(typestr), "%s", ((tagtype & MFU_TT_MAGIC_1B) == MFU_TT_MAGIC_1B) ? _GREEN_("Gen 1b") : "");
    snprintf(typestr + strlen(typestr), sizeof(typestr) - strlen(typestr), "%s", ((tagtype & MFU_TT_MAGIC_2) == MFU_TT_MAGIC_2) ? _GREEN_("Gen 2 / CUID") : "");
    snprintf(typestr + strlen(typestr), sizeof(typestr) - strlen(typestr), "%s", ((tagtype & MFU_TT_MAGIC_4) == MFU_TT_MAGIC_4) ? _GREEN_("USCUID-UL") : "");
    snprintf(typestr + strlen(typestr), sizeof(typestr) - strlen(typestr), "%s", ((tagtype & MFU_TT_MAGIC_NTAG) == MFU_TT_MAGIC_NTAG) ? _GREEN_("NTAG CUID") : "");
    snprintf(typestr + strlen(typestr), sizeof(typestr) - strlen(typestr), "%s", ((tagtype & MFU_TT_MAGIC_NTAG21X) == MFU_TT_MAGIC_NTAG21X) ? _GREEN_("NTAG21x") : "");


    if (ismagic) {
        snprintf(typestr + strlen(typestr), 4, " )");
    }

    PrintAndLogEx(SUCCESS, "%s", typestr);
    return PM3_SUCCESS;
}

static int ulc_print_3deskey(uint8_t *data) {
    PrintAndLogEx(INFO, "    deskey1 [44/0x2C]: %s [%s]", sprint_hex(data, 4), sprint_ascii(data, 4));
    PrintAndLogEx(INFO, "    deskey1 [45/0x2D]: %s [%s]", sprint_hex(data + 4, 4), sprint_ascii(data + 4, 4));
    PrintAndLogEx(INFO, "    deskey2 [46/0x2E]: %s [%s]", sprint_hex(data + 8, 4), sprint_ascii(data + 8, 4));
    PrintAndLogEx(INFO, "    deskey2 [47/0x2F]: %s [%s]", sprint_hex(data + 12, 4), sprint_ascii(data + 12, 4));
    PrintAndLogEx(INFO, "3des key: " _GREEN_("%s"), sprint_hex_inrow(SwapEndian64(data, 16, 8), 16));
    return PM3_SUCCESS;
}

// Only takes 16 bytes of data.  Now key data available here
static int ulc_print_configuration(uint8_t *data) {

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("UL-C Configuration") " --------------------------");
    PrintAndLogEx(INFO, "Total memory....... " _YELLOW_("%u") " bytes", MAX_ULC_BLOCKS * 4);
    PrintAndLogEx(INFO, "Available memory... " _YELLOW_("%u") " bytes", (MAX_ULC_BLOCKS - 4) * 4);
    PrintAndLogEx(INFO, "40 / 0x28 | %s - %s Higher lockbits", sprint_hex(data, 4), sprint_bin(data, 2));
    PrintAndLogEx(INFO, "41 / 0x29 | %s - %s Counter", sprint_hex(data + 4, 4), sprint_bin(data + 4, 2));

    bool validAuth = (data[8] >= 0x03 && data[8] < 0x30);
    if (validAuth) {
        PrintAndLogEx(INFO, "42 / 0x2A | %s Auth0 Page " _YELLOW_("%d") "/" _YELLOW_("0x%02X") " and above need authentication"
                      , sprint_hex(data + 8, 4)
                      , data[8]
                      , data[8]
                     );
    } else {
        if (data[8] == 0) {
            PrintAndLogEx(INFO, "42 / 0x2A | %s Auth0 default", sprint_hex(data + 8, 4));
        } else if (data[8] == 0x30) {
            PrintAndLogEx(INFO, "42 / 0x2A | %s Auth0 " _GREEN_("unlocked"), sprint_hex(data + 8, 4));
        } else {
            PrintAndLogEx(INFO, "42 / 0x2A | %s Auth0 " _RED_("byte is out-of-range"), sprint_hex(data + 8, 4));
        }
    }

    PrintAndLogEx(INFO, "43 / 0x2B | %s Auth1 %s",
                  sprint_hex(data + 12, 4),
                  (data[12] & 1) ? "write access restricted" : _RED_("R/W access restricted")
                 );

    return PM3_SUCCESS;
}

static int ulaes_print_configuration(uint8_t *data, uint8_t start_page) {

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("UL-AES Configuration") " --------------------------");

    bool rid_act = (data[0] & 1);
    bool sec_msg_act = (data[0] & 2);
    bool prot = (data[4] & 0x80);
    bool cfglck = (data[4] & 0x40);
    bool cnt_inc_en = (data[4] & 8);
    bool cnt_rd_en = (data[4] & 4);
    uint16_t authlim = (data[6]) | ((data[7] & 0x3) << 8);

    PrintAndLogEx(INFO, "  cfg0 [%u/0x%02X]: " _YELLOW_("%s"), start_page, start_page, sprint_hex_inrow(data, 4));

    PrintAndLogEx(INFO, "                    - Random ID is %s", (rid_act) ? "enabled" : "disabled");
    PrintAndLogEx(INFO, "                    - Secure messaging is %s", (sec_msg_act) ? "enabled" : "disabled");
    if (data[3] < 0x3c) {
        PrintAndLogEx(INFO, "                    - page %d and above need authentication", data[3]);
    } else {
        PrintAndLogEx(INFO, "                    - pages don't need authentication");
    }
    PrintAndLogEx(INFO, "  cfg1 [%u/0x%02X]: " _YELLOW_("%s"), start_page + 1, start_page + 1,  sprint_hex_inrow(data + 4, 4));

    if (authlim == 0) {
        PrintAndLogEx(INFO, "                    - " _GREEN_("Unlimited authentication attempts"));
    } else {
        PrintAndLogEx(INFO, "                    - Max number of authentication attempts is " _YELLOW_("%d"), authlim);
    }
    PrintAndLogEx(INFO, "                    - %s access requires authentication", prot ? "Read and write" : "Write");
    PrintAndLogEx(INFO, "                    - User configuration is %s", cfglck ? _RED_("locked") : "unlocked");
    PrintAndLogEx(INFO, "                    - Counter 2 increment access %s authentication", cnt_inc_en ? "does not require" : "requires");
    PrintAndLogEx(INFO, "                    - Counter 2      read access %s authentication", cnt_rd_en ? "does not require" : "requires");
    return PM3_SUCCESS;
}

static int ulev1_print_configuration(uint64_t tagtype, uint8_t *data, uint8_t startPage) {

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Configuration"));

    bool strg_mod_en = (data[0] & 2);

    uint8_t authlim = (data[4] & 0x07);
    bool nfc_cnf_prot_pwd = ((data[4] & 0x08) == 0x08);
    bool nfc_cnf_en  = ((data[4] & 0x10) == 0x10);
    bool cfglck = ((data[4] & 0x40) == 0x40);
    bool prot = ((data[4] & 0x80) == 0x80);

    uint8_t vctid = data[5];

    PrintAndLogEx(INFO, "  cfg0 [%u/0x%02X]: " _YELLOW_("%s"), startPage, startPage, sprint_hex_inrow(data, 4));

    //NTAG213TT has different ASCII mirroring options and config bytes interpretation from other ulev1 class tags
    if (tagtype & MFU_TT_NTAG_213_TT) {
        uint8_t mirror_conf = ((data[0] & 0xE0) >> 5);
        uint8_t mirror_byte = ((data[0] & 0x18) >> 3);
        uint8_t mirror_page = data[2];

        switch (mirror_conf) {
            case 0:
                PrintAndLogEx(INFO, "                    - no ASCII mirror");
                break;
            case 1:
                PrintAndLogEx(INFO, "                    - UID ASCII mirror");
                break;
            case 2:
                PrintAndLogEx(INFO, "                    - NFC counter ASCII mirror");
                break;
            case 3:
                PrintAndLogEx(INFO, "                    - UID and NFC counter ASCII mirror");
                break;
            case 4:
                PrintAndLogEx(INFO, "                    - tag tamper ASCII mirror");
                break;
            case 5:
                PrintAndLogEx(INFO, "                    - UID and tag tamper ASCII mirror");
                break;
            case 6:
                PrintAndLogEx(INFO, "                    - NFC counter and tag tamper ASCII mirror");
                break;
            case 7:
                PrintAndLogEx(INFO, "                    - UID, NFC counter, and tag tamper ASCII mirror");
                break;
            default:
                break;
        }

        if (mirror_conf) {
            uint8_t mirror_user_mem_start_byte = (4 * (mirror_page - 4)) + mirror_byte;
            uint8_t bytes_required_for_mirror_data = 0;

            switch (mirror_conf) {
                case 1:
                    bytes_required_for_mirror_data = 14;
                    break;
                case 2:
                    bytes_required_for_mirror_data = 6;
                    break;
                case 3:
                    bytes_required_for_mirror_data = 8;
                    break;
                case 4:
                    bytes_required_for_mirror_data = 21;
                    break;
                case 5:
                    bytes_required_for_mirror_data = 23;
                    break;
                case 6:
                    bytes_required_for_mirror_data = 15;
                    break;
                case 7:
                    bytes_required_for_mirror_data = 30;
                    break;
                default:
                    break;
            }
            PrintAndLogEx(INFO, "                mirror start page %02X | byte pos %02X - %s"
                          , mirror_page, mirror_byte
                          , (mirror_page >= 0x4 && ((mirror_user_mem_start_byte + bytes_required_for_mirror_data) <= 144)) ? _GREEN_("ok") : _YELLOW_("Invalid value")
                         );
        }

    } else if (tagtype & (MFU_TT_NTAG_213_F | MFU_TT_NTAG_216_F)) {
        uint8_t mirror_conf = ((data[0] & 0xC0) >> 6);
        uint8_t mirror_byte = (data[0] & 0x30);
        bool sleep_en = (data[0] & 0x08);
        strg_mod_en = (data[0] & 0x04);
        uint8_t fdp_conf = (data[0] & 0x03);

        switch (mirror_conf) {
            case 0:
                PrintAndLogEx(INFO, "                    - no ASCII mirror");
                break;
            case 1:
                PrintAndLogEx(INFO, "                    - UID ASCII mirror");
                break;
            case 2:
                PrintAndLogEx(INFO, "                    - NFC counter ASCII mirror");
                break;
            case 3:
                PrintAndLogEx(INFO, "                    - UID and NFC counter ASCII mirror");
                break;
            default:
                break;
        }

        PrintAndLogEx(INFO, "                    - SLEEP mode %s", (sleep_en) ? "enabled" : "disabled");

        switch (fdp_conf) {
            case 0:
                PrintAndLogEx(INFO, "                    - no field detect");
                break;
            case 1:
                PrintAndLogEx(INFO, "                    - enabled by first State-of-Frame (start of communication)");
                break;
            case 2:
                PrintAndLogEx(INFO, "                    - enabled by selection of the tag");
                break;
            case 3:
                PrintAndLogEx(INFO, "                    - enabled by field presence");
                break;
            default:
                break;
        }
        // valid mirror start page and byte position within start page.
        if (tagtype & MFU_TT_NTAG_213_F) {
            switch (mirror_conf) {
                case 1:
                { PrintAndLogEx(INFO, "         mirror start block %02X | byte pos %02X - %s", data[2], mirror_byte, (data[2] >= 0x4 && data[2] <= 0x24) ? "OK" : "Invalid value"); break;}
                case 2:
                { PrintAndLogEx(INFO, "         mirror start block %02X | byte pos %02X - %s", data[2], mirror_byte, (data[2] >= 0x4 && data[2] <= 0x26) ? "OK" : "Invalid value"); break;}
                case 3:
                { PrintAndLogEx(INFO, "         mirror start block %02X | byte pos %02X - %s", data[2], mirror_byte, (data[2] >= 0x4 && data[2] <= 0x22) ? "OK" : "Invalid value"); break;}
                default:
                    break;
            }
        } else if (tagtype & MFU_TT_NTAG_216_F) {
            switch (mirror_conf) {
                case 1:
                { PrintAndLogEx(INFO, "         mirror start block %02X | byte pos %02X - %s", data[2], mirror_byte, (data[2] >= 0x4 && data[2] <= 0xDE) ? "OK" : "Invalid value"); break;}
                case 2:
                { PrintAndLogEx(INFO, "         mirror start block %02X | byte pos %02X - %s", data[2], mirror_byte, (data[2] >= 0x4 && data[2] <= 0xE0) ? "OK" : "Invalid value"); break;}
                case 3:
                { PrintAndLogEx(INFO, "         mirror start block %02X | byte pos %02X - %s", data[2], mirror_byte, (data[2] >= 0x4 && data[2] <= 0xDC) ? "OK" : "Invalid value"); break;}
                default:
                    break;
            }
        }
    }
    PrintAndLogEx(INFO, "                    - strong modulation mode %s", (strg_mod_en) ? "enabled" : "disabled");

    if (data[3] < 0xff)
        PrintAndLogEx(INFO, "                    - page %d and above need authentication", data[3]);
    else
        PrintAndLogEx(INFO, "                    - pages don't need authentication");

    uint8_t tt_enabled = 0;
    uint8_t tt_message[4] = {0x00};
    uint8_t tt_msg_resp_len = 0;
    uint8_t tt_status_resp[5] = {0x00};

    if (tagtype & MFU_TT_NTAG_213_TT) {
        tt_enabled = (data[1] & 0x02);
        tt_msg_resp_len = ul_read(45, tt_message, 4);

        PrintAndLogEx(INFO, "                    - tamper detection feature is %s"
                      , (tt_enabled) ? _GREEN_("ENABLED") : "disabled"
                     );

        switch (data[1] & 0x06) {
            case 0x00:
                PrintAndLogEx(INFO, "                    - tamper message is unlocked and read/write enabled");
                break;
            case 0x02:
                PrintAndLogEx(INFO, "                    - tamper message is reversibly read/write locked in memory while the tamper feature is enabled");
                break;
            case 0x04:
            case 0x06:
                PrintAndLogEx(INFO, "                    - tamper message is permanently read/write locked in memory");
                break;
            default:
                break;
        }
    }

    PrintAndLogEx(INFO, "  cfg1 [%u/0x%02X]: " _YELLOW_("%s"), startPage + 1, startPage + 1,  sprint_hex_inrow(data + 4, 4));
    if (authlim == 0)
        PrintAndLogEx(INFO, "                    - " _GREEN_("Unlimited password attempts"));
    else
        PrintAndLogEx(INFO, "                    - Max number of password attempts is " _YELLOW_("%d"), authlim);

    PrintAndLogEx(INFO, "                    - NFC counter %s", (nfc_cnf_en) ? "enabled" : "disabled");
    PrintAndLogEx(INFO, "                    - NFC counter %s", (nfc_cnf_prot_pwd) ? "password protection enabled" : "not protected");

    PrintAndLogEx(INFO, "                    - user configuration %s", cfglck ? "permanently locked" : "writeable");
    PrintAndLogEx(INFO, "                    - %s access is protected with password", prot ? "read and write" : "write");
    PrintAndLogEx(INFO, "                    - %02X, Virtual Card Type Identifier is %sdefault", vctid, (vctid == 0x05) ? "" : "not ");
    PrintAndLogEx(INFO, "  PWD  [%u/0x%02X]: %s ( cannot be read )", startPage + 2, startPage + 2,  sprint_hex_inrow(data + 8, 4));
    PrintAndLogEx(INFO, "  PACK [%u/0x%02X]: %s     ( cannot be read )", startPage + 3, startPage + 3,  sprint_hex_inrow(data + 12, 2));
    PrintAndLogEx(INFO, "  RFU  [%u/0x%02X]:     %s ( cannot be read )", startPage + 3, startPage + 3,  sprint_hex_inrow(data + 14, 2));

    if (tagtype & MFU_TT_NTAG_213_TT) {
        if (data[1] & 0x06) {
            PrintAndLogEx(INFO, "TT_MSG [45/0x2D]: %s (cannot be read)", sprint_hex_inrow(tt_message, tt_msg_resp_len));
            PrintAndLogEx(INFO, "                    - tamper message is masked in memory");
        } else {
            PrintAndLogEx(INFO, "TT_MSG [45/0x2D]: %s", sprint_hex_inrow(tt_message, tt_msg_resp_len));
            PrintAndLogEx(INFO, "                    - tamper message is %s and is readable/writablbe in memory", sprint_hex(tt_message, tt_msg_resp_len));
        }
    }

    //The NTAG213TT only returns meaningful information for the fields below if the tamper feature is enabled
    if ((tagtype & MFU_TT_NTAG_213_TT) && tt_enabled) {

        int tt_status_len = ntagtt_getTamperStatus(tt_status_resp, 5);
        if (tt_status_len != 5) {
            PrintAndLogEx(WARNING, "Error sending the READ_TT_STATUS command to tag\n");
            return PM3_ESOFT;
        }

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "--- " _CYAN_("Tamper Status"));
        PrintAndLogEx(INFO, "  READ_TT_STATUS: %s", sprint_hex_inrow(tt_status_resp, 5));

        PrintAndLogEx(INFO, "     Tamper status result from this power-up:");
        switch (tt_status_resp[4]) {
            case 0x43:
                PrintAndLogEx(INFO, "            - Tamper loop was detcted as closed during this power-up");
                break;
            case 0x4F:
                PrintAndLogEx(INFO, "            - Tamper loop was detected as open during this power-up");
                break;
            case 0x49:
                PrintAndLogEx(INFO, "            - Tamper loop measurement was not enabled or not valid during this power-up");
                break;
            default:
                break;
        }

        PrintAndLogEx(INFO, "     Tamper detection permanent memory:");
        if ((tt_status_resp[0] | tt_status_resp [1] | tt_status_resp[2] | tt_status_resp[3]) == 0x00)

            PrintAndLogEx(INFO, "            - Tamper loop has never been detected as open during power-up");
        else {
            PrintAndLogEx(INFO, "            - Tamper loop was detected as open during power-up at least once");
            PrintAndLogEx(INFO, "            - Tamper message returned by READ_TT_STATUS command: %s", sprint_hex(tt_status_resp, 4));
        }
    }
    return PM3_SUCCESS;
}

static int ulev1_print_counters(void) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Counters"));
    uint8_t tear[1] = {0};
    uint8_t counter[3] = {0, 0, 0};
    int len = 0;
    for (uint8_t i = 0; i < 3; ++i) {
        ulev1_readTearing(i, tear, sizeof(tear));
        len = ulev1_readCounter(i, counter, sizeof(counter));
        if (len == 3) {
            PrintAndLogEx(INFO, "       [%0d]: %s", i, sprint_hex(counter, 3));
            PrintAndLogEx(SUCCESS, "            - %02X tearing ( %s )"
                          , tear[0]
                          , (tear[0] == 0xBD) ? _GREEN_("ok") : _RED_("fail")
                         );
        }
    }
    return len;
}

static int ulev1_print_signature(uint64_t tagtype, uint8_t *uid, uint8_t *signature, size_t signature_len) {

#define PUBLIC_ECDA_KEYLEN 33
#define PUBLIC_ECDA_192_KEYLEN 49
    // known public keys for the originality check (source: https://github.com/alexbatalov/node-nxp-originality-verifier)
    // ref: AN11350 NTAG 21x Originality Signature Validation
    // ref: AN11341 MIFARE Ultralight EV1 Originality Signature Validation
    const ecdsa_publickey_t nxp_mfu_public_keys[] = {
        {"NXP MIFARE Classic MFC1C14_x",   "044F6D3F294DEA5737F0F46FFEE88A356EED95695DD7E0C27A591E6F6F65962BAF"},
        {"MIFARE Classic / QL88",          "046F70AC557F5461CE5052C8E4A7838C11C7A236797E8A0730A101837C004039C2"},
        {"NXP ICODE DNA, ICODE SLIX2",     "048878A2A2D3EEC336B4F261A082BD71F9BE11C4E2E896648B32EFA59CEA6E59F0"},
        {"NXP Public key",                 "04A748B6A632FBEE2C0897702B33BEA1C074998E17B84ACA04FF267E5D2C91F6DC"},
        {"NXP Ultralight Ev1",             "0490933BDCD6E99B4E255E3DA55389A827564E11718E017292FAF23226A96614B8"},
        {"NXP NTAG21x (2013)",             "04494E1A386D3D3CFE3DC10E5DE68A499B1C202DB5B132393E89ED19FE5BE8BC61"},
        {"MIKRON Public key",              "04F971EDA742A4A80D32DCF6A814A707CC3DC396D35902F72929FDCD698B3468F2"},
        {"VivoKey Spark1 Public key",      "04D64BB732C0D214E7EC580736ACF847284B502C25C0F7F2FA86AACE1DADA4387A"},
        {"TruST25 (ST) key 01?",           "041D92163650161A2548D33881C235D0FB2315C2C31A442F23C87ACF14497C0CBA"},
        {"TruST25 (ST) key 04?",           "04101E188A8B4CDDBC62D5BC3E0E6850F0C2730E744B79765A0E079907FBDB01BC"},
    };

    // https://www.nxp.com/docs/en/application-note/AN13452.pdf
    const ecdsa_publickey_t nxp_mfu_192_public_keys[] = {
        {"NXP Ultralight AES", "0453BF8C49B7BD9FE3207A91513B9C1D238ECAB07186B772104AB535F7D3AE63CF7C7F3DD0D169DA3E99E43C6399621A86"},
    };

    /*
        uint8_t nxp_mfu_public_keys[6][PUBLIC_ECDA_KEYLEN] = {
            // UL, NTAG21x and NDEF
            {
                0x04, 0x49, 0x4e, 0x1a, 0x38, 0x6d, 0x3d, 0x3c,
                0xfe, 0x3d, 0xc1, 0x0e, 0x5d, 0xe6, 0x8a, 0x49,
                0x9b, 0x1c, 0x20, 0x2d, 0xb5, 0xb1, 0x32, 0x39,
                0x3e, 0x89, 0xed, 0x19, 0xfe, 0x5b, 0xe8, 0xbc, 0x61
            },
            // UL EV1
            {
                0x04, 0x90, 0x93, 0x3b, 0xdc, 0xd6, 0xe9, 0x9b,
                0x4e, 0x25, 0x5e, 0x3d, 0xa5, 0x53, 0x89, 0xa8,
                0x27, 0x56, 0x4e, 0x11, 0x71, 0x8e, 0x01, 0x72,
                0x92, 0xfa, 0xf2, 0x32, 0x26, 0xa9, 0x66, 0x14, 0xb8
            },
            // unknown. Needs identification
            {
                0x04, 0x4F, 0x6D, 0x3F, 0x29, 0x4D, 0xEA, 0x57,
                0x37, 0xF0, 0xF4, 0x6F, 0xFE, 0xE8, 0x8A, 0x35,
                0x6E, 0xED, 0x95, 0x69, 0x5D, 0xD7, 0xE0, 0xC2,
                0x7A, 0x59, 0x1E, 0x6F, 0x6F, 0x65, 0x96, 0x2B, 0xAF
            },
            // unknown. Needs identification
            {
                0x04, 0xA7, 0x48, 0xB6, 0xA6, 0x32, 0xFB, 0xEE,
                0x2C, 0x08, 0x97, 0x70, 0x2B, 0x33, 0xBE, 0xA1,
                0xC0, 0x74, 0x99, 0x8E, 0x17, 0xB8, 0x4A, 0xCA,
                0x04, 0xFF, 0x26, 0x7E, 0x5D, 0x2C, 0x91, 0xF6, 0xDC
            },
            // manufacturer public key
            {
                0x04, 0x6F, 0x70, 0xAC, 0x55, 0x7F, 0x54, 0x61,
                0xCE, 0x50, 0x52, 0xC8, 0xE4, 0xA7, 0x83, 0x8C,
                0x11, 0xC7, 0xA2, 0x36, 0x79, 0x7E, 0x8A, 0x07,
                0x30, 0xA1, 0x01, 0x83, 0x7C, 0x00, 0x40, 0x39, 0xC2
            },
            // MIKRON public key.
            {
                0x04, 0xf9, 0x71, 0xed, 0xa7, 0x42, 0xa4, 0xa8,
                0x0d, 0x32, 0xdc, 0xf6, 0xa8, 0x14, 0xa7, 0x07,
                0xcc, 0x3d, 0xc3, 0x96, 0xd3, 0x59, 0x02, 0xf7,
                0x29, 0x29, 0xfd, 0xcd, 0x69, 0x8b, 0x34, 0x68, 0xf2
            }
        };
    */
    uint8_t i;
    bool is_valid = false;
    if (signature_len == 32) {
        for (i = 0; i < ARRAYLEN(nxp_mfu_public_keys); i++) {

            int dl = 0;
            uint8_t key[PUBLIC_ECDA_KEYLEN] = {0};
            param_gethex_to_eol(nxp_mfu_public_keys[i].value, 0, key, PUBLIC_ECDA_KEYLEN, &dl);

            int res = ecdsa_signature_r_s_verify(MBEDTLS_ECP_DP_SECP128R1, key, uid, 7, signature, signature_len, false);

            is_valid = (res == 0);
            if (is_valid)
                break;
        }
    }

    bool is_192_valid = false;
    if (signature_len == 48) {
        for (i = 0; i < ARRAYLEN(nxp_mfu_192_public_keys); i++) {
            int dl = 0;
            uint8_t key[PUBLIC_ECDA_192_KEYLEN] = {0};
            param_gethex_to_eol(nxp_mfu_192_public_keys[i].value, 0, key, PUBLIC_ECDA_192_KEYLEN, &dl);

            int res = ecdsa_signature_r_s_verify(MBEDTLS_ECP_DP_SECP192R1, key, uid, 7, signature, signature_len, false);

            is_192_valid = (res == 0);
            if (is_192_valid)
                break;
        }
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Signature"));
    if (is_192_valid) {
        PrintAndLogEx(INFO, " IC signature public key name: " _GREEN_("%s"), nxp_mfu_192_public_keys[i].desc);
        PrintAndLogEx(INFO, "IC signature public key value: %s", nxp_mfu_192_public_keys[i].value);
        PrintAndLogEx(INFO, "    Elliptic curve parameters: NID_secp192r1");
        PrintAndLogEx(INFO, "             TAG IC Signature: %s", sprint_hex_inrow(signature, signature_len));
        PrintAndLogEx(SUCCESS, "       Signature verification ( " _GREEN_("successful") " )");
        return PM3_SUCCESS;
    }

    if (is_valid) {
        PrintAndLogEx(INFO, " IC signature public key name: " _GREEN_("%s"), nxp_mfu_public_keys[i].desc);
        PrintAndLogEx(INFO, "IC signature public key value: %s", nxp_mfu_public_keys[i].value);
        PrintAndLogEx(INFO, "    Elliptic curve parameters: NID_secp128r1");
        PrintAndLogEx(INFO, "             TAG IC Signature: %s", sprint_hex_inrow(signature, signature_len));
        PrintAndLogEx(SUCCESS, "       Signature verification ( " _GREEN_("successful") " )");
        return PM3_SUCCESS;
    }

    PrintAndLogEx(INFO, "    Elliptic curve parameters: %s", (signature_len == 48) ? "NID_secp192r1" : "NID_secp128r1");
    PrintAndLogEx(INFO, "             TAG IC Signature: %s", sprint_hex_inrow(signature, signature_len));
    PrintAndLogEx(SUCCESS, "       Signature verification ( " _RED_("fail") " )");
    return PM3_ESOFT;
}

static int ulev1_print_version(uint8_t *data) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Version"));
    PrintAndLogEx(INFO, "       Raw bytes: " _YELLOW_("%s"), sprint_hex_inrow(data, 8));
    PrintAndLogEx(INFO, "       Vendor ID: %02X, %s", data[1], getTagInfo(data[1]));
    PrintAndLogEx(INFO, "    Product type: %s", getProductTypeStr(data[2]));
    PrintAndLogEx(INFO, " Product subtype: %02X, %s", data[3], (data[3] == 1) ? "17 pF" : "50pF");
    PrintAndLogEx(INFO, "   Major version: %02X", data[4]);
    PrintAndLogEx(INFO, "   Minor version: %02X", data[5]);
    PrintAndLogEx(INFO, "            Size: %s", getUlev1CardSizeStr(data[6]));
    PrintAndLogEx(INFO, "   Protocol type: %02X%s", data[7], (data[7] == 0x3) ? ", ISO14443-3 Compliant" : "");
    return PM3_SUCCESS;
}

static int ntag_print_counter(void) {
    // NTAG has one counter/tearing.  At address 0x02.
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Counter"));
    uint8_t tear[1] = {0};
    uint8_t counter[3] = {0, 0, 0};
    uint16_t len;
    len = ulev1_readTearing(0x02, tear, sizeof(tear));
    (void)len;
    len = ulev1_readCounter(0x02, counter, sizeof(counter));
    (void)len;
    PrintAndLogEx(INFO, "       [02]: %s", sprint_hex(counter, 3));
    PrintAndLogEx(SUCCESS, "            - %02X tearing ( %s )"
                  , tear[0]
                  , (tear[0] == 0xBD) ? _GREEN_("ok") : _RED_("fail")
                 );
    return len;
}

/*
static int ulc_magic_test(){
    // Magic Ultralight test
        // Magic UL-C, by observation,
    // 1) it seems to have a static nonce response to 0x1A command.
    // 2) the deskey bytes is not-zero:d out on as datasheet states.
    // 3) UID - changeable, not only, but pages 0-1-2-3.
    // 4) use the ul_magic_test !  magic tags answers specially!
    int returnValue = UL_ERROR;
    iso14a_card_select_t card;
    uint8_t nonce1[11] = {0x00};
    uint8_t nonce2[11] = {0x00};
    if ( !ul_select(&card) ){
        return MFU_TT_UL_ERROR;
    }
    int status = ulc_requestAuthentication(nonce1, sizeof(nonce1));
    if ( status <= 0 ) {
        status = ulc_requestAuthentication(nonce2, sizeof(nonce2));
        returnValue =  ( !memcmp(nonce1, nonce2, 11) ) ? MFU_TT_UL_C_MAGIC : MFU_TT_UL_C;
    } else {
        returnValue = MFU_TT_UL;
    }
    DropField();
    return returnValue;
}
*/
static uint64_t ul_magic_test(void) {
    // Magic Ultralight tests
    // 1) take present UID, and try to write it back. OBSOLETE
    // 2) make a wrong length write to page0, and see if tag answers with ACK/NACK:

    DropField();

    iso14a_card_select_t card;
    if (ul_select_rats(&card) == false) {
        return MFU_TT_UL_ERROR;
    }

    /*
    // iceman:  how to proper identify RU based UID cards
    if (
        (memcmp(card.uid, "\xAA\x55\x39", 3) == 0) ||
        (memcmp(card.uid, "\xAA\x55\xC3", 3) == 0)
        ) {
            // Ul-5 MFU Ev1 FUID,
        return MFU_TT_UL_EV1_MAGIC;
    }
    */
    PrintAndLogEx(DEBUG, "%u - %s", card.ats_len, sprint_hex_inrow(card.ats, card.ats_len));

    // USCUID-UL cards
    if (card.ats_len == 18) {

        // USCUID-UL configuration
        // https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/magic_cards_notes.md#uscuid-ul-configuration-guide
        // identify:   ATS len 18,
        //     First 8 bytes can vary depending on setup. next 8 bytes is GET VERSION data and finally 2 byte crc
        //
        //  \x85\x00\x00\xA0\x0A\x00\x0A\xC3 \x00\x04\x03\x01\x01\x00\x0B\x03 \xZZ\xZZ
        //
        // 7AFF - back door enabled
        // 8500 -
        //  if we ignore first 8 bytes we can identify regardless how card is configured
        //
        if (compare_ul_family(card.ats + 8, 8)) {
            return MFU_TT_MAGIC_4 | MFU_TT_MAGIC;
        }
    }

    // Direct write alternative cards
    if (card.ats_len == 14) {

        // UL Direct Write ,  UL-C Direct write,  NTAG 213 Direct write
        if (memcmp(card.ats, "\x0A\x78\x00\x81\x02\xDB\xA0\xC1\x19\x40\x2A\xB5", 12) == 0) {
            return MFU_TT_MAGIC_2;
        }
    }


    int status = ul_comp_write(0, NULL, 0);
    DropField();
    if (status == PM3_SUCCESS) {
        PrintAndLogEx(INFO, "comp write pass");
        return MFU_TT_MAGIC_2 | MFU_TT_MAGIC;
    }

    // check for GEN1A, GEN1B and NTAG21x
    PacketResponseNG resp;
    clearCommandBuffer();
    uint8_t payload[] = { 0 };
    SendCommandNG(CMD_HF_MIFARE_CIDENT, payload, sizeof(payload));

    uint16_t is_generation = MAGIC_FLAG_NONE;
    if (WaitForResponseTimeout(CMD_HF_MIFARE_CIDENT, &resp, 1500)) {
        if ((resp.status == PM3_SUCCESS) && resp.length == sizeof(uint16_t)) {
            is_generation = resp.data.asDwords[0] & 0xFFFF;
        }
    }

    if ((is_generation & MAGIC_FLAG_GEN_1A) == MAGIC_FLAG_GEN_1A) {
        return MFU_TT_MAGIC_1A | MFU_TT_MAGIC;
    }

    if ((is_generation & MAGIC_FLAG_GEN_1B) == MAGIC_FLAG_GEN_1B) {
        return MFU_TT_MAGIC_1B | MFU_TT_MAGIC;
    }

    if ((is_generation & MAGIC_FLAG_NTAG21X) == MAGIC_FLAG_NTAG21X) {
        return MFU_TT_MAGIC_NTAG21X | MFU_TT_MAGIC;
    }

    return MFU_TT_UNKNOWN;
}

static char *mfu_generate_filename(const char *prefix, const char *suffix) {
    iso14a_card_select_t card;
    if (ul_select(&card) == false) {
        PrintAndLogEx(WARNING, "No tag found.");
        return NULL;
    }

    char *fptr = calloc(sizeof(char) * (strlen(prefix) + strlen(suffix)) + sizeof(card.uid) * 2 + 1,  sizeof(uint8_t));
    strcpy(fptr, prefix);
    FillFileNameByUID(fptr, card.uid, suffix, card.uidlen);
    return fptr;
}

// used with the Amiibo dumps loading...
// Not related to 'hf mfu dump'
static int mfu_dump_tag(uint16_t pages, void **pdata, uint16_t *len) {

    // read uid
    iso14a_card_select_t card;
    if (ul_select(&card) == false) {
        return PM3_ECARDEXCHANGE;
    }

    int res = PM3_SUCCESS;
    uint16_t maxbytes = (pages * MFU_BLOCK_SIZE);

    *pdata = calloc(maxbytes, sizeof(uint8_t));
    if (*pdata == NULL) {
        PrintAndLogEx(FAILED, "error, cannot allocate memory");
        res = PM3_EMALLOC;
        goto out;
    }

    // UL_EV1/NTAG auth
    uint8_t keytype = 2;
    // generate PWD
    uint8_t key[4] = {0};
    num_to_bytes(ul_ev1_pwdgenB(card.uid), 4, key);

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_MIFAREU_READCARD, 0, pages, keytype, key, 4);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 2500) == false) {
        PrintAndLogEx(WARNING, "command execution time out");
        free(*pdata);
        res = PM3_ETIMEOUT;
        goto out;
    }

    if (resp.oldarg[0] != 1) {
        PrintAndLogEx(WARNING, "Failed reading card");
        free(*pdata);
        res = PM3_ESOFT;
        goto out;
    }

    // read all memory
    uint32_t startindex = resp.oldarg[2];
    uint32_t buffer_size = resp.oldarg[1];
    if (buffer_size > maxbytes) {
        PrintAndLogEx(FAILED, "Data exceeded buffer size!");
        buffer_size = maxbytes;
    }

    if (GetFromDevice(BIG_BUF, *pdata, buffer_size, startindex, NULL, 0, NULL, 2500, false) == false) {
        PrintAndLogEx(WARNING, "command execution time out");
        free(*pdata);
        res = PM3_ETIMEOUT;
        goto out;
    }

    if (len) {
        *len = buffer_size;
    }

out:
    return res;
}

/*
Lego Dimensions,
  Version: 00 04 04 02 01 00 0F 03

  matching bytes:
  index 12  ( 3 * 4 )
   E1 10 12 00 01 03 A0 0C 34 03 13 D1 01 0F 54 02 65 6E
*/

typedef struct {
    const char *desc;
    uint8_t mpos;
    uint8_t mlen;
    const char *match;
    uint32_t (*otp)(const uint8_t *uid);
    const char *hint;
} mfu_otp_identify_t;

static mfu_otp_identify_t mfu_otp_ident_table[] = {
    { "SALTO Systems card", 12, 4, "534C544F", ul_c_otpgenA, NULL },
    { NULL, 0, 0, NULL, NULL, NULL }
};

static mfu_otp_identify_t *mfu_match_otp_fingerprint(uint8_t *uid, uint8_t *data) {
    uint8_t i = 0;
    do {
        int ml = 0;
        uint8_t mtmp[40] = {0};

        // static or dynamic created OTP to fingerprint.
        if (mfu_otp_ident_table[i].match) {
            param_gethex_to_eol(mfu_otp_ident_table[i].match, 0, mtmp, sizeof(mtmp), &ml);
        } else {
            uint32_t otp = mfu_otp_ident_table[i].otp(uid);
            num_to_bytes(otp, 4, mtmp);
        }

        int min = MIN(mfu_otp_ident_table[i].mlen, 4);

        PrintAndLogEx(DEBUG, "uid.... %s", sprint_hex_inrow(uid, 7));
        PrintAndLogEx(DEBUG, "calc... %s", sprint_hex_inrow(mtmp, 4));
        PrintAndLogEx(DEBUG, "dump... %s", sprint_hex_inrow(data + mfu_otp_ident_table[i].mpos, min));

        bool m2 = (memcmp(mtmp, data + mfu_otp_ident_table[i].mpos, min) == 0);
        if (m2) {
            PrintAndLogEx(DEBUG, "(fingerprint) found %s", mfu_otp_ident_table[i].desc);
            return &mfu_otp_ident_table[i];
        }
    } while (mfu_otp_ident_table[++i].desc);
    return NULL;
}

typedef struct {
    const char *desc;
    const char *version;
    uint8_t mpos;
    uint8_t mlen;
    const char *match;
    uint32_t (*Pwd)(const uint8_t *uid);
    uint16_t (*Pack)(const uint8_t *uid);
    const char *hint;
} mfu_identify_t;

static mfu_identify_t mfu_ident_table[] = {
    {
        "Jooki", "0004040201000F03",
        12, 32, "E11012000103A00C340329D101255504732E6A6F6F6B692E726F636B732F732F",
        ul_ev1_pwdgen_def, ul_ev1_packgen_def,
        "hf mfu ndefread"
    },
    {
        "Lego Dimensions", "0004040201000F03",
        12, 18, "E11012000103A00C340313D1010F5402656E",
        ul_ev1_pwdgenC, ul_ev1_packgenC,
        "hf mfu dump -k %08x"
    },
    {
        "Hotwheels", "0004040201000F03",
        9, 9, "E110120F",
        ul_ev1_pwdgen_def, ul_ev1_packgen_def,
        "hf mfu dump -k %08x"
    },
    {
        "Minecraft Earth", "0004040201000F03",
        9, 26, "48F6FFE1101200037C91012C55027069642E6D617474656C2F4167",
        ul_ev1_pwdgen_def, ul_ev1_packgen_def,
        "hf mfu dump -k %08x"
    },
    {
        "Snackworld", "0004040101000B03",
        9, 7, "483000E1100600",
        NULL, NULL,
        "hf mfu dump -k"
    },
    {
        "Amiibo", "0004040201001103",
        9, 9, "480FE0F110FFEEA500",
        ul_ev1_pwdgenB, ul_ev1_packgenB,
        "hf mfu dump -k %08x"
    },
    {
        "Amiibo - Power Up band", "0004040502021303",
        8, 10, "44000FE0F110FFEEA500",
        ul_ev1_pwdgenB, ul_ev1_packgenB,
        "hf mfu dump -k %08x"
    },
    /*
    {
        "Xiaomi AIR Purifier", "0004040201000F03",
        0, 0, "",
        ul_ev1_pwdgenE, ul_ev1_packgenE,
        "hf mfu dump -k %08x"
    },
    */
    {
        "Philips Toothbrush", "0004040201010F03",
        16, 20, "0310D1010C55027068696C6970732E636F6DFE00",
        ul_ev1_pwdgen_def, ul_ev1_packgen_def,
        "hf mfu pwdgen -r"
    },
    {
        "Philips Toothbrush", "0004040201010F03",
        16, 36, "0320D1011C55027068696C6970732E636F6D2F6E6663627275736868656164746170FE00",
        ul_ev1_pwdgen_def, ul_ev1_packgen_def,
        "hf mfu pwdgen -r"
    },
    {
        "Bank Of Archie brothers", "0004030101000B03",
        9, 11, "48F6FF0000000036343533",
        ul_ev1_pwdgen_def, ul_ev1_packgen_def,
        NULL
    },
    {
        "Art-Dass NFT card", "0004040201000F03",
        16, 16, "033ED1013A5504617274646173732E6E",
        ul_ev1_pwdgen_def, ul_ev1_packgen_def,
        NULL
    },
    {
        "Bonverde Coffe card", "0004030101000B03",
        18, 4, "644B05AA",
        ul_ev1_pwdgen_def, ul_ev1_packgen_def,
        NULL
    },
    {NULL, NULL, 0, 0, NULL, NULL, NULL, NULL}
};

static mfu_identify_t *mfu_match_fingerprint(const uint8_t *version, const uint8_t *data) {
    uint8_t i = 0;
    do {

        int vl = 0;
        uint8_t vtmp[10] = {0};
        param_gethex_to_eol(mfu_ident_table[i].version, 0, vtmp, sizeof(vtmp), &vl);

        bool m1 = (memcmp(vtmp, version, vl) == 0);
        if (m1 == false) {
            PrintAndLogEx(DEBUG, "(fingerprint) wrong version");
            continue;
        }

        int ml = 0;
        uint8_t mtmp[40] = {0};
        param_gethex_to_eol(mfu_ident_table[i].match, 0, mtmp, sizeof(mtmp), &ml);

        bool m2 = (memcmp(mtmp, data + mfu_ident_table[i].mpos, mfu_ident_table[i].mlen) == 0);
        if (m2) {
            PrintAndLogEx(DEBUG, "(fingerprint) found %s", mfu_ident_table[i].desc);
            return &mfu_ident_table[i];
        }
    } while (mfu_ident_table[++i].desc);
    return NULL;
}

static uint8_t mfu_max_len(void) {
    uint8_t n = 0, i = 0;
    do {
        uint8_t tmp = mfu_ident_table[i].mpos + mfu_ident_table[i].mlen;
        if (tmp > n) {
            n = tmp;
        }
    } while (mfu_ident_table[++i].desc);
    return n;
}

static int mfu_get_version_uid(uint8_t *version, uint8_t *uid) {
    iso14a_card_select_t card;
    if (ul_select(&card) == false) {
        return PM3_ESOFT;
    }
    memcpy(uid, card.uid, card.uidlen);

    uint8_t v[10] = {0x00};
    int len  = ulev1_getVersion(v, sizeof(v));
    DropField();
    if (len != sizeof(v)) {
        return PM3_ESOFT;
    }

    memcpy(version, v, 8);
    return PM3_SUCCESS;
}

static int mfu_fingerprint(uint64_t tagtype, bool hasAuthKey, const uint8_t *authkey, int ak_len) {

    uint8_t dbg_curr = DBG_NONE;
    uint8_t *data = NULL;
    int res = PM3_ESOFT;
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Fingerprint"));
    uint8_t maxbytes = mfu_max_len();
    if (maxbytes == 0) {
        PrintAndLogEx(ERR, "fingerprint table wrong");
        res = PM3_ESOFT;
        goto out;
    }

    maxbytes = ((maxbytes / MFU_BLOCK_SIZE) + 1) * MFU_BLOCK_SIZE;
    data = calloc(maxbytes, sizeof(uint8_t));
    if (data == NULL) {
        PrintAndLogEx(ERR, "failed to allocate memory");
        res = PM3_EMALLOC;
        goto out;
    }

    uint8_t pages = (maxbytes / MFU_BLOCK_SIZE);
    uint8_t keytype = 0;

    if (hasAuthKey) {
        if (tagtype & MFU_TT_UL_C)
            keytype = 1; // UL_C auth
        else
            keytype = 2; // UL_EV1/NTAG auth
    }

    if (getDeviceDebugLevel(&dbg_curr) != PM3_SUCCESS) {
        res = PM3_ESOFT;
        goto out;
    }

    if (setDeviceDebugLevel(DBG_NONE, false) != PM3_SUCCESS) {
        res = PM3_ESOFT;
        goto out;
    }

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_MIFAREU_READCARD, 0, pages, keytype, authkey, ak_len);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 2500) == false) {
        PrintAndLogEx(WARNING, "command execution time out");
        res = PM3_ETIMEOUT;
        goto out;
    }

    if (resp.oldarg[0] != 1) {
        PrintAndLogEx(WARNING, "Failed reading card");
        res = PM3_ESOFT;
        goto out;
    }

    // read all memory
    uint32_t startindex = resp.oldarg[2];
    uint32_t buffer_size = resp.oldarg[1];

    if (buffer_size > maxbytes) {
        PrintAndLogEx(FAILED, "Data exceeded buffer size!");
        buffer_size = maxbytes;
    }

    if (GetFromDevice(BIG_BUF, data, buffer_size, startindex, NULL, 0, NULL, 2500, false) == false) {
        PrintAndLogEx(WARNING, "command execution time out");
        res = PM3_ETIMEOUT;
        goto out;
    }

    uint8_t version[8] = {0};
    uint8_t uid[7] = {0};
    if (mfu_get_version_uid(version, uid) == PM3_SUCCESS) {
        mfu_identify_t *item = mfu_match_fingerprint(version, data);
        if (item) {
            PrintAndLogEx(SUCCESS, _GREEN_("%s"), item->desc);
            res = PM3_SUCCESS;

            if (item->hint) {
                if (item->Pwd) {
                    char s[40] = {0};
                    snprintf(s, sizeof(s), item->hint, item->Pwd(uid));
                    PrintAndLogEx(HINT, "Use `" _YELLOW_("%s") "`", s);
                } else {
                    PrintAndLogEx(HINT, "Use `" _YELLOW_("%s") "`", item->hint);
                }
            }
        }
    }

    // OTP checks
    mfu_otp_identify_t *item = mfu_match_otp_fingerprint(uid, data);
    if (item) {
        PrintAndLogEx(SUCCESS, _GREEN_("%s"), item->desc);
        res = PM3_SUCCESS;

        if (item->hint) {
            if (item->otp) {
                char s[40] = {0};
                snprintf(s, sizeof(s), item->hint, item->otp(uid));
                PrintAndLogEx(HINT, "Use `" _YELLOW_("%s") "`", s);
            } else {
                PrintAndLogEx(HINT, "Use `" _YELLOW_("%s") "`", item->hint);
            }
        }
    }

out:

    if (res != PM3_SUCCESS) {
        PrintAndLogEx(INFO, "n/a");
    }

    setDeviceDebugLevel(dbg_curr, false);
    free(data);
    return res;
}

static int mfu_write_block(const uint8_t *data, uint8_t datalen, bool has_auth_key,  bool has_pwd, const uint8_t *auth_key_ptr, uint8_t blockno) {

    // 4 or 16.
    uint8_t cmd[32];
    memcpy(cmd, data, datalen);

    // 0 - no pwd/key, no authentication
    // 1 - 3des key (16 bytes)
    // 2 - pwd  (4 bytes)
    uint8_t keytype = 0;
    size_t cmdlen = datalen;
    if (has_auth_key) {
        keytype = 1;
        memcpy(cmd + datalen, auth_key_ptr, 16);
        cmdlen += 16;
    } else if (has_pwd) {
        keytype = 2;
        memcpy(cmd + datalen, auth_key_ptr, 4);
        cmdlen += 4;
    }

    clearCommandBuffer();
    if (datalen == 16) {
        SendCommandMIX(CMD_HF_MIFAREU_WRITEBL_COMPAT, blockno, keytype, 0, cmd, cmdlen);
    } else {
        SendCommandMIX(CMD_HF_MIFAREU_WRITEBL, blockno, keytype, 0, cmd, cmdlen);
    }
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500) == false) {
        return PM3_ETIMEOUT;
    }

    uint8_t isOK  = resp.oldarg[0] & 0xFF;
    if (isOK) {
        return PM3_SUCCESS;
    }
    return PM3_ESOFT;
}

uint64_t GetHF14AMfU_Type(void) {

    uint64_t tagtype = MFU_TT_UNKNOWN;
    iso14a_card_select_t card;

    if (ul_select(&card) == false)
        return MFU_TT_UL_ERROR;

    // Ultralight - ATQA / SAK
    if (card.atqa[1] != 0x00 || card.atqa[0] != 0x44 || card.sak != 0x00) {
        //PrintAndLogEx(NORMAL, "Tag is not Ultralight | NTAG | MY-D  [ATQA: %02X %02X SAK: %02X]\n", card.atqa[1], card.atqa[0], card.sak);
        DropField();
        return MFU_TT_UL_ERROR;
    }

    if (card.uid[0] != 0x05) {

        uint8_t version[10] = {0x00};
        int len  = ulev1_getVersion(version, sizeof(version));
        DropField();

        switch (len) {
            case 0x0A: {
                /*
                MF0UL1001DUx 0004030100000B03
                MF0UL1101DUx 0004030101000B03
                MF0ULH1101DUx 0004030201000B03
                MF0UL1141DUF 0004030301000B03
                MF0UL2101Dxy 0004030101000E03
                MF0UL2101DUx 0004030201000E03
                MF0UL3101DUx 0004030101001103
                MF0ULH3101DUx 0004030201001103
                MF0UL5101DUx 0004030101001303
                NT2L1011F0DUx 0004040101000B03
                NT2H1011G0DUD 0004040201000B03
                NT2L1211F0DUx 0004040101000E03
                NT2H1311G0DUx 0004040201000F03
                NT2H1311F0Dxy 0004040401000F03
                NT2H1411G0DUx 0004040201011103
                NT2H1511G0DUx 0004040201001103
                NT2H1511F0Dxy 0004040401001103
                NT2H1611G0DUx 0004040201001303
                NT2H1611F0Dxy 0004040401001303
                NT2H1311C1DTL 0004040201010F03
                NT2H1311TTDUx 0004040203000F03
                NT3H1101W0FHK 0004040502001303
                NT3H1201W0FHK 0004040502001503
                NT3H1101W0FHK_Variant 0004040502011303
                NT3H1201 0004040502011503
                NT3H2111 0004040502021303
                NT3H2211 0004040502021503
                nhs 0004040600001303
                MF0UN0001DUx 0004030102000B03
                MF0UNH0001DUx 0004030202000B03
                MF0UN1001DUx 0004030103000B03
                MF0UNH1001DUx 0004030203000B03
                NT2L1001G0DUx 0004040102000B03
                NT2H1001G0DUx 0004040202000B03
                NT2H1311TTDUx 0004040203000F03
                MF0AES2001DUD 0004030104000F03

                Micron UL       0034210101000E03
                Feiju NTAG      0053040201000F03
                Feiju NTAG 215  0005340201001103
                */

                if (memcmp(version, "\x00\x04\x03\x01\x01\x00\x0B", 7) == 0)      { tagtype = MFU_TT_UL_EV1_48; break; }
                else if (memcmp(version, "\x00\x04\x03\x01\x02\x00\x0B", 7) == 0) { tagtype = MFU_TT_UL_NANO_40; break; }
                else if (memcmp(version, "\x00\x04\x03\x02\x01\x00\x0B", 7) == 0) { tagtype = MFU_TT_UL_EV1_48; break; }
                else if (memcmp(version, "\x00\x04\x03\x01\x01\x00\x0E", 7) == 0) { tagtype = MFU_TT_UL_EV1_128; break; }
                else if (memcmp(version, "\x00\x04\x03\x02\x01\x00\x0E", 7) == 0) { tagtype = MFU_TT_UL_EV1_128; break; }
                else if (memcmp(version, "\x00\x04\x03\x01\x04\x00\x0F\x03", 8) == 0) { tagtype = MFU_TT_UL_AES; break; }
                else if (memcmp(version, "\x00\x34\x21\x01\x01\x00\x0E", 7) == 0) { tagtype = MFU_TT_UL_EV1_128; break; } // Mikron JSC Russia EV1 41 pages tag
                else if (memcmp(version, "\x00\x04\x04\x01\x01\x00\x0B", 7) == 0) { tagtype = MFU_TT_NTAG_210; break; }
                else if (memcmp(version, "\x00\x04\x04\x01\x02\x00\x0B", 7) == 0) { tagtype = MFU_TT_NTAG_210u; break; }
                else if (memcmp(version, "\x00\x04\x04\x02\x02\x00\x0B", 7) == 0) { tagtype = MFU_TT_NTAG_210u; break; }
                else if (memcmp(version, "\x00\x04\x04\x01\x01\x00\x0E", 7) == 0) { tagtype = MFU_TT_NTAG_212; break; }
                else if (memcmp(version, "\x00\x04\x04\x02\x01\x00\x0F", 7) == 0) { tagtype = MFU_TT_NTAG_213; break; }
                else if (memcmp(version, "\x00\x53\x04\x02\x01\x00\x0F", 7) == 0) { tagtype = MFU_TT_NTAG_213; break; } // Shanghai Feiju Microelectronics Co. Ltd. China (Xiaomi Air Purifier filter)
                else if (memcmp(version, "\x00\x04\x04\x02\x01\x01\x0F", 7) == 0) { tagtype = MFU_TT_NTAG_213_C; break; }
                else if (memcmp(version, "\x00\x04\x04\x02\x01\x00\x11", 7) == 0) { tagtype = MFU_TT_NTAG_215; break; }
                else if (memcmp(version, "\x00\x05\x34\x02\x01\x00\x11", 7) == 0) { tagtype = MFU_TT_NTAG_215; break; }  // Shanghai Feiju  Microelectronics Co. Ltd. China
                else if (memcmp(version, "\x00\x04\x04\x02\x01\x00\x13", 7) == 0) { tagtype = MFU_TT_NTAG_216; break; }
                else if (memcmp(version, "\x00\x04\x04\x04\x01\x00\x0F", 7) == 0) { tagtype = MFU_TT_NTAG_213_F; break; }
                else if (memcmp(version, "\x00\x04\x04\x04\x01\x00\x13", 7) == 0) { tagtype = MFU_TT_NTAG_216_F; break; }
                else if (memcmp(version, "\x00\x04\x04\x02\x03\x00\x0F", 7) == 0) { tagtype = MFU_TT_NTAG_213_TT; break; }
                else if (memcmp(version, "\x00\x04\x04\x05\x02\x01\x13", 7) == 0) { tagtype = MFU_TT_NTAG_I2C_1K; break; }
                else if (memcmp(version, "\x00\x04\x04\x05\x02\x01\x15", 7) == 0) { tagtype = MFU_TT_NTAG_I2C_2K; break; }
                else if (memcmp(version, "\x00\x04\x04\x05\x02\x02\x13", 7) == 0) { tagtype = MFU_TT_NTAG_I2C_1K_PLUS; break; }
                else if (memcmp(version, "\x00\x04\x04\x05\x02\x02\x15", 7) == 0) { tagtype = MFU_TT_NTAG_I2C_2K_PLUS; break; }
                else if (version[2] == 0x04) { tagtype = MFU_TT_NTAG; break; }
                else if (version[2] == 0x03) { tagtype = MFU_TT_UL_EV1; }
                break;
            }
            case 0x01:
                tagtype = MFU_TT_UL_C;
                break;
            case 0x00:
                tagtype = MFU_TT_UL;
                break;
            case PM3_ETIMEOUT:
            case PM3_EWRONGANSWER:
                tagtype = (MFU_TT_UL | MFU_TT_UL_C | MFU_TT_NTAG_203);
                break;  // could be UL | UL_C magic tags
            default  :
                tagtype = MFU_TT_UNKNOWN;
                break;
        }

        // This is a test from cards that doesn't answer to GET_VERSION command
        // UL vs UL-C vs NTAG203 vs FUDAN FM11NT021 (which is NTAG213 compatiable)
        if (tagtype & (MFU_TT_UL | MFU_TT_UL_C | MFU_TT_NTAG_203)) {
            if (ul_select(&card) == false) {
                return MFU_TT_UL_ERROR;
            }

            // do UL_C check first...
            uint8_t nonce[11] = {0x00};
            int status = ulc_requestAuthentication(nonce, sizeof(nonce));
            DropField();
            if (status > 1) {
                tagtype = MFU_TT_UL_C;
            } else {
                // need to re-select after authentication error
                if (ul_select(&card) == false) {
                    return MFU_TT_UL_ERROR;
                }

                uint8_t data[16] = {0x00};

                // read page 0x26-0x29 (last valid ntag203 page)
                // if error response, its ULTRALIGHT since doesn't have that memory block
                status = ul_read(0x26, data, sizeof(data));
                if (status <= 1) {
                    tagtype = MFU_TT_UL;
                } else {

                    // read page 44 / 0x2C
                    // if error response, its NTAG203 since doesn't have that memory block
                    status = ul_read(0x2C, data, sizeof(data));
                    if (status <= 1) {
                        tagtype = MFU_TT_NTAG_203;
                    } else {

                        // read page 48 / 0x30
                        // if response, its FUDAN FM11NT021
                        status = ul_read(0x30, data, sizeof(data));
                        if (status == sizeof(data)) {
                            tagtype = MFU_TT_NTAG_213;
                        } else  {
                            tagtype = MFU_TT_UNKNOWN;
                        }
                    }
                }
                DropField();
            }
        }

        if (tagtype & MFU_TT_UL) {
            tagtype = ul_fudan_check();
            DropField();
        }
    } else {
        DropField();
        // Infinition MY-D tests   Exam high nibble
        uint8_t nib = (card.uid[1] & 0xf0) >> 4;
        switch (nib) {
            // case 0: tagtype =  SLE66R35E7; break; //or SLE 66R35E7 - mifare compat... should have different sak/atqa for mf 1k
            case 1:
                tagtype =  MFU_TT_MY_D;
                break; // or SLE 66RxxS ... up to 512 pages of 8 user bytes...
            case 2:
                tagtype = MFU_TT_MY_D_NFC;
                break; // or SLE 66RxxP ... up to 512 pages of 8 user bytes... (or in nfc mode FF pages of 4 bytes)
            case 3:
                tagtype = (MFU_TT_MY_D_MOVE | MFU_TT_MY_D_MOVE_NFC);
                break; // or SLE 66R01P // 38 pages of 4 bytes //notice: we can not currently distinguish between these two
            case 7:
                tagtype =  MFU_TT_MY_D_MOVE_LEAN;
                break; // or SLE 66R01L  // 16 pages of 4 bytes
        }
    }

    tagtype |= ul_magic_test();
    if (tagtype == (MFU_TT_UNKNOWN | MFU_TT_MAGIC)) {
        tagtype = (MFU_TT_UL_MAGIC);
    }

    return tagtype;
}
//
//  extended tag information
//
static int CmdHF14AMfUInfo(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu info",
                  "Get info about MIFARE Ultralight Family styled tag.\n"
                  "Sometimes the tags are locked down, and you may need a key to be able to read the information",
                  "hf mfu info\n"
                  "hf mfu info -k AABBCCDD\n"
                  "hf mfu info --key 00112233445566778899AABBCCDDEEFF"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("k", "key", "<hex>", "Authentication key (UL-C 16 bytes, EV1/NTAG 4 bytes)"),
        arg_lit0("l", NULL, "Swap entered key's endianness"),
//        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0(NULL, "force", "override `hw dbg` settings"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int ak_len = 0;
    uint8_t authenticationkey[16] = {0x00};
    CLIGetHexWithReturn(ctx, 1, authenticationkey, &ak_len);
    bool swap_endian = arg_get_lit(ctx, 2);
//    bool verbose = arg_get_lit(ctx, 3);
    bool override = (arg_get_lit(ctx, 3) == false);
    CLIParserFree(ctx);

    if (ak_len) {
        if (ak_len != 16 && ak_len != 4) {
            PrintAndLogEx(WARNING, "ERROR: Key is incorrect length\n");
            return PM3_EINVARG;
        }
    }

    bool has_auth_key = false;
    if (ak_len > 0)
        has_auth_key = true;

    uint8_t authlim = 0xff;
    uint8_t data[16] = {0x00};
    iso14a_card_select_t card;
    int status;
    uint8_t *authkeyptr = authenticationkey;
    uint8_t pwd[4] = {0, 0, 0, 0};
    uint8_t *key = pwd;
    uint8_t pack[4] = {0, 0, 0, 0};
    int len;

    uint64_t tagtype = GetHF14AMfU_Type();
    if (tagtype == MFU_TT_UL_ERROR) {
        return PM3_ESOFT;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " --------------------------");
    ul_print_type(tagtype, 6);

    // Swap endianness
    if (swap_endian && has_auth_key) {
        authkeyptr = SwapEndian64(authenticationkey, ak_len, (ak_len == 16) ? 8 : 4);
    }

    if (ul_auth_select(&card, tagtype, has_auth_key, authkeyptr, pack, sizeof(pack)) == PM3_ESOFT) {
        return PM3_ESOFT;
    }

    bool locked = false;
    // read pages 0,1,2,3 (should read 4 pages)
    status = ul_read(0, data, sizeof(data));
    if (status <= 0) {
        DropField();
        PrintAndLogEx(ERR, "Error: tag didn't answer to READ");
        return PM3_ESOFT;
    } else if (status == 16) {
        ul_print_default(data, card.uid);
        ndef_print_CC(data + 12);
    } else {
        locked = true;
    }

    // UL_C Specific
    if ((tagtype & MFU_TT_UL_C)) {

        // read pages 0x28, 0x29, 0x2A, 0x2B
        uint8_t ulc_conf[16] = {0x00};
        status = ul_read(0x28, ulc_conf, sizeof(ulc_conf));
        if (status <= 0) {
            PrintAndLogEx(ERR, "Error: tag didn't answer to READ UL-C");
            PrintAndLogEx(HINT, "Hint: tag is likely fully read protected");
            DropField();
            return PM3_ESOFT;
        }

        if (status == 16) {
            ulc_print_configuration(ulc_conf);
        } else {
            locked = true;
        }

        mfu_fingerprint(tagtype, has_auth_key, authkeyptr, ak_len);

        DropField();

        if ((tagtype & MFU_TT_MAGIC) == MFU_TT_MAGIC) {
            //just read key
            uint8_t ulc_deskey[16] = {0x00};
            status = ul_read(0x2C, ulc_deskey, sizeof(ulc_deskey));
            if (status <= 0) {
                DropField();
                PrintAndLogEx(ERR, "Error: tag didn't answer to READ magic");
                return PM3_ESOFT;
            }

            if (status == 16) {
                ulc_print_3deskey(ulc_deskey);
            }

            PrintAndLogEx(NORMAL, "");
            return PM3_SUCCESS;

        } else {
            // if we called info with key, just return
            if (has_auth_key) {
                PrintAndLogEx(NORMAL, "");
                return PM3_SUCCESS;
            }

            // also try to diversify default keys..  look into CmdHF14AMfGenDiverseKeys
            if (try_default_3des_keys(override, &key) == PM3_SUCCESS) {
                PrintAndLogEx(SUCCESS, "Found default 3des key: ");
                uint8_t keySwap[16];
                memcpy(keySwap, SwapEndian64(key, 16, 8), 16);
                ulc_print_3deskey(keySwap);
            } else {
                PrintAndLogEx(INFO, "n/a");
            }

            PrintAndLogEx(NORMAL, "");
            return PM3_SUCCESS;
        }
    }

    // Specific UL-AES
    if (tagtype & MFU_TT_UL_AES) {

        // read pages 0x28, 0x29, 0x2A, 0x2B
        uint8_t ulaes_conf[16] = {0x00};
        status = ul_read(0x29, ulaes_conf, sizeof(ulaes_conf));
        if (status <= 0) {
            PrintAndLogEx(ERR, "Error: tag didn't answer to READ UL-AES");
            DropField();
            return PM3_ESOFT;
        }

        if (status == 16) {
            ulaes_print_configuration(ulaes_conf, 0x29);
        } else {
            locked = true;
        }

        DropField();

        // also try to diversify default keys..  look into CmdHF14AMfGenDiverseKeys
        if (try_default_aes_keys(override) != PM3_SUCCESS) {
            PrintAndLogEx(INFO, "n/a");
        }
        DropField();

        if (ul_auth_select(&card, tagtype, has_auth_key, authkeyptr, pack, sizeof(pack)) == PM3_ESOFT) {
            return PM3_ESOFT;
        }
    }

    // do counters and signature first (don't neet auth)

    // ul counters are different than ntag counters
    if ((tagtype & (MFU_TT_UL_EV1_48 | MFU_TT_UL_EV1_128 | MFU_TT_UL_EV1))) {
        if (ulev1_print_counters() != 3) {
            // failed - re-select
            if (ul_auth_select(&card, tagtype, has_auth_key, authkeyptr, pack, sizeof(pack)) == PM3_ESOFT) {
                return PM3_ESOFT;
            }
        }
    }

    // NTAG counters?
    if ((tagtype & (MFU_TT_NTAG_213 | MFU_TT_NTAG_213_F | MFU_TT_NTAG_213_C | MFU_TT_NTAG_213_TT | MFU_TT_NTAG_215 | MFU_TT_NTAG_216))) {
        if (ntag_print_counter()) {
            // failed - re-select
            if (ul_auth_select(&card, tagtype, has_auth_key, authkeyptr, pack, sizeof(pack)) == PM3_ESOFT) {
                return PM3_ESOFT;
            }
        }
    }

    // Read signature
    if ((tagtype & (MFU_TT_UL_EV1_48 | MFU_TT_UL_EV1_128 | MFU_TT_UL_EV1 | MFU_TT_UL_NANO_40 |
                    MFU_TT_NTAG_210u | MFU_TT_NTAG_213 | MFU_TT_NTAG_213_F | MFU_TT_NTAG_213_C |
                    MFU_TT_NTAG_213_TT | MFU_TT_NTAG_215 | MFU_TT_NTAG_216 | MFU_TT_NTAG_216_F |
                    MFU_TT_NTAG_I2C_1K | MFU_TT_NTAG_I2C_2K | MFU_TT_NTAG_I2C_1K_PLUS | MFU_TT_NTAG_I2C_2K_PLUS |
                    MFU_TT_UL_AES))) {
        uint8_t ulev1_signature[48] = {0x00};
        status = ulev1_readSignature(ulev1_signature, sizeof(ulev1_signature));
        if (status < 0) {
            PrintAndLogEx(ERR, "Error: tag didn't answer to READ SIGNATURE");
            DropField();
            return PM3_ESOFT;
        }
        if (status == 32 || status == 34) {
            ulev1_print_signature(tagtype, card.uid, ulev1_signature, 32);
        } else if (status == 48) {
            ulev1_print_signature(tagtype, card.uid, ulev1_signature, 48);
        } else {
            // re-select
            if (ul_auth_select(&card, tagtype, has_auth_key, authkeyptr, pack, sizeof(pack)) == PM3_ESOFT) {
                return PM3_ESOFT;
            }
        }

        // print silicon info
        ul_print_nxp_silicon_info(card.uid);

        // Get Version
        uint8_t version[10] = {0x00};
        status  = ulev1_getVersion(version, sizeof(version));
        if (status < 0) {
            PrintAndLogEx(ERR, "Error: tag didn't answer to GETVERSION");
            DropField();
            return PM3_ESOFT;
        } else if (status == 10) {
            ulev1_print_version(version);
        } else {
            locked = true;
            if (ul_auth_select(&card, tagtype, has_auth_key, authkeyptr, pack, sizeof(pack)) == PM3_ESOFT) {
                return PM3_ESOFT;
            }
        }

        // Don't check config / passwords for Ul AES :)
        if (tagtype == MFU_TT_UL_AES) {
            goto out;
        }

        uint8_t startconfigblock = 0;
        uint8_t ulev1_conf[16] = {0x00};

        for (uint8_t i = 1; i < ARRAYLEN(UL_TYPES_ARRAY); i++) {
            if ((tagtype & UL_TYPES_ARRAY[i]) == UL_TYPES_ARRAY[i]) {
                startconfigblock = UL_MEMORY_ARRAY[i] - 3;
                break;
            }
        }

        if (startconfigblock) { // if we know where the config block is...
            status = ul_read(startconfigblock, ulev1_conf, sizeof(ulev1_conf));
            if (status <= 0) {
                PrintAndLogEx(ERR, "Error: tag didn't answer to READ EV1");
                DropField();
                return PM3_ESOFT;
            } else if (status == 16) {
                // save AUTHENTICATION LIMITS for later:
                authlim = (ulev1_conf[4] & 0x07);
                // add pwd / pack if used from cli
                if (has_auth_key) {
                    memcpy(ulev1_conf + 8, authkeyptr, 4);
                    memcpy(ulev1_conf + 12, pack, 2);
                }
                ulev1_print_configuration(tagtype, ulev1_conf, startconfigblock);
            }
        }

        // AUTHLIMIT, (number of failed authentications)
        // 0 = limitless.
        // 1-7 = limit. No automatic tries then.
        // hasAuthKey,  if we was called with key, skip test.
        if (!authlim && (has_auth_key == false)) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(SUCCESS, "--- " _CYAN_("Known EV1/NTAG passwords"));

            // test pwd gen A
            num_to_bytes(ul_ev1_pwdgenA(card.uid), 4, key);
            len = ulev1_requestAuthentication(key, pack, sizeof(pack));
            if (len > -1) {
                has_auth_key = true;
                ak_len = 4;
                memcpy(authenticationkey, key, 4);
                PrintAndLogEx(SUCCESS, "Password... " _GREEN_("%s") "  pack... " _GREEN_("%02X%02X"), sprint_hex_inrow(key, 4), pack[0], pack[1]);
                goto out;
            }

            if (ul_auth_select(&card, tagtype, has_auth_key, authkeyptr, pack, sizeof(pack)) == PM3_ESOFT) {
                return PM3_ESOFT;
            }

            // test pwd gen B
            num_to_bytes(ul_ev1_pwdgenB(card.uid), 4, key);
            len = ulev1_requestAuthentication(key, pack, sizeof(pack));
            if (len > -1) {
                has_auth_key = true;
                ak_len = 4;
                memcpy(authenticationkey, key, 4);
                PrintAndLogEx(SUCCESS, "Password... " _GREEN_("%s") "  pack... " _GREEN_("%02X%02X"), sprint_hex_inrow(key, 4), pack[0], pack[1]);
                goto out;
            }

            if (ul_auth_select(&card, tagtype, has_auth_key, authkeyptr, pack, sizeof(pack)) == PM3_ESOFT) {
                return PM3_ESOFT;
            }

            // test pwd gen C
            num_to_bytes(ul_ev1_pwdgenC(card.uid), 4, key);
            len = ulev1_requestAuthentication(key, pack, sizeof(pack));
            if (len > -1) {
                has_auth_key = true;
                ak_len = 4;
                memcpy(authenticationkey, key, 4);
                PrintAndLogEx(SUCCESS, "Password... " _GREEN_("%s") "  pack... " _GREEN_("%02X%02X"), sprint_hex_inrow(key, 4), pack[0], pack[1]);
                goto out;
            }

            if (ul_auth_select(&card, tagtype, has_auth_key, authkeyptr, pack, sizeof(pack)) == PM3_ESOFT) {
                return PM3_ESOFT;
            }

            // test pwd gen D
            num_to_bytes(ul_ev1_pwdgenD(card.uid), 4, key);
            len = ulev1_requestAuthentication(key, pack, sizeof(pack));
            if (len > -1) {
                has_auth_key = true;
                ak_len = 4;
                memcpy(authenticationkey, key, 4);
                PrintAndLogEx(SUCCESS, "Password... " _GREEN_("%s") "  pack... " _GREEN_("%02X%02X"), sprint_hex_inrow(key, 4), pack[0], pack[1]);
                goto out;
            }

            if (ul_auth_select(&card, tagtype, has_auth_key, authkeyptr, pack, sizeof(pack)) == PM3_ESOFT) {
                return PM3_ESOFT;
            }

            for (uint8_t i = 0; i < ARRAYLEN(default_pwd_pack); ++i) {
                key = default_pwd_pack[i];
                len = ulev1_requestAuthentication(key, pack, sizeof(pack));
                if (len > -1) {
                    has_auth_key = true;
                    ak_len = 4;
                    memcpy(authenticationkey, key, 4);
                    PrintAndLogEx(SUCCESS, "Password... " _GREEN_("%s") "  pack... " _GREEN_("%02X%02X"), sprint_hex_inrow(key, 4), pack[0], pack[1]);
                    break;
                } else {
                    if (ul_auth_select(&card, tagtype, has_auth_key, authkeyptr, pack, sizeof(pack)) == PM3_ESOFT) {
                        return PM3_ESOFT;
                    }
                }
            }
            if (len < 1) {
                PrintAndLogEx(WARNING, _YELLOW_("password not known"));
                PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`hf mfu pwdgen -r`") " to get see known pwd gen algo suggestions");
            }
        } else {
            if (locked) {
                PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`hf mfu pwdgen -r`") " to get see known pwd gen algo suggestions");
            }
        }
    }

out:
    DropField();

    mfu_fingerprint(tagtype, has_auth_key, authkeyptr, ak_len);

    if (locked) {
        PrintAndLogEx(INFO, "\nTag appears to be locked, try using a key to get more info");
        PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`hf mfu pwdgen -r`") " to get see known pwd gen algo suggestions");
    }

    if (tagtype & (MFU_TT_MAGIC_1A | MFU_TT_MAGIC_1B | MFU_TT_MAGIC_2)) {
        PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`script run hf_mfu_setuid -h`") " to set UID");
    }

    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

//
//  Write Single Block
//
static int CmdHF14AMfUWrBl(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu wrbl",
                  "Write a block. It autodetects card type.",
                  "hf mfu wrbl -b 0 -d 01234567\n"
                  "hf mfu wrbl -b 0 -d 01234567 -k AABBCCDD\n"
                  "hf mfu wrbl -b 0 -d 01234567 -k 00112233445566778899AABBCCDDEEFF"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("k", "key", "<hex>", "Authentication key (UL-C 16 bytes, EV1/NTAG 4 bytes)"),
        arg_lit0("l", NULL, "Swap entered key's endianness"),
        arg_int1("b", "block", "<dec>", "Block number to write"),
        arg_str1("d", "data", "<hex>", "Block data (4 or 16 hex bytes, 16 hex bytes will do a compatibility write)"),
        arg_lit0(NULL, "force", "Force operation even if address is out of range"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int ak_len = 0;
    uint8_t authenticationkey[16] = {0x00};
    CLIGetHexWithReturn(ctx, 1, authenticationkey, &ak_len);
    bool swap_endian = arg_get_lit(ctx, 2);

    int blockno = arg_get_int_def(ctx, 3, -1);

    int datalen = 0;
    uint8_t data[16] = {0x00};
    CLIGetHexWithReturn(ctx, 4, data, &datalen);
    bool force = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    bool has_auth_key = false;
    bool has_pwd = false;
    if (ak_len == 16) {
        has_auth_key = true;
    } else if (ak_len == 4) {
        has_pwd = true;
    } else if (ak_len != 0) {
        PrintAndLogEx(WARNING, "ERROR: Key is incorrect length\n");
        return PM3_EINVARG;
    }

    if (blockno < 0) {
        PrintAndLogEx(WARNING, "Wrong block number");
        return PM3_EINVARG;
    }

    if (datalen != 16 && datalen != 4) {
        PrintAndLogEx(WARNING, "Wrong data length. Expect 16 or 4, got %d", datalen);
        return PM3_EINVARG;
    }

    uint8_t *auth_key_ptr = authenticationkey;

    // starting with getting tagtype
    uint64_t tagtype = GetHF14AMfU_Type();
    if (tagtype == MFU_TT_UL_ERROR)
        return PM3_ESOFT;

    uint8_t maxblockno = 0;
    for (uint8_t idx = 1; idx < ARRAYLEN(UL_TYPES_ARRAY); idx++) {
        if ((tagtype & UL_TYPES_ARRAY[idx]) == UL_TYPES_ARRAY[idx]) {
            maxblockno = UL_MEMORY_ARRAY[idx];
            break;
        }
    }
    if ((blockno > maxblockno) && (!force)) {
        PrintAndLogEx(WARNING, "block number too large. Max block is %u/0x%02X \n", maxblockno, maxblockno);
        return PM3_EINVARG;
    }

    // Swap endianness
    if (swap_endian) {
        if (has_auth_key)
            auth_key_ptr = SwapEndian64(authenticationkey, 16, 8);

        if (has_pwd)
            auth_key_ptr = SwapEndian64(authenticationkey, 4, 4);
    }

    if (blockno <= 3)
        PrintAndLogEx(INFO, "Special block: %0d (0x%02X) [ %s]", blockno, blockno, sprint_hex(data, datalen));
    else
        PrintAndLogEx(INFO, "Block: %0d (0x%02X) [ %s]", blockno, blockno, sprint_hex(data, datalen));

    if (ak_len) {
        PrintAndLogEx(INFO, "Using %s " _GREEN_("%s"), (ak_len == 16) ? "3des" : "pwd", sprint_hex(authenticationkey, ak_len));
    }


    // Send write Block.
    uint8_t *d = data;
    int res = 0;
    if (datalen == 16) {
        // Comp write may take 16bytes, but only write 4bytes.   See UL-C datasheet
        for (uint8_t i = 0; i < 4; i++) {

            res = mfu_write_block(d, 4, has_auth_key, has_pwd, auth_key_ptr, blockno + i);
            if (res == PM3_SUCCESS) {
                d += 4;
            } else {
                PrintAndLogEx(INFO, "Write ( %s )", _RED_("fail"));
                return PM3_ESOFT;
            }
        }

        if (res == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "Write ( " _GREEN_("ok") " )");
            PrintAndLogEx(HINT, "Try `" _YELLOW_("hf mfu rdbl -b %u") "` to verify ", blockno);
        }

    } else {
        res = mfu_write_block(data, datalen, has_auth_key, has_pwd, auth_key_ptr, blockno);
        switch (res) {
            case PM3_SUCCESS: {
                PrintAndLogEx(SUCCESS, "Write ( " _GREEN_("ok") " )");
                PrintAndLogEx(HINT, "Try `" _YELLOW_("hf mfu rdbl -b %u") "` to verify ", blockno);
                break;
            }
            case PM3_ESOFT: {
                PrintAndLogEx(FAILED, "Write ( " _RED_("fail") " )");
                PrintAndLogEx(HINT, "Check password / key!");
                break;
            }
            case PM3_ETIMEOUT:
            default: {
                PrintAndLogEx(WARNING, "command execution time out");
                break;
            }
        }
    }

    return res;
}
//
//  Read Single Block
//
static int CmdHF14AMfURdBl(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu rdbl",
                  "Read a block and print. It autodetects card type.",
                  "hf mfu rdbl -b 0\n"
                  "hf mfu rdbl -b 0 -k AABBCCDD\n"
                  "hf mfu rdbl -b 0 --key 00112233445566778899AABBCCDDEEFF"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("k", "key", "<hex>", "Authentication key (UL-C 16 bytes, EV1/NTAG 4 bytes)"),
        arg_lit0("l", NULL, "Swap entered key's endianness"),
        arg_int1("b", "block", "<dec>", "Block number to read"),
        arg_lit0(NULL, "force", "Force operation even if address is out of range"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int ak_len = 0;
    uint8_t authenticationkey[16] = {0x00};
    CLIGetHexWithReturn(ctx, 1, authenticationkey, &ak_len);
    bool swap_endian = arg_get_lit(ctx, 2);
    int blockno = arg_get_int_def(ctx, 3, -1);
    bool force = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    bool has_auth_key = false;
    bool has_pwd = false;
    if (ak_len == 16) {
        has_auth_key = true;
    } else if (ak_len == 4) {
        has_pwd = true;
    } else if (ak_len != 0) {
        PrintAndLogEx(WARNING, "ERROR: Key is incorrect length\n");
        return PM3_EINVARG;
    }

    if (blockno < 0) {
        PrintAndLogEx(WARNING, "Wrong block number");
        return PM3_EINVARG;
    }

    uint8_t *authKeyPtr = authenticationkey;

    // start with getting tagtype
    uint64_t tagtype = GetHF14AMfU_Type();
    if (tagtype == MFU_TT_UL_ERROR)
        return PM3_ESOFT;

    uint8_t maxblockno = 0;
    for (uint8_t idx = 1; idx < ARRAYLEN(UL_TYPES_ARRAY); idx++) {
        if ((tagtype & UL_TYPES_ARRAY[idx]) == UL_TYPES_ARRAY[idx]) {
            maxblockno = UL_MEMORY_ARRAY[idx];
            break;
        }
    }
    if ((blockno > maxblockno) && (!force)) {
        PrintAndLogEx(WARNING, "block number to large. Max block is %u/0x%02X \n", maxblockno, maxblockno);
        return PM3_EINVARG;
    }

    // Swap endianness
    if (swap_endian) {
        if (has_auth_key)
            authKeyPtr = SwapEndian64(authenticationkey, ak_len, 8);

        if (has_pwd)
            authKeyPtr = SwapEndian64(authenticationkey, ak_len, 4);
    }

    if (ak_len) {
        PrintAndLogEx(INFO, "Using %s " _GREEN_("%s"), (ak_len == 16) ? "3des" : "pwd", sprint_hex(authenticationkey, ak_len));
    }

    //Read Block
    uint8_t keytype = 0;
    uint8_t datalen = 0;
    if (has_auth_key) {
        keytype = 1;
        datalen = 16;
    } else if (has_pwd) {
        keytype = 2;
        datalen = 4;
    }

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_MIFAREU_READBL, blockno, keytype, 0, authKeyPtr, datalen);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        uint8_t isOK = resp.oldarg[0] & 0xff;
        if (isOK) {
            uint8_t *d = resp.data.asBytes;
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, "Block#  | Data        | Ascii");
            PrintAndLogEx(INFO, "-----------------------------");
            PrintAndLogEx(INFO, "%02d/0x%02X | %s| %s\n", blockno, blockno, sprint_hex(d, 4), sprint_ascii(d, 4));
        } else {
            PrintAndLogEx(WARNING, "Failed reading block: ( %02x )", isOK);
        }
    } else {
        PrintAndLogEx(WARNING, "command execution time out");
    }
    return PM3_SUCCESS;
}

void mfu_print_dump(mfu_dump_t *card, uint16_t pages, uint8_t startpage, bool dense_output) {

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, _CYAN_("MFU dump file information"));
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    PrintAndLogEx(INFO, "Version..... " _YELLOW_("%s"), sprint_hex(card->version, sizeof(card->version)));
    PrintAndLogEx(INFO, "TBD 0....... %s", sprint_hex(card->tbo, sizeof(card->tbo)));
    PrintAndLogEx(INFO, "TBD 1....... %s", sprint_hex(card->tbo1, sizeof(card->tbo1)));
    PrintAndLogEx(INFO, "Signature... %s", sprint_hex(card->signature, 16));
    PrintAndLogEx(INFO, "             %s", sprint_hex(card->signature + 16, sizeof(card->signature) - 16));
    for (uint8_t i = 0; i < 3; i ++) {
        PrintAndLogEx(INFO, "Counter %d... %s", i, sprint_hex(card->counter_tearing[i], 3));
        PrintAndLogEx(INFO, "Tearing %d... %s", i, sprint_hex(card->counter_tearing[i] + 3, 1));
    }

    // 0-bases index,  to get total bytes, its +1 page.
    // UL-C,
    //  Max index page is 47.
    //  total pages is 48
    //  total bytes is 192
    PrintAndLogEx(INFO, "Max data page... " _YELLOW_("%d") " ( " _YELLOW_("%d") " bytes )", card->pages, (card->pages + 1) * MFU_BLOCK_SIZE);
    PrintAndLogEx(INFO, "Header size..... %d bytes", MFU_DUMP_PREFIX_LENGTH);

    uint8_t j = 0;
    bool lckbit = false;
    uint8_t *data = card->data;

    uint8_t lockbytes_sta[] = {0, 0};
    uint8_t lockbytes_dyn[] = {0, 0, 0};
    bool bit_stat[16]  = {0};
    bool bit_dyn[16] = {0};

    // Load static lock bytes.
    memcpy(lockbytes_sta, data + 10, sizeof(lockbytes_sta));
    for (j = 0; j < 16; j++) {
        bit_stat[j] = lockbytes_sta[j / 8] & (1 << (7 - j % 8));
    }

    // Load dynamic lockbytes if available
    // TODO -- FIGURE OUT LOCK BYTES FOR TO EV1 and/or NTAG
    if (pages == 44) {

        memcpy(lockbytes_dyn, data + (40 * 4), sizeof(lockbytes_dyn));

        for (j = 0; j < 16; j++) {
            bit_dyn[j] = lockbytes_dyn[j / 8] & (1 << (7 - j % 8));
        }
        PrintAndLogEx(INFO, "Dynamic lock.... %s", sprint_hex(lockbytes_dyn, 3));
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    PrintAndLogEx(INFO, "block#   | data        |lck| ascii");
    PrintAndLogEx(INFO, "---------+-------------+---+------");

    bool in_repeated_block = false;

    for (uint16_t i = 0; i < pages; ++i) {
        if (i < 3) {
            PrintAndLogEx(INFO, "%3d/0x%02X | " _RED_("%s")"|   | %s",
                          i + startpage,
                          i + startpage,
                          sprint_hex(data + i * 4, 4),
                          sprint_ascii(data + i * 4, 4)
                         );
            continue;
        }
        switch (i) {
            case  3:
                lckbit = bit_stat[4];
                break;
            case  4:
                lckbit = bit_stat[3];
                break;
            case  5:
                lckbit = bit_stat[2];
                break;
            case  6:
                lckbit = bit_stat[1];
                break;
            case  7:
                lckbit = bit_stat[0];
                break;
            case  8:
                lckbit = bit_stat[15];
                break;
            case  9:
                lckbit = bit_stat[14];
                break;
            case 10:
                lckbit = bit_stat[13];
                break;
            case 11:
                lckbit = bit_stat[12];
                break;
            case 12:
                lckbit = bit_stat[11];
                break;
            case 13:
                lckbit = bit_stat[10];
                break;
            case 14:
                lckbit = bit_stat[9];
                break;
            case 15:
                lckbit = bit_stat[8];
                break;
            case 16:
            case 17:
            case 18:
            case 19:
                lckbit = bit_dyn[6];
                break;
            case 20:
            case 21:
            case 22:
            case 23:
                lckbit = bit_dyn[5];
                break;
            case 24:
            case 25:
            case 26:
            case 27:
                lckbit = bit_dyn[4];
                break;
            case 28:
            case 29:
            case 30:
            case 31:
                lckbit = bit_dyn[2];
                break;
            case 32:
            case 33:
            case 34:
            case 35:
                lckbit = bit_dyn[1];
                break;
            case 36:
            case 37:
            case 38:
            case 39:
                lckbit = bit_dyn[0];
                break;
            case 40:
                lckbit = bit_dyn[12];
                break;
            case 41:
                lckbit = bit_dyn[11];
                break;
            case 42:
                lckbit = bit_dyn[10];
                break; //auth0
            case 43:
                lckbit = bit_dyn[9];
                break;  //auth1
            default:
                break;
        }


        // suppress repeating blocks, truncate as such that the first and last block with the same data is shown
        // but the blocks in between are replaced with a single line of "......" if dense_output is enabled
        const uint8_t *blk = data + (i * MFU_BLOCK_SIZE);
        if (dense_output &&
                (i > 3) &&
                (i < pages) &&
                (in_repeated_block == false) &&
                (memcmp(blk, blk - MFU_BLOCK_SIZE, MFU_BLOCK_SIZE) == 0) &&
                (memcmp(blk, blk + MFU_BLOCK_SIZE, MFU_BLOCK_SIZE) == 0) &&
                (memcmp(blk, blk + (MFU_BLOCK_SIZE * 2), MFU_BLOCK_SIZE) == 0)
           ) {
            // we're in a user block that isn't the first user block nor last two user blocks,
            // and the current block data is the same as the previous and next two block
            in_repeated_block = true;
            PrintAndLogEx(INFO, "  ......");
        } else if (in_repeated_block &&
                   (memcmp(blk, blk + MFU_BLOCK_SIZE, MFU_BLOCK_SIZE) || i == pages)
                  ) {
            // in a repeating block, but the next block doesn't match anymore, or we're at the end block
            in_repeated_block = false;
        }


        if (in_repeated_block == false) {
            PrintAndLogEx(INFO, "%3d/0x%02X | %s| %s | %s"
                          , i + startpage
                          , i + startpage
                          , sprint_hex(data + i * 4, 4)
                          , (lckbit) ? _RED_("1") : "0"
                          , sprint_ascii(data + i * 4, 4)
                         );
        }
    }
    PrintAndLogEx(INFO, "---------------------------------");
}

//
//  Mifare Ultralight / Ultralight-C / Ultralight-EV1
//  Read and Dump Card Contents,  using auto detection of tag size.
static int CmdHF14AMfUDump(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu dump",
                  "Dump MIFARE Ultralight/NTAG tag to files (bin/json)\n"
                  "It autodetects card type."
                  "Supports:\n"
                  "Ultralight, Ultralight-C, Ultralight EV1\n"
                  "NTAG 203, NTAG 210, NTAG 212, NTAG 213, NTAG 215, NTAG 216\n",
                  "hf mfu dump -f myfile\n"
                  "hf mfu dump -k AABBCCDD      -> dump whole tag using pwd AABBCCDD\n"
                  "hf mfu dump -p 10            -> start at page 10 and dump rest of blocks\n"
                  "hf mfu dump -p 10 -q 2       -> start at page 10 and dump two blocks\n"
                  "hf mfu dump --key 00112233445566778899AABBCCDDEEFF"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "Specify a filename for dump file"),
        arg_str0("k", "key", "<hex>", "Key for authentication (UL-C 16 bytes, EV1/NTAG 4 bytes)"),
        arg_lit0("l", NULL, "Swap entered key's endianness"),
        arg_int0("p", "page", "<dec>", "Manually set start page number to start from"),
        arg_int0("q", "qty", "<dec>", "Manually set number of pages to dump"),
        arg_lit0(NULL, "ns", "no save to file"),
        arg_lit0("z", "dense", "dense dump output style"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    int ak_len = 0;
    uint8_t authenticationkey[16] = {0x00};
    uint8_t *authKeyPtr = authenticationkey;
    CLIGetHexWithReturn(ctx, 2, authenticationkey, &ak_len);
    bool swap_endian = arg_get_lit(ctx, 3);
    int start_page = arg_get_int_def(ctx, 4, 0);
    int pages = arg_get_int_def(ctx, 5, 16);
    bool nosave = arg_get_lit(ctx, 6);
    bool dense_output = (g_session.dense_output || arg_get_lit(ctx, 7));
    CLIParserFree(ctx);

    bool has_auth_key = false;
    bool has_pwd = false;
    if (ak_len == 16) {
        has_auth_key = true;
    } else if (ak_len == 4) {
        has_pwd = true;
    } else if (ak_len != 0) {
        PrintAndLogEx(WARNING, "ERROR: Key is incorrect length\n");
        return PM3_EINVARG;
    }

    bool manual_pages = false;
    if (start_page > 0) {
        manual_pages = true;
    }

    if (pages != 16) {
        manual_pages = true;
    }

    uint8_t card_mem_size = 0;

    // Swap endianness
    if (swap_endian) {
        if (has_auth_key) {
            authKeyPtr = SwapEndian64(authenticationkey, ak_len, 8);
        }

        if (has_pwd) {
            authKeyPtr = SwapEndian64(authenticationkey, ak_len, 4);
        }
    }

    uint64_t tagtype = GetHF14AMfU_Type();
    if (tagtype == MFU_TT_UL_ERROR) {
        return PM3_ESOFT;
    }

    //get number of pages to read
    if (manual_pages == false) {
        for (uint8_t idx = 1; idx < ARRAYLEN(UL_TYPES_ARRAY); idx++) {
            if ((tagtype & UL_TYPES_ARRAY[idx]) == UL_TYPES_ARRAY[idx]) {
                //add one as maxblks starts at 0
                card_mem_size = pages = UL_MEMORY_ARRAY[idx] + 1;
                break;
            }
        }
    }

    ul_print_type(tagtype, 0);
    PrintAndLogEx(SUCCESS, "Reading tag memory...");
    uint8_t keytype = 0;
    if (has_auth_key || has_pwd) {
        if ((tagtype & MFU_TT_UL_C) == MFU_TT_UL_C)
            keytype = 1; // UL_C auth
        else
            keytype = 2; // UL_EV1/NTAG auth
    }

    uint8_t dbg_curr = DBG_NONE;
    if (getDeviceDebugLevel(&dbg_curr) != PM3_SUCCESS) {
        return PM3_ESOFT;
    }

    if (setDeviceDebugLevel(DBG_NONE, false) != PM3_SUCCESS) {
        return PM3_ESOFT;
    }

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_MIFAREU_READCARD, start_page, pages, keytype, authKeyPtr, ak_len);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 2500) == false) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    if (resp.oldarg[0] != 1) {
        PrintAndLogEx(WARNING, "Failed dumping card");
        return PM3_ESOFT;
    }

    setDeviceDebugLevel(dbg_curr, false);

    // read all memory
    uint8_t data[1024] = {0x00};
    memset(data, 0x00, sizeof(data));

    uint32_t startindex = resp.oldarg[2];
    uint32_t buffer_size = resp.oldarg[1];
    if (buffer_size > sizeof(data)) {
        PrintAndLogEx(FAILED, "Data exceeded buffer size!");
        buffer_size = sizeof(data);
    }

    if (GetFromDevice(BIG_BUF, data, buffer_size, startindex, NULL, 0, NULL, 2500, false) == false) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    bool is_partial = (pages != buffer_size / MFU_BLOCK_SIZE);

    pages = buffer_size / MFU_BLOCK_SIZE;

    if (is_partial) {

        if ((tagtype & MFU_TT_UL_C) == MFU_TT_UL_C) {
            if (card_mem_size != (pages + 4)) {
                PrintAndLogEx(INFO, "Partial dump, got " _RED_("%d") " bytes - card mem size is %u bytes", pages * MFU_BLOCK_SIZE, card_mem_size * MFU_BLOCK_SIZE);
                PrintAndLogEx(HINT, "Try using a key");
            }
        } else {
            PrintAndLogEx(HINT, "Try using a pwd");
        }
    }

    iso14a_card_select_t card;
    mfu_dump_t dump_file_data;
    memset(&dump_file_data, 0, sizeof(dump_file_data));
    uint8_t get_version[] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t get_counter_tearing[][4] = {{0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}};
    uint8_t get_signature[32];
    memset(get_signature, 0, sizeof(get_signature));

    // not ul_c and not std ul then attempt to collect info like
    //  VERSION, SIGNATURE, COUNTERS, TEARING, PACK,
    if (!(tagtype & MFU_TT_UL_C || tagtype & MFU_TT_UL || tagtype & MFU_TT_MY_D_MOVE || tagtype & MFU_TT_MY_D_MOVE_LEAN)) {
        // attempt to read pack
        bool has_key = (has_auth_key || has_pwd);
        uint8_t get_pack[] = {0, 0};
        if (ul_auth_select(&card, tagtype, has_key, authKeyPtr, get_pack, sizeof(get_pack)) != PM3_SUCCESS) {
            //reset pack
            get_pack[0] = 0;
            get_pack[1] = 0;
        }
        DropField();

        // only add pack if not partial read,  and complete pages read.
        if (!is_partial && pages == card_mem_size) {

            // add pack to block read
            memcpy(data + (pages * 4) - 4, get_pack, sizeof(get_pack));
        }

        if (has_auth_key) {
            uint8_t dummy_pack[] = {0, 0};
            ul_auth_select(&card, tagtype, has_auth_key, authKeyPtr, dummy_pack, sizeof(dummy_pack));
        } else {
            ul_select(&card);
        }

        ulev1_getVersion(get_version, sizeof(get_version));

        // ULEV-1 has 3 counters
        uint8_t n = 0;

        // NTAG has 1 counter, at 0x02
        if ((tagtype & (MFU_TT_NTAG_213 | MFU_TT_NTAG_213_F | MFU_TT_NTAG_213_C | MFU_TT_NTAG_213_TT | MFU_TT_NTAG_215 | MFU_TT_NTAG_216))) {
            n = 2;
        }

        // NTAG can have nfc counter pwd protection enabled
        for (; n < 3; n++) {

            if (has_auth_key) {
                uint8_t dummy_pack[] = {0, 0};
                ul_auth_select(&card, tagtype, has_auth_key, authKeyPtr, dummy_pack, sizeof(dummy_pack));
            } else {
                ul_select(&card);
            }
            ulev1_readCounter(n, &get_counter_tearing[n][0], 3);

            if (has_auth_key) {
                uint8_t dummy_pack[] = {0, 0};
                ul_auth_select(&card, tagtype, has_auth_key, authKeyPtr, dummy_pack, sizeof(dummy_pack));
            } else {
                ul_select(&card);
            }
            ulev1_readTearing(n, &get_counter_tearing[n][3], 1);
        }

        DropField();

        if (has_auth_key) {
            uint8_t dummy_pack[] = {0, 0};
            ul_auth_select(&card, tagtype, has_auth_key, authKeyPtr, dummy_pack, sizeof(dummy_pack));
        } else {
            ul_select(&card);
        }

        ulev1_readSignature(get_signature, sizeof(get_signature));
        DropField();
    }


    // format and add keys to block dump output
    // only add keys if not partial read, and complete pages read

    // UL-C  add a working known key
    if (has_auth_key && (tagtype & MFU_TT_UL_C) == MFU_TT_UL_C) { // add 4 pages of key

        // if we didn't swapendian before - do it now for the sprint_hex call
        // NOTE: default entry is bigendian (unless swapped), sprint_hex outputs little endian
        //       need to swap to keep it the same
        if (swap_endian == false) {
            authKeyPtr = SwapEndian64(authenticationkey, ak_len, 8);
        } else {
            authKeyPtr = authenticationkey;
        }

        memcpy(data + pages * MFU_BLOCK_SIZE, authKeyPtr, ak_len);
        pages += ak_len / MFU_BLOCK_SIZE;

        // fix
        if (is_partial && pages == card_mem_size) {
            is_partial = false;
        }
    }

    if (!is_partial && pages == card_mem_size && has_pwd) {
        // if we didn't swapendian before - do it now for the sprint_hex call
        // NOTE: default entry is bigendian (unless swapped), sprint_hex outputs little endian
        //       need to swap to keep it the same
        if (swap_endian == false) {
            authKeyPtr = SwapEndian64(authenticationkey, ak_len, 4);
        } else {
            authKeyPtr = authenticationkey;
        }

        memcpy(data + (pages * MFU_BLOCK_SIZE) - 8, authenticationkey, ak_len);
    }

    //add *special* blocks to dump
    // pack and pwd saved into last pages of dump, if was not partial read
    dump_file_data.pages = pages - 1;
    memcpy(dump_file_data.version, get_version, sizeof(dump_file_data.version));
    memcpy(dump_file_data.signature, get_signature, sizeof(dump_file_data.signature));
    memcpy(dump_file_data.counter_tearing, get_counter_tearing, sizeof(dump_file_data.counter_tearing));
    memcpy(dump_file_data.data, data, pages * MFU_BLOCK_SIZE);

    mfu_print_dump(&dump_file_data, pages, start_page, dense_output);

    if (nosave) {
        PrintAndLogEx(INFO, "Called with no save option");
        PrintAndLogEx(NORMAL, "");
        return PM3_SUCCESS;
    }

    // user supplied filename?
    if (fnlen < 1) {
        PrintAndLogEx(INFO, "Using UID as filename");
        uint8_t uid[7] = {0};
        memcpy(uid, (uint8_t *)&dump_file_data.data, 3);
        memcpy(uid + 3, (uint8_t *)&dump_file_data.data + 4, 4);
        strcat(filename, "hf-mfu-");
        FillFileNameByUID(filename, uid, "-dump", sizeof(uid));
    }

    uint16_t datalen = MFU_DUMP_PREFIX_LENGTH + (pages * MFU_BLOCK_SIZE);
    pm3_save_dump(filename, (uint8_t *)&dump_file_data, datalen, jsfMfuMemory);

    if (is_partial) {
        PrintAndLogEx(WARNING, "Partial dump created. (%d of %d blocks)", pages, card_mem_size);
    }
    return PM3_SUCCESS;
}

static void wait4response(uint8_t b) {
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        uint8_t isOK  = resp.oldarg[0] & 0xff;
        if (isOK == 0) {
            PrintAndLogEx(WARNING, "failed to write block %d", b);
        }
    } else {
        PrintAndLogEx(WARNING, "command execution time out");
    }
}

//
//Configure tamper feature of NTAG 213TT
//
int CmdHF14MfUTamper(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu tamper",
                  "Set the configuration of the NTAG 213TT tamper feature\n"
                  "Supports:\n"
                  "NTAG 213TT\n",
                  "hf mfu tamper -e               -> enable tamper feature\n"
                  "hf mfu tamper -d               -> disable tamper feature\n"
                  "hf mfu tamper -m 0A0A0A0A      -> set the tamper message to 0A0A0A0A\n"
                  "hf mfu tamper --lockmessage    -> permanently lock the tamper message and mask it from memory\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("e", "enable", "Enable the tamper feature"),
        arg_lit0("d", "disable", "Disable the tamper feature"),
        arg_str0("m", "message", "<hex>", "Set the tamper message (4 bytes)"),
        arg_lit0(NULL, "lockmessage", "Permanently lock the tamper message and mask it from memory (does not lock tamper feature itself)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int tt_cfg_page = 41;
    int tt_msg_page = 45;
    int msg_len = 0;
    uint8_t msg_data[4] = {0x00};
    CLIGetHexWithReturn(ctx, 3, msg_data, &msg_len);
    bool use_msg = (msg_len > 0);

    if (use_msg && msg_len != 4) {
        PrintAndLogEx(WARNING, "The tamper message must be 4 hex bytes if provided");
        DropField();
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    bool lock_msg = arg_get_lit(ctx, 4);
    bool enable = arg_get_lit(ctx, 1);
    bool disable = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    uint64_t tagtype = GetHF14AMfU_Type();
    if (tagtype == MFU_TT_UL_ERROR) {
        PrintAndLogEx(WARNING, "Tag type not detected");
        DropField();
        return PM3_ESOFT;
    }
    if (tagtype != MFU_TT_NTAG_213_TT) {
        PrintAndLogEx(WARNING, "Tag type not NTAG 213TT");
        DropField();
        return PM3_ESOFT;
    }

    DropField();
    iso14a_card_select_t card;

    if (enable && disable) {
        PrintAndLogEx(WARNING, "You can only select one of the options enable/disable tamper feature");
        DropField();
        return PM3_ESOFT;
    }

    if (use_msg) {
        if (ul_select(&card) == false) {
            DropField();
            return MFU_TT_UL_ERROR;
        }
        PrintAndLogEx(INFO, "Trying to write tamper message");
        SendCommandMIX(CMD_HF_MIFAREU_WRITEBL, tt_msg_page, 0, 0, msg_data, 4);

        PacketResponseNG resp;

        if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
            uint8_t isOK  = resp.oldarg[0] & 0xff;
            if (!isOK)
                PrintAndLogEx(WARNING, "Failed to write tamper message");
            else
                PrintAndLogEx(SUCCESS, "Tamper message written successfully");
        } else {
            PrintAndLogEx(WARNING, "command execution time out");
        }
    }

    if (enable || disable || lock_msg) {

        if (ul_select(&card) == false) {
            PrintAndLogEx(ERR, "Unable to select tag");
            DropField();
            return MFU_TT_UL_ERROR;
        }

        uint8_t cfg_page[4] = {0x00};
        uint8_t cmd[] = {ISO14443A_CMD_READBLOCK, tt_cfg_page};
        int status = ul_send_cmd_raw(cmd, sizeof(cmd), cfg_page, 4);
        DropField();

        if (status <= 0) {
            PrintAndLogEx(WARNING, "Problem reading current config from tag");
            DropField();
            return PM3_ESOFT;
        }

        if (enable) {
            cfg_page[1] = cfg_page[1] | 0x02;
            PrintAndLogEx(INFO, "Enabling tamper feature");
        }
        if (disable) {
            cfg_page[1] = cfg_page[1] & 0xFD;
            PrintAndLogEx(INFO, "Disabling tamper feature");
        }
        if (lock_msg) {
            cfg_page[1] = cfg_page[1] | 0x04;
            PrintAndLogEx(INFO, "Locking tamper message");
        }

        SendCommandMIX(CMD_HF_MIFAREU_WRITEBL, tt_cfg_page, 0, 0, cfg_page, 4);
        PacketResponseNG resp;

        if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
            uint8_t isOK  = resp.oldarg[0] & 0xff;
            if (!isOK)
                PrintAndLogEx(WARNING, "Failed to write tamper configuration");
            else
                PrintAndLogEx(SUCCESS, "Tamper configuration written successfully");
        } else {
            PrintAndLogEx(WARNING, "command execution time out");
        }
    }

    DropField();
    return PM3_SUCCESS;
}

//
//  Restore dump file onto tag
//
static int CmdHF14AMfURestore(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu restore",
                  "Restore MIFARE Ultralight/NTAG dump file (bin/eml/json) to tag.\n",
                  "hf mfu restore -f myfile -s                 -> special write\n"
                  "hf mfu restore -f myfile -k AABBCCDD -s     -> special write, use key\n"
                  "hf mfu restore -f myfile -k AABBCCDD -ser   -> special write, use key, write dump pwd, ..."
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "Specify a filename for dump file"),
        arg_str0("k", "key", "<hex>", "key for authentication (UL-C 16 bytes, EV1/NTAG 4 bytes)"),
        arg_lit0("l", NULL, "swap entered key's endianness"),
        arg_lit0("s", NULL, "enable special write UID -MAGIC TAG ONLY-"),
        arg_lit0("e", NULL, "enable special write version/signature -MAGIC NTAG 21* ONLY-"),
        arg_lit0("r", NULL, "use password found in dumpfile to configure tag. Requires " _YELLOW_("'-e'") " parameter to work"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0("z", "dense", "dense dump output style"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    int ak_len = 0;
    uint8_t authkey[16] = {0x00};
    uint8_t *p_authkey = authkey;
    CLIGetHexWithReturn(ctx, 2, authkey, &ak_len);

    bool swap_endian = arg_get_lit(ctx, 3);
    bool write_special = arg_get_lit(ctx, 4);
    bool write_extra = arg_get_lit(ctx, 5);
    bool read_key = arg_get_lit(ctx, 6);
    bool verbose = arg_get_lit(ctx, 7);
    bool dense_output = (g_session.dense_output || arg_get_lit(ctx, 8));
    CLIParserFree(ctx);

    bool has_key = false;
    if (ak_len > 0) {
        if (ak_len != 4 && ak_len != 16) {
            PrintAndLogEx(ERR, "Wrong key length. expected 4 or 16, got %d", ak_len);
            return PM3_EINVARG;
        } else {
            has_key = true;
        }
    }

    if (fnlen == 0) {
        char *fptr = mfu_generate_filename("hf-mfu-", "-dump.bin");
        if (fptr != NULL) {
            strncpy(filename, fptr, sizeof(filename) - 1);
        } else {
            snprintf(filename, sizeof(filename), "dumpdata.bin");
        }
        free(fptr);
    }

    // read dump file
    uint8_t *dump = NULL;
    size_t bytes_read = 0;
    int res = pm3_load_dump(filename, (void **)&dump, &bytes_read, (MFU_MAX_BYTES + MFU_DUMP_PREFIX_LENGTH));
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (bytes_read < MFU_DUMP_PREFIX_LENGTH) {
        PrintAndLogEx(ERR, "Error, dump file is too small");
        free(dump);
        return PM3_ESOFT;
    }

    res = convert_mfu_dump_format(&dump, &bytes_read, verbose);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Failed convert on load to new Ultralight/NTAG format");
        free(dump);
        return res;
    }

    mfu_dump_t *mem = (mfu_dump_t *)dump;
    uint8_t pages = (bytes_read - MFU_DUMP_PREFIX_LENGTH) / MFU_BLOCK_SIZE;

    if (pages - 1 != mem->pages) {
        PrintAndLogEx(ERR, "Error, invalid dump, wrong page count");
        PrintAndLogEx(INFO, " %u  vs mempg %u", pages - 1,  mem->pages);
        free(dump);
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "Restoring " _YELLOW_("%s")" to card", filename);

    mfu_print_dump(mem, pages, 0, dense_output);

    // Swap endianness
    if (swap_endian && has_key) {
        if (ak_len == 16)
            p_authkey = SwapEndian64(authkey, ak_len, 8);
        else
            p_authkey = SwapEndian64(authkey, ak_len, 4);
    }

    uint8_t data[20] = {0};
    uint8_t keytype = 0;
    // set key - only once
    if (has_key) {
        keytype = (ak_len == 16) ? 1 : 2;
        memcpy(data + 4, p_authkey, ak_len);
    }

    // write version, signature, pack
    // only magic NTAG cards
    if (write_extra) {

#define MFU_NTAG_SPECIAL_PWD        0xF0
#define MFU_NTAG_SPECIAL_PACK       0xF1
#define MFU_NTAG_SPECIAL_VERSION    0xFA
#define MFU_NTAG_SPECIAL_SIGNATURE  0xF2
        // pwd
        if (has_key || read_key) {

            memcpy(data,  p_authkey, 4);
            if (read_key) {
                // try reading key from dump and use.
                memcpy(data, mem->data + (bytes_read - MFU_DUMP_PREFIX_LENGTH - 8), 4);
            }

            PrintAndLogEx(INFO, "special PWD     block written 0x%X - %s", MFU_NTAG_SPECIAL_PWD, sprint_hex(data, 4));
            clearCommandBuffer();
            SendCommandMIX(CMD_HF_MIFAREU_WRITEBL, MFU_NTAG_SPECIAL_PWD, keytype, 0, data, sizeof(data));

            wait4response(MFU_NTAG_SPECIAL_PWD);

            // copy the new key
            keytype = 2;
            memcpy(authkey, data, 4);
            memcpy(data + 4, authkey, 4);
        }

        // pack
        memcpy(data, mem->data + (bytes_read - MFU_DUMP_PREFIX_LENGTH - 4), 2);
        data[2] = 0;
        data[3] = 0;
        PrintAndLogEx(INFO, "special PACK    block written 0x%X - %s", MFU_NTAG_SPECIAL_PACK, sprint_hex(data, 4));
        clearCommandBuffer();
        SendCommandMIX(CMD_HF_MIFAREU_WRITEBL, MFU_NTAG_SPECIAL_PACK, keytype, 0, data, sizeof(data));
        wait4response(MFU_NTAG_SPECIAL_PACK);

        // Signature
        for (uint8_t s = MFU_NTAG_SPECIAL_SIGNATURE, i = 0; s < MFU_NTAG_SPECIAL_SIGNATURE + 8; s++, i += 4) {
            memcpy(data, mem->signature + i, 4);
            PrintAndLogEx(INFO, "special SIG     block written 0x%X - %s", s, sprint_hex(data, 4));
            clearCommandBuffer();
            SendCommandMIX(CMD_HF_MIFAREU_WRITEBL, s, keytype, 0, data, sizeof(data));
            wait4response(s);
        }

        // Version
        for (uint8_t s = MFU_NTAG_SPECIAL_VERSION, i = 0; s < MFU_NTAG_SPECIAL_VERSION + 2; s++, i += 4) {
            memcpy(data, mem->version + i, 4);
            PrintAndLogEx(INFO, "special VERSION block written 0x%X - %s", s, sprint_hex(data, 4));
            clearCommandBuffer();
            SendCommandMIX(CMD_HF_MIFAREU_WRITEBL, s, keytype, 0, data, sizeof(data));
            wait4response(s);
        }
    }

    PrintAndLogEx(INFO, "Restoring data blocks.");
    PrintAndLogEx(INFO, "." NOLF);
    // write all other data
    // Skip block 0,1,2,3 (only magic tags can write to them)
    // Skip last 5 blocks usually is configuration
    for (uint8_t b = 4; b < pages - 5; b++) {

        //Send write Block
        memcpy(data, mem->data + (b * 4), 4);
        clearCommandBuffer();
        SendCommandMIX(CMD_HF_MIFAREU_WRITEBL, b, keytype, 0, data, sizeof(data));
        wait4response(b);
        PrintAndLogEx(NORMAL, "." NOLF);
        fflush(stdout);
    }
    PrintAndLogEx(NORMAL, "");

    // write special data last
    if (write_special) {

        PrintAndLogEx(INFO, "Restoring configuration blocks");

        PrintAndLogEx(INFO, "Authentication with keytype[%x]  %s\n", (uint8_t)(keytype & 0xff), sprint_hex(p_authkey, 4));

#if defined ICOPYX
        // otp, uid, lock, dynlockbits, cfg0, cfg1, pwd, pack
        uint8_t blocks[] = {3, 0, 1, 2, pages - 5, pages - 4, pages - 3, pages - 2, pages - 1};
#else
        // otp, uid, lock, dynlockbits, cfg0, cfg1
        uint8_t blocks[] = {3, 0, 1, 2, pages - 5, pages - 4, pages - 3};
#endif
        for (uint8_t i = 0; i < ARRAYLEN(blocks); i++) {
            uint8_t b = blocks[i];
            memcpy(data, mem->data + (b * 4), 4);
            clearCommandBuffer();
            SendCommandMIX(CMD_HF_MIFAREU_WRITEBL, b, keytype, 0, data, sizeof(data));
            wait4response(b);
            PrintAndLogEx(INFO, "special block written " _YELLOW_("%u") " - %s", b, sprint_hex(data, 4));
        }
    }

    DropField();
    free(dump);
    PrintAndLogEx(HINT, "try `" _YELLOW_("hf mfu dump --ns") "` to verify");
    PrintAndLogEx(INFO, "Done!");
    return PM3_SUCCESS;
}
//
//  Load emulator with dump file
//
static int CmdHF14AMfUeLoad(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu eload",
                  "Load emulator memory with data from (bin/eml/json) dump file\n",
                  "hf mfu eload -f hf-mfu-04010203040506.bin\n"
                  "hf mfu eload -f hf-mfu-04010203040506.bin -q 57   -> load 57 blocks from myfile"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "Specify a filename for dump file"),
        arg_int0("q", "qty", "<dec>", "Number of blocks to load from eml file"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    CLIParserFree(ctx);

    size_t nc_len = strlen(Cmd) + 6;
    char *nc = calloc(nc_len, 1);
    if (nc == NULL) {
        return CmdHF14AMfELoad(Cmd);
    }

    snprintf(nc, nc_len, "%s --ul", Cmd);
    int res = CmdHF14AMfELoad(nc);
    free(nc);

    PrintAndLogEx(HINT, "Try " _YELLOW_("`hf mfu sim -t 7`") " to simulate an Amiibo.");
    PrintAndLogEx(INFO, "Done!");
    return res;
}

//
//  Simulate tag
//
static int CmdHF14AMfUSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu sim",
                  "Simulate MIFARE Ultralight family type based upon\n"
                  "ISO/IEC 14443 type A tag with 4,7 or 10 byte UID\n"
                  "from emulator memory.  See `hf mfu eload` first. \n"
                  "The UID from emulator memory will be used if not specified.\n"
                  "See `hf 14a sim -h` to see available types. You want 2 or 7 usually.",
                  "hf mfu sim -t 2 --uid 11223344556677        -> MIFARE Ultralight\n"
                  "hf mfu sim -t 7 --uid 11223344556677 -n 5   -> MFU EV1 / NTAG 215 Amiibo\n"
                  "hf mfu sim -t 7                             -> MFU EV1 / NTAG 215 Amiibo"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int1("t", "type", "<1..12> ", "Simulation type to use"),
        arg_str0("u", "uid", "<hex>", "<4|7|10> hex bytes UID"),
        arg_int0("n", "num", "<dec>", "Exit simulation after <numreads> blocks. 0 = infinite"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    CLIParserFree(ctx);
    return CmdHF14ASim(Cmd);
}

//-------------------------------------------------------------------------------
// Ultralight C Methods
//-------------------------------------------------------------------------------

// Ultralight C Authentication
//
static int CmdHF14AMfUCAuth(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu cauth",
                  "Tests 3DES password on Mifare Ultralight-C tag.\n"
                  "If password is not specified, a set of known defaults will be tested.",
                  "hf mfu cauth\n"
                  "hf mfu cauth --key 000102030405060708090a0b0c0d0e0f"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "key", "<hex>", "Authentication key (UL-C 16 hex bytes)"),
        arg_lit0("l", NULL, "Swap entered key's endianness"),
        arg_lit0("k", NULL, "Keep field on (only if a password is provided)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int ak_len = 0;
    uint8_t authenticationkey[16] = {0x00};
    uint8_t *authKeyPtr = authenticationkey;
    CLIGetHexWithReturn(ctx, 1, authenticationkey, &ak_len);
    bool swap_endian = arg_get_lit(ctx, 2);
    bool keep_field_on = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (ak_len != 16 && ak_len != 0) {
        PrintAndLogEx(WARNING, "ERROR: Key is incorrect length");
        return PM3_EINVARG;
    }

    // Swap endianness
    if (swap_endian && ak_len) {
        authKeyPtr = SwapEndian64(authenticationkey, 16, 8);
    }

    int isok;

    // If no hex key is specified, try default keys
    if (ak_len == 0) {
        isok = try_default_3des_keys(false, &authKeyPtr);
    } else {
        // try user-supplied
        isok = ulc_authentication(authKeyPtr, !keep_field_on);
    }

    if (isok == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Authentication 3DES key... " _GREEN_("%s") " ( " _GREEN_("ok")" )", sprint_hex_inrow(authKeyPtr, 16));
    } else {
        PrintAndLogEx(WARNING, "Authentication ( " _RED_("fail") " )");
    }
    return PM3_SUCCESS;
}

/**
A test function to validate that the polarssl-function works the same
was as the openssl-implementation.
Commented out, since it requires openssl

static int CmdTestDES(const char * cmd)
{
    uint8_t key[16] = {0x00};

    memcpy(key,key3_3des_data,16);
    DES_cblock RndA, RndB;

    PrintAndLogEx(NORMAL, "----------OpenSSL DES implementation----------");
    {
        uint8_t e_RndB[8] = {0x00};
        unsigned char RndARndB[16] = {0x00};

        DES_cblock iv = { 0 };
        DES_key_schedule ks1,ks2;
        DES_cblock key1,key2;

        memcpy(key,key3_3des_data,16);
        memcpy(key1,key,8);
        memcpy(key2,key+8,8);


        DES_set_key((DES_cblock *)key1,&ks1);
        DES_set_key((DES_cblock *)key2,&ks2);

        DES_random_key(&RndA);
        PrintAndLogEx(NORMAL, "     RndA:%s",sprint_hex(RndA, 8));
        PrintAndLogEx(NORMAL, "     e_RndB:%s",sprint_hex(e_RndB, 8));
        //void DES_ede2_cbc_encrypt(const unsigned char *input,
        //    unsigned char *output, long length, DES_key_schedule *ks1,
        //    DES_key_schedule *ks2, DES_cblock *ivec, int enc);
        DES_ede2_cbc_encrypt(e_RndB,RndB,sizeof(e_RndB),&ks1,&ks2,&iv,0);

        PrintAndLogEx(NORMAL, "     RndB:%s",sprint_hex(RndB, 8));
        rol(RndB,8);
        memcpy(RndARndB,RndA,8);
        memcpy(RndARndB+8,RndB,8);
        PrintAndLogEx(NORMAL, "     RA+B:%s",sprint_hex(RndARndB, 16));
        DES_ede2_cbc_encrypt(RndARndB,RndARndB,sizeof(RndARndB),&ks1,&ks2,&e_RndB,1);
        PrintAndLogEx(NORMAL, "enc(RA+B):%s",sprint_hex(RndARndB, 16));

    }
    PrintAndLogEx(NORMAL, "----------PolarSSL implementation----------");
    {
        uint8_t random_a[8]     = { 0 };
        uint8_t enc_random_a[8] = { 0 };
        uint8_t random_b[8]     = { 0 };
        uint8_t enc_random_b[8] = { 0 };
        uint8_t random_a_and_b[16] = { 0 };
        des3_context ctx        = { 0 };

        memcpy(random_a, RndA,8);

        uint8_t output[8]       = { 0 };
        uint8_t iv[8]           = { 0 };

        PrintAndLogEx(NORMAL, "     RndA  :%s",sprint_hex(random_a, 8));
        PrintAndLogEx(NORMAL, "     e_RndB:%s",sprint_hex(enc_random_b, 8));

        des3_set2key_dec(&ctx, key);

        des3_crypt_cbc(&ctx      // des3_context *ctx
            , DES_DECRYPT        // int mode
            , sizeof(random_b)   // size_t length
            , iv                 // unsigned char iv[8]
            , enc_random_b       // const unsigned char *input
            , random_b           // unsigned char *output
            );

        PrintAndLogEx(NORMAL, "     RndB:%s",sprint_hex(random_b, 8));

        rol(random_b,8);
        memcpy(random_a_and_b  ,random_a,8);
        memcpy(random_a_and_b+8,random_b,8);

        PrintAndLogEx(NORMAL, "     RA+B:%s",sprint_hex(random_a_and_b, 16));

        des3_set2key_enc(&ctx, key);

        des3_crypt_cbc(&ctx          // des3_context *ctx
            , DES_ENCRYPT            // int mode
            , sizeof(random_a_and_b)   // size_t length
            , enc_random_b           // unsigned char iv[8]
            , random_a_and_b         // const unsigned char *input
            , random_a_and_b         // unsigned char *output
            );

        PrintAndLogEx(NORMAL, "enc(RA+B):%s",sprint_hex(random_a_and_b, 16));
    }
    return 0;
}
**/

//
// Mifare Ultralight C - Set password
//
static int CmdHF14AMfUCSetPwd(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu setpwd",
                  "Set the 3DES key on MIFARE Ultralight-C tag. ",
                  "hf mfu setpwd --key 000102030405060708090a0b0c0d0e0f"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("k", "key", "<hex>", "New key (16 hex bytes)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int k_len = 0;
    uint8_t key[16] = {0x00};
    CLIGetHexWithReturn(ctx, 1, key, &k_len);
    CLIParserFree(ctx);

    if (k_len != 16) {
        PrintAndLogEx(WARNING, "Key must be 16 hex bytes");
        return PM3_EINVARG;
    }

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_MIFAREUC_SETPWD, 0, 0, 0, key, sizeof(key));

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        if ((resp.oldarg[0] & 0xff) == 1) {
            PrintAndLogEx(INFO, "Ultralight-C new key... " _GREEN_("%s"), sprint_hex_inrow(key, sizeof(key)));
        } else {
            PrintAndLogEx(WARNING, "Failed writing at block %u", (uint8_t)(resp.oldarg[1] & 0xFF));
            return PM3_ESOFT;
        }
    } else {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }
    return PM3_SUCCESS;
}

//
// Magic UL / UL-C tags  - Set UID
//
static int CmdHF14AMfUCSetUid(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu setuid",
                  "Set UID on MIFARE Ultralight tag.\n"
                  "This only works for `magic Ultralight` tags.",
                  "hf mfu setuid --uid 11223344556677"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("u", "uid", "<hex>", "New UID (7 hex bytes)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int u_len = 0;
    uint8_t uid[7] = {0x00};
    CLIGetHexWithReturn(ctx, 1, uid, &u_len);
    CLIParserFree(ctx);

    if (u_len != 7) {
        PrintAndLogEx(WARNING, "UID must be 7 hex bytes");
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "Please ignore possible transient BCC warnings");

    // read block2.
    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_MIFAREU_READBL, 2, 0, 0, NULL, 0);
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    // save old block2.
    uint8_t oldblock2[4] = {0x00};
    memcpy(resp.data.asBytes, oldblock2, 4);

    // Enforce bad BCC handling temporarily as BCC will be wrong between
    // block 1 write and block2 write
    hf14a_config config;
    SendCommandNG(CMD_HF_ISO14443A_GET_CONFIG, NULL, 0);
    if (!WaitForResponseTimeout(CMD_HF_ISO14443A_GET_CONFIG, &resp, 2000)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }
    memcpy(&config, resp.data.asBytes, sizeof(hf14a_config));
    int8_t oldconfig_bcc = config.forcebcc;
    if (oldconfig_bcc != 2) {
        config.forcebcc = 2;
        SendCommandNG(CMD_HF_ISO14443A_SET_CONFIG, (uint8_t *)&config, sizeof(hf14a_config));
    }

    // block 0.
    uint8_t data[4];
    data[0] = uid[0];
    data[1] = uid[1];
    data[2] = uid[2];
    data[3] =  0x88 ^ uid[0] ^ uid[1] ^ uid[2];
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_MIFAREU_WRITEBL, 0, 0, 0, data, sizeof(data));
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    // block 1.
    data[0] = uid[3];
    data[1] = uid[4];
    data[2] = uid[5];
    data[3] = uid[6];
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_MIFAREU_WRITEBL, 1, 0, 0, data, sizeof(data));
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    // block 2.
    data[0] = uid[3] ^ uid[4] ^ uid[5] ^ uid[6];
    data[1] = oldblock2[1];
    data[2] = oldblock2[2];
    data[3] = oldblock2[3];
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_MIFAREU_WRITEBL, 2, 0, 0, data, sizeof(data));
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    // restore BCC config
    if (oldconfig_bcc != 2) {
        config.forcebcc = oldconfig_bcc;
        SendCommandNG(CMD_HF_ISO14443A_SET_CONFIG, (uint8_t *)&config, sizeof(hf14a_config));
    }
    return PM3_SUCCESS;
}

static int CmdHF14AMfUKeyGen(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu keygen",
                  "Calculate MFC keys based ",
                  "hf mfu keygen -r\n"
                  "hf mfu keygen --uid 11223344556677"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("u", "uid", "<hex>", "<4|7> hex byte UID"),
        arg_lit0("r", NULL, "Read UID from tag"),
        arg_u64_0("b", "blk", "<dec>", "Block number"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int ulen = 0;
    uint8_t uid[7];
    CLIGetHexWithReturn(ctx, 1, uid, &ulen);
    bool read_tag = arg_get_lit(ctx, 2);
    uint8_t block = arg_get_u64_def(ctx, 3, 1) & 0xFF;
    CLIParserFree(ctx);

    if (read_tag) {
        // read uid from tag
        clearCommandBuffer();
        SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_NO_RATS, 0, 0, NULL, 0);
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_ACK, &resp, 2500) == false) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply.");
            return PM3_ETIMEOUT;
        }

        iso14a_card_select_t card;
        memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

        uint64_t select_status = resp.oldarg[0];
        // 0: couldn't read,
        // 1: OK, with ATS
        // 2: OK, no ATS
        // 3: proprietary Anticollision

        if (select_status == 0) {
            PrintAndLogEx(WARNING, "iso14443a card select failed");
            return PM3_ESOFT;
        }

        if (card.uidlen != 4 && card.uidlen != 7) {
            PrintAndLogEx(WARNING, "Wrong sized UID, expected 4|7 bytes got %d", card.uidlen);
            return PM3_ESOFT;
        }
        ulen = card.uidlen;
        memcpy(uid, card.uid, card.uidlen);
    } else {
        if (ulen != 4 && ulen != 7) {
            PrintAndLogEx(ERR, "Must supply 4 or 7 hex byte uid");
            return PM3_EINVARG;
        }
    }

    uint8_t iv[8] = { 0x00 };

    uint8_t mifarekeyA[] = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5 };
    uint8_t mifarekeyB[] = { 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5 };
    uint8_t dkeyA[8] = { 0x00 };
    uint8_t dkeyB[8] = { 0x00 };

    uint8_t masterkey[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    uint8_t mix[8] = { 0x00 };
    uint8_t divkey[8] = { 0x00 };

    memcpy(mix, mifarekeyA, 4);

    mix[4] = mifarekeyA[4] ^ uid[0];
    mix[5] = mifarekeyA[5] ^ uid[1];
    mix[6] = block ^ uid[2];
    mix[7] = uid[3];

    mbedtls_des3_context ctx_des3;
    mbedtls_des3_set2key_enc(&ctx_des3, masterkey);

    mbedtls_des3_crypt_cbc(&ctx_des3  // des3_context
                           , MBEDTLS_DES_ENCRYPT    // int mode
                           , sizeof(mix)    // length
                           , iv             // iv[8]
                           , mix            // input
                           , divkey         // output
                          );

    PrintAndLogEx(SUCCESS, "-- 3DES version");
    PrintAndLogEx(SUCCESS, "Masterkey......... %s", sprint_hex(masterkey, sizeof(masterkey)));
    PrintAndLogEx(SUCCESS, "UID............... %s", sprint_hex(uid, ulen));
    PrintAndLogEx(SUCCESS, "block............. %0d", block);
    PrintAndLogEx(SUCCESS, "Mifare key........ %s", sprint_hex(mifarekeyA, sizeof(mifarekeyA)));
    PrintAndLogEx(SUCCESS, "Message........... %s", sprint_hex(mix, sizeof(mix)));
    PrintAndLogEx(SUCCESS, "Diversified key... %s", sprint_hex(divkey + 1, 6));

    for (int i = 0; i < ARRAYLEN(mifarekeyA); ++i) {
        dkeyA[i]  = (mifarekeyA[i] << 1) & 0xff;
        dkeyA[6] |= ((mifarekeyA[i] >> 7) & 1) << (i + 1);
    }

    for (int i = 0; i < ARRAYLEN(mifarekeyB); ++i) {
        dkeyB[1]  |= ((mifarekeyB[i] >> 7) & 1) << (i + 1);
        dkeyB[2 + i] = (mifarekeyB[i] << 1) & 0xff;
    }

    uint8_t zeros[8] = {0x00};
    uint8_t newpwd[8] = {0x00};
    uint8_t dmkey[24] = {0x00};
    memcpy(dmkey, dkeyA, 8);
    memcpy(dmkey + 8, dkeyB, 8);
    memcpy(dmkey + 16, dkeyA, 8);
    memset(iv, 0x00, 8);

    mbedtls_des3_set3key_enc(&ctx_des3, dmkey);

    mbedtls_des3_crypt_cbc(&ctx_des3  // des3_context
                           , MBEDTLS_DES_ENCRYPT    // int mode
                           , sizeof(newpwd) // length
                           , iv             // iv[8]
                           , zeros         // input
                           , newpwd         // output
                          );

    PrintAndLogEx(SUCCESS, "\n-- DES version");
    PrintAndLogEx(SUCCESS, "MIFARE dkeyA...... %s", sprint_hex(dkeyA, sizeof(dkeyA)));
    PrintAndLogEx(SUCCESS, "MIFARE dkeyB...... %s", sprint_hex(dkeyB, sizeof(dkeyB)));
    PrintAndLogEx(SUCCESS, "MIFARE ABA........ %s", sprint_hex(dmkey, sizeof(dmkey)));
    PrintAndLogEx(SUCCESS, "MIFARE PWD........ %s", sprint_hex(newpwd, sizeof(newpwd)));

    mbedtls_des3_free(&ctx_des3);

    mbedtls_aes_context ctx_aes;
    uint8_t aes_iv[16] = { 0x00 };
    uint8_t aes_masterkey[] = { 0x00, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
    uint8_t aes_input[16] = {0x01, 0x04, 0x2A, 0x2E, 0x19, 0x70, 0x1C, 0x80, 0x01, 0x04, 0x2A, 0x2E, 0x19, 0x70, 0x1C, 0x80};
    uint8_t aes_output[16] = {0x00};
    mbedtls_aes_setkey_enc(&ctx_aes, aes_masterkey, 128);
    mbedtls_aes_crypt_cbc(&ctx_aes, MBEDTLS_AES_ENCRYPT, 16, aes_iv, aes_input, aes_output);
    mbedtls_aes_free(&ctx_aes);

    PrintAndLogEx(SUCCESS, "\n-- AES version");
    PrintAndLogEx(SUCCESS, "MIFARE AES mk..... %s", sprint_hex(aes_masterkey, sizeof(aes_masterkey)));
    PrintAndLogEx(SUCCESS, "MIFARE Div........ %s", sprint_hex(aes_output, sizeof(aes_output)));

    // next. from the diversify_key method.
    return PM3_SUCCESS;
}

static int CmdHF14AMfUPwdGen(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu pwdgen",
                  "Generate different passwords from known pwdgen algos",
                  "hf mfu pwdgen -r\n"
                  "hf mfu pwdgen --uid 11223344556677\n"
                  "hf mfu pwdgen --test"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("u", "uid", "<hex>", "UID (7 hex bytes)"),
        arg_lit0("r", NULL, "Read UID from tag"),
        arg_lit0(NULL, "test", "self test"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int u_len = 0;
    uint8_t uid[7] = {0x00};
    CLIGetHexWithReturn(ctx, 1, uid, &u_len);
    bool use_tag = arg_get_lit(ctx, 2);
    bool selftest = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (selftest) {
        return generator_selftest();
    }

    uint8_t philips_mfg[10] = {0};

    if (use_tag) {
        // read uid from tag
        int res = ul_read_uid(uid);
        if (res == PM3_ELENGTH) {
            // got 4 byte UID, lets adapt to 7 bytes :)
            memset(uid + 4, 0x00, 3);
            u_len = 7;
        } else {

            if (res != PM3_SUCCESS) {
                return res;
            }

            iso14a_card_select_t card;
            if (ul_select(&card)) {
                // Philips toothbrush needs page 0x21-0x23
                uint8_t data[16] = {0x00};
                int status = ul_read(0x21, data, sizeof(data));
                if (status <= 0) {
                    PrintAndLogEx(DEBUG, "Error: tag didn't answer to READ");
                } else if (status == 16) {
                    memcpy(philips_mfg, data + 2, sizeof(philips_mfg));
                }
                DropField();
            }
        }
    } else {
        if (u_len != 7 && u_len != 4) {
            PrintAndLogEx(WARNING, "Key must be 7 hex bytes");
            return PM3_EINVARG;
        } else if (u_len == 4) {
            // adapt to 7 bytes :)
            memset(uid + 4, 0x00, 3);
            u_len = 7;
        }
    }

    PrintAndLogEx(INFO, "-----------------------------------");
    PrintAndLogEx(INFO, " UID 4b... " _YELLOW_("%s"), sprint_hex(uid, 4));
    PrintAndLogEx(INFO, " UID 7b... " _YELLOW_("%s"), sprint_hex(uid, 7));
    PrintAndLogEx(INFO, "-----------------------------------");
    PrintAndLogEx(INFO, " algo               pwd       pack");
    PrintAndLogEx(INFO, "-----------------------------+-----");
    PrintAndLogEx(INFO, " Transport EV1..... %08X | %04X", ul_ev1_pwdgenA(uid), ul_ev1_packgenA(uid));
    PrintAndLogEx(INFO, " Amiibo............ %08X | %04X", ul_ev1_pwdgenB(uid), ul_ev1_packgenB(uid));
    PrintAndLogEx(INFO, " Lego Dimension.... %08X | %04X", ul_ev1_pwdgenC(uid), ul_ev1_packgenC(uid));
    PrintAndLogEx(INFO, " XYZ 3D printer.... %08X | %04X", ul_ev1_pwdgenD(uid), ul_ev1_packgenD(uid));
    PrintAndLogEx(INFO, " Xiaomi purifier... %08X | %04X", ul_ev1_pwdgenE(uid), ul_ev1_packgenE(uid));
    PrintAndLogEx(INFO, " NTAG tools........ %08X | %04X", ul_ev1_pwdgenF(uid), ul_ev1_packgen_def(uid));
    if (philips_mfg[0] != 0) {
        PrintAndLogEx(INFO, " Philips Toothbrush | %08X | %04X", ul_ev1_pwdgenG(uid, philips_mfg), ul_ev1_packgenG(uid, philips_mfg));
    }
    PrintAndLogEx(INFO, "-----------------------------+-----");
    PrintAndLogEx(INFO, _CYAN_("Vingcard"));
    uint64_t key = 0;
    mfc_algo_saflok_one(uid, 0, 0, &key);
    PrintAndLogEx(INFO, " Saflok algo        | %012" PRIX64, key);
    PrintAndLogEx(INFO, " SALTO algo");
    PrintAndLogEx(INFO, " Dorma Kaba algo");
    PrintAndLogEx(INFO, " STiD algo");
    PrintAndLogEx(INFO, "-------------------------------------");
    return PM3_SUCCESS;
}

//
// MFU TearOff against OTP
// Moebius et al
//
static int CmdHF14AMfuOtpTearoff(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu otptear",
                  "Tear-off test against OTP block",
                  "hf mfu otptear -b 3\n"
                  "hf mfu otptear -b 3 -i 100 -s 1000\n"
                  "hf mfu otptear -b 3 -i 1 -e 200\n"
                  "hf mfu otptear -b 3 -i 100 -s 200 -e 2500 -d FFFFFFFF -t EEEEEEEE\n"
                  "hf mfu otptear -b 3 -i 100 -s 200 -e 2500 -d FFFFFFFF -t EEEEEEEE -m 00000000    -> quit when OTP is reset"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("b", "blk", "<dec>", "target block (def 8)"),
        arg_u64_0("i", "inc", "<dec>", "increase time steps (def 500 us)"),
        arg_u64_0("e", "end", "<dec>", "end time (def 3000 us)"),
        arg_u64_0("s", "start", "<dec>", "start time (def 0 us)"),
        arg_str0("d", "data", "<hex>", "initialise data before run (4 bytes)"),
        arg_str0("t", "test", "<hex>", "test write data (4 bytes, 00000000 by default)"),
        arg_str0("m", "match", "<hex>", "exit criteria, if block matches this value (4 bytes)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t blockno = arg_get_u32_def(ctx, 1, 8);
    uint32_t steps = arg_get_u32_def(ctx, 2, 500);
    uint32_t end = arg_get_u32_def(ctx, 3, 3000);
    uint32_t start = arg_get_u32_def(ctx, 4, 0);

    int d_len = 0;
    uint8_t data[4] = {0x00};
    CLIGetHexWithReturn(ctx, 5, data, &d_len);
    bool use_data = (d_len > 0);

    int t_len = 0;
    uint8_t test[4] = {0x00};
    CLIGetHexWithReturn(ctx, 6, test, &t_len);

    int m_len = 0;
    uint8_t match[4] = {0x00};
    CLIGetHexWithReturn(ctx, 7, match, &m_len);
    bool use_match = (m_len > 0);
    CLIParserFree(ctx);

    if (blockno < 2) {
        PrintAndLogEx(WARNING, "Block number must be larger than 2.");
        return PM3_EINVARG;
    }
    if (end < steps) {
        PrintAndLogEx(WARNING, "end time smaller than increase value");
        return PM3_EINVARG;
    }
    if (end > 43000) {
        PrintAndLogEx(WARNING, "end time - out of 1 .. 43000 range");
        return PM3_EINVARG;
    }
    if (start > (end - steps)) {
        PrintAndLogEx(WARNING, "Start time larger than (end time + steps)");
        return PM3_EINVARG;
    }

    if (d_len && d_len != 4) {
        PrintAndLogEx(WARNING, "data must be 4 hex bytes");
        return PM3_EINVARG;
    }

    if (t_len && t_len != 4) {
        PrintAndLogEx(WARNING, "test data must be 4 hex bytes");
        return PM3_EINVARG;
    }

    if (m_len && m_len != 4) {
        PrintAndLogEx(WARNING, "match data must be 4 hex bytes");
        return PM3_EINVARG;
    }

    uint8_t teardata[4] = {0x00};
    memcpy(teardata, test, sizeof(test));

    PrintAndLogEx(INFO, "----------------- " _CYAN_("MFU Tear off") " ---------------------");
    PrintAndLogEx(INFO, "Starting Tear-off test");
    PrintAndLogEx(INFO, "Target block no: %u", blockno);
    if (use_data) {
        PrintAndLogEx(INFO, "Target initial block data : %s", sprint_hex_inrow(data, 4));
    }
    PrintAndLogEx(INFO, "Target write block data  : %s", sprint_hex_inrow(teardata, 4));
    if (use_match) {
        PrintAndLogEx(INFO, "Target match block data  : %s", sprint_hex_inrow(match, 4));
    }
    PrintAndLogEx(INFO, "----------------------------------------------------");
    uint8_t isOK;
    bool lock_on = false;
    uint8_t pre[4] = {0};
    uint8_t post[4] = {0};
    uint32_t current = start;
    int phase_begin_clear = -1;
    int phase_end_clear = -1;
    int phase_begin_newwr = -1;
    int phase_end_newwr = -1;
    bool skip_phase1 = false;
    uint8_t retries = 0;
    uint8_t error_retries = 0;

    while ((current <= (end - steps)) && (error_retries < 10)) {

        if (kbd_enter_pressed()) {
            PrintAndLogEx(WARNING, "\naborted via keyboard!\n");
            break;
        }

        PrintAndLogEx(INFO, "Using tear-off delay " _GREEN_("%" PRIu32) " us", current);

        clearCommandBuffer();
        PacketResponseNG resp;

        if (use_data) {
            SendCommandMIX(CMD_HF_MIFAREU_WRITEBL, blockno, 0, 0, data, d_len);
            bool got_written = false;
            if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
                isOK  = resp.oldarg[0] & 0xff;
                if (isOK) {
                    got_written = true;
                }
            }
            if (! got_written) {
                PrintAndLogEx(FAILED, "Failed to write block BEFORE");
                error_retries++;
                continue; // try again
            }
        }

        SendCommandMIX(CMD_HF_MIFAREU_READBL, blockno, 0, 0, NULL, 0);

        bool got_pre = false;
        if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
            isOK = resp.oldarg[0] & 0xFF;
            if (isOK) {
                memcpy(pre, resp.data.asBytes, sizeof(pre));
                got_pre = true;
            }
        }
        if (! got_pre) {
            PrintAndLogEx(FAILED, "Failed to read block BEFORE");
            error_retries++;
            continue; // try again
        }
        clearCommandBuffer();
        SendCommandMIX(CMD_HF_MFU_OTP_TEAROFF, blockno, current, 0, teardata, sizeof(teardata));

        // we be getting ACK that we are silently ignoring here..

        if (!WaitForResponseTimeout(CMD_HF_MFU_OTP_TEAROFF, &resp, 2000)) {
            PrintAndLogEx(WARNING, "Failed");
            return PM3_ESOFT;
        }

        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "Tear off reporting failure to select tag");
            error_retries++;
            continue;
        }

        bool got_post = false;
        clearCommandBuffer();
        SendCommandMIX(CMD_HF_MIFAREU_READBL, blockno, 0, 0, NULL, 0);
        if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
            isOK = resp.oldarg[0] & 0xFF;
            if (isOK) {
                memcpy(post, resp.data.asBytes, sizeof(post));
                got_post = true;
            }
        }
        if (! got_post) {
            PrintAndLogEx(FAILED, "Failed to read block BEFORE");
            error_retries++;
            continue; // try again
        }
        error_retries = 0;
        char prestr[20] = {0};
        snprintf(prestr, sizeof(prestr), "%s", sprint_hex_inrow(pre, sizeof(pre)));
        char poststr[20] = {0};
        snprintf(poststr, sizeof(poststr), "%s", sprint_hex_inrow(post, sizeof(post)));

        if (memcmp(pre, post, sizeof(pre)) == 0) {

            PrintAndLogEx(INFO, "Current :           %02d (0x%02X) %s"
                          , blockno
                          , blockno
                          , poststr
                         );
        } else {
            PrintAndLogEx(INFO, _CYAN_("Tear off occurred") " : %02d (0x%02X) %s => " _RED_("%s")
                          , blockno
                          , blockno
                          , prestr
                          , poststr
                         );

            lock_on = true;

            uint32_t post32 = bytes_to_num(post, 4);
            uint32_t pre32 = bytes_to_num(pre, 4);

            if ((phase_begin_clear == -1) && (bitcount32(pre32) > bitcount32(post32)))
                phase_begin_clear = current;

            if ((phase_begin_clear > -1) && (phase_end_clear == -1) && (bitcount32(post32) == 0))
                phase_end_clear = current;

            if ((current == start) && (phase_end_clear > -1))
                skip_phase1 = true;
            // new write phase must be atleast 100us later..
            if (((bitcount32(pre32) == 0) || (phase_end_clear > -1)) && (phase_begin_newwr == -1) && (bitcount32(post32) != 0) && (skip_phase1 || (current > (phase_end_clear + 100))))
                phase_begin_newwr = current;

            if ((phase_begin_newwr > -1) && (phase_end_newwr == -1) && (memcmp(post, teardata, sizeof(teardata)) == 0))
                phase_end_newwr = current;
        }

        if (use_match && memcmp(post, match, sizeof(post)) == 0) {
            PrintAndLogEx(SUCCESS, "Block matches stop condition!\n");
            break;
        }

        /*  TEMPORALLY DISABLED
                uint8_t d0, d1, d2, d3;
                d0 = *resp.data.asBytes;
                d1 = *(resp.data.asBytes + 1);
                d2 = *(resp.data.asBytes + 2);
                d3 = *(resp.data.asBytes + 3);
                if ((d0 != 0xFF) || (d1 != 0xFF) || (d2 != 0xFF) || (d3 = ! 0xFF)) {
                    PrintAndLogEx(NORMAL, "---------------------------------");
                    PrintAndLogEx(NORMAL, "        EFFECT AT: %d us", actualTime);
                    PrintAndLogEx(NORMAL, "---------------------------------\n");
                }
        */
        if (start != end) {
            current += steps;
        } else {
            if (lock_on == false) {
                if (++retries == 20) {
                    current++;
                    end++;
                    start++;
                    retries = 0;
                    PrintAndLogEx(INFO, _CYAN_("Retried %u times, increased delay with 1us"), retries);
                }
            }
        }
    }

    PrintAndLogEx(INFO, "----------------------------------------------------");
    if ((phase_begin_clear > - 1) && (phase_begin_clear != start)) {
        PrintAndLogEx(INFO, "Erase phase start boundary around " _YELLOW_("%5d") " us", phase_begin_clear);
    }
    if ((phase_end_clear > - 1) && (phase_end_clear != start)) {
        PrintAndLogEx(INFO, "Erase phase end boundary around   " _YELLOW_("%5d") " us", phase_end_clear);
    }
    if (phase_begin_newwr > - 1) {
        PrintAndLogEx(INFO, "Write phase start boundary around " _YELLOW_("%5d") " us", phase_begin_newwr);
    }
    if (phase_end_newwr > - 1) {
        PrintAndLogEx(INFO, "Write phase end boundary around   " _YELLOW_("%5d") " us", phase_end_newwr);
    }
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

/*
static int counter_reset_tear(iso14a_card_select_t *card, uint8_t cnt_no) {

    PrintAndLogEx(INFO, "Reset tear check");

    uint8_t cw[6] = { MIFARE_ULEV1_INCR_CNT, cnt_no, 0x00, 0x00, 0x00, 0x00};
    uint8_t ct[1] = {0};
    uint8_t resp[10] = {0};

    if (ul_select(card) == false) {
        PrintAndLogEx(FAILED, "failed to select card, exiting...");
        return PM3_ESOFT;
    }
    if (ul_send_cmd_raw(cw, sizeof(cw), resp, sizeof(resp)) < 0) {
        PrintAndLogEx(FAILED, "failed to write all ZEROS");
        return PM3_ESOFT;
    }
    if (ulev1_readTearing(cnt_no, ct, sizeof(ct)) < 0) {
        PrintAndLogEx(FAILED, "AFTER, failed to read ANTITEAR,  exiting...");
        return PM3_ESOFT;
    }
    DropField();

    if (ct[0] != 0xBD) {
        PrintAndLogEx(INFO, "Resetting seem to have failed, WHY!?");
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}
*/

/*
static int CmdHF14AMfuEv1CounterTearoff(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu countertear",
                  "Tear-off test against a Ev1 counter",
                  "hf mfu countertear\n"
                  "hf mfu countertear -s 200 -l 2500      -> target counter 0, start delay 200\n"
                  "hf mfu countertear -i 2 -s 200 -l 400  -> target counter 0, start delay 200\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("c", "cnt", "<0,1,2>", "Target this EV1 counter (0,1,2)"),
        arg_int0("i", "inc", "<dec>", "time interval to increase in each iteration - default 10 us"),
        arg_int0("l", "limit", "<dec>", "test upper limit time - default 3000 us"),
        arg_int0("s", "start", "<dec>", "test start time - default 0 us"),
        arg_int0(NULL, "fix", "<dec>", "test fixed loop delay"),
        arg_str0("x", "hex",  NULL, "3 byte hex to increase counter with"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int interval = 0;
    int time_limit, start_time = 0;
    int counter = arg_get_int_def(ctx, 1, 0);
    int fixed = arg_get_int_def(ctx, 5, -1);

    if ( fixed == -1 ) {
        interval = arg_get_int_def(ctx, 2, 10);
        time_limit = arg_get_int_def(ctx, 3, 3000);
        start_time = arg_get_int_def(ctx, 4, 0);
    } else {
        start_time = fixed;
        interval = 0;
        time_limit = fixed;
    }

    uint8_t newvalue[5] = {0};
    int newvaluelen = 0;
    CLIGetHexWithReturn(ctx, 6, newvalue, &newvaluelen);
    CLIParserFree(ctx);

    // Validations
    if (start_time > (time_limit - interval)) {
        PrintAndLogEx(WARNING, "Wrong start time number");
        return PM3_EINVARG;
    }
    if (time_limit < interval) {
        PrintAndLogEx(WARNING, "Wrong time limit number");
        return PM3_EINVARG;
    }
    if (time_limit > 43000) {
        PrintAndLogEx(WARNING, "You can't set delay out of 1..43000 range!");
        return PM3_EINVARG;
    }
    uint8_t cnt_no = 0;
    if (counter < 0 || counter > 2) {
        PrintAndLogEx(WARNING, "Counter must 0, 1 or 2");
        return PM3_EINVARG;
    }

    cnt_no = (uint8_t)counter;

    iso14a_card_select_t card;

    // reset counter tear
    counter_reset_tear(&card, cnt_no);

    if (ul_select(&card) == false) {
        PrintAndLogEx(INFO, "failed to select card,  exiting...");
        return PM3_ESOFT;
    }

    uint8_t initial_cnt[3] = {0, 0, 0};
    int len = ulev1_readCounter(cnt_no, initial_cnt, sizeof(initial_cnt));
    if ( len != sizeof(initial_cnt) ) {
        PrintAndLogEx(WARNING, "failed to read counter");
        return PM3_ESOFT;
    }

    uint8_t initial_tear[1] = {0};
    len = ulev1_readTearing(cnt_no, initial_tear, sizeof(initial_tear));
    DropField();
    if ( len != sizeof(initial_tear) ) {
        PrintAndLogEx(WARNING, "failed to read ANTITEAR,  exiting...  %d", len);
        return PM3_ESOFT;
    }

    uint32_t wr_value = ( newvalue[0] | newvalue[1] << 8 | newvalue[2] << 16 );
    uint32_t initial_value = ( initial_cnt[0] | initial_cnt[1] << 8 | initial_cnt[2] << 16 );;

    PrintAndLogEx(INFO, "----------------- " _CYAN_("MFU Ev1 Counter Tear off") " ---------------------");
    PrintAndLogEx(INFO, "Target counter no     [ " _GREEN_("%u") " ]", counter);
    PrintAndLogEx(INFO, "       counter value  [ " _GREEN_("%s") " ]", sprint_hex_inrow(initial_cnt, sizeof(initial_cnt)));
    PrintAndLogEx(INFO, "     anti-tear value  [ " _GREEN_("%02X") " ]", initial_tear[0]);
    PrintAndLogEx(INFO, "       increase value [ " _GREEN_("%s") " ]", sprint_hex_inrow(newvalue, newvaluelen));
    PrintAndLogEx(INFO, "----------------------------------------------------");

    uint8_t pre_tear = 0, post_tear = 0;
    uint8_t pre[3] = {0};
    uint8_t post[3] = {0};
    uint32_t actual_time = start_time;
    uint32_t a = 0, b = 0;
    uint32_t loop = 0;

    uint16_t late = 0;

    while (actual_time <= (time_limit - interval)) {

        DropField();

        loop++;

        if (kbd_enter_pressed()) {
            PrintAndLogEx(INFO, "\naborted via keyboard!\n");
            break;
        }

        PrintAndLogEx(INPLACE, "Using tear-off delay " _GREEN_("%" PRIu32) " µs  (attempt %u)", actual_time, loop);

        if (ul_select(&card) == false) {
            PrintAndLogEx(FAILED, "BEFORE, failed to select card,  looping...");
            continue;
        }

        uint8_t cntresp[3] = {0, 0, 0};
        int rlen = ulev1_readCounter(cnt_no, cntresp, sizeof(cntresp));
        if ( rlen == sizeof(cntresp) ) {
            memcpy(pre, cntresp, sizeof(pre));
        } else {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(FAILED, "BEFORE, failed to read COUNTER,  exiting...");
            break;
        }

        uint8_t tear[1] = {0};
        int tlen = ulev1_readTearing(cnt_no, tear, sizeof(tear));
        if ( tlen == sizeof(tear) ) {
            pre_tear = tear[0];
        } else {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(FAILED, "BEFORE, failed to read ANTITEAR,  exiting...  %d", tlen);
            break;
        }

        DropField();

        struct p {
            uint8_t counter;
            uint32_t tearoff_time;
            uint8_t value[3];
        } PACKED payload;
        payload.counter = cnt_no;
        payload.tearoff_time = actual_time;
        memcpy(payload.value, newvalue, sizeof(payload.value));

        clearCommandBuffer();
        PacketResponseNG resp;
        SendCommandNG(CMD_HF_MFU_COUNTER_TEAROFF, (uint8_t*)&payload, sizeof(payload));
        if (!WaitForResponseTimeout(CMD_HF_MFU_COUNTER_TEAROFF, &resp, 2000)) {
            PrintAndLogEx(WARNING, "\ntear off command failed");
            continue;
        }

        if (ul_select(&card) == false) {
            PrintAndLogEx(FAILED, "AFTER, failed to select card,  exiting...");
            break;
        }

        rlen = ulev1_readCounter(cnt_no, cntresp, sizeof(cntresp));
        if ( rlen == sizeof(cntresp) ) {
            memcpy(post, cntresp, sizeof(post));
        } else {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(FAILED, "AFTER, failed to read COUNTER,  exiting...");
            break;
        }

        tear[0] = 0;
        tlen = ulev1_readTearing(cnt_no, tear, sizeof(tear));
        if ( tlen == sizeof(tear) ) {
            post_tear = tear[0];
        } else {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(FAILED, "AFTER, failed to read ANTITEAR,  exiting...");
            break;
        }

        DropField();

        char prestr[20] = {0};
        snprintf(prestr, sizeof(prestr), "%s", sprint_hex_inrow(pre, sizeof(pre)));
        char poststr[20] = {0};
        snprintf(poststr, sizeof(poststr), "%s", sprint_hex_inrow(post, sizeof(post)));

        bool post_tear_check = (post_tear == 0xBD);
        a = (pre[0] | pre[1] << 8 | pre[2]  << 16);
        b = (post[0] | post[1] << 8 | post[2]  << 16);

        // A != B
        if (memcmp(pre, post, sizeof(pre)) != 0) {


            PrintAndLogEx(NORMAL, "");

            if (initial_value != a ) {

                if ( initial_value != b )
                    PrintAndLogEx(INFO, "pre %08x, post %08x != initial %08x  |  tear:  0x%02X  == 0x%02X", a, b, initial_value, pre_tear, post_tear);
                else
                    PrintAndLogEx(INFO, "pre %08x != initial and post %08x == initial %08x |  tear:  0x%02X  == 0x%02X", a, b, initial_value, pre_tear, post_tear);
            } else {

                if ( initial_value != b )
                    PrintAndLogEx(INFO, "pre %08x == initial and post %08x != initial  %08x |  tear:  0x%02X  == 0x%02X", a, b, initial_value, pre_tear, post_tear);
            }

            if ( b == 0 ) {
                PrintAndLogEx(INFO, _CYAN_("Tear off occurred  (ZEROS value!) ->  ") "%s vs " _GREEN_("%s") "  Tear status:  0x%02X == 0x%02X   ( %s )"
                    , prestr
                    , poststr
                    , pre_tear
                    , post_tear
                    , post_tear_check ? _GREEN_("ok") : _RED_("DETECTED")
                );
                break;
            }

            if ( a > b ) {
                PrintAndLogEx(INFO, _CYAN_("Tear off occurred  " _RED_("( LESS )") " ->  ") "%s vs " _GREEN_("%s") "  Tear status:  0x%02X == 0x%02X   ( %s )"
                    , prestr
                    , poststr
                    , pre_tear
                    , post_tear
                    , post_tear_check ? _GREEN_("ok") : _RED_("DETECTED")
                );


                if (counter_reset_tear(&card, cnt_no) != PM3_SUCCESS){
                    PrintAndLogEx(FAILED, "failed to reset tear,  exiting...");
                    break;
                }

                uint32_t bar =  (0x1000000 - b) + 2;
                // wr_value = bar;
                // newvalue[0] = (bar) & 0xFF;
                // newvalue[1] = ((bar >> 8) & 0xFF);
                // newvalue[2] = ((bar >> 16) & 0xFF);

                wr_value = 0;
                newvalue[0] = 0;
                newvalue[1] = 0;
                newvalue[2] = 0;

                PrintAndLogEx(INFO, "     0x1000000 - 0x%x == 0x%x", b, bar);
                PrintAndLogEx(INFO, "      new increase value 0x%x" , wr_value);
                PrintAndLogEx(INFO, "    because BAR + post == 0x%x" , bar + b);

                PrintAndLogEx(INFO, "New increase value " _YELLOW_("%s"), sprint_hex_inrow(newvalue, newvaluelen));
                continue;
            } else  {

                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(INFO, _CYAN_("Tear off occurred  (+1)  (too late) ->  ") "%s vs %s   Tear:  0x%02X == 0x%02X   ( %s )"
                    , prestr
                    , poststr
                    , pre_tear
                    , post_tear
                    , post_tear_check ? _GREEN_("ok") : _RED_("DETECTED")
                );

                if ( post_tear_check  && b == initial_value) {
                    PrintAndLogEx(INFO, "Reverted to previous value");
                    break;
                }
                if ( wr_value != 0 ) {

                    //uint32_t bar =  (0x1000000 - b) + 2;
                    wr_value = 0;
                    newvalue[0] = 0;
                    newvalue[1] = 0;
                    newvalue[2] = 0;

                    if ( b >= (initial_value + (2 * wr_value))) {
                        PrintAndLogEx(INFO, "Large " _YELLOW_("( JUMP )") " detected");


                        // wr_value = bar;
                        // newvalue[0] = (bar) & 0xFF;
                        // newvalue[1] = ((bar >> 8) & 0xFF);
                        // newvalue[2] = ((bar >> 16) & 0xFF);
                    } else {

                        // wr_value = bar;
                        // newvalue[0] = (bar) & 0xFF;
                        // newvalue[1] = ((bar >> 8) & 0xFF);
                        // newvalue[2] = ((bar >> 16) & 0xFF);
                        // wr_value = 0;
                        // newvalue[0] = 0;
                        // newvalue[1] = 0;
                        // newvalue[2] = 0;
                    }

                }
                PrintAndLogEx(INFO, "New increase value " _YELLOW_("%s"), sprint_hex_inrow(newvalue, newvaluelen));

                //actual_time--;
                late++;
            }
        } else {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, _CYAN_("Status:  same value!   ->  ") "%s == %s   Tear:  0x%02X == 0x%02X   ( %s )"
                , prestr
                , poststr
                , pre_tear
                , post_tear
                , post_tear_check ? _GREEN_("ok") : _RED_("DETECTED")
            );

            if ( post_tear_check ) {
                if ( a == b ) {
                    //actual_time--;
                    continue;
                }

                if ( b == initial_value ) {
                    PrintAndLogEx(INFO, "Reverted to previous value");
                    break;
                }
            } else {

                if (counter_reset_tear(&card, cnt_no) != PM3_SUCCESS){
                    PrintAndLogEx(FAILED, "failed to reset tear,  exiting...");
                    break;
                }

            }
        }

        actual_time += interval;
    }

    DropField();

    PrintAndLogEx(INFO, " Sent %u tear offs ", loop);

    counter_reset_tear(&card, cnt_no);

    PrintAndLogEx(INFO, "hf 14a raw -s -c 3900              -->  read counter 0");
    PrintAndLogEx(INFO, "hf 14a raw -s -c 3e00              -->  read tearing 0");
    PrintAndLogEx(NORMAL, "");
    char read_cnt_str[30];
    snprintf(read_cnt_str, sizeof(read_cnt_str), "hf 14a raw -s -c 39%02x", counter);
    CommandReceived(read_cnt_str);
    char read_tear_str[30];
    snprintf(read_tear_str, sizeof(read_tear_str), "hf 14a raw -s -c 3e%02x", counter);
    CommandReceived(read_tear_str);
    return PM3_SUCCESS;
}

*/

//
// name, identifying bytes,  decode function,  hints text
// identifying bits
// 1. getversion data must match.
// 2. magic bytes in the readable payload


int CmdHF14MfuNDEFRead(const char *Cmd) {

    int keylen;
    int maxsize = 16, status;
    bool hasAuthKey = false;
    bool swapEndian = false;

    iso14a_card_select_t card;
    uint8_t data[16] = {0x00};
    uint8_t key[16] = {0x00};
    uint8_t *p_key = key;
    uint8_t pack[4] = {0, 0, 0, 0};

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu ndefread",
                  "Prints NFC Data Exchange Format (NDEF)",
                  "hf mfu ndefread -> shows NDEF data\n"
                  "hf mfu ndefread -k ffffffff -> shows NDEF data with key\n"
                  "hf mfu ndefread -f myfilename -> save raw NDEF to file"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("k", "key", "Replace default key for NDEF", NULL),
        arg_lit0("l", NULL, "Swap entered key's endianness"),
        arg_str0("f", "file", "<fn>", "Save raw NDEF to file"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIGetHexWithReturn(ctx, 1, key, &keylen);
    swapEndian = arg_get_lit(ctx, 2);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 3), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    bool verbose = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    switch (keylen) {
        case 0:
            break;
        case 4:
        case 16:
            hasAuthKey = true;
            break;
        default:
            PrintAndLogEx(WARNING, "ERROR: Key is incorrect length\n");
            return PM3_EINVARG;
    }

    // Get tag type
    uint64_t tagtype = GetHF14AMfU_Type();
    if (tagtype == MFU_TT_UL_ERROR) {
        PrintAndLogEx(WARNING, "No Ultralight / NTAG based tag found");
        return PM3_ESOFT;
    }

    // Is tag UL/NTAG?

    // Swap endianness
    if (swapEndian && hasAuthKey) p_key = SwapEndian64(key, keylen, (keylen == 16) ? 8 : 4);

    // Select and Auth
    if (ul_auth_select(&card, tagtype, hasAuthKey, p_key, pack, sizeof(pack)) == PM3_ESOFT) return PM3_ESOFT;

    // read pages 0,1,2,3 (should read 4pages)
    status = ul_read(0, data, sizeof(data));
    if (status <= 0) {
        DropField();
        PrintAndLogEx(ERR, "Error: tag didn't answer to READ");
        return PM3_ESOFT;
    } else if (status == 16) {

        status = ndef_print_CC(data + 12);
        if (status == PM3_ESOFT) {
            DropField();
            PrintAndLogEx(ERR, "Error: tag didn't contain a NDEF Container");
            return PM3_ESOFT;
        }

        // max datasize;
        maxsize = ndef_get_maxsize(data + 12);
    }

    // iceman: maybe always take MIN of tag identified size vs NDEF reported size?
    // fix: UL_EV1 48bytes != NDEF reported size
    for (uint8_t idx = 1; idx < ARRAYLEN(UL_TYPES_ARRAY); idx++) {
        if ((tagtype & UL_TYPES_ARRAY[idx]) == UL_TYPES_ARRAY[idx]) {

            if (maxsize != (UL_MEMORY_ARRAY[idx] * 4)) {
                PrintAndLogEx(INFO, "Tag reported size vs NDEF reported size mismatch. Using smallest value");
            }
            maxsize = MIN(maxsize, (UL_MEMORY_ARRAY[idx] * 4));
            break;
        }
    }

    // The following read will read in blocks of 16 bytes.
    // ensure maxsize is rounded up to a multiple of 16
    maxsize = maxsize + (16 - (maxsize % 16));
    // allocate mem
    uint8_t *records = calloc(maxsize, sizeof(uint8_t));
    if (records == NULL) {
        DropField();
        return PM3_EMALLOC;
    }

    // read NDEF records.
    for (uint32_t i = 0, j = 0; i < maxsize; i += 16, j += 4) {
        status = ul_read(4 + j, records + i, 16);
        if (status <= 0) {
            DropField();
            PrintAndLogEx(ERR, "Error: tag didn't answer to READ");
            free(records);
            return PM3_ESOFT;
        }
    }

    DropField();

    status = NDEFRecordsDecodeAndPrint(records, (size_t)maxsize, verbose);
    if (status != PM3_SUCCESS) {
        status = NDEFDecodeAndPrint(records, (size_t)maxsize, verbose);
    }

    // get total NDEF length before save. If fails, we save it all
    size_t n = 0;
    if (NDEFGetTotalLength(records, maxsize, &n) != PM3_SUCCESS)
        n = maxsize;

    pm3_save_dump(filename, records, n, jsfNDEF);


    char *jooki = strstr((char *)records, "s.jooki.rocks/s/?s=");
    if (jooki) {
        jooki += 17;
        while (jooki) {
            if ((*jooki) != '=')
                jooki++;
            else  {
                jooki++;
                char s[17] = {0};
                strncpy(s, jooki, 16);
                PrintAndLogEx(HINT, "Use `" _YELLOW_("hf jooki decode -d %s") "` to decode", s);
                break;
            }
        }
    }
    char *mattel = strstr((char *)records, ".pid.mattel/");
    if (mattel) {
        mattel += 12;
        while (mattel) {
            if ((*mattel) != '/')
                mattel++;
            else  {
                mattel++;
                char b64[33] = {0};
                strncpy(b64, mattel, 32);
                uint8_t arr[24] = {0};
                size_t arrlen = 0;
                mbedtls_base64_decode(arr, sizeof(arr), &arrlen, (const unsigned char *)b64, 32);

                PrintAndLogEx(INFO, "decoded... %s", sprint_hex(arr, arrlen));
                break;
            }
        }
    }

    free(records);
    return status;
}

// utility function. Retrieves emulator memory
static int GetMfuDumpFromEMul(mfu_dump_t **buf) {

    mfu_dump_t *dump = calloc(1, sizeof(mfu_dump_t));
    if (dump == NULL) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }

    PrintAndLogEx(INFO, "downloading from emulator memory");
    if (!GetFromDevice(BIG_BUF_EML, (uint8_t *)dump, MFU_MAX_BYTES + MFU_DUMP_PREFIX_LENGTH, 0, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        free(dump);
        return PM3_ETIMEOUT;
    }

    *buf = dump ;
    return PM3_SUCCESS ;
}

static int CmdHF14AMfuEView(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu eview",
                  "Displays emulator memory\n"
                  "By default number of pages shown depends on defined tag type.\n"
                  "You can override this with option --end.",
                  "hf mfu eview\n"
                  "hf mfu eview --end 255 -> dumps whole memory"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("e", "end", "<dec>", "index of last block"),
        arg_lit0("z", "dense", "dense dump output style"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int end = arg_get_int_def(ctx, 1, -1);
    bool dense_output = (g_session.dense_output || arg_get_lit(ctx, 2));
    CLIParserFree(ctx);

    bool override_end = (end != -1) ;

    if (override_end && (end < 0 || end > MFU_MAX_BLOCKS)) {
        PrintAndLogEx(WARNING, "Invalid value for end: %d   Must be be positive integer < %d", end, MFU_MAX_BLOCKS);
        return PM3_EINVARG ;
    }

    mfu_dump_t *dump ;
    int res = GetMfuDumpFromEMul(&dump) ;
    if (res != PM3_SUCCESS) {
        return res ;
    }

    if (override_end) {
        ++end ;
    } else {
        end = dump->pages + 1;
    }

    mfu_print_dump(dump, end, 0, dense_output);
    free(dump);
    return PM3_SUCCESS;
}

static int CmdHF14AMfuESave(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu esave",
                  "Saves emulator memory to a MIFARE Ultralight/NTAG dump file (bin/json)\n"
                  "By default number of pages saved depends on defined tag type.\n"
                  "You can override this with option --end.",
                  "hf mfu esave\n"
                  "hf mfu esave --end 255 -> saves whole memory\n"
                  "hf mfu esave -f hf-mfu-04010203040506-dump"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("e", "end", "<dec>", "index of last block"),
        arg_str0("f", "file", "<fn>", "Specify a filename for dump file"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int end = arg_get_int_def(ctx, 1, -1);

    char filename[FILE_PATH_SIZE];
    int fnlen = 0 ;
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    CLIParserFree(ctx);

    bool override_end = (end != -1) ;

    if (override_end && (end < 0 || end > MFU_MAX_BLOCKS)) {
        PrintAndLogEx(WARNING, "Invalid value for end:%d. Must be be positive integer <= %d.", end, MFU_MAX_BLOCKS);
        return PM3_EINVARG ;
    }

    // get dump from memory
    mfu_dump_t *dump ;
    int res = GetMfuDumpFromEMul(&dump) ;
    if (res != PM3_SUCCESS) {
        return res ;
    }

    // initialize filename
    if (fnlen < 1) {
        PrintAndLogEx(INFO, "Using UID as filename");
        uint8_t uid[7] = {0};
        memcpy(uid, (uint8_t *) & (dump->data), 3);
        memcpy(uid + 3, (uint8_t *) & (dump->data) + 4, 4);
        strcat(filename, "hf-mfu-");
        FillFileNameByUID(filename, uid, "-dump", sizeof(uid));
    }

    if (override_end) {
        end ++ ;
    } else {
        end = dump->pages ;
    }

    // save dump. Last block contains PACK + RFU
    uint16_t datalen = (end + 1) * MFU_BLOCK_SIZE + MFU_DUMP_PREFIX_LENGTH;
    res = pm3_save_dump(filename, (uint8_t *)dump, datalen, jsfMfuMemory);

    free(dump);
    return res;
}

static int CmdHF14AMfuView(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu view",
                  "Print a MIFARE Ultralight/NTAG dump file (bin/eml/json)",
                  "hf mfu view -f hf-mfu-01020304-dump.bin"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "Specify a filename for dump file"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_lit0("z", "dense", "dense dump output style"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE];
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    bool verbose = arg_get_lit(ctx, 2);
    bool dense_output = (g_session.dense_output || arg_get_lit(ctx, 3));
    CLIParserFree(ctx);

    // read dump file
    uint8_t *dump = NULL;
    size_t bytes_read = 0;
    int res = pm3_load_dump(filename, (void **)&dump, &bytes_read, (MFU_MAX_BYTES + MFU_DUMP_PREFIX_LENGTH));
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (bytes_read < MFU_DUMP_PREFIX_LENGTH) {
        PrintAndLogEx(ERR, "Error, dump file is too small");
        free(dump);
        return PM3_ESOFT;
    }

    res = convert_mfu_dump_format(&dump, &bytes_read, verbose);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Failed convert on load to new Ultralight/NTAG format");
        free(dump);
        return res;
    }

    uint16_t block_cnt = ((bytes_read - MFU_DUMP_PREFIX_LENGTH) / MFU_BLOCK_SIZE);

    if (verbose) {
        PrintAndLogEx(INFO, "File: " _YELLOW_("%s"), filename);
        PrintAndLogEx(INFO, "File size %zu bytes, file blocks %d (0x%x)", bytes_read, block_cnt, block_cnt);
    }

    mfu_print_dump((mfu_dump_t *)dump, block_cnt, 0, dense_output);
    free(dump);
    return PM3_SUCCESS;
}

static int CmdHF14AMfuList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf 14a", "14a -c");
}

static int CmdHF14AAmiibo(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu amiibo",
                  "Tries to read all memory from amiibo tag and decrypt it",
                  "hf mfu amiiboo --dec -f hf-mfu-04579DB27C4880-dump.bin  --> decrypt file\n"
                  "hf mfu amiiboo -v --dec                                 --> decrypt tag"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "dec", "Decrypt memory"),
        arg_lit0(NULL, "enc", "Encrypt memory"),
        arg_str0("i", "in", "<fn>", "Specify a filename for input dump file"),
        arg_str0("o", "out", "<fn>", "Specify a filename for output dump file"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool shall_decrypt = arg_get_lit(ctx, 1);
    bool shall_encrypt = arg_get_lit(ctx, 2);

    int infnlen = 0;
    char infilename[FILE_PATH_SIZE];
    CLIParamStrToBuf(arg_get_str(ctx, 3), (uint8_t *)infilename, FILE_PATH_SIZE, &infnlen);

    int outfnlen = 0;
    char outfilename[FILE_PATH_SIZE];
    CLIParamStrToBuf(arg_get_str(ctx, 4), (uint8_t *)outfilename, FILE_PATH_SIZE, &outfnlen);

    bool verbose = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    // sanity checks
    if ((shall_decrypt + shall_encrypt) > 1) {
        PrintAndLogEx(WARNING, "Only specify decrypt or encrypt");
        return PM3_EINVARG;
    }

    // load keys
    nfc3d_amiibo_keys_t amiibo_keys;
    if (nfc3d_amiibo_load_keys(&amiibo_keys) == false) {
        PrintAndLogEx(INFO, "loading key file ( " _RED_("fail") " )");
        return PM3_EFILE;
    }

    int res = PM3_ESOFT;

    uint8_t original[NFC3D_AMIIBO_SIZE] = {0};

    // load dump file if available
    if (infnlen > 0) {
        uint8_t *dump = NULL;
        size_t dumplen = 0;
        res = loadFile_safe(infilename, "", (void **)&dump, &dumplen);
        if (res != PM3_SUCCESS) {
            free(dump);
            return PM3_EFILE;
        }

        if (dumplen < MFU_DUMP_PREFIX_LENGTH) {
            PrintAndLogEx(ERR, "Error, dump file is too small");
            free(dump);
            return PM3_ESOFT;
        }

        res = convert_mfu_dump_format(&dump, &dumplen, verbose);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Failed convert on load to new Ultralight/NTAG format");
            free(dump);
            return res;
        }

        const mfu_dump_t *d = (mfu_dump_t *)dump;
        memcpy(original, d->data, sizeof(original));
        free(dump);
    } else {
        uint16_t dlen = 0;
        uint8_t *dump = NULL;
        res = mfu_dump_tag(MAX_NTAG_215, (void **)&dump, &dlen);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Failed to dump memory from tag");
            free(dump);
            return res;
        }
        memcpy(original, dump, sizeof(original));
        free(dump);
    }


    uint8_t decrypted[NFC3D_AMIIBO_SIZE] = {0};
    if (shall_decrypt) {
        if (nfc3d_amiibo_unpack(&amiibo_keys, original, decrypted) == false) {
            PrintAndLogEx(INFO, "Tag signature ( " _RED_("fail") " )");
            return PM3_ESOFT;
        }
        // print
        if (verbose) {
            for (uint8_t i = 0; i < (NFC3D_AMIIBO_SIZE / 16); i++) {
                PrintAndLogEx(INFO, "[%d] %s", i, sprint_hex_ascii(decrypted + (i * 16), 16));
            }
        }
    }

    if (shall_encrypt) {
        uint8_t encrypted[NFC3D_AMIIBO_SIZE] = {0};
        nfc3d_amiibo_pack(&amiibo_keys, decrypted, encrypted);
        // print
        if (verbose) {
            for (uint8_t i = 0; i < (NFC3D_AMIIBO_SIZE / 16); i++) {
                PrintAndLogEx(INFO, "[%d] %s", i, sprint_hex_ascii(encrypted + (i * 16), 16));
            }
        }
    }

    if (outfnlen) {
        // save dump. Last block contains PACK + RFU
//        uint16_t datalen = MFU_BLOCK_SIZE + MFU_DUMP_PREFIX_LENGTH;
//        res = pm3_save_dump(outfilename, (uint8_t *)dump, datalen, jsfMfuMemory);
    }

    return PM3_SUCCESS;
}

static int CmdHF14AMfuWipe(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu wipe",
                  "Wipe card to zeros. It will ignore block0,1,2,3\n"
                  "you will need to call it with password in order to wipe the config and sett default pwd/pack\n"
                  "Abort by pressing a key\n"
                  "New password.... FFFFFFFF\n"
                  "New 3-DES key... 49454D4B41455242214E4143554F5946\n",
                  "hf mfu wipe\n"
                  "hf mfu wipe -k 49454D4B41455242214E4143554F5946\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0("k", "key", "<hex>", "Key for authentication (UL-C 16 bytes, EV1/NTAG 4 bytes)"),
        arg_lit0("l", NULL, "Swap entered key's endianness"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int ak_len = 0;
    uint8_t authenticationkey[16] = {0x00};
    uint8_t *auth_key_ptr = authenticationkey;
    CLIGetHexWithReturn(ctx, 1, authenticationkey, &ak_len);
    bool swap_endian = arg_get_lit(ctx, 2);

    CLIParserFree(ctx);

    bool has_auth_key = false;
    bool has_pwd = false;
    if (ak_len == 16) {
        has_auth_key = true;
    } else if (ak_len == 4) {
        has_pwd = true;
    } else if (ak_len != 0) {
        PrintAndLogEx(WARNING, "ERROR: Key is incorrect length\n");
        return PM3_EINVARG;
    }

    uint8_t card_mem_size = 0;

    // Swap endianness
    if (swap_endian) {
        if (has_auth_key) {
            auth_key_ptr = SwapEndian64(authenticationkey, ak_len, 8);
        }

        if (has_pwd) {
            auth_key_ptr = SwapEndian64(authenticationkey, ak_len, 4);
        }
    }

    uint64_t tagtype = GetHF14AMfU_Type();
    if (tagtype == MFU_TT_UL_ERROR) {
        return PM3_ESOFT;
    }

    // number of pages to WRITE
    for (uint8_t idx = 1; idx < ARRAYLEN(UL_TYPES_ARRAY); idx++) {
        if ((tagtype & UL_TYPES_ARRAY[idx]) == UL_TYPES_ARRAY[idx]) {
            //add one as maxblks starts at 0
            card_mem_size = UL_MEMORY_ARRAY[idx] + 1;
            break;
        }
    }

    ul_print_type(tagtype, 0);

    // GDM / GEN1A / GEN4 / NTAG21x read the key
    if (ak_len == 0) {

        DropField();

        int res = get_ulc_3des_key_magic(tagtype, auth_key_ptr);
        if (res != PM3_SUCCESS) {
            return res;
        }
        PrintAndLogEx(SUCCESS, "Using 3DES key... %s", sprint_hex_inrow(auth_key_ptr, 16));
        has_auth_key = true;
    }

    DropField();

    PrintAndLogEx(INFO, "Start wiping...");
    PrintAndLogEx(INFO, "-----+-----------------------------");
    // time to wipe card
    // We skip the first four blocks.
    //  block 0,1  - UID
    //  block 2    - lock
    //  block 3    - OTP
    for (uint8_t i = 4; i < card_mem_size; i++) {

        if (kbd_enter_pressed()) {
            PrintAndLogEx(WARNING, "\naborted via keyboard!\n");
            goto out;
        }

        uint8_t data[MFU_BLOCK_SIZE];
        memset(data, 0x00, sizeof(data));

        // UL_C specific
        if ((tagtype & MFU_TT_UL_C) == MFU_TT_UL_C) {
            // default config?

            switch (i) {
                case 4:
                    memcpy(data, "\x02\x00\x00\x10", 4);
                    break;
                case 5:
                    memcpy(data, "\x00\x06\x01\x10", 4);
                    break;
                case 6:
                    memcpy(data, "\x11\xFF\x00\x00", 4);
                    break;
                case 42:
                    memcpy(data, "\x30\x00\x00\x00", 4);
                    break;
                case 44:
                    goto ulc;
            }
        }

        // UL_AES specific
        if ((tagtype & MFU_TT_UL_AES)) {
            // default config?
        }

        // UL / NTAG with PWD/PACK
        if ((tagtype & (MFU_TT_UL_EV1_48 | MFU_TT_UL_EV1_128 | MFU_TT_UL_EV1 | MFU_TT_UL_NANO_40 |
                        MFU_TT_NTAG_210u | MFU_TT_NTAG_213 | MFU_TT_NTAG_213_F | MFU_TT_NTAG_213_C |
                        MFU_TT_NTAG_213_TT | MFU_TT_NTAG_215 | MFU_TT_NTAG_216 | MFU_TT_NTAG_216_F |
                        MFU_TT_NTAG_I2C_1K | MFU_TT_NTAG_I2C_2K | MFU_TT_NTAG_I2C_1K_PLUS | MFU_TT_NTAG_I2C_2K_PLUS
                       ))) {


            // cfg 1
            if (i == card_mem_size - 4) {
                // strong modulation mode disabled
                // pages don't need authentication
                uint8_t cfg1[MFU_BLOCK_SIZE] = {0x00, 0x00, 0x00, 0xFF};
                memcpy(data, cfg1, sizeof(cfg1));
            }

            // cfg 2
            if (i == card_mem_size - 3) {
                // Unlimited password attempts
                // NFC counter disabled
                // NFC counter not protected
                // user configuration writeable
                // write access is protected with password
                // 05, Virtual Card Type Identifier is default
                uint8_t cfg2[MFU_BLOCK_SIZE] = {0x00, 0x05, 0x00, 0x00};
                memcpy(data, cfg2, sizeof(cfg2));
            }

            // Set PWD blocks  0xFF FF FF FF
            if (i == card_mem_size - 2) {
                memset(data, 0xFF, sizeof(data));
            }

            // Since we changed PWD before, we need to use new PWD to set PACK
            // Pack will be all zeros,
            if (i == card_mem_size - 1) {
                memset(auth_key_ptr, 0xFF, ak_len);
            }
        }

        /*
        int res = PM3_SUCCESS;
        if (res == PM3_ESOFT) {
            res = mfu_write_block(data, MFU_BLOCK_SIZE, has_auth_key, has_pwd, auth_key_ptr, i);
        }
        */

        int res = mfu_write_block(data, MFU_BLOCK_SIZE, has_auth_key, has_pwd, auth_key_ptr, i);

        PrintAndLogEx(INFO, " %3d | %s" NOLF, i, sprint_hex(data, MFU_BLOCK_SIZE));
        switch (res) {
            case PM3_SUCCESS: {
                PrintAndLogEx(NORMAL, "( " _GREEN_("ok") " )");
                break;
            }
            case PM3_ESOFT: {
                PrintAndLogEx(NORMAL, "( " _RED_("fail") " )");
                break;
            }
            case PM3_ETIMEOUT:
            default: {
                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(WARNING, "command execution time out");
                goto out;
            }
        }
    }

    PrintAndLogEx(INFO, "-----+-----------------------------");

ulc:

    // UL-C - set 3-DES key
    if ((tagtype & MFU_TT_UL_C) == MFU_TT_UL_C) {

        uint8_t key[16] = {
            0x49, 0x45, 0x4D, 0x4B, 0x41, 0x45, 0x52, 0x42,
            0x21, 0x4E, 0x41, 0x43, 0x55, 0x4F, 0x59, 0x46
        };

        clearCommandBuffer();
        SendCommandMIX(CMD_HF_MIFAREUC_SETPWD, 0, 0, 0, key, sizeof(key));
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
            if ((resp.oldarg[0] & 0xff) == 1) {
                PrintAndLogEx(INFO, "Ultralight-C new key... " _GREEN_("%s"), sprint_hex_inrow(key, sizeof(key)));
            } else {
                PrintAndLogEx(WARNING, "Failed writing at block %u", (uint8_t)(resp.oldarg[1] & 0xFF));
                return PM3_ESOFT;
            }
        } else {
            PrintAndLogEx(WARNING, "command execution time out");
            return PM3_ETIMEOUT;
        }
    }

    // UL_AES specific
    if ((tagtype & MFU_TT_UL_AES)) {
        // Set AES key
    }


    PrintAndLogEx(HINT, "try `" _YELLOW_("hf mfu dump --ns") "` to verify");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "Done!");

out:
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",     CmdHelp,                   AlwaysAvailable, "This help"},
    {"list",     CmdHF14AMfuList,           AlwaysAvailable, "List MIFARE Ultralight / NTAG history"},
    {"-----------", CmdHelp,                IfPm3Iso14443a,  "----------------------- " _CYAN_("recovery") " -------------------------"},
    {"keygen",   CmdHF14AMfUKeyGen,         AlwaysAvailable, "Generate DES/3DES/AES MIFARE diversified keys"},
    {"pwdgen",   CmdHF14AMfUPwdGen,         AlwaysAvailable, "Generate pwd from known algos"},
    {"otptear",  CmdHF14AMfuOtpTearoff,     IfPm3Iso14443a,  "Tear-off test on OTP bits"},
//    {"tear_cnt", CmdHF14AMfuEv1CounterTearoff,     IfPm3Iso14443a,  "Tear-off test on Ev1/NTAG Counter bits"},
    {"-----------", CmdHelp,                IfPm3Iso14443a,  "----------------------- " _CYAN_("operations") " -----------------------"},
    {"cauth",    CmdHF14AMfUCAuth,          IfPm3Iso14443a,  "Ultralight-C - Authentication"},
    {"setpwd",   CmdHF14AMfUCSetPwd,        IfPm3Iso14443a,  "Ultralight-C - Set 3DES key"},
    {"dump",     CmdHF14AMfUDump,           IfPm3Iso14443a,  "Dump MIFARE Ultralight family tag to binary file"},
    {"info",     CmdHF14AMfUInfo,           IfPm3Iso14443a,  "Tag information"},
    {"ndefread", CmdHF14MfuNDEFRead,        IfPm3Iso14443a,  "Prints NDEF records from card"},
    {"rdbl",     CmdHF14AMfURdBl,           IfPm3Iso14443a,  "Read block"},
    {"restore",  CmdHF14AMfURestore,        IfPm3Iso14443a,  "Restore a dump file onto a tag"},
    {"tamper",   CmdHF14MfUTamper,          IfPm3Iso14443a,  "NTAG 213TT - Configure the tamper feature"},
    {"view",     CmdHF14AMfuView,           AlwaysAvailable, "Display content from tag dump file"},
    {"wipe",     CmdHF14AMfuWipe,           IfPm3Iso14443a,  "Wipe card to zeros and default key"},
    {"wrbl",     CmdHF14AMfUWrBl,           IfPm3Iso14443a,  "Write block"},
    {"-----------", CmdHelp,                IfPm3Iso14443a,  "----------------------- " _CYAN_("simulation") " -----------------------"},
    {"eload",    CmdHF14AMfUeLoad,          IfPm3Iso14443a,  "Upload file into emulator memory"},
    {"esave",    CmdHF14AMfuESave,          IfPm3Iso14443a,  "Save emulator memory to file"},
    {"eview",    CmdHF14AMfuEView,          IfPm3Iso14443a,  "View emulator memory"},
    {"sim",      CmdHF14AMfUSim,            IfPm3Iso14443a,  "Simulate MIFARE Ultralight from emulator memory"},
    {"-----------", CmdHelp,                IfPm3Iso14443a,  "----------------------- " _CYAN_("magic") " ----------------------------"},
    {"setuid",   CmdHF14AMfUCSetUid,        IfPm3Iso14443a,  "Set UID - MAGIC tags only"},
    {"-----------", CmdHelp,                IfPm3Iso14443a,  "----------------------- " _CYAN_("amiibo") " ----------------------------"},
    {"amiibo",   CmdHF14AAmiibo,            IfPm3Iso14443a,  "Amiibo tag operations"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFMFUltra(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
