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

static int CmdHelp(const char *Cmd);

static uint8_t default_3des_keys[][16] = {
    { 0x42, 0x52, 0x45, 0x41, 0x4b, 0x4d, 0x45, 0x49, 0x46, 0x59, 0x4f, 0x55, 0x43, 0x41, 0x4e, 0x21 }, // 3des std key
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // all zeroes
    { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }, // 0x00-0x0F
    { 0x49, 0x45, 0x4D, 0x4B, 0x41, 0x45, 0x52, 0x42, 0x21, 0x4E, 0x41, 0x43, 0x55, 0x4F, 0x59, 0x46 }, // NFC-key
    { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 }, // all ones
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, // all FF
    { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF } // 11 22 33
};

static uint8_t default_pwd_pack[][4] = {
    {0xFF, 0xFF, 0xFF, 0xFF}, // PACK 0x00,0x00 -- factory default
    {0x4E, 0x45, 0x78, 0x54}, // NExT
};

static uint32_t UL_TYPES_ARRAY[] = {
    UNKNOWN,            UL,                 UL_C,                UL_EV1_48,          UL_EV1_128,
    NTAG,               NTAG_203,           NTAG_210,            NTAG_212,
    NTAG_213,           NTAG_215,           NTAG_216,
    MY_D,               MY_D_NFC,           MY_D_MOVE,           MY_D_MOVE_NFC,      MY_D_MOVE_LEAN,
    NTAG_I2C_1K,        NTAG_I2C_2K,        NTAG_I2C_1K_PLUS,    NTAG_I2C_2K_PLUS,
    FUDAN_UL,           NTAG_213_F,         NTAG_216_F,          UL_EV1,             UL_NANO_40,
    NTAG_213_TT,        NTAG_213_C,
    MAGIC_1A,           MAGIC_1B,           MAGIC_NTAG,
    NTAG_210u,          UL_MAGIC,           UL_C_MAGIC
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
    MAX_NTAG_210,       MAX_UL_BLOCKS,      MAX_ULC_BLOCKS
};

//------------------------------------
// get version nxp product type
static const char *getProductTypeStr(uint8_t id) {
    static char buf[20];

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

static int ul_print_nxp_silicon_info(uint8_t *card_uid) {

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
    WaitForResponse(CMD_ACK, &resp);
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
    if (card.uidlen != 7) {
        PrintAndLogEx(WARNING, "Wrong sized UID, expected 7bytes got %d", card.uidlen);
        return PM3_ESOFT;
    }
    memcpy(uid, card.uid, 7);
    return PM3_SUCCESS;
}

static void ul_switch_on_field(void) {
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_NO_DISCONNECT | ISO14A_NO_RATS, 0, 0, NULL, 0);
}

static int ul_send_cmd_raw(uint8_t *cmd, uint8_t cmdlen, uint8_t *response, uint16_t responseLength) {
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_APPEND_CRC | ISO14A_NO_RATS, cmdlen, 0, cmd, cmdlen);
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) return -1;
    if (!resp.oldarg[0] && responseLength) return -1;

    uint16_t resplen = (resp.oldarg[0] < responseLength) ? resp.oldarg[0] : responseLength;
    memcpy(response, resp.data.asBytes, resplen);
    return resplen;
}

static bool ul_select(iso14a_card_select_t *card) {

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

        if (card)
            memcpy(card, resp.data.asBytes, sizeof(iso14a_card_select_t));
    }
    return true;
}

// This read command will at least return 16bytes.
static int ul_read(uint8_t page, uint8_t *response, uint16_t responseLength) {

    uint8_t cmd[] = {ISO14443A_CMD_READBLOCK, page};
    int len = ul_send_cmd_raw(cmd, sizeof(cmd), response, responseLength);
    return len;
}

static int ul_comp_write(uint8_t page, uint8_t *data, uint8_t datalen) {

    if (data == NULL)
        return -1;

    uint8_t cmd[18];
    memset(cmd, 0x00, sizeof(cmd));
    datalen = (datalen > 16) ? 16 : datalen;

    cmd[0] = ISO14443A_CMD_WRITEBLOCK;
    cmd[1] = page;
    memcpy(cmd + 2, data, datalen);

    uint8_t response[1] = {0xFF};
    ul_send_cmd_raw(cmd, 2 + datalen, response, sizeof(response));
    // ACK
    if (response[0] == 0x0a) return 0;
    // NACK
    return -1;
}

static int ulc_requestAuthentication(uint8_t *nonce, uint16_t nonceLength) {

    uint8_t cmd[] = {MIFARE_ULC_AUTH_1, 0x00};
    int len = ul_send_cmd_raw(cmd, sizeof(cmd), nonce, nonceLength);
    return len;
}

static int ulc_authentication(uint8_t *key, bool switch_off_field) {

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_MIFAREUC_AUTH, switch_off_field, 0, 0, key, 16);
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) return 0;
    if (resp.oldarg[0] == 1) return 1;

    return 0;
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

static int try_default_3des_keys(uint8_t **correct_key) {
    PrintAndLogEx(INFO, "Trying some default 3des keys");
    for (uint8_t i = 0; i < ARRAYLEN(default_3des_keys); ++i) {
        uint8_t *key = default_3des_keys[i];
        if (ulc_authentication(key, true)) {
            *correct_key = key;
            return PM3_SUCCESS;
        }
    }
    return PM3_ESOFT;
}

static int ulev1_requestAuthentication(uint8_t *pwd, uint8_t *pack, uint16_t packLength) {

    uint8_t cmd[] = {MIFARE_ULEV1_AUTH, pwd[0], pwd[1], pwd[2], pwd[3]};
    int len = ul_send_cmd_raw(cmd, sizeof(cmd), pack, packLength);
    // NACK tables different tags,  but between 0-9 is a NEGATIVE response.
    // ACK == 0xA
    if (len == 1 && pack[0] <= 0x09)
        return -1;
    return len;
}

static int ul_auth_select(iso14a_card_select_t *card, TagTypeUL_t tagtype, bool hasAuthKey, uint8_t *authkey, uint8_t *pack, uint8_t packSize) {
    if (hasAuthKey && (tagtype & UL_C)) {
        //will select card automatically and close connection on error
        if (!ulc_authentication(authkey, false)) {
            PrintAndLogEx(WARNING, "Authentication Failed UL-C");
            return PM3_ESOFT;
        }
    } else {
        if (!ul_select(card)) return PM3_ESOFT;

        if (hasAuthKey) {
            if (ulev1_requestAuthentication(authkey, pack, packSize) == -1) {
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
    int len = ul_send_cmd_raw(cmd, sizeof(cmd), response, responseLength);
    return len;
}

static int ulev1_getVersion(uint8_t *response, uint16_t responseLength) {
    uint8_t cmd[] = {MIFARE_ULEV1_VERSION};
    int len = ul_send_cmd_raw(cmd, sizeof(cmd), response, responseLength);
    return len;
}

static int ulev1_readCounter(uint8_t counter, uint8_t *response, uint16_t responseLength) {

    uint8_t cmd[] = {MIFARE_ULEV1_READ_CNT, counter};
    int len = ul_send_cmd_raw(cmd, sizeof(cmd), response, responseLength);
    return len;
}

static int ulev1_readTearing(uint8_t counter, uint8_t *response, uint16_t responseLength) {

    uint8_t cmd[] = {MIFARE_ULEV1_CHECKTEAR, counter};
    int len = ul_send_cmd_raw(cmd, sizeof(cmd), response, responseLength);
    return len;
}

static int ulev1_readSignature(uint8_t *response, uint16_t responseLength) {

    uint8_t cmd[] = {MIFARE_ULEV1_READSIG, 0x00};
    int len = ul_send_cmd_raw(cmd, sizeof(cmd), response, responseLength);
    return len;
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
    if (!ul_select(&card))
        return UL_ERROR;

    uint8_t cmd[4] = {ISO14443A_CMD_READBLOCK, 0x00, 0x02, 0xa7}; //wrong crc on purpose  should be 0xa8
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_NO_RATS, 4, 0, cmd, sizeof(cmd));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) return UL_ERROR;
    if (resp.oldarg[0] != 1) return UL_ERROR;

    return (!resp.data.asBytes[0]) ? FUDAN_UL : UL; //if response == 0x00 then Fudan, else Genuine NXP
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

    PrintAndLogEx(SUCCESS, "OneTimePad: %s - %s",
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
    if (data[0] != 0xE1)
        return PM3_ESOFT;

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
    PrintAndLogEx(SUCCESS, "Capability Container: %s", sprint_hex(data, 4));
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
    PrintAndLogEx(SUCCESS, "  %s", sprint_bin(&data[3], 1));
    PrintAndLogEx(SUCCESS, "  xxx..... - %02X: RFU ( %s )", msb3, (msb3 == 0) ? _GREEN_("ok") : _RED_("fail"));
    PrintAndLogEx(SUCCESS, "  ...x.... - %02X: %s special frame", sf, (sf) ? "support" : "don\'t support");
    PrintAndLogEx(SUCCESS, "  ....x... - %02X: %s lock block", lb, (lb) ? "support" : "don\'t support");
    PrintAndLogEx(SUCCESS, "  .....xx. - %02X: RFU ( %s )", mlrule, (mlrule == 0) ? _GREEN_("ok") : _RED_("fail"));
    PrintAndLogEx(SUCCESS, "  .......x - %02X: IC %s multiple block reads", mbread, (mbread) ? "support" : "don\'t support");
    return PM3_SUCCESS;
}

int ul_print_type(uint32_t tagtype, uint8_t spaces) {

    if (spaces > 10)
        spaces = 10;

    char typestr[100];
    memset(typestr, 0x00, sizeof(typestr));

    if (tagtype & UL)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("MIFARE Ultralight (MF0ICU1)"), spaces, "");
    else if (tagtype & UL_C)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("MIFARE Ultralight C (MF0ULC)"), spaces, "");
    else if (tagtype & UL_NANO_40)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("MIFARE Ultralight Nano 40bytes (MF0UNH00)"), spaces, "");
    else if (tagtype & UL_EV1_48)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("MIFARE Ultralight EV1 48bytes (MF0UL1101)"), spaces, "");
    else if (tagtype & UL_EV1_128)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("MIFARE Ultralight EV1 128bytes (MF0UL2101)"), spaces, "");
    else if (tagtype & UL_EV1)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("MIFARE Ultralight EV1 UNKNOWN"), spaces, "");
    else if (tagtype & NTAG)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG UNKNOWN"), spaces, "");
    else if (tagtype & NTAG_203)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG 203 144bytes (NT2H0301F0DT)"), spaces, "");
    else if (tagtype & NTAG_210u)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG 210u (micro) 48bytes (NT2L1001G0DU)"), spaces, "");
    else if (tagtype & NTAG_210)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG 210 48bytes (NT2L1011G0DU)"), spaces, "");
    else if (tagtype & NTAG_212)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG 212 128bytes (NT2L1211G0DU)"), spaces, "");
    else if (tagtype & NTAG_213)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG 213 144bytes (NT2H1311G0DU)"), spaces, "");
    else if (tagtype & NTAG_213_F)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG 213F 144bytes (NT2H1311F0DTL)"), spaces, "");
    else if (tagtype & NTAG_213_C)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG 213C 144bytes (NT2H1311C1DTL)"), spaces, "");
    else if (tagtype & NTAG_213_TT)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG 213TT 144bytes (NT2H1311TTDU)"), spaces, "");
    else if (tagtype & NTAG_215)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG 215 504bytes (NT2H1511G0DU)"), spaces, "");
    else if (tagtype & NTAG_216)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG 216 888bytes (NT2H1611G0DU)"), spaces, "");
    else if (tagtype & NTAG_216_F)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG 216F 888bytes (NT2H1611F0DTL)"), spaces, "");
    else if (tagtype & NTAG_I2C_1K)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG I2C 888bytes (NT3H1101FHK)"), spaces, "");
    else if (tagtype & NTAG_I2C_2K)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG I2C 1904bytes (NT3H1201FHK)"), spaces, "");
    else if (tagtype & NTAG_I2C_1K_PLUS)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG I2C plus 888bytes (NT3H2111FHK)"), spaces, "");
    else if (tagtype & NTAG_I2C_2K_PLUS)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("NTAG I2C plus 1912bytes (NT3H2211FHK)"), spaces, "");
    else if (tagtype & MY_D)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("INFINEON my-d\x99 (SLE 66RxxS)"), spaces, "");
    else if (tagtype & MY_D_NFC)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("INFINEON my-d\x99 NFC (SLE 66RxxP)"), spaces, "");
    else if (tagtype & MY_D_MOVE)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("INFINEON my-d\x99 move (SLE 66R01P)"), spaces, "");
    else if (tagtype & MY_D_MOVE_NFC)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("INFINEON my-d\x99 move NFC (SLE 66R01P)"), spaces, "");
    else if (tagtype & MY_D_MOVE_LEAN)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("INFINEON my-d\x99 move lean (SLE 66R01L)"), spaces, "");
    else if (tagtype & FUDAN_UL)
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("FUDAN Ultralight Compatible (or other compatible)"), spaces, "");
    else
        snprintf(typestr, sizeof(typestr), "%*sTYPE: " _YELLOW_("Unknown %06x"), spaces, "", tagtype);

    bool ismagic = ((tagtype & MAGIC) == MAGIC);
    if (ismagic)
        snprintf(typestr + strlen(typestr), 4, " (");

    snprintf(typestr + strlen(typestr), sizeof(typestr) - strlen(typestr), " %s ", (tagtype & MAGIC) ?  _GREEN_("magic") : "");
    tagtype &= ~(MAGIC);
    snprintf(typestr + strlen(typestr), sizeof(typestr) - strlen(typestr), "%s", (tagtype & MAGIC_1A) ? _GREEN_("Gen 1a") : "");
    snprintf(typestr + strlen(typestr), sizeof(typestr) - strlen(typestr), "%s", (tagtype & MAGIC_1B) ? _GREEN_("Gen 1b") : "");

    if (ismagic)
        snprintf(typestr + strlen(typestr), 4, " )");

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

static int ulc_print_configuration(uint8_t *data) {

    PrintAndLogEx(NORMAL, "\n--- " _CYAN_("UL-C Configuration"));
    PrintAndLogEx(NORMAL, " Higher Lockbits [40/0x28]: %s - %s", sprint_hex(data, 4), sprint_bin(data, 2));
    PrintAndLogEx(NORMAL, "         Counter [41/0x29]: %s - %s", sprint_hex(data + 4, 4), sprint_bin(data + 4, 2));

    bool validAuth = (data[8] >= 0x03 && data[8] <= 0x30);
    if (validAuth)
        PrintAndLogEx(NORMAL, "           Auth0 [42/0x2A]: %s page %d/0x%02X and above need authentication", sprint_hex(data + 8, 4), data[8], data[8]);
    else {
        if (data[8] == 0) {
            PrintAndLogEx(NORMAL, "           Auth0 [42/0x2A]: %s default", sprint_hex(data + 8, 4));
        } else {
            PrintAndLogEx(NORMAL, "           Auth0 [42/0x2A]: %s auth byte is out-of-range", sprint_hex(data + 8, 4));
        }
    }
    PrintAndLogEx(NORMAL, "           Auth1 [43/0x2B]: %s %s",
                  sprint_hex(data + 12, 4),
                  (data[12] & 1) ? "write access restricted" : "read and write access restricted"
                 );
    return PM3_SUCCESS;
}

static int ulev1_print_configuration(uint32_t tagtype, uint8_t *data, uint8_t startPage) {

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Configuration"));

    bool strg_mod_en = (data[0] & 2);

    uint8_t authlim = (data[4] & 0x07);
    bool nfc_cnf_prot_pwd = ((data[4] & 0x08) == 0x08);
    bool nfc_cnf_en  = ((data[4] & 0x10) == 0x10);
    bool cfglck = ((data[4] & 0x40) == 0x40);
    bool prot = ((data[4] & 0x80) == 0x80);

    uint8_t vctid = data[5];

    PrintAndLogEx(INFO, "  cfg0 [%u/0x%02X]: %s", startPage, startPage, sprint_hex(data, 4));

    //NTAG213TT has different ASCII mirroring options and config bytes interpretation from other ulev1 class tags
    if (tagtype & NTAG_213_TT) {
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
            PrintAndLogEx(INFO, "                mirror start page %02X | byte pos %02X - %s", mirror_page, mirror_byte, (mirror_page >= 0x4 && ((mirror_user_mem_start_byte + bytes_required_for_mirror_data) <= 144)) ? _GREEN_("OK") : _YELLOW_("Invalid value"));
        }

    } else if (tagtype & (NTAG_213_F | NTAG_216_F)) {
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
        if (tagtype & NTAG_213_F) {
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
        } else if (tagtype & NTAG_216_F) {
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

    if (tagtype & NTAG_213_TT) {
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

    PrintAndLogEx(INFO, "  cfg1 [%u/0x%02X]: %s", startPage + 1, startPage + 1,  sprint_hex(data + 4, 4));
    if (authlim == 0)
        PrintAndLogEx(INFO, "                    - " _GREEN_("Unlimited password attempts"));
    else
        PrintAndLogEx(INFO, "                    - Max number of password attempts is " _YELLOW_("%d"), authlim);

    PrintAndLogEx(INFO, "                    - NFC counter %s", (nfc_cnf_en) ? "enabled" : "disabled");
    PrintAndLogEx(INFO, "                    - NFC counter %s", (nfc_cnf_prot_pwd) ? "password protection enabled" : "not protected");

    PrintAndLogEx(INFO, "                    - user configuration %s", cfglck ? "permanently locked" : "writeable");
    PrintAndLogEx(INFO, "                    - %s access is protected with password", prot ? "read and write" : "write");
    PrintAndLogEx(INFO, "                    - %02X, Virtual Card Type Identifier is %sdefault", vctid, (vctid == 0x05) ? "" : "not ");
    PrintAndLogEx(INFO, "  PWD  [%u/0x%02X]: %s- (cannot be read)", startPage + 2, startPage + 2,  sprint_hex(data + 8, 4));
    PrintAndLogEx(INFO, "  PACK [%u/0x%02X]: %s      - (cannot be read)", startPage + 3, startPage + 3,  sprint_hex(data + 12, 2));
    PrintAndLogEx(INFO, "  RFU  [%u/0x%02X]:       %s- (cannot be read)", startPage + 3, startPage + 3,  sprint_hex(data + 14, 2));

    if (tagtype & NTAG_213_TT) {
        if (data[1] & 0x06) {
            PrintAndLogEx(INFO, "TT_MSG [45/0x2D]: %s- (cannot be read)", sprint_hex(tt_message, tt_msg_resp_len));
            PrintAndLogEx(INFO, "                    - tamper message is masked in memory");
        } else {
            PrintAndLogEx(INFO, "TT_MSG [45/0x2D]: %s", sprint_hex(tt_message, tt_msg_resp_len));
            PrintAndLogEx(INFO, "                    - tamper message is %s and is readable/writablbe in memory", sprint_hex(tt_message, tt_msg_resp_len));
        }
    }

    //The NTAG213TT only returns meaningful information for the fields below if the tamper feature is enabled
    if ((tagtype & NTAG_213_TT) && tt_enabled) {

        uint8_t tt_status_len = ntagtt_getTamperStatus(tt_status_resp, 5);

        if (tt_status_len != 5) {
            PrintAndLogEx(WARNING, "Error sending the READ_TT_STATUS command to tag\n");
            return PM3_ESOFT;
        }

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "--- " _CYAN_("Tamper Status"));
        PrintAndLogEx(INFO, "  READ_TT_STATUS: %s", sprint_hex(tt_status_resp, 5));

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

static int ulev1_print_signature(TagTypeUL_t tagtype, uint8_t *uid, uint8_t *signature, size_t signature_len) {

#define PUBLIC_ECDA_KEYLEN 33
    // known public keys for the originality check (source: https://github.com/alexbatalov/node-nxp-originality-verifier)
    // ref: AN11350 NTAG 21x Originality Signature Validation
    // ref: AN11341 MIFARE Ultralight EV1 Originality Signature Validation
    const ecdsa_publickey_t nxp_mfu_public_keys[] = {
        {"NXP MIFARE Classic MFC1C14_x",          "044F6D3F294DEA5737F0F46FFEE88A356EED95695DD7E0C27A591E6F6F65962BAF"},
        {"Manufacturer MIFARE Classic MFC1C14_x", "046F70AC557F5461CE5052C8E4A7838C11C7A236797E8A0730A101837C004039C2"},
        {"NXP ICODE DNA, ICODE SLIX2",            "048878A2A2D3EEC336B4F261A082BD71F9BE11C4E2E896648B32EFA59CEA6E59F0"},
        {"NXP Public key",                        "04A748B6A632FBEE2C0897702B33BEA1C074998E17B84ACA04FF267E5D2C91F6DC"},
        {"NXP Ultralight Ev1",                    "0490933BDCD6E99B4E255E3DA55389A827564E11718E017292FAF23226A96614B8"},
        {"NXP NTAG21x (2013)",                    "04494E1A386D3D3CFE3DC10E5DE68A499B1C202DB5B132393E89ED19FE5BE8BC61"},
        {"MIKRON Public key",                     "04f971eda742a4a80d32dcf6a814a707cc3dc396d35902f72929fdcd698b3468f2"},
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
    for (i = 0; i < ARRAYLEN(nxp_mfu_public_keys); i++) {

        int dl = 0;
        uint8_t key[PUBLIC_ECDA_KEYLEN] = {0};
        param_gethex_to_eol(nxp_mfu_public_keys[i].value, 0, key, PUBLIC_ECDA_KEYLEN, &dl);

        int res = ecdsa_signature_r_s_verify(MBEDTLS_ECP_DP_SECP128R1, key, uid, 7, signature, signature_len, false);

        is_valid = (res == 0);
        if (is_valid)
            break;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Signature"));
    if (is_valid == false || i == ARRAYLEN(nxp_mfu_public_keys)) {
        PrintAndLogEx(INFO, "    Elliptic curve parameters: NID_secp128r1");
        PrintAndLogEx(INFO, "             TAG IC Signature: %s", sprint_hex_inrow(signature, signature_len));
        PrintAndLogEx(SUCCESS, "       Signature verification ( " _RED_("fail") " )");
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, " IC signature public key name: " _GREEN_("%s"), nxp_mfu_public_keys[i].desc);
    PrintAndLogEx(INFO, "IC signature public key value: %s", nxp_mfu_public_keys[i].value);
    PrintAndLogEx(INFO, "    Elliptic curve parameters: NID_secp128r1");
    PrintAndLogEx(INFO, "             TAG IC Signature: %s", sprint_hex_inrow(signature, signature_len));
    PrintAndLogEx(SUCCESS, "       Signature verification ( " _GREEN_("successful") " )");
    return PM3_SUCCESS;
}

static int ulev1_print_version(uint8_t *data) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Version"));
    PrintAndLogEx(INFO, "       Raw bytes: %s", sprint_hex(data, 8));
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
        return UL_ERROR;
    }
    int status = ulc_requestAuthentication(nonce1, sizeof(nonce1));
    if ( status > 0 ) {
        status = ulc_requestAuthentication(nonce2, sizeof(nonce2));
        returnValue =  ( !memcmp(nonce1, nonce2, 11) ) ? UL_C_MAGIC : UL_C;
    } else {
        returnValue = UL;
    }
    DropField();
    return returnValue;
}
*/
static int ul_magic_test(void) {
    // Magic Ultralight tests
    // 1) take present UID, and try to write it back. OBSOLETE
    // 2) make a wrong length write to page0, and see if tag answers with ACK/NACK:

    iso14a_card_select_t card;
    if (ul_select(&card) == false)
        return UL_ERROR;

    int status = ul_comp_write(0, NULL, 0);
    DropField();
    if (status == 0)
        return MAGIC;

    // check for GEN1A, GEN1B and NTAG21x
    uint8_t is_generation = 0;
    PacketResponseNG resp;
    clearCommandBuffer();
    uint8_t payload[] = { 0 };
    SendCommandNG(CMD_HF_MIFARE_CIDENT, payload, sizeof(payload));
    if (WaitForResponseTimeout(CMD_HF_MIFARE_CIDENT, &resp, 1500)) {
        if (resp.status == PM3_SUCCESS)
            is_generation = resp.data.asBytes[0];
    }
    switch (is_generation) {
        case MAGIC_GEN_1A:
            return MAGIC_1A;
        case MAGIC_GEN_1B:
            return MAGIC_1B;
        case MAGIC_NTAG21X:
            return MAGIC_NTAG;
        default:
            break;
    }
    return 0;
}

static char *GenerateFilename(const char *prefix, const char *suffix) {
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

//------------------------------------
/*
static int mfu_decrypt_amiibo(uint8_t *encrypted, uint16_t elen, uint8_t *decrypted, uint16_t *dlen) {

    if (elen < NFC3D_AMIIBO_SIZE / 4) {
        PrintAndLogEx(ERR, "ERR,  data wrong length, got %zu , expected %zu", elen,  (NFC3D_AMIIBO_SIZE / 4));
        return PM3_ESOFT;
    }

    nfc3d_amiibo_keys amiibo_keys = {0};
    if (nfc3d_amiibo_load_keys(&amiibo_keys) == false) {
        return PM3_ESOFT;
    }

    if (nfc3d_amiibo_unpack(&amiibo_keys, encrypted, decrypted) == false) {
        PrintAndLogEx(ERR, "WARNING, Tag signature was NOT valid");
    }

    *dlen = NFC3D_AMIIBO_SIZE;
    return PM3_SUCCESS;
}
static int mfu_dump_tag(uint16_t pages, void **pdata, uint16_t *len) {

    int res = PM3_SUCCESS;
    uint16_t maxbytes = (pages * 4);

    *pdata = calloc(maxbytes, sizeof(uint8_t));
    if (*pdata == NULL) {
        PrintAndLogEx(FAILED, "error, cannot allocate memory");
        res = PM3_EMALLOC;
        goto out;
    }

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_MIFAREU_READCARD, 0, pages, 0, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 2500) == false) {
        PrintAndLogEx(WARNING, "Command execute time-out");
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

    if (!GetFromDevice(BIG_BUF, *pdata, buffer_size, startindex, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "command execution time out");
        free(*pdata);
        res = PM3_ETIMEOUT;
        goto out;
    }

    if (len)
        *len = buffer_size;

out:
    return res;
}
*/
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
    { "SALTO tag", 12, 4, "534C544F", ul_c_otpgenA, NULL },
//    { "SAFLOK tag", 12, 4, NULL, ul_c_otpgenB, NULL },
//    { "VINGCARD tag", 12, 4, NULL, ul_c_otpgenC, NULL },
//    { "DORMA KABA tag", 12, 4, NULL, ul_c_otpgenD, NULL },
    { NULL, 0, 0, NULL, NULL, NULL }
};

static mfu_otp_identify_t *mfu_match_otp_fingerprint(uint8_t *data) {
    uint8_t i = 0;
    do {
        int ml = 0;
        uint8_t mtmp[40] = {0};

        // static or dynamic created OTP to fingerprint.
        if (mfu_otp_ident_table[i].match) {
            param_gethex_to_eol(mfu_otp_ident_table[i].match, 0, mtmp, sizeof(mtmp), &ml);
        } else {
            uint32_t otp = mfu_otp_ident_table[i].otp(data);
            num_to_bytes(otp, 4, mtmp);
        }

        bool m2 = (memcmp(mtmp, data + mfu_otp_ident_table[i].mpos, mfu_otp_ident_table[i].mlen) == 0);
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
    {NULL, NULL, 0, 0, NULL, NULL, NULL, NULL}
};

static mfu_identify_t *mfu_match_fingerprint(uint8_t *version, uint8_t *data) {
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
    if (ul_select(&card) == false)
        return PM3_ESOFT;

    uint8_t v[10] = {0x00};
    int len  = ulev1_getVersion(v, sizeof(v));
    DropField();
    if (len != sizeof(v))
        return PM3_ESOFT;

    memcpy(version, v, 8);
    memcpy(uid, card.uid, 7);
    return PM3_SUCCESS;
}

static int mfu_fingerprint(TagTypeUL_t tagtype, bool hasAuthKey, uint8_t *authkey, int ak_len) {

    uint8_t *data = NULL;
    int res = PM3_SUCCESS;
    PrintAndLogEx(INFO, "------------------------ " _CYAN_("Fingerprint") " -----------------------");
    uint8_t maxbytes = mfu_max_len();
    if (maxbytes == 0) {
        PrintAndLogEx(ERR, "fingerprint table wrong");
        res = PM3_ESOFT;
        goto out;
    }

    maxbytes = ((maxbytes / 4) + 1) * 4;
    data = calloc(maxbytes, sizeof(uint8_t));
    if (data == NULL) {
        PrintAndLogEx(ERR, "failed to allocate memory");
        res = PM3_EMALLOC;
        goto out;
    }

    uint8_t pages = (maxbytes / 4);
    PrintAndLogEx(INFO, "Reading tag memory...");

    uint8_t keytype = 0;
    if (hasAuthKey) {
        if (tagtype & UL_C)
            keytype = 1; //UL_C auth
        else
            keytype = 2; //UL_EV1/NTAG auth
    }
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_MIFAREU_READCARD, 0, pages, keytype, authkey, ak_len);

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
        PrintAndLogEx(WARNING, "Command execute time-out");
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

    if (!GetFromDevice(BIG_BUF, data, buffer_size, startindex, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "command execution time out");
        res = PM3_ETIMEOUT;
        goto out;
    }

    uint8_t version[8] = {0};
    uint8_t uid[7] = {0};
    if (mfu_get_version_uid(version, uid) == PM3_SUCCESS) {
        mfu_identify_t *item = mfu_match_fingerprint(version, data);
        if (item) {
            PrintAndLogEx(SUCCESS, "Found " _GREEN_("%s"), item->desc);

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
    mfu_otp_identify_t *item = mfu_match_otp_fingerprint(data);
    if (item) {
        PrintAndLogEx(SUCCESS, "Found " _GREEN_("%s"), item->desc);

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
    //



out:
    free(data);
    PrintAndLogEx(INFO, "------------------------------------------------------------");
    return res;
}

uint32_t GetHF14AMfU_Type(void) {

    TagTypeUL_t tagtype = UNKNOWN;
    iso14a_card_select_t card;

    if (ul_select(&card) == false)
        return UL_ERROR;

    // Ultralight - ATQA / SAK
    if (card.atqa[1] != 0x00 || card.atqa[0] != 0x44 || card.sak != 0x00) {
        //PrintAndLogEx(NORMAL, "Tag is not Ultralight | NTAG | MY-D  [ATQA: %02X %02X SAK: %02X]\n", card.atqa[1], card.atqa[0], card.sak);
        DropField();
        return UL_ERROR;
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
                Micron UL 0034210101000E03
                Feiju NTAG 0053040201000F03
                */

                if (memcmp(version, "\x00\x04\x03\x01\x01\x00\x0B", 7) == 0)      { tagtype = UL_EV1_48; break; }
                else if (memcmp(version, "\x00\x04\x03\x01\x02\x00\x0B", 7) == 0) { tagtype = UL_NANO_40; break; }
                else if (memcmp(version, "\x00\x04\x03\x02\x01\x00\x0B", 7) == 0) { tagtype = UL_EV1_48; break; }
                else if (memcmp(version, "\x00\x04\x03\x01\x01\x00\x0E", 7) == 0) { tagtype = UL_EV1_128; break; }
                else if (memcmp(version, "\x00\x04\x03\x02\x01\x00\x0E", 7) == 0) { tagtype = UL_EV1_128; break; }
                else if (memcmp(version, "\x00\x34\x21\x01\x01\x00\x0E", 7) == 0) { tagtype = UL_EV1_128; break; } // Mikron JSC Russia EV1 41 pages tag
                else if (memcmp(version, "\x00\x04\x04\x01\x01\x00\x0B", 7) == 0) { tagtype = NTAG_210; break; }
                else if (memcmp(version, "\x00\x04\x04\x01\x02\x00\x0B", 7) == 0) { tagtype = NTAG_210u; break; }
                else if (memcmp(version, "\x00\x04\x04\x02\x02\x00\x0B", 7) == 0) { tagtype = NTAG_210u; break; }
                else if (memcmp(version, "\x00\x04\x04\x01\x01\x00\x0E", 7) == 0) { tagtype = NTAG_212; break; }
                else if (memcmp(version, "\x00\x04\x04\x02\x01\x00\x0F", 7) == 0) { tagtype = NTAG_213; break; }
                else if (memcmp(version, "\x00\x53\x04\x02\x01\x00\x0F", 7) == 0) { tagtype = NTAG_213; break; } //Shanghai Feiju Microelectronics Co. Ltd. China (Xiaomi Air Purifier filter)
                else if (memcmp(version, "\x00\x04\x04\x02\x01\x01\x0F", 7) == 0) { tagtype = NTAG_213_C; break; }
                else if (memcmp(version, "\x00\x04\x04\x02\x01\x00\x11", 7) == 0) { tagtype = NTAG_215; break; }
                else if (memcmp(version, "\x00\x04\x04\x02\x01\x00\x13", 7) == 0) { tagtype = NTAG_216; break; }
                else if (memcmp(version, "\x00\x04\x04\x04\x01\x00\x0F", 7) == 0) { tagtype = NTAG_213_F; break; }
                else if (memcmp(version, "\x00\x04\x04\x04\x01\x00\x13", 7) == 0) { tagtype = NTAG_216_F; break; }
                else if (memcmp(version, "\x00\x04\x04\x02\x03\x00\x0F", 7) == 0) { tagtype = NTAG_213_TT; break; }
                else if (memcmp(version, "\x00\x04\x04\x05\x02\x01\x13", 7) == 0) { tagtype = NTAG_I2C_1K; break; }
                else if (memcmp(version, "\x00\x04\x04\x05\x02\x01\x15", 7) == 0) { tagtype = NTAG_I2C_2K; break; }
                else if (memcmp(version, "\x00\x04\x04\x05\x02\x02\x13", 7) == 0) { tagtype = NTAG_I2C_1K_PLUS; break; }
                else if (memcmp(version, "\x00\x04\x04\x05\x02\x02\x15", 7) == 0) { tagtype = NTAG_I2C_2K_PLUS; break; }
                else if (version[2] == 0x04) { tagtype = NTAG; break; }
                else if (version[2] == 0x03) { tagtype = UL_EV1; }
                break;
            }
            case 0x01:
                tagtype = UL_C;
                break;
            case 0x00:
                tagtype = UL;
                break;
            case -1  :
                tagtype = (UL | UL_C | NTAG_203);
                break;  // could be UL | UL_C magic tags
            default  :
                tagtype = UNKNOWN;
                break;
        }

        // UL vs UL-C vs ntag203 test
        if (tagtype & (UL | UL_C | NTAG_203)) {
            if (!ul_select(&card)) return UL_ERROR;

            // do UL_C check first...
            uint8_t nonce[11] = {0x00};
            int status = ulc_requestAuthentication(nonce, sizeof(nonce));
            DropField();
            if (status > 1) {
                tagtype = UL_C;
            } else {
                // need to re-select after authentication error
                if (ul_select(&card) == false)
                    return UL_ERROR;

                uint8_t data[16] = {0x00};
                // read page 0x26-0x29 (last valid ntag203 page)
                status = ul_read(0x26, data, sizeof(data));
                if (status <= 1) {
                    tagtype = UL;
                } else {
                    // read page 0x30 (should error if it is a ntag203)
                    status = ul_read(0x30, data, sizeof(data));
                    if (status <= 1) {
                        tagtype = NTAG_203;
                    } else {
                        tagtype = UNKNOWN;
                    }
                }
                DropField();
            }
        }
        if (tagtype & UL) {
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
                tagtype =  MY_D;
                break; // or SLE 66RxxS ... up to 512 pages of 8 user bytes...
            case 2:
                tagtype = (MY_D_NFC);
                break; // or SLE 66RxxP ... up to 512 pages of 8 user bytes... (or in nfc mode FF pages of 4 bytes)
            case 3:
                tagtype = (MY_D_MOVE | MY_D_MOVE_NFC);
                break; // or SLE 66R01P // 38 pages of 4 bytes //notice: we can not currently distinguish between these two
            case 7:
                tagtype =  MY_D_MOVE_LEAN;
                break; // or SLE 66R01L  // 16 pages of 4 bytes
        }
    }

    tagtype |= ul_magic_test();
    if (tagtype == (UNKNOWN | MAGIC)) {
        tagtype = (UL_MAGIC);
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
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int ak_len = 0;
    uint8_t authenticationkey[16] = {0x00};
    CLIGetHexWithReturn(ctx, 1, authenticationkey, &ak_len);
    bool swap_endian = arg_get_lit(ctx, 2);
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

    TagTypeUL_t tagtype = GetHF14AMfU_Type();
    if (tagtype == UL_ERROR)
        return PM3_ESOFT;

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
    // read pages 0,1,2,3 (should read 4pages)
    status = ul_read(0, data, sizeof(data));
    if (status == -1) {
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
    if ((tagtype & UL_C)) {

        // read pages 0x28, 0x29, 0x2A, 0x2B
        uint8_t ulc_conf[16] = {0x00};
        status = ul_read(0x28, ulc_conf, sizeof(ulc_conf));
        if (status == -1) {
            PrintAndLogEx(ERR, "Error: tag didn't answer to READ UL-C");
            DropField();
            return PM3_ESOFT;
        }
        if (status == 16)
            ulc_print_configuration(ulc_conf);
        else
            locked = true;

        mfu_fingerprint(tagtype, has_auth_key, authkeyptr, ak_len);

        if ((tagtype & MAGIC)) {
            //just read key
            uint8_t ulc_deskey[16] = {0x00};
            status = ul_read(0x2C, ulc_deskey, sizeof(ulc_deskey));
            if (status == -1) {
                DropField();
                PrintAndLogEx(ERR, "Error: tag didn't answer to READ magic");
                return PM3_ESOFT;
            }
            if (status == 16) {
                ulc_print_3deskey(ulc_deskey);
            }

        } else {
            DropField();
            // if we called info with key, just return
            if (has_auth_key) {
                return PM3_SUCCESS;
            }

            // also try to diversify default keys..  look into CmdHF14AMfGenDiverseKeys
            if (try_default_3des_keys(&key) == PM3_SUCCESS) {
                PrintAndLogEx(SUCCESS, "Found default 3des key: ");
                uint8_t keySwap[16];
                memcpy(keySwap, SwapEndian64(key, 16, 8), 16);
                ulc_print_3deskey(keySwap);
            }
            return PM3_SUCCESS;
        }
    }

    // do counters and signature first (don't neet auth)

    // ul counters are different than ntag counters
    if ((tagtype & (UL_EV1_48 | UL_EV1_128 | UL_EV1))) {
        if (ulev1_print_counters() != 3) {
            // failed - re-select
            if (ul_auth_select(&card, tagtype, has_auth_key, authkeyptr, pack, sizeof(pack)) == PM3_ESOFT) {
                return PM3_ESOFT;
            }
        }
    }

    // NTAG counters?
    if ((tagtype & (NTAG_213 | NTAG_213_F | NTAG_213_C | NTAG_213_TT | NTAG_215 | NTAG_216))) {
        if (ntag_print_counter()) {
            // failed - re-select
            if (ul_auth_select(&card, tagtype, has_auth_key, authkeyptr, pack, sizeof(pack)) == PM3_ESOFT) {
                return PM3_ESOFT;
            }
        }
    }

    // Read signature
    if ((tagtype & (UL_EV1_48 | UL_EV1_128 | UL_EV1 | UL_NANO_40 | NTAG_210u | NTAG_213 | NTAG_213_F | NTAG_213_C | NTAG_213_TT | NTAG_215 | NTAG_216 | NTAG_216_F | NTAG_I2C_1K | NTAG_I2C_2K | NTAG_I2C_1K_PLUS | NTAG_I2C_2K_PLUS))) {
        uint8_t ulev1_signature[32] = {0x00};
        status = ulev1_readSignature(ulev1_signature, sizeof(ulev1_signature));
        if (status == -1) {
            PrintAndLogEx(ERR, "Error: tag didn't answer to READ SIGNATURE");
            DropField();
            return PM3_ESOFT;
        }
        if (status == 32) {
            ulev1_print_signature(tagtype, card.uid, ulev1_signature, sizeof(ulev1_signature));
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
        if (status == -1) {
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

        uint8_t startconfigblock = 0;
        uint8_t ulev1_conf[16] = {0x00};

        for (uint8_t i = 0; i < ARRAYLEN(UL_TYPES_ARRAY); i++) {
            if (tagtype & UL_TYPES_ARRAY[i]) {
                startconfigblock = UL_MEMORY_ARRAY[i] - 3;
                break;
            }
        }

        if (startconfigblock) { // if we know where the config block is...
            status = ul_read(startconfigblock, ulev1_conf, sizeof(ulev1_conf));
            if (status == -1) {
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
        if (!authlim && !has_auth_key) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(SUCCESS, "--- " _CYAN_("Known EV1/NTAG passwords"));
            // test pwd gen A
            num_to_bytes(ul_ev1_pwdgenA(card.uid), 4, key);
            len = ulev1_requestAuthentication(key, pack, sizeof(pack));
            if (len > -1) {
                PrintAndLogEx(SUCCESS, "Found default password " _GREEN_("%s") " pack %02X %02X", sprint_hex(key, 4), pack[0], pack[1]);
                goto out;
            }

            if (ul_auth_select(&card, tagtype, has_auth_key, authkeyptr, pack, sizeof(pack)) == PM3_ESOFT) {
                return PM3_ESOFT;
            }

            // test pwd gen B
            num_to_bytes(ul_ev1_pwdgenB(card.uid), 4, key);
            len = ulev1_requestAuthentication(key, pack, sizeof(pack));
            if (len > -1) {
                PrintAndLogEx(SUCCESS, "Found default password " _GREEN_("%s") " pack %02X %02X", sprint_hex(key, 4), pack[0], pack[1]);
                goto out;
            }

            if (ul_auth_select(&card, tagtype, has_auth_key, authkeyptr, pack, sizeof(pack)) == PM3_ESOFT) {
                return PM3_ESOFT;
            }

            // test pwd gen C
            num_to_bytes(ul_ev1_pwdgenC(card.uid), 4, key);
            len = ulev1_requestAuthentication(key, pack, sizeof(pack));
            if (len > -1) {
                PrintAndLogEx(SUCCESS, "Found default password " _GREEN_("%s") " pack %02X %02X", sprint_hex(key, 4), pack[0], pack[1]);
                goto out;
            }

            if (ul_auth_select(&card, tagtype, has_auth_key, authkeyptr, pack, sizeof(pack)) == PM3_ESOFT) {
                return PM3_ESOFT;
            }

            // test pwd gen D
            num_to_bytes(ul_ev1_pwdgenD(card.uid), 4, key);
            len = ulev1_requestAuthentication(key, pack, sizeof(pack));
            if (len > -1) {
                PrintAndLogEx(SUCCESS, "Found default password" _GREEN_("%s") " pack %02X %02X", sprint_hex(key, 4), pack[0], pack[1]);
                goto out;
            }

            if (ul_auth_select(&card, tagtype, has_auth_key, authkeyptr, pack, sizeof(pack)) == PM3_ESOFT) {
                return PM3_ESOFT;
            }

            for (uint8_t i = 0; i < ARRAYLEN(default_pwd_pack); ++i) {
                key = default_pwd_pack[i];
                len = ulev1_requestAuthentication(key, pack, sizeof(pack));
                if (len > -1) {
                    PrintAndLogEx(SUCCESS, "Found default password " _GREEN_("%s") " pack %02X %02X", sprint_hex(key, 4), pack[0], pack[1]);
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
            PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`hf mfu pwdgen -r`") " to get see known pwd gen algo suggestions");
        }
    }

    mfu_fingerprint(tagtype, has_auth_key, authkeyptr, ak_len);

out:
    DropField();
    if (locked) {
        PrintAndLogEx(INFO, "\nTag appears to be locked, try using a key to get more info");
        PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`hf mfu pwdgen -r`") " to get see known pwd gen algo suggestions");
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

    uint8_t *authKeyPtr = authenticationkey;

    // starting with getting tagtype
    TagTypeUL_t tagtype = GetHF14AMfU_Type();
    if (tagtype == UL_ERROR)
        return PM3_ESOFT;

    uint8_t maxblockno = 0;
    for (uint8_t idx = 0; idx < ARRAYLEN(UL_TYPES_ARRAY); idx++) {
        if (tagtype & UL_TYPES_ARRAY[idx]) {
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
            authKeyPtr = SwapEndian64(authenticationkey, 16, 8);

        if (has_pwd)
            authKeyPtr = SwapEndian64(authenticationkey, 4, 4);
    }

    if (blockno <= 3)
        PrintAndLogEx(INFO, "Special block: %0d (0x%02X) [ %s]", blockno, blockno, sprint_hex(data, datalen));
    else
        PrintAndLogEx(INFO, "Block: %0d (0x%02X) [ %s]", blockno, blockno, sprint_hex(data, datalen));

    if (ak_len) {
        PrintAndLogEx(INFO, "Using %s " _GREEN_("%s"), (ak_len == 16) ? "3des" : "pwd", sprint_hex(authenticationkey, ak_len));
    }

    //Send write Block

    // 4 or 16.
    uint8_t cmddata[32];
    memcpy(cmddata, data, datalen);

    // 0 - no pwd/key, no authentication
    // 1 - 3des key (16 bytes)
    // 2 - pwd  (4 bytes)
    uint8_t keytype = 0;
    size_t cmdlen = datalen;
    if (has_auth_key) {
        keytype = 1;
        memcpy(cmddata + datalen, authKeyPtr, 16);
        cmdlen += 16;
    } else if (has_pwd) {
        keytype = 2;
        memcpy(cmddata + datalen, authKeyPtr, 4);
        cmdlen += 4;
    }

    clearCommandBuffer();
    if (datalen == 16) {
        SendCommandMIX(CMD_HF_MIFAREU_WRITEBL_COMPAT, blockno, keytype, 0, cmddata, cmdlen);
    } else {
        SendCommandMIX(CMD_HF_MIFAREU_WRITEBL, blockno, keytype, 0, cmddata, cmdlen);
    }
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        uint8_t isOK  = resp.oldarg[0] & 0xff;
        PrintAndLogEx(SUCCESS, "isOk:%02x", isOK);
    } else {
        PrintAndLogEx(WARNING, "Command execute timeout");
    }

    return PM3_SUCCESS;
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
        arg_int1("b", "block", "<dec>", "Nlock number to read"),
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
    TagTypeUL_t tagtype = GetHF14AMfU_Type();
    if (tagtype == UL_ERROR)
        return PM3_ESOFT;

    uint8_t maxblockno = 0;
    for (uint8_t idx = 0; idx < ARRAYLEN(UL_TYPES_ARRAY); idx++) {
        if (tagtype & UL_TYPES_ARRAY[idx]) {
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
        PrintAndLogEx(WARNING, "Command execute time-out");
    }
    return PM3_SUCCESS;
}

void printMFUdumpEx(mfu_dump_t *card, uint16_t pages, uint8_t startpage) {

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

    PrintAndLogEx(INFO, "Max data page... " _YELLOW_("%d") " ( " _YELLOW_("%d") " bytes )", card->pages - 1, card->pages * 4);
    PrintAndLogEx(INFO, "Header size..... %d bytes", MFU_DUMP_PREFIX_LENGTH);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    PrintAndLogEx(INFO, "block#   | data        |lck| ascii");
    PrintAndLogEx(INFO, "---------+-------------+---+------");

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
        PrintAndLogEx(INFO, "DYNAMIC LOCK: %s", sprint_hex(lockbytes_dyn, 3));
    }

    for (uint16_t i = 0; i < pages; ++i) {
        if (i < 3) {
            PrintAndLogEx(INFO, "%3d/0x%02X | %s|   | %s", i + startpage, i + startpage, sprint_hex(data + i * 4, 4), sprint_ascii(data + i * 4, 4));
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
        PrintAndLogEx(INFO, "%3d/0x%02X | %s| %s | %s", i + startpage, i + startpage, sprint_hex(data + i * 4, 4), (lckbit) ? _RED_("1") : "0", sprint_ascii(data + i * 4, 4));
    }
    PrintAndLogEx(INFO, "---------------------------------");
}

//
//  Mifare Ultralight / Ultralight-C / Ultralight-EV1
//  Read and Dump Card Contents,  using auto detection of tag size.
static int CmdHF14AMfUDump(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu dump",
                  "Dump MIFARE Ultralight/NTAG tag to binary/eml/json files.\n"
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
    if (start_page > 0)
        manual_pages = true;

    if (pages != 16)
        manual_pages = true;

    uint8_t card_mem_size = 0;

    // Swap endianness
    if (swap_endian) {
        if (has_auth_key)
            authKeyPtr = SwapEndian64(authenticationkey, ak_len, 8);

        if (has_pwd)
            authKeyPtr = SwapEndian64(authenticationkey, ak_len, 4);
    }

    TagTypeUL_t tagtype = GetHF14AMfU_Type();
    if (tagtype == UL_ERROR)
        return PM3_ESOFT;

    //get number of pages to read
    if (manual_pages == false) {
        for (uint8_t idx = 0; idx < ARRAYLEN(UL_TYPES_ARRAY); idx++) {
            if (tagtype & UL_TYPES_ARRAY[idx]) {
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
        if (tagtype & UL_C)
            keytype = 1; //UL_C auth
        else
            keytype = 2; //UL_EV1/NTAG auth
    }

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_MIFAREU_READCARD, start_page, pages, keytype, authKeyPtr, ak_len);

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
        PrintAndLogEx(WARNING, "Command execute time-out");
        return PM3_ETIMEOUT;
    }

    if (resp.oldarg[0] != 1) {
        PrintAndLogEx(WARNING, "Failed dumping card");
        return PM3_ESOFT;
    }

    // read all memory
    uint8_t data[1024] = {0x00};
    memset(data, 0x00, sizeof(data));

    uint32_t startindex = resp.oldarg[2];
    uint32_t buffer_size = resp.oldarg[1];
    if (buffer_size > sizeof(data)) {
        PrintAndLogEx(FAILED, "Data exceeded Buffer size!");
        buffer_size = sizeof(data);
    }

    if (!GetFromDevice(BIG_BUF, data, buffer_size, startindex, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    bool is_partial = (pages != buffer_size / 4);

    pages = buffer_size / 4;

    iso14a_card_select_t card;
    mfu_dump_t dump_file_data;
    memset(&dump_file_data, 0, sizeof(dump_file_data));
    uint8_t get_version[] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t get_counter_tearing[][4] = {{0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}};
    uint8_t get_signature[32];
    memset(get_signature, 0, sizeof(get_signature));

    // not ul_c and not std ul then attempt to collect info like
    //  VERSION, SIGNATURE, COUNTERS, TEARING, PACK,
    if (!(tagtype & UL_C || tagtype & UL || tagtype & MY_D_MOVE || tagtype & MY_D_MOVE_LEAN)) {
        //attempt to read pack
        uint8_t get_pack[] = {0, 0};
        if (ul_auth_select(&card, tagtype, true, authKeyPtr, get_pack, sizeof(get_pack)) != PM3_SUCCESS) {
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
        if ((tagtype & (NTAG_213 | NTAG_213_F | NTAG_213_C | NTAG_213_TT | NTAG_215 | NTAG_216))) {
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
        } else
            ul_select(&card);

        ulev1_readSignature(get_signature, sizeof(get_signature));
        DropField();
    }

    // format and add keys to block dump output
    // only add keys if not partial read, and complete pages read
    if (!is_partial && pages == card_mem_size && (has_auth_key || has_pwd)) {
        // if we didn't swapendian before - do it now for the sprint_hex call
        // NOTE: default entry is bigendian (unless swapped), sprint_hex outputs little endian
        //       need to swap to keep it the same
        if (swap_endian == false) {
            authKeyPtr = SwapEndian64(authenticationkey, ak_len, (ak_len == 16) ? 8 : 4);
        } else {
            authKeyPtr = authenticationkey;
        }

        if (tagtype & UL_C) { //add 4 pages
            memcpy(data + pages * 4, authKeyPtr, ak_len);
            pages += ak_len / 4;
        } else { // 2nd page from end
            memcpy(data + (pages * 4) - 8, authenticationkey, ak_len);
        }
    }

    //add *special* blocks to dump
    // pack and pwd saved into last pages of dump, if was not partial read
    dump_file_data.pages = pages - 1;
    memcpy(dump_file_data.version, get_version, sizeof(dump_file_data.version));
    memcpy(dump_file_data.signature, get_signature, sizeof(dump_file_data.signature));
    memcpy(dump_file_data.counter_tearing, get_counter_tearing, sizeof(dump_file_data.counter_tearing));
    memcpy(dump_file_data.data, data, pages * 4);

    printMFUdumpEx(&dump_file_data, pages, start_page);

    if (nosave == false) {
        // user supplied filename?
        if (fnlen < 1) {
            PrintAndLogEx(INFO, "Using UID as filename");
            uint8_t uid[7] = {0};
            memcpy(uid, (uint8_t *)&dump_file_data.data, 3);
            memcpy(uid + 3, (uint8_t *)&dump_file_data.data + 4, 4);
            strcat(filename, "hf-mfu-");
            FillFileNameByUID(filename, uid, "-dump", sizeof(uid));
        }

        uint16_t datalen = pages * MFU_BLOCK_SIZE + MFU_DUMP_PREFIX_LENGTH;
        pm3_save_dump(filename, (uint8_t *)&dump_file_data, datalen, jsfMfuMemory, MFU_BLOCK_SIZE);

        if (is_partial) {
            PrintAndLogEx(WARNING, "Partial dump created. (%d of %d blocks)", pages, card_mem_size);
        }
    }

    return PM3_SUCCESS;
}

static void wait4response(uint8_t b) {
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        uint8_t isOK  = resp.oldarg[0] & 0xff;
        if (!isOK)
            PrintAndLogEx(WARNING, "failed to write block %d", b);
    } else {
        PrintAndLogEx(WARNING, "Command execute timeout");
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

    TagTypeUL_t tagtype = GetHF14AMfU_Type();
    if (tagtype == UL_ERROR) {
        PrintAndLogEx(WARNING, "Tag type not detected");
        DropField();
        return PM3_ESOFT;
    }
    if (tagtype != NTAG_213_TT) {
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
            return UL_ERROR;
        }
        PrintAndLogEx(INFO, "Trying to write tamper message\n");
        SendCommandMIX(CMD_HF_MIFAREU_WRITEBL, tt_msg_page, 0, 0, msg_data, 4);

        PacketResponseNG resp;

        if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
            uint8_t isOK  = resp.oldarg[0] & 0xff;
            if (!isOK)
                PrintAndLogEx(WARNING, "Failed to write tamper message");
            else
                PrintAndLogEx(SUCCESS, "Tamper message written successfully");
        } else {
            PrintAndLogEx(WARNING, "Command execute timeout");
        }
    }

    if (enable | disable | lock_msg) {

        if (ul_select(&card) == false) {
            PrintAndLogEx(ERR, "Unable to select tag");
            DropField();
            return UL_ERROR;
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
            PrintAndLogEx(WARNING, "Command execute timeout");
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
                  "Restore MIFARE Ultralight/NTAG dump file to tag.\n",
                  "hf mfu restore -f myfile -s                 -> special write\n"
                  "hf mfu restore -f myfile -k AABBCCDD -s     -> special write, use key\n"
                  "hf mfu restore -f myfile -k AABBCCDD -ser   -> special write, use key, write dump pwd, ..."
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "specify dump filename (bin/eml/json)"),
        arg_str0("k", "key", "<hex>", "key for authentication (UL-C 16 bytes, EV1/NTAG 4 bytes)"),
        arg_lit0("l", NULL, "swap entered key's endianness"),
        arg_lit0("s", NULL, "enable special write UID -MAGIC TAG ONLY-"),
        arg_lit0("e", NULL, "enable special write version/signature -MAGIC NTAG 21* ONLY-"),
        arg_lit0("r", NULL, "use password found in dumpfile to configure tag. Requires " _YELLOW_("'-e'") " parameter to work"),
        arg_lit0("v", "verbose", "verbose"),
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
        char *fptr = GenerateFilename("hf-mfu-", "-dump.bin");
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

    // print dump
    printMFUdumpEx(mem, pages, 0);

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

            PrintAndLogEx(INFO, "special PWD     block written 0x%X - %s\n", MFU_NTAG_SPECIAL_PWD, sprint_hex(data, 4));
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
        PrintAndLogEx(INFO, "special PACK    block written 0x%X - %s\n", MFU_NTAG_SPECIAL_PACK, sprint_hex(data, 4));
        clearCommandBuffer();
        SendCommandMIX(CMD_HF_MIFAREU_WRITEBL, MFU_NTAG_SPECIAL_PACK, keytype, 0, data, sizeof(data));
        wait4response(MFU_NTAG_SPECIAL_PACK);

        // Signature
        for (uint8_t s = MFU_NTAG_SPECIAL_SIGNATURE, i = 0; s < MFU_NTAG_SPECIAL_SIGNATURE + 8; s++, i += 4) {
            memcpy(data, mem->signature + i, 4);
            PrintAndLogEx(INFO, "special SIG     block written 0x%X - %s\n", s, sprint_hex(data, 4));
            clearCommandBuffer();
            SendCommandMIX(CMD_HF_MIFAREU_WRITEBL, s, keytype, 0, data, sizeof(data));
            wait4response(s);
        }

        // Version
        for (uint8_t s = MFU_NTAG_SPECIAL_VERSION, i = 0; s < MFU_NTAG_SPECIAL_VERSION + 2; s++, i += 4) {
            memcpy(data, mem->version + i, 4);
            PrintAndLogEx(INFO, "special VERSION block written 0x%X - %s\n", s, sprint_hex(data, 4));
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

        PrintAndLogEx(INFO, "Restoring configuration blocks.\n");

        PrintAndLogEx(INFO, "authentication with keytype[%x]  %s\n", (uint8_t)(keytype & 0xff), sprint_hex(p_authkey, 4));

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
            PrintAndLogEx(INFO, "special block written %u - %s\n", b, sprint_hex(data, 4));
        }
    }

    DropField();
    free(dump);
    PrintAndLogEx(INFO, "Restore finished");
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
        arg_str1("f", "file", "<fn>", "Filename of dump"),
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
        PrintAndLogEx(WARNING, "ERROR: Key is incorrect length\n");
        return PM3_EINVARG;
    }

    // Swap endianness
    if (swap_endian && ak_len) {
        authKeyPtr = SwapEndian64(authenticationkey, 16, 8);
    }

    bool isok = false;

    // If no hex key is specified, try default keys
    if (ak_len == 0) {
        isok = (try_default_3des_keys(&authKeyPtr) == PM3_SUCCESS);
    } else {
        // try user-supplied
        isok = ulc_authentication(authKeyPtr, !keep_field_on);
    }

    if (isok)
        PrintAndLogEx(SUCCESS, "Authentication success. 3des key: " _GREEN_("%s"), sprint_hex_inrow(authKeyPtr, 16));
    else
        PrintAndLogEx(WARNING, "Authentication ( " _RED_("fail") " )");

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
            PrintAndLogEx(INFO, "Ultralight-C new key: %s", sprint_hex(key, sizeof(key)));
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
        PrintAndLogEx(WARNING, "Command execute timeout");
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
        PrintAndLogEx(WARNING, "Command execute timeout");
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
        PrintAndLogEx(WARNING, "Command execute timeout");
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
        PrintAndLogEx(WARNING, "Command execute timeout");
        return PM3_ETIMEOUT;
    }

    // restore BCC config
    if (oldconfig_bcc != 2) {
        config.forcebcc = oldconfig_bcc;
        SendCommandNG(CMD_HF_ISO14443A_SET_CONFIG, (uint8_t *)&config, sizeof(hf14a_config));
    }
    return PM3_SUCCESS;
}

static int CmdHF14AMfUGenDiverseKeys(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu keygen",
                  "Set the 3DES key on MIFARE Ultralight-C tag. ",
                  "hf mfu keygen -r\n"
                  "hf mfu keygen --uid 11223344556677"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("u", "uid", "<hex>", "<4|7> hex byte UID"),
        arg_lit0("r", NULL, "Read UID from tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int ulen = 0;
    uint8_t uid[7];
    CLIGetHexWithReturn(ctx, 1, uid, &ulen);
    bool read_tag = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    if (read_tag) {
        // read uid from tag
        clearCommandBuffer();
        SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_NO_RATS, 0, 0, NULL, 0);
        PacketResponseNG resp;
        WaitForResponse(CMD_ACK, &resp);
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
    uint8_t block = 0x01;

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
                  "hf mfu pwdgen -t\n"
                  "hf mfu pwdgen --uid 11223344556677"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("u", "uid", "<hex>", "UID (7 hex bytes)"),
        arg_lit0("r", NULL, "Read UID from tag"),
        arg_lit0("t", NULL, "Selftest"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int u_len = 0;
    uint8_t uid[7] = {0x00};
    CLIGetHexWithReturn(ctx, 1, uid, &u_len);
    bool use_tag = arg_get_lit(ctx, 2);
    bool selftest = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (selftest)
        return generator_selftest();

    uint8_t philips_mfg[10] = {0};

    if (use_tag) {
        // read uid from tag
        int res = ul_read_uid(uid);
        if (res != PM3_SUCCESS) {
            return res;
        }

        iso14a_card_select_t card;
        if (ul_select(&card)) {
            // Philips toothbrush needs page 0x21-0x23
            uint8_t data[16] = {0x00};
            int status = ul_read(0x21, data, sizeof(data));
            if (status == -1) {
                PrintAndLogEx(DEBUG, "Error: tag didn't answer to READ");
            } else if (status == 16) {
                memcpy(philips_mfg, data + 2, sizeof(philips_mfg));
            }
            DropField();
        }

    } else {
        if (u_len != 7) {
            PrintAndLogEx(WARNING, "Key must be 7 hex bytes");
            return PM3_EINVARG;
        }
    }

    PrintAndLogEx(INFO, "------------------.------------------");
    PrintAndLogEx(INFO, " Using UID 4b: " _YELLOW_("%s"), sprint_hex(uid, 4));
    PrintAndLogEx(INFO, " Using UID 7b: " _YELLOW_("%s"), sprint_hex(uid, 7));
    PrintAndLogEx(INFO, "-------------------------------------");
    PrintAndLogEx(INFO, " algo               | pwd      | pack");
    PrintAndLogEx(INFO, "--------------------+----------+-----");
    PrintAndLogEx(INFO, " Transport EV1      | %08X | %04X", ul_ev1_pwdgenA(uid), ul_ev1_packgenA(uid));
    PrintAndLogEx(INFO, " Amiibo             | %08X | %04X", ul_ev1_pwdgenB(uid), ul_ev1_packgenB(uid));
    PrintAndLogEx(INFO, " Lego Dimension     | %08X | %04X", ul_ev1_pwdgenC(uid), ul_ev1_packgenC(uid));
    PrintAndLogEx(INFO, " XYZ 3D printer     | %08X | %04X", ul_ev1_pwdgenD(uid), ul_ev1_packgenD(uid));
    PrintAndLogEx(INFO, " Xiaomi purifier    | %08X | %04X", ul_ev1_pwdgenE(uid), ul_ev1_packgenE(uid));
    PrintAndLogEx(INFO, " NTAG tools         | %08X | %04X", ul_ev1_pwdgenF(uid), ul_ev1_packgen_def(uid));
    if (philips_mfg[0] != 0) {
        PrintAndLogEx(INFO, " Philips Toothbrush | %08X | %04X", ul_ev1_pwdgenG(uid, philips_mfg), ul_ev1_packgenG(uid, philips_mfg));
    }
    PrintAndLogEx(INFO, "--------------------+----------+-----");
    PrintAndLogEx(INFO, " Vingcard algo");
    PrintAndLogEx(INFO, " Saflok algo");
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
        arg_litn("v",  "verbose",  0, 2, "show technical data"),
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
    TagTypeUL_t tagtype = GetHF14AMfU_Type();
    if (tagtype == UL_ERROR) {
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
    if (status == -1) {
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
    for (uint8_t i = 0; i < ARRAYLEN(UL_TYPES_ARRAY); i++) {
        if (tagtype & UL_TYPES_ARRAY[i]) {

            if (maxsize != (UL_MEMORY_ARRAY[i] * 4)) {
                PrintAndLogEx(INFO, "Tag reported size vs NDEF reported size mismatch. Using smallest value");
            }
            maxsize = MIN(maxsize, (UL_MEMORY_ARRAY[i] * 4));
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
        if (status == -1) {
            DropField();
            PrintAndLogEx(ERR, "Error: tag didn't answer to READ");
            free(records);
            return PM3_ESOFT;
        }
    }

    DropField();
    if (fnlen != 0) {
        saveFile(filename, ".bin", records, (size_t)maxsize);
    }
    status = NDEFRecordsDecodeAndPrint(records, (size_t)maxsize, verbose);
    if (status != PM3_SUCCESS) {
        status = NDEFDecodeAndPrint(records, (size_t)maxsize, verbose);
    }

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
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int end = arg_get_int_def(ctx, 1, -1);
    CLIParserFree(ctx);

    bool override_end = (end != -1) ;

    if (override_end && (end < 0 || end > MFU_MAX_BLOCKS)) {
        PrintAndLogEx(WARNING, "Invalid value for end:%d. Must be be positive integer < %d.", end, MFU_MAX_BLOCKS);
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
        end = dump->pages ;
    }

    printMFUdumpEx(dump, end, 0);
    free(dump);
    return PM3_SUCCESS;
}

static int CmdHF14AMfuESave(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu esave",
                  "Saves emulator memory to a MIFARE Ultralight/NTAG dump file (bin/eml/json)\n"
                  "By default number of pages saved depends on defined tag type.\n"
                  "You can override this with option --end.",
                  "hf mfu esave\n"
                  "hf mfu esave --end 255 -> saves whole memory\n"
                  "hf mfu esave -f hf-mfu-04010203040506-dump.json"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("e", "end", "<dec>", "index of last block"),
        arg_str0("f", "file", "<fn>", "filename of dump"),
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
    res = pm3_save_dump(filename, (uint8_t *)dump, datalen, jsfMfuMemory, MFU_BLOCK_SIZE);

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
        arg_str1("f", "file", "<fn>", "Filename of dump"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE];
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    bool verbose = arg_get_lit(ctx, 2);
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

    printMFUdumpEx((mfu_dump_t *)dump, block_cnt, 0);
    free(dump);
    return PM3_SUCCESS;
}

static int CmdHF14AMfuList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf 14a", "14a -c");
}


/*
static int CmdHF14AMfUCDecryptAmiibo(const char *Cmd){

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfu decrypt",
                  "Tries to read all memory from amiibo tag and decrypt it",
                  "hf mfu decrypt"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    uint16_t elen = 0, dlen = 0;
    uint8_t *encrypted = NULL;

    int res = mfu_dump_tag( MAX_NTAG_215, (void **)&encrypted, &elen);
    if (res == PM3_SUCCESS) {

        PrintAndLogEx(INFO, "32 first bytes of tag dump");
        PrintAndLogEx(INFO, "%s", sprint_hex(encrypted, 32));
        PrintAndLogEx(INFO, "-----------------------");

        uint8_t decrypted[NFC3D_AMIIBO_SIZE] = {0};
        res = mfu_decrypt_amiibo(encrypted, elen, decrypted, &dlen);
        if ( res == PM3_SUCCESS) {

            for (uint8_t i = 0; i < dlen/16; i++ ) {
                PrintAndLogEx(INFO, "[%d] %s", i, sprint_hex_ascii(decrypted + (i * 16), 16));
            }
        }
        free(encrypted);
    }
    return PM3_SUCCESS;
}
*/

//------------------------------------
// Menu Stuff
//------------------------------------
static command_t CommandTable[] = {
    {"help",     CmdHelp,                   AlwaysAvailable, "This help"},
    {"list",     CmdHF14AMfuList,           AlwaysAvailable, "List MIFARE Ultralight / NTAG history"},
    {"-----------", CmdHelp,                IfPm3Iso14443a,  "----------------------- " _CYAN_("recovery") " -------------------------"},
    {"keygen",   CmdHF14AMfUGenDiverseKeys, AlwaysAvailable, "Generate 3DES MIFARE diversified keys"},
    {"pwdgen",   CmdHF14AMfUPwdGen,         AlwaysAvailable, "Generate pwd from known algos"},
    {"otptear",  CmdHF14AMfuOtpTearoff,     IfPm3Iso14443a,  "Tear-off test on OTP bits"},
//    {"tear_cnt", CmdHF14AMfuEv1CounterTearoff,     IfPm3Iso14443a,  "Tear-off test on Ev1/NTAG Counter bits"},
    {"-----------", CmdHelp,                IfPm3Iso14443a,  "----------------------- " _CYAN_("operations") " -----------------------"},
    {"cauth",    CmdHF14AMfUCAuth,          IfPm3Iso14443a,  "Authentication - Ultralight-C"},
    {"dump",     CmdHF14AMfUDump,           IfPm3Iso14443a,  "Dump MIFARE Ultralight family tag to binary file"},
    {"info",     CmdHF14AMfUInfo,           IfPm3Iso14443a,  "Tag information"},
    {"ndefread", CmdHF14MfuNDEFRead,        IfPm3Iso14443a,  "Prints NDEF records from card"},
    {"rdbl",     CmdHF14AMfURdBl,           IfPm3Iso14443a,  "Read block"},
    {"restore",  CmdHF14AMfURestore,        IfPm3Iso14443a,  "Restore a dump onto a MFU MAGIC tag"},
    {"view",     CmdHF14AMfuView,           AlwaysAvailable, "Display content from tag dump file"},
    {"wrbl",     CmdHF14AMfUWrBl,           IfPm3Iso14443a,  "Write block"},
    {"tamper",   CmdHF14MfUTamper,          IfPm3Iso14443a,  "Configure the tamper feature on an NTAG 213TT"},
    {"---------", CmdHelp,                  IfPm3Iso14443a,  "----------------------- " _CYAN_("simulation") " -----------------------"},
    {"eload",    CmdHF14AMfUeLoad,          IfPm3Iso14443a,  "Load Ultralight dump file into emulator memory"},
    {"esave",    CmdHF14AMfuESave,          IfPm3Iso14443a,  "Save Ultralight dump file from emulator memory"},
    {"eview",    CmdHF14AMfuEView,          IfPm3Iso14443a,  "View emulator memory"},
    {"sim",      CmdHF14AMfUSim,            IfPm3Iso14443a,  "Simulate MIFARE Ultralight from emulator memory"},
    {"---------", CmdHelp,                  IfPm3Iso14443a,  "----------------------- " _CYAN_("magic") " ----------------------------"},
    {"setpwd",   CmdHF14AMfUCSetPwd,        IfPm3Iso14443a,  "Set 3DES key - Ultralight-C"},
    {"setuid",   CmdHF14AMfUCSetUid,        IfPm3Iso14443a,  "Set UID - MAGIC tags only"},
//    {"---------", CmdHelp,                 IfPm3Iso14443a,  "----------------------- " _CYAN_("amiibo") " ----------------------------"},
//    {"decrypt",  CmdHF14AMfUCDecryptAmiibo, IfPm3Iso14443a, "Decrypt a amiibo tag"},
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
