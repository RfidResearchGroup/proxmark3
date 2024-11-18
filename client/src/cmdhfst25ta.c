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
// High frequency ISO14443A / ST25TA  commands
//-----------------------------------------------------------------------------

#include "cmdhfst25ta.h"
#include "cmdhfst.h"
#include <ctype.h>
#include "fileutils.h"
#include "cmdparser.h"         // command_t
#include "comms.h"             // clearCommandBuffer
#include "cmdtrace.h"
#include "cliparser.h"
#include "crc16.h"
#include "cmdhf14a.h"
#include "protocols.h"         // definitions of ISO14A/7816 protocol
#include "iso7816/apduinfo.h"  // GetAPDUCodeDescription
#include "nfc/ndef.h"          // NDEFRecordsDecodeAndPrint
#include "cmdnfc.h"            // print_type4_cc_info
#include "commonutil.h"        // get_sw
#include "protocols.h"         // ISO7816 APDU return codes
#include "crypto/libpcrypto.h" // ecdsa

#define TIMEOUT 2000

static int CmdHelp(const char *Cmd);

static bool st25ta_select(iso14a_card_select_t *card) {

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_NO_DISCONNECT | ISO14A_NO_RATS, 0, 0, NULL, 0);
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
    }
    return true;
}

static void print_st25ta_system_info(uint8_t *d, uint8_t n) {
    if (n < 0x12) {
        PrintAndLogEx(WARNING, "Not enough bytes read from system file");
        return;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "------------ " _CYAN_("ST System file") " -----------------------------");

    PrintAndLogEx(SUCCESS, "Manufacture..... " _YELLOW_("%s"), getTagInfo(d[8]));
    PrintAndLogEx(SUCCESS, "Product Code.... " _YELLOW_("%s"), get_st_chip_model(d[9]));
    PrintAndLogEx(SUCCESS, "Device Serial... " _YELLOW_("%s"), sprint_hex_inrow(d + 10, 5));

    if (d[2] != 0x80) {

        PrintAndLogEx(SUCCESS, "GPO Config... 0x%02X", d[2]);
        PrintAndLogEx(SUCCESS, " lock bit.... %s", ((d[2] & 0x80) == 0x80) ? _RED_("locked") : _GREEN_("unlocked"));

        uint8_t conf = (d[2] & 0x70) >> 4;
        switch (conf) {
            case 0:
                break;
            case 1:
                PrintAndLogEx(SUCCESS, " Session opened");
                break;
            case 2:
                PrintAndLogEx(SUCCESS, " WIP");
                break;
            case 3:
                PrintAndLogEx(SUCCESS, " MIP");
                break;
            case 4:
                PrintAndLogEx(SUCCESS, " Interrupt");
                break;
            case 5:
                PrintAndLogEx(SUCCESS, " State Control");
                break;
            case 6:
                PrintAndLogEx(SUCCESS, " RF Busy");
                break;
            case 7:
                PrintAndLogEx(SUCCESS, " Field Detect");
                break;
        }
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "Event counter config.... 0x%02X", d[3]);
    PrintAndLogEx(SUCCESS, " config lock bit........ %s", ((d[3] & 0x80) == 0x80) ? _RED_("locked") : _GREEN_("unlocked"));
    PrintAndLogEx(SUCCESS, " counter................ %s", ((d[3] & 0x02) == 0x02) ? _RED_("enabled") : _GREEN_("disable"));
    PrintAndLogEx(SUCCESS, " counter increment on... %s", ((d[3] & 0x01) == 0x01) ? _YELLOW_("write") : _YELLOW_("read"));
    PrintAndLogEx(NORMAL, "");

    uint16_t len = (d[0] << 8 | d[1]);

    PrintAndLogEx(SUCCESS, "----------------- " _CYAN_("raw") " -----------------------------------");
    PrintAndLogEx(SUCCESS, " %s", sprint_hex_inrow(d, n));
    PrintAndLogEx(SUCCESS, " %02X%02X................................ - Len ( %u bytes )", d[0], d[1], len);

    if (d[2] == 0x80) {
        PrintAndLogEx(SUCCESS, " ....%02X.............................. - ST reserved", d[2]);
    } else {
        PrintAndLogEx(SUCCESS, " ....%02X.............................. - GPO config", d[2]);
    }

    PrintAndLogEx(SUCCESS, " ......%02X............................ - Event counter config", d[3]);

    uint32_t counter = (d[4] << 16 | d[5] << 8 | d[6]);
    PrintAndLogEx(SUCCESS, " ........%02X%02X%02X...................... - 20 bit counter ( %u )", d[4], d[5], d[6], (counter & 0xFFFFF));
    PrintAndLogEx(SUCCESS, " ..............%02X.................... - Product version", d[7]);
    PrintAndLogEx(SUCCESS, " ................%s...... - UID", sprint_hex_inrow(d + 8, 7));

    uint16_t mem = (d[0xF] << 8 | d[0x10]);
    PrintAndLogEx(SUCCESS, " ..............................%02X%02X.. - Mem size - 1 ( %u bytes )", d[0xf], d[0x10], mem);

    PrintAndLogEx(SUCCESS, " ..................................%02X - IC ref code", d[0x11]);
    PrintAndLogEx(NORMAL, "");

    /*
    0012
    80000000001302E2007D0E8DCC
    */
}

static int print_st25ta_signature(uint8_t *uid, uint8_t *signature) {

#define PUBLIC_ECDA_KEYLEN 33
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

    for (uint8_t i = 0; i < ARRAYLEN(nxp_mfu_public_keys); i++) {

        int dl = 0;
        uint8_t key[PUBLIC_ECDA_KEYLEN] = {0};
        param_gethex_to_eol(nxp_mfu_public_keys[i].value, 0, key, PUBLIC_ECDA_KEYLEN, &dl);

        int res = ecdsa_signature_r_s_verify(MBEDTLS_ECP_DP_SECP128R1, key, uid, 7, signature, 32, true);

        if (res == 0) {

            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, "--- " _CYAN_("Tag Signature"));


            PrintAndLogEx(INFO, " IC signature public key name: " _GREEN_("%s"), nxp_mfu_public_keys[i].desc);
            PrintAndLogEx(INFO, "IC signature public key value: %s", nxp_mfu_public_keys[i].value);
            PrintAndLogEx(INFO, "    Elliptic curve parameters: NID_secp128r1");
            PrintAndLogEx(INFO, "             TAG IC Signature: %s", sprint_hex_inrow(signature, 32));
            PrintAndLogEx(SUCCESS, "       Signature verification ( " _GREEN_("successful") " )");
            return PM3_SUCCESS;
        }
    }

    return PM3_ESOFT;
}

static int st25ta_get_signature(uint8_t *signature) {
    /*
    hf 14a raw -sck 0200A4040007D276000085010100
    hf 14a raw -ck 0300A4000C020001
    hf 14a raw -c 02a2b000e020
    */
    typedef struct {
        const char *apdu;
        uint8_t apdulen;
    } transport_st25a_apdu_t;

    transport_st25a_apdu_t cmds[] = {
        { "\x00\xA4\x04\x00\x07\xD2\x76\x00\x00\x85\x01\x01\x00", 13 },
        { "\x00\xA4\x00\x0C\x02\x00\x01", 7 },
        { "\xa2\xb0\x00\xe0\x20", 5 },
    };

    uint8_t resp[40] = {0};
    int resplen = 0;
    bool activate_field = true;

    for (uint8_t i = 0; i < ARRAYLEN(cmds); i++) {
        int res = ExchangeAPDU14a((uint8_t *)cmds[i].apdu, cmds[i].apdulen, activate_field, true, resp, sizeof(resp), &resplen);
        if (res != PM3_SUCCESS) {
            DropField();
            return res;
        }
        activate_field = false;
    }

    if (signature) {
        memcpy(signature, resp, 32);
    }

    DropField();
    return PM3_SUCCESS;
}

// ST25TA
static int infoHFST25TA(void) {

    bool activate_field = true;
    bool keep_field_on = true;
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;

    // ---------------  Select NDEF Tag application ----------------
    uint8_t aSELECT_AID[80];
    int aSELECT_AID_n = 0;
    param_gethex_to_eol("00a4040007d276000085010100", 0, aSELECT_AID, sizeof(aSELECT_AID), &aSELECT_AID_n);
    int res = ExchangeAPDU14a(aSELECT_AID, aSELECT_AID_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    if (resplen < 2) {
        DropField();
        return PM3_ESOFT;
    }

    uint16_t sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Selecting NDEF aid failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    activate_field = false;
    keep_field_on = true;
    // ---------------  CC file reading ----------------

    uint8_t aSELECT_FILE_CC[30];
    int aSELECT_FILE_CC_n = 0;
    param_gethex_to_eol("00a4000c02e103", 0, aSELECT_FILE_CC, sizeof(aSELECT_FILE_CC), &aSELECT_FILE_CC_n);
    res = ExchangeAPDU14a(aSELECT_FILE_CC, aSELECT_FILE_CC_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Selecting CC file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    uint8_t aREAD_CC[30];
    int aREAD_CC_n = 0;
    param_gethex_to_eol("00b000000f", 0, aREAD_CC, sizeof(aREAD_CC), &aREAD_CC_n);
    res = ExchangeAPDU14a(aREAD_CC, aREAD_CC_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "reading CC file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }
    // store st cc data for later
    uint8_t st_cc_data[resplen - 2];
    memcpy(st_cc_data, response, sizeof(st_cc_data));

    // ---------------  System file reading ----------------
    uint8_t aSELECT_FILE_SYS[30];
    int aSELECT_FILE_SYS_n = 0;
    param_gethex_to_eol("00a4000c02e101", 0, aSELECT_FILE_SYS, sizeof(aSELECT_FILE_SYS), &aSELECT_FILE_SYS_n);
    res = ExchangeAPDU14a(aSELECT_FILE_SYS, aSELECT_FILE_SYS_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Selecting system file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    keep_field_on = false;

    uint8_t aREAD_SYS[30];
    int aREAD_SYS_n = 0;
    param_gethex_to_eol("00b0000012", 0, aREAD_SYS, sizeof(aREAD_SYS), &aREAD_SYS_n);
    res = ExchangeAPDU14a(aREAD_SYS, aREAD_SYS_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "reading system file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
    PrintAndLogEx(NORMAL, "");
    iso14a_card_select_t card;
    if (st25ta_select(&card)) {
        uint8_t sig[32] = {0};
        if (st25ta_get_signature(sig) == PM3_SUCCESS) {
            print_st25ta_signature(card.uid, sig);
        }
    }

    print_type4_cc_info(st_cc_data, sizeof(st_cc_data));
    print_st25ta_system_info(response, resplen - 2);

    return PM3_SUCCESS;
}

// menu command to get and print all info known about any known ST25TA tag
static int CmdHFST25TAInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf st25ta info",
                  "Get info about ST25TA tag",
                  "hf st25ta info"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return infoHFST25TA();
}

static int CmdHFST25TASim(const char *Cmd) {
    int uidlen = 0;
    uint8_t uid[7] = {0};

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf st25ta sim",
                  "Emulating ST25TA512B tag with 7 byte UID",
                  "hf st25ta sim -u 02E2007D0FCA4C\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("u", "uid", "<hex>", "7 byte UID"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    CLIGetHexWithReturn(ctx, 1, uid, &uidlen);
    CLIParserFree(ctx);

    if (uidlen != 7) {
        PrintAndLogEx(ERR, "UID must be 7 hex bytes");
        return PM3_EINVARG;
    }

    char param[40];
    snprintf(param, sizeof(param), "-t 10 -u %s", sprint_hex_inrow(uid, uidlen));
    return CmdHF14ASim(param);
}

int CmdHFST25TANdefRead(const char *Cmd) {
    int pwdlen = 0;
    uint8_t pwd[16] = {0};
    bool with_pwd = false;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf st25ta ndefread",
                  "Read NFC Data Exchange Format (NDEF) file on ST25TA",
                  "hf st25ta ndefread -p 82E80053D4CA5C0B656D852CC696C8A1\n"
                  "hf st25ta ndefread -f myfilename -> save raw NDEF to file"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("p", "pwd", "<hex>", "16 byte read password"),
        arg_str0("f", "file", "<fn>", "save raw NDEF to file"),
        arg_lit0("v",  "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIGetHexWithReturn(ctx, 1, pwd, &pwdlen);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    bool verbose = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (pwdlen == 0) {
        with_pwd = false;
    } else {
        if (pwdlen != 16) {
            PrintAndLogEx(ERR, "Password must be 16 hex bytes");
            return PM3_EINVARG;
        }
        with_pwd = true;
    }

    bool activate_field = true;
    bool keep_field_on = true;
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;

    // ---------------  Select NDEF Tag application ----------------
    uint8_t aSELECT_AID[80];
    int aSELECT_AID_n = 0;
    param_gethex_to_eol("00a4040007d276000085010100", 0, aSELECT_AID, sizeof(aSELECT_AID), &aSELECT_AID_n);
    int res = ExchangeAPDU14a(aSELECT_AID, aSELECT_AID_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    if (resplen < 2) {
        DropField();
        return PM3_ESOFT;
    }

    uint16_t sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Selecting NDEF aid failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    activate_field = false;
    keep_field_on = true;

    // ---------------  NDEF file reading ----------------
    uint8_t aSELECT_FILE_NDEF[30];
    int aSELECT_FILE_NDEF_n = 0;
    param_gethex_to_eol("00a4000c020001", 0, aSELECT_FILE_NDEF, sizeof(aSELECT_FILE_NDEF), &aSELECT_FILE_NDEF_n);
    res = ExchangeAPDU14a(aSELECT_FILE_NDEF, aSELECT_FILE_NDEF_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Selecting NDEF file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    if (with_pwd) {
        // ---------------  VERIFY ----------------
        uint8_t aVERIFY[30];
        int aVERIFY_n = 0;
        param_gethex_to_eol("0020000100", 0, aVERIFY, sizeof(aVERIFY), &aVERIFY_n);
        res = ExchangeAPDU14a(aVERIFY, aVERIFY_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
        if (res != PM3_SUCCESS) {
            DropField();
            return res;
        }

        sw = get_sw(response, resplen);
        if (sw == 0x6300) {
            // need to provide 16byte password
            param_gethex_to_eol("0020000110", 0, aVERIFY, sizeof(aVERIFY), &aVERIFY_n);
            memcpy(aVERIFY + aVERIFY_n, pwd, pwdlen);
            res = ExchangeAPDU14a(aVERIFY, aVERIFY_n + pwdlen, activate_field, keep_field_on, response, sizeof(response), &resplen);
            if (res != PM3_SUCCESS) {
                DropField();
                return res;
            }

            sw = get_sw(response, resplen);
            if (sw != ISO7816_OK) {
                PrintAndLogEx(ERR, "Verify password failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
                DropField();
                return PM3_ESOFT;
            }
        }
    }

    keep_field_on = false;
    uint8_t aREAD_NDEF[30];
    int aREAD_NDEF_n = 0;
    param_gethex_to_eol("00b000001d", 0, aREAD_NDEF, sizeof(aREAD_NDEF), &aREAD_NDEF_n);
    res = ExchangeAPDU14a(aREAD_NDEF, aREAD_NDEF_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "reading NDEF file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    NDEFRecordsDecodeAndPrint(response + 2, resplen - 4, verbose);

    // get total NDEF length before save. If fails, we save it all
    size_t n = 0;
    if (NDEFGetTotalLength(response, resplen, &n) != PM3_SUCCESS)
        n = resplen;

    pm3_save_dump(filename, response + 2, n, jsfNDEF);

    return PM3_SUCCESS;
}

static int CmdHFST25TAProtect(const char *Cmd) {

    int pwdlen = 0;
    uint8_t pwd[16] = {0};
    int statelen = 3;
    uint8_t state[3] = {0x26, 0, 0x02};

    bool disable_protection = false;
    bool enable_protection = false;
    bool read_protection = false;
    bool write_protection = false;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf st25ta protect",
                  "Change read or write protection for NFC Data Exchange Format (NDEF) file on ST25TA",
                  "hf st25ta protect -p 82E80053D4CA5C0B656D852CC696C8A1 -r -e -> enable read protection\n"
                  "hf st25ta protect -p 82E80053D4CA5C0B656D852CC696C8A1 -w -d -> disable write protection\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("e",  "enable",            "enable protection"),
        arg_lit0("d",  "disable",           "disable protection (default)"),
        arg_lit0("r",  "read",              "change read protection"),
        arg_lit0("w",  "write",             "change write protection (default)"),
        arg_str1("p",  "password", "<hex>", "16 byte write password"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    enable_protection = arg_get_lit(ctx, 1);
    disable_protection = arg_get_lit(ctx, 2);
    read_protection = arg_get_lit(ctx, 3);
    write_protection = arg_get_lit(ctx, 4);
    CLIGetHexWithReturn(ctx, 5, pwd, &pwdlen);
    CLIParserFree(ctx);

    //Validations
    if (enable_protection && disable_protection) {
        PrintAndLogEx(ERR, "Must specify either enable or disable protection, not both");
        return PM3_EINVARG;
    }
    if (enable_protection) {
        state[0] = 0x28;
    }
    if (disable_protection) {
        state[0] = 0x26;
    }

    if (read_protection && write_protection) {
        PrintAndLogEx(ERR, "Must specify either read or write protection, not both");
        return PM3_EINVARG;
    }
    if (read_protection) {
        state[2] = 0x01;
    }
    if (write_protection) {
        state[2] = 0x02;
    }

    if (pwdlen != 16) {
        PrintAndLogEx(ERR, "Missing 16 byte password");
        return PM3_EINVARG;
    }

    bool activate_field = true;
    bool keep_field_on = true;
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;

    // ---------------  Select NDEF Tag application ----------------
    uint8_t aSELECT_AID[80];
    int aSELECT_AID_n = 0;
    param_gethex_to_eol("00a4040007d276000085010100", 0, aSELECT_AID, sizeof(aSELECT_AID), &aSELECT_AID_n);
    int res = ExchangeAPDU14a(aSELECT_AID, aSELECT_AID_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    if (resplen < 2) {
        DropField();
        return PM3_ESOFT;
    }

    uint16_t sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Selecting NDEF aid failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    activate_field = false;
    keep_field_on = true;

    // ---------------  Select NDEF file ----------------
    uint8_t aSELECT_FILE_NDEF[30];
    int aSELECT_FILE_NDEF_n = 0;
    param_gethex_to_eol("00a4000c020001", 0, aSELECT_FILE_NDEF, sizeof(aSELECT_FILE_NDEF), &aSELECT_FILE_NDEF_n);
    res = ExchangeAPDU14a(aSELECT_FILE_NDEF, aSELECT_FILE_NDEF_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Selecting NDEF file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    // ---------------  VERIFY ----------------
    uint8_t aVERIFY[30];
    int aVERIFY_n = 0;
    // need to provide 16byte password
    param_gethex_to_eol("0020000210", 0, aVERIFY, sizeof(aVERIFY), &aVERIFY_n);
    memcpy(aVERIFY + aVERIFY_n, pwd, pwdlen);
    res = ExchangeAPDU14a(aVERIFY, aVERIFY_n + pwdlen, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Verify password failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    // ---------------  Change protection ----------------
    keep_field_on = false;
    uint8_t aPROTECT[30];
    int aPROTECT_n = 0;
    param_gethex_to_eol("00", 0, aPROTECT, sizeof(aPROTECT), &aPROTECT_n);
    memcpy(aPROTECT + aPROTECT_n, state, statelen);
    res = ExchangeAPDU14a(aPROTECT, aPROTECT_n + statelen, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "changing protection failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, " %s protection ( %s )", ((state[2] & 0x01) == 0x01) ? _YELLOW_("read") : _YELLOW_("write"),
                  ((state[0] & 0x28) == 0x28) ? _RED_("enabled") : _GREEN_("disabled"));

    return PM3_SUCCESS;
}

static int CmdHFST25TAPwd(const char *Cmd) {

    int pwdlen = 0;
    uint8_t pwd[16] = {0};
    int newpwdlen = 0;
    uint8_t newpwd[16] = {0};
    int changePwdlen = 4;
    uint8_t changePwd[4] = {0x24, 0x00, 0x01, 0x10};
    bool change_read_password = false;
    bool change_write_password = false;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf st25ta pwd",
                  "Change read or write password for NFC Data Exchange Format (NDEF) file on ST25TA",
                  "hf st25ta pwd -p 82E80053D4CA5C0B656D852CC696C8A1 -r -n 00000000000000000000000000000000 -> change read password\n"
                  "hf st25ta pwd -p 82E80053D4CA5C0B656D852CC696C8A1 -w -n 00000000000000000000000000000000 -> change write password\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("r", "read",              "change the read password (default)"),
        arg_lit0("w", "write",             "change the write password"),
        arg_str1("p", "password", "<hex>", "current 16 byte write password"),
        arg_str1("n", "new",      "<hex>", "new 16 byte password"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    change_read_password = arg_get_lit(ctx, 1);
    change_write_password = arg_get_lit(ctx, 2);
    CLIGetHexWithReturn(ctx, 3, pwd, &pwdlen);
    CLIGetHexWithReturn(ctx, 4, newpwd, &newpwdlen);
    CLIParserFree(ctx);

    if (change_read_password && change_write_password) {
        PrintAndLogEx(ERR, "Must specify either read or write, not both");
        return PM3_EINVARG;
    }
    if (change_read_password) {
        changePwd[2] = 0x01;
    }
    if (change_write_password) {
        changePwd[2] = 0x02;
    }

    if (pwdlen != 16) {
        PrintAndLogEx(ERR, "Original write password must be 16 hex bytes");
        return PM3_EINVARG;
    }
    if (newpwdlen != 16) {
        PrintAndLogEx(ERR, "New password must be 16 hex bytes");
        return PM3_EINVARG;
    }

    bool activate_field = true;
    bool keep_field_on = true;
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;

    // ---------------  Select NDEF Tag application ----------------
    uint8_t aSELECT_AID[80];
    int aSELECT_AID_n = 0;
    param_gethex_to_eol("00a4040007d276000085010100", 0, aSELECT_AID, sizeof(aSELECT_AID), &aSELECT_AID_n);
    int res = ExchangeAPDU14a(aSELECT_AID, aSELECT_AID_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    if (resplen < 2) {
        DropField();
        return PM3_ESOFT;
    }

    uint16_t sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Selecting NDEF aid failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    activate_field = false;
    keep_field_on = true;

    // ---------------  Select NDEF file ----------------
    uint8_t aSELECT_FILE_NDEF[30];
    int aSELECT_FILE_NDEF_n = 0;
    param_gethex_to_eol("00a4000c020001", 0, aSELECT_FILE_NDEF, sizeof(aSELECT_FILE_NDEF), &aSELECT_FILE_NDEF_n);
    res = ExchangeAPDU14a(aSELECT_FILE_NDEF, aSELECT_FILE_NDEF_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Selecting NDEF file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    // ---------------  VERIFY ----------------
    uint8_t aVERIFY[30];
    int aVERIFY_n = 0;
    // need to provide 16byte password
    param_gethex_to_eol("0020000210", 0, aVERIFY, sizeof(aVERIFY), &aVERIFY_n);
    memcpy(aVERIFY + aVERIFY_n, pwd, pwdlen);
    res = ExchangeAPDU14a(aVERIFY, aVERIFY_n + pwdlen, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Verify password failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    // ---------------  Change password ----------------

    keep_field_on = false;
    uint8_t aCHG_PWD[30];
    int aCHG_PWD_n = 0;
    param_gethex_to_eol("00", 0, aCHG_PWD, sizeof(aCHG_PWD), &aCHG_PWD_n);
    memcpy(aCHG_PWD + aCHG_PWD_n, changePwd, changePwdlen);
    memcpy(aCHG_PWD + aCHG_PWD_n + changePwdlen, newpwd, newpwdlen);
    res = ExchangeAPDU14a(aCHG_PWD, aCHG_PWD_n + changePwdlen + newpwdlen, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "password change failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }
    PrintAndLogEx(SUCCESS, " %s password changed", ((changePwd[2] & 0x01) == 0x01) ? _YELLOW_("read") : _YELLOW_("write"));
    return PM3_SUCCESS;
}

static int CmdHFST25TAList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf st25ta", "7816");
}

static command_t CommandTable[] = {
    {"help",     CmdHelp,               AlwaysAvailable, "This help"},
    {"info",     CmdHFST25TAInfo,       IfPm3Iso14443a,  "Tag information"},
    {"list",     CmdHFST25TAList,       AlwaysAvailable, "List ISO 14443A/7816 history"},
    {"ndefread", CmdHFST25TANdefRead,   AlwaysAvailable, "read NDEF file on tag"},
    {"protect",  CmdHFST25TAProtect,    IfPm3Iso14443a,  "change protection on tag"},
    {"pwd",      CmdHFST25TAPwd,        IfPm3Iso14443a,  "change password on tag"},
    {"sim",      CmdHFST25TASim,        IfPm3Iso14443a,  "Fake ISO 14443A/ST tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFST25TA(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
