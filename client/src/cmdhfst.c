//-----------------------------------------------------------------------------
// Copyright (C) 2020 iceman1001
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency ISO14443A / ST  commands
//-----------------------------------------------------------------------------

#include "cmdhfst.h"
#include <ctype.h>
#include "fileutils.h"
#include "cmdparser.h"     // command_t
#include "comms.h"         // clearCommandBuffer
#include "cmdtrace.h"
#include "cliparser.h"
#include "crc16.h"
#include "cmdhf14a.h"
#include "protocols.h"     // definitions of ISO14A/7816 protocol
#include "emv/apduinfo.h"  // GetAPDUCodeDescription
#include "mifare/ndef.h"   // NDEFRecordsDecodeAndPrint

#define TIMEOUT 2000

static int CmdHelp(const char *Cmd);

// get ST Microelectronics chip model (from UID)
static char *get_st_chip_model(uint8_t pc) {
    static char model[40];
    char *s = model;
    memset(model, 0, sizeof(model));
    switch (pc) {
        case 0x0:
            sprintf(s, "SRIX4K (Special)");
            break;
        case 0x2:
            sprintf(s, "SR176");
            break;
        case 0x3:
            sprintf(s, "SRIX4K");
            break;
        case 0x4:
            sprintf(s, "SRIX512");
            break;
        case 0x6:
            sprintf(s, "SRI512");
            break;
        case 0x7:
            sprintf(s, "SRI4K");
            break;
        case 0xC:
            sprintf(s, "SRT512");
            break;
        case 0xC4:
            sprintf(s, "ST25TA64K");
            break;
        case 0xE2:
            sprintf(s, "ST25??? IKEA Rothult");
            break;
        case 0xE3:
            sprintf(s, "ST25TA02KB");
            break;
        case 0xE4:
            sprintf(s, "ST25TA512B");
            break;
        case 0xA3:
            sprintf(s, "ST25TA02KB-P");
            break;
        case 0xF3:
            sprintf(s, "ST25TA02KB-D");
            break;
        default :
            sprintf(s, "Unknown");
            break;
    }
    return s;
}
/*
// print UID info from SRx chips (ST Microelectronics)
static void print_st_general_info(uint8_t *data, uint8_t len) {
    //uid = first 8 bytes in data
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, " UID: " _GREEN_("%s"), sprint_hex(SwapEndian64(data, 8, 8), len));
    PrintAndLogEx(SUCCESS, " MFG: %02X, " _YELLOW_("%s"), data[6], getTagInfo(data[6]));
    PrintAndLogEx(SUCCESS, "Chip: %02X, " _YELLOW_("%s"), data[5] >> 2, get_st_chip_model(data[5] >> 2));
}

*/
static void print_st_cc_info(uint8_t *d, uint8_t n) {
    if (n < 0x0F) {
        PrintAndLogEx(WARNING, "Not enought bytes read from system file");
        return;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "------------ " _CYAN_("Capability Container file") " ------------");
    PrintAndLogEx(SUCCESS, " len      %u bytes (" _GREEN_("0x%02X") ")", d[1], d[1]);
    PrintAndLogEx(SUCCESS, " version  %s (" _GREEN_("0x%02X") ")", (d[2] == 0x20) ? "v2.0" : "v1.0", d[2]);

    uint16_t maxr = (d[3] << 8 | d[4]);
    PrintAndLogEx(SUCCESS, " max bytes read  %u bytes ( 0x%04X )", maxr, maxr);
    uint16_t maxw = (d[5] << 8 | d[6]);
    PrintAndLogEx(SUCCESS, " max bytes write %u bytes ( 0x%04X )", maxw, maxw);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, " NDEF file control TLV  {");
    PrintAndLogEx(SUCCESS, "    (t) type of file  ( %02X )", d[7]);
    PrintAndLogEx(SUCCESS, "    (v)               ( %02X )", d[8]);
    PrintAndLogEx(SUCCESS, "    file id           ( %02X%02X )", d[9], d[10]);

    uint16_t maxndef = (d[11] << 8 | d[12]);
    PrintAndLogEx(SUCCESS, "    max NDEF filesize   %u bytes ( 0x%04X )", maxndef, maxndef);
    PrintAndLogEx(SUCCESS, "    ----- " _CYAN_("access rights") " -------");
    PrintAndLogEx(SUCCESS, "    read   ( %02X ) protection: %s", d[13], ((d[13] & 0x80) == 0x80) ? _RED_("enabled") : _GREEN_("disabled"));
    PrintAndLogEx(SUCCESS, "    write  ( %02X ) protection: %s", d[14], ((d[14] & 0x80) == 0x80) ? _RED_("enabled") : _GREEN_("disabled"));
    PrintAndLogEx(SUCCESS, " }");
    PrintAndLogEx(SUCCESS, "----------------- " _CYAN_("raw") " -----------------");
    PrintAndLogEx(SUCCESS, "%s", sprint_hex_inrow(d, n));
    PrintAndLogEx(NORMAL, "");
}
static void print_st_system_info(uint8_t *d, uint8_t n) {
    if (n < 0x12) {
        PrintAndLogEx(WARNING, "Not enought bytes read from system file");
        return;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "------------ " _CYAN_("ST System file") " ------------");

    uint16_t len = (d[0] << 8 | d[1]);
    PrintAndLogEx(SUCCESS, " len      %u bytes (" _GREEN_("0x%04X") ")", len, len);

    if (d[2] == 0x80) {
        PrintAndLogEx(SUCCESS, " ST reserved  ( 0x%02X )", d[2]);
    } else {
        PrintAndLogEx(SUCCESS, " GPO Config ( 0x%02X )", d[2]);
        PrintAndLogEx(SUCCESS, "    config lock bit ( %s )", ((d[2] & 0x80) == 0x80) ? _RED_("locked") : _GREEN_("unlocked"));
        uint8_t conf = (d[2] & 0x70) >> 4;
        switch (conf) {
            case 0:
                PrintAndLogEx(SUCCESS, "");
                break;
            case 1:
                PrintAndLogEx(SUCCESS, "Session opened");
                break;
            case 2:
                PrintAndLogEx(SUCCESS, "WIP");
                break;
            case 3:
                PrintAndLogEx(SUCCESS, "MIP");
                break;
            case 4:
                PrintAndLogEx(SUCCESS, "Interrupt");
                break;
            case 5:
                PrintAndLogEx(SUCCESS, "State Control");
                break;
            case 6:
                PrintAndLogEx(SUCCESS, "RF Busy");
                break;
            case 7:
                PrintAndLogEx(SUCCESS, "Field Detect");
                break;
        }
    }

    PrintAndLogEx(SUCCESS, " Event counter config ( 0x%02X )", d[3]);
    PrintAndLogEx(SUCCESS, "        config lock bit ( %s )", ((d[3] & 0x80) == 0x80) ? _RED_("locked") : _GREEN_("unlocked"));
    PrintAndLogEx(SUCCESS, "                counter ( %s )", ((d[3] & 0x02) == 0x02) ? _RED_("enabled") : _GREEN_("disable"));
    PrintAndLogEx(SUCCESS, "   counter increment on ( %s )", ((d[3] & 0x01) == 0x01) ? _YELLOW_("write") : _YELLOW_("read"));

    uint32_t counter = (d[4] << 16 | d[5] << 8 | d[6]);
    PrintAndLogEx(SUCCESS, " 20bit counter ( 0x%05X )", counter & 0xFFFFF);

    PrintAndLogEx(SUCCESS, " Product version ( 0x%02X )", d[7]);

    PrintAndLogEx(SUCCESS, "          UID " _GREEN_("%s"), sprint_hex_inrow(d + 8, 7));
    PrintAndLogEx(SUCCESS, "          MFG  0x%02X, " _YELLOW_("%s"), d[8], getTagInfo(d[8]));
    PrintAndLogEx(SUCCESS, " Product Code  0x%02X, " _YELLOW_("%s"), d[9], get_st_chip_model(d[9]));
    PrintAndLogEx(SUCCESS, "      Device#  " _YELLOW_("%s"), sprint_hex_inrow(d + 10, 5));

    uint16_t mem = (d[0xF] << 8 | d[0x10]);
    PrintAndLogEx(SUCCESS, " Memory Size - 1   %u bytes (" _GREEN_("0x%04X") ")", mem, mem);

    PrintAndLogEx(SUCCESS, " IC Reference code %u ( 0x%02X )", d[0x12], d[0x12]);

    PrintAndLogEx(SUCCESS, "----------------- " _CYAN_("raw") " -----------------");
    PrintAndLogEx(SUCCESS, "%s", sprint_hex_inrow(d, n));
    PrintAndLogEx(NORMAL, "");

    /*
    0012
    80000000001302E2007D0E8DCC
    */
}

static uint16_t get_sw(uint8_t *d, uint8_t n) {
    if (n < 2)
        return 0;

    n -= 2;
    return d[n] * 0x0100 + d[n + 1];
}

// ST rothult
int infoHF_ST(void) {

    bool activate_field = true;
    bool keep_field_on = true;
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;

    // ---------------  Select NDEF Tag application ----------------
    uint8_t aSELECT_AID[80];
    int aSELECT_AID_n = 0;
    param_gethex_to_eol("00a4040007d276000085010100", 0, aSELECT_AID, sizeof(aSELECT_AID), &aSELECT_AID_n);
    int res = ExchangeAPDU14a(aSELECT_AID, aSELECT_AID_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res) {
        DropField();
        return res;
    }

    if (resplen < 2) {
        DropField();
        return PM3_ESOFT;
    }

    uint16_t sw = get_sw(response, resplen);
    if (sw != 0x9000) {
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
    if (res) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "Selecting CC file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    uint8_t aREAD_CC[30];
    int aREAD_CC_n = 0;
    param_gethex_to_eol("00b000000f", 0, aREAD_CC, sizeof(aREAD_CC), &aREAD_CC_n);
    res = ExchangeAPDU14a(aREAD_CC, aREAD_CC_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
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
    if (res) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "Selecting system file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    keep_field_on = false;

    uint8_t aREAD_SYS[30];
    int aREAD_SYS_n = 0;
    param_gethex_to_eol("00b0000012", 0, aREAD_SYS, sizeof(aREAD_SYS), &aREAD_SYS_n);
    res = ExchangeAPDU14a(aREAD_SYS, aREAD_SYS_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "reading system file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }



    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
    PrintAndLogEx(NORMAL, "");
    print_st_cc_info(st_cc_data, sizeof(st_cc_data));
    print_st_system_info(response, resplen - 2);
    return PM3_SUCCESS;
}

// menu command to get and print all info known about any known ST25TA tag
static int cmd_hf_st_info(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf st info",
                  "Get info about ST25TA tag",
                  "hf st info"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return infoHF_ST();
}

static int cmd_hf_st_sim(const char *Cmd) {
    int uidlen = 0;
    uint8_t uid[7] = {0};

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf st sim",
                  "Emulating ST25TA512B tag with 7 byte UID",
                  "hf st sim -u 02E2007D0FCA4C\n");

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

static int cmd_hf_st_ndef(const char *Cmd) {
    int pwdlen = 0;
    uint8_t pwd[16] = {0};
    bool with_pwd = false;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf st ndef",
                  "Read NFC Data Exchange Format (NDEF) file on ST25TA",
                  "hf st ndef -p 82E80053D4CA5C0B656D852CC696C8A1\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("p", "pwd", "<hex>", "16 byte read password"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIGetHexWithReturn(ctx, 1, pwd, &pwdlen);
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
    if (res) {
        DropField();
        return res;
    }

    if (resplen < 2) {
        DropField();
        return PM3_ESOFT;
    }

    uint16_t sw = get_sw(response, resplen);
    if (sw != 0x9000) {
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
    if (res) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
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
        if (res) {
            DropField();
            return res;
        }

        sw = get_sw(response, resplen);
        if (sw == 0x6300) {
            // need to provide 16byte password
            param_gethex_to_eol("0020000110", 0, aVERIFY, sizeof(aVERIFY), &aVERIFY_n);
            memcpy(aVERIFY + aVERIFY_n, pwd, pwdlen);
            res = ExchangeAPDU14a(aVERIFY, aVERIFY_n + pwdlen, activate_field, keep_field_on, response, sizeof(response), &resplen);
            if (res) {
                DropField();
                return res;
            }

            sw = get_sw(response, resplen);
            if (sw != 0x9000) {
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
    if (res) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "reading NDEF file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    NDEFRecordsDecodeAndPrint(response + 2, resplen - 4);
    return PM3_SUCCESS;
}

static int cmd_hf_st_protect(const char *Cmd) {

    int pwdlen = 0;
    uint8_t pwd[16] = {0};
    int statelen = 3;
    uint8_t state[3] = {0x26, 0, 0x02};

    bool disable_protection = false;
    bool enable_protection = false;
    bool read_protection = false;
    bool write_protection = false;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf st protect",
                  "Change read or write protection for NFC Data Exchange Format (NDEF) file on ST25TA",
                  "hf st protect -p 82E80053D4CA5C0B656D852CC696C8A1 -r -e -> enable read protection\n"
                  "hf st protect -p 82E80053D4CA5C0B656D852CC696C8A1 -w -d -> disable write protection\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("e",  "enable",            "enable protection"),
        arg_lit0("d",  "disable",           "disable protection (default)"),
        arg_lit0("r",  "read",              "change read protection"),
        arg_lit0("w",  "write",             "change write protection (default)"),
        arg_str1("p", "password", "<hex>", "16 byte write password"),
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
    if (res) {
        DropField();
        return res;
    }

    if (resplen < 2) {
        DropField();
        return PM3_ESOFT;
    }

    uint16_t sw = get_sw(response, resplen);
    if (sw != 0x9000) {
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
    if (res) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
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
    if (res) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
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
    if (res) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "changing protection failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, " %s protection ( %s )", ((state[2] & 0x01) == 0x01) ? _YELLOW_("read") : _YELLOW_("write"),
                  ((state[0] & 0x28) == 0x28) ? _RED_("enabled") : _GREEN_("disabled"));

    return PM3_SUCCESS;
}

static int cmd_hf_st_pwd(const char *Cmd) {

    int pwdlen = 0;
    uint8_t pwd[16] = {0};
    int newpwdlen = 0;
    uint8_t newpwd[16] = {0};
    int changePwdlen = 4;
    uint8_t changePwd[4] = {0x24, 0x00, 0x01, 0x10};
    bool change_read_password = false;
    bool change_write_password = false;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf st pwd",
                  "Change read or write password for NFC Data Exchange Format (NDEF) file on ST25TA",
                  "hf st pwd -p 82E80053D4CA5C0B656D852CC696C8A1 -r -n 00000000000000000000000000000000 -> change read password\n"
                  "hf st pwd -p 82E80053D4CA5C0B656D852CC696C8A1 -w -n 00000000000000000000000000000000 -> change write password\n");

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
    if (res) {
        DropField();
        return res;
    }

    if (resplen < 2) {
        DropField();
        return PM3_ESOFT;
    }

    uint16_t sw = get_sw(response, resplen);
    if (sw != 0x9000) {
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
    if (res) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
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
    if (res) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
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
    if (res) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "password change failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }
    PrintAndLogEx(SUCCESS, " %s password changed", ((changePwd[2] & 0x01) == 0x01) ? _YELLOW_("read") : _YELLOW_("write"));
    return PM3_SUCCESS;
}

static int cmd_hf_st_list(const char *Cmd) {
    char args[128] = {0};
    if (strlen(Cmd) == 0) {
        snprintf(args, sizeof(args), "-t 7816");
    } else {
        strncpy(args, Cmd, sizeof(args) - 1);
    }
    return CmdTraceList(args);
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,           AlwaysAvailable, "This help"},
    {"info",    cmd_hf_st_info,    IfPm3Iso14443a,  "Tag information"},
    {"list",    cmd_hf_st_list,    AlwaysAvailable, "List ISO 14443A/7816 history"},
    {"ndef",    cmd_hf_st_ndef,    AlwaysAvailable, "read NDEF file on tag"},
    {"protect", cmd_hf_st_protect, IfPm3Iso14443a,  "change protection on tag"},
    {"pwd",     cmd_hf_st_pwd,     IfPm3Iso14443a,  "change password on tag"},
    {"sim",     cmd_hf_st_sim,     IfPm3Iso14443a,  "Fake ISO 14443A/ST tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHF_ST(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
