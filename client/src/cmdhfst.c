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
#include "crc16.h"
#include "cmdhf14a.h"
#include "protocols.h"     // definitions of ISO14A/7816 protocol
#include "emv/apduinfo.h"  // GetAPDUCodeDescription 
#include "mifare/ndef.h"   // NDEFRecordsDecodeAndPrint

#define TIMEOUT 2000
static int CmdHelp(const char *Cmd);

static int usage_hf_st_info(void) {
    PrintAndLogEx(NORMAL, "Usage: hf st info [h]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h    this help");
    PrintAndLogEx(NORMAL, "Example:");
    PrintAndLogEx(NORMAL, _YELLOW_("       hf st info"));
    return PM3_SUCCESS;
}
static int usage_hf_st_sim(void) {
    PrintAndLogEx(NORMAL, "\n Emulating ST25TA512B tag with 7 byte UID\n");
    PrintAndLogEx(NORMAL, "Usage: hf st sim [h] u <uid> ");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "    h     : This help");
    PrintAndLogEx(NORMAL, "    u     : 7 byte UID");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("          hf st sim u 02E2007D0FCA4C"));
    return PM3_SUCCESS;
}
static int usage_hf_st_ndef(void) {
    PrintAndLogEx(NORMAL, "\n Print NFC Data Exchange Format (NDEF)\n");
    PrintAndLogEx(NORMAL, "Usage: hf st ndef [h] p <pwd> ");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "    h          : This help");
    PrintAndLogEx(NORMAL, "    p <pwd>    : 16 byte password");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("          hf st ndef p 82E80053D4CA5C0B656D852CC696C8A1"));
    return PM3_SUCCESS;
}

static int usage_hf_st_protect(void) {
    PrintAndLogEx(NORMAL, "\n Change R/W protection for NFC Data Exchange Format (NDEF)\n");
    PrintAndLogEx(NORMAL, "Usage: hf st protect [h] p <pwd> r|w [0|1]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "    h          : This help");
    PrintAndLogEx(NORMAL, "    p <pwd>    : 16 byte write password");
    PrintAndLogEx(NORMAL, "    r|w        : Change (r)ead or (w)rite protection");
    PrintAndLogEx(NORMAL, "    [0|1]      : Enable / Disable protection");
    PrintAndLogEx(NORMAL, "                 0 = Disable (default)");
    PrintAndLogEx(NORMAL, "                 1 = Enable");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("          hf st protect p 82E80053D4CA5C0B656D852CC696C8A1 r 0"));
    return PM3_SUCCESS;
}

static int usage_hf_st_pwd(void) {
    PrintAndLogEx(NORMAL, "\n Change R/W password for NFC Data Exchange Format (NDEF)\n");
    PrintAndLogEx(NORMAL, "Usage: hf st pwd [h] p <pwd> r|w n <newpwd>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "    h           : This help");
    PrintAndLogEx(NORMAL, "    p <pwd>     : 16 byte write password");
    PrintAndLogEx(NORMAL, "    r|w         : Change (r)ead or (w)rite password");
    PrintAndLogEx(NORMAL, "    n <newpwd>  : New 16 byte password");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("       hf st pwd p 82E80053D4CA5C0B656D852CC696C8A1 r n 00000000000000000000000000000000"));
    return PM3_SUCCESS;
}

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
    PrintAndLogEx(SUCCESS, " len      %u bytes (" _GREEN_("0x%02X") ")", d[1],d[1]);
    PrintAndLogEx(SUCCESS, " version  %s (" _GREEN_("0x%02X") ")", (d[2] == 0x20) ? "v2.0" : "v1.0", d[2]);

    uint16_t maxr =  (d[3] << 8 | d[4]);
    PrintAndLogEx(SUCCESS, " max bytes read  %u bytes ( 0x%04X )", maxr, maxr);
    uint16_t maxw =  (d[5] << 8 | d[6]);
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
    
    uint16_t len =  (d[0] << 8 | d[1]);
    PrintAndLogEx(SUCCESS, " len      %u bytes (" _GREEN_("0x%04X") ")", len, len);

    if (d[2] == 0x80) {
        PrintAndLogEx(SUCCESS, " ST reserved  ( 0x%02X )", d[2]);
    } else {
        PrintAndLogEx(SUCCESS, " GPO Config ( 0x%02X )", d[2]);
        PrintAndLogEx(SUCCESS, "    config lock bit ( %s )", ((d[2] & 0x80) == 0x80) ? _RED_("locked") : _GREEN_("unlocked"));
        uint8_t conf = (d[2] & 0x70) >> 4;
        switch(conf) {
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

    uint32_t counter =  (d[4] << 16 | d[5] << 8 | d[6]);
    PrintAndLogEx(SUCCESS, " 20bit counter ( 0x%05X )", counter & 0xFFFFF);
    
    PrintAndLogEx(SUCCESS, " Product version ( 0x%02X )", d[7]);
    
    PrintAndLogEx(SUCCESS, "          UID " _GREEN_("%s"), sprint_hex_inrow(d + 8, 7));
    PrintAndLogEx(SUCCESS, "          MFG  0x%02X, " _YELLOW_("%s"), d[8], getTagInfo(d[8]));
    PrintAndLogEx(SUCCESS, " Product Code  0x%02X, " _YELLOW_("%s"), d[9], get_st_chip_model(d[9]));
    PrintAndLogEx(SUCCESS, "      Device#  " _YELLOW_("%s"), sprint_hex_inrow(d + 10, 5));    

    uint16_t mem =  (d[0xF] << 8 | d[0x10]);
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
    if (res)
        return res;

    if (resplen < 2)
        return PM3_ESOFT;

    uint16_t sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "Selecting NDEF aid failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return PM3_ESOFT;
    }

    activate_field = false;
    keep_field_on = true;
    // ---------------  CC file reading ----------------
    
    uint8_t aSELECT_FILE_CC[30];
    int aSELECT_FILE_CC_n = 0;
    param_gethex_to_eol("00a4000c02e103", 0, aSELECT_FILE_CC, sizeof(aSELECT_FILE_CC), &aSELECT_FILE_CC_n);    
    res = ExchangeAPDU14a(aSELECT_FILE_CC, aSELECT_FILE_CC_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res)
        return res;

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "Selecting CC file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return PM3_ESOFT;
    }
   
    uint8_t aREAD_CC[30];
    int aREAD_CC_n = 0;
    param_gethex_to_eol("00b000000f", 0, aREAD_CC, sizeof(aREAD_CC), &aREAD_CC_n);    
    res = ExchangeAPDU14a(aREAD_CC, aREAD_CC_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res)
        return res;

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "reading CC file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return PM3_ESOFT;
    }

    print_st_cc_info(response, resplen - 2);


    // ---------------  System file reading ----------------   
    uint8_t aSELECT_FILE_SYS[30];
    int aSELECT_FILE_SYS_n = 0;
    param_gethex_to_eol("00a4000c02e101", 0, aSELECT_FILE_SYS, sizeof(aSELECT_FILE_SYS), &aSELECT_FILE_SYS_n);    
    res = ExchangeAPDU14a(aSELECT_FILE_SYS, aSELECT_FILE_SYS_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res)
        return res;

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "Selecting system file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return PM3_ESOFT;
    }

    keep_field_on = false;
    
    uint8_t aREAD_SYS[30];
    int aREAD_SYS_n = 0;
    param_gethex_to_eol("00b0000012", 0, aREAD_SYS, sizeof(aREAD_SYS), &aREAD_SYS_n);    
    res = ExchangeAPDU14a(aREAD_SYS, aREAD_SYS_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res)
        return res;

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "reading system file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return PM3_ESOFT;
    }
    print_st_system_info(response, resplen - 2);
//    PrintAndLogEx(NORMAL, "<<<< %s", sprint_hex(response, resplen));
    return PM3_SUCCESS;
}

// menu command to get and print all info known about any known 14b tag
static int cmd_hf_st_info(const char *Cmd) {
    char c = tolower(param_getchar(Cmd, 0));
    if (c == 'h') return usage_hf_st_info();
    return infoHF_ST();
}

static int cmd_hf_st_sim(const char *Cmd) {
    char c = tolower(param_getchar(Cmd, 0));
    if (c == 'h' || c == 0x00) return usage_hf_st_sim();

    int uidlen = 0;    
    uint8_t cmdp = 0;
    uint8_t uid[7] = {0};
    if (c == 'u') {
        param_gethex_ex(Cmd, cmdp + 1, uid, &uidlen);
        uidlen >>= 1;
        if (uidlen != 7) {
             return usage_hf_st_sim();
        }
    }
    
    char param[40];
    snprintf(param, sizeof(param), "t 10 u %s", sprint_hex_inrow(uid, uidlen));
    return CmdHF14ASim(param);
}

static int cmd_hf_st_ndef(const char *Cmd) {
    char c = tolower(param_getchar(Cmd, 0));
    if (c == 'h' || c == 0x00) return usage_hf_st_ndef();

    int pwdlen = 0;    
    uint8_t cmdp = 0;
    uint8_t pwd[16] = {0};
    if (c == 'p') {
        param_gethex_ex(Cmd, cmdp + 1, pwd, &pwdlen);
        pwdlen >>= 1;
        if (pwdlen != 16) {
             return usage_hf_st_ndef();
        }
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
    if (res)
        return res;

    if (resplen < 2)
        return PM3_ESOFT;

    uint16_t sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "Selecting NDEF aid failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return PM3_ESOFT;
    }

    activate_field = false;
    keep_field_on = true;

    // ---------------  NDEF file reading ----------------
    uint8_t aSELECT_FILE_NDEF[30];
    int aSELECT_FILE_NDEF_n = 0;
    param_gethex_to_eol("00a4000c020001", 0, aSELECT_FILE_NDEF, sizeof(aSELECT_FILE_NDEF), &aSELECT_FILE_NDEF_n);    
    res = ExchangeAPDU14a(aSELECT_FILE_NDEF, aSELECT_FILE_NDEF_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res)
        return res;

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "Selecting NDEF file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return PM3_ESOFT;
    }

    // ---------------  VERIFY ----------------   
    uint8_t aVERIFY[30];
    int aVERIFY_n = 0;
    param_gethex_to_eol("0020000100", 0, aVERIFY, sizeof(aVERIFY), &aVERIFY_n);
    res = ExchangeAPDU14a(aVERIFY, aVERIFY_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res)
        return res;

    sw = get_sw(response, resplen);
    if (sw == 0x6300) {
        // need to provide 16byte password
        param_gethex_to_eol("0020000110", 0, aVERIFY, sizeof(aVERIFY), &aVERIFY_n);
        memcpy(aVERIFY + aVERIFY_n, pwd, pwdlen);
        res = ExchangeAPDU14a(aVERIFY, aVERIFY_n + pwdlen, activate_field, keep_field_on, response, sizeof(response), &resplen);
        if (res)
            return res;

        sw = get_sw(response, resplen);       
        if (sw != 0x9000) {
            PrintAndLogEx(ERR, "Verify password failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
            return PM3_ESOFT;
        }
    }
   
    keep_field_on = false;
    uint8_t aREAD_NDEF[30];
    int aREAD_NDEF_n = 0;
    param_gethex_to_eol("00b000001d", 0, aREAD_NDEF, sizeof(aREAD_NDEF), &aREAD_NDEF_n);    
    res = ExchangeAPDU14a(aREAD_NDEF, aREAD_NDEF_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res)
        return res;

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "reading NDEF file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return PM3_ESOFT;
    }

    NDEFRecordsDecodeAndPrint(response + 2, resplen - 4);
    return PM3_SUCCESS;
}

static int cmd_hf_st_protect(const char *Cmd) {
    
    uint8_t cmdp = 0;
    bool errors = false;
    int pwdlen = 0;
    uint8_t pwd[16] = {0};
    int statelen = 3;
    uint8_t state[3] = {0x26, 0, 0};
    
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_st_protect();
            case '0': 
                state[0] = 0x26;  //Disable protection
                cmdp++;
                break;
            case '1': 
                state[0] = 0x28;  //Enable protection
                cmdp++;
                break;
            case 'r':
                state[2] = 0x01;
                cmdp++;
                break;
            case 'w':
                state[2] = 0x02;
                cmdp++;
                break;
            case 'p':
                param_gethex_ex(Cmd, cmdp + 1, pwd, &pwdlen);
                pwdlen >>= 1;
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations

    if (state[2] == 0x00) {
         PrintAndLogEx(WARNING, "Missing action (r)ead or (w)rite");
         errors = true;
    }
    if (pwdlen != 16) {
         PrintAndLogEx(WARNING, "Missing 16 byte password");
         errors = true;
    } 
    
    if (errors || cmdp == 0) return usage_hf_st_protect();

    bool activate_field = true;
    bool keep_field_on = true;
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;

    // ---------------  Select NDEF Tag application ----------------    
    uint8_t aSELECT_AID[80];
    int aSELECT_AID_n = 0;
    param_gethex_to_eol("00a4040007d276000085010100", 0, aSELECT_AID, sizeof(aSELECT_AID), &aSELECT_AID_n);    
    int res = ExchangeAPDU14a(aSELECT_AID, aSELECT_AID_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res)
        return res;

    if (resplen < 2)
        return PM3_ESOFT;

    uint16_t sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "Selecting NDEF aid failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return PM3_ESOFT;
    }

    activate_field = false;
    keep_field_on = true;

    // ---------------  Select NDEF file ----------------
    uint8_t aSELECT_FILE_NDEF[30];
    int aSELECT_FILE_NDEF_n = 0;
    param_gethex_to_eol("00a4000c020001", 0, aSELECT_FILE_NDEF, sizeof(aSELECT_FILE_NDEF), &aSELECT_FILE_NDEF_n);    
    res = ExchangeAPDU14a(aSELECT_FILE_NDEF, aSELECT_FILE_NDEF_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res)
        return res;

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "Selecting NDEF file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return PM3_ESOFT;
    }

    // ---------------  VERIFY ----------------   
    uint8_t aVERIFY[30];
    int aVERIFY_n = 0;
    // need to provide 16byte password
    param_gethex_to_eol("0020000210", 0, aVERIFY, sizeof(aVERIFY), &aVERIFY_n);
    memcpy(aVERIFY + aVERIFY_n, pwd, pwdlen);
    res = ExchangeAPDU14a(aVERIFY, aVERIFY_n + pwdlen, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res)
        return res;

    sw = get_sw(response, resplen);       
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "Verify password failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return PM3_ESOFT;
    }
    
    // ---------------  Change protection ----------------
    keep_field_on = false;
    uint8_t aPROTECT[30];
    int aPROTECT_n = 0;
    param_gethex_to_eol("00", 0, aPROTECT, sizeof(aPROTECT), &aPROTECT_n);
    memcpy(aPROTECT + aPROTECT_n, state, statelen);
    res = ExchangeAPDU14a(aPROTECT, aPROTECT_n + statelen, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res)
        return res;

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "changing protection failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return PM3_ESOFT;
    }
    
    PrintAndLogEx(SUCCESS, " %s protection ( %s )", ((state[2] & 0x01) == 0x01) ? _YELLOW_("read") : _YELLOW_("write"), 
                                                    ((state[0] & 0x28) == 0x28) ? _RED_("enabled") : _GREEN_("disabled"));

    return PM3_SUCCESS;
}

static int cmd_hf_st_pwd(const char *Cmd) {
    char c = tolower(param_getchar(Cmd, 0));
    if (c == 'h' || c == 0x00) return usage_hf_st_pwd();

    uint8_t cmdp = 0;
    bool errors = false;
    int pwdlen = 0;    
    uint8_t pwd[16] = {0};
    int newpwdlen = 0;    
    uint8_t newpwd[16] = {0};
    int changePwdlen = 4;
    uint8_t changePwd[4] = {0x24, 0x00, 0x00, 0x10};

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_st_pwd();
            case 'r':
                changePwd[2] = 0x01;
                cmdp++;
                break;
            case 'w':
                changePwd[2] = 0x02;
                cmdp++;
                break;
            case 'p':
                param_gethex_ex(Cmd, cmdp + 1, pwd, &pwdlen);
                pwdlen >>= 1;
                cmdp += 2;
                break;
            case 'n':
                param_gethex_ex(Cmd, cmdp + 1, newpwd, &newpwdlen);
                newpwdlen >>= 1;
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations

    if (changePwd[2] == 0x00) {
         PrintAndLogEx(WARNING, "Missing password specification: (r)ead or (w)rite");
         errors = true;
    }
    if (pwdlen != 16) {
         PrintAndLogEx(WARNING, "Missing original 16 byte password");
         errors = true;
    } 
    if (newpwdlen != 16) {
         PrintAndLogEx(WARNING, "Missing new 16 byte password");
         errors = true;
    } 
    if (errors || cmdp == 0) return usage_hf_st_pwd();

    bool activate_field = true;
    bool keep_field_on = true;
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;

    // ---------------  Select NDEF Tag application ----------------    
    uint8_t aSELECT_AID[80];
    int aSELECT_AID_n = 0;
    param_gethex_to_eol("00a4040007d276000085010100", 0, aSELECT_AID, sizeof(aSELECT_AID), &aSELECT_AID_n);    
    int res = ExchangeAPDU14a(aSELECT_AID, aSELECT_AID_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res)
        return res;

    if (resplen < 2)
        return PM3_ESOFT;

    uint16_t sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "Selecting NDEF aid failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return PM3_ESOFT;
    }

    activate_field = false;
    keep_field_on = true;

    // ---------------  Select NDEF file ----------------
    uint8_t aSELECT_FILE_NDEF[30];
    int aSELECT_FILE_NDEF_n = 0;
    param_gethex_to_eol("00a4000c020001", 0, aSELECT_FILE_NDEF, sizeof(aSELECT_FILE_NDEF), &aSELECT_FILE_NDEF_n);    
    res = ExchangeAPDU14a(aSELECT_FILE_NDEF, aSELECT_FILE_NDEF_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res)
        return res;

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "Selecting NDEF file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return PM3_ESOFT;
    }

    // ---------------  VERIFY ----------------   
    uint8_t aVERIFY[30];
    int aVERIFY_n = 0;
    // need to provide 16byte password
    param_gethex_to_eol("0020000210", 0, aVERIFY, sizeof(aVERIFY), &aVERIFY_n);
    memcpy(aVERIFY + aVERIFY_n, pwd, pwdlen);
    res = ExchangeAPDU14a(aVERIFY, aVERIFY_n + pwdlen, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res)
        return res;

    sw = get_sw(response, resplen);       
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "Verify password failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
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
    if (res)
        return res;

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "password change failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return PM3_ESOFT;
    }
    PrintAndLogEx(SUCCESS, " %s password changed", ((changePwd[2] & 0x01) == 0x01) ? _YELLOW_("read") : _YELLOW_("write"));

    return PM3_SUCCESS;

}

static int cmd_hf_st_list(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdTraceList("7816");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help", CmdHelp,              AlwaysAvailable, "This help"},
    {"info", cmd_hf_st_info,       IfPm3Iso14443a,  "Tag information"},
    {"list", cmd_hf_st_list,       AlwaysAvailable, "List ISO 14443A/7816 history"},
    {"ndef", cmd_hf_st_ndef,       AlwaysAvailable, "read NDEF file on tag"},
    {"protect", cmd_hf_st_protect, IfPm3Iso14443a,  "change protection on tag"},
    {"pwd",  cmd_hf_st_pwd,        IfPm3Iso14443a,  "change password on tag"},
    {"sim",  cmd_hf_st_sim,        IfPm3Iso14443a,  "Fake ISO 14443A/ST tag"},
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
