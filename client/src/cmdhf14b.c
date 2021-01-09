//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
// Modified 2018, 2020 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency ISO14443B commands
//-----------------------------------------------------------------------------

#include "cmdhf14b.h"
#include <ctype.h>
#include "iso14b.h"
#include "fileutils.h"
#include "cmdparser.h"     // command_t
#include "commonutil.h"    // ARRAYLEN
#include "comms.h"         // clearCommandBuffer
#include "emv/emvcore.h"   // TLVPrintFromBuffer
#include "cmdtrace.h"
#include "cliparser.h"
#include "crc16.h"
#include "cmdhf14a.h"
#include "protocols.h"     // definitions of ISO14B/7816 protocol
#include "emv/apduinfo.h"  // GetAPDUCodeDescription
#include "mifare/ndef.h"   // NDEFRecordsDecodeAndPrint
#include "aidsearch.h"


#define TIMEOUT 2000
#define APDU_TIMEOUT 2000

// iso14b apdu input frame length
static uint16_t apdu_frame_length = 0;
uint16_t ats_fsc[] = {16, 24, 32, 40, 48, 64, 96, 128, 256};
bool apdu_in_framing_enable = true;

static int CmdHelp(const char *Cmd);

static int usage_hf_14b_write_srx(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf 14b [h] sriwrite <1|2> <block> <data>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h        this help");
    PrintAndLogEx(NORMAL, "       <1|2>    1 = SRIX4K , 2 = SRI512");
    PrintAndLogEx(NORMAL, "       <block>  (hex) block number depends on tag, special block == FF");
    PrintAndLogEx(NORMAL, "       <data>   hex bytes of data to be written");
    PrintAndLogEx(NORMAL, "Example:");
    PrintAndLogEx(NORMAL, _YELLOW_("       hf 14b sriwrite 1 7F 11223344"));
    PrintAndLogEx(NORMAL, _YELLOW_("       hf 14b sriwrite 1 FF 11223344"));
    PrintAndLogEx(NORMAL, _YELLOW_("       hf 14b sriwrite 2 15 11223344"));
    PrintAndLogEx(NORMAL, _YELLOW_("       hf 14b sriwrite 2 FF 11223344"));
    return PM3_SUCCESS;
}

static int switch_off_field_14b(void) {
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443B_COMMAND, ISO14B_DISCONNECT, 0, 0, NULL, 0);
    return PM3_SUCCESS;
}

static uint16_t get_sw(uint8_t *d, uint8_t n) {
    if (n < 2)
        return 0;

    n -= 2;
    return d[n] * 0x0100 + d[n + 1];
}

static void hf14b_aid_search(bool verbose) {

    int elmindx = 0;
    json_t *root = AIDSearchInit(verbose);
    if (root == NULL)  {
        switch_off_field_14b();
        return;
    }

    PrintAndLogEx(INFO, "-------------------- " _CYAN_("AID Search") " --------------------");

    bool found = false;
    bool leave_signal_on = true;
    bool activate_field = true;
    for (elmindx = 0; elmindx < json_array_size(root); elmindx++) {

        if (kbd_enter_pressed()) {
            break;
        }

        json_t *data = AIDSearchGetElm(root, elmindx);
        uint8_t vaid[200] = {0};
        int vaidlen = 0;
        if (!AIDGetFromElm(data, vaid, sizeof(vaid), &vaidlen) || !vaidlen)
            continue;


        // COMPUTE APDU
        uint8_t apdu_data[PM3_CMD_DATA_SIZE] = {0};
        int apdu_len = 0;
        sAPDU apdu = (sAPDU) {0x00, 0xa4, 0x04, 0x00, vaidlen, vaid};

        if (APDUEncodeS(&apdu, false, 0x00, apdu_data, &apdu_len)) {
            PrintAndLogEx(ERR, "APDU encoding error.");
            return;
        }

        PrintAndLogEx(DEBUG, ">>>> %s", sprint_hex(apdu_data, apdu_len));

        int resultlen = 0;
        uint8_t result[1024] = {0};
        int res = exchange_14b_apdu(apdu_data, apdu_len, activate_field, leave_signal_on, result, sizeof(result), &resultlen, -1);
        activate_field = false;
        if (res)
            continue;

        uint16_t sw = get_sw(result, resultlen);

        uint8_t dfname[200] = {0};
        size_t dfnamelen = 0;
        if (resultlen > 3) {
            struct tlvdb *tlv = tlvdb_parse_multi(result, resultlen);
            if (tlv) {
                // 0x84 Dedicated File (DF) Name
                const struct tlv *dfnametlv = tlvdb_get_tlv(tlvdb_find_full(tlv, 0x84));
                if (dfnametlv) {
                    dfnamelen = dfnametlv->len;
                    memcpy(dfname, dfnametlv->value, dfnamelen);
                }
                tlvdb_free(tlv);
            }
        }

        if (sw == 0x9000 || sw == 0x6283 || sw == 0x6285) {
            if (sw == 0x9000) {
                if (verbose) PrintAndLogEx(SUCCESS, "Application ( " _GREEN_("ok") " )");
            } else {
                if (verbose) PrintAndLogEx(WARNING, "Application ( " _RED_("blocked") " )");
            }

            PrintAIDDescriptionBuf(root, vaid, vaidlen, verbose);

            if (dfnamelen) {
                if (dfnamelen == vaidlen) {
                    if (memcmp(dfname, vaid, vaidlen) == 0) {
                        if (verbose) PrintAndLogEx(INFO, "(DF) Name found and equal to AID");
                    } else {
                        PrintAndLogEx(INFO, "(DF) Name not equal to AID: %s :", sprint_hex(dfname, dfnamelen));
                        PrintAIDDescriptionBuf(root, dfname, dfnamelen, verbose);
                    }
                } else {
                    PrintAndLogEx(INFO, "(DF) Name not equal to AID: %s :", sprint_hex(dfname, dfnamelen));
                    PrintAIDDescriptionBuf(root, dfname, dfnamelen, verbose);
                }
            } else {
                if (verbose) PrintAndLogEx(INFO, "(DF) Name not found");
            }

            if (verbose) PrintAndLogEx(SUCCESS, "----------------------------------------------------");
            found = true;
        }
    }
    switch_off_field_14b();
    if (verbose == false && found)
        PrintAndLogEx(INFO, "----------------------------------------------------");
}

static bool wait_cmd_14b(bool verbose, bool is_select) {

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT)) {

        uint16_t len = (resp.oldarg[1] & 0xFFFF);
        uint8_t *data = resp.data.asBytes;

        // handle select responses
        if (is_select) {

            // 0: OK; -1: attrib fail; -2:crc fail
            int status = (int)resp.oldarg[0];
            if (status == 0) {

                if (verbose) {
                    PrintAndLogEx(SUCCESS, "received " _YELLOW_("%u") " bytes", len);
                    PrintAndLogEx(SUCCESS, "%s", sprint_hex(data, len));
                }
                return true;
            } else {
                return false;
            }
        }

        // handle raw bytes responses
        if (verbose) {

            if (len >= 3) {
                bool crc = check_crc(CRC_14443_B, data, len);

                PrintAndLogEx(SUCCESS, "received " _YELLOW_("%u") " bytes", len);
                PrintAndLogEx(SUCCESS, "%s[%02X %02X] %s",
                              sprint_hex(data, len - 2),
                              data[len - 2],
                              data[len - 1],
                              (crc) ? _GREEN_("ok") : _RED_("fail")
                             );
            } else if (len == 0) {
                if (verbose)
                    PrintAndLogEx(INFO, "no response from tag");
            } else {
                PrintAndLogEx(SUCCESS, "%s", sprint_hex(data, len));
            }
        }
        return true;
    } else {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        return false;
    }
}

static int CmdHF14BList(const char *Cmd) {
    char args[128] = {0};
    if (strlen(Cmd) == 0) {
        snprintf(args, sizeof(args), "-t 14b");
    } else {
        strncpy(args, Cmd, sizeof(args) - 1);
    }
    return CmdTraceList(args);
}

static int CmdHF14BSim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14b sim",
                  "Simulate a ISO/IEC 14443 type B tag with 4 byte UID / PUPI",
                  "hf 14b sim -u 11AA33BB"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_strx0("u", "uid", "hex", "4byte UID/PUPI"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t pupi[4];
    int n = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), pupi, sizeof(pupi), &n);
    CLIParserFree(ctx);

    if (res) {
        PrintAndLogEx(FAILED, "failed to read pupi");
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "Simulate with PUPI : " _GREEN_("%s"), sprint_hex_inrow(pupi, sizeof(pupi)));
    PrintAndLogEx(INFO, "Press pm3-button to abort simulation");
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443B_SIMULATE, pupi, sizeof(pupi));
    return PM3_SUCCESS;
}

static int CmdHF14BSniff(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14b sniff",
                  "Sniff the communication reader and tag",
                  "hf 14b sniff"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443B_SNIFF, NULL, 0);

    WaitForResponse(CMD_HF_ISO14443B_SNIFF, &resp);

    PrintAndLogEx(HINT, "Try `" _YELLOW_("hf 14b list") "` to view captured tracelog");
    PrintAndLogEx(HINT, "Try `" _YELLOW_("trace save h") "` to save tracelog for later analysing");
    return PM3_SUCCESS;
}

static int CmdHF14BCmdRaw(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14b raw",
                  "Sends raw bytes to card",
                  "hf 14b raw -cks      --data 0200a40400    -> standard select\n"
                  "hf 14b raw -ck --sr  --data 0200a40400    -> SRx select\n"
                  "hf 14b raw -ck --cts --data 0200a40400    -> C-ticket select\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k", "keep",           "leave the signal field ON after receive response"),
        arg_lit0("s", "std",            "activate field, use ISO14B select"),
        arg_lit0(NULL, "sr",            "activate field, use SRx ST select"),
        arg_lit0(NULL, "cts",           "activate field, use ASK C-ticket select"),
        arg_lit0("c", "crc",            "calculate and append CRC"),
        arg_lit0("r", "noresponse",         "do not read response from card"),
        arg_int0("t", "timeout",   "<dec>", "timeout in ms"),
        arg_lit0("v", "verbose",            "verbose"),
        arg_strx0("d", "data",     "<hex>", "data, bytes to send"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool keep_field_on = arg_get_lit(ctx, 1);
    bool select_std = arg_get_lit(ctx, 2);
    bool select_sr = arg_get_lit(ctx, 3);
    bool select_cts = arg_get_lit(ctx, 4);
    bool add_crc = arg_get_lit(ctx, 5);
    bool read_reply = !arg_get_lit(ctx, 6);
    int user_timeout = arg_get_int_def(ctx, 7, -1);
    bool verbose = arg_get_lit(ctx, 8);

    uint32_t flags = ISO14B_CONNECT;
    if (add_crc) {
        flags |= ISO14B_APPEND_CRC;
    }

    if (select_std) {
        flags |= (ISO14B_SELECT_STD | ISO14B_CLEARTRACE);
        if (verbose)
            PrintAndLogEx(INFO, "using ISO14443-B select");
    } else if (select_sr) {
        flags |= (ISO14B_SELECT_SR | ISO14B_CLEARTRACE);
        if (verbose)
            PrintAndLogEx(INFO, "using ST/SRx select");
    } else if (select_cts) {
        flags |= (ISO14B_SELECT_CTS | ISO14B_CLEARTRACE);
        if (verbose)
            PrintAndLogEx(INFO, "using ASK/C-ticket select");
    }

    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00};
    int datalen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 9), data, sizeof(data), &datalen);
    if (res && verbose) {
        PrintAndLogEx(INFO, "called with no raw bytes");
    }
    CLIParserFree(ctx);

    uint32_t time_wait = 0;
    if (user_timeout > 0) {

#define MAX_14B_TIMEOUT 40542464 // = (2^32-1) * (8*16) / 13560000Hz * 1000ms/s
        flags |= ISO14B_SET_TIMEOUT;
        if (user_timeout > MAX_14B_TIMEOUT) {
            user_timeout = MAX_14B_TIMEOUT;
            PrintAndLogEx(INFO, "set timeout to 40542 seconds (11.26 hours). The max we can wait for response");
        }
        time_wait = 13560000 / 1000 / (8 * 16) * user_timeout; // timeout in ETUs (time to transfer 1 bit, approx. 9.4 us)
        if (verbose)
            PrintAndLogEx(INFO, "using timeout %u", user_timeout);
    }

    if (keep_field_on == 0)
        flags |= ISO14B_DISCONNECT;

    if (datalen > 0)
        flags |= ISO14B_RAW;

    // Max buffer is PM3_CMD_DATA_SIZE
    datalen = (datalen > PM3_CMD_DATA_SIZE) ? PM3_CMD_DATA_SIZE : datalen;

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443B_COMMAND, flags, datalen, time_wait, data, datalen);
    if (read_reply == false) {
        clearCommandBuffer();
        return PM3_SUCCESS;
    }

    bool success = true;

    // Select, device will send back iso14b_card_select_t, don't print it.
    if (select_std) {
        success = wait_cmd_14b(verbose, true);
        if (verbose && success)
            PrintAndLogEx(SUCCESS, "Got response for standard select");
    }

    if (select_sr) {
        success = wait_cmd_14b(verbose, true);
        if (verbose && success)
            PrintAndLogEx(SUCCESS, "Got response for ST/SRx select");
    }

    if (select_cts) {
        success = wait_cmd_14b(verbose, true);
        if (verbose && success)
            PrintAndLogEx(SUCCESS, "Got response for ASK/C-ticket select");
    }

    // get back response from the raw bytes you sent.
    if (success && datalen > 0) {
        wait_cmd_14b(true, false);
    }

    return PM3_SUCCESS;
}

static bool get_14b_UID(iso14b_card_select_t *card) {

    if (card == NULL)
        return false;

    int status = 0;

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443B_COMMAND, ISO14B_CONNECT | ISO14B_SELECT_SR | ISO14B_DISCONNECT, 0, 0, NULL, 0);
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT)) {

        status = resp.oldarg[0];
        if (status == 0) {
            memcpy(card, (iso14b_card_select_t *)resp.data.asBytes, sizeof(iso14b_card_select_t));
            return true;
        }
    }

    // test 14b standard
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443B_COMMAND, ISO14B_CONNECT | ISO14B_SELECT_STD | ISO14B_DISCONNECT, 0, 0, NULL, 0);
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT)) {

        status = resp.oldarg[0];
        if (status == 0) {
            memcpy(card, (iso14b_card_select_t *)resp.data.asBytes, sizeof(iso14b_card_select_t));
            return true;
        }
    }

    PrintAndLogEx(WARNING, "timeout while waiting for reply.");
    return false;
}

// print full atqb info
// bytes
// 0,1,2,3 = application data
// 4       = bit rate capacity
// 5       = max frame size / -4 info
// 6       = FWI / Coding options
static int print_atqb_resp(uint8_t *data, uint8_t cid) {
    //PrintAndLogEx(SUCCESS, "           UID: %s", sprint_hex(data+1,4));
    PrintAndLogEx(SUCCESS, "      App Data: %s", sprint_hex(data, 4));
    PrintAndLogEx(SUCCESS, "      Protocol: %s", sprint_hex(data + 4, 3));
    uint8_t BitRate = data[4];
    if (!BitRate) PrintAndLogEx(SUCCESS, "      Bit Rate: 106 kbit/s only PICC <-> PCD");
    if (BitRate & 0x10) PrintAndLogEx(SUCCESS, "      Bit Rate: 212 kbit/s PICC -> PCD supported");
    if (BitRate & 0x20) PrintAndLogEx(SUCCESS, "      Bit Rate: 424 kbit/s PICC -> PCD supported");
    if (BitRate & 0x40) PrintAndLogEx(SUCCESS, "      Bit Rate: 847 kbit/s PICC -> PCD supported");
    if (BitRate & 0x01) PrintAndLogEx(SUCCESS, "      Bit Rate: 212 kbit/s PICC <- PCD supported");
    if (BitRate & 0x02) PrintAndLogEx(SUCCESS, "      Bit Rate: 424 kbit/s PICC <- PCD supported");
    if (BitRate & 0x04) PrintAndLogEx(SUCCESS, "      Bit Rate: 847 kbit/s PICC <- PCD supported");
    if (BitRate & 0x80) PrintAndLogEx(SUCCESS, "                Same bit rate <-> required");

    uint16_t maxFrame = data[5] >> 4;
    if (maxFrame < 5)       maxFrame = 8 * maxFrame + 16;
    else if (maxFrame == 5) maxFrame = 64;
    else if (maxFrame == 6) maxFrame = 96;
    else if (maxFrame == 7) maxFrame = 128;
    else if (maxFrame == 8) maxFrame = 256;
    else maxFrame = 257;

    PrintAndLogEx(SUCCESS, "Max Frame Size: %u%s bytes", maxFrame, (maxFrame == 257) ? "+ RFU" : "");

    uint8_t protocolT = data[5] & 0xF;
    PrintAndLogEx(SUCCESS, " Protocol Type: Protocol is %scompliant with ISO/IEC 14443-4", (protocolT) ? "" : "not ");

    uint8_t fwt = data[6] >> 4;
    if (fwt < 16) {
        uint32_t etus = (32 << fwt);
        uint32_t fwt_time = (302 << fwt);
        PrintAndLogEx(SUCCESS, "Frame Wait Integer: %u - %u ETUs | %u us", fwt, etus, fwt_time);
    } else {
        PrintAndLogEx(SUCCESS, "Frame Wait Integer: %u - RFU", fwt);
    }

    PrintAndLogEx(SUCCESS, " App Data Code: Application is %s", (data[6] & 4) ? "Standard" : "Proprietary");
    PrintAndLogEx(SUCCESS, " Frame Options: NAD is %ssupported", (data[6] & 2) ? "" : "not ");
    PrintAndLogEx(SUCCESS, " Frame Options: CID is %ssupported", (data[6] & 1) ? "" : "not ");
    PrintAndLogEx(SUCCESS, "Tag :");
    PrintAndLogEx(SUCCESS, "  Max Buf Length: %u (MBLI) %s", cid >> 4, (cid & 0xF0) ? "" : "chained frames not supported");
    PrintAndLogEx(SUCCESS, "  CID : %u", cid & 0x0f);
    return PM3_SUCCESS;
}

// get SRx chip model (from UID) // from ST Microelectronics
static char *get_st_chip_model(uint8_t data) {
    static char model[20];
    char *retStr = model;
    memset(model, 0, sizeof(model));

    switch (data) {
        case 0x0:
            sprintf(retStr, "SRIX4K (Special)");
            break;
        case 0x2:
            sprintf(retStr, "SR176");
            break;
        case 0x3:
            sprintf(retStr, "SRIX4K");
            break;
        case 0x4:
            sprintf(retStr, "SRIX512");
            break;
        case 0x6:
            sprintf(retStr, "SRI512");
            break;
        case 0x7:
            sprintf(retStr, "SRI4K");
            break;
        case 0xC:
            sprintf(retStr, "SRT512");
            break;
        default :
            sprintf(retStr, "Unknown");
            break;
    }
    return retStr;
}

static char *get_st_lock_info(uint8_t model, uint8_t *lockbytes, uint8_t blk) {

    static char str[16];
    char *s = str;
    sprintf(s, " ");

    if (blk > 15) {
        return s;
    }

    uint8_t mask = 0;
    switch (model) {
        case 0x0:   // SRIX4K special
        case 0x3:   // SRIx4K
        case 0x7: { // SRI4K
            //only need data[3]
            switch (blk) {
                case 7:
                case 8:
                    mask = 0x01;
                    break;
                case 9:
                    mask = 0x02;
                    break;
                case 10:
                    mask = 0x04;
                    break;
                case 11:
                    mask = 0x08;
                    break;
                case 12:
                    mask = 0x10;
                    break;
                case 13:
                    mask = 0x20;
                    break;
                case 14:
                    mask = 0x40;
                    break;
                case 15:
                    mask = 0x80;
                    break;
                default:
                    return s;
            }
            if ((lockbytes[1] & mask) == 0) {
                sprintf(s, _RED_("1"));
            }
            return s;
        }
        case 0x4:   // SRIX512
        case 0x6:   // SRI512
        case 0xC: { // SRT512
            //need data[2] and data[3]
            uint8_t b = 1;
            switch (blk) {
                case 0:
                    mask = 0x01;
                    break;
                case 1:
                    mask = 0x02;
                    break;
                case 2:
                    mask = 0x04;
                    break;
                case 3:
                    mask = 0x08;
                    break;
                case 4:
                    mask = 0x10;
                    break;
                case 5:
                    mask = 0x20;
                    break;
                case 6:
                    mask = 0x40;
                    break;
                case 7:
                    mask = 0x80;
                    break;
                case 8:
                    mask = 0x01;
                    b = 0;
                    break;
                case 9:
                    mask = 0x02;
                    b = 0;
                    break;
                case 10:
                    mask = 0x04;
                    b = 0;
                    break;
                case 11:
                    mask = 0x08;
                    b = 0;
                    break;
                case 12:
                    mask = 0x10;
                    b = 0;
                    break;
                case 13:
                    mask = 0x20;
                    b = 0;
                    break;
                case 14:
                    mask = 0x40;
                    b = 0;
                    break;
                case 15:
                    mask = 0x80;
                    b = 0;
                    break;
            }
            if ((lockbytes[b] & mask) == 0) {
                sprintf(s, _RED_("1"));
            }
            return s;
        }
        case 0x2: {  // SR176
            //need data[2]
            switch (blk) {
                case 0:
                case 1:
                    mask = 0x1;
                    break;
                case 2:
                case 3:
                    mask = 0x2;
                    break;
                case 4:
                case 5:
                    mask = 0x4;
                    break;
                case 6:
                case 7:
                    mask = 0x8;
                    break;
                case 8:
                case 9:
                    mask = 0x10;
                    break;
                case 10:
                case 11:
                    mask = 0x20;
                    break;
                case 12:
                case 13:
                    mask = 0x40;
                    break;
                case 14:
                case 15:
                    mask = 0x80;
                    break;
            }
            // iceman:  this is opposite!  need sample to test with.
            if ((lockbytes[0] & mask)) {
                sprintf(s, _RED_("1"));
            }
            return s;
        }
        default:
            break;
    }
    return s;
}

static uint8_t get_st_chipid(uint8_t *uid) {
    return uid[5] >> 2;
}

static uint8_t get_st_cardsize(uint8_t *uid) {
    uint8_t chipid = get_st_chipid(uid);
    switch (chipid) {
        case 0x0:
        case 0x3:
        case 0x7:
            return 1;
        case 0x4:
        case 0x6:
        case 0xC:
            return 2;
        default:
            return 0;
    }
    return 0;
}

// print UID info from SRx chips (ST Microelectronics)
static void print_st_general_info(uint8_t *data, uint8_t len) {
    //uid = first 8 bytes in data
    uint8_t mfgid = data[6];
    uint8_t chipid = get_st_chipid(data);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, " UID: " _GREEN_("%s"), sprint_hex(SwapEndian64(data, 8, 8), len));
    PrintAndLogEx(SUCCESS, " MFG: %02X, " _YELLOW_("%s"), mfgid, getTagInfo(mfgid));
    PrintAndLogEx(SUCCESS, "Chip: %02X, " _YELLOW_("%s"), chipid, get_st_chip_model(chipid));
}

// print UID info from ASK CT chips
static void print_ct_general_info(void *vcard) {
    iso14b_cts_card_select_t card;
    memcpy(&card, (iso14b_cts_card_select_t *)vcard, sizeof(iso14b_cts_card_select_t));

    uint32_t uid32 = (card.uid[0] | card.uid[1] << 8 | card.uid[2] << 16 | card.uid[3] << 24);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "ASK C-Ticket");
    PrintAndLogEx(SUCCESS, "           UID: " _GREEN_("%s") " ( " _YELLOW_("%010u") " )", sprint_hex(card.uid, sizeof(card.uid)), uid32);
    PrintAndLogEx(SUCCESS, "  Product Code: %02X", card.pc);
    PrintAndLogEx(SUCCESS, " Facility Code: %02X", card.fc);
    PrintAndLogEx(NORMAL, "");
}

// iceman, calypso?
// 05 00 00 = find one tag in field
// 1d xx xx xx xx 00 08 01 00 = attrib xx=UID (resp 10 [f9 e0])
// 0200a40400 (resp 02 67 00 [29 5b])
// 0200a4040c07a0000002480300 (resp 02 67 00 [29 5b])
// 0200a4040c07a0000002480200 (resp 02 67 00 [29 5b])
// 0200a4040006a0000000010100 (resp 02 6a 82 [4b 4c])
// 0200a4040c09d27600002545500200 (resp 02 67 00 [29 5b])
// 0200a404000cd2760001354b414e4d30310000 (resp 02 6a 82 [4b 4c])
// 0200a404000ca000000063504b43532d313500 (resp 02 6a 82 [4b 4c])
// 0200a4040010a000000018300301000000000000000000 (resp 02 6a 82 [4b 4c])

// 14b get and print Full Info (as much as we know)
static bool HF14B_Std_Info(bool verbose, bool do_aid_search) {

    bool is_success = false;

    // 14b get and print UID only (general info)
    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandMIX(CMD_HF_ISO14443B_COMMAND, ISO14B_CONNECT | ISO14B_SELECT_STD | ISO14B_DISCONNECT, 0, 0, NULL, 0);

    if (!WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT)) {
        if (verbose) PrintAndLogEx(WARNING, "timeout while waiting for reply");
        switch_off_field_14b();
        return is_success;
    }

    iso14b_card_select_t card;
    memcpy(&card, (iso14b_card_select_t *)resp.data.asBytes, sizeof(iso14b_card_select_t));

    int status = resp.oldarg[0];

    switch (status) {
        case 0: {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, "-------------------- " _CYAN_("Tag information") " --------------------");
            PrintAndLogEx(SUCCESS, " UID    : " _GREEN_("%s"), sprint_hex(card.uid, card.uidlen));
            PrintAndLogEx(SUCCESS, " ATQB   : %s", sprint_hex(card.atqb, sizeof(card.atqb)));
            PrintAndLogEx(SUCCESS, " CHIPID : %02X", card.chipid);
            print_atqb_resp(card.atqb, card.cid);

            if (do_aid_search) {
                hf14b_aid_search(verbose);
            }

            is_success = true;
            break;
        }
        case -1:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-3 ATTRIB fail");
            break;
        case -2:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-3 CRC fail");
            break;
        default:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-b card select failed");
            break;
    }

    return is_success;
}

// SRx get and print full info (needs more info...)
static bool HF14B_ST_Info(bool verbose, bool do_aid_search) {
    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandMIX(CMD_HF_ISO14443B_COMMAND, ISO14B_CONNECT | ISO14B_SELECT_SR | ISO14B_DISCONNECT, 0, 0, NULL, 0);

    if (!WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT)) {
        if (verbose) PrintAndLogEx(WARNING, "timeout while waiting for reply");
        return false;
    }

    iso14b_card_select_t card;
    memcpy(&card, (iso14b_card_select_t *)resp.data.asBytes, sizeof(iso14b_card_select_t));

    int status = resp.oldarg[0];
    if (status < 0)
        return false;

    print_st_general_info(card.uid, card.uidlen);

    if (do_aid_search) {
        hf14b_aid_search(verbose);
    }
    return true;
}

// menu command to get and print all info known about any known 14b tag
static int CmdHF14Binfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14b info",
                  "Tag information for ISO/IEC 14443 type B based tags",
                  "hf 14b info\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("s",  "aidsearch", "checks if AIDs from aidlist.json is present on the card and prints information about found AIDs"),
        arg_lit0("v", "verbose", "verbose"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool do_aid_search = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);
    return infoHF14B(verbose, do_aid_search);
}

static bool HF14B_st_reader(bool verbose) {

    bool is_success = false;

    // SRx get and print general info about SRx chip from UID
    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandMIX(CMD_HF_ISO14443B_COMMAND, ISO14B_CONNECT | ISO14B_SELECT_SR | ISO14B_DISCONNECT, 0, 0, NULL, 0);

    if (!WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT)) {
        if (verbose) PrintAndLogEx(WARNING, "timeout while waiting for reply");
        return is_success;
    }

    iso14b_card_select_t card;
    memcpy(&card, (iso14b_card_select_t *)resp.data.asBytes, sizeof(iso14b_card_select_t));

    int status = resp.oldarg[0];

    switch (status) {
        case 0:
            print_st_general_info(card.uid, card.uidlen);
            is_success = true;
            break;
        case -1:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-3 ST ATTRIB fail");
            break;
        case -2:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-3 ST CRC fail");
            break;
        case -3:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-3 ST random chip id fail");
            break;
        default:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-b ST card select SRx failed");
            break;
    }
    return is_success;
}

static bool HF14B_std_reader(bool verbose) {

    bool is_success = false;

    // 14b get and print UID only (general info)
    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandMIX(CMD_HF_ISO14443B_COMMAND, ISO14B_CONNECT | ISO14B_SELECT_STD | ISO14B_DISCONNECT, 0, 0, NULL, 0);

    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT) == false) {
        if (verbose) PrintAndLogEx(WARNING, "timeout while waiting for reply");
        return false;
    }

    int status = resp.oldarg[0];

    switch (status) {
        case 0: {
            iso14b_card_select_t card;
            memcpy(&card, (iso14b_card_select_t *)resp.data.asBytes, sizeof(iso14b_card_select_t));
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(SUCCESS, " UID    : " _GREEN_("%s"), sprint_hex(card.uid, card.uidlen));
            PrintAndLogEx(SUCCESS, " ATQB   : %s", sprint_hex(card.atqb, sizeof(card.atqb)));
            PrintAndLogEx(SUCCESS, " CHIPID : %02X", card.chipid);
            print_atqb_resp(card.atqb, card.cid);
            is_success = true;
            break;
        }
        case -1: {
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-3 ATTRIB fail");
            break;
        }
        case -2: {
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-3 CRC fail");
            break;
        }
        default: {
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-b card select failed");
            break;
        }
    }
    return is_success;
}

static bool HF14B_ask_ct_reader(bool verbose) {

    bool is_success = false;

    // 14b get and print UID only (general info)
    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandMIX(CMD_HF_ISO14443B_COMMAND, ISO14B_CONNECT | ISO14B_SELECT_CTS | ISO14B_DISCONNECT, 0, 0, NULL, 0);
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT) == false) {
        if (verbose) PrintAndLogEx(WARNING, "timeout while waiting for reply");
        return false;
    }

    int status = resp.oldarg[0];

    switch (status) {
        case 0: {
            print_ct_general_info(resp.data.asBytes);
            is_success = true;
            break;
        }
        case -1: {
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-3 CTS wrong length");
            break;
        }
        case -2: {
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-3 CTS CRC fail");
            break;
        }
        default: {
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-b CTS card select failed");
            break;
        }
    }
    return is_success;
}

// test for other 14b type tags (mimic another reader - don't have tags to identify)
static bool HF14B_other_reader(bool verbose) {

    uint8_t data[] = {0x00, 0x0b, 0x3f, 0x80};
    uint8_t datalen = 4;

    // 14b get and print UID only (general info)
    uint32_t flags = ISO14B_CONNECT | ISO14B_SELECT_STD | ISO14B_RAW | ISO14B_APPEND_CRC;

    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandMIX(CMD_HF_ISO14443B_COMMAND, flags, datalen, 0, data, datalen);

    if (!WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT)) {
        if (verbose) PrintAndLogEx(WARNING, "timeout while waiting for reply");
        switch_off_field_14b();
        return false;
    }
    int status = resp.oldarg[0];
    PrintAndLogEx(DEBUG, "status %d", status);

    if (status == 0) {
        PrintAndLogEx(SUCCESS, "\n14443-3b tag found:");
        PrintAndLogEx(SUCCESS, "unknown tag type answered to a 0x000b3f80 command ans:");
        switch_off_field_14b();
        return true;
    } else if (status > 0) {
        PrintAndLogEx(SUCCESS, "\n14443-3b tag found:");
        PrintAndLogEx(SUCCESS, "unknown tag type answered to a 0x000b3f80 command ans:");
        PrintAndLogEx(SUCCESS, "%s", sprint_hex(resp.data.asBytes, status));
        switch_off_field_14b();
        return true;
    }

    data[0] = ISO14443B_AUTHENTICATE;
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443B_COMMAND, flags, 1, 0, data, 1);
    if (!WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT)) {
        if (verbose) PrintAndLogEx(WARNING, "timeout while waiting for reply");
        switch_off_field_14b();
        return false;
    }
    status = resp.oldarg[0];
    PrintAndLogEx(DEBUG, "status %d", status);

    if (status == 0) {
        PrintAndLogEx(SUCCESS, "\n14443-3b tag found:");
        PrintAndLogEx(SUCCESS, "Unknown tag type answered to a 0x0A command ans:");
        switch_off_field_14b();
        return true;
    } else if (status > 0) {
        PrintAndLogEx(SUCCESS, "\n14443-3b tag found:");
        PrintAndLogEx(SUCCESS, "unknown tag type answered to a 0x0A command ans:");
        PrintAndLogEx(SUCCESS, "%s", sprint_hex(resp.data.asBytes, status));
        switch_off_field_14b();
        return true;
    }

    data[0] = ISO14443B_RESET;
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443B_COMMAND, flags, 1, 0, data, 1);
    if (!WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT)) {
        if (verbose) PrintAndLogEx(WARNING, "timeout while waiting for reply");
        switch_off_field_14b();
        return false;
    }
    status = resp.oldarg[0];
    PrintAndLogEx(DEBUG, "status %d", status);

    if (status == 0) {
        PrintAndLogEx(SUCCESS, "\n14443-3b tag found:");
        PrintAndLogEx(SUCCESS, "Unknown tag type answered to a 0x0C command ans:");
        switch_off_field_14b();
        return true;
    } else if (status > 0) {
        PrintAndLogEx(SUCCESS, "\n14443-3b tag found:");
        PrintAndLogEx(SUCCESS, "unknown tag type answered to a 0x0C command ans:");
        PrintAndLogEx(SUCCESS, "%s", sprint_hex(resp.data.asBytes, status));
        switch_off_field_14b();
        return true;
    }

    switch_off_field_14b();
    return false;
}

// menu command to get and print general info about all known 14b chips
static int CmdHF14BReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14b reader",
                  "Act as a 14443B reader to identify a tag",
                  "hf 14b reader\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "verbose"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool verbose = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);
    return readHF14B(verbose);
}

// Read SRI512|SRIX4K block
static int CmdHF14BSriRdBl(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14b rdbl",
                  "Read SRI512 | SRIX4K block",
                  "hf 14b rdbl -b 06\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("b", "block",   "<dec>", "block number"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int blockno = arg_get_int_def(ctx, 1, -1);
    CLIParserFree(ctx);

    /*
        iso14b_card_select_t card;
        if (get_14b_UID(&card) == false) {
            PrintAndLogEx(WARNING, "no tag found");
            return PM3_SUCCESS;
        }

        if (card.uidlen != 8) {
            PrintAndLogEx(FAILED, "current read command only work with SRI4K / SRI512 tags");
            return PM3_SUCCESS;
        }

        // detect cardsize
        // 1 = 4096
        // 2 = 512
        uint8_t cardtype = get_st_cardsize(card.uid);
        uint8_t blocks = (cardtype == 1) ? 0x7F : 0x0F;
    */
    struct {
        uint8_t blockno;
    } PACKED payload;

    payload.blockno = blockno;

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_SRI_READ, (uint8_t *)&payload, sizeof(payload));
    if (WaitForResponseTimeout(CMD_HF_SRI_READ, &resp, TIMEOUT) == false) {
        return PM3_ETIMEOUT;
    }
    if (resp.status == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "block %02u : " _GREEN_("%s") " | " _GREEN_("%s"), blockno, sprint_hex(resp.data.asBytes, resp.length), sprint_ascii(resp.data.asBytes, resp.length));
    }
    return resp.status;
}

// New command to write a SRI512/SRIX4K tag.
static int CmdHF14BWriteSri(const char *Cmd) {
    /*
     * For SRIX4K  blocks 00 - 7F
     * hf 14b raw --sr -c --data [09 $srix4kwblock $srix4kwdata
     *
     * For SR512  blocks 00 - 0F
     * hf 14b raw --sr -c --data [09 $sr512wblock $sr512wdata]
     *
     * Special block FF =  otp_lock_reg block.
     * Data len 4 bytes-
     */
    char cmdp = tolower(param_getchar(Cmd, 0));
    uint8_t blockno = -1;
    uint8_t data[4] = {0x00};
    bool isSrix4k = true;
    char str[30];
    memset(str, 0x00, sizeof(str));

    if (strlen(Cmd) < 1 || cmdp == 'h') return usage_hf_14b_write_srx();

    if (cmdp == '2')
        isSrix4k = false;

    //blockno = param_get8(Cmd, 1);

    if (param_gethex(Cmd, 1, &blockno, 2)) {
        PrintAndLogEx(WARNING, "block number must include 2 HEX symbols");
        return 0;
    }

    if (isSrix4k) {
        if (blockno > 0x7f && blockno != 0xff) {
            PrintAndLogEx(FAILED, "block number out of range");
            return PM3_ESOFT;
        }
    } else {
        if (blockno > 0x0f && blockno != 0xff) {
            PrintAndLogEx(FAILED, "block number out of range");
            return PM3_ESOFT;
        }
    }

    if (param_gethex(Cmd, 2, data, 8)) {
        PrintAndLogEx(WARNING, "data must include 8 HEX symbols");
        return PM3_ESOFT;
    }

    if (blockno == 0xff) {
        PrintAndLogEx(SUCCESS, "[%s] Write special block %02X [ " _YELLOW_("%s")" ]",
                      (isSrix4k) ? "SRIX4K" : "SRI512",
                      blockno,
                      sprint_hex(data, 4)
                     );
    } else {
        PrintAndLogEx(SUCCESS, "[%s] Write block %02X [ " _YELLOW_("%s")" ]",
                      (isSrix4k) ? "SRIX4K" : "SRI512",
                      blockno,
                      sprint_hex(data, 4)
                     );
    }

    sprintf(str, "--sr -c --data %02x%02x%02x%02x%02x%02x", ISO14443B_WRITE_BLK, blockno, data[0], data[1], data[2], data[3]);
    return CmdHF14BCmdRaw(str);
}

// need to write to file
static int CmdHF14BDump(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14b dump",
                  "This command dumps the contents of a ISO-14443-B tag and save it to file\n"
                  "Tries to autodetect cardtype, memory size defaults to SRI4K",
                  "hf 14b dump\n"
                  "hf 14b dump -f myfilename\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_strx0("f", "file", "<filename>", "(optional) filename,  if no <name> UID will be used as filename"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    char *fptr = filename;
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    iso14b_card_select_t card;
    if (get_14b_UID(&card) == false) {
        PrintAndLogEx(WARNING, "no tag found");
        return PM3_SUCCESS;
    }

    if (card.uidlen != 8) {
        PrintAndLogEx(FAILED, "current dump command only work with SRI4K / SRI512 tags");
        return PM3_SUCCESS;
    }

    // detect cardsize
    // 1 = 4096
    // 2 = 512
    uint8_t cardtype = get_st_cardsize(card.uid);
    uint8_t blocks = 0;
    uint16_t cardsize = 0;

    switch (cardtype) {
        case 2:
            cardsize = (512 / 8) + 4;
            blocks = 0x0F;
            break;
        case 1:
        default:
            cardsize = (4096 / 8) + 4;
            blocks = 0x7F;
            break;
    }

    if (fnlen < 1) {
        PrintAndLogEx(INFO, "using UID as filename");
        fptr += sprintf(fptr, "hf-14b-");
        FillFileNameByUID(fptr, SwapEndian64(card.uid, card.uidlen, 8), "-dump", card.uidlen);
    }

    uint8_t chipid = get_st_chipid(card.uid);
    PrintAndLogEx(SUCCESS, "found a " _GREEN_("%s") " tag", get_st_chip_model(chipid));

    // detect blocksize from card :)
    PrintAndLogEx(INFO, "reading tag memory from UID " _GREEN_("%s"), sprint_hex_inrow(SwapEndian64(card.uid, card.uidlen, 8), card.uidlen));

    uint8_t data[cardsize];
    memset(data, 0, sizeof(data));
    uint8_t *recv = NULL;
    int status = 0;

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443B_COMMAND,  ISO14B_CONNECT | ISO14B_SELECT_SR, 0, 0, NULL, 0);

    //select
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, 2000)) {
        status = resp.oldarg[0];
        if (status < 0) {
            PrintAndLogEx(FAILED, "failed to select arg0[%" PRId64 "] arg1 [%" PRId64 "]", resp.oldarg[0], resp.oldarg[1]);
            goto out;
        }
    }

    PrintAndLogEx(INFO, "." NOLF);

    uint8_t req[2] = {ISO14443B_READ_BLK};
    int blocknum = 0;
    for (int retry = 0; retry < 5; retry++) {

        req[1] = blocknum;

        clearCommandBuffer();
        SendCommandMIX(CMD_HF_ISO14443B_COMMAND, ISO14B_APPEND_CRC | ISO14B_RAW, 2, 0, req, sizeof(req));

        if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, 2000)) {

            status = resp.oldarg[0];
            if (status < 0) {
                PrintAndLogEx(FAILED, "retrying one more time");
                continue;
            }

            uint16_t len = (resp.oldarg[1] & 0xFFFF);
            recv = resp.data.asBytes;

            if (check_crc(CRC_14443_B, recv, len) == false) {
                PrintAndLogEx(FAILED, "crc fail, retrying one more time");
                continue;
            }

            memcpy(data + (blocknum * 4), resp.data.asBytes, 4);

            // last read.
            if (blocknum == 0xFF) {
                break;
            }

            retry = 0;
            blocknum++;
            if (blocknum > blocks) {
                // read config block
                blocknum = 0xFF;
            }

            PrintAndLogEx(NORMAL, "." NOLF);
            fflush(stdout);
        }
    }
    PrintAndLogEx(NORMAL, "");

    if (blocknum != 0xFF) {
        PrintAndLogEx(FAILED, "dump failed");
        goto out;
    }

    PrintAndLogEx(DEBUG, "systemblock : %s", sprint_hex(data + (blocknum * 4), 4));
    PrintAndLogEx(DEBUG, "   otp lock : %02x %02x", data[(blocknum * 4)], data[(blocknum * 4) + 1]);


    PrintAndLogEx(INFO, " block#  | data         |lck| ascii");
    PrintAndLogEx(INFO, "---------+--------------+---+----------");

    for (int i = 0; i <= blocks; i++) {
        PrintAndLogEx(INFO,
                      "%3d/0x%02X | %s | %s | %s",
                      i,
                      i,
                      sprint_hex(data + (i * 4), 4),
                      get_st_lock_info(chipid, data + (blocknum * 4), i),
                      sprint_ascii(data + (i * 4), 4)
                     );
    }

    PrintAndLogEx(INFO,
                  "%3d/0x%02X | %s | %s | %s",
                  0xFF,
                  0xFF,
                  sprint_hex(data + (0xFF * 4), 4),
                  get_st_lock_info(chipid, data + (blocknum * 4), 0xFF),
                  sprint_ascii(data + (0xFF * 4), 4)
                 );
    PrintAndLogEx(INFO, "---------+--------------+---+----------");
    PrintAndLogEx(NORMAL, "");

    // save to file
    size_t datalen = (blocks + 1) * 4;
    saveFileEML(filename, data, datalen, 4);
    saveFile(filename, ".bin", data, datalen);
    // JSON?
out:
    return switch_off_field_14b();
}
/*

static uint32_t srix4kEncode(uint32_t value) {
    // vv = value
    // pp = position
    //                vv vv vv pp
    // 4 bytes      : 00 1A 20 01
    // only the lower crumbs.
    uint8_t block = (value & 0xFF);
    uint8_t i = 0;
    uint8_t valuebytes[] = {0, 0, 0};

    num_to_bytes(value, 3, valuebytes);

    // Scrambled part
    // Crumb swapping of value.
    uint8_t temp[] = {0, 0};
    temp[0] = (CRUMB(value, 22) << 4 | CRUMB(value, 14) << 2 | CRUMB(value, 6)) << 4;
    temp[0] |= CRUMB(value, 20) << 4 | CRUMB(value, 12) << 2 | CRUMB(value, 4);
    temp[1] = (CRUMB(value, 18) << 4 | CRUMB(value, 10) << 2 | CRUMB(value, 2)) << 4;
    temp[1] |= CRUMB(value, 16) << 4 | CRUMB(value, 8) << 2 | CRUMB(value, 0);

    // chksum part
    uint32_t chksum = 0xFF - block;

    // chksum is reduced by each nibbles of value.
    for (i = 0; i < 3; ++i) {
        chksum -= NIBBLE_HIGH(valuebytes[i]);
        chksum -= NIBBLE_LOW(valuebytes[i]);
    }

    // base4 conversion and left shift twice
    i = 3;
    uint8_t base4[] = {0, 0, 0, 0};
    while (chksum != 0) {
        base4[i--] = (chksum % 4 << 2);
        chksum /= 4;
    }

    // merge scambled and chksum parts
    uint32_t encvalue =
        (NIBBLE_LOW(base4[0]) << 28) |
        (NIBBLE_HIGH(temp[0])  << 24) |

        (NIBBLE_LOW(base4[1]) << 20) |
        (NIBBLE_LOW(temp[0])  << 16) |

        (NIBBLE_LOW(base4[2]) << 12) |
        (NIBBLE_HIGH(temp[1])  << 8) |

        (NIBBLE_LOW(base4[3]) << 4) |
        NIBBLE_LOW(temp[1]);

    PrintAndLogEx(NORMAL, "ICE encoded | %08X -> %08X", value, encvalue);
    return encvalue;
}

static uint32_t srix4kDecode(uint32_t value) {
    switch (value) {
        case 0xC04F42C5:
            return 0x003139;
        case 0xC1484807:
            return 0x002943;
        case 0xC0C60848:
            return 0x001A20;
    }
    return 0;
}

static uint32_t srix4kDecodeCounter(uint32_t num) {
    uint32_t value = ~num;
    ++value;
    return value;
}

static uint32_t srix4kGetMagicbytes(uint64_t uid, uint32_t block6, uint32_t block18, uint32_t block19) {
#define MASK 0xFFFFFFFF;
    uint32_t uid32 = uid & MASK;
    uint32_t counter = srix4kDecodeCounter(block6);
    uint32_t decodedBlock18 = srix4kDecode(block18);
    uint32_t decodedBlock19 = srix4kDecode(block19);
    uint32_t doubleBlock = (decodedBlock18 << 16 | decodedBlock19) + 1;

    uint32_t result = (uid32 * doubleBlock * counter) & MASK;
    PrintAndLogEx(SUCCESS, "Magic bytes | %08X", result);
    return result;
}

static int srix4kValid(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far

    uint64_t uid = 0xD00202501A4532F9;
    uint32_t block6 = 0xFFFFFFFF;
    uint32_t block18 = 0xC04F42C5;
    uint32_t block19 = 0xC1484807;
    uint32_t block21 = 0xD1BCABA4;

    uint32_t test_b18 = 0x00313918;
    uint32_t test_b18_enc = srix4kEncode(test_b18);
    //uint32_t test_b18_dec = srix4kDecode(test_b18_enc);
    PrintAndLogEx(SUCCESS, "ENCODE & CHECKSUM |  %08X -> %08X (%s)", test_b18, test_b18_enc, "");

    uint32_t magic = srix4kGetMagicbytes(uid, block6, block18, block19);
    PrintAndLogEx(SUCCESS, "BLOCK 21 |  %08X -> %08X (no XOR)", block21, magic ^ block21);
    return 0;
}
*/

static int select_card_14443b_4(bool disconnect, iso14b_card_select_t *card) {

    PacketResponseNG resp;
    if (card)
        memset(card, 0, sizeof(iso14b_card_select_t));

    switch_off_field_14b();

    // Anticollision + SELECT STD card
    SendCommandMIX(CMD_HF_ISO14443B_COMMAND, ISO14B_CONNECT | ISO14B_SELECT_STD, 0, 0, NULL, 0);
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT) == false) {
        PrintAndLogEx(INFO, "Trying 14B Select SRx");

        // Anticollision + SELECT SR card
        SendCommandMIX(CMD_HF_ISO14443B_COMMAND, ISO14B_CONNECT | ISO14B_SELECT_SR, 0, 0, NULL, 0);
        if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT) == false) {
            PrintAndLogEx(INFO, "Trying 14B Select CTS");

            // Anticollision + SELECT ASK C-Ticket card
            SendCommandMIX(CMD_HF_ISO14443B_COMMAND, ISO14B_CONNECT | ISO14B_SELECT_CTS, 0, 0, NULL, 0);
            if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT) == false) {
                PrintAndLogEx(ERR, "connection timeout");
                switch_off_field_14b();
                return PM3_ESOFT;
            }
        }
    }

    // check result
    int status = resp.oldarg[0];
    if (status < 0) {
        PrintAndLogEx(ERR, "No card in field.");
        switch_off_field_14b();
        return PM3_ESOFT;
    }

    apdu_frame_length = 0;
    // get frame length from ATS in card data structure
    iso14b_card_select_t *vcard = (iso14b_card_select_t *) resp.data.asBytes;
//    uint8_t fsci = vcard->atqb[1] & 0x0f;
//    if (fsci < ARRAYLEN(ats_fsc)) {
//        apdu_frame_length = ats_fsc[fsci];
//    }

    if (card) {
        memcpy(card, vcard, sizeof(iso14b_card_select_t));
    }

    if (disconnect) {
        switch_off_field_14b();
    }
    return PM3_SUCCESS;
}

static int handle_14b_apdu(bool chainingin, uint8_t *datain, int datainlen, bool activateField, uint8_t *dataout, int maxdataoutlen, int *dataoutlen, bool *chainingout, int user_timeout) {
    *chainingout = false;

    if (activateField) {
        // select with no disconnect and set frameLength
        int selres = select_card_14443b_4(false, NULL);
        if (selres != PM3_SUCCESS)
            return selres;
    }

    uint16_t flags = 0;

    if (chainingin)
        flags = ISO14B_SEND_CHAINING;

    uint32_t time_wait = 0;
    if (user_timeout > 0) {
#define MAX_14B_TIMEOUT 40542464 // = (2^32-1) * (8*16) / 13560000Hz * 1000ms/s
        flags |= ISO14B_SET_TIMEOUT;
        if (user_timeout > MAX_14B_TIMEOUT) {
            user_timeout = MAX_14B_TIMEOUT;
            PrintAndLogEx(INFO, "set timeout to 40542 seconds (11.26 hours). The max we can wait for response");
        }
        time_wait = 13560000 / 1000 / (8 * 16) * user_timeout; // timeout in ETUs (time to transfer 1 bit, approx. 9.4 us)
    }

    // "Command APDU" length should be 5+255+1, but javacard's APDU buffer might be smaller - 133 bytes
    // https://stackoverflow.com/questions/32994936/safe-max-java-card-apdu-data-command-and-respond-size
    // here length PM3_CMD_DATA_SIZE=512
    if (datain)
        SendCommandMIX(CMD_HF_ISO14443B_COMMAND, ISO14B_APDU | flags, (datainlen & 0xFFFF), time_wait, datain, datainlen & 0xFFFF);
    else
        SendCommandMIX(CMD_HF_ISO14443B_COMMAND, ISO14B_APDU | flags, 0, time_wait, NULL, 0);

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, MAX(APDU_TIMEOUT, user_timeout))) {
        uint8_t *recv = resp.data.asBytes;
        int rlen = resp.oldarg[0];
        uint8_t res = resp.oldarg[1];

        int dlen = rlen - 2;
        if (dlen < 0) {
            dlen = 0;
        }

        *dataoutlen += dlen;

        if (maxdataoutlen && *dataoutlen > maxdataoutlen) {
            PrintAndLogEx(ERR, "APDU: Buffer too small(%d). Needs %d bytes", *dataoutlen, maxdataoutlen);
            return PM3_ESOFT;
        }

        // I-block ACK
        if ((res & 0xf2) == 0xa2) {
            *dataoutlen = 0;
            *chainingout = true;
            return PM3_SUCCESS;
        }

        if (rlen < 0) {
            PrintAndLogEx(ERR, "APDU: No APDU response.");
            return PM3_ESOFT;
        }

        // check apdu length
        if (rlen == 0 || rlen == 1) {
            PrintAndLogEx(ERR, "APDU: Small APDU response. Len=%d", rlen);
            return PM3_ESOFT;
        }

        memcpy(dataout, recv, dlen);

        // chaining
        if ((res & 0x10) != 0) {
            *chainingout = true;
        }

    } else {
        PrintAndLogEx(ERR, "APDU: Reply timeout.");
        return PM3_ETIMEOUT;
    }

    return PM3_SUCCESS;
}

int exchange_14b_apdu(uint8_t *datain, int datainlen, bool activate_field, bool leave_signal_on, uint8_t *dataout, int maxdataoutlen, int *dataoutlen, int user_timeout) {
    *dataoutlen = 0;
    bool chaining = false;
    int res;

    // 3 byte here - 1b framing header, 2b crc16
    if (apdu_in_framing_enable &&
            ((apdu_frame_length && (datainlen > apdu_frame_length - 3)) || (datainlen > PM3_CMD_DATA_SIZE - 3))) {

        int clen = 0;
        bool v_activate_field = activate_field;

        do {
            int vlen = MIN(apdu_frame_length - 3, datainlen - clen);
            bool chainBlockNotLast = ((clen + vlen) < datainlen);

            *dataoutlen = 0;
            res = handle_14b_apdu(chainBlockNotLast, &datain[clen], vlen, v_activate_field, dataout, maxdataoutlen, dataoutlen, &chaining, user_timeout);
            if (res) {
                if (leave_signal_on == false)
                    switch_off_field_14b();

                return 200;
            }

            // TODO check this one...
            // check R-block ACK
            // *dataoutlen!=0. 'A && (!A || B)' is equivalent to 'A && B'
            if ((*dataoutlen == 0) && (*dataoutlen != 0 || chaining != chainBlockNotLast)) {
                if (leave_signal_on == false) {
                    switch_off_field_14b();
                }
                return 201;
            }

            clen += vlen;
            v_activate_field = false;
            if (*dataoutlen) {
                if (clen != datainlen)
                    PrintAndLogEx(ERR, "APDU: I-block/R-block sequence error. Data len=%d, Sent=%d, Last packet len=%d", datainlen, clen, *dataoutlen);
                break;
            }
        } while (clen < datainlen);

    } else {

        res = handle_14b_apdu(false, datain, datainlen, activate_field, dataout, maxdataoutlen, dataoutlen, &chaining, user_timeout);
        if (res != PM3_SUCCESS) {
            if (leave_signal_on == false) {
                switch_off_field_14b();
            }
            return res;
        }
    }

    while (chaining) {
        // I-block with chaining
        res = handle_14b_apdu(false, NULL, 0, false, &dataout[*dataoutlen], maxdataoutlen, dataoutlen, &chaining, user_timeout);
        if (res != PM3_SUCCESS) {
            if (leave_signal_on == false) {
                switch_off_field_14b();
            }
            return 100;
        }
    }

    if (leave_signal_on == false) {
        switch_off_field_14b();
    }

    return PM3_SUCCESS;
}

// ISO14443-4. 7. Half-duplex block transmission protocol
static int CmdHF14BAPDU(const char *Cmd) {
    uint8_t data[PM3_CMD_DATA_SIZE];
    int datalen = 0;
    uint8_t header[PM3_CMD_DATA_SIZE];
    int headerlen = 0;
    bool activate_field = false;
    bool leave_signal_on = false;
    bool decode_TLV = false;
    bool decode_APDU = false;
    bool make_APDU = false;
    bool extended_APDU = false;
    int le = 0;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14b apdu",
                  "Sends an ISO 7816-4 APDU via ISO 14443-4 block transmission protocol (T=CL). works with all apdu types from ISO 7816-4:2013",
                  "hf 14b apdu -s  --hex 94a40800043f000002\n"
                  "hf 14b apdu -sd --hex 00A404000E325041592E5359532E444446303100        -> decode apdu\n"
                  "hf 14b apdu -sm 00A40400 -l 256    --hex 325041592E5359532E4444463031 -> encode standard apdu\n"
                  "hf 14b apdu -sm 00A40400 -el 65536 --hex 325041592E5359532E4444463031 -> encode extended apdu\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("s",  "select",   "activate field and select card"),
        arg_lit0("k",  "keep",     "leave the signal field ON after receive response"),
        arg_lit0("t",  "tlv",      "executes TLV decoder if it possible"),
        arg_lit0("d",  "decode",   "decode apdu request if it possible"),
        arg_str0("m",  "make",     "<hex>", "make apdu with head from this field and data from data field. Must be 4 bytes length: <CLA INS P1 P2>"),
        arg_lit0("e",  "extended", "make extended length apdu if `m` parameter included"),
        arg_int0("l",  "le",       "<int>", "Le apdu parameter if `m` parameter included"),
        arg_strx1(NULL, "hex",     "<hex>", "<APDU | data> if `m` parameter included"),
        arg_int0(NULL, "timeout",   "<dec>", "timeout in ms"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    activate_field = arg_get_lit(ctx, 1);
    leave_signal_on = arg_get_lit(ctx, 2);
    decode_TLV = arg_get_lit(ctx, 3);
    decode_APDU = arg_get_lit(ctx, 4);

    CLIGetHexWithReturn(ctx, 5, header, &headerlen);
    make_APDU = headerlen > 0;
    if (make_APDU && headerlen != 4) {
        PrintAndLogEx(ERR, "header length must be 4 bytes instead of %d", headerlen);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    extended_APDU = arg_get_lit(ctx, 6);
    le = arg_get_int_def(ctx, 7, 0);

    if (make_APDU) {
        uint8_t apdudata[PM3_CMD_DATA_SIZE] = {0};
        int apdudatalen = 0;

        CLIGetHexBLessWithReturn(ctx, 8, apdudata, &apdudatalen, 1 + 2);

        APDUStruct apdu;
        apdu.cla = header[0];
        apdu.ins = header[1];
        apdu.p1 = header[2];
        apdu.p2 = header[3];

        apdu.lc = apdudatalen;
        apdu.data = apdudata;

        apdu.extended_apdu = extended_APDU;
        apdu.le = le;

        if (APDUEncode(&apdu, data, &datalen)) {
            PrintAndLogEx(ERR, "can't make apdu with provided parameters.");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }

    } else {
        if (extended_APDU) {
            PrintAndLogEx(ERR, "make mode not set but here `e` option.");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
        if (le > 0) {
            PrintAndLogEx(ERR, "make mode not set but here `l` option.");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }

        // len = data + PCB(1b) + CRC(2b)
        CLIGetHexBLessWithReturn(ctx, 8, data, &datalen, 1 + 2);
    }
    int user_timeout = arg_get_int_def(ctx, 9, -1);
    CLIParserFree(ctx);

    PrintAndLogEx(NORMAL, ">>>>[%s%s%s] %s",
                  activate_field ? "sel" : "",
                  leave_signal_on ? " keep" : "",
                  decode_TLV ? " TLV" : "",
                  sprint_hex(data, datalen)
                 );

    if (decode_APDU) {
        APDUStruct apdu;
        if (APDUDecode(data, datalen, &apdu) == 0)
            APDUPrint(apdu);
        else
            PrintAndLogEx(WARNING, "can't decode APDU.");
    }

    int res = exchange_14b_apdu(data, datalen, activate_field, leave_signal_on, data, PM3_CMD_DATA_SIZE, &datalen, user_timeout);
    if (res != PM3_SUCCESS) {
        return res;
    }

    PrintAndLogEx(NORMAL, "<<<< %s", sprint_hex(data, datalen));
    PrintAndLogEx(SUCCESS, "APDU response: " _YELLOW_("%02x %02x") " - %s", data[datalen - 2], data[datalen - 1], GetAPDUCodeDescription(data[datalen - 2], data[datalen - 1]));

    // TLV decoder
    if (decode_TLV && datalen > 4) {
        TLVPrintFromBuffer(data, datalen - 2);
    }

    return PM3_SUCCESS;
}

static int CmdHF14BNdef(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14b ndef",
                  "Print NFC Data Exchange Format (NDEF)",
                  "hf 14b ndef"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    bool activate_field = true;
    bool keep_field_on = true;
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;

    // ---------------  Select NDEF Tag application ----------------
    uint8_t aSELECT_AID[80];
    int aSELECT_AID_n = 0;
    param_gethex_to_eol("00a4040007d276000085010100", 0, aSELECT_AID, sizeof(aSELECT_AID), &aSELECT_AID_n);
    int res = exchange_14b_apdu(aSELECT_AID, aSELECT_AID_n, activate_field, keep_field_on, response, sizeof(response), &resplen, -1);
    if (res) {
        goto out;
    }

    if (resplen < 2) {
        res = PM3_ESOFT;
        goto out;
    }

    uint16_t sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "Selecting NDEF aid failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        res = PM3_ESOFT;
        goto out;
    }

    activate_field = false;
    keep_field_on = true;
    // ---------------  Send CC select ----------------
    // ---------------  Read binary ----------------

    // ---------------  NDEF file reading ----------------
    uint8_t aSELECT_FILE_NDEF[30];
    int aSELECT_FILE_NDEF_n = 0;
    param_gethex_to_eol("00a4000c020001", 0, aSELECT_FILE_NDEF, sizeof(aSELECT_FILE_NDEF), &aSELECT_FILE_NDEF_n);
    res = exchange_14b_apdu(aSELECT_FILE_NDEF, aSELECT_FILE_NDEF_n, activate_field, keep_field_on, response, sizeof(response), &resplen, -1);
    if (res)
        goto out;

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "Selecting NDEF file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        res = PM3_ESOFT;
        goto out;
    }

    // ---------------  Read binary ----------------
    uint8_t aREAD_NDEF[30];
    int aREAD_NDEF_n = 0;
    param_gethex_to_eol("00b0000002", 0, aREAD_NDEF, sizeof(aREAD_NDEF), &aREAD_NDEF_n);
    res = exchange_14b_apdu(aREAD_NDEF, aREAD_NDEF_n, activate_field, keep_field_on, response, sizeof(response), &resplen, -1);
    if (res) {
        goto out;
    }

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "reading NDEF file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        res = PM3_ESOFT;
        goto out;
    }
    // take offset from response
    uint8_t offset = response[1];

    // ---------------  Read binary w offset ----------------
    keep_field_on = false;
    aREAD_NDEF_n = 0;
    param_gethex_to_eol("00b00002", 0, aREAD_NDEF, sizeof(aREAD_NDEF), &aREAD_NDEF_n);
    aREAD_NDEF[4] = offset;
    res = exchange_14b_apdu(aREAD_NDEF, aREAD_NDEF_n, activate_field, keep_field_on, response, sizeof(response), &resplen, -1);
    if (res) {
        goto out;
    }

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "reading NDEF file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        res = PM3_ESOFT;
        goto out;
    }

    res = NDEFRecordsDecodeAndPrint(response + 2, resplen - 4);

out:
    switch_off_field_14b();
    return res;
}

static command_t CommandTable[] = {
    {"help",        CmdHelp,          AlwaysAvailable, "This help"},
    {"apdu",        CmdHF14BAPDU,     IfPm3Iso14443b,  "Send ISO 14443-4 APDU to tag"},
    {"dump",        CmdHF14BDump,     IfPm3Iso14443b,  "Read all memory pages of an ISO14443-B tag, save to file"},
    {"info",        CmdHF14Binfo,     IfPm3Iso14443b,  "Tag information"},
    {"list",        CmdHF14BList,     AlwaysAvailable, "List ISO 14443B history"},
    {"ndef",        CmdHF14BNdef,     IfPm3Iso14443b,  "Read NDEF file on tag"},
    {"raw",         CmdHF14BCmdRaw,   IfPm3Iso14443b,  "Send raw hex data to tag"},
    {"reader",      CmdHF14BReader,   IfPm3Iso14443b,  "Act as a 14443B reader to identify a tag"},
    {"sim",         CmdHF14BSim,      IfPm3Iso14443b,  "Fake ISO 14443B tag"},
    {"sniff",       CmdHF14BSniff,    IfPm3Iso14443b,  "Eavesdrop ISO 14443B"},
    {"rdbl",        CmdHF14BSriRdBl,  IfPm3Iso14443b,  "Read SRI512/SRIX4x block"},
    {"sriwrite",    CmdHF14BWriteSri, IfPm3Iso14443b,  "Write data to a SRI512 | SRIX4K tag"},
// {"valid",     srix4kValid,      AlwaysAvailable, "srix4k checksum test"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHF14B(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// get and print all info known about any known 14b tag
int infoHF14B(bool verbose, bool do_aid_search) {

    // try std 14b (atqb)
    if (HF14B_Std_Info(verbose, do_aid_search))
        return 1;

    // try ST 14b
    if (HF14B_ST_Info(verbose, do_aid_search))
        return 1;

    // try unknown 14b read commands (to be identified later)
    //   could be read of calypso, CEPAS, moneo, or pico pass.
    if (verbose) PrintAndLogEx(FAILED, "no 14443-B tag found");
    return 0;
}

// get and print general info about all known 14b chips
int readHF14B(bool verbose) {

    // try std 14b (atqb)
    if (HF14B_std_reader(verbose))
        return 1;

    // try ST Microelectronics 14b
    if (HF14B_st_reader(verbose))
        return 1;

    // try ASK CT 14b
    if (HF14B_ask_ct_reader(verbose))
        return 1;

    // try unknown 14b read commands (to be identified later)
    // could be read of calypso, CEPAS, moneo, or pico pass.
    if (HF14B_other_reader(verbose))
        return 1;

    if (verbose) PrintAndLogEx(FAILED, "no 14443-B tag found");
    return 0;
}
