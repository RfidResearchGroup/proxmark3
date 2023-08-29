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
#include "iso7816/apduinfo.h"  // GetAPDUCodeDescription
#include "nfc/ndef.h"   // NDEFRecordsDecodeAndPrint
#include "aidsearch.h"
#include "fileutils.h"     // saveFile

#define MAX_14B_TIMEOUT_MS (4949U)

// client side time out,  waiting for device to ask tag.
#define TIMEOUT         1000

// client side time out, waiting for device to ask tag a APDU to answer
#define APDU_TIMEOUT    2000

// for static arrays
#define ST25TB_SR_BLOCK_SIZE 4

// iso14b apdu input frame length
static uint16_t apdu_frame_length = 0;
//static uint16_t ats_fsc[] = {16, 24, 32, 40, 48, 64, 96, 128, 256};
static bool apdu_in_framing_enable = true;

static int CmdHelp(const char *Cmd);

static int switch_off_field_14b(void) {
    SetISODEPState(ISODEP_INACTIVE);
    iso14b_raw_cmd_t packet = {
        .flags = ISO14B_DISCONNECT,
        .timeout = 0,
        .rawlen = 0,
    };
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t));
    return PM3_SUCCESS;
}

static void hf14b_aid_search(bool verbose) {

    json_t *root = AIDSearchInit(verbose);
    if (root == NULL)  {
        switch_off_field_14b();
        return;
    }

    PrintAndLogEx(INFO, "-------------------- " _CYAN_("AID Search") " --------------------");

    bool found = false;
    bool leave_signal_on = true;
    bool activate_field = true;
    for (size_t elmindx = 0; elmindx < json_array_size(root); elmindx++) {

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
        sAPDU_t apdu = (sAPDU_t) {0x00, 0xa4, 0x04, 0x00, vaidlen, vaid};

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

        if (sw == ISO7816_OK || sw == ISO7816_INVALID_DF || sw == ISO7816_FILE_TERMINATED) {
            if (sw == ISO7816_OK) {
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

static bool wait_cmd_14b(bool verbose, bool is_select, uint32_t timeout) {

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, MAX(TIMEOUT, timeout)) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        return false;
    }

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
            PrintAndLogEx(SUCCESS, "%s[%02X %02X] ( %s )",
                          sprint_hex(data, len - 2),
                          data[len - 2],
                          data[len - 1],
                          (crc) ? _GREEN_("ok") : _RED_("fail")
                         );
        } else if (len == 0) {
            PrintAndLogEx(INFO, "no response from tag");
        } else {
            PrintAndLogEx(SUCCESS, "%s", sprint_hex(data, len));
        }
    }
    return true;
}

static int CmdHF14BList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf 14b", "14b");
}

static int CmdHF14BSim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14b sim",
                  "Simulate a ISO/IEC 14443 type B tag with 4 byte UID / PUPI",
                  "hf 14b sim -u 11AA33BB"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("u", "uid", "hex", "4byte UID/PUPI"),
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
    PrintAndLogEx(HINT, "Try `" _YELLOW_("trace save -h") "` to save tracelog for later analysing");
    return PM3_SUCCESS;
}

static int CmdHF14BCmdRaw(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14b raw",
                  "Sends raw bytes to card",
                  "hf 14b raw -cks      --data 0200a40400    -> standard select, apdu 0200a4000 (7816)\n"
                  "hf 14b raw -ck --sr  --data 0200a40400    -> SRx select\n"
                  "hf 14b raw -ck --cts --data 0200a40400    -> C-ticket select\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k", "keep", "leave the signal field ON after receive response"),
        arg_lit0("s", "std", "activate field, use ISO14B select"),
        arg_lit0(NULL, "sr", "activate field, use SRx ST select"),
        arg_lit0(NULL, "cts", "activate field, use ASK C-ticket select"),
        arg_lit0(NULL, "xrx", "activate field, use Fuji/Xerox select"),
        arg_lit0("c", "crc", "calculate and append CRC"),
        arg_lit0("r", NULL, "do not read response from card"),
        arg_int0("t", "timeout", "<dec>", "timeout in ms"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_str0("d", "data", "<hex>", "data, bytes to send"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool keep_field_on = arg_get_lit(ctx, 1);
    bool select_std = arg_get_lit(ctx, 2);
    bool select_sr = arg_get_lit(ctx, 3);
    bool select_cts = arg_get_lit(ctx, 4);
    bool select_xrx = arg_get_lit(ctx, 5);
    bool add_crc = arg_get_lit(ctx, 6);
    bool read_reply = (arg_get_lit(ctx, 7) == false);
    int user_timeout = arg_get_int_def(ctx, 8, -1);
    bool verbose = arg_get_lit(ctx, 9);

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
    } else if (select_xrx) {
        flags |= (ISO14B_SELECT_XRX | ISO14B_CLEARTRACE);
        if (verbose)
            PrintAndLogEx(INFO, "using Fuji/Xerox select");
    }

    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00};
    int datalen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 10), data, sizeof(data), &datalen);
    if (res && verbose) {
        PrintAndLogEx(INFO, "called with no raw bytes");
    }
    CLIParserFree(ctx);


    uint32_t time_wait = 0;
    if (user_timeout > 0) {

        flags |= ISO14B_SET_TIMEOUT;

        if (user_timeout > MAX_14B_TIMEOUT_MS) {
            user_timeout = MAX_14B_TIMEOUT_MS;
            PrintAndLogEx(INFO, "set timeout to 4.9 seconds. The max we can wait for response");
        }

        // timeout in ETUs (time to transfer 1 bit, approx. 9.4 us)
        time_wait = (uint32_t)((13560 / 128) * user_timeout);
        if (verbose)
            PrintAndLogEx(INFO, " new raw timeout :  %u ETU  ( %u ms )", time_wait, user_timeout);
    }

    if (keep_field_on == 0)
        flags |= ISO14B_DISCONNECT;

    if (datalen > 0)
        flags |= ISO14B_RAW;

    // Max buffer is PM3_CMD_DATA_SIZE
    datalen = (datalen > PM3_CMD_DATA_SIZE) ? PM3_CMD_DATA_SIZE : datalen;


    iso14b_raw_cmd_t *packet = (iso14b_raw_cmd_t *)calloc(1, sizeof(iso14b_raw_cmd_t) + datalen);
    if (packet == NULL) {
        PrintAndLogEx(FAILED, "failed to allocate memory");
        return PM3_EMALLOC;
    }
    packet->flags = flags;
    packet->timeout = time_wait;
    packet->rawlen = datalen;
    memcpy(packet->raw, data, datalen);

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)packet, sizeof(iso14b_raw_cmd_t) + packet->rawlen);
    free(packet);

    if (read_reply == false) {
        clearCommandBuffer();
        return PM3_SUCCESS;
    }

    bool success = true;

    // Select, device will send back iso14b_card_select_t, don't print it.
    if (select_std) {
        success = wait_cmd_14b(verbose, true, user_timeout);
        if (verbose && success)
            PrintAndLogEx(SUCCESS, "Got response for standard select");
    }

    if (select_sr) {
        success = wait_cmd_14b(verbose, true, user_timeout);
        if (verbose && success)
            PrintAndLogEx(SUCCESS, "Got response for ST/SRx select");
    }

    if (select_cts) {
        success = wait_cmd_14b(verbose, true, user_timeout);
        if (verbose && success)
            PrintAndLogEx(SUCCESS, "Got response for ASK/C-ticket select");
    }

    if (select_xrx) {
        success = wait_cmd_14b(verbose, true, user_timeout);
        if (verbose && success)
            PrintAndLogEx(SUCCESS, "Got response for Fuji/Xerox select");
    }

    // get back response from the raw bytes you sent.
    if (success && datalen > 0) {
        wait_cmd_14b(true, false, user_timeout);
    }

    return PM3_SUCCESS;
}

static bool get_14b_UID(uint8_t *d, iso14b_type_t *found_type) {

    // sanity checks
    if (d == NULL || found_type == NULL) {
        return false;
    }

    *found_type = ISO14B_NONE;

    iso14b_raw_cmd_t packet = {
        .flags = (ISO14B_CONNECT | ISO14B_SELECT_SR | ISO14B_DISCONNECT),
        .timeout = 0,
        .rawlen = 0,
    };

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t));
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT)) {

        if (resp.oldarg[0] == 0) {
            memcpy(d, resp.data.asBytes, sizeof(iso14b_card_select_t));

            iso14b_card_select_t *card = (iso14b_card_select_t*)d;
            uint8_t empty[] =  {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            if (memcmp(card->uid, empty, card->uidlen) == 0) {
                return false;
            }
            *found_type = ISO14B_SR;
            return true;
        }
    }

    // test 14b standard
    packet.flags = (ISO14B_CONNECT | ISO14B_SELECT_STD | ISO14B_DISCONNECT);
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t));
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT)) {

        if (resp.oldarg[0] == 0) {
            memcpy(d, resp.data.asBytes, sizeof(iso14b_card_select_t));
            *found_type = ISO14B_STANDARD;
            return true;
        }
    }

    // test CT
    packet.flags = (ISO14B_CONNECT | ISO14B_SELECT_CTS | ISO14B_DISCONNECT);
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t));
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT)) {

        if (resp.oldarg[0] == 0) {
            memcpy(d, resp.data.asBytes, sizeof(iso14b_cts_card_select_t));
            *found_type = ISO14B_CT;
            return true;
        }
    }

    PrintAndLogEx(WARNING, "timeout while waiting for reply");
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
    if (fwt < 15) {
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
static const char *get_st_chip_model(uint8_t data) {
    switch (data) {
        case 0x0:
            return "SRIX4K (Special)";
        case 0x2:
            return "SR176";
        case 0x3:
            return "SRIX4K";
        case 0x4:
            return "SRIX512";
        case 0x6:
            return "SRI512";
        case 0x7:
            return "SRI4K";
        case 0xC:
            return "SRT512";
        default :
            return "Unknown";
    }
}

#define ST_LOCK_INFO_EMPTY " "
static const char *get_st_lock_info(uint8_t model, const uint8_t *lockbytes, uint8_t blk) {
    if (blk > 15) {
        return ST_LOCK_INFO_EMPTY;
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
                    return ST_LOCK_INFO_EMPTY;
            }
            if ((lockbytes[1] & mask) == 0) {
                return _RED_("1");
            }
            return ST_LOCK_INFO_EMPTY;
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
                return _RED_("1");
            }
            return ST_LOCK_INFO_EMPTY;
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
                return _RED_("1");
            }
            return ST_LOCK_INFO_EMPTY;
        }
        default:
            break;
    }
    return ST_LOCK_INFO_EMPTY;
}

static uint8_t get_st_chipid(const uint8_t *uid) {
    return uid[5] >> 2;
}

static uint8_t get_st_cardsize(const uint8_t *uid) {
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

    uint32_t uid32 = MemLeToUint4byte(card.uid);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "ASK C-Ticket");
    PrintAndLogEx(SUCCESS, "           UID: " _GREEN_("%s") " ( " _YELLOW_("%010u") " )", sprint_hex(card.uid, sizeof(card.uid)), uid32);
    PrintAndLogEx(SUCCESS, "  Product Code: %02X", card.pc);
    PrintAndLogEx(SUCCESS, " Facility Code: %02X", card.fc);
    PrintAndLogEx(NORMAL, "");
}

static void print_hdr(void) {
    PrintAndLogEx(INFO, " block#  | data         |lck| ascii");
    PrintAndLogEx(INFO, "---------+--------------+---+----------");
}

static void print_footer(void) {
    PrintAndLogEx(INFO, "---------+--------------+---+----------");
    PrintAndLogEx(NORMAL, "");
}

/*
static void print_ct_blocks(uint8_t *data, size_t len) {

    size_t blocks = len / ST25TB_SR_BLOCK_SIZE;

    print_hdr();

    for (int i = 0; i <= blocks; i++) {
        PrintAndLogEx(INFO,
                      "%3d/0x%02X | %s | %s | %s",
                      i,
                      i,
                      sprint_hex(data + (i * 4), 4),
                      " ",
                      sprint_ascii(data + (i * 4), 4)
                     );
    }
    print_footer();
}
*/

static void print_sr_blocks(uint8_t *data, size_t len, const uint8_t *uid) {

    size_t blocks = (len / ST25TB_SR_BLOCK_SIZE) - 1 ;
    uint8_t *systemblock = data + blocks * ST25TB_SR_BLOCK_SIZE ;
    uint8_t chipid = get_st_chipid(uid);
    PrintAndLogEx(SUCCESS, _GREEN_("%s") " tag", get_st_chip_model(chipid));

    PrintAndLogEx(DEBUG, "systemblock : %s", sprint_hex(systemblock, ST25TB_SR_BLOCK_SIZE));
    PrintAndLogEx(DEBUG, "   otp lock : %02x %02x", *systemblock, *(systemblock + 1));

    print_hdr();

    for (int i = 0; i < blocks; i++) {
        PrintAndLogEx(INFO,
                      "%3d/0x%02X | %s | %s | %s",
                      i,
                      i,
                      sprint_hex(data + (i * ST25TB_SR_BLOCK_SIZE), ST25TB_SR_BLOCK_SIZE),
                      get_st_lock_info(chipid, systemblock, i),
                      sprint_ascii(data + (i * ST25TB_SR_BLOCK_SIZE), ST25TB_SR_BLOCK_SIZE)
                     );
    }

    PrintAndLogEx(INFO,
                  "%3d/0x%02X | %s | %s | %s",
                  0xFF,
                  0xFF,
                  sprint_hex(systemblock, ST25TB_SR_BLOCK_SIZE),
                  get_st_lock_info(chipid, systemblock, 0xFF),
                  sprint_ascii(systemblock, ST25TB_SR_BLOCK_SIZE)
                 );

    print_footer();
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
    // 14b get and print UID only (general info)
    iso14b_raw_cmd_t packet = {
        .flags = (ISO14B_CONNECT | ISO14B_SELECT_STD | ISO14B_DISCONNECT),
        .timeout = 0,
        .rawlen = 0,
    };

    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t));
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT) == false) {
        if (verbose) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply");
        }
        switch_off_field_14b();
        return false;
    }

    iso14b_card_select_t card;
    memcpy(&card, (iso14b_card_select_t *)resp.data.asBytes, sizeof(iso14b_card_select_t));

    int status = resp.oldarg[0];
    switch (status) {
        case 0: {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
            PrintAndLogEx(SUCCESS, " UID    : " _GREEN_("%s"), sprint_hex(card.uid, card.uidlen));
            PrintAndLogEx(SUCCESS, " ATQB   : %s", sprint_hex(card.atqb, sizeof(card.atqb)));
            PrintAndLogEx(SUCCESS, " CHIPID : %02X", card.chipid);
            print_atqb_resp(card.atqb, card.cid);

            if (do_aid_search) {
                hf14b_aid_search(verbose);
            }

            return true;
        }
        case -1:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-3 STD ATTRIB fail");
            break;
        case -2:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-3 STD CRC fail");
            break;
        default:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-b STD select failed");
            break;
    }

    return false;
}

// SRx get and print full info (needs more info...)
static bool HF14B_ST_Info(bool verbose, bool do_aid_search) {

    iso14b_raw_cmd_t packet = {
        .flags = (ISO14B_CONNECT | ISO14B_SELECT_SR | ISO14B_DISCONNECT),
        .timeout = 0,
        .rawlen = 0,
    };

    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t));
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT) == false) {
        if (verbose) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply");
        }
        return false;
    }

    iso14b_card_select_t card;
    memcpy(&card, (iso14b_card_select_t *)resp.data.asBytes, sizeof(iso14b_card_select_t));

    int status = resp.oldarg[0];
    if (status < 0)
        return false;

    uint8_t empty[] =  {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    if ((card.uidlen < 8) || (memcmp(card.uid, empty, card.uidlen) == 0)) {
        return false;
    }

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
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool do_aid_search = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);
    return infoHF14B(verbose, do_aid_search);
}

static bool HF14B_st_reader(bool verbose) {

    iso14b_raw_cmd_t packet = {
        .flags = (ISO14B_CONNECT | ISO14B_SELECT_SR | ISO14B_DISCONNECT),
        .timeout = 0,
        .rawlen = 0,
    };

    // SRx get and print general info about SRx chip from UID
    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t));
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT) == false) {
        if (verbose) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply");
        }
        return false;
    }

    iso14b_card_select_t card;
    memcpy(&card, (iso14b_card_select_t *)resp.data.asBytes, sizeof(iso14b_card_select_t));

    uint8_t empty[] =  {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    if ((card.uidlen < 8) || (memcmp(card.uid, empty, card.uidlen) == 0)) {
        return false;
    }

    int status = resp.oldarg[0];
    switch (status) {
        case 0:
            print_st_general_info(card.uid, card.uidlen);
            return true;
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
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-b ST select SRx failed");
            break;
    }
    return false;
}

static bool HF14B_std_reader(bool verbose) {
    iso14b_raw_cmd_t packet = {
        .flags = (ISO14B_CONNECT | ISO14B_SELECT_STD | ISO14B_DISCONNECT),
        .timeout = 0,
        .rawlen = 0,
    };

    // 14b get and print UID only (general info)
    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t));
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT) == false) {
        if (verbose) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply");
        }
        return false;
    }
    int status = resp.oldarg[0];

    iso14b_card_select_t card;
    memcpy(&card, (iso14b_card_select_t *)resp.data.asBytes, sizeof(iso14b_card_select_t));

    uint8_t empty[] =  {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    if (memcmp(card.uid, empty, card.uidlen) == 0) {
        return false;
    }

    switch (status) {
        case 0: {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(SUCCESS, " UID    : " _GREEN_("%s"), sprint_hex(card.uid, card.uidlen));
            PrintAndLogEx(SUCCESS, " ATQB   : %s", sprint_hex(card.atqb, sizeof(card.atqb)));
            PrintAndLogEx(SUCCESS, " CHIPID : %02X", card.chipid);
            print_atqb_resp(card.atqb, card.cid);
            return true;
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
    return false;
}

static bool HF14B_ask_ct_reader(bool verbose) {

    iso14b_raw_cmd_t packet = {
        .flags = (ISO14B_CONNECT | ISO14B_SELECT_CTS | ISO14B_DISCONNECT),
        .timeout = 0,
        .rawlen = 0,
    };

    // 14b get and print UID only (general info)
    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t));
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT) == false) {
        if (verbose) PrintAndLogEx(WARNING, "timeout while waiting for reply");
        return false;
    }

    int status = resp.oldarg[0];

    switch (status) {
        case 0: {
            print_ct_general_info(resp.data.asBytes);
            return true;
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
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-b CTS select failed");
            break;
        }
    }
    return false;
}

// test for other 14b type tags (mimic another reader - don't have tags to identify)
static bool HF14B_other_reader(bool verbose) {

    iso14b_raw_cmd_t *packet = (iso14b_raw_cmd_t *)calloc(1, sizeof(iso14b_raw_cmd_t) + 4);
    if (packet == NULL) {
        PrintAndLogEx(FAILED, "failed to allocate memory");
        return false;
    }
    packet->flags = (ISO14B_CONNECT | ISO14B_SELECT_STD | ISO14B_RAW | ISO14B_APPEND_CRC);
    packet->timeout = 0;
    packet->rawlen = 4;
    memcpy(packet->raw, "\x00\x0b\x3f\x80", 4);

    // 14b get and print UID only (general info)

    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)packet, sizeof(iso14b_raw_cmd_t) + packet->rawlen);
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT) == false) {
        if (verbose) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply");
        }
        free(packet);
        switch_off_field_14b();
        return false;
    }
    int status = resp.oldarg[0];
    PrintAndLogEx(DEBUG, "status %d", status);

    if (status == 0) {
        PrintAndLogEx(SUCCESS, "\n14443-3b tag found:");
        PrintAndLogEx(SUCCESS, "unknown tag type answered to a " _YELLOW_("0x000b3f80") " command ans:");
        switch_off_field_14b();
        free(packet);
        return true;
    } else if (status > 0) {
        PrintAndLogEx(SUCCESS, "\n14443-3b tag found:");
        PrintAndLogEx(SUCCESS, "unknown tag type answered to a " _YELLOW_("0x000b3f80") " command ans:");
        PrintAndLogEx(SUCCESS, "%s", sprint_hex(resp.data.asBytes, status));
        switch_off_field_14b();
        free(packet);
        return true;
    }

    packet->rawlen = 1;
    packet->raw[0] = ISO14443B_AUTHENTICATE;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)packet, sizeof(iso14b_raw_cmd_t) + packet->rawlen);
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT) == false) {
        if (verbose) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply");
        }
        switch_off_field_14b();
        free(packet);
        return false;
    }
    status = resp.oldarg[0];
    PrintAndLogEx(DEBUG, "status %d", status);

    if (status == 0) {
        PrintAndLogEx(SUCCESS, "\n14443-3b tag found:");
        PrintAndLogEx(SUCCESS, "Unknown tag type answered to a " _YELLOW_("0x0A") " command ans:");
        switch_off_field_14b();
        free(packet);
        return true;
    } else if (status > 0) {
        PrintAndLogEx(SUCCESS, "\n14443-3b tag found:");
        PrintAndLogEx(SUCCESS, "unknown tag type answered to a " _YELLOW_("0x0A") " command ans:");
        PrintAndLogEx(SUCCESS, "%s", sprint_hex(resp.data.asBytes, status));
        switch_off_field_14b();
        free(packet);
        return true;
    }

    packet->raw[0] = ISO14443B_RESET;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)packet, sizeof(iso14b_raw_cmd_t) + packet->rawlen);
    free(packet);
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT) == false) {
        if (verbose) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply");
        }
        switch_off_field_14b();
        return false;
    }
    status = resp.oldarg[0];
    PrintAndLogEx(DEBUG, "status %d", status);

    if (status == 0) {
        PrintAndLogEx(SUCCESS, "\n14443-3b tag found:");
        PrintAndLogEx(SUCCESS, "Unknown tag type answered to a " _YELLOW_("0x0C") " command ans:");
        switch_off_field_14b();
        return true;
    } else if (status > 0) {
        PrintAndLogEx(SUCCESS, "\n14443-3b tag found:");
        PrintAndLogEx(SUCCESS, "unknown tag type answered to a " _YELLOW_("0x0C") " command ans:");
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
                  "hf 14b reader -@   -> continuous reader mode"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0("@", NULL, "optional - continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool verbose = arg_get_lit(ctx, 1);
    bool cm = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    return readHF14B(cm, verbose);
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

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14b sriwrite",
                  "Write data to a SRI512 or SRIX4K block",
                  "hf 14b sriwrite --4k -b 100 -d 11223344\n"
                  "hf 14b sriwrite --4k --sb -d 11223344    --> special block write\n"
                  "hf 14b sriwrite --512 -b 15 -d 11223344\n"
                  "hf 14b sriwrite --512 --sb -d 11223344    --> special block write\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("b", "block",  "<dec>", "block number"),
        arg_str1("d", "data",  "<hex>", "4 hex bytes"),
        arg_lit0(NULL, "512", "target SRI 512 tag"),
        arg_lit0(NULL, "4k", "target SRIX 4k tag"),
        arg_lit0(NULL, "sb", "special block write at end of memory (0xFF)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int blockno = arg_get_int_def(ctx, 1, -1);
    int dlen = 0;
    uint8_t data[4] = {0, 0, 0, 0};
    int res = CLIParamHexToBuf(arg_get_str(ctx, 2), data, sizeof(data), &dlen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool use_sri512 = arg_get_lit(ctx, 3);
    bool use_srix4k = arg_get_lit(ctx, 4);
    bool special = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    if (dlen != sizeof(data)) {
        PrintAndLogEx(FAILED, "data must be 4 hex bytes,  got %d", dlen);
        return PM3_EINVARG;
    }

    if (use_sri512 + use_srix4k > 1) {
        PrintAndLogEx(FAILED, "Select only one card type");
        return PM3_EINVARG;
    }

    if (use_srix4k && blockno > 0x7F) {
        PrintAndLogEx(FAILED, "block number out of range, max 127 (0x7F)");
        return PM3_EINVARG;
    }

    if (use_sri512 && blockno > 0x0F) {
        PrintAndLogEx(FAILED, "block number out of range, max 15 (0x0F)");
        return PM3_EINVARG;
    }

    // special block at end of memory
    if (special) {
        blockno = 0xFF;
        PrintAndLogEx(SUCCESS, "[%s] Write special block %02X [ " _YELLOW_("%s")" ]",
                      (use_srix4k) ? "SRIX4K" : "SRI512",
                      blockno,
                      sprint_hex(data, sizeof(data))
                     );
    } else {
        PrintAndLogEx(SUCCESS, "[%s] Write block %02X [ " _YELLOW_("%s")" ]",
                      (use_srix4k) ? "SRIX4K" : "SRI512",
                      blockno,
                      sprint_hex(data, sizeof(data))
                     );
    }

    char str[36];
    memset(str, 0x00, sizeof(str));
    snprintf(str, sizeof(str), "--sr -c --data %02x%02x%02x%02x%02x%02x", ISO14443B_WRITE_BLK, blockno, data[0], data[1], data[2], data[3]);
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
        arg_str0("f", "file", "<fn>", "(optional) filename,  if no <name> UID will be used as filename"),
        arg_lit0(NULL, "ns", "no save to file"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    bool nosave = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);


    uint8_t select[sizeof(iso14b_card_select_t)] = {0};
    iso14b_type_t select_cardtype = ISO14B_NONE;
    if (get_14b_UID(select, &select_cardtype) == false) {
        PrintAndLogEx(WARNING, "no tag found");
        return PM3_SUCCESS;
    }

    if (select_cardtype == ISO14B_CT) {
        iso14b_cts_card_select_t ct_card;
        memcpy(&ct_card, (iso14b_cts_card_select_t *)&select, sizeof(iso14b_cts_card_select_t));

        uint32_t uid32 = MemLeToUint4byte(ct_card.uid);
        PrintAndLogEx(SUCCESS, "UID: " _GREEN_("%s") " ( " _YELLOW_("%010u") " )", sprint_hex(ct_card.uid, 4), uid32);

        // Have to figure out how large one of these are..
        PrintAndLogEx(FAILED, "Dumping CT tags is not implemented yet.");

        // print_ct_blocks(data, cardsize);
        return switch_off_field_14b();
    }

    if (select_cardtype == ISO14B_STANDARD) {
        // Have to figure out how large one of these are..
        PrintAndLogEx(FAILED, "Dumping Standard ISO14443-B tags is not implemented yet.");
        // print_std_blocks(data, cardsize);
        return switch_off_field_14b();
    }

    if (select_cardtype == ISO14B_SR) {
        iso14b_card_select_t card;
        memcpy(&card, (iso14b_card_select_t *)&select, sizeof(iso14b_card_select_t));

        // detect cardsize
        // 1 = 4096
        // 2 = 512
        uint8_t cardtype = get_st_cardsize(card.uid);
        uint8_t lastblock = 0;
        uint16_t cardsize = 0;

        switch (cardtype) {
            case 2:
                cardsize = (512 / 8) + ST25TB_SR_BLOCK_SIZE;
                lastblock = 0x0F;
                break;
            case 1:
            default:
                cardsize = (4096 / 8) + ST25TB_SR_BLOCK_SIZE;
                lastblock = 0x7F;
                break;
        }

        uint8_t chipid = get_st_chipid(card.uid);
        PrintAndLogEx(SUCCESS, "found a " _GREEN_("%s") " tag", get_st_chip_model(chipid));

        // detect blocksize from card :)
        PrintAndLogEx(INFO, "reading tag memory from UID " _GREEN_("%s"), sprint_hex_inrow(SwapEndian64(card.uid, card.uidlen, 8), card.uidlen));
        iso14b_raw_cmd_t *packet = (iso14b_raw_cmd_t *)calloc(1, sizeof(iso14b_raw_cmd_t) + 2);
        if (packet == NULL) {
            PrintAndLogEx(FAILED, "failed to allocate memory");
            return PM3_EMALLOC;
        }
        packet->flags = (ISO14B_CONNECT | ISO14B_SELECT_SR);
        packet->timeout = 0;
        packet->rawlen = 0;

        clearCommandBuffer();
        SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)packet, sizeof(iso14b_raw_cmd_t));
        PacketResponseNG resp;

        // select SR tag
        int status;
        if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, 2000)) {
            status = resp.oldarg[0];
            if (status < 0) {
                PrintAndLogEx(FAILED, "failed to select arg0[%" PRId64 "]", resp.oldarg[0]);
                free(packet);
                return switch_off_field_14b();
            }
        }

        PrintAndLogEx(INFO, "." NOLF);

        uint8_t data[cardsize];
        memset(data, 0, sizeof(data));
        uint16_t blocknum = 0;

        for (int retry = 0; retry < 5; retry++) {

            // set up the read command
            packet->flags = (ISO14B_APPEND_CRC | ISO14B_RAW);
            packet->rawlen = 2;
            packet->raw[0] = ISO14443B_READ_BLK;
            packet->raw[1] = blocknum & 0xFF;

            clearCommandBuffer();
            SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)packet, sizeof(iso14b_raw_cmd_t) + 2);
            if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, 2000)) {

                status = resp.oldarg[0];
                if (status < 0) {
                    PrintAndLogEx(FAILED, "retrying one more time");
                    continue;
                }

                uint16_t len = (resp.oldarg[1] & 0xFFFF);
                uint8_t *recv = resp.data.asBytes;

                if (check_crc(CRC_14443_B, recv, len) == false) {
                    PrintAndLogEx(FAILED, "crc fail, retrying one more time");
                    continue;
                }


                // last read
                if (blocknum == 0xFF) {
                    // we reserved space for this block after 0x0F and 0x7F,  ie 0x10, 0x80
                    memcpy(data + ((lastblock + 1) * ST25TB_SR_BLOCK_SIZE), recv, ST25TB_SR_BLOCK_SIZE);
                    break;
                }
                memcpy(data + (blocknum * ST25TB_SR_BLOCK_SIZE), recv, ST25TB_SR_BLOCK_SIZE);


                retry = 0;
                blocknum++;
                if (blocknum > lastblock) {
                    // read config block
                    blocknum = 0xFF;
                }

                PrintAndLogEx(NORMAL, "." NOLF);
                fflush(stdout);
            }
        }
        free(packet);

        PrintAndLogEx(NORMAL, "");

        if (blocknum != 0xFF) {
            PrintAndLogEx(FAILED, "dump failed");
            return switch_off_field_14b();
        }

        print_sr_blocks(data, cardsize, card.uid);

        if (nosave == false) {
            // save to file
            if (fnlen < 1) {
                PrintAndLogEx(INFO, "using UID as filename");
                char *fptr = filename + snprintf(filename, sizeof(filename), "hf-14b-");
                FillFileNameByUID(fptr, SwapEndian64(card.uid, card.uidlen, 8), "-dump", card.uidlen);
            }

            size_t datalen = (lastblock + 2) * ST25TB_SR_BLOCK_SIZE;
            pm3_save_dump(filename, data, datalen, jsf14b, ST25TB_SR_BLOCK_SIZE);
        }
    }

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

int select_card_14443b_4(bool disconnect, iso14b_card_select_t *card) {
    if (card)
        memset(card, 0, sizeof(iso14b_card_select_t));

    switch_off_field_14b();

    iso14b_raw_cmd_t packet = {
        .flags = (ISO14B_CONNECT | ISO14B_SELECT_STD),
        .timeout = 0,
        .rawlen = 0,
    };
    // Anticollision + SELECT STD card
    PacketResponseNG resp;
    SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t));
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT) == false) {
        PrintAndLogEx(INFO, "Trying 14B Select SRx");

        // Anticollision + SELECT SR card
        packet.flags = (ISO14B_CONNECT | ISO14B_SELECT_SR);
        SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t));
        if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT) == false) {
            PrintAndLogEx(INFO, "Trying 14B Select CTS");

            // Anticollision + SELECT ASK C-Ticket card
            packet.flags = (ISO14B_CONNECT | ISO14B_SELECT_CTS);
            SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t));
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
    SetISODEPState(ISODEP_NFCB);
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

static int handle_14b_apdu(bool chainingin, uint8_t *datain, int datainlen,
                           bool activateField, uint8_t *dataout, int maxdataoutlen,
                           int *dataoutlen, bool *chainingout, int user_timeout) {

    *chainingout = false;

    if (activateField) {
        // select with no disconnect and set frameLength
        int selres = select_card_14443b_4(false, NULL);
        if (selres != PM3_SUCCESS)
            return selres;
    }

    iso14b_raw_cmd_t *packet = (iso14b_raw_cmd_t *)calloc(1, sizeof(iso14b_raw_cmd_t) + datainlen);
    if (packet == NULL) {
        PrintAndLogEx(FAILED, "APDU: failed to allocate memory");
        return PM3_EMALLOC;
    }
    packet->flags = (ISO14B_CONNECT | ISO14B_APDU);
    packet->timeout = 0;
    packet->rawlen = 0;

    if (chainingin)
        packet->flags = (ISO14B_SEND_CHAINING | ISO14B_APDU);

    if (user_timeout > 0) {
        packet->flags |= ISO14B_SET_TIMEOUT;
        if (user_timeout > MAX_14B_TIMEOUT_MS) {
            user_timeout = MAX_14B_TIMEOUT_MS;
            PrintAndLogEx(INFO, "set timeout to 4.9 seconds. The max we can wait for response");
        }

        // timeout in ETU
        packet->timeout = (uint32_t)((13560 / 128) * user_timeout);
    }

    // "Command APDU" length should be 5+255+1, but javacard's APDU buffer might be smaller - 133 bytes
    // https://stackoverflow.com/questions/32994936/safe-max-java-card-apdu-data-command-and-respond-size
    // here length PM3_CMD_DATA_SIZE=512
    if (datain) {
        packet->rawlen = datainlen;
        memcpy(packet->raw, datain, datainlen);
        SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)packet, sizeof(iso14b_raw_cmd_t) + packet->rawlen);
    } else {
        SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)packet, sizeof(iso14b_raw_cmd_t));
    }
    free(packet);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, MAX(APDU_TIMEOUT, user_timeout)) == false) {
        PrintAndLogEx(ERR, "APDU: reply timeout");
        return PM3_ETIMEOUT;
    }

    int rlen = resp.oldarg[0];
    int dlen = rlen - 2;
    if (dlen < 0) {
        dlen = 0;
    }

    *dataoutlen += dlen;

    if (maxdataoutlen && *dataoutlen > maxdataoutlen) {
        PrintAndLogEx(ERR, "APDU: buffer too small(%d), needs %d bytes", maxdataoutlen, *dataoutlen);
        return PM3_ESOFT;
    }

    // I-block ACK
    uint8_t res = resp.oldarg[1];
    if ((res & 0xF2) == 0xA2) {
        *dataoutlen = 0;
        *chainingout = true;
        return PM3_SUCCESS;
    }

    if (rlen < 0) {
        PrintAndLogEx(ERR, "APDU: no APDU response");
        return PM3_ESOFT;
    }

    // check apdu length
    if (rlen == 0 || rlen == 1) {
        PrintAndLogEx(ERR, "APDU: small APDU response, len %d", rlen);
        return PM3_ESOFT;
    }

    memcpy(dataout, resp.data.asBytes, dlen);

    // chaining
    if ((res & 0x10) != 0) {
        *chainingout = true;
    }
    return PM3_SUCCESS;
}

int exchange_14b_apdu(uint8_t *datain, int datainlen, bool activate_field,
                      bool leave_signal_on, uint8_t *dataout, int maxdataoutlen,
                      int *dataoutlen, int user_timeout) {

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
            if ((*dataoutlen == 0) && (chaining != chainBlockNotLast)) {
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
                  "Sends an ISO 7816-4 APDU via ISO 14443-4 block transmission protocol (T=CL).\n"
                  "works with all apdu types from ISO 7816-4:2013",
                  "hf 14b apdu -s -d 94a40800043f000002\n"
                  "hf 14b apdu -s --decode -d 00A404000E325041592E5359532E444446303100 -> decode apdu\n"
                  "hf 14b apdu -sm 00A40400 -l 256 -d 325041592E5359532E4444463031     -> encode standard apdu\n"
                  "hf 14b apdu -sm 00A40400 -el 65536 -d 325041592E5359532E4444463031  -> encode extended apdu\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("s",  "select",   "activate field and select card"),
        arg_lit0("k",  "keep",     "leave the signal field ON after receive response"),
        arg_lit0("t",  "tlv",      "executes TLV decoder if it possible"),
        arg_lit0(NULL,  "decode",   "decode apdu request if it possible"),
        arg_str0("m",  "make",     "<hex>", "make apdu with head from this field and data from data field.\n"
                 "                                   must be 4 bytes: <CLA INS P1 P2>"),
        arg_lit0("e",  "extended", "make extended length apdu if `m` parameter included"),
        arg_int0("l",  "le",       "<int>", "Le apdu parameter if `m` parameter included"),
        arg_str1("d", "data",     "<hex>", "<APDU | data> if `m` parameter included"),
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

        APDU_t apdu;
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
        APDU_t apdu;
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

int CmdHF14BNdefRead(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14b ndefread",
                  "Print NFC Data Exchange Format (NDEF)",
                  "hf 14b ndefread\n"
                  "hf 14b ndefread -f myfilename   -> save raw NDEF to file"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "save raw NDEF to file"),
        arg_litn("v",  "verbose",  0, 2, "show technical data"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool verbose = arg_get_lit(ctx, 2);
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
    if (sw != ISO7816_OK) {
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
    if (sw != ISO7816_OK) {
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
    if (sw != ISO7816_OK) {
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
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "reading NDEF file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        res = PM3_ESOFT;
        goto out;
    }

    if (fnlen != 0) {
        saveFile(filename, ".bin", response + 2, resplen - 4);
    }
    res = NDEFRecordsDecodeAndPrint(response + 2, resplen - 4, verbose);

out:
    switch_off_field_14b();
    return res;
}

/* extract uid from filename
 * filename must match '^hf-14b-[0-9A-F]{16}'
 */
uint8_t *get_uid_from_filename(const char *filename) {
    static uint8_t uid[8]  ;
    memset(uid, 0, 8) ;
    char uidinhex[17] ;
    if (strlen(filename) < 23 || strncmp(filename, "hf-14b-", 7)) {
        PrintAndLogEx(ERR, "can't get uid from filename '%s'. Expected format is hf-14b-<uid>...", filename);
        return uid ;
    }
    // extract uid part from filename
    strncpy(uidinhex, filename + 7, 16) ;
    uidinhex[16] = '\0' ;
    int len = hex_to_bytes(uidinhex, uid, 8);
    if (len == 8)
        return SwapEndian64(uid, 8, 8);
    else {
        PrintAndLogEx(ERR, "get_uid_from_filename failed: hex_to_bytes returned %d", len);
        memset(uid, 0, 8);
    }
    return uid ;
}

static int CmdHF14BView(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14b view",
                  "Print a ISO14443-B dump file (bin/eml/json)",
                  "hf 14b view -f hf-14b-01020304-dump.bin"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "filename of dump"),
        arg_lit0("v", "verbose", "verbose output"),
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
    int res = pm3_load_dump(filename, (void **)&dump, &bytes_read, (ST25TB_SR_BLOCK_SIZE * 0xFF));
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint16_t block_cnt = bytes_read / ST25TB_SR_BLOCK_SIZE;

    if (verbose) {
        PrintAndLogEx(INFO, "File: " _YELLOW_("%s"), filename);
        PrintAndLogEx(INFO, "File size %zu bytes, file blocks %d (0x%x)", bytes_read, block_cnt, block_cnt);
    }

    // figure out a way to identify the different dump files.
    // STD/SR/CT is difference
    print_sr_blocks(dump, bytes_read, get_uid_from_filename(filename));
    //print_std_blocks(dump, bytes_read);
    //print_ct_blocks(dump, bytes_read);

    free(dump);
    return PM3_SUCCESS;
}


static command_t CommandTable[] = {
    {"help",        CmdHelp,          AlwaysAvailable, "This help"},
    {"apdu",        CmdHF14BAPDU,     IfPm3Iso14443b,  "Send ISO 14443-4 APDU to tag"},
    {"dump",        CmdHF14BDump,     IfPm3Iso14443b,  "Read all memory pages of an ISO-14443-B tag, save to file"},
    {"info",        CmdHF14Binfo,     IfPm3Iso14443b,  "Tag information"},
    {"list",        CmdHF14BList,     AlwaysAvailable, "List ISO-14443-B history"},
    {"ndefread",    CmdHF14BNdefRead, IfPm3Iso14443b,  "Read NDEF file on tag"},
    {"raw",         CmdHF14BCmdRaw,   IfPm3Iso14443b,  "Send raw hex data to tag"},
    {"reader",      CmdHF14BReader,   IfPm3Iso14443b,  "Act as a ISO-14443-B reader to identify a tag"},
//    {"restore",     CmdHF14BRestore,     IfPm3Iso14443b,   "Restore from file to all memory pages of an ISO-14443-B tag"},
    {"sim",         CmdHF14BSim,      IfPm3Iso14443b,  "Fake ISO ISO-14443-B tag"},
    {"sniff",       CmdHF14BSniff,    IfPm3Iso14443b,  "Eavesdrop ISO-14443-B"},
    {"rdbl",        CmdHF14BSriRdBl,  IfPm3Iso14443b,  "Read SRI512/SRIX4x block"},
    {"sriwrite",    CmdHF14BWriteSri, IfPm3Iso14443b,  "Write data to a SRI512 or SRIX4K tag"},
    {"view",        CmdHF14BView,     AlwaysAvailable, "Display content from tag dump file"},
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
        return PM3_SUCCESS;

    // try ST 14b
    if (HF14B_ST_Info(verbose, do_aid_search))
        return PM3_SUCCESS;

    // try unknown 14b read commands (to be identified later)
    //   could be read of calypso, CEPAS, moneo, or pico pass.
    if (verbose) PrintAndLogEx(FAILED, "no 14443-B tag found");
    return PM3_EOPABORTED;
}

// get and print general info about all known 14b chips
int readHF14B(bool loop, bool verbose) {
    bool found = false;
    do {
        found = false;

        // try std 14b (atqb)
        found |= HF14B_std_reader(verbose);
        if (found && loop)
            continue;

        // try ST Microelectronics 14b
        found |= HF14B_st_reader(verbose);
        if (found && loop)
            continue;

        // try ASK CT 14b
        found |= HF14B_ask_ct_reader(verbose);
        if (found && loop)
            continue;

        // try unknown 14b read commands (to be identified later)
        // could be read of calypso, CEPAS, moneo, or pico pass.
        found |= HF14B_other_reader(verbose);
        if (found && loop)
            continue;

    } while (loop && kbd_enter_pressed() == false);

    if (verbose && found == false) {
        PrintAndLogEx(FAILED, "no ISO 14443-B tag found");
    }
    return (found) ? PM3_SUCCESS : PM3_EOPABORTED;
}
