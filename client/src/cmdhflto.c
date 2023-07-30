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
// LTO-CM commands
// LTO Cartridge memory
//-----------------------------------------------------------------------------
#include "cmdhflto.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include "cliparser.h"
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "cmdtrace.h"
#include "crc16.h"
#include "ui.h"
#include "cmdhf14a.h"
#include "protocols.h"
#include "fileutils.h"    // saveFile
#include "commonutil.h"   // ARRAYLEN
/*
  iceman notes
  We can't dump LTO 5 or 6 tags yet since we don't have a datasheet.
  If you have access to datasheet,  le me know!

  CM size  xx field indicate size in units of 1024b

  LTO w Type info 00 01   has 101 blocks.
  LTO w Type info 00 02   has  95 blocks.
  LTO w Type info 00 03   has 255 blocks.
  LTO w Type info 00 xx   has NN blocks.
*/
#define CM_MEM_MAX_SIZE     0x1FE0  // (32byte/block * 255block = 8160byte)

// todo: vendor mapping table..

// structure and database for uid -> tagtype lookups
typedef struct cm_page_s {
    uint16_t pageid;
    uint16_t len;
    const char *name;
    const char *desc;
} cm_page_t;

static const cm_page_t cm_page_map[] = {
    { 0x001, 64,   "Cartridge Manufacture's information", "" },
    { 0x002, 64,   "Media Manufacture's information", "" },
    { 0x101, 64,   "Initialisation Data", "" },
    { 0x102, 48,   "Tape Write Data", "" },
    { 0x103, 1552, "Tape Directory", "" },
    { 0x104, 64,   "EOD Information", "" },
    { 0x105, 32,   "Cartidge Status and Tape Alert Flags", "" },
    { 0x106, 384,  "Mechanism Related", "" },
    { 0x107, 128,  "Suspended Append Writes", "" },
    { 0x108, 64,   "Usage Information 0", "" },
    { 0x109, 64,   "Usage Information 1", "" },
    { 0x10A, 64,   "Usage Information 2", "" },
    { 0x10B, 64,   "Usage Information 3", "" },
    { 0x200, 1056, "Application Specific", "" },
    { 0xFFC, 0,    "Pad", "Used to reserve space for future Pages, and to align some Pages to 16-byte / 32-byte boundaries" },
    { 0xFFD, 0,    "Defect", "Used to indicate that the LTO CM contains defective memory locations in that area" },
    { 0xFFE, 0,    "Empty", "Indicates an empty table" },
    { 0xFFF, 0,    "EOPT", "End Of Page Table" },
    { 0x000, 0,    "no page info available", "" } // must be the last entry
};

/*
static uint16_t get_page_len(uint16_t pageid) {
    for (uint8_t i = 0; i < ARRAYLEN(cm_page_map ); ++i) {
        if (pageid == cm_page_map[i].pageid) {
            return cm_page_map[i].len;
        }
    }
    //No match, return default
    return 0;
}
*/

static const char *get_page_name(uint16_t pageid) {
    for (uint8_t i = 0; i < ARRAYLEN(cm_page_map); ++i) {
        if (pageid == cm_page_map[i].pageid) {
            return cm_page_map[i].name;
        }
    }
    //No match, return default
    return cm_page_map[ARRAYLEN(cm_page_map) - 1].name;
}

static int CmdHelp(const char *Cmd);

static void lto_switch_off_field(void) {
    SetISODEPState(ISODEP_INACTIVE);
    SendCommandMIX(CMD_HF_ISO14443A_READER, 0, 0, 0, NULL, 0);
}

static void lto_switch_on_field(void) {
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_NO_SELECT | ISO14A_NO_DISCONNECT | ISO14A_NO_RATS, 0, 0, NULL, 0);
}

// send a raw LTO-CM command, returns the length of the response (0 in case of error)
static int lto_send_cmd_raw(uint8_t *cmd, uint8_t len, uint8_t *response, uint16_t *response_len, bool addcrc, bool is7bits, bool verbose) {

    uint64_t arg0 = ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_NO_RATS;
    uint32_t arg1;

    if (addcrc) {
        arg0 |= ISO14A_APPEND_CRC;
    }

    if (is7bits) {
        arg1 = 7 << 16;
    } else {
        arg1 = 0;
    }

    arg1 |= len;

    SendCommandMIX(CMD_HF_ISO14443A_READER, arg0, arg1, 0, cmd, len);
    PacketResponseNG resp;

    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        if (verbose) PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.oldarg[0] == *response_len) {
        *response_len = resp.oldarg[0];
        if (*response_len > 0) {
            memcpy(response, resp.data.asBytes, *response_len);
        }
    } else {
        if (verbose) PrintAndLogEx(WARNING, "Wrong response length (%d != %" PRIu64 ")", *response_len, resp.oldarg[0]);
        return PM3_ESOFT;
    }

    return PM3_SUCCESS;
}

// select a LTO-CM tag. Send WUPA and RID.
static int lto_select(uint8_t *id_response, uint8_t id_len, uint8_t *type_response, bool verbose) {
    // Todo: implement anticollision

    uint8_t resp[] = {0, 0};
    uint16_t resp_len;
    uint8_t wupa_cmd[] = {LTO_REQ_STANDARD};
    uint8_t select_sn_cmd[] = {LTO_SELECT, 0x20};
    uint8_t select_cmd[] = {LTO_SELECT, 0x70, 0, 0, 0, 0, 0};

    resp_len = 2;
    int status = lto_send_cmd_raw(wupa_cmd, sizeof(wupa_cmd), type_response, &resp_len, false, true, verbose);
    if (status == PM3_ETIMEOUT || status == PM3_ESOFT) {
        return PM3_ESOFT; // WUPA failed
    }

    resp_len = id_len;
    status = lto_send_cmd_raw(select_sn_cmd, sizeof(select_sn_cmd), id_response, &resp_len, false, false, verbose);
    if (status == PM3_ETIMEOUT || status == PM3_ESOFT) {
        return PM3_EWRONGANSWER; // REQUEST SERIAL NUMBER failed
    }

    memcpy(select_cmd + 2, id_response, sizeof(select_cmd) - 2);
    resp_len = 1;
    status = lto_send_cmd_raw(select_cmd, sizeof(select_cmd), resp, &resp_len, true, false, verbose);
    if (status == PM3_ETIMEOUT || status == PM3_ESOFT || resp[0] != 0x0A) {
        return PM3_EWRONGANSWER; // SELECT failed
    }

    // tag is now INIT and SELECTED.
    return PM3_SUCCESS;
}

static int lto_rdbl(uint8_t blk, uint8_t *block_response, uint8_t *block_cnt_response, bool verbose) {

    uint16_t resp_len = 18;
    uint8_t rdbl_cmd[] = {0x30, blk};
    uint8_t rdbl_cnt_cmd[] = {0x80};

    int status = lto_send_cmd_raw(rdbl_cmd, sizeof(rdbl_cmd), block_response, &resp_len, true, false, verbose);
    if (status == PM3_ETIMEOUT || status == PM3_ESOFT) {
        return PM3_EWRONGANSWER; // READ BLOCK failed
    }

    status = lto_send_cmd_raw(rdbl_cnt_cmd, sizeof(rdbl_cnt_cmd), block_cnt_response, &resp_len, false, false, verbose);
    if (status == PM3_ETIMEOUT || status == PM3_ESOFT) {
        return PM3_EWRONGANSWER; // READ BLOCK CONTINUE failed
    }

    return PM3_SUCCESS;
}

/*
static int lto_rdbl_ext(uint16_t blk, uint8_t *block_response, uint8_t *block_cnt_response, bool verbose) {

    if (blk && 0x) {
        blk &= 0xFE;
    }

    uint16_t resp_len = 18;
    uint8_t rdbl_ext_cmd[] = {0x21 , blk & 0xFF, (blk >> 8) & 0xFF};
    uint8_t rdbl_cnt_cmd[] = {0x80};

    int status = lto_send_cmd_raw(rdbl_ext_cmd, sizeof(rdbl_ext_cmd), block_response, &resp_len, true, false, verbose);
    if (status == PM3_ETIMEOUT || status == PM3_ESOFT) {
        return PM3_EWRONGANSWER; // READ BLOCK failed
    }

    status = lto_send_cmd_raw(rdbl_cnt_cmd, sizeof(rdbl_cnt_cmd), block_cnt_response, &resp_len, false, false, verbose);
    if (status == PM3_ETIMEOUT || status == PM3_ESOFT) {
        return PM3_EWRONGANSWER; // READ BLOCK CONTINUE failed
    }

    return PM3_SUCCESS;
}
*/

static int CmdHfLTOInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf lto info",
                  "Get info from LTO tags",
                  "hf lto info");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return infoLTO(true);
}

static const char *lto_print_size(uint8_t ti) {
    switch (ti) {
        case 1:
            return "101 blocks / 3232 bytes";
        case 2:
            return "95 blocks / 3040 bytes";
        case 3:
            return "255 blocks / 8160 bytes";
        default :
            return "unknown";
    }
}

static void lto_print_ci(uint8_t *d) {
    uint32_t sn = (bytes_to_num(d, 4) & 0x0FFFFFFF);
    PrintAndLogEx(INFO, "CM Serial number... " _YELLOW_("%u"), sn);
    PrintAndLogEx(INFO, "Manufacture Id..... " _YELLOW_("%u"), (d[3] >> 4));
    PrintAndLogEx(INFO, "CM Size............ " _YELLOW_("%u") " ( 1024 x %u bytes )", d[5], d[5]);
    PrintAndLogEx(INFO, "Type............... " _YELLOW_("%s"), sprint_hex_inrow(d + 6, 2));
    PrintAndLogEx(INFO, "Manufacture info... " _YELLOW_("%s"), sprint_hex_inrow(d + 8, 24));
}

static void lto_print_cmwi(uint8_t *d) {

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("LTO CM Write-Inhibit") " --------------------------");
    PrintAndLogEx(INFO, "Raw");
    PrintAndLogEx(INFO, "   " _YELLOW_("%s"), sprint_hex_inrow(d, 4));
    PrintAndLogEx(INFO, "Last write-inhibited block#... " _YELLOW_("%u"), d[0]);
    PrintAndLogEx(INFO, "Block 1 protected flag........ %s", (d[1] == 0) ? _GREEN_("uninitialised cartridge") : (d[1] == 1) ? "initialised cartridge" : "n/a");
    PrintAndLogEx(INFO, "Reserved for future use....... " _YELLOW_("%s"), sprint_hex_inrow(d + 2, 2));
}

static void lto_print_cmpt(uint8_t *d) {
// Block Address:    B0 = integer part of [ (start address + offset) ÷ 32 ]
// Word Address:    w = mod(start address + offset, 32 ) ÷ 2

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Page Descriptor Table") " ----------------------------------------");
    PrintAndLogEx(INFO, "Raw");
    PrintAndLogEx(INFO, "   " _YELLOW_("%s"), sprint_hex_inrow(d, 28));
    PrintAndLogEx(INFO, "                                                   ^^^^^^^^ CRC-32");
    PrintAndLogEx(INFO, "------------------------------------------------------------------");
    PrintAndLogEx(INFO, "                 start ");
    PrintAndLogEx(INFO, " # | ver | id  | address | name ");
    PrintAndLogEx(INFO, "---+-----+-----+---------+----------------------------------------");

    uint8_t p = 0;
    for (uint8_t i = 0; i < 24; i += 4) {

        uint8_t page_vs = d[i] >> 4;
        uint16_t page_id = ((d[i] & 0x0F) << 8) | d[i + 1];
        uint16_t sa = (d[i + 2] << 8 | d[i + 3]);
        PrintAndLogEx(INFO, " %u |  %u  | %03x | 0x%04X  | %s", p, page_vs, page_id, sa, get_page_name(page_id));
        p++;
    }
    PrintAndLogEx(INFO, "---+-----+-----+---------+----------------------------------------");
    PrintAndLogEx(INFO, "# Pages found...  %u", p);
}

static void lto_print_cmi(uint8_t *d) {

    uint16_t page_id = (d[0] << 8) | d[1];
    uint16_t page_len = (d[2] << 8) | d[3];

    char man[8 + 1];
    memcpy(man, (char *)d + 4, 8);

    char serial[10 + 1];
    memcpy(serial, (char *)d + 12, 10);

    uint16_t cart_type = (d[22] << 8) | d[23];
    char dom[8 + 1];
    memcpy(dom, (char *)d + 24, 8);

    uint16_t tape_len = (d[32] << 8) | d[33];
    uint16_t tape_thick = (d[34] << 8) | d[35];
    uint16_t empty_reel = (d[36] << 8) | d[37];
    uint16_t hub_radius = (d[38] << 8) | d[39];
    uint16_t full_reel = (d[40] << 8) | d[41];
    uint16_t max_media_speed = (d[42] << 8) | d[43];
    char lic[4 + 1];
    memcpy(lic, (char *)d + 44, 4);

    char cmuse[12 + 1];
    memcpy(cmuse, (char *)d + 48, 12);

//    uint32_t crc = bytes_to_num(d+60, 4);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Cartridge Manufacturer's information") " --------------------------");
    PrintAndLogEx(INFO, "Raw");
    PrintAndLogEx(INFO, "   " _YELLOW_("%s"), sprint_hex_inrow(d, 32));
    PrintAndLogEx(INFO, "   " _YELLOW_("%s"), sprint_hex_inrow(d + 32, 32));
    PrintAndLogEx(INFO, "                                                           ^^^^^^^^ CRC-32");
    PrintAndLogEx(INFO, "Page id.................. ..." _YELLOW_("0x%04x"), page_id);
    PrintAndLogEx(INFO, "Page len.................... " _YELLOW_("%u"), page_len);
    PrintAndLogEx(INFO, "Cartridge Manufacturer...... " _YELLOW_("%s"), man);
    PrintAndLogEx(INFO, "Serial number............... " _YELLOW_("%s"), serial);
    PrintAndLogEx(INFO, "Cartridge type.............. " _YELLOW_("0x%02x"), cart_type);
    PrintAndLogEx(INFO, "Date of manufacture......... " _YELLOW_("%s"), dom);
    PrintAndLogEx(INFO, "Tape len.................... " _YELLOW_("%u"), tape_len);
    PrintAndLogEx(INFO, "Tape thickness.............. " _YELLOW_("%u"), tape_thick);
    PrintAndLogEx(INFO, "Empty reel inertia.......... " _YELLOW_("%u") " %s", empty_reel, (empty_reel == 7270) ? "( def )" : "");
    PrintAndLogEx(INFO, "Hub radius.................. " _YELLOW_("%u") " %s", hub_radius, (hub_radius == 22528) ? "( def )" : "");
    PrintAndLogEx(INFO, "Full reel pack radius....... " _YELLOW_("%u") " / 0x%04x", full_reel, full_reel);
    PrintAndLogEx(INFO, "Maximum media speed......... " _YELLOW_("%u"), max_media_speed);
    PrintAndLogEx(INFO, "License code................ " _YELLOW_("%s"), lic);
    PrintAndLogEx(INFO, "Cartridge manufacture use... " _YELLOW_("%s"), cmuse);
}

static void lto_print_mmi(uint8_t *d) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Media Manufacturer's information") " --------------------------");
    PrintAndLogEx(INFO, "Raw");
    PrintAndLogEx(INFO, "   " _YELLOW_("%s"), sprint_hex_inrow(d, 32));
    PrintAndLogEx(INFO, "   " _YELLOW_("%s"), sprint_hex_inrow(d + 32, 32));
    PrintAndLogEx(INFO, "                                                           ^^^^^^^^ CRC-32");


    uint16_t page_id = (d[0] << 8) | d[1];
    uint16_t page_len = (d[2] << 8) | d[3];

    char man[48 + 1];
    memcpy(man, (char *)d + 4, 48);
    PrintAndLogEx(INFO, "Page id.................... " _YELLOW_("0x%04x"), page_id);
    PrintAndLogEx(INFO, "Page len................... " _YELLOW_("%u"), page_len);
    PrintAndLogEx(INFO, "Servowriter Manufacturer... " _YELLOW_("%s"), man);
}

// common pages
//  - pad page
//  - defect page
// Unprotected pages
//  - initialisation data (64b)
//  - Cartridge Status and Tape Alert Flags  (64b)
//  - Usage Information (4*64b , 256b)
//  - Tape Write Pass (48b)
//  - Tape Directory (16*xx) (max 1536b)
//  - EOD Information (64b)
//  - Mechanism Related (384b)
//  - Application Specific Data (1056b)
//  - Suspended Append Writes (128b)

static int CmdHFLTOReader(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf lto reader",
                  "Act as a LTO-CM reader. Look for LTO-CM tags until Enter or the pm3 button is pressed",
                  "hf lto reader -@   -> continuous reader mode"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("@", NULL, "optional - continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool cm = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    return reader_lto(cm, true);
}

int reader_lto(bool loop, bool verbose) {

    int ret = PM3_SUCCESS;

    do {
        uint8_t serial[5] = {0};
        uint8_t serial_len = sizeof(serial);
        uint8_t type_info[2] = {0};

        lto_switch_off_field();
        lto_switch_on_field();
        clearCommandBuffer();

        ret = lto_select(serial, serial_len, type_info, verbose);
        if (loop) {
            if (ret != PM3_SUCCESS) {
                continue;
            }
        }

        if (ret == PM3_SUCCESS) {

            if (loop == false) {
                PrintAndLogEx(NORMAL, "");
            }

            PrintAndLogEx(INFO, "UID......... " _GREEN_("%s"), sprint_hex_inrow(serial, sizeof(serial)));
        }

    } while (loop && kbd_enter_pressed() == false);

    lto_switch_off_field();
    return ret;
}

int infoLTO(bool verbose) {

    clearCommandBuffer();
    lto_switch_on_field();

    uint8_t serial_number[5];
    uint8_t serial_len = sizeof(serial_number);
    uint8_t type_info[2];

    int ret_val = lto_select(serial_number, serial_len, type_info, verbose);
    if (verbose == false) {
        if (ret_val == PM3_SUCCESS) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, "UID......... " _YELLOW_("%s"), sprint_hex_inrow(serial_number, sizeof(serial_number)));
        }
        lto_switch_off_field();
        return ret_val;
    }

    if (ret_val == PM3_SUCCESS) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
        PrintAndLogEx(INFO, "UID......... " _YELLOW_("%s"), sprint_hex_inrow(serial_number, sizeof(serial_number)));
        PrintAndLogEx(INFO, "Type info... " _YELLOW_("%s"), sprint_hex_inrow(type_info, sizeof(type_info)));
        PrintAndLogEx(INFO, "Memory...... " _YELLOW_("%s"), lto_print_size(type_info[1]));
        if (type_info[1] > 3) {
            PrintAndLogEx(INFO, "Unknown LTO tag, report to @iceman!");
        }

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "--- " _CYAN_("LTO Cartridge Information") " -----------------");

        // read block 0
        uint8_t d00_d15[18];
        uint8_t d16_d31[18];
        if (lto_rdbl(0, d00_d15, d16_d31, verbose) == PM3_SUCCESS) {
            uint8_t b0[32];
            memcpy(b0, d00_d15, 16);
            memcpy(b0 + 16, d16_d31, 16);
            lto_print_ci(b0);
        }
        // read block 1
        if (lto_rdbl(1, d00_d15, d16_d31, verbose) == PM3_SUCCESS) {
            uint8_t b1[32];
            memcpy(b1, d00_d15, 16);
            memcpy(b1 + 16, d16_d31, 16);
            lto_print_cmwi(b1);
            lto_print_cmpt(b1 + 4);
        }
        // read block 2 - cartidge manufacture information
        if (lto_rdbl(2, d00_d15, d16_d31, verbose) == PM3_SUCCESS) {
            uint8_t b2_3[64];
            memcpy(b2_3, d00_d15, 16);
            memcpy(b2_3 + 16, d16_d31, 16);

            if (lto_rdbl(3, d00_d15, d16_d31, verbose) == PM3_SUCCESS) {
                memcpy(b2_3 + 32, d00_d15, 16);
                memcpy(b2_3 + 48, d16_d31, 16);
                lto_print_cmi(b2_3);
            }
        }

        if (lto_rdbl(4, d00_d15, d16_d31, verbose) == PM3_SUCCESS) {
            uint8_t b2_3[64];
            memcpy(b2_3, d00_d15, 16);
            memcpy(b2_3 + 16, d16_d31, 16);

            if (lto_rdbl(5, d00_d15, d16_d31, verbose) == PM3_SUCCESS) {
                memcpy(b2_3 + 32, d00_d15, 16);
                memcpy(b2_3 + 48, d16_d31, 16);
                lto_print_mmi(b2_3);
            }
        }


    }
    PrintAndLogEx(NORMAL, "");
    lto_switch_off_field();
    return ret_val;
}

static int CmdHfLTOList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf lto", "lto -c");
}

int rdblLTO(uint8_t st_blk, uint8_t end_blk, bool verbose) {

    clearCommandBuffer();
    lto_switch_on_field();

    uint8_t serial_number[5];
    uint8_t serial_len = sizeof(serial_number);
    uint8_t type_info[2];
    int ret_val = lto_select(serial_number, serial_len, type_info, verbose);

    if (ret_val != PM3_SUCCESS) {
        lto_switch_off_field();
        return ret_val;
    }

    uint8_t block_data_d00_d15[18];
    uint8_t block_data_d16_d31[18];
    uint8_t block_data[32];

    for (uint8_t i = st_blk; i < end_blk + 1; i++) {

        ret_val = lto_rdbl(i, block_data_d00_d15,  block_data_d16_d31, verbose);

        if (ret_val == PM3_SUCCESS) {

            memcpy(block_data, block_data_d00_d15, 16);
            memcpy(block_data + 16, block_data_d16_d31, 16);
            PrintAndLogEx(SUCCESS, "BLK %03d: " _YELLOW_("%s"), i, sprint_hex_inrow(block_data, sizeof(block_data)));
        } else {
            lto_switch_off_field();
            return ret_val;
        }
    }

    lto_switch_off_field();
    return ret_val;
}

static int CmdHfLTOReadBlock(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf lto rdbl",
                  "Reead blocks from LTO tag",
                  "hf lto rdbl --first 0 --last 254");

    void *argtable[] = {
        arg_param_begin,
        arg_int0(NULL, "first", "<dec>", "The first block number to read as an integer"),
        arg_int0(NULL, "last", "<dec>", "The last block number to read as an integer"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int startblock = arg_get_int_def(ctx, 1, 0);
    int endblock = arg_get_int_def(ctx, 2, 254);

    CLIParserFree(ctx);

    //Validations
    if (endblock < startblock) {
        PrintAndLogEx(ERR, "First block must be less than last block");
        return PM3_EINVARG;
    }

    return rdblLTO(startblock, endblock, true);
}

static int lto_wrbl(uint8_t blk, uint8_t *data, bool verbose) {

    uint8_t resp[] = {0, 0};
    uint16_t resp_len = 1;
    uint8_t wrbl_cmd[] = {0xA0, blk};
    uint8_t wrbl_d00_d15[16];
    uint8_t wrbl_d16_d31[16];

    memcpy(wrbl_d00_d15, data, 16);
    memcpy(wrbl_d16_d31, data + 16, 16);

    int status = lto_send_cmd_raw(wrbl_cmd, sizeof(wrbl_cmd), resp, &resp_len, true, false, verbose);
    if (status == PM3_ETIMEOUT || status == PM3_ESOFT || resp[0] != 0x0A) {
        return PM3_EWRONGANSWER; // WRITE BLOCK failed
    }

    status = lto_send_cmd_raw(wrbl_d00_d15, sizeof(wrbl_d00_d15), resp, &resp_len, true, false, verbose);
    if (status == PM3_ETIMEOUT || status == PM3_ESOFT || resp[0] != 0x0A) {
        return PM3_EWRONGANSWER; // WRITE BLOCK failed
    }

    status = lto_send_cmd_raw(wrbl_d16_d31, sizeof(wrbl_d16_d31), resp, &resp_len, true, false, verbose);
    if (status == PM3_ETIMEOUT || status == PM3_ESOFT || resp[0] != 0x0A) {
        return PM3_EWRONGANSWER; // WRITE BLOCK failed
    }

    return PM3_SUCCESS;
}

int wrblLTO(uint8_t blk, uint8_t *data, bool verbose) {

    clearCommandBuffer();
    lto_switch_on_field();

    uint8_t serial_number[5];
    uint8_t serial_len = sizeof(serial_number);
    uint8_t type_info[2];
    int ret_val = lto_select(serial_number, serial_len, type_info, verbose);

    if (ret_val != PM3_SUCCESS) {
        lto_switch_off_field();
        return ret_val;
    }

    ret_val = lto_wrbl(blk, data, verbose);
    lto_switch_off_field();

    if (ret_val == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "BLK %03d: " _YELLOW_("write success"), blk);
    } else {
        PrintAndLogEx(WARNING, "BLK %03d: write error. Maybe this is a read-only block address.",  blk);
    }

    return ret_val;
}

static int CmdHfLTOWriteBlock(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf lto wrbl",
                  "Write data to block on LTO tag",
                  "hf lto wrbl --block 128 -d 0001020304050607080910111213141516171819202122232425262728293031");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "data", "<hex>", "32 bytes of data to write (64 hex symbols, no spaces)"),
        arg_int1(NULL, "block", "<dec>", "The  block number to write to as an integer"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int block_data_len = 0;
    uint8_t block_data[32] = {0};

    CLIGetHexWithReturn(ctx, 1, block_data, &block_data_len);

    if (block_data_len != 32) {
        PrintAndLogEx(ERR, "Block data is incorrect length");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int blk = arg_get_int_def(ctx, 2, 0);

    CLIParserFree(ctx);

    int res = wrblLTO(blk, block_data, true);
    if (res == PM3_SUCCESS)
        PrintAndLogEx(HINT, "Try use 'hf lto rdbl' for verification");

    return res;
}

int dumpLTO(uint8_t *dump, bool verbose) {

    clearCommandBuffer();
    lto_switch_on_field();

    uint8_t serial_number[5];
    uint8_t serial_len = sizeof(serial_number);
    uint8_t type_info[2];
    int ret_val = lto_select(serial_number, serial_len, type_info, verbose);

    if (ret_val != PM3_SUCCESS) {
        lto_switch_off_field();
        return ret_val;
    }
    // 0003 == 255 blocks x 32 = 8160 bytes
    // 0002 ==  95 blocks x 32 = 3040 bytes
    // 0001 == 101 blocks x 32 = 3232 bytes
    uint8_t blocks = 0xFF;
    if (type_info[1] == 0x01) {
        blocks = 0x65;
    } else if (type_info[1] == 0x02) {
        blocks = 0x5F;
    }
    PrintAndLogEx(SUCCESS, "Found LTO tag w " _YELLOW_("%s") " memory", lto_print_size(type_info[1]));

    uint8_t block_data_d00_d15[18];
    uint8_t block_data_d16_d31[18];

    for (uint8_t i = 0; i < blocks; i++) {

        ret_val = lto_rdbl(i, block_data_d00_d15,  block_data_d16_d31, verbose);

        if (ret_val == PM3_SUCCESS) {
            // remove CRCs
            memcpy(dump + i * 32, block_data_d00_d15, 16);
            memcpy(dump + (i * 32) + 16, block_data_d16_d31, 16);
        } else {
            lto_switch_off_field();
            return ret_val;
        }
        PrintAndLogEx(INPLACE, "...reading block %d", i);
        fflush(stdout);
    }

    lto_switch_off_field();
    return ret_val;
}

static int CmdHfLTODump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf lto dump",
                  "Dump data from LTO tag",
                  "hf lto dump -f myfile");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "specify a filename for dumpfile"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    uint32_t dump_len = CM_MEM_MAX_SIZE;
    uint8_t *dump = calloc(dump_len, sizeof(uint8_t));
    if (!dump) {
        PrintAndLogEx(ERR, "error, cannot allocate memory");
        return PM3_EMALLOC;
    }

    int ret_val = dumpLTO(dump, true);
    PrintAndLogEx(NORMAL, "");
    if (ret_val != PM3_SUCCESS) {
        free(dump);
        return ret_val;
    }

    if (strlen(filename) == 0) {
        char *fptr = filename + snprintf(filename, sizeof(filename), "hf-lto-");
        FillFileNameByUID(fptr, dump, "-dump", 5);
    }
    saveFile(filename, ".bin", dump, dump_len);
    saveFileEML(filename, dump, dump_len, 32);
    free(dump);
    return PM3_SUCCESS;
}

int restoreLTO(uint8_t *dump, bool verbose) {

    clearCommandBuffer();
    lto_switch_on_field();

    uint8_t type_info[2];
    uint8_t serial_number[5];
    uint8_t serial_len = sizeof(serial_number);
    int ret_val = lto_select(serial_number, serial_len, type_info, verbose);

    if (ret_val != PM3_SUCCESS) {
        lto_switch_off_field();
        return ret_val;
    }

    uint8_t block_data[32] = {0};

    //Block address 0 and 1 are read-only
    for (uint8_t blk = 2; blk < 255; blk++) {

        memcpy(block_data, dump + (blk * 32), 32);

        ret_val = lto_wrbl(blk, block_data, verbose);

        if (ret_val == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "Block %03d - " _YELLOW_("write success"), blk);
        } else {
            lto_switch_off_field();
            return ret_val;
        }
    }

    lto_switch_off_field();
    return ret_val;
}

static int CmdHfLTRestore(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf lto restore",
                  "Restore data from dumpfile to LTO tag",
                  "hf lto restore -f hf-lto-92C7842CFF.bin|.eml");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "specify a filename for dumpfile"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    CLIParserFree(ctx);

    size_t dump_len = 0;
    char *lowstr = str_dup(filename);
    str_lower(lowstr);

    if (str_endswith(lowstr, ".bin")) {

        uint8_t *dump = NULL;
        if (loadFile_safe(filename, "", (void **)&dump, &dump_len) == PM3_SUCCESS) {
            restoreLTO(dump, true);
        }
        free(dump);

    } else if (str_endswith(lowstr, ".eml")) {

        uint8_t *dump = NULL;
        if (loadFileEML_safe(filename, (void **)&dump, &dump_len) == PM3_SUCCESS) {
            restoreLTO(dump, true);
        }
        free(dump);

    } else {
        PrintAndLogEx(WARNING, "Warning: invalid dump filename " _YELLOW_("%s") " to restore", filename);
    }
    free(lowstr);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",     CmdHelp,             AlwaysAvailable, "This help"},
    {"dump",     CmdHfLTODump,        IfPm3Iso14443a,  "Dump LTO-CM tag to file"},
    {"info",     CmdHfLTOInfo,        IfPm3Iso14443a,  "Tag information"},
    {"list",     CmdHfLTOList,        AlwaysAvailable, "List LTO-CM history"},
    {"rdbl",     CmdHfLTOReadBlock,   IfPm3Iso14443a,  "Read block"},
    {"reader",   CmdHFLTOReader,      IfPm3Iso14443a,  "Act like a LTO-CM reader"},
    {"restore",  CmdHfLTRestore,      IfPm3Iso14443a,  "Restore dump file to LTO-CM tag"},
    {"wrbl",     CmdHfLTOWriteBlock,  IfPm3Iso14443a,  "Write block"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFLTO(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
