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
// Thinfilm commands
//-----------------------------------------------------------------------------
#include "cmdhfthinfilm.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "cliparser.h"
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "cmdtrace.h"
#include "crc16.h"
#include "ui.h"
#include "cmdhf14a.h" // manufacture

static int CmdHelp(const char *Cmd);

// Printing function based upon the code in libnfc
// ref
//    https://github.com/nfc-tools/libnfc/blob/master/utils/nfc-barcode.c
static int print_barcode(uint8_t *barcode, const size_t barcode_len, bool verbose) {

    PrintAndLogEx(NORMAL, "");
    // remove start bit
    uint8_t mb = barcode[0] & ~0x80;
    PrintAndLogEx(SUCCESS, "    Manufacturer : "_YELLOW_("%s") "[0x%02X]",  getTagInfo(mb), mb);

    if (verbose) {
        PrintAndLogEx(SUCCESS, "     Data format : "_YELLOW_("%02X"), barcode[1]);
        if (barcode_len > 2) {
            uint8_t b1 = 0, b2 = 0;
            compute_crc(CRC_14443_A, barcode, barcode_len - 2, &b1, &b2);
            bool isok = (barcode[barcode_len - 1] == b1 && barcode[barcode_len - 2] == b2);

            PrintAndLogEx(SUCCESS, "        Checksum : "_YELLOW_("%02X %02X")" ( %s )", b2, b1, (isok) ? _GREEN_("ok") : _RED_("fail"));
        } else {
            PrintAndLogEx(SUCCESS, "        Checksum : "_YELLOW_("too few data for checksum")" - " _RED_("fail"));
        }
        PrintAndLogEx(SUCCESS, " Data len (bits) : "_YELLOW_("%zu")" ( %s )", barcode_len * 8, (barcode_len == 16 || barcode_len == 32) ? _GREEN_("ok") : _YELLOW_("warning"));
        PrintAndLogEx(SUCCESS, "        Raw data : "_YELLOW_("%s"), sprint_hex(barcode, barcode_len));
        if (barcode_len < 4) // too few to go to next decoding stages
            return PM3_ESOFT;
    }

    char s[45];
    memset(s, 0x00, sizeof(s));

    switch (barcode[1]) {
        case 0:
            PrintAndLogEx(SUCCESS, "     Data format : Reserved for allocation by tag manufacturer");
            return PM3_SUCCESS;
        case 1:
            snprintf(s, sizeof(s), "http://www.");
            break;
        case 2:
            snprintf(s, sizeof(s), "https://www.");
            break;
        case 3:
            snprintf(s, sizeof(s), "http://");
            break;
        case 4:
            snprintf(s, sizeof(s), "https://");
            break;
        case 5:
            if (barcode_len < 16) {
                PrintAndLogEx(WARNING, "EPC: (partial data) %s", sprint_hex(barcode + 2, barcode_len - 2));
                return PM3_ESOFT;
            }
            PrintAndLogEx(SUCCESS, "EPC: %s", sprint_hex(barcode + 2, 12));
            return PM3_SUCCESS;
        default:
            PrintAndLogEx(SUCCESS, "     Data format : RFU Reserved for future use (%02X)", barcode[1]);
            if (!verbose)
                PrintAndLogEx(SUCCESS, "Raw data with CRC: "_YELLOW_("%s"), sprint_hex(barcode, barcode_len));
            return PM3_SUCCESS;
    }

    snprintf(s + strlen(s), barcode_len - 3, (const char *)&barcode[2], barcode_len - 4);

    for (size_t i = 0; i < strlen(s); i++) {

        // terminate string
        if ((uint8_t) s[i] == 0xFE) {
            s[i] = 0;
            break;
        }
    }
    PrintAndLogEx(SUCCESS, " Decoded NFC URL : "_YELLOW_("%s"), s);
    return PM3_SUCCESS;
}

int CmdHfThinFilmInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf thinfilm info",
                  "Get info from Thinfilm tags",
                  "hf thinfilm info");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return infoThinFilm(true);
}

int infoThinFilm(bool verbose) {

    clearCommandBuffer();
    SendCommandNG(CMD_HF_THINFILM_READ, NULL, 0);

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_HF_THINFILM_READ, &resp, 1500)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_SUCCESS) {
        if (resp.length == 16 || resp.length == 32)  {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
            print_barcode(resp.data.asBytes, resp.length, verbose);
        } else {
            if (verbose)
                PrintAndLogEx(WARNING, "Response is wrong length. (%d)", resp.length);

            return PM3_ESOFT;
        }
    }

    return resp.status;
}

int CmdHfThinFilmSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf thinfilm sim",
                  "Simulate Thinfilm tag",
                  "hf thinfilm sim -d B70470726f786d61726b2e636f6d");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "data", "<hex>", "bytes to send"),
        arg_lit0(NULL, "raw", "raw, provided bytes should include CRC"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int data_len = 0;
    uint8_t data[512] = {0};
    CLIGetHexWithReturn(ctx, 1, data, &data_len);

    bool addcrc = true;

    if (arg_get_lit(ctx, 2)) {
        addcrc = false;
    }

    CLIParserFree(ctx);

    if (addcrc && data_len <= 510) {
        uint8_t b1 = 0, b2 = 0;
        compute_crc(CRC_14443_A, data, data_len, &b1, &b2);
        data[data_len++] = b2;
        data[data_len++] = b1;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_THINFILM_SIMULATE, (uint8_t *)&data, data_len);
    PacketResponseNG resp;
    PrintAndLogEx(SUCCESS, "press pm3-button to abort simulation");

    int ret;
    while (!(ret = kbd_enter_pressed())) {
        if (WaitForResponseTimeout(CMD_HF_THINFILM_SIMULATE, &resp, 500) == 0) continue;
        if (resp.status != PM3_SUCCESS) break;
    }
    if (ret) {
        PrintAndLogEx(INFO, "Client side interrupted");
        PrintAndLogEx(WARNING, "Simulation still running on Proxmark3 till next command or button press");
    } else {
        PrintAndLogEx(INFO, "Done");
    }
    return PM3_SUCCESS;
}

static int CmdHfThinFilmList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf thinfilm", "thinfilm");
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,            AlwaysAvailable, "This help"},
    {"info",    CmdHfThinFilmInfo,  IfPm3NfcBarcode, "Tag information"},
    {"list",    CmdHfThinFilmList,  AlwaysAvailable, "List NFC Barcode / Thinfilm history - not correct"},
    {"sim",     CmdHfThinFilmSim,   IfPm3NfcBarcode, "Fake Thinfilm tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFThinfilm(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
