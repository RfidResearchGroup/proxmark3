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
// Wiegand commands
//-----------------------------------------------------------------------------
#include "cmdwiegand.h"

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "cmdparser.h"          // command_t
#include "cliparser.h"
#include "comms.h"
#include "pm3_cmd.h"
#include "protocols.h"
#include "parity.h"             // oddparity
#include "cmdhflist.h"          // annotations
#include "wiegand_formats.h"
#include "wiegand_formatutils.h"
#include "util.h"

static int CmdHelp(const char *Cmd);

int CmdWiegandList(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "wiegand info",
                  "List available wiegand formats",
                  "wiegand list"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    HIDListFormats();
    return PM3_SUCCESS;
}

int CmdWiegandEncode(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "wiegand encode",
                  "Encode wiegand formatted number to raw hex",
                  "wiegand encode --fc 101 --cn 1337               ->  show all formats\n"
                  "wiegand encode -w H10301 --fc 101 --cn 1337     ->  H10301 format "
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0(NULL, "fc", "<dec>", "facility number"),
        arg_u64_1(NULL, "cn", "<dec>", "card number"),
        arg_u64_0(NULL, "issue", "<dec>", "issue level"),
        arg_u64_0(NULL, "oem", "<dec>", "OEM code"),
        arg_str0("w", "wiegand", "<format>", "see `wiegand list` for available formats"),
        arg_lit0(NULL, "pre", "add HID ProxII preamble to wiegand output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    wiegand_card_t data;
    memset(&data, 0, sizeof(wiegand_card_t));

    data.FacilityCode = arg_get_u32_def(ctx, 1, 0);
    data.CardNumber = arg_get_u64_def(ctx, 2, 0);
    data.IssueLevel = arg_get_u32_def(ctx, 3, 0);
    data.OEM = arg_get_u32_def(ctx, 4, 0);

    int len = 0;
    char format[16] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 5), (uint8_t *)format, sizeof(format), &len);
    bool preamble = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    int idx = -1;
    if (len) {
        idx = HIDFindCardFormat(format);
        if (idx == -1) {
            PrintAndLogEx(WARNING, "Unknown format: %s", format);
            return PM3_EINVARG;
        }
    }

    if (idx != -1) {
        wiegand_message_t packed;
        memset(&packed, 0, sizeof(wiegand_message_t));
        if (HIDPack(idx, &data, &packed, preamble) == false) {
            PrintAndLogEx(WARNING, "The card data could not be encoded in the selected format.");
            return PM3_ESOFT;
        }
        print_wiegand_code(&packed);
    } else {
        // try all formats and print only the ones that work.
        HIDPackTryAll(&data, preamble);
    }
    return PM3_SUCCESS;
}

int CmdWiegandDecode(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "wiegand decode",
                  "Decode raw hex or binary to wiegand format",
                  "wiegand decode --raw 2006f623ae"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("r", "raw", "<hex>", "raw hex to be decoded"),
        arg_str0("b", "bin", "<bin>", "binary string to be decoded"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int hlen = 0;
    char hex[40] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)hex, sizeof(hex), &hlen);

    int blen = 0;
    uint8_t binarr[100] = {0x00};
    int res = CLIParamBinToBuf(arg_get_str(ctx, 2), binarr, sizeof(binarr), &blen);
    CLIParserFree(ctx);

    if (res) {
        PrintAndLogEx(FAILED, "Error parsing binary string");
        return PM3_EINVARG;
    }

    uint32_t top = 0, mid = 0, bot = 0;

    if (hlen) {
        res = hexstring_to_u96(&top, &mid, &bot, hex);
        if (res != hlen) {
            PrintAndLogEx(ERR, "hex string contains none hex chars");
            return PM3_EINVARG;
        }
    } else if (blen) {
        int n = binarray_to_u96(&top, &mid, &bot, binarr, blen);
        if (n != blen) {
            PrintAndLogEx(ERR, "Binary string contains none <0|1> chars");
            return PM3_EINVARG;
        }
    } else {
        PrintAndLogEx(ERR, "empty input");
        return PM3_EINVARG;
    }

    wiegand_message_t packed = initialize_message_object(top, mid, bot, blen);
    HIDTryUnpack(&packed);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,           AlwaysAvailable, "This help"},
    {"list",    CmdWiegandList,    AlwaysAvailable, "List available wiegand formats"},
    {"encode",  CmdWiegandEncode,  AlwaysAvailable, "Encode to wiegand raw hex (currently for HID Prox)"},
    {"decode",  CmdWiegandDecode,  AlwaysAvailable, "Convert raw hex to decoded wiegand format (currently for HID Prox)"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdWiegand(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
