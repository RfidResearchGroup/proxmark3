//-----------------------------------------------------------------------------
// Copyright (C) 2018 iceman <iceman at iuse.se>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Trace commands
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

static void print_wiegand_code(wiegand_message_t *packed) {
    const char *s = "Encoded wiegand: ";
    if (packed->Top != 0) {
        PrintAndLogEx(SUCCESS, "%s" _GREEN_("%X%08X%08X"),
                      s,
                      (uint32_t)packed->Top,
                      (uint32_t)packed->Mid,
                      (uint32_t)packed->Bot
                     );
    } else {
        PrintAndLogEx(SUCCESS, "%s" _YELLOW_("%X%08X"),
                      s,
                      (uint32_t)packed->Mid,
                      (uint32_t)packed->Bot
                     );
    }
}

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
                  "wiegand encode -w H10301 --fc 101 --cn 1337"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0(NULL, "fc", "<dec>", "facility number"),
        arg_u64_1(NULL, "cn", "<dec>", "card number"),
        arg_u64_0(NULL, "issue", "<dec>", "issue level"),
        arg_u64_0(NULL, "oem", "<dec>", "OEM code"),
        arg_str1("w", "wiegand", "<format>", "see `wiegand list` for available formats"),
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
    CLIParserFree(ctx);

    int idx = HIDFindCardFormat(format);
    if (idx == -1) {
        PrintAndLogEx(WARNING, "Unknown format: %s", format);
        return PM3_EINVARG;
    }

    wiegand_message_t packed;
    memset(&packed, 0, sizeof(wiegand_message_t));

    if (HIDPack(idx, &data, &packed) == false) {
        PrintAndLogEx(WARNING, "The card data could not be encoded in the selected format.");
        return PM3_ESOFT;
    }

    print_wiegand_code(&packed);
    return PM3_SUCCESS;
}

int CmdWiegandDecode(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "wiegand decode",
                  "Decode raw hex to wiegand format",
                  "wiegand decode --raw 2006f623ae"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("p", "parity", "ignore invalid parity"),
        arg_strx1("r", "raw", "<hex>", "raw hex to be decoded"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool ignore_parity = arg_get_lit(ctx, 1);
    int len = 0;
    char hex[40] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)hex, sizeof(hex), &len);
    CLIParserFree(ctx);

    if (len == 0) {
        PrintAndLogEx(ERR, "empty input");
        return PM3_EINVARG;
    }

    uint32_t top = 0, mid = 0, bot = 0;
    hexstring_to_u96(&top, &mid, &bot, hex);

    wiegand_message_t packed = initialize_message_object(top, mid, bot);
    HIDTryUnpack(&packed, ignore_parity);

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
