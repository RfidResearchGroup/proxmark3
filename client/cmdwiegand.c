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
#include "comms.h"
#include "pm3_cmd.h"
#include "protocols.h"
#include "parity.h"             // oddparity
#include "cmdhflist.h"          // annotations
#include "wiegand_formats.h"
#include "wiegand_formatutils.h"
#include "util.h"

static int CmdHelp(const char *Cmd);

static int usage_wiegand_list() {
    PrintAndLogEx(NORMAL, "List available wiegand formats");
    return PM3_SUCCESS;
}
static int usage_wiegand_encode() {
    PrintAndLogEx(NORMAL, "Encode wiegand formatted number to raw hex");
    PrintAndLogEx(NORMAL, "Usage:  wiegand encode [w <format>] [<field> <value (decimal)>] {...}");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "          w <format>       see `wiegand list` for available formats");
    PrintAndLogEx(NORMAL, "          c <value>        card number");
    PrintAndLogEx(NORMAL, "          f <value>        facility code");
    PrintAndLogEx(NORMAL, "          i <value>        issue Level");
    PrintAndLogEx(NORMAL, "          o <value>        OEM code");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "samples:");
    PrintAndLogEx(NORMAL, "      wiegand encode w H10301 f 101 c 1337");
    return PM3_SUCCESS;
}
static int usage_wiegand_decode() {
    PrintAndLogEx(NORMAL, "Decode raw hex to wiegand format");
    PrintAndLogEx(NORMAL, "Usage:  wiegand decode [id] <p>");
    PrintAndLogEx(NORMAL, "        p         ignore invalid parity");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Samples:");
    PrintAndLogEx(NORMAL, "          wiegand decode 2006f623ae");
    return PM3_SUCCESS;
}

void PrintTagId(wiegand_message_t *packed) {
    if (packed->Top != 0) {
        PrintAndLogEx(SUCCESS, "Card ID: %X%08X%08X",
                      (uint32_t)packed->Top,
                      (uint32_t)packed->Mid,
                      (uint32_t)packed->Bot)
        ;
    } else {
        PrintAndLogEx(SUCCESS, "Card ID: %X%08X",
                      (uint32_t)packed->Mid,
                      (uint32_t)packed->Bot)
        ;
    }
}

int CmdWiegandList(const char *Cmd) {
    bool errors = false;
    char cmdp = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_wiegand_list();
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    HIDListFormats();
    return PM3_SUCCESS;
}

int CmdWiegandEncode(const char *Cmd) {

    int format_idx = -1;
    char format[16] = {0};

    wiegand_card_t data;
    memset(&data, 0, sizeof(wiegand_card_t));

    bool errors = false;
    char cmdp = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_wiegand_encode();
            case 'w':
                param_getstr(Cmd, cmdp + 1, format, sizeof(format));
                format_idx = HIDFindCardFormat(format);
                if (format_idx == -1) {
                    PrintAndLogEx(WARNING, "Unknown format: %s", format);
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'i':
                data.IssueLevel = param_get32ex(Cmd, cmdp + 1, 0, 10);
                cmdp += 2;
                break;
            case 'f':
                data.FacilityCode = param_get32ex(Cmd, cmdp + 1, 0, 10);
                cmdp += 2;
                break;
            case 'c':
                data.CardNumber = param_get64ex(Cmd, cmdp + 1, 0, 10);
                cmdp += 2;
                break;
            case 'o':
                data.OEM = param_get32ex(Cmd, cmdp + 1, 0, 10);
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    if (errors || cmdp == 0) return usage_wiegand_encode();

    wiegand_message_t packed;
    memset(&packed, 0, sizeof(wiegand_message_t));

    if (HIDPack(format_idx, &data, &packed) == false) {
        PrintAndLogEx(WARNING, "The card data could not be encoded in the selected format.");
        return PM3_ESOFT;
    }

    PrintTagId(&packed);
    return PM3_SUCCESS;
}

int CmdWiegandDecode(const char *Cmd) {

    uint32_t top = 0, mid = 0, bot = 0;
    bool ignore_parity = false, gothex = false;
    bool errors = false;
    char cmdp = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        uint32_t slen = param_getlength(Cmd, cmdp);
        slen++; // null termin
        if (slen > 2) {
            char *s = calloc(slen, sizeof(uint8_t));
            param_getstr(Cmd, cmdp, s, slen);
            hexstring_to_u96(&top, &mid, &bot, s);
            free(s);
            gothex = true;
            cmdp++;
            continue;
        }
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_wiegand_decode();
            case 'p':
                ignore_parity = true;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    if (gothex == false)
        errors = true;

    if (errors || cmdp < 1) return usage_wiegand_decode();

    wiegand_message_t packed = initialize_message_object(top, mid, bot);

    HIDTryUnpack(&packed, ignore_parity);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,           AlwaysAvailable, "This help"},
    {"list",    CmdWiegandList,    AlwaysAvailable, "List available wiegand formats"},
    {"encode",  CmdWiegandEncode,  AlwaysAvailable, "Convert "},
    {"decode",  CmdWiegandDecode,  AlwaysAvailable, "Convert raw hex to wiegand format"},
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
