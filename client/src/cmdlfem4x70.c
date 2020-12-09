//-----------------------------------------------------------------------------
// Copyright (C) 2020 sirloins
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency EM4x70 commands
//-----------------------------------------------------------------------------

#include "cmdlfem4x70.h"
#include <ctype.h>
#include "cmdparser.h"    // command_t
#include "cliparser.h"
#include "fileutils.h"
#include "commonutil.h"
#include "em4x70.h"


static int CmdHelp(const char *Cmd);

static void print_info_result(uint8_t *data) {

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
    PrintAndLogEx(INFO, "-------------------------------------------------------------");

    // data section
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, _YELLOW_("EM4x70 data:"));
    
    for(int i=1; i <= 32; i+=2) {
        PrintAndLogEx(NORMAL, "%02X %02X", data[32-i], data[32-i-1]);
    }
    PrintAndLogEx(NORMAL, "Tag ID: %02X %02X %02X %02X", data[7], data[6], data[5], data[4]);
    PrintAndLogEx(NORMAL, "Lockbit 0: %d", (data[3] & 0x40) ? 1:0);
    PrintAndLogEx(NORMAL, "Lockbit 1: %d", (data[3] & 0x80) ? 1:0);
    PrintAndLogEx(NORMAL, "");

}

int em4x70_info(void) {
    
    em4x70_data_t edata = {
        .parity = false // TODO: try both? or default to true
    };

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X70_INFO, (uint8_t *)&edata, sizeof(edata));
    
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X70_INFO, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "(em4x70) timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.status) {
        print_info_result(resp.data.asBytes);
        return PM3_SUCCESS;
    }

    return PM3_ESOFT;
}

//quick test for EM4x70 tag
bool detect_4x70_block(void) {

    return em4x70_info() == PM3_SUCCESS;
}

int CmdEM4x70Info(const char *Cmd) {

    // envoke reading of a EM4x70 tag which has to be on the antenna because
    // decoding is done by the device (not on client side)

    em4x70_data_t etd = {0};

    CLIParserContext *ctx;

    CLIParserInit(&ctx, "lf em 4x10 info",
                  "Tag Information EM4x70\n"
                  "  Tag variants include ID48 automotive transponder.\n"
                  "  ID48 does not use command parity (default).\n"
                  "  V4070 and EM4170 do require parity bit.",
                  "lf em 4x70 info\n"
                  "lf em 4x70 -p -> adds parity bit to commands\n"
                );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("p", "parity", "Add parity bit when sending commands"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    etd.parity = arg_get_lit(ctx, 0);
    CLIParserFree(ctx);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X70_INFO, (uint8_t *)&etd, sizeof(etd));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X70_INFO, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.status) {
        print_info_result(resp.data.asBytes);
        return PM3_SUCCESS;
    }

    PrintAndLogEx(FAILED, "reading tag " _RED_("failed"));
    return PM3_ESOFT;
}

static command_t CommandTable[] = {
    {"help",   CmdHelp,         AlwaysAvailable, "This help"},
    {"info",   CmdEM4x70Info,   IfPm3EM4x70,     "tag information EM4x70"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFEM4X70(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
