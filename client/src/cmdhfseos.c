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
// SEOS commands
//-----------------------------------------------------------------------------
#include "cmdhfseos.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>              // tolower
#include "cliparser.h"
#include "cmdparser.h"          // command_t
#include "comms.h"              // clearCommandBuffer
#include "cmdtrace.h"
#include "crc16.h"
#include "ui.h"
#include "cmdhf14a.h"           // manufacture
#include "protocols.h"          // definitions of ISO14A/7816 protocol
#include "iso7816/apduinfo.h"   // GetAPDUCodeDescription
#include "crypto/asn1utils.h"   // ASN1 decode / print
#include "commonutil.h"         // get_sw
#include "protocols.h"          // ISO7816 APDU return codes

static int CmdHelp(const char *Cmd);

static int seos_select(void) {
    bool activate_field = true;
    bool keep_field_on = true;
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;

    // ---------------  Select SEOS applet ----------------
    uint8_t aSELECT_AID[80];
    int aSELECT_AID_n = 0;
    param_gethex_to_eol("00a404000aa000000440000101000100", 0, aSELECT_AID, sizeof(aSELECT_AID), &aSELECT_AID_n);
    int res = ExchangeAPDU14a(aSELECT_AID, aSELECT_AID_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    if (resplen < 2) {
        DropField();
        return PM3_ESOFT;
    }

    uint16_t sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Selecting SEOS applet aid failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    activate_field = false;
    keep_field_on = false;
    // ---------------  CC file reading ----------------

    uint8_t aSELECT_FILE_ADF[30];
    int aSELECT_FILE_ADF_n = 0;
    param_gethex_to_eol("80a504001306112b0601040181e43801010201180101020200", 0, aSELECT_FILE_ADF, sizeof(aSELECT_FILE_ADF), &aSELECT_FILE_ADF_n);
    res = ExchangeAPDU14a(aSELECT_FILE_ADF, aSELECT_FILE_ADF_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Selecting ADF file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    // remove the 2byte SW
    asn1_print(response, resplen - 2, "  ");
    return PM3_SUCCESS;
}

int infoSeos(bool verbose) {
    int res = seos_select();
    if (res == PM3_SUCCESS) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
    }
    return PM3_SUCCESS;
}

static int CmdHfSeosInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf seos info",
                  "Get info from SEOS tags",
                  "hf seos info");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return infoSeos(true);
}

static int CmdHfSeosList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf seos", "7816");
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,        AlwaysAvailable, "This help"},
    {"info",    CmdHfSeosInfo,  IfPm3NfcBarcode, "Tag information"},
    {"list",    CmdHfSeosList,  AlwaysAvailable, "List SEOS history"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFSeos(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
