//-----------------------------------------------------------------------------
// Copyright (C) 2021 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency FIDO U2F and FIDO2 contactless authenticators
//-----------------------------------------------------------------------------
//
//  JAVA implementation here:
//
//  https://github.com/duychuongvn/cipurse-card-core
//-----------------------------------------------------------------------------

#include "cmdhffido.h"
#include <unistd.h>
#include "cmdparser.h"    // command_t
#include "commonutil.h"
#include "comms.h"
#include "proxmark3.h"
#include "emv/emvcore.h"
#include "emv/emvjson.h"
#include "cliparser.h"
#include "cmdhfcipurse.h"
#include "cipurse/cipursecore.h"
#include "cipurse/cipursecrypto.h"
#include "ui.h"
#include "cmdhf14a.h"
#include "cmdtrace.h"
#include "util.h"
#include "fileutils.h"   // laodFileJSONroot

static int CmdHelp(const char *Cmd);

static int CmdHFCipurseInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cipurse info",
                  "Get info from cipurse tags",
                  "hf cipurse info");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    // info about 14a part
    infoHF14A(false, false, false);

    // CIPURSE info
    PrintAndLogEx(INFO, "-----------" _CYAN_("CIPURSE Info") "---------------------------------");
    SetAPDULogging(false);

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = CIPURSESelect(true, true, buf, sizeof(buf), &len, &sw);

    if (res) {
        DropField();
        return res;
    }

    if (sw != 0x9000) {
        if (sw)
            PrintAndLogEx(INFO, "Not a CIPURSE card! APDU response: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        else
            PrintAndLogEx(ERR, "APDU exchange error. Card returns 0x0000.");

        DropField();
        return PM3_SUCCESS;
    }

    PrintAndLogEx(INFO, "Cipurse card: " _GREEN_("OK"));



    DropField();
    return PM3_SUCCESS;
}

static int CmdHFCipurseAuth(const char *Cmd) {
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    
    SetAPDULogging(true);
    
    int res = CIPURSESelect(true, true, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != 0x9000) {
        PrintAndLogEx(ERR, "Cipurse select error. Card returns 0x%04x.", sw);
        DropField();
        return PM3_ESOFT;
    }
    
    uint8_t key[] = {0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73};
    CipurseContext ctx = {0};
    CipurseSetKey(&ctx, 1, key);
    
    uint8_t kvv[CIPURSE_KVV_LENGTH] = {0};
    CipurseCGetKVV(key, kvv);
    PrintAndLogEx(INFO, "Key: %s KVV: %s", sprint_hex(key, CIPURSE_AES_KEY_LENGTH), sprint_hex_inrow(kvv, CIPURSE_KVV_LENGTH));

    res = CIPURSEChallenge(buf, sizeof(buf), &len, &sw);
    if (res != 0 || len != 0x16) {
        PrintAndLogEx(ERR, "Cipurse get challenge error. Card returns 0x%04x.", sw);
        DropField();
        return PM3_ESOFT;
    }
    CipurseSetRandomFromPICC(&ctx, buf);
    
    
    
    
    DropField();
    return PM3_SUCCESS;
}









bool CheckCardCipurse(void) {
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = CIPURSESelect(true, false, buf, sizeof(buf), &len, &sw);

    return (res == 0 && sw == 0x9000);
}

static command_t CommandTable[] = {
    {"help",      CmdHelp,                   AlwaysAvailable, "This help."},
    {"info",      CmdHFCipurseInfo,          IfPm3Iso14443a,  "Info about Cipurse tag."},
    {"auth",      CmdHFCipurseAuth,          IfPm3Iso14443a,  "Authentication."},
    {NULL, NULL, 0, NULL}
};

int CmdHFCipurse(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}
