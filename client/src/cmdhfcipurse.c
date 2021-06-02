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

    res = CIPURSESelectFile(0x2ff7, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != 0x9000) {
        DropField();
        return PM3_SUCCESS;
    }

    res = CIPURSEReadBinary(0, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != 0x9000) {
        DropField();
        return PM3_SUCCESS;
    }
    
    if (len > 0) {
        PrintAndLogEx(INFO, "Info file: " _GREEN_("OK"));
        PrintAndLogEx(INFO, "[%d]: %s", len, sprint_hex(buf, len));
        CIPURSEPrintInfoFile(buf, len);
    }

    DropField();
    return PM3_SUCCESS;
}

static int CmdHFCipurseAuth(const char *Cmd) {
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    uint8_t keyId = 1;
    uint8_t key[] = {0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73};

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cipurse auth",
                  "Authenticate with key ID and key",
                  "hf cipurse auth      -> Authenticate with keyID=1 and key = 7373...7373\n"
                  "hf cipurse auth -n 2 -k 65656565656565656565656565656565 -> Authenticate with key\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyid",   "<dec>", "key id"),
        arg_str0("k",  "key",     "<hex>", "key for authenticate"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    
    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    keyId = arg_get_int_def(ctx, 3, 1);
    
    uint8_t hdata[250] = {0};
    int hdatalen = sizeof(hdata);    
    CLIGetHexWithReturn(ctx, 4, hdata, &hdatalen);
    if (hdatalen && hdatalen != 16) {
        PrintAndLogEx(ERR, _RED_("ERROR:") " key length for AES128 must be 16 bytes only.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    if (hdatalen)
        memcpy(key, hdata, CIPURSE_AES_KEY_LENGTH);
    
    SetAPDULogging(APDULogging);

    CLIParserFree(ctx);
    
    int res = CIPURSESelect(true, true, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != 0x9000) {
        PrintAndLogEx(ERR, "Cipurse select " _RED_("error") ". Card returns 0x%04x.", sw);
        DropField();
        return PM3_ESOFT;
    }
        
    uint8_t kvv[CIPURSE_KVV_LENGTH] = {0};
    CipurseCGetKVV(key, kvv);
    if (verbose)
        PrintAndLogEx(INFO, "Key id: %d key: %s KVV: %s", keyId, sprint_hex(key, CIPURSE_AES_KEY_LENGTH), sprint_hex_inrow(kvv, CIPURSE_KVV_LENGTH));

    bool bres = CIPURSEChannelAuthenticate(keyId, key, verbose);
    
    if (verbose == false) {
        if (bres)
            PrintAndLogEx(INFO, "Authentication " _GREEN_("OK"));
        else
            PrintAndLogEx(ERR, "Authentication " _RED_("ERROR"));
    }
    
    DropField();
    return bres ? PM3_SUCCESS : PM3_ESOFT;
}

static int CmdHFCipurseReadFile(const char *Cmd) {
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    uint8_t key[] = CIPURSE_DEFAULT_KEY;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cipurse read",
                  "Read file by file ID with key ID and key",
                  "hf cipurse read -f 2ff7   -> Authenticate with keyID=1 and key = 7373...7373 and read file with id 2ff7\n"
                  "hf cipurse auth -n 2 -k 65656565656565656565656565656565 -f 2ff7 -> Authenticate with specified key and read file\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  "keyid",   "<dec>", "key id"),
        arg_str0("k",  "key",     "<hex>", "key for authenticate"),
        arg_str0("f",  "file",    "<hex>", "file ID"),
        arg_int0("o",  "offset",  "<dec>", "offset for reading data from file"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    
    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    uint8_t keyId = arg_get_int_def(ctx, 3, 1);
    
    uint8_t hdata[250] = {0};
    int hdatalen = sizeof(hdata);    
    CLIGetHexWithReturn(ctx, 4, hdata, &hdatalen);
    if (hdatalen && hdatalen != 16) {
        PrintAndLogEx(ERR, _RED_("ERROR:") " key length for AES128 must be 16 bytes only.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    if (hdatalen)
        memcpy(key, hdata, CIPURSE_AES_KEY_LENGTH);
    
    uint16_t fileId = 0x2ff7;
    
    hdatalen = sizeof(hdata);    
    CLIGetHexWithReturn(ctx, 5, hdata, &hdatalen);
    if (hdatalen && hdatalen != 2) {
        PrintAndLogEx(ERR, _RED_("ERROR:") " file id length must be 2 bytes only.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    if (hdatalen)
        fileId = (hdata[0] << 8) + hdata[1];
    
    size_t offset = arg_get_int_def(ctx, 6, 0);
    
    SetAPDULogging(APDULogging);

    CLIParserFree(ctx);
    
    int res = CIPURSESelect(true, true, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != 0x9000) {
        PrintAndLogEx(ERR, "Cipurse select " _RED_("error") ". Card returns 0x%04x.", sw);
        DropField();
        return PM3_ESOFT;
    }
        
    if (verbose)
        PrintAndLogEx(INFO, "File id: %x offset %d key id: %d key: %s", fileId, offset, keyId, sprint_hex(key, CIPURSE_AES_KEY_LENGTH));

    bool bres = CIPURSEChannelAuthenticate(keyId, key, verbose);
    if (bres == false) {
        if (verbose == false)
            PrintAndLogEx(ERR, "Authentication " _RED_("ERROR"));
        DropField();
        return PM3_ESOFT;
    }
    
    res = CIPURSESelectFile(fileId, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != 0x9000) {
        if (verbose == false)
            PrintAndLogEx(ERR, "File select " _RED_("ERROR") ". Card returns 0x%04x.", sw);
        DropField();
        return PM3_ESOFT;
    }

    if (verbose)
        PrintAndLogEx(INFO, "Select file 0x%x " _GREEN_("OK"), fileId);
    
    res = CIPURSEReadBinary(offset, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != 0x9000) {
        if (verbose == false)
            PrintAndLogEx(ERR, "File read " _RED_("ERROR") ". Card returns 0x%04x.", sw);
        DropField();
        return PM3_ESOFT;
    }
        
    if (len == 0)
        PrintAndLogEx(INFO, "File id: %x is empty", fileId);
    else
        PrintAndLogEx(INFO, "File id: %x data[%d]: %s", fileId, len, sprint_hex(buf, len));
    
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
    {"read",      CmdHFCipurseReadFile,      IfPm3Iso14443a,  "Read file."},
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
