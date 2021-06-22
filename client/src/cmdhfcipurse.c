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
            PrintAndLogEx(INFO, "Not a CIPURSE card. APDU response: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        else
            PrintAndLogEx(ERR, "APDU exchange error. Card returns 0x0000");

        DropField();
        return PM3_SUCCESS;
    }

    PrintAndLogEx(INFO, "Cipurse card ( " _GREEN_("ok") " )");

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
        PrintAndLogEx(INFO, "Info file ( " _GREEN_("ok") " )");
        PrintAndLogEx(INFO, "[%zu]: %s", len, sprint_hex(buf, len));
        CIPURSEPrintInfoFile(buf, len);
    }

    DropField();
    return PM3_SUCCESS;
}

static int CmdHFCipurseAuth(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cipurse auth",
                  "Authenticate with key ID and key. If no key is supplied, default key of 737373...7373 will be used",
                  "hf cipurse auth      -> Authenticate with keyID 1, default key\n"
                  "hf cipurse auth -n 2 -k 65656565656565656565656565656565 -> Authenticate keyID 2 with key\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  NULL,      "<dec>", "key ID"),
        arg_str0("k",  "key",     "<hex>", "Auth key"),
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
        PrintAndLogEx(ERR, _RED_("ERROR:") " key length for AES128 must be 16 bytes only");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t key[] = {0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73};
    if (hdatalen)
        memcpy(key, hdata, CIPURSE_AES_KEY_LENGTH);

    SetAPDULogging(APDULogging);

    CLIParserFree(ctx);

    size_t len = 0;
    uint16_t sw = 0;
    uint8_t buf[APDU_RES_LEN] = {0};

    int res = CIPURSESelect(true, true, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != 0x9000) {
        PrintAndLogEx(ERR, "Cipurse select " _RED_("error") ". Card returns 0x%04x", sw);
        DropField();
        return PM3_ESOFT;
    }

    uint8_t kvv[CIPURSE_KVV_LENGTH] = {0};
    CipurseCGetKVV(key, kvv);
    if (verbose) {
        PrintAndLogEx(INFO, "Key id" _YELLOW_("%d") " key " _YELLOW_("%s") " KVV " _YELLOW_("%s")
                      , keyId
                      , sprint_hex(key, CIPURSE_AES_KEY_LENGTH)
                      , sprint_hex_inrow(kvv, CIPURSE_KVV_LENGTH)
                     );
    }

    bool bres = CIPURSEChannelAuthenticate(keyId, key, verbose);

    if (verbose == false) {
        if (bres)
            PrintAndLogEx(INFO, "Authentication ( " _GREEN_("ok") " )");
        else
            PrintAndLogEx(ERR, "Authentication ( " _RED_("fail") " )");
    }

    DropField();
    return (bres) ? PM3_SUCCESS : PM3_ESOFT;
}

static int CLIParseKeyAndSecurityLevels(CLIParserContext *ctx, size_t keyid, size_t sreqid, size_t srespid, uint8_t *key, CipurseChannelSecurityLevel *sreq, CipurseChannelSecurityLevel *sresp) {
    uint8_t hdata[250] = {0};
    int hdatalen = sizeof(hdata);
    CLIGetHexWithReturn(ctx, keyid, hdata, &hdatalen);
    if (hdatalen && hdatalen != 16) {
        PrintAndLogEx(ERR, _RED_("ERROR:") " key length for AES128 must be 16 bytes only");
        return PM3_EINVARG;
    }
    if (hdatalen)
        memcpy(key, hdata, CIPURSE_AES_KEY_LENGTH);

    *sreq = CPSMACed;
    *sresp = CPSMACed;

    char cdata[250] = {0};
    int cdatalen = sizeof(cdata);
    cdatalen--; // for trailer 0x00
    CLIGetStrWithReturn(ctx, sreqid, (uint8_t *)cdata, &cdatalen);
    if (cdatalen) {
        str_lower(cdata);
        if (strcmp(cdata, "plain") == 0)
            *sreq = CPSPlain;
        else if (strcmp(cdata, "mac") == 0)
            *sreq = CPSMACed;
        else if (strcmp(cdata, "enc") == 0 || strcmp(cdata, "encode") == 0 || strcmp(cdata, "encrypted") == 0)
            *sreq = CPSEncrypted;
        else {
            PrintAndLogEx(ERR, _RED_("ERROR:") " security level can be only: plain | mac | encode");
            return PM3_EINVARG;
        }
    }

    cdatalen = sizeof(cdata);
    memset(cdata, 0, cdatalen);
    cdatalen--; // for trailer 0x00
    CLIGetStrWithReturn(ctx, srespid, (uint8_t *)cdata, &cdatalen);
    if (cdatalen) {
        str_lower(cdata);
        if (strcmp(cdata, "plain") == 0)
            *sresp = CPSPlain;
        else if (strcmp(cdata, "mac") == 0)
            *sresp = CPSMACed;
        else if (strcmp(cdata, "enc") == 0 || strcmp(cdata, "encode") == 0 || strcmp(cdata, "encrypted") == 0)
            *sresp = CPSEncrypted;
        else {
            PrintAndLogEx(ERR, _RED_("ERROR:") " security level can be only: plain | mac | encode");
            return PM3_EINVARG;
        }
    }

    return PM3_SUCCESS;
}

static int CmdHFCipurseReadFile(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cipurse read",
                  "Read file by file ID with key ID and key. If no key is supplied, default key of 737373...7373 will be used",
                  "hf cipurse read -f 2ff7   -> Authenticate with keyID 1, read file with id 2ff7\n"
                  "hf cipurse read -n 2 -k 65656565656565656565656565656565 --fid 2ff7 -> Authenticate keyID 2 and read file\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  NULL,      "<dec>", "key ID"),
        arg_str0("k",  "key",     "<hex>", "Auth key"),
        arg_str0(NULL,  "fid",    "<hex>", "file ID"),
        arg_int0("o",  "offset",  "<dec>", "offset for reading data from file"),
        arg_lit0(NULL, "noauth",  "read file without authentication"),
        arg_str0(NULL, "sreq",    "<plain|mac(default)|encode>", "communication reader-PICC security level"),
        arg_str0(NULL, "sresp",   "<plain|mac(default)|encode>", "communication PICC-reader security level"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);


    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    uint8_t keyId = arg_get_int_def(ctx, 3, 1);

    CipurseChannelSecurityLevel sreq = CPSMACed;
    CipurseChannelSecurityLevel sresp = CPSMACed;
    uint8_t key[] = CIPURSE_DEFAULT_KEY;
    int res = CLIParseKeyAndSecurityLevels(ctx, 4, 8, 9, key, &sreq, &sresp);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t hdata[250] = {0};
    int hdatalen = sizeof(hdata);
    CLIGetHexWithReturn(ctx, 5, hdata, &hdatalen);
    if (hdatalen && hdatalen != 2) {
        PrintAndLogEx(ERR, _RED_("ERROR:") " file id length must be 2 bytes only");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint16_t fileId = 0x2ff7;
    if (hdatalen)
        fileId = (hdata[0] << 8) + hdata[1];

    size_t offset = arg_get_int_def(ctx, 6, 0);

    bool noAuth = arg_get_lit(ctx, 7);

    SetAPDULogging(APDULogging);

    CLIParserFree(ctx);

    size_t len = 0;
    uint16_t sw = 0;
    uint8_t buf[APDU_RES_LEN] = {0};

    res = CIPURSESelect(true, true, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != 0x9000) {
        PrintAndLogEx(ERR, "Cipurse select " _RED_("error") ". Card returns 0x%04x", sw);
        DropField();
        return PM3_ESOFT;
    }

    if (verbose)
        PrintAndLogEx(INFO, "File id " _YELLOW_("%x") " offset " _YELLOW_("%zu") " key id " _YELLOW_("%d") " key " _YELLOW_("%s"), fileId, offset, keyId, sprint_hex(key, CIPURSE_AES_KEY_LENGTH));

    if (noAuth == false) {
        bool bres = CIPURSEChannelAuthenticate(keyId, key, verbose);
        if (bres == false) {
            if (verbose == false)
                PrintAndLogEx(ERR, "Authentication ( " _RED_("fail") " )");
            DropField();
            return PM3_ESOFT;
        }

        // set channel security levels
        CIPURSECSetActChannelSecurityLevels(sreq, sresp);
    }

    res = CIPURSESelectFile(fileId, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != 0x9000) {
        if (verbose == false)
            PrintAndLogEx(ERR, "File select " _RED_("ERROR") ". Card returns 0x%04x", sw);
        DropField();
        return PM3_ESOFT;
    }

    if (verbose)
        PrintAndLogEx(INFO, "Select file 0x%x ( " _GREEN_("ok") " )", fileId);

    res = CIPURSEReadBinary(offset, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != 0x9000) {
        if (verbose == false)
            PrintAndLogEx(ERR, "File read " _RED_("ERROR") ". Card returns 0x%04x", sw);
        DropField();
        return PM3_ESOFT;
    }

    if (len == 0)
        PrintAndLogEx(INFO, "File id " _YELLOW_("%x") " is empty", fileId);
    else
        PrintAndLogEx(INFO, "File id " _YELLOW_("%x") " data[%zu]: %s", fileId, len, sprint_hex(buf, len));

    DropField();
    return PM3_SUCCESS;
}

static int CmdHFCipurseWriteFile(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cipurse write",
                  "Write file by file ID with key ID and key. If no key is supplied, default key of 737373...7373 will be used",
                  "hf cipurse write -f 2ff7   -> Authenticate with keyID 1, write file with id 2ff7\n"
                  "hf cipurse write -n 2 -k 65656565656565656565656565656565 --fid 2ff7 -> Authenticate keyID 2 and write file\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  NULL,      "<dec>", "key ID"),
        arg_str0("k",  "key",     "<hex>", "Auth key"),
        arg_str0(NULL,  "fid",    "<hex>", "file ID"),
        arg_int0("o",  "offset",  "<dec>", "offset for reading data from file"),
        arg_lit0(NULL, "noauth",  "read file without authentication"),
        arg_str0(NULL, "sreq",    "<plain|mac(default)|encode>", "communication reader-PICC security level"),
        arg_str0(NULL, "sresp",   "<plain|mac(default)|encode>", "communication PICC-reader security level"),
        arg_str0("d",  "data",    "<hex>", "hex data to write to new file"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    uint8_t keyId = arg_get_int_def(ctx, 3, 1);

    CipurseChannelSecurityLevel sreq = CPSMACed;
    CipurseChannelSecurityLevel sresp = CPSMACed;

    uint8_t key[] = CIPURSE_DEFAULT_KEY;
    int res = CLIParseKeyAndSecurityLevels(ctx, 4, 8, 9, key, &sreq, &sresp);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint16_t fileId = 0x2ff7;

    uint8_t hdata[250] = {0};
    int hdatalen = sizeof(hdata);
    CLIGetHexWithReturn(ctx, 5, hdata, &hdatalen);
    if (hdatalen && hdatalen != 2) {
        PrintAndLogEx(ERR, _RED_("ERROR:") " file id length must be 2 bytes only");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    if (hdatalen)
        fileId = (hdata[0] << 8) + hdata[1];

    size_t offset = arg_get_int_def(ctx, 6, 0);

    bool noAuth = arg_get_lit(ctx, 7);

    hdatalen = sizeof(hdata);
    CLIGetHexWithReturn(ctx, 10, hdata, &hdatalen);
    if (hdatalen == 0) {
        PrintAndLogEx(ERR, _RED_("ERROR:") " file content length must be more 0");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);

    CLIParserFree(ctx);

    size_t len = 0;
    uint16_t sw = 0;
    uint8_t buf[APDU_RES_LEN] = {0};

    res = CIPURSESelect(true, true, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != 0x9000) {
        PrintAndLogEx(ERR, "Cipurse select " _RED_("error") ". Card returns 0x%04x", sw);
        DropField();
        return PM3_ESOFT;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "File id " _YELLOW_("%x") " offset " _YELLOW_("%zu") " key id " _YELLOW_("%d") " key " _YELLOW_("%s")
                      , fileId
                      , offset
                      , keyId
                      , sprint_hex(key, CIPURSE_AES_KEY_LENGTH)
                     );
        PrintAndLogEx(INFO, "data[%d]: %s", hdatalen, sprint_hex(hdata, hdatalen));
    }

    if (noAuth == false) {
        bool bres = CIPURSEChannelAuthenticate(keyId, key, verbose);
        if (bres == false) {
            if (verbose == false)
                PrintAndLogEx(ERR, "Authentication ( " _RED_("fail") " )");
            DropField();
            return PM3_ESOFT;
        }

        // set channel security levels
        CIPURSECSetActChannelSecurityLevels(sreq, sresp);
    }

    res = CIPURSESelectFile(fileId, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != 0x9000) {
        if (verbose == false)
            PrintAndLogEx(ERR, "File select " _RED_("ERROR") ". Card returns 0x%04x", sw);
        DropField();
        return PM3_ESOFT;
    }

    if (verbose)
        PrintAndLogEx(INFO, "Select file 0x%x ( " _GREEN_("ok") " )", fileId);

    res = CIPURSEUpdateBinary(offset, hdata, hdatalen, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != 0x9000) {
        if (verbose == false)
            PrintAndLogEx(ERR, "File write " _RED_("ERROR") ". Card returns 0x%04x", sw);
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "File id " _YELLOW_("%x") " successfully written", fileId);

    DropField();
    return PM3_SUCCESS;
}

static int CmdHFCipurseReadFileAttr(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cipurse aread",
                  "Read file attributes by file ID with key ID and key. If no key is supplied, default key of 737373...7373 will be used",
                  "hf cipurse aread -f 2ff7   -> Authenticate with keyID 1, read file attributes with id 2ff7\n"
                  "hf cipurse aread -n 2 -k 65656565656565656565656565656565 --fid 2ff7 -> Authenticate keyID 2, read file attributes\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  NULL,      "<dec>", "key ID"),
        arg_str0("k",  "key",     "<hex>", "Auth key"),
        arg_str0(NULL, "fid",     "<hex>", "file ID"),
        arg_lit0(NULL, "noauth",  "read file attributes without authentication"),
        arg_str0(NULL, "sreq",    "<plain|mac(default)|encode>", "communication reader-PICC security level"),
        arg_str0(NULL, "sresp",   "<plain|mac(default)|encode>", "communication PICC-reader security level"),
        arg_lit0(NULL, "sel-adf", "show info about ADF itself"),
        arg_lit0(NULL, "sel-mf",  "show info about master file"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    uint8_t keyId = arg_get_int_def(ctx, 3, 1);

    CipurseChannelSecurityLevel sreq = CPSMACed;
    CipurseChannelSecurityLevel sresp = CPSMACed;
    uint8_t key[] = CIPURSE_DEFAULT_KEY;
    int res = CLIParseKeyAndSecurityLevels(ctx, 4, 7, 8, key, &sreq, &sresp);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t hdata[250] = {0};
    int hdatalen = sizeof(hdata);
    CLIGetHexWithReturn(ctx, 5, hdata, &hdatalen);
    if (hdatalen && hdatalen != 2) {
        PrintAndLogEx(ERR, _RED_("ERROR:") " file id length must be 2 bytes only");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint16_t fileId = 0x2ff7;
    if (hdatalen)
        fileId = (hdata[0] << 8) + hdata[1];

    bool noAuth = arg_get_lit(ctx, 6);
    bool seladf = arg_get_lit(ctx, 9);
    bool selmf = arg_get_lit(ctx, 10);

    SetAPDULogging(APDULogging);

    CLIParserFree(ctx);

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    res = CIPURSESelect(true, true, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != 0x9000) {
        PrintAndLogEx(ERR, "Cipurse select " _RED_("error") ". Card returns 0x%04x", sw);
        DropField();
        return PM3_ESOFT;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "File id " _YELLOW_("%x") " key id " _YELLOW_("%d") " key " _YELLOW_("%s")
                      , fileId
                      , keyId
                      , sprint_hex(key, CIPURSE_AES_KEY_LENGTH)
                     );
    }

    if (noAuth == false) {
        bool bres = CIPURSEChannelAuthenticate(keyId, key, verbose);
        if (bres == false) {
            if (verbose == false)
                PrintAndLogEx(ERR, "Authentication ( " _RED_("fail") " )");
            DropField();
            return PM3_ESOFT;
        }

        // set channel security levels
        CIPURSECSetActChannelSecurityLevels(sreq, sresp);
    }

    if (seladf == false) {
        if (selmf)
            res = CIPURSESelectMFFile(buf, sizeof(buf), &len, &sw);
        else
            res = CIPURSESelectFile(fileId, buf, sizeof(buf), &len, &sw);

        if (res != 0 || sw != 0x9000) {
            if (verbose == false)
                PrintAndLogEx(ERR, "File select " _RED_("ERROR") ". Card returns 0x%04x", sw);
            DropField();
            return PM3_ESOFT;
        }
    }

    if (verbose)
        PrintAndLogEx(INFO, "Select file 0x%x ( " _GREEN_("ok") " )", fileId);

    res = CIPURSEReadFileAttributes(buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != 0x9000) {
        if (verbose == false)
            PrintAndLogEx(ERR, "File read " _RED_("ERROR") ". Card returns 0x%04x", sw);
        DropField();
        return PM3_ESOFT;
    }

    if (len == 0) {
        PrintAndLogEx(WARNING, "File id " _YELLOW_("%x") " attributes is empty", fileId);
        DropField();
        return PM3_SUCCESS;
    }

    if (verbose)
        PrintAndLogEx(INFO, "File id " _YELLOW_("%x") " attributes[%zu]: %s", fileId, len, sprint_hex(buf, len));

    CIPURSEPrintFileAttr(buf, len);

    DropField();
    return PM3_SUCCESS;
}

static int CmdHFCipurseDeleteFile(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cipurse delete",
                  "Read file by file ID with key ID and key. If no key is supplied, default key of 737373...7373 will be used",
                  "hf cipurse delete -f 2ff7   -> Authenticate with keyID 1, delete file with id 2ff7\n"
                  "hf cipurse delete -n 2 -k 65656565656565656565656565656565 --fid 2ff7 -> Authenticate keyID 2 and delete file\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "show APDU requests and responses"),
        arg_lit0("v",  "verbose", "show technical data"),
        arg_int0("n",  NULL,      "<dec>", "key ID"),
        arg_str0("k",  "key",     "<hex>", "Auth key"),
        arg_str0(NULL, "fid",     "<hex>", "file ID"),
        arg_str0(NULL, "sreq",    "<plain|mac(default)|encode>", "communication reader-PICC security level"),
        arg_str0(NULL, "sresp",   "<plain|mac(default)|encode>", "communication PICC-reader security level"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    uint8_t keyId = arg_get_int_def(ctx, 3, 1);

    CipurseChannelSecurityLevel sreq = CPSMACed;
    CipurseChannelSecurityLevel sresp = CPSMACed;
    uint8_t key[] = CIPURSE_DEFAULT_KEY;
    int res = CLIParseKeyAndSecurityLevels(ctx, 4, 6, 7, key, &sreq, &sresp);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t hdata[250] = {0};
    int hdatalen = sizeof(hdata);
    CLIGetHexWithReturn(ctx, 5, hdata, &hdatalen);
    if (hdatalen && hdatalen != 2) {
        PrintAndLogEx(ERR, _RED_("ERROR:") " file id length must be 2 bytes only");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint16_t fileId = 0x2ff7;
    if (hdatalen)
        fileId = (hdata[0] << 8) + hdata[1];

    SetAPDULogging(APDULogging);

    CLIParserFree(ctx);

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    res = CIPURSESelect(true, true, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != 0x9000) {
        PrintAndLogEx(ERR, "Cipurse select " _RED_("error") ". Card returns 0x%04x", sw);
        DropField();
        return PM3_ESOFT;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "File id " _YELLOW_("%x") " key id " _YELLOW_("%d") " key " _YELLOW_("%s")
                      , fileId
                      , keyId
                      , sprint_hex(key, CIPURSE_AES_KEY_LENGTH)
                     );
    }

    bool bres = CIPURSEChannelAuthenticate(keyId, key, verbose);
    if (bres == false) {
        if (verbose == false)
            PrintAndLogEx(ERR, "Authentication ( " _RED_("fail") " )");
        DropField();
        return PM3_ESOFT;
    }

    // set channel security levels
    CIPURSECSetActChannelSecurityLevels(sreq, sresp);

    res = CIPURSEDeleteFile(fileId, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != 0x9000) {
        if (verbose == false)
            PrintAndLogEx(ERR, "File select " _RED_("ERROR") ". Card returns 0x%04x", sw);
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "File id " _YELLOW_("%04x") " deleted " _GREEN_("succesfully"), fileId);

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
    {"info",      CmdHFCipurseInfo,          IfPm3Iso14443a,  "Get info about CIPURSE tag"},
    {"auth",      CmdHFCipurseAuth,          IfPm3Iso14443a,  "Authenticate CIPURSE tag"},
    {"read",      CmdHFCipurseReadFile,      IfPm3Iso14443a,  "Read binary file"},
    {"write",     CmdHFCipurseWriteFile,     IfPm3Iso14443a,  "Write binary file"},
    {"aread",     CmdHFCipurseReadFileAttr,  IfPm3Iso14443a,  "Read file attributes"},
    {"delete",    CmdHFCipurseDeleteFile,    IfPm3Iso14443a,  "Delete file"},
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
