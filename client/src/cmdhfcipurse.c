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
#include "cipurse/cipursetest.h"
#include "ui.h"
#include "cmdhf14a.h"
#include "cmdtrace.h"
#include "util.h"
#include "fileutils.h"   // laodFileJSONroot
#include "crypto/libpcrypto.h"
#include "protocols.h"   // ISO7816 APDU return codes

const uint8_t PxSE_AID[] = {0xA0, 0x00, 0x00, 0x05, 0x07, 0x01, 0x00};
#define PxSE_AID_LENGTH 7
typedef struct {
    uint8_t aid[PxSE_AID_LENGTH];
    const char *name;
} PxSE_AID_t;

static const PxSE_AID_t PxSE_AID_LIST[] = {
    {{0xA0, 0x00, 0x00, 0x05, 0x07, 0x01, 0x00}, "Proximity Transport System Environment (PTSE)" },
    {{0xA0, 0x00, 0x00, 0x05, 0x07, 0x02, 0x00}, "Proximity Facility Access System Environment (PASE)" },
    {{0xA0, 0x00, 0x00, 0x05, 0x07, 0x03, 0x00}, "Proximity Digital Identity System Environment (PDSE)" },
    {{0xA0, 0x00, 0x00, 0x05, 0x07, 0x04, 0x00}, "Proximity Event Ticketing System Environment (PESE)" },
    {{0xA0, 0x00, 0x00, 0x05, 0x07, 0x05, 0x00}, "Proximity Couponing System Environment (PCSE)" },
    {{0xA0, 0x00, 0x00, 0x05, 0x07, 0x06, 0x00}, "Proximity Micro-Payment System Environment (PMSE)" }
};

static const APDUSpcCodeDescription_t SelectAPDUCodeDescriptions[] = {
    {0x6984, "Key is blocked for use as key encryption key" },
    {0x6985, "Command not allowed on deactivated ADF or maximum files count already reached" },
    {0x6A80, "Incorrect creation parameters in the command data field for the EF/ADF creation" },
    {0x6A81, "Command for creation of ADF is not permitted on ADF level" },
    {0x6A84, "Not enough memory space" },
    {0x6A88, "Invalid key number (outside the range supported by the currend DF)" },
    {0x6A89, "FileID / SFID already exists" },
    {0x6A89, "AID already exists" }
};

static const APDUSpcCodeDescription_t DeleteAPDUCodeDescriptions[] = {
    {0x6985, "Referenced PxSE application cannot be deleted due to reference to CIPURSE application" },
    {0x6986, "Deletion of MF or predefined EFs is not allowed" },
    {0x6A82, "File not found" }
};

static const APDUSpcCodeDescription_t UAPDpdateKeyAttrCodeDescriptions[] = {
    {0x6581, "Transaction mechanism capabilities exceeded" },
    {0x6982, "Key is frozen or only the key itself has the rights to update" },
    {0x6985, "Deactivated file" },
    {0x6A88, "Invalid key number (outside the range supported by the current DF)" }
};

static const APDUSpcCodeDescription_t UAPDpdateKeyCodeDescriptions[] = {
    {0x6982, "Key is frozen or only the key itself has the rights to update" },
    {0x6984, "Enc key is blocked or invalid" },
    {0x6985, "Deactivated file" },
    {0x6A80, "Invalid algo, key length or kvv" },
    {0x6A88, "Invalid key number (outside the range supported by the current DF)" }
};

static uint8_t defaultKeyId = 1;
static uint8_t defaultKey[CIPURSE_AES_KEY_LENGTH] = CIPURSE_DEFAULT_KEY;
#define CIPURSE_MAX_AID_LENGTH 16
static uint8_t defaultAID[CIPURSE_MAX_AID_LENGTH] = CIPURSE_DEFAULT_AID;
static size_t defaultAIDLength = 5;
static uint16_t defaultFileId = 0x2ff7;

static int CmdHelp(const char *Cmd);

static int SelectAndPrintInfoFile(void) {
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    int res = CIPURSESelectFile(0x2ff7, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != ISO7816_OK)
        return PM3_EAPDU_FAIL;

    res = CIPURSEReadBinary(0, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != ISO7816_OK)
        return PM3_EAPDU_FAIL;

    if (len > 0) {
        PrintAndLogEx(INFO, "Info file ( " _GREEN_("ok") " )");

        PrintAndLogEx(INFO, " # | bytes                                           | ascii");
        PrintAndLogEx(INFO, "---+-------------------------------------------------+-----------------");
        print_hex_break(buf, len, 16);
        PrintAndLogEx(NORMAL, "");
        CIPURSEPrintInfoFile(buf, len);
        PrintAndLogEx(INFO, "");
    }
    return PM3_SUCCESS;
}

static int CmdHFCipurseInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cipurse info",
                  "Get info from CIPURSE tags",
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
    PrintAndLogEx(INFO, "------------------- " _CYAN_("CIPURSE Info") " --------------------");
    SetAPDULogging(false);

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    bool mfExist = false;
    bool infoPrinted = false;
    int res = CIPURSESelectMFEx(true, true, buf, sizeof(buf), &len, &sw);
    if (res == PM3_SUCCESS && sw == ISO7816_OK) {
        mfExist = true;
        PrintAndLogEx(INFO, _YELLOW_("MasterFile") " exist and can be selected.");

        res = SelectAndPrintInfoFile();
        infoPrinted = (res == PM3_SUCCESS);
    }

    for (int i = 0; i < ARRAYLEN(PxSE_AID_LIST); i++) {
        res = CIPURSESelectAID(false, true, (uint8_t *)PxSE_AID_LIST[i].aid, PxSE_AID_LENGTH, buf, sizeof(buf), &len, &sw);
        if (res == PM3_SUCCESS && sw == ISO7816_OK) {
            mfExist = true;
            PrintAndLogEx(INFO, _CYAN_("PxSE") " exist: %s", PxSE_AID_LIST[i].name);
            if (len > 0) {
                PrintAndLogEx(INFO, "PxSE data:");
                TLVPrintFromBuffer(buf, len);
            }
            PrintAndLogEx(INFO, "");
        }
    }

    res = CIPURSESelect(false, true, buf, sizeof(buf), &len, &sw);
    if (res) {
        DropField();
        return res;
    }
    PrintAndLogEx(INFO, "Application `" _YELLOW_("AF F1") "` selected " _GREEN_("successfully"));

    if (sw != ISO7816_OK) {
        if (sw == 0x0000) {
            PrintAndLogEx(ERR, "APDU exchange error. Card returns 0x0000");
        } else {
            if (!mfExist)
                PrintAndLogEx(INFO, "Not a CIPURSE card. APDU response: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
            else
                PrintAndLogEx(INFO, "Unknown AID and MasterFile can be selected. Maybe CIPURSE card in the " _CYAN_("perso") " state");
        }

        DropField();
        return PM3_SUCCESS;
    }

    PrintAndLogEx(INFO, "Cipurse card ( " _GREEN_("ok") " )");

    if (!infoPrinted) {
        res = SelectAndPrintInfoFile();
        if (res != PM3_SUCCESS) {
            DropField();
            return PM3_SUCCESS;
        }
    }

    DropField();
    return PM3_SUCCESS;
}

static int CLIParseCommandParametersEx(CLIParserContext *ctx, size_t keyid, size_t aidid, size_t fidid, size_t chfidid, size_t sreqid, size_t srespid,
                                       uint8_t *key, uint8_t *aid, size_t *aidlen, bool *useaid, uint16_t *fid, bool *usefid, uint16_t *chfid, bool *usechfid,
                                       CipurseChannelSecurityLevel *sreq, CipurseChannelSecurityLevel *sresp) {
    uint8_t hdata[250] = {0};
    int hdatalen = sizeof(hdata);
    if (keyid) {
        if (CLIParamHexToBuf(arg_get_str(ctx, keyid), hdata, hdatalen, &hdatalen)) {
            return PM3_ESOFT;
        }

        if (hdatalen && hdatalen != 16) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " key length for AES128 must be 16 bytes only");
            return PM3_EINVARG;
        }

        if (hdatalen)
            memcpy(key, hdata, CIPURSE_AES_KEY_LENGTH);
        else
            memcpy(key, defaultKey, sizeof(defaultKey));
    }

    if (useaid) {
        *useaid = false;
    }

    if (aidid && aid && aidlen) {
        hdatalen = sizeof(hdata);
        if (CLIParamHexToBuf(arg_get_str(ctx, aidid), hdata, hdatalen, &hdatalen)) {
            return PM3_ESOFT;
        }

        if (hdatalen && (hdatalen < 1 || hdatalen > 16)) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " application id length must be 1-16 bytes only");
            return PM3_EINVARG;
        }

        *aidlen = 0;
        if (hdatalen) {
            memcpy(aid, hdata, hdatalen);
            *aidlen = hdatalen;
            if (useaid) {
                *useaid = true;
            }
        } else {
            memcpy(aid, defaultAID, defaultAIDLength);
            *aidlen = defaultAIDLength;
        }
    }

    if (usefid) {
        *usefid = false;
    }

    if (fidid && fid) {
        hdatalen = sizeof(hdata);
        if (CLIParamHexToBuf(arg_get_str(ctx, fidid), hdata, hdatalen, &hdatalen))
            return PM3_ESOFT;

        if (hdatalen && hdatalen != 2) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " file id length must be 2 bytes only");
            return PM3_EINVARG;
        }

        *fid = 0;
        if (hdatalen) {
            *fid = (hdata[0] << 8) + hdata[1];
            if (usefid)
                *usefid = true;
        }
    }

    if (usechfid)
        *usechfid = false;
    if (chfidid && chfid) {
        hdatalen = sizeof(hdata);
        if (CLIParamHexToBuf(arg_get_str(ctx, chfidid), hdata, hdatalen, &hdatalen))
            return PM3_ESOFT;
        if (hdatalen && hdatalen != 2) {
            PrintAndLogEx(ERR, _RED_("ERROR:") " child file id length must be 2 bytes only");
            return PM3_EINVARG;
        }

        *chfid = defaultFileId;
        if (hdatalen) {
            *chfid = (hdata[0] << 8) + hdata[1];
            if (usechfid)
                *usechfid = true;
        }
    }

    if (sreqid && srespid && sreq && sresp) {
        *sreq = CPSMACed;
        *sresp = CPSMACed;

        char cdata[250] = {0};
        int cdatalen = sizeof(cdata);
        cdatalen--; // for trailer 0x00
        if (CLIParamStrToBuf(arg_get_str(ctx, sreqid), (uint8_t *)cdata, cdatalen, &cdatalen))
            return PM3_ESOFT;

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
        if (CLIParamStrToBuf(arg_get_str(ctx, srespid), (uint8_t *)cdata, cdatalen, &cdatalen))
            return PM3_ESOFT;

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
    }

    return PM3_SUCCESS;
}

static int CLIParseCommandParameters(CLIParserContext *ctx, size_t keyid, size_t aidid, size_t fidid,  size_t sreqid, size_t srespid,
                                     uint8_t *key, uint8_t *aid, size_t *aidlen, bool *useaid, uint16_t *fid, bool *usefid,
                                     CipurseChannelSecurityLevel *sreq, CipurseChannelSecurityLevel *sresp) {
    return CLIParseCommandParametersEx(ctx, keyid, aidid, fidid, 0, sreqid, srespid,
                                       key, aid, aidlen, useaid, fid, usefid, NULL, NULL, sreq, sresp);
}

static int SelectCommandEx(bool selectDefaultFile, bool useAID, uint8_t *aid, size_t aidLen, bool useFID, uint16_t fileId,
                           bool selChildFile, uint16_t childFileId, bool verbose,
                           uint8_t *buf, size_t bufSize, size_t *len, uint16_t *sw) {
    int res = 0;
    if (verbose && selChildFile)
        PrintAndLogEx(INFO, "Select top level application/file");

    if (useAID && aidLen > 0) {

        res = CIPURSESelectAID(true, true, aid, aidLen, buf, bufSize, len, sw);
        if (res != 0 || *sw != ISO7816_OK) {
            if (verbose) {
                PrintAndLogEx(ERR, "Cipurse select application " _GREEN_("%s ") _RED_("error") ". Card returns 0x%04x", sprint_hex_inrow(aid, aidLen), *sw);
            }
            return PM3_ESOFT;
        }
        if (verbose) {
            PrintAndLogEx(INFO, "Cipurse select application " _YELLOW_("%s ") " ( %s )", sprint_hex_inrow(aid, aidLen), _GREEN_("ok"));
        }

    } else if (useFID) {

        res = CIPURSESelectFileEx(true, true, fileId, buf, bufSize, len, sw);
        if (res != 0 || *sw != ISO7816_OK) {
            if (verbose) {
                PrintAndLogEx(ERR, "Cipurse select file 0x%04x  ( %s )", fileId, _RED_("fail"));
                PrintAndLogEx(ERR, "Card returns 0x%04x", *sw);
            }
            return PM3_ESOFT;
        }
        if (verbose) {
            PrintAndLogEx(INFO, "Cipurse select file " _YELLOW_("0x%04X ") " ( " _GREEN_("ok") " )", fileId);
        }

    } else if (selectDefaultFile) {

        res = CIPURSESelectMFDefaultFileEx(true, true, buf, bufSize, len, sw);
        if (res != 0 || *sw != ISO7816_OK) {
            if (verbose) {
                PrintAndLogEx(ERR, "Cipurse select default file " _RED_("error") ". Card returns 0x%04x", *sw);
            }
            return PM3_ESOFT;
        }
        if (verbose) {
            PrintAndLogEx(INFO, "Cipurse select default file  ( " _GREEN_("ok") " )");
        }

    } else {

        res = CIPURSESelect(true, true, buf, bufSize, len, sw);
        if (res != 0 || *sw != ISO7816_OK) {
            if (verbose) {
                PrintAndLogEx(ERR, "Cipurse select default application " _RED_("error") ". Card returns 0x%04x", *sw);
            }
            return PM3_ESOFT;
        }
        if (verbose) {
            PrintAndLogEx(INFO, "Cipurse select default application ( " _GREEN_("ok") " )");
        }
    }

    if (selChildFile) {
        if (verbose) {
            PrintAndLogEx(INFO, "Select child file");
        }

        res = CIPURSESelectFileEx(false, true, childFileId, buf, bufSize, len, sw);
        if (res != 0 || *sw != ISO7816_OK) {
            if (verbose) {
                PrintAndLogEx(ERR, "Select child file 0x%04x " _RED_("error") ". Card returns 0x%04x", childFileId, *sw);
            }
            return PM3_ESOFT;
        }
        if (verbose) {
            PrintAndLogEx(INFO, "Select child file " _CYAN_("0x%04x ") " ( " _GREEN_("ok") " )", childFileId);
        }
    }

    return PM3_SUCCESS;
}

static int SelectCommand(bool selectDefaultFile, bool useAID, uint8_t *aid, size_t aidLen, bool useFID, uint16_t fileId, bool verbose,
                         uint8_t *buf, size_t bufSize, size_t *len, uint16_t *sw) {
    return SelectCommandEx(selectDefaultFile, useAID, aid, aidLen, useFID, fileId, false, 0, verbose, buf, bufSize, len, sw);
}

static int CmdHFCipurseSelect(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cipurse select",
                  "Select application or file",
                  "hf cipurse select --aid A0000005070100  -> Select PTSE application by AID\n"
                  "hf cipurse select --fid 3f00            -> Select master file by FID 3f00\n"
                  "hf cipurse select --fid 2ff7            -> Select attribute file by FID 2ff7\n"
                  "hf cipurse select --mfd -vt             -> Select default file by empty FID and show response data in plain and TLV decoded format\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose mode"),
        arg_lit0("t",  "tlv",     "TLV decode returned data"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (AID) 1..16 bytes"),
        arg_str0(NULL, "fid",     "<hex>", "Top level file (or application) ID (FID) 2 bytes"),
        arg_lit0(NULL, "mfd",     "Select masterfile by empty id"),
        arg_str0(NULL, "chfid",   "<hex>", "Child file ID (EF under application/master file) 2 bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool showTLV = arg_get_lit(ctx, 3);

    uint8_t aid[16] = {0};
    size_t aidLen = 0;
    bool useAID = false;
    uint16_t fileId = 0;
    bool useFID = false;
    uint16_t childFileId = defaultFileId;
    bool useChildFID = false;
    int res = CLIParseCommandParametersEx(ctx, 0, 4, 5, 7, 0, 0, NULL, aid, &aidLen, &useAID, &fileId, &useFID, &childFileId, &useChildFID, NULL, NULL);
    if (res || (useAID && useFID)) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool selmfd = arg_get_lit(ctx, 6);

    CLIParserFree(ctx);

    SetAPDULogging(APDULogging);

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    res = SelectCommandEx(selmfd, useAID, aid, aidLen, useFID, fileId, useChildFID, childFileId, true, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != ISO7816_OK) {
        DropField();
        return PM3_ESOFT;
    }

    if (len > 0) {
        if (verbose) {
            PrintAndLogEx(INFO, "File data:");
            print_buffer(buf, len, 1);
        }

        if (showTLV)
            TLVPrintFromBuffer(buf, len);
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
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose mode"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (AID) ( 1..16 bytes )"),
        arg_str0(NULL, "fid",     "<hex>", "Top file/application ID (FID) ( 2 bytes )"),
        arg_lit0(NULL, "mfd",     "Select masterfile by empty id"),
        arg_int0("n",  NULL,      "<dec>", "Key ID"),
        arg_str0("k",  "key",     "<hex>", "Auth key"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    uint8_t key[CIPURSE_AES_KEY_LENGTH] = {0};
    uint8_t aid[16] = {0};
    size_t aidLen = 0;
    bool useAID = false;
    uint16_t fileId = defaultFileId;
    bool useFID = false;
    int res = CLIParseCommandParameters(ctx, 7, 3, 4, 0, 0, key, aid, &aidLen, &useAID, &fileId, &useFID, NULL, NULL);
    if (res || (useAID && useFID)) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool selmfd = arg_get_lit(ctx, 5);
    uint8_t keyId = arg_get_int_def(ctx, 6, defaultKeyId);

    CLIParserFree(ctx);

    SetAPDULogging(APDULogging);

    size_t len = 0;
    uint16_t sw = 0;
    uint8_t buf[APDU_RES_LEN] = {0};

    res = SelectCommand(selmfd, useAID, aid, aidLen, useFID, fileId, true, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != ISO7816_OK) {
        DropField();
        return PM3_ESOFT;
    }

    uint8_t kvv[CIPURSE_KVV_LENGTH] = {0};
    CipurseCGetKVV(key, kvv);
    if (verbose) {
        PrintAndLogEx(INFO, "Key id " _YELLOW_("%d") " key " _YELLOW_("%s") " KVV " _YELLOW_("%s")
                      , keyId
                      , sprint_hex(key, CIPURSE_AES_KEY_LENGTH)
                      , sprint_hex_inrow(kvv, CIPURSE_KVV_LENGTH)
                     );
    }

    bool bres = CIPURSEChannelAuthenticate(keyId, key, verbose);

    if (verbose == false) {
        PrintAndLogEx(INFO, "Authentication ( %s ) ", (bres) ?  _GREEN_("ok") :  _RED_("fail"));
    }

    DropField();
    return (bres) ? PM3_SUCCESS : PM3_ESOFT;
}

static int CmdHFCipurseReadFile(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cipurse read",
                  "Read file in the application by file ID with key ID and key. If no key is supplied, default key of 737373...7373 will be used",
                  "hf cipurse read --fid 2ff7   -> Authenticate with keyID 1, read file with id 2ff7\n"
                  "hf cipurse read -n 2 -k 65656565656565656565656565656565 --fid 2ff7    -> Authenticate keyID 2 and read file\n"
                  "hf cipurse read --aid 4144204631 --fid 0102    -> read file with id 0102 from application 4144204631\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose mode"),
        arg_int0("n",  NULL,      "<dec>", "Key ID"),
        arg_str0("k",  "key",     "<hex>", "Auth key"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (AID) ( 1..16 bytes )"),
        arg_str0(NULL, "fid",     "<hex>", "File ID"),
        arg_int0("o",  "offset",  "<dec>", "Offset for reading data from file"),
        arg_lit0(NULL, "noauth",  "Read file without authentication"),
        arg_str0(NULL, "sreq",    "<plain|mac|encode>", "Communication reader-PICC security level (def: mac)"),
        arg_str0(NULL, "sresp",   "<plain|mac|encode>", "Communication PICC-reader security level (def: mac)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);


    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    uint8_t keyId = arg_get_int_def(ctx, 3, defaultKeyId);

    CipurseChannelSecurityLevel sreq = CPSMACed;
    CipurseChannelSecurityLevel sresp = CPSMACed;
    uint8_t key[CIPURSE_AES_KEY_LENGTH] = {0};

    uint8_t aid[16] = {0};
    size_t aidLen = 0;
    bool useAID = false;
    uint16_t fileId = defaultFileId;
    bool useFID = false;
    int res = CLIParseCommandParameters(ctx, 4, 5, 6, 9, 10, key, aid, &aidLen, &useAID, &fileId, &useFID, &sreq, &sresp);
    if (res || useFID == false) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    size_t offset = arg_get_int_def(ctx, 7, 0);

    bool noAuth = arg_get_lit(ctx, 8);

    SetAPDULogging(APDULogging);

    CLIParserFree(ctx);

    size_t len = 0;
    uint16_t sw = 0;
    uint8_t buf[APDU_RES_LEN] = {0};

    res = CIPURSESelectAID(true, true, aid, aidLen, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Cipurse select application " _CYAN_("%s") " ( " _RED_("error") " ). Card returns 0x%04x", sprint_hex_inrow(aid, aidLen), sw);
        DropField();
        return PM3_ESOFT;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "Cipurse select application " _CYAN_("%s") " ( %s )", sprint_hex_inrow(aid, aidLen), _GREEN_("ok"));
        PrintAndLogEx(INFO, "File id " _YELLOW_("%x") " offset " _YELLOW_("%zu") " key id " _YELLOW_("%d") " key " _YELLOW_("%s"), fileId, offset, keyId, sprint_hex(key, CIPURSE_AES_KEY_LENGTH));
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
    if (res != 0 || sw != ISO7816_OK) {
        if (verbose == false)
            PrintAndLogEx(ERR, "File select ( " _RED_("error") " ). Card returns 0x%04x", sw);
        DropField();
        return PM3_ESOFT;
    }

    if (verbose)
        PrintAndLogEx(INFO, "Select file 0x%x ( %s )", fileId, _GREEN_("ok"));

    res = CIPURSEReadBinary(offset, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != ISO7816_OK) {
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
                  "Write file in the application by file ID with key ID and key. If no key is supplied, default key of 737373...7373 will be used",
                  "hf cipurse write --fid 2ff7 -d aabb  -> Authenticate with keyID 1, write file with id 2ff7\n"
                  "hf cipurse write -n 2 -k 65656565656565656565656565656565 --fid 2ff7 -d aabb -> Authenticate keyID 2 and write file\n"
                  "hf cipurse write --aid 4144204631 --fid 0102 -d aabb  -> write file with id 0102 in the 4144204631 application\n"
                  "hf cipurse write --fid 0102 -d aabb --commit  -> write file with id 0102 and perform commit after write\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose mode"),
        arg_int0("n",  NULL,      "<dec>", "Key ID"),
        arg_str0("k",  "key",     "<hex>", "Auth key"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (AID) ( 1..16 bytes )"),
        arg_str0(NULL, "fid",     "<hex>", "File ID"),
        arg_int0("o",  "offset",  "<dec>", "Offset for reading data from file"),
        arg_lit0(NULL, "noauth",  "Read file without authentication"),
        arg_str0(NULL, "sreq",    "<plain|mac|encode>", "Communication reader-PICC security level (def: mac)"),
        arg_str0(NULL, "sresp",   "<plain|mac|encode>", "Communication PICC-reader security level (def: mac)"),
        arg_str0("d",  "data",    "<hex>", "Data to write to new file"),
        arg_lit0(NULL, "commit",  "Commit after write"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    uint8_t keyId = arg_get_int_def(ctx, 3, defaultKeyId);

    CipurseChannelSecurityLevel sreq = CPSMACed;
    CipurseChannelSecurityLevel sresp = CPSMACed;

    uint8_t key[CIPURSE_AES_KEY_LENGTH] = {0};

    uint8_t aid[16] = {0};
    size_t aidLen = 0;
    bool useAID = false;
    uint16_t fileId = defaultFileId;
    bool useFID = false;
    int res = CLIParseCommandParameters(ctx, 4, 5, 6, 9, 10, key, aid, &aidLen, &useAID, &fileId, &useFID, &sreq, &sresp);
    if (res || useFID == false) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    size_t offset = arg_get_int_def(ctx, 7, 0);

    bool noAuth = arg_get_lit(ctx, 8);

    uint8_t hdata[250] = {0};
    int hdatalen = sizeof(hdata);
    CLIGetHexWithReturn(ctx, 11, hdata, &hdatalen);
    if (hdatalen == 0) {
        PrintAndLogEx(ERR, _RED_("ERROR:") " file content length must be more 0");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool needCommit = arg_get_lit(ctx, 12);

    CLIParserFree(ctx);

    SetAPDULogging(APDULogging);

    size_t len = 0;
    uint16_t sw = 0;
    uint8_t buf[APDU_RES_LEN] = {0};

    res = CIPURSESelectAID(true, true, aid, aidLen, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Cipurse select application " _CYAN_("%s") " ( " _RED_("error") " ). Card returns 0x%04x", sprint_hex_inrow(aid, aidLen), sw);
        DropField();
        return PM3_ESOFT;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "Cipurse select application " _CYAN_("%s") " ( %s )", sprint_hex_inrow(aid, aidLen), _GREEN_("ok"));
        PrintAndLogEx(INFO, "File id " _YELLOW_("%x") " offset " _YELLOW_("%zu") " key id " _YELLOW_("%d") " key " _YELLOW_("%s")
                      , fileId
                      , offset
                      , keyId
                      , sprint_hex(key, CIPURSE_AES_KEY_LENGTH)
                     );
        PrintAndLogEx(INFO, "Data [%d]: %s", hdatalen, sprint_hex(hdata, hdatalen));
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
    if (res != 0 || sw != ISO7816_OK) {
        if (verbose == false)
            PrintAndLogEx(ERR, "File select " _RED_("ERROR") ". Card returns 0x%04x", sw);
        DropField();
        return PM3_ESOFT;
    }

    if (verbose)
        PrintAndLogEx(INFO, "Select file 0x%x ( %s )", fileId, _GREEN_("ok"));

    res = CIPURSEUpdateBinary(offset, hdata, hdatalen, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != ISO7816_OK) {
        if (verbose == false)
            PrintAndLogEx(ERR, "File write " _RED_("ERROR") ". Card returns 0x%04x", sw);
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "File id " _YELLOW_("%x") " successfully written", fileId);

    if (needCommit) {
        sw = 0;
        res = CIPURSECommitTransaction(&sw);
        if (res != 0 || sw != ISO7816_OK)
            PrintAndLogEx(WARNING, "Commit ( " _YELLOW_("fail") " ) Card returns 0x%04x", sw);

        if (verbose)
            PrintAndLogEx(INFO, "Commit ( " _GREEN_("ok") " )");
    }

    DropField();
    return PM3_SUCCESS;
}

static int CmdHFCipurseReadFileAttr(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cipurse aread",
                  "Read file attributes by file ID with key ID and key. If no key is supplied, default key of 737373...7373 will be used",
                  "hf cipurse aread --fid 2ff7  -> Select MF, Authenticate with keyID 1, read file attributes with id 2ff7\n"
                  "hf cipurse aread --mfd   -> read file attributes for master file (MF)\n"
                  "hf cipurse aread --chfid 0102  -> read file 0102 attributes in the default application\n"
                  "hf cipurse aread --aid 4144204632 --chfid 0102  -> read file 0102 attributes in the 4144204632 application\n"
                  "hf cipurse aread -n 2 -k 65656565656565656565656565656565 --fid 2ff7 -> Authenticate keyID 2, read file attributes\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose mode"),
        arg_int0("n",  NULL,      "<dec>", "Key ID"),
        arg_str0("k",  "key",     "<hex>", "Auth key"),
        arg_lit0(NULL, "mfd",     "Show info about master file"),
        arg_str0(NULL, "aid",     "<hex>", "Select application ID (AID) ( 1..16 bytes )"),
        arg_str0(NULL, "fid",     "<hex>", "File ID"),
        arg_str0(NULL, "chfid",   "<hex>", "Child file ID (EF under application/master file) ( 2 bytes )"),
        arg_lit0(NULL, "noauth",  "Read file attributes without authentication"),
        arg_str0(NULL, "sreq",    "<plain|mac|encode>", "Communication reader-PICC security level (def: mac)"),
        arg_str0(NULL, "sresp",   "<plain|mac|encode>", "Communication PICC-reader security level (def: mac)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    uint8_t keyId = arg_get_int_def(ctx, 3, defaultKeyId);
    bool selmfd = arg_get_lit(ctx, 5);

    CipurseChannelSecurityLevel sreq = CPSMACed;
    CipurseChannelSecurityLevel sresp = CPSMACed;
    uint8_t key[CIPURSE_AES_KEY_LENGTH] = {0};

    uint8_t aid[16] = {0};
    size_t aidLen = 0;
    bool useAID = false;
    uint16_t fileId = defaultFileId;
    bool useFID = false;
    uint16_t childFileId = defaultFileId;
    bool useChildFID = false;
    int res = CLIParseCommandParametersEx(ctx, 4, 6, 7, 8, 10, 11, key, aid, &aidLen, &useAID, &fileId, &useFID, &childFileId, &useChildFID, &sreq, &sresp);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool noAuth = arg_get_lit(ctx, 9);

    CLIParserFree(ctx);

    SetAPDULogging(APDULogging);

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    res = SelectCommandEx(selmfd, useAID, aid, aidLen, useFID, fileId, useChildFID, childFileId, verbose, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Select command ( " _RED_("error") " )");
        DropField();
        return PM3_ESOFT;
    }

    if (verbose) {
        if (selmfd)
            PrintAndLogEx(INFO, "File " _CYAN_("Master File"));
        else if (useFID)
            PrintAndLogEx(INFO, "File id " _CYAN_("%04x"), fileId);
        else
            PrintAndLogEx(INFO, "Application ID " _CYAN_("%s"), sprint_hex_inrow(aid, aidLen));

        if (useChildFID)
            PrintAndLogEx(INFO, "Child file id " _CYAN_("%04x"), childFileId);

        if (!noAuth)
            PrintAndLogEx(INFO, "Key id " _YELLOW_("%d") " key " _YELLOW_("%s")
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

    res = CIPURSEReadFileAttributes(buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != ISO7816_OK) {
        if (verbose == false)
            PrintAndLogEx(ERR, "File read " _RED_("ERROR") ". Card returns 0x%04x", sw);
        DropField();
        return PM3_ESOFT;
    }

    if (len == 0) {
        PrintAndLogEx(WARNING, "File attributes is empty");
        DropField();
        return PM3_SUCCESS;
    }

    if (verbose)
        PrintAndLogEx(INFO, "Attributes raw data [%zu]: %s", len, sprint_hex(buf, len));

    CIPURSEPrintFileAttr(buf, len);

    DropField();
    return PM3_SUCCESS;
}

static int CmdHFCipurseWriteFileAttr(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cipurse awrite",
                  "Write file attributes by file ID with key ID and key. If no key is supplied, default key of 737373...7373 will be used",
                  "hf cipurse awrite --fid 2ff7 -d 080000C1C1C1C1C1C1C1C1C1    -> write default file attributes with id 2ff7\n"
                  "hf cipurse awrite --mfd -d 080000FFFFFFFFFFFFFFFFFF86023232 --commit    -> write file attributes for master file (MF)\n"
                  "hf cipurse awrite --chfid 0102 -d 020000ffffff  -> write file 0102 attributes in the default application to full access\n"
                  "hf cipurse awrite --chfid 0102 -d 02000040ffff  -> write file 0102 attributes in the default application to full access with keys 1 and 2\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose mode"),
        arg_int0("n",  NULL,      "<dec>", "Key ID"),
        arg_str0("k",  "key",     "<hex>", "Auth key"),
        arg_lit0(NULL, "mfd",     "Show info about master file"),
        arg_str0(NULL, "aid",     "<hex>", "Select application ID (AID) ( 1..16 bytes )"),
        arg_str0(NULL, "fid",     "<hex>", "File ID"),
        arg_str0(NULL, "chfid",   "<hex>", "Child file ID (EF under application/master file) ( 2 bytes )"),
        arg_lit0(NULL, "noauth",  "Read file attributes without authentication"),
        arg_str0(NULL, "sreq",    "<plain|mac|encode>", "Communication reader-PICC security level (def: mac)"),
        arg_str0(NULL, "sresp",   "<plain|mac|encode>", "Communication PICC-reader security level (def: mac)"),
        arg_str0("d",  "data",    "<hex>", "File attributes"),
        arg_lit0(NULL, "commit",  "Commit after write"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    uint8_t keyId = arg_get_int_def(ctx, 3, defaultKeyId);
    bool selmfd = arg_get_lit(ctx, 5);

    CipurseChannelSecurityLevel sreq = CPSMACed;
    CipurseChannelSecurityLevel sresp = CPSMACed;
    uint8_t key[CIPURSE_AES_KEY_LENGTH] = {0};

    uint8_t aid[16] = {0};
    size_t aidLen = 0;
    bool useAID = false;
    uint16_t fileId = defaultFileId;
    bool useFID = false;
    uint16_t childFileId = defaultFileId;
    bool useChildFID = false;
    int res = CLIParseCommandParametersEx(ctx, 4, 6, 7, 8, 10, 11, key, aid, &aidLen, &useAID, &fileId, &useFID, &childFileId, &useChildFID, &sreq, &sresp);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool noAuth = arg_get_lit(ctx, 9);

    uint8_t hdata[250] = {0};
    int hdatalen = sizeof(hdata);
    CLIGetHexWithReturn(ctx, 12, hdata, &hdatalen);
    if (hdatalen == 0) {
        PrintAndLogEx(ERR, _RED_("ERROR:") " file attributes length must be more 0");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool needCommit = arg_get_lit(ctx, 13);

    CLIParserFree(ctx);

    SetAPDULogging(APDULogging);

    if (verbose) {
        PrintAndLogEx(INFO, "Attribtes data[%d]: %s", hdatalen, sprint_hex(hdata, hdatalen));
        CIPURSEPrintFileUpdateAttr(hdata, hdatalen);
    }

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    res = SelectCommandEx(selmfd, useAID, aid, aidLen, useFID, fileId, useChildFID, childFileId, verbose, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Select command ( " _RED_("error") " )");
        DropField();
        return PM3_ESOFT;
    }

    if (verbose) {
        if (selmfd)
            PrintAndLogEx(INFO, "File " _CYAN_("Master File"));
        else if (useFID)
            PrintAndLogEx(INFO, "File id " _CYAN_("%04x"), fileId);
        else
            PrintAndLogEx(INFO, "Application ID " _CYAN_("%s"), sprint_hex_inrow(aid, aidLen));

        if (useChildFID)
            PrintAndLogEx(INFO, "Child file id " _CYAN_("%04x"), childFileId);

        if (!noAuth)
            PrintAndLogEx(INFO, "Key id " _YELLOW_("%d") " key " _YELLOW_("%s")
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

    res = CIPURSEUpdateFileAttributes(hdata, hdatalen, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != ISO7816_OK) {
        if (verbose == false)
            PrintAndLogEx(ERR, "File attributes update " _RED_("ERROR") ". Card returns 0x%04x", sw);
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "File attributes updated ( " _GREEN_("ok") " )");

    if (needCommit) {
        sw = 0;
        res = CIPURSECommitTransaction(&sw);
        if (res != 0 || sw != ISO7816_OK)
            PrintAndLogEx(WARNING, "Commit ( " _YELLOW_("fail") " ) Card returns 0x%04x", sw);

        if (verbose)
            PrintAndLogEx(INFO, "Commit ( " _GREEN_("ok") " )");
    }

    DropField();
    return PM3_SUCCESS;
}

static int CmdHFCipurseFormatAll(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cipurse formatall",
                  "Format card. Erases all the data at the card level!",
                  "hf cipurse formatall  -> Format card with default key\n"
                  "hf cipurse formatall -n 2 -k 65656565656565656565656565656565 -> Format card with keyID 2\n"
                  "hf cipurse formatall --no-auth -> Format card without authentication. Works for card in perso state\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose mode"),
        arg_int0("n",  NULL,      "<dec>", "Key ID"),
        arg_str0("k",  "key",     "<hex>", "Auth key"),
        arg_str0(NULL, "sreq",    "<plain|mac|encode>", "Communication reader-PICC security level (def: mac)"),
        arg_str0(NULL, "sresp",   "<plain|mac|encode>", "Communication PICC-reader security level (def: mac)"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    uint8_t keyId = arg_get_int_def(ctx, 3, defaultKeyId);

    CipurseChannelSecurityLevel sreq = CPSMACed;
    CipurseChannelSecurityLevel sresp = CPSMACed;
    uint8_t key[CIPURSE_AES_KEY_LENGTH] = {0};
    int res = CLIParseCommandParameters(ctx, 4, 0, 0, 5, 6, key, NULL, NULL, NULL, NULL, NULL, &sreq, &sresp);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool noauth = arg_get_lit(ctx, 7);

    CLIParserFree(ctx);
    SetAPDULogging(APDULogging);

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    res = CIPURSESelectMFEx(true, true, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Cipurse masterfile select " _RED_("error") ". Card returns 0x%04x", sw);
        DropField();
        return PM3_ESOFT;
    }

    if (verbose) {
        PrintAndLogEx(WARNING, _YELLOW_("FORMAT erases all the data at this card!!!"));
        if (!noauth)
            PrintAndLogEx(INFO, "key id " _YELLOW_("%d") " key " _YELLOW_("%s")
                          , keyId
                          , sprint_hex(key, CIPURSE_AES_KEY_LENGTH)
                         );
    }

    if (!noauth) {
        bool bres = CIPURSEChannelAuthenticate(keyId, key, verbose);
        if (bres == false) {
            if (verbose)
                PrintAndLogEx(ERR, "Authentication ( " _RED_("fail") " )");
            DropField();
            return PM3_ESOFT;
        }

        // set channel security levels
        CIPURSECSetActChannelSecurityLevels(sreq, sresp);
    }

    res = CIPURSEFormatAll(&sw);
    if (res != 0 || sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Format " _RED_("ERROR") ". Card returns 0x%04x", sw);
        DropField();
        return PM3_ESOFT;
    }
    PrintAndLogEx(INFO, "Card formatted " _GREEN_("succesfully"));

    DropField();
    return PM3_SUCCESS;
}

static int CmdHFCipurseCreateDGI(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cipurse create",
                  "Create application/file/key by provide appropriate DGI. If no key is supplied, default key of 737373...7373 will be used",
                  "hf cipurse create -d 9200123F00200008000062098407A0000005070100 -> create PTSE file with FID 0x2000 and space for 8 AIDs\n"
                  "hf cipurse create -d 92002438613F010A050200004040FF021009021009621084054144204631D407A0000005070100A00F28"
                  "73737373737373737373737373737373015FD67B000102030405060708090A0B0C0D0E0F01C6A13B -> create default file with FID 3F01 and 2 keys\n"
                  "hf cipurse create --aid 4144204631 -d 92010C010001020030020000FFFFFF -> create 0x0102 binary data EF under application 4144204631\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose mode"),
        arg_int0("n",  NULL,      "<dec>", "Key ID"),
        arg_str0("k",  "key",     "<hex>", "Auth key"),

        arg_str0(NULL, "aid",     "<hex>", "Application ID (AID) ( 1..16 bytes )"),
        arg_str0(NULL, "fid",     "<hex>", "File ID (FID) ( 2 bytes )"),
        arg_lit0(NULL, "mfd",     "Select masterfile by empty id"),

        arg_str0("d",  "data",    "<hex>", "Data with DGI for create"),
        arg_str0(NULL, "sreq",    "<plain|mac|encode>", "Communication reader-PICC security level (def: mac)"),
        arg_str0(NULL, "sresp",   "<plain|mac|encode>", "Communication PICC-reader security level (def: mac)"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_lit0(NULL, "commit",  "Commit after create"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    uint8_t keyId = arg_get_int_def(ctx, 3, defaultKeyId);

    CipurseChannelSecurityLevel sreq = CPSMACed;
    CipurseChannelSecurityLevel sresp = CPSMACed;
    uint8_t key[CIPURSE_AES_KEY_LENGTH] = {0};

    uint8_t aid[16] = {0};
    size_t aidLen = 0;
    bool useAID = false;
    uint16_t fileId = defaultFileId;
    bool useFID = false;
    int res = CLIParseCommandParameters(ctx, 4, 5, 6, 9, 10, key, aid, &aidLen, &useAID, &fileId, &useFID, &sreq, &sresp);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool selmfd = arg_get_lit(ctx, 7);

    uint8_t hdata[250] = {0};
    int hdatalen = sizeof(hdata);
    CLIGetHexWithReturn(ctx, 8, hdata, &hdatalen);
    if (hdatalen < 4 || hdatalen > 200) {
        PrintAndLogEx(ERR, _RED_("ERROR:") " data length must be 4-200 bytes only");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool noauth = arg_get_lit(ctx, 11);
    bool needCommit = arg_get_lit(ctx, 12);

    CLIParserFree(ctx);
    SetAPDULogging(APDULogging);

    if (verbose && hdatalen > 3)
        CIPURSEPrintDGIArray(hdata, hdatalen);

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    if (useAID || useFID || selmfd) {
        res = SelectCommand(selmfd, useAID, aid, aidLen, useFID, fileId, verbose, buf, sizeof(buf), &len, &sw);
        if (res != 0 || sw != ISO7816_OK) {
            PrintAndLogEx(ERR, "Select command ( " _RED_("error") " )");
            DropField();
            return PM3_ESOFT;
        }
    } else {
        res = CIPURSESelectMFEx(true, true, buf, sizeof(buf), &len, &sw);
        if (res != 0 || sw != ISO7816_OK) {
            PrintAndLogEx(ERR, "Cipurse masterfile select " _RED_("error") ". Card returns 0x%04x", sw);
            DropField();
            return PM3_ESOFT;
        }
        if (verbose)
            PrintAndLogEx(INFO, "Cipurse masterfile " _GREEN_("selected"));
    }

    if (verbose) {
        if (!noauth)
            PrintAndLogEx(INFO, "Key id " _YELLOW_("%d") " key " _YELLOW_("%s")
                          , keyId
                          , sprint_hex(key, CIPURSE_AES_KEY_LENGTH)
                         );
    }

    if (!noauth) {
        bool bres = CIPURSEChannelAuthenticate(keyId, key, verbose);
        if (bres == false) {
            if (verbose)
                PrintAndLogEx(ERR, "Authentication ( " _RED_("fail") " )");
            DropField();
            return PM3_ESOFT;
        }

        // set channel security levels
        CIPURSECSetActChannelSecurityLevels(sreq, sresp);
    }

    res = CIPURSECreateFile(hdata, hdatalen, buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Create file command " _RED_("ERROR"));
        PrintAndLogEx(ERR, "0x%04x - %s", sw,
                      GetSpecificAPDUCodeDesc(SelectAPDUCodeDescriptions, ARRAYLEN(SelectAPDUCodeDescriptions), sw));
        DropField();
        return PM3_ESOFT;
    }
    PrintAndLogEx(INFO, "File created " _GREEN_("succesfully"));

    if (needCommit) {
        sw = 0;
        res = CIPURSECommitTransaction(&sw);
        if (res != 0 || sw != ISO7816_OK)
            PrintAndLogEx(WARNING, "Commit ( " _YELLOW_("fail") " ) Card returns 0x%04x", sw);

        if (verbose)
            PrintAndLogEx(INFO, "Commit ( " _GREEN_("ok") " )");
    }

    DropField();
    return PM3_SUCCESS;
}

static int CmdHFCipurseDeleteFile(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cipurse delete",
                  "Delete file by file ID with key ID and key. If no key is supplied, default key of 737373...7373 will be used",
                  "hf cipurse delete --fid 2ff7       -> Authenticate with keyID 1, delete file with id 2ff7 at top level\n"
                  "hf cipurse delete -n 2 -k 65656565656565656565656565656565 --fid 2ff7 -> Authenticate keyID 2 and delete file\n"
                  "hf cipurse delete --aid A0000005070100 --no-auth  -> delete PTSE file with AID A0000005070100 without authentication\n"
                  "hf cipurse delete --aid 4144204631 --chfid 0102  -> delete EF with FID 0x0102 under default application\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Verbose mode"),
        arg_int0("n",  NULL,      "<dec>", "Key ID"),
        arg_str0("k",  "key",     "<hex>", "Auth key"),
        arg_str0(NULL, "fid",     "<hex>", "File/application ID under MF for delete"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (AID) for delete ( 1..16 bytes )"),
        arg_str0(NULL, "chfid",   "<hex>", "Child file ID (EF under application/master file) ( 2 bytes )"),
        arg_str0(NULL, "sreq",    "<plain|mac|encode>", "Communication reader-PICC security level (def: mac)"),
        arg_str0(NULL, "sresp",   "<plain|mac|encode>", "Communication PICC-reader security level (def: mac)"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_lit0(NULL, "commit",  "commit after delete"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    uint8_t keyId = arg_get_int_def(ctx, 3, defaultKeyId);

    CipurseChannelSecurityLevel sreq = CPSMACed;
    CipurseChannelSecurityLevel sresp = CPSMACed;
    uint8_t key[CIPURSE_AES_KEY_LENGTH] = {0};

    uint8_t aid[16] = {0};
    size_t aidLen = 0;
    bool useAID = false;
    uint16_t fileId = defaultFileId;
    bool useFID = false;
    uint16_t childFileId = defaultFileId;
    bool useChildFID = false;
    int res = CLIParseCommandParametersEx(ctx, 4, 6, 5, 7, 8, 9, key, aid, &aidLen, &useAID, &fileId, &useFID, &childFileId, &useChildFID, &sreq, &sresp);
    // useAID and useFID in the same state
    if (res || !(useAID ^ useFID)) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool noauth = arg_get_lit(ctx, 10);
    bool needCommit = arg_get_lit(ctx, 11);

    CLIParserFree(ctx);
    SetAPDULogging(APDULogging);

    if (verbose) {
        if (useFID)
            PrintAndLogEx(INFO, "File id " _CYAN_("%x"), fileId);
        else
            PrintAndLogEx(INFO, "Application ID " _CYAN_("%s"), sprint_hex_inrow(aid, aidLen));

        if (useChildFID)
            PrintAndLogEx(INFO, "Child file id " _CYAN_("%x"), childFileId);

        if (!noauth)
            PrintAndLogEx(INFO, "Key id " _YELLOW_("%d") " key " _YELLOW_("%s")
                          , keyId
                          , sprint_hex(key, CIPURSE_AES_KEY_LENGTH)
                         );
    }

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    if (useChildFID) {
        res = SelectCommand(false, useAID, aid, aidLen, useFID, fileId, verbose, buf, sizeof(buf), &len, &sw);
        if (res != 0 || sw != ISO7816_OK) {
            PrintAndLogEx(ERR, "Top level select " _RED_("error") ". Card returns 0x%04x", sw);
            DropField();
            return PM3_ESOFT;
        }
    } else {
        res = CIPURSESelectMFEx(true, true, buf, sizeof(buf), &len, &sw);
        if (res != 0 || sw != ISO7816_OK) {
            PrintAndLogEx(ERR, "Cipurse masterfile select " _RED_("error") ". Card returns 0x%04x", sw);
            DropField();
            return PM3_ESOFT;
        }
    }

    if (!noauth) {
        bool bres = CIPURSEChannelAuthenticate(keyId, key, verbose);
        if (bres == false) {
            if (verbose)
                PrintAndLogEx(ERR, "Authentication ( " _RED_("fail") " )");
            DropField();
            return PM3_ESOFT;
        }

        // set channel security levels
        CIPURSECSetActChannelSecurityLevels(sreq, sresp);
    }

    if (useChildFID) {
        res = CIPURSEDeleteFile(childFileId, buf, sizeof(buf), &len, &sw);
        if (res != 0 || sw != ISO7816_OK) {
            PrintAndLogEx(ERR, "Delete child file " _CYAN_("%04x ") " %s", childFileId, _RED_("ERROR"));
            PrintAndLogEx(ERR, "0x%04x - %s",
                          sw,
                          GetSpecificAPDUCodeDesc(DeleteAPDUCodeDescriptions, ARRAYLEN(DeleteAPDUCodeDescriptions), sw)
                         );
            DropField();
            return PM3_ESOFT;
        }
        PrintAndLogEx(INFO, "Child file id " _CYAN_("%04x") " deleted " _GREEN_("succesfully"), childFileId);
    } else if (useFID) {
        res = CIPURSEDeleteFile(fileId, buf, sizeof(buf), &len, &sw);
        if (res != 0 || sw != ISO7816_OK) {
            PrintAndLogEx(ERR, "Delete file " _CYAN_("%04x ") " %s", fileId, _RED_("ERROR"));
            PrintAndLogEx(ERR, "0x%04x - %s",
                          sw,
                          GetSpecificAPDUCodeDesc(DeleteAPDUCodeDescriptions, ARRAYLEN(DeleteAPDUCodeDescriptions), sw)
                         );
            DropField();
            return PM3_ESOFT;
        }
        PrintAndLogEx(INFO, "File id " _CYAN_("%04x") " deleted " _GREEN_("succesfully"), fileId);
    } else {
        res = CIPURSEDeleteFileAID(aid, aidLen, buf, sizeof(buf), &len, &sw);
        if (res != 0 || sw != ISO7816_OK) {
            PrintAndLogEx(ERR, "Delete application " _CYAN_("%s ") " %s", sprint_hex_inrow(aid, aidLen), _RED_("ERROR"));
            PrintAndLogEx(ERR, "0x%04x - %s",
                          sw,
                          GetSpecificAPDUCodeDesc(DeleteAPDUCodeDescriptions, ARRAYLEN(DeleteAPDUCodeDescriptions), sw)
                         );
            DropField();
            return PM3_ESOFT;
        }
        PrintAndLogEx(INFO, "Delete application " _CYAN_("%s") " ( %s )", sprint_hex_inrow(aid, aidLen),  _GREEN_("ok"));
    }

    if (needCommit) {
        sw = 0;
        res = CIPURSECommitTransaction(&sw);
        if (res != 0 || sw != ISO7816_OK)
            PrintAndLogEx(WARNING, "Commit ( " _YELLOW_("fail") " ) Card returns 0x%04x", sw);

        if (verbose)
            PrintAndLogEx(INFO, "Commit ( " _GREEN_("ok") " )");
    }

    DropField();
    return PM3_SUCCESS;
}

static int CmdHFCipurseUpdateKey(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cipurse updkey",
                  "Update key",
                  "hf cipurse updkey --aid 4144204631 --newkeyn 2 --newkeya 00 --newkey 73737373737373737373737373737373   -> update default application key 2 with default value 73..73\n"
                  "hf cipurse updkey --newkeyn 1 --newkeya 00 --newkey 0102030405060708090a0b0c0d0e0f10 --commit           ->  for key 1");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Show technical data"),
        arg_int0("n",  NULL,      "<dec>", "Key ID for authentication"),
        arg_str0("k",  "key",     "<hex>", "Auth key"),

        arg_str0(NULL, "aid",     "<hex 1..16 bytes>", "Application ID (AID)"),
        arg_str0(NULL, "fid",     "<hex 2 bytes>", "File ID (FID)"),
        arg_lit0(NULL, "mfd",     "Select masterfile by empty id"),

        arg_int0(NULL, "newkeyn", "<dec>", "Target key ID"),
        arg_str0(NULL, "newkey",  "<hex 16 byte>", "New key"),
        arg_str0(NULL, "newkeya", "<hex 1 byte>", "New key additional info (def: 0x00)"),

        arg_int0(NULL, "enckeyn", "<dec>", "Encrypt key ID (must be equal to the key on the card)"),
        arg_str0(NULL, "enckey",  "<hex 16 byte>", "Encrypt key (must be equal to the key on the card)"),

        arg_str0(NULL, "sreq",    "<plain|mac(default)|encode>", "Communication reader-PICC security level"),
        arg_str0(NULL, "sresp",   "<plain|mac(default)|encode>", "Communication PICC-reader security level"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_lit0(NULL, "commit",  "Commit "),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    uint8_t keyId = arg_get_int_def(ctx, 3, defaultKeyId);

    CipurseChannelSecurityLevel sreq = CPSMACed;
    CipurseChannelSecurityLevel sresp = CPSMACed;
    uint8_t key[CIPURSE_AES_KEY_LENGTH] = {0};

    uint8_t aid[16] = {0};
    size_t aidLen = 0;
    bool useAID = false;
    uint16_t fileId = defaultFileId;
    bool useFID = false;
    int res = CLIParseCommandParameters(ctx, 4, 5, 6, 13, 14, key, aid, &aidLen, &useAID, &fileId, &useFID, &sreq, &sresp);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool selmfd = arg_get_lit(ctx, 7);

    uint8_t newKeyId = arg_get_int_def(ctx, 8, 0);
    if (newKeyId == 0) {
        PrintAndLogEx(ERR, _RED_("ERROR:") " new key id must be specified.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t hdata[250] = {0};
    int hdatalen = sizeof(hdata);
    CLIGetHexWithReturn(ctx, 9, hdata, &hdatalen);
    if (hdatalen != 16) {
        PrintAndLogEx(ERR, _RED_("ERROR:") " new key must be 16 bytes only and must be specified.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t newKey[CIPURSE_AES_KEY_LENGTH] = {0};
    memcpy(newKey, hdata, CIPURSE_AES_KEY_LENGTH);

    hdatalen = sizeof(hdata);
    CLIGetHexWithReturn(ctx, 10, hdata, &hdatalen);
    if (hdatalen && hdatalen != 1) {
        PrintAndLogEx(ERR, _RED_("ERROR:") " new key additional info must be 1 byte only.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t newKeyAInfo = (hdatalen) ? hdata[0] : 0x00;

    uint8_t encKeyId = arg_get_int_def(ctx, 11, 0);

    hdatalen = sizeof(hdata);
    CLIGetHexWithReturn(ctx, 12, hdata, &hdatalen);
    if (hdatalen && hdatalen != 16) {
        PrintAndLogEx(ERR, _RED_("ERROR:") " encode key must be 16 bytes only and must be specified.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t encKey[CIPURSE_AES_KEY_LENGTH] = CIPURSE_DEFAULT_KEY;
    if (hdatalen)
        memcpy(encKey, hdata, CIPURSE_AES_KEY_LENGTH);

    bool noauth = arg_get_lit(ctx, 15);
    bool needCommit = arg_get_lit(ctx, 16);

    CLIParserFree(ctx);
    SetAPDULogging(APDULogging);

    uint8_t kvv[CIPURSE_KVV_LENGTH] = {0};
    CipurseCGetKVV(newKey, kvv);

    uint8_t keydata[3 + 16 + 3] = {newKeyAInfo, 0x10, 0x09, 0x00};
    memcpy(&keydata[3], newKey, 16);
    memcpy(&keydata[3 + 16], kvv, 3);

    if (verbose) {
        PrintAndLogEx(INFO, "New key number: %d", newKeyId);
        PrintAndLogEx(INFO, "New key additional info: 0x%02x", newKeyAInfo);
        PrintAndLogEx(INFO, "New key: %s", sprint_hex_inrow(newKey, 16));
        PrintAndLogEx(INFO, "New key kvv: %s", sprint_hex_inrow(kvv, 3));
        PrintAndLogEx(INFO, "New key data: %s", sprint_hex_inrow(keydata, sizeof(keydata)));
        if (encKeyId) {
            PrintAndLogEx(INFO, "Encode key number: %d", encKeyId);
            PrintAndLogEx(INFO, "Encode key: %s", sprint_hex_inrow(encKey, 16));

            aes_encode(NULL, encKey, newKey, &keydata[3], CIPURSE_AES_KEY_LENGTH);

            PrintAndLogEx(INFO, "Encoded new key data: %s", sprint_hex_inrow(keydata, sizeof(keydata)));
        }
        PrintAndLogEx(NORMAL, "");
    }

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    if (useAID || useFID || selmfd) {
        res = SelectCommand(selmfd, useAID, aid, aidLen, useFID, fileId, verbose, buf, sizeof(buf), &len, &sw);
        if (res != 0 || sw != ISO7816_OK) {
            PrintAndLogEx(ERR, "Select command ( " _RED_("error") " )");
            DropField();
            return PM3_ESOFT;
        }
    } else {
        res = CIPURSESelectMFEx(true, true, buf, sizeof(buf), &len, &sw);
        if (res != 0 || sw != ISO7816_OK) {
            PrintAndLogEx(ERR, "Cipurse masterfile select " _RED_("error") ". Card returns 0x%04x", sw);
            DropField();
            return PM3_ESOFT;
        }
        if (verbose)
            PrintAndLogEx(INFO, "Cipurse masterfile " _GREEN_("selected"));
    }

    if (verbose) {
        if (!noauth)
            PrintAndLogEx(INFO, "Key id " _YELLOW_("%d") " key " _YELLOW_("%s")
                          , keyId
                          , sprint_hex(key, CIPURSE_AES_KEY_LENGTH)
                         );
    }

    if (!noauth) {
        bool bres = CIPURSEChannelAuthenticate(keyId, key, verbose);
        if (bres == false) {
            if (verbose)
                PrintAndLogEx(ERR, "Authentication ( " _RED_("fail") " )");
            DropField();
            return PM3_ESOFT;
        }

        // set channel security levels
        CIPURSECSetActChannelSecurityLevels(sreq, sresp);
    }

    res = CIPURSEUpdateKey(encKeyId, newKeyId, keydata, sizeof(keydata), buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Update key command " _RED_("ERROR"));
        PrintAndLogEx(ERR, "0x%04x - %s", sw,
                      GetSpecificAPDUCodeDesc(UAPDpdateKeyCodeDescriptions, ARRAYLEN(UAPDpdateKeyCodeDescriptions), sw));
        DropField();
        return PM3_ESOFT;
    }
    PrintAndLogEx(INFO, "Key updated " _GREEN_("succesfully"));

    if (needCommit) {
        sw = 0;
        res = CIPURSECommitTransaction(&sw);
        if (res != 0 || sw != ISO7816_OK)
            PrintAndLogEx(WARNING, "Commit ( " _YELLOW_("fail") " ) Card returns 0x%04x", sw);

        if (verbose)
            PrintAndLogEx(INFO, "Commit ( " _GREEN_("ok") " )");
    }

    DropField();
    return PM3_SUCCESS;
}

static int CmdHFCipurseUpdateKeyAttr(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cipurse updakey",
                  "Update key attributes. Factory default - 0x02.\n"
                  "b0 - Update right - 1 self\n"
                  "b1 - Change key and rights - 0 frozen\n"
                  "b2 - Use as key encryption key - 1 blocked\n"
                  "b8 - Key validity - 0 valid",
                  "hf cipurse updakey --trgkeyn 2 --attr 80 ->  block key 2 for lifetime (WARNING!)\n"
                  "hf cipurse updakey --trgkeyn 1 --attr 02 --commit ->  for key 1");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("v",  "verbose", "Show technical data"),
        arg_int0("n",  NULL,      "<dec>", "Key ID for authentication"),
        arg_str0("k",  "key",     "<hex>", "Auth key"),

        arg_str0(NULL, "aid",     "<hex 1..16 bytes>", "Application ID (AID)"),
        arg_str0(NULL, "fid",     "<hex 2 bytes>", "File ID (FID)"),
        arg_lit0(NULL, "mfd",     "Select masterfile by empty id"),

        arg_int0(NULL, "trgkeyn", "<dec>", "Target key ID"),
        arg_str0(NULL, "attr",    "<hex 1 byte>", "Key attributes 1 byte"),
        arg_str0(NULL, "sreq",    "<plain|mac(default)|encode>", "Communication reader-PICC security level"),
        arg_str0(NULL, "sresp",   "<plain|mac(default)|encode>", "Communication PICC-reader security level"),
        arg_lit0(NULL, "no-auth", "Execute without authentication"),
        arg_lit0(NULL, "commit",  "Commit "),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    uint8_t keyId = arg_get_int_def(ctx, 3, defaultKeyId);

    CipurseChannelSecurityLevel sreq = CPSMACed;
    CipurseChannelSecurityLevel sresp = CPSMACed;
    uint8_t key[CIPURSE_AES_KEY_LENGTH] = {0};

    uint8_t aid[16] = {0};
    size_t aidLen = 0;
    bool useAID = false;
    uint16_t fileId = defaultFileId;
    bool useFID = false;
    int res = CLIParseCommandParameters(ctx, 4, 5, 6, 10, 11, key, aid, &aidLen, &useAID, &fileId, &useFID, &sreq, &sresp);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool selmfd = arg_get_lit(ctx, 7);

    uint8_t trgKeyId = arg_get_int_def(ctx, 8, 0);
    if (trgKeyId == 0) {
        PrintAndLogEx(ERR, _RED_("ERROR:") " target key id must be specified.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t hdata[250] = {0};
    int hdatalen = sizeof(hdata);
    CLIGetHexWithReturn(ctx, 9, hdata, &hdatalen);
    if (hdatalen != 1) {
        PrintAndLogEx(ERR, _RED_("ERROR:") " key attributes must be 1 bytes only and must be specified.");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool noauth = arg_get_lit(ctx, 12);
    bool needCommit = arg_get_lit(ctx, 13);

    CLIParserFree(ctx);
    SetAPDULogging(APDULogging);

    if (verbose && hdatalen == 1) {
        PrintAndLogEx(INFO, "Decoded attributes:");
        CIPURSEPrintKeySecurityAttributes(hdata[0]);
        PrintAndLogEx(NORMAL, "");
    }

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    if (useAID || useFID || selmfd) {
        res = SelectCommand(selmfd, useAID, aid, aidLen, useFID, fileId, verbose, buf, sizeof(buf), &len, &sw);
        if (res != 0 || sw != ISO7816_OK) {
            PrintAndLogEx(ERR, "Select command ( " _RED_("error") " )");
            DropField();
            return PM3_ESOFT;
        }
    } else {
        res = CIPURSESelectMFEx(true, true, buf, sizeof(buf), &len, &sw);
        if (res != 0 || sw != ISO7816_OK) {
            PrintAndLogEx(ERR, "Cipurse masterfile select " _RED_("error") ". Card returns 0x%04x", sw);
            DropField();
            return PM3_ESOFT;
        }
        if (verbose)
            PrintAndLogEx(INFO, "Cipurse masterfile " _GREEN_("selected"));
    }

    if (verbose) {
        if (!noauth)
            PrintAndLogEx(INFO, "Key id " _YELLOW_("%d") " key " _YELLOW_("%s")
                          , keyId
                          , sprint_hex(key, CIPURSE_AES_KEY_LENGTH)
                         );
    }

    if (!noauth) {
        bool bres = CIPURSEChannelAuthenticate(keyId, key, verbose);
        if (bres == false) {
            if (verbose)
                PrintAndLogEx(ERR, "Authentication ( " _RED_("fail") " )");
            DropField();
            return PM3_ESOFT;
        }

        // set channel security levels
        CIPURSECSetActChannelSecurityLevels(sreq, sresp);
    }

    res = CIPURSEUpdateKeyAttrib(trgKeyId, hdata[0], buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Update key attributes command " _RED_("ERROR"));
        PrintAndLogEx(ERR, "0x%04x - %s", sw,
                      GetSpecificAPDUCodeDesc(UAPDpdateKeyAttrCodeDescriptions, ARRAYLEN(UAPDpdateKeyAttrCodeDescriptions), sw));
        DropField();
        return PM3_ESOFT;
    }
    PrintAndLogEx(INFO, "Key attributes updated " _GREEN_("succesfully"));

    if (needCommit) {
        sw = 0;
        res = CIPURSECommitTransaction(&sw);
        if (res != 0 || sw != ISO7816_OK)
            PrintAndLogEx(WARNING, "Commit ( " _YELLOW_("fail") " ) Card returns 0x%04x", sw);

        if (verbose)
            PrintAndLogEx(INFO, "Commit ( " _GREEN_("ok") " )");
    }

    DropField();
    return PM3_SUCCESS;
}

bool CheckCardCipurse(void) {
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = CIPURSESelect(true, false, buf, sizeof(buf), &len, &sw);

    return (res == 0 && sw == ISO7816_OK);
}

static int CmdHFCipurseTest(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cipurse test",
                  "Regression tests",
                  "hf cipurse test");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    CIPURSETest(true);
    return PM3_SUCCESS;
}

static int CmdHFCipurseDefault(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cipurse default",
                  "Set default parameters for access to cipurse card",
                  "hf cipurse default --reset -> reset parameters to default\n"
                  "hf cipurse default -n 1 -k 65656565656565656565656565656565 --fid 2ff7 -> Set key, key id and file id\n"
                  "hf cipurse default --aid 4144204632 -> set default application id\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "clear",   "Resets to defaults"),
        arg_int0("n",  NULL,      "<dec>", "Key ID"),
        arg_str0("k",  "key",     "<hex>", "Authentication key"),
        arg_str0(NULL, "aid",     "<hex>", "Application ID (AID) ( 1..16 bytes )"),
        arg_str0(NULL, "fid",     "<hex>", "File ID ( 2 bytes )"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool clearing = arg_get_lit(ctx, 1);
    if (clearing) {
        defaultKeyId = 1;
        defaultFileId = 0x2ff7;
        uint8_t ckey[CIPURSE_AES_KEY_LENGTH] = CIPURSE_DEFAULT_KEY;
        memcpy(defaultKey, ckey, CIPURSE_AES_KEY_LENGTH);
        uint8_t aid[CIPURSE_MAX_AID_LENGTH] = CIPURSE_DEFAULT_AID;
        memcpy(defaultAID, aid, CIPURSE_MAX_AID_LENGTH);
        defaultAIDLength = 5;
    }

    defaultKeyId = arg_get_int_def(ctx, 2, defaultKeyId);

    uint8_t aid[CIPURSE_MAX_AID_LENGTH] = {0};
    size_t aidLen = 0;
    bool useAID = false;
    uint16_t fileId = defaultFileId;
    bool useFID = false;
    int res = CLIParseCommandParameters(ctx, 3, 4, 5, 0, 0, defaultKey, aid, &aidLen, &useAID, &fileId, &useFID, NULL, NULL);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    if (useFID)
        defaultFileId = fileId;

    if (useAID) {
        memcpy(defaultAID, aid, CIPURSE_MAX_AID_LENGTH);
        defaultAIDLength = aidLen;
    }

    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "------------------- " _CYAN_("Default parameters") " -------------------");

    PrintAndLogEx(INFO, "Key ID : %d", defaultKeyId);
    PrintAndLogEx(INFO, "Key    : %s", sprint_hex(defaultKey, sizeof(defaultKey)));
    PrintAndLogEx(INFO, "AID    : %s", sprint_hex(defaultAID, defaultAIDLength));
    PrintAndLogEx(INFO, "File ID: 0x%04x", defaultFileId);

    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",      CmdHelp,                   AlwaysAvailable, "This help."},
    {"info",      CmdHFCipurseInfo,          IfPm3Iso14443a,  "Get info about CIPURSE tag"},
    {"select",    CmdHFCipurseSelect,        IfPm3Iso14443a,  "Select CIPURSE application or file"},
    {"auth",      CmdHFCipurseAuth,          IfPm3Iso14443a,  "Authenticate CIPURSE tag"},
    {"read",      CmdHFCipurseReadFile,      IfPm3Iso14443a,  "Read binary file"},
    {"write",     CmdHFCipurseWriteFile,     IfPm3Iso14443a,  "Write binary file"},
    {"aread",     CmdHFCipurseReadFileAttr,  IfPm3Iso14443a,  "Read file attributes"},
    {"awrite",    CmdHFCipurseWriteFileAttr, IfPm3Iso14443a,  "Write file attributes"},
    {"formatall", CmdHFCipurseFormatAll,     IfPm3Iso14443a,  "Erase all the data from chip"},
    {"create",    CmdHFCipurseCreateDGI,     IfPm3Iso14443a,  "Create file, application, key via DGI record"},
    {"delete",    CmdHFCipurseDeleteFile,    IfPm3Iso14443a,  "Delete file"},
    {"updkey",    CmdHFCipurseUpdateKey,     IfPm3Iso14443a,  "Update key"},
    {"updakey",   CmdHFCipurseUpdateKeyAttr, IfPm3Iso14443a,  "Update key attributes"},
    {"default",   CmdHFCipurseDefault,       IfPm3Iso14443a,  "Set default key and file id for all the other commands"},
    {"test",      CmdHFCipurseTest,          AlwaysAvailable, "Regression tests"},
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
