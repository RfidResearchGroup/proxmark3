//-----------------------------------------------------------------------------
// Copyright (C) 2017 Merlok
// modified 2017 iceman
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// EMV commands
//-----------------------------------------------------------------------------

#include <ctype.h>
#include "mifare.h"
#include "cmdemv.h"
#include "emvjson.h"
#include "emv_pki.h"
#include "test/cryptotest.h"
#include "cliparser/cliparser.h"
#include <jansson.h>

static int CmdHelp(const char *Cmd);

#define TLV_ADD(tag, value)( tlvdb_change_or_add_node(tlvRoot, tag, sizeof(value) - 1, (const unsigned char *)value) )
static void ParamLoadDefaults(struct tlvdb *tlvRoot) {
    //9F02:(Amount, authorized (Numeric)) len:6
    TLV_ADD(0x9F02, "\x00\x00\x00\x00\x01\x00");
    //9F1A:(Terminal Country Code) len:2
    TLV_ADD(0x9F1A, "ru");
    //5F2A:(Transaction Currency Code) len:2
    // USD 840, EUR 978, RUR 810, RUB 643, RUR 810(old), UAH 980, AZN 031, n/a 999
    TLV_ADD(0x5F2A, "\x09\x80");
    //9A:(Transaction Date) len:3
    TLV_ADD(0x9A,   "\x00\x00\x00");
    //9C:(Transaction Type) len:1   |  00 => Goods and service #01 => Cash
    TLV_ADD(0x9C,   "\x00");
    // 9F37 Unpredictable Number len:4
    TLV_ADD(0x9F37, "\x01\x02\x03\x04");
    // 9F6A Unpredictable Number (MSD for UDOL) len:4
    TLV_ADD(0x9F6A, "\x01\x02\x03\x04");
    //9F66:(Terminal Transaction Qualifiers (TTQ)) len:4
    TLV_ADD(0x9F66, "\x26\x00\x00\x00"); // qVSDC
    //95:(Terminal Verification Results) len:5
    // all OK TVR
    TLV_ADD(0x95,   "\x00\x00\x00\x00\x00");
}

static void PrintChannel(EMVCommandChannel channel) {
    switch (channel) {
        case ECC_CONTACTLESS:
            PrintAndLogEx(INFO, "Channel: CONTACTLESS (T=CL)");
            break;
        case ECC_CONTACT:
            PrintAndLogEx(INFO, "Channel: CONTACT");
            break;
    }
}

static int CmdEMVSelect(const char *Cmd) {
    uint8_t data[APDU_AID_LEN] = {0};
    int datalen = 0;

    CLIParserInit("emv select",
                  "Executes select applet command",
                  "Usage:\n\temv select -s a00000000101 -> select card, select applet\n\temv select -st a00000000101 -> select card, select applet, show result in TLV\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("sS",  "select",  "activate field and select card"),
        arg_lit0("kK",  "keep",    "keep field for next command"),
        arg_lit0("aA",  "apdu",    "show APDU reqests and responses"),
        arg_lit0("tT",  "tlv",     "TLV decode results"),
        arg_lit0("wW",  "wired",   "Send data via contact (iso7816) interface. Contactless interface set by default."),
        arg_strx0(NULL,  NULL,     "<HEX applet AID>", NULL),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, true);

    bool activateField = arg_get_lit(1);
    bool leaveSignalON = arg_get_lit(2);
    bool APDULogging = arg_get_lit(3);
    bool decodeTLV = arg_get_lit(4);
    EMVCommandChannel channel = ECC_CONTACTLESS;
    if (arg_get_lit(5))
        channel = ECC_CONTACT;
    PrintChannel(channel);
    CLIGetHexWithReturn(6, data, &datalen);
    CLIParserFree();

    SetAPDULogging(APDULogging);

    // exec
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = EMVSelect(channel, activateField, leaveSignalON, data, datalen, buf, sizeof(buf), &len, &sw, NULL);

    if (sw)
        PrintAndLogEx(INFO, "APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));

    if (res)
        return res;

    if (decodeTLV)
        TLVPrintFromBuffer(buf, len);

    return PM3_SUCCESS;
}

static int CmdEMVSearch(const char *Cmd) {

    CLIParserInit("emv search",
                  "Tries to select all applets from applet list:\n",
                  "Usage:\n\temv search -s -> select card and search\n\temv search -st -> select card, search and show result in TLV\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("sS",  "select",  "activate field and select card"),
        arg_lit0("kK",  "keep",    "keep field ON for next command"),
        arg_lit0("aA",  "apdu",    "show APDU reqests and responses"),
        arg_lit0("tT",  "tlv",     "TLV decode results of selected applets"),
        arg_lit0("wW",  "wired",   "Send data via contact (iso7816) interface. Contactless interface set by default."),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, true);

    bool activateField = arg_get_lit(1);
    bool leaveSignalON = arg_get_lit(2);
    bool APDULogging = arg_get_lit(3);
    bool decodeTLV = arg_get_lit(4);
    EMVCommandChannel channel = ECC_CONTACTLESS;
    if (arg_get_lit(5))
        channel = ECC_CONTACT;
    PrintChannel(channel);
    CLIParserFree();

    SetAPDULogging(APDULogging);

    struct tlvdb *t = NULL;
    const char *al = "Applets list";
    t = tlvdb_fixed(1, strlen(al), (const unsigned char *)al);

    if (EMVSearch(channel, activateField, leaveSignalON, decodeTLV, t)) {
        tlvdb_free(t);
        return PM3_ERFTRANS;
    }

    PrintAndLogEx(SUCCESS, "Search completed.");

    // print list here
    if (!decodeTLV) {
        TLVPrintAIDlistFromSelectTLV(t);
    }

    tlvdb_free(t);

    return PM3_SUCCESS;
}

static int CmdEMVPPSE(const char *Cmd) {

    CLIParserInit("emv pse",
                  "Executes PSE/PPSE select command. It returns list of applet on the card:\n",
                  "Usage:\n\temv pse -s1 -> select, get pse\n\temv pse -st2 -> select, get ppse, show result in TLV\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("sS",  "select",  "activate field and select card"),
        arg_lit0("kK",  "keep",    "keep field ON for next command"),
        arg_lit0("1",   "pse",     "pse (1PAY.SYS.DDF01) mode"),
        arg_lit0("2",   "ppse",    "ppse (2PAY.SYS.DDF01) mode (default mode)"),
        arg_lit0("aA",  "apdu",    "show APDU reqests and responses"),
        arg_lit0("tT",  "tlv",     "TLV decode results of selected applets"),
        arg_lit0("wW",  "wired",   "Send data via contact (iso7816) interface. Contactless interface set by default."),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, true);

    bool activateField = arg_get_lit(1);
    bool leaveSignalON = arg_get_lit(2);
    uint8_t PSENum = 2;
    if (arg_get_lit(3))
        PSENum = 1;
    if (arg_get_lit(4))
        PSENum = 2;
    bool APDULogging = arg_get_lit(5);
    bool decodeTLV = arg_get_lit(6);
    EMVCommandChannel channel = ECC_CONTACTLESS;
    if (arg_get_lit(7))
        channel = ECC_CONTACT;
    PrintChannel(channel);
    CLIParserFree();

    SetAPDULogging(APDULogging);

    // exec
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = EMVSelectPSE(channel, activateField, leaveSignalON, PSENum, buf, sizeof(buf), &len, &sw);

    if (sw)
        PrintAndLogEx(INFO, "APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));

    if (res)
        return res;

    if (decodeTLV)
        TLVPrintFromBuffer(buf, len);

    return PM3_SUCCESS;
}

static int CmdEMVGPO(const char *Cmd) {
    uint8_t data[APDU_RES_LEN] = {0};
    int datalen = 0;

    CLIParserInit("emv gpo",
                  "Executes Get Processing Options command. It returns data in TLV format (0x77 - format2) or plain format (0x80 - format1).\nNeeds a EMV applet to be selected.",
                  "Usage:\n\temv gpo -k -> execute GPO\n"
                  "\temv gpo -t 01020304 -> execute GPO with 4-byte PDOL data, show result in TLV\n"
                  "\temv gpo -pmt 9F 37 04 -> load params from file, make PDOL data from PDOL, execute GPO with PDOL, show result in TLV\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("kK",  "keep",    "keep field ON for next command"),
        arg_lit0("pP",  "params",  "load parameters from `emv/defparams.json` file for PDOLdata making from PDOL and parameters"),
        arg_lit0("mM",  "make",    "make PDOLdata from PDOL (tag 9F38) and parameters (by default uses default parameters)"),
        arg_lit0("aA",  "apdu",    "show APDU reqests and responses"),
        arg_lit0("tT",  "tlv",     "TLV decode results of selected applets"),
        arg_lit0("wW",  "wired",   "Send data via contact (iso7816) interface. Contactless interface set by default."),
        arg_strx0(NULL,  NULL,     "<HEX PDOLdata/PDOL>", NULL),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, true);

    bool leaveSignalON = arg_get_lit(1);
    bool paramsLoadFromFile = arg_get_lit(2);
    bool dataMakeFromPDOL = arg_get_lit(3);
    bool APDULogging = arg_get_lit(4);
    bool decodeTLV = arg_get_lit(5);
    EMVCommandChannel channel = ECC_CONTACTLESS;
    if (arg_get_lit(6))
        channel = ECC_CONTACT;
    PrintChannel(channel);
    CLIGetHexWithReturn(7, data, &datalen);
    CLIParserFree();

    SetAPDULogging(APDULogging);

    // Init TLV tree
    const char *alr = "Root terminal TLV tree";
    struct tlvdb *tlvRoot = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);

    // calc PDOL
    struct tlv *pdol_data_tlv = NULL;
    struct tlvdb *tmp_ext = NULL;
    struct tlv data_tlv = {
        .tag = 0x83,
        .len = datalen,
        .value = (uint8_t *)data,
    };
    if (dataMakeFromPDOL) {
        ParamLoadDefaults(tlvRoot);

        if (paramsLoadFromFile) {
            PrintAndLogEx(INFO, "Params loading from file...");
            ParamLoadFromJson(tlvRoot);
        };

        tmp_ext = tlvdb_external(0x9f38, datalen, data);
        pdol_data_tlv = dol_process((const struct tlv *)tmp_ext, tlvRoot, 0x83);
        if (!pdol_data_tlv) {
            PrintAndLogEx(ERR, "Can't create PDOL TLV.");
            tlvdb_free(tmp_ext);
            tlvdb_free(tlvRoot);
            return PM3_ESOFT;
        }
    } else {
        if (paramsLoadFromFile) {
            PrintAndLogEx(WARNING, "Don't need to load parameters. Sending plain PDOL data...");
        }
        pdol_data_tlv = &data_tlv;
    }

    size_t pdol_data_tlv_data_len = 0;
    unsigned char *pdol_data_tlv_data = tlv_encode(pdol_data_tlv, &pdol_data_tlv_data_len);
    if (!pdol_data_tlv_data) {
        PrintAndLogEx(ERR, "Can't create PDOL data.");
        tlvdb_free(tmp_ext);
        tlvdb_free(tlvRoot);
        if (pdol_data_tlv != &data_tlv);
        free(pdol_data_tlv);
        return PM3_ESOFT;
    }
    PrintAndLogEx(INFO, "PDOL data[%d]: %s", pdol_data_tlv_data_len, sprint_hex(pdol_data_tlv_data, pdol_data_tlv_data_len));

    // exec
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = EMVGPO(channel, leaveSignalON, pdol_data_tlv_data, pdol_data_tlv_data_len, buf, sizeof(buf), &len, &sw, tlvRoot);

    if (pdol_data_tlv != &data_tlv)
        free(pdol_data_tlv);

    tlvdb_free(tmp_ext);
    tlvdb_free(tlvRoot);

    if (sw)
        PrintAndLogEx(INFO, "APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));

    if (res)
        return res;

    if (decodeTLV)
        TLVPrintFromBuffer(buf, len);

    return PM3_SUCCESS;
}

static int CmdEMVReadRecord(const char *Cmd) {
    uint8_t data[APDU_RES_LEN] = {0};
    int datalen = 0;

    CLIParserInit("emv readrec",
                  "Executes Read Record command. It returns data in TLV format.\nNeeds a bank applet to be selected and sometimes needs GPO to be executed.",
                  "Usage:\n\temv readrec -k 0101 -> read file SFI=01, SFIrec=01\n\temv readrec -kt 0201-> read file 0201 and show result in TLV\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("kK",  "keep",    "keep field ON for next command"),
        arg_lit0("aA",  "apdu",    "show APDU reqests and responses"),
        arg_lit0("tT",  "tlv",     "TLV decode results of selected applets"),
        arg_lit0("wW",  "wired",   "Send data via contact (iso7816) interface. Contactless interface set by default."),
        arg_strx1(NULL,  NULL,     "<SFI 1byte HEX><SFIrecord 1byte HEX>", NULL),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, true);

    bool leaveSignalON = arg_get_lit(1);
    bool APDULogging = arg_get_lit(2);
    bool decodeTLV = arg_get_lit(3);
    EMVCommandChannel channel = ECC_CONTACTLESS;
    if (arg_get_lit(4))
        channel = ECC_CONTACT;
    PrintChannel(channel);
    CLIGetHexWithReturn(5, data, &datalen);
    CLIParserFree();

    if (datalen != 2) {
        PrintAndLogEx(ERR, "Command needs to have 2 bytes of data");
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);

    // exec
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = EMVReadRecord(channel, leaveSignalON, data[0], data[1], buf, sizeof(buf), &len, &sw, NULL);

    if (sw)
        PrintAndLogEx(INFO, "APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));

    if (res)
        return res;


    if (decodeTLV)
        TLVPrintFromBuffer(buf, len);

    return PM3_SUCCESS;
}

static int CmdEMVAC(const char *Cmd) {
    uint8_t data[APDU_RES_LEN] = {0};
    int datalen = 0;

    CLIParserInit("emv genac",
                  "Generate Application Cryptogram command. It returns data in TLV format .\nNeeds a EMV applet to be selected and GPO to be executed.",
                  "Usage:\n\temv genac -k 0102 -> generate AC with 2-byte CDOLdata and keep field ON after command\n"
                  "\temv genac -t 01020304 -> generate AC with 4-byte CDOL data, show result in TLV\n"
                  "\temv genac -Daac 01020304 -> generate AC with 4-byte CDOL data and terminal decision 'declined'\n"
                  "\temv genac -pmt 9F 37 04 -> load params from file, make CDOL data from CDOL, generate AC with CDOL, show result in TLV");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("kK",  "keep",     "keep field ON for next command"),
        arg_lit0("cC",  "cda",      "executes CDA transaction. Needs to get SDAD in results."),
        arg_str0("dD",  "decision", "<aac|tc|arqc>", "Terminal decision. aac - declined, tc - approved, arqc - online authorisation requested"),
        arg_lit0("pP",  "params",   "load parameters from `emv/defparams.json` file for CDOLdata making from CDOL and parameters"),
        arg_lit0("mM",  "make",     "make CDOLdata from CDOL (tag 8C and 8D) and parameters (by default uses default parameters)"),
        arg_lit0("aA",  "apdu",     "show APDU reqests and responses"),
        arg_lit0("tT",  "tlv",      "TLV decode results of selected applets"),
        arg_lit0("wW",  "wired",   "Send data via contact (iso7816) interface. Contactless interface set by default."),
        arg_strx1(NULL,  NULL,      "<HEX CDOLdata/CDOL>", NULL),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, false);

    bool leaveSignalON = arg_get_lit(1);
    bool trTypeCDA = arg_get_lit(2);
    uint8_t termDecision = 0xff;
    if (arg_get_str_len(3)) {
        if (!strncmp(arg_get_str(3)->sval[0], "aac", 4))
            termDecision = EMVAC_AAC;
        if (!strncmp(arg_get_str(3)->sval[0], "tc", 4))
            termDecision = EMVAC_TC;
        if (!strncmp(arg_get_str(3)->sval[0], "arqc", 4))
            termDecision = EMVAC_ARQC;

        if (termDecision == 0xff) {
            PrintAndLogEx(ERR, "ERROR: can't find terminal decision '%s'", arg_get_str(3)->sval[0]);
            return PM3_EINVARG;
        }
    } else {
        termDecision = EMVAC_TC;
    }
    if (trTypeCDA)
        termDecision = termDecision | EMVAC_CDAREQ;
    bool paramsLoadFromFile = arg_get_lit(4);
    bool dataMakeFromCDOL = arg_get_lit(5);
    bool APDULogging = arg_get_lit(6);
    bool decodeTLV = arg_get_lit(7);
    EMVCommandChannel channel = ECC_CONTACTLESS;
    if (arg_get_lit(8))
        channel = ECC_CONTACT;
    PrintChannel(channel);
    CLIGetHexWithReturn(9, data, &datalen);
    CLIParserFree();

    SetAPDULogging(APDULogging);

    // Init TLV tree
    const char *alr = "Root terminal TLV tree";
    struct tlvdb *tlvRoot = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);

    // calc CDOL
    struct tlv *cdol_data_tlv = NULL;
    struct tlvdb *tmp_ext = NULL;
    struct tlv data_tlv = {
        .tag = 0x01,
        .len = datalen,
        .value = (uint8_t *)data,
    };

    if (dataMakeFromCDOL) {
        ParamLoadDefaults(tlvRoot);

        if (paramsLoadFromFile) {
            PrintAndLogEx(INFO, "Params loading from file...");
            ParamLoadFromJson(tlvRoot);
        };

        tmp_ext = tlvdb_external(0x8c, datalen, data);
        cdol_data_tlv = dol_process((const struct tlv *)tmp_ext, tlvRoot, 0x01); // 0x01 - dummy tag
        if (!cdol_data_tlv) {
            PrintAndLogEx(ERR, "Can't create CDOL TLV.");
            tlvdb_free(tmp_ext);
            tlvdb_free(tlvRoot);
            return PM3_ESOFT;
        }
    } else {
        if (paramsLoadFromFile) {
            PrintAndLogEx(WARNING, "Don't need to load parameters. Sending plain CDOL data...");
        }
        cdol_data_tlv = &data_tlv;
    }

    PrintAndLogEx(INFO, "CDOL data[%d]: %s", cdol_data_tlv->len, sprint_hex(cdol_data_tlv->value, cdol_data_tlv->len));

    // exec
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = EMVAC(channel, leaveSignalON, termDecision, (uint8_t *)cdol_data_tlv->value, cdol_data_tlv->len, buf, sizeof(buf), &len, &sw, tlvRoot);

    if (cdol_data_tlv != &data_tlv)
        free(cdol_data_tlv);

    tlvdb_free(tmp_ext);
    tlvdb_free(tlvRoot);

    if (sw)
        PrintAndLogEx(INFO, "APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));

    if (res)
        return res;

    if (decodeTLV)
        TLVPrintFromBuffer(buf, len);

    return PM3_SUCCESS;
}

static int CmdEMVGenerateChallenge(const char *Cmd) {

    CLIParserInit("emv challenge",
                  "Executes Generate Challenge command. It returns 4 or 8-byte random number from card.\nNeeds a EMV applet to be selected and GPO to be executed.",
                  "Usage:\n\temv challenge -> get challenge\n\temv challenge -k -> get challenge, keep fileld ON\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("kK",  "keep",    "keep field ON for next command"),
        arg_lit0("aA",  "apdu",    "show APDU reqests and responses"),
        arg_lit0("wW",  "wired",   "Send data via contact (iso7816) interface. Contactless interface set by default."),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, true);

    bool leaveSignalON = arg_get_lit(1);
    bool APDULogging = arg_get_lit(2);
    EMVCommandChannel channel = ECC_CONTACTLESS;
    if (arg_get_lit(3))
        channel = ECC_CONTACT;
    PrintChannel(channel);
    CLIParserFree();

    SetAPDULogging(APDULogging);

    // exec
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = EMVGenerateChallenge(channel, leaveSignalON, buf, sizeof(buf), &len, &sw, NULL);

    if (sw)
        PrintAndLogEx(INFO, "APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));

    if (res)
        return res;

    PrintAndLogEx(SUCCESS, "Challenge: %s", sprint_hex(buf, len));

    if (len != 4 && len != 8)
        PrintAndLogEx(WARNING, "Length of challenge must be 4 or 8, but it %d", len);

    return PM3_SUCCESS;
}

static int CmdEMVInternalAuthenticate(const char *Cmd) {
    uint8_t data[APDU_RES_LEN] = {0};
    int datalen = 0;

    CLIParserInit("emv intauth",
                  "Generate Internal Authenticate command. Usually needs 4-byte random number. It returns data in TLV format .\n"
                  "Needs a EMV applet to be selected and GPO to be executed.",

                  "Usage:\n"
                  "\temv intauth -k 01020304 -> execute Internal Authenticate with 4-byte DDOLdata and keep field ON after command\n"
                  "\temv intauth -t 01020304 -> execute Internal Authenticate with 4-byte DDOL data, show result in TLV\n"
                  "\temv intauth -pmt 9F 37 04 -> load params from file, make DDOL data from DDOL, Internal Authenticate with DDOL, show result in TLV");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("kK",  "keep",    "keep field ON for next command"),
        arg_lit0("pP",  "params",  "load parameters from `emv/defparams.json` file for DDOLdata making from DDOL and parameters"),
        arg_lit0("mM",  "make",    "make DDOLdata from DDOL (tag 9F49) and parameters (by default uses default parameters)"),
        arg_lit0("aA",  "apdu",    "show APDU reqests and responses"),
        arg_lit0("tT",  "tlv",     "TLV decode results of selected applets"),
        arg_lit0("wW",  "wired",   "Send data via contact (iso7816) interface. Contactless interface set by default."),
        arg_strx1(NULL,  NULL,     "<HEX DDOLdata/DDOL>", NULL),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, false);

    bool leaveSignalON = arg_get_lit(1);
    bool paramsLoadFromFile = arg_get_lit(2);
    bool dataMakeFromDDOL = arg_get_lit(3);
    bool APDULogging = arg_get_lit(4);
    bool decodeTLV = arg_get_lit(5);
    EMVCommandChannel channel = ECC_CONTACTLESS;
    if (arg_get_lit(6))
        channel = ECC_CONTACT;
    PrintChannel(channel);
    CLIGetHexWithReturn(7, data, &datalen);
    CLIParserFree();

    SetAPDULogging(APDULogging);

    // Init TLV tree
    const char *alr = "Root terminal TLV tree";
    struct tlvdb *tlvRoot = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);

    // calc DDOL
    struct tlv *ddol_data_tlv = NULL;
    struct tlvdb *tmp_ext = NULL;
    struct tlv data_tlv = {
        .tag = 0x01,
        .len = datalen,
        .value = (uint8_t *)data,
    };

    if (dataMakeFromDDOL) {
        ParamLoadDefaults(tlvRoot);

        if (paramsLoadFromFile) {
            PrintAndLogEx(INFO, "Params loading from file...");
            ParamLoadFromJson(tlvRoot);
        };

        tmp_ext = tlvdb_external(0x9f49, datalen, data);
        ddol_data_tlv = dol_process((const struct tlv *)tmp_ext, tlvRoot, 0x01); // 0x01 - dummy tag
        if (!ddol_data_tlv) {
            PrintAndLogEx(ERR, "Can't create DDOL TLV.");
            tlvdb_free(tmp_ext);
            tlvdb_free(tlvRoot);
            return PM3_ESOFT;
        }
    } else {
        if (paramsLoadFromFile) {
            PrintAndLogEx(WARNING, "Don't need to load parameters. Sending plain DDOL data...");
        }
        ddol_data_tlv = &data_tlv;
    }

    PrintAndLogEx(INFO, "DDOL data[%d]: %s", ddol_data_tlv->len, sprint_hex(ddol_data_tlv->value, ddol_data_tlv->len));

    // exec
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = EMVInternalAuthenticate(channel, leaveSignalON, data, datalen, buf, sizeof(buf), &len, &sw, NULL);

    if (ddol_data_tlv != &data_tlv)
        free(ddol_data_tlv);

    tlvdb_free(tmp_ext);
    tlvdb_free(tlvRoot);

    if (sw)
        PrintAndLogEx(INFO, "APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));

    if (res)
        return res;

    if (decodeTLV)
        TLVPrintFromBuffer(buf, len);

    return PM3_SUCCESS;
}

#define dreturn(n) {free(pdol_data_tlv); tlvdb_free(tlvSelect); tlvdb_free(tlvRoot); DropFieldEx( channel ); return n;}

static void InitTransactionParameters(struct tlvdb *tlvRoot, bool paramLoadJSON, enum TransactionType TrType, bool GenACGPO) {

    ParamLoadDefaults(tlvRoot);

    if (paramLoadJSON) {
        PrintAndLogEx(INFO, "* * Transaction parameters loading from JSON...");
        ParamLoadFromJson(tlvRoot);
    }

    //9F66:(Terminal Transaction Qualifiers (TTQ)) len:4
    const char *qVSDC = "\x26\x00\x00\x00";
    if (GenACGPO) {
        qVSDC = "\x26\x80\x00\x00";
    }
    switch (TrType) {
        case TT_MSD:
            TLV_ADD(0x9F66, "\x86\x00\x00\x00"); // MSD
            break;
        // not standard for contactless. just for test.
        case TT_VSDC:
            TLV_ADD(0x9F66, "\x46\x00\x00\x00"); // VSDC
            break;
        case TT_QVSDCMCHIP:
            TLV_ADD(0x9F66, qVSDC); // qVSDC
            break;
        case TT_CDA:
            TLV_ADD(0x9F66, qVSDC); // qVSDC (VISA CDA not enabled)
            break;
        default:
            break;
    }
}

static void ProcessGPOResponseFormat1(struct tlvdb *tlvRoot, uint8_t *buf, size_t len, bool decodeTLV) {
    if (buf[0] == 0x80) {
        if (decodeTLV) {
            PrintAndLogEx(SUCCESS, "GPO response format1:");
            TLVPrintFromBuffer(buf, len);
        }

        if (len < 4 || (len - 4) % 4) {
            PrintAndLogEx(ERR, "GPO response format 1 parsing error. length = %d", len);
        } else {
            // AIP
            struct tlvdb *f1AIP = tlvdb_fixed(0x82, 2, buf + 2);
            tlvdb_add(tlvRoot, f1AIP);
            if (decodeTLV) {
                PrintAndLogEx(INFO, "\n* * Decode response format 1 (0x80) AIP and AFL:");
                TLVPrintFromTLV(f1AIP);
            }

            // AFL
            struct tlvdb *f1AFL = tlvdb_fixed(0x94, len - 4, buf + 2 + 2);
            tlvdb_add(tlvRoot, f1AFL);
            if (decodeTLV)
                TLVPrintFromTLV(f1AFL);
        }
    } else {
        if (decodeTLV)
            TLVPrintFromBuffer(buf, len);
    }
}

static void ProcessACResponseFormat1(struct tlvdb *tlvRoot, uint8_t *buf, size_t len, bool decodeTLV) {
    if (buf[0] == 0x80) {
        if (decodeTLV) {
            PrintAndLogEx(SUCCESS, "GPO response format 1:");
            TLVPrintFromBuffer(buf, len);
        }

        uint8_t elmlen = len - 2; // wo 0x80XX

        if (len < 4 + 2 || (elmlen - 2) % 4 || elmlen != buf[1]) {
            PrintAndLogEx(ERR, "GPO response format1 parsing error. length=%d", len);
        } else {
            struct tlvdb *tlvElm = NULL;
            if (decodeTLV)
                PrintAndLogEx(NORMAL, "\n------------ Format1 decoded ------------");

            // CID (Cryptogram Information Data)
            tlvdb_change_or_add_node_ex(tlvRoot, 0x9f27, 1, &buf[2], &tlvElm);
            if (decodeTLV)
                TLVPrintFromTLV(tlvElm);

            // ATC (Application Transaction Counter)
            tlvdb_change_or_add_node_ex(tlvRoot, 0x9f36, 2, &buf[3], &tlvElm);
            if (decodeTLV)
                TLVPrintFromTLV(tlvElm);

            // AC (Application Cryptogram)
            tlvdb_change_or_add_node_ex(tlvRoot, 0x9f26, MIN(8, elmlen - 3), &buf[5], &tlvElm);
            if (decodeTLV)
                TLVPrintFromTLV(tlvElm);

            // IAD (Issuer Application Data) - optional
            if (len > 11 + 2) {
                tlvdb_change_or_add_node_ex(tlvRoot, 0x9f10, elmlen - 11, &buf[13], &tlvElm);
                if (decodeTLV)
                    TLVPrintFromTLV(tlvElm);
            }
        }
    } else {
        if (decodeTLV)
            TLVPrintFromBuffer(buf, len);
    }
}

static int CmdEMVExec(const char *Cmd) {
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    uint8_t AID[APDU_AID_LEN] = {0};
    size_t AIDlen = 0;
    uint8_t ODAiList[4096];
    size_t ODAiListLen = 0;

    int res;

    struct tlvdb *tlvSelect = NULL;
    struct tlvdb *tlvRoot = NULL;
    struct tlv *pdol_data_tlv = NULL;

    CLIParserInit("emv exec",
                  "Executes EMV contactless transaction",
                  "Usage:\n"
                  "\temv exec -sat -> select card, execute MSD transaction, show APDU and TLV\n"
                  "\temv exec -satc -> select card, execute CDA transaction, show APDU and TLV\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("sS",  "select",   "activate field and select card."),
        arg_lit0("aA",  "apdu",     "show APDU reqests and responses."),
        arg_lit0("tT",  "tlv",      "TLV decode results."),
        arg_lit0("jJ",  "jload",    "Load transaction parameters from `emv/defparams.json` file."),
        arg_lit0("fF",  "forceaid", "Force search AID. Search AID instead of execute PPSE."),
        arg_rem("By default:",      "Transaction type - MSD"),
        arg_lit0("vV",  "qvsdc",    "Transaction type - qVSDC or M/Chip."),
        arg_lit0("cC",  "qvsdccda", "Transaction type - qVSDC or M/Chip plus CDA (SDAD generation)."),
        arg_lit0("xX",  "vsdc",     "Transaction type - VSDC. For test only. Not a standart behavior."),
        arg_lit0("gG",  "acgpo",    "VISA. generate AC from GPO."),
        arg_lit0("wW",  "wired",   "Send data via contact (iso7816) interface. Contactless interface set by default."),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, true);

    bool activateField = arg_get_lit(1);
    bool showAPDU = arg_get_lit(2);
    bool decodeTLV = arg_get_lit(3);
    bool paramLoadJSON = arg_get_lit(4);
    bool forceSearch = arg_get_lit(5);

    enum TransactionType TrType = TT_MSD;
    if (arg_get_lit(7))
        TrType = TT_QVSDCMCHIP;
    if (arg_get_lit(8))
        TrType = TT_CDA;
    if (arg_get_lit(9))
        TrType = TT_VSDC;

    bool GenACGPO = arg_get_lit(10);
    EMVCommandChannel channel = ECC_CONTACTLESS;
    if (arg_get_lit(11))
        channel = ECC_CONTACT;
    PrintChannel(channel);
    uint8_t psenum = (channel == ECC_CONTACT) ? 1 : 2;
    CLIParserFree();

    if (!IfPm3Smartcard()) {
        if (channel == ECC_CONTACT) {
            PrintAndLogEx(WARNING, "PM3 does not have SMARTCARD support. Exiting.");
            return PM3_EDEVNOTSUPP;
        }
    }

    SetAPDULogging(showAPDU);

    // init applets list tree
    const char *al = "Applets list";
    tlvSelect = tlvdb_fixed(1, strlen(al), (const unsigned char *)al);

    // Application Selection
    // https://www.openscdp.org/scripts/tutorial/emv/applicationselection.html
    if (!forceSearch) {
        // PPSE
        PrintAndLogEx(NORMAL, "\n* PPSE.");
        SetAPDULogging(showAPDU);
        res = EMVSearchPSE(channel, activateField, true, psenum, decodeTLV, tlvSelect);

        // check PPSE and select application id
        if (!res) {
            TLVPrintAIDlistFromSelectTLV(tlvSelect);
            EMVSelectApplication(tlvSelect, AID, &AIDlen);
        }
    }

    // Search
    if (!AIDlen) {
        PrintAndLogEx(NORMAL, "\n* Search AID in list.");
        SetAPDULogging(false);
        if (EMVSearch(channel, activateField, true, decodeTLV, tlvSelect)) {
            dreturn(PM3_ERFTRANS);
        }

        // check search and select application id
        TLVPrintAIDlistFromSelectTLV(tlvSelect);
        EMVSelectApplication(tlvSelect, AID, &AIDlen);
    }

    // Init TLV tree
    const char *alr = "Root terminal TLV tree";
    tlvRoot = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);

    // check if we found EMV application on card
    if (!AIDlen) {
        PrintAndLogEx(WARNING, "Can't select AID. EMV AID not found");
        dreturn(PM3_ERFTRANS);
    }

    // Select
    PrintAndLogEx(NORMAL, "\n* Selecting AID:%s", sprint_hex_inrow(AID, AIDlen));
    SetAPDULogging(showAPDU);
    res = EMVSelect(channel, false, true, AID, AIDlen, buf, sizeof(buf), &len, &sw, tlvRoot);

    if (res) {
        PrintAndLogEx(WARNING, "Can't select AID (%d). Exit...", res);
        dreturn(PM3_ERFTRANS);
    }

    if (decodeTLV)
        TLVPrintFromBuffer(buf, len);
    PrintAndLogEx(NORMAL, "* Selected.");

    PrintAndLogEx(NORMAL, "\n* Init transaction parameters.");
    InitTransactionParameters(tlvRoot, paramLoadJSON, TrType, GenACGPO);
    TLVPrintFromTLV(tlvRoot); // TODO delete!!!

    PrintAndLogEx(NORMAL, "\n* Calc PDOL.");
    pdol_data_tlv = dol_process(tlvdb_get(tlvRoot, 0x9f38, NULL), tlvRoot, 0x83);
    if (!pdol_data_tlv) {
        PrintAndLogEx(ERR, "Error: can't create PDOL TLV.");
        dreturn(PM3_ESOFT);
    }

    size_t pdol_data_tlv_data_len;
    unsigned char *pdol_data_tlv_data = tlv_encode(pdol_data_tlv, &pdol_data_tlv_data_len);
    if (!pdol_data_tlv_data) {
        PrintAndLogEx(ERR, "Error: can't create PDOL data.");
        dreturn(PM3_ESOFT);
    }
    PrintAndLogEx(NORMAL, "PDOL data[%d]: %s", pdol_data_tlv_data_len, sprint_hex(pdol_data_tlv_data, pdol_data_tlv_data_len));

    PrintAndLogEx(NORMAL, "\n* GPO.");
    res = EMVGPO(channel, true, pdol_data_tlv_data, pdol_data_tlv_data_len, buf, sizeof(buf), &len, &sw, tlvRoot);

    free(pdol_data_tlv_data);
    //free(pdol_data_tlv); --- free on exit.

    if (res) {
        PrintAndLogEx(ERR, "GPO error(%d): %4x. Exit...", res, sw);
        dreturn(PM3_ERFTRANS);
    }

    // process response template format 1 [id:80  2b AIP + x4b AFL] and format 2 [id:77 TLV]
    ProcessGPOResponseFormat1(tlvRoot, buf, len, decodeTLV);

    // extract PAN from track2
    {
        const struct tlv *track2 = tlvdb_get(tlvRoot, 0x57, NULL);
        if (!tlvdb_get(tlvRoot, 0x5a, NULL) && track2 && track2->len >= 8) {
            struct tlvdb *pan = GetPANFromTrack2(track2);
            if (pan) {
                tlvdb_add(tlvRoot, pan);

                const struct tlv *pantlv = tlvdb_get(tlvRoot, 0x5a, NULL);
                PrintAndLogEx(NORMAL, "\n* * Extracted PAN from track2: %s", sprint_hex(pantlv->value, pantlv->len));
            } else {
                PrintAndLogEx(WARNING, "\n* * WARNING: Can't extract PAN from track2.");
            }
        }
    }

    PrintAndLogEx(NORMAL, "\n* Read records from AFL.");
    const struct tlv *AFL = tlvdb_get(tlvRoot, 0x94, NULL);

    if (!AFL || !AFL->len)
        PrintAndLogEx(WARNING, "WARNING: AFL not found.");

    while (AFL && AFL->len) {
        if (AFL->len % 4) {
            PrintAndLogEx(WARNING, "Error: Wrong AFL length: %d", AFL->len);
            break;
        }

        for (int i = 0; i < AFL->len / 4; i++) {
            uint8_t SFI = AFL->value[i * 4 + 0] >> 3;
            uint8_t SFIstart = AFL->value[i * 4 + 1];
            uint8_t SFIend = AFL->value[i * 4 + 2];
            uint8_t SFIoffline = AFL->value[i * 4 + 3];

            PrintAndLogEx(NORMAL, "* * SFI[%02x] start:%02x end:%02x offline count:%02x", SFI, SFIstart, SFIend, SFIoffline);
            if (SFI == 0 || SFI == 31 || SFIstart == 0 || SFIstart > SFIend) {
                PrintAndLogEx(NORMAL, "SFI ERROR! Skipped...");
                continue;
            }

            for (int n = SFIstart; n <= SFIend; n++) {
                PrintAndLogEx(NORMAL, "* * * SFI[%02x] %d", SFI, n);

                res = EMVReadRecord(channel, true, SFI, n, buf, sizeof(buf), &len, &sw, tlvRoot);
                if (res) {
                    PrintAndLogEx(WARNING, "Error SFI[%02x]. APDU error %4x", SFI, sw);
                    continue;
                }

                if (decodeTLV) {
                    TLVPrintFromBuffer(buf, len);
                    PrintAndLogEx(NORMAL, "");
                }

                // Build Input list for Offline Data Authentication
                // EMV 4.3 book3 10.3, page 96
                if (SFIoffline > 0) {
                    if (SFI < 11) {
                        const unsigned char *abuf = buf;
                        size_t elmlen = len;
                        struct tlv e;
                        if (tlv_parse_tl(&abuf, &elmlen, &e)) {
                            memcpy(&ODAiList[ODAiListLen], &buf[len - elmlen], elmlen);
                            ODAiListLen += elmlen;
                        } else {
                            PrintAndLogEx(WARNING, "Error SFI[%02x]. Creating input list for Offline Data Authentication error.", SFI);
                        }
                    } else {
                        memcpy(&ODAiList[ODAiListLen], buf, len);
                        ODAiListLen += len;
                    }

                    SFIoffline--;
                }
            }
        }

        break;
    }

    // copy Input list for Offline Data Authentication
    if (ODAiListLen) {
        struct tlvdb *oda = tlvdb_fixed(0x21, ODAiListLen, ODAiList); // not a standard tag
        tlvdb_add(tlvRoot, oda);
        PrintAndLogEx(NORMAL, "* Input list for Offline Data Authentication added to TLV. len=%d \n", ODAiListLen);
    }

    // get AIP
    uint16_t AIP = 0;
    const struct tlv *AIPtlv = tlvdb_get(tlvRoot, 0x82, NULL);
    if (AIPtlv) {
        AIP = AIPtlv->value[0] + AIPtlv->value[1] * 0x100;
        PrintAndLogEx(NORMAL, "* * AIP=%04x", AIP);
    } else {
        PrintAndLogEx(ERR, "Can't found AIP.");
    }

    // SDA
    if (AIP & 0x0040) {
        PrintAndLogEx(NORMAL, "\n* SDA");
        trSDA(tlvRoot);
    }

    // DDA
    if (AIP & 0x0020) {
        PrintAndLogEx(NORMAL, "\n* DDA");
        trDDA(channel, decodeTLV, tlvRoot);
    }

    // transaction check

    // qVSDC
    if (TrType == TT_QVSDCMCHIP || TrType == TT_CDA) {
        // 9F26: Application Cryptogram
        const struct tlv *AC = tlvdb_get(tlvRoot, 0x9F26, NULL);
        if (AC) {
            PrintAndLogEx(NORMAL, "\n--> qVSDC transaction.");
            PrintAndLogEx(NORMAL, "* AC path");

            // 9F36: Application Transaction Counter (ATC)
            const struct tlv *ATC = tlvdb_get(tlvRoot, 0x9F36, NULL);
            if (ATC) {

                // 9F10: Issuer Application Data - optional
                const struct tlv *IAD = tlvdb_get(tlvRoot, 0x9F10, NULL);

                // print AC data
                PrintAndLogEx(NORMAL, "ATC: %s", sprint_hex(ATC->value, ATC->len));
                PrintAndLogEx(NORMAL, "AC: %s", sprint_hex(AC->value, AC->len));
                if (IAD) {
                    PrintAndLogEx(NORMAL, "IAD: %s", sprint_hex(IAD->value, IAD->len));

                    if (IAD->len >= IAD->value[0] + 1) {
                        PrintAndLogEx(NORMAL, "\tKey index:  0x%02x", IAD->value[1]);
                        PrintAndLogEx(NORMAL, "\tCrypto ver: 0x%02x(%03d)", IAD->value[2], IAD->value[2]);
                        PrintAndLogEx(NORMAL, "\tCVR:", sprint_hex(&IAD->value[3], IAD->value[0] - 2));
                        struct tlvdb *cvr = tlvdb_fixed(0x20, IAD->value[0] - 2, &IAD->value[3]);
                        TLVPrintFromTLVLev(cvr, 1);
                    }
                } else {
                    PrintAndLogEx(NORMAL, "WARNING: IAD not found.");
                }

            } else {
                PrintAndLogEx(WARNING, "Error AC: Application Transaction Counter (ATC) not found.");
            }
        }
    }

    // Mastercard M/CHIP
    if (GetCardPSVendor(AID, AIDlen) == CV_MASTERCARD && (TrType == TT_QVSDCMCHIP || TrType == TT_CDA)) {
        const struct tlv *CDOL1 = tlvdb_get(tlvRoot, 0x8c, NULL);
        if (CDOL1 && GetCardPSVendor(AID, AIDlen) == CV_MASTERCARD) { // and m/chip transaction flag
            PrintAndLogEx(NORMAL, "\n--> Mastercard M/Chip transaction.");

            PrintAndLogEx(NORMAL, "* * Generate challenge");
            res = EMVGenerateChallenge(channel, true, buf, sizeof(buf), &len, &sw, tlvRoot);
            if (res) {
                PrintAndLogEx(ERR, "Error GetChallenge. APDU error %4x", sw);
                dreturn(PM3_ERFTRANS);
            }
            if (len < 4) {
                PrintAndLogEx(ERR, "Error GetChallenge. Wrong challenge length %d", len);
                dreturn(PM3_ESOFT);
            }

            // ICC Dynamic Number
            struct tlvdb *ICCDynN = tlvdb_fixed(0x9f4c, len, buf);
            tlvdb_add(tlvRoot, ICCDynN);
            if (decodeTLV) {
                PrintAndLogEx(NORMAL, "\n* * ICC Dynamic Number:");
                TLVPrintFromTLV(ICCDynN);
            }

            PrintAndLogEx(NORMAL, "* * Calc CDOL1");
            struct tlv *cdol_data_tlv = dol_process(tlvdb_get(tlvRoot, 0x8c, NULL), tlvRoot, 0x01); // 0x01 - dummy tag
            if (!cdol_data_tlv) {
                PrintAndLogEx(ERR, "Error: can't create CDOL1 TLV.");
                dreturn(PM3_ESOFT);
            }

            PrintAndLogEx(NORMAL, "CDOL1 data[%d]: %s", cdol_data_tlv->len, sprint_hex(cdol_data_tlv->value, cdol_data_tlv->len));

            PrintAndLogEx(NORMAL, "* * AC1");
            // EMVAC_TC + EMVAC_CDAREQ --- to get SDAD
            res = EMVAC(channel, true, (TrType == TT_CDA) ? EMVAC_TC + EMVAC_CDAREQ : EMVAC_TC, (uint8_t *)cdol_data_tlv->value, cdol_data_tlv->len, buf, sizeof(buf), &len, &sw, tlvRoot);

            if (res) {
                PrintAndLogEx(ERR, "AC1 error(%d): %4x. Exit...", res, sw);
                dreturn(PM3_ERFTRANS);
            }

            if (decodeTLV)
                TLVPrintFromBuffer(buf, len);

            // CDA
            PrintAndLogEx(NORMAL, "\n* CDA:");
            struct tlvdb *ac_tlv = tlvdb_parse_multi(buf, len);
            res = trCDA(tlvRoot, ac_tlv, pdol_data_tlv, cdol_data_tlv);
            if (res) {
                PrintAndLogEx(NORMAL, "CDA error (%d)", res);
            }

            free(ac_tlv);
            free(cdol_data_tlv);

            PrintAndLogEx(NORMAL, "\n* M/Chip transaction result:");
            // 9F27: Cryptogram Information Data (CID)
            const struct tlv *CID = tlvdb_get(tlvRoot, 0x9F27, NULL);
            if (CID) {
                emv_tag_dump(CID, stdout, 0);
                PrintAndLogEx(NORMAL, "------------------------------");
                if (CID->len > 0) {
                    switch (CID->value[0] & EMVAC_AC_MASK) {
                        case EMVAC_AAC:
                            PrintAndLogEx(NORMAL, "Transaction DECLINED.");
                            break;
                        case EMVAC_TC:
                            PrintAndLogEx(NORMAL, "Transaction approved OFFLINE.");
                            break;
                        case EMVAC_ARQC:
                            PrintAndLogEx(NORMAL, "Transaction approved ONLINE.");
                            break;
                        default:
                            PrintAndLogEx(WARNING, "Error: CID transaction code error %2x", CID->value[0] & EMVAC_AC_MASK);
                            break;
                    }
                } else {
                    PrintAndLogEx(WARNING, "Error: Wrong CID length %d", CID->len);
                }
            } else {
                PrintAndLogEx(WARNING, "Error: CID(9F27) not found.");
            }

        }
    }

    // MSD
    if (AIP & 0x8000 && TrType == TT_MSD) {
        PrintAndLogEx(NORMAL, "\n--> MSD transaction.");

        PrintAndLogEx(NORMAL, "* MSD dCVV path. Check dCVV");

        const struct tlv *track2 = tlvdb_get(tlvRoot, 0x57, NULL);
        if (track2) {
            PrintAndLogEx(NORMAL, "Track2: %s", sprint_hex(track2->value, track2->len));

            struct tlvdb *dCVV = GetdCVVRawFromTrack2(track2);
            PrintAndLogEx(NORMAL, "dCVV raw data:");
            TLVPrintFromTLV(dCVV);

            if (GetCardPSVendor(AID, AIDlen) == CV_MASTERCARD) {
                PrintAndLogEx(NORMAL, "\n* Mastercard calculate UDOL");

                // UDOL (9F69)
                const struct tlv *UDOL = tlvdb_get(tlvRoot, 0x9F69, NULL);
                // UDOL(9F69) default: 9F6A (Unpredictable number) 4 bytes
                const struct tlv defUDOL = {
                    .tag = 0x01,
                    .len = 3,
                    .value = (uint8_t *)"\x9f\x6a\x04",
                };
                if (!UDOL)
                    PrintAndLogEx(NORMAL, "Use default UDOL.");

                struct tlv *udol_data_tlv = dol_process(UDOL ? UDOL : &defUDOL, tlvRoot, 0x01); // 0x01 - dummy tag
                if (!udol_data_tlv) {
                    PrintAndLogEx(ERR, "Error: can't create UDOL TLV.");
                    dreturn(PM3_ESOFT);
                }

                PrintAndLogEx(NORMAL, "UDOL data[%d]: %s", udol_data_tlv->len, sprint_hex(udol_data_tlv->value, udol_data_tlv->len));

                PrintAndLogEx(NORMAL, "\n* Mastercard compute cryptographic checksum(UDOL)");

                res = MSCComputeCryptoChecksum(channel, true, (uint8_t *)udol_data_tlv->value, udol_data_tlv->len, buf, sizeof(buf), &len, &sw, tlvRoot);
                if (res) {
                    PrintAndLogEx(ERR, "Error Compute Crypto Checksum. APDU error %4x", sw);
                    free(udol_data_tlv);
                    dreturn(PM3_ESOFT);
                }

                // Mastercard compute cryptographic checksum result
                TLVPrintFromBuffer(buf, len);
                PrintAndLogEx(NORMAL, "");

                free(udol_data_tlv);

            }
        } else {
            PrintAndLogEx(ERR, "Error MSD: Track2 data not found.");
        }
    }

    // VSDC
    if (GetCardPSVendor(AID, AIDlen) == CV_VISA && (TrType == TT_VSDC || TrType == TT_CDA)) {
        PrintAndLogEx(NORMAL, "\n--> VSDC transaction.");

        PrintAndLogEx(NORMAL, "* * Calc CDOL1");
        struct tlv *cdol1_data_tlv = dol_process(tlvdb_get(tlvRoot, 0x8c, NULL), tlvRoot, 0x01); // 0x01 - dummy tag
        if (!cdol1_data_tlv) {
            PrintAndLogEx(ERR, "Error: can't create CDOL1 TLV.");
            dreturn(PM3_ESOFT);
        }

        PrintAndLogEx(NORMAL, "CDOL1 data[%d]: %s", cdol1_data_tlv->len, sprint_hex(cdol1_data_tlv->value, cdol1_data_tlv->len));

        PrintAndLogEx(NORMAL, "* * AC1");
        // EMVAC_TC + EMVAC_CDAREQ --- to get SDAD
        res = EMVAC(channel, true, (TrType == TT_CDA) ? EMVAC_TC + EMVAC_CDAREQ : EMVAC_TC, (uint8_t *)cdol1_data_tlv->value, cdol1_data_tlv->len, buf, sizeof(buf), &len, &sw, tlvRoot);

        if (res) {
            PrintAndLogEx(ERR, "AC1 error(%d): %4x. Exit...", res, sw);
            free(cdol1_data_tlv);
            dreturn(PM3_ERFTRANS);
        }

        // process Format1 (0x80) and print Format2 (0x77)
        ProcessACResponseFormat1(tlvRoot, buf, len, decodeTLV);

        uint8_t CID = 0;
        tlvdb_get_uint8(tlvRoot, 0x9f27, &CID);

        // AC1 print result
        PrintAndLogEx(NORMAL, "");
        if ((CID & EMVAC_AC_MASK) == EMVAC_AAC)     PrintAndLogEx(INFO, "AC1 result: AAC (Transaction declined)");
        if ((CID & EMVAC_AC_MASK) == EMVAC_TC)      PrintAndLogEx(INFO, "AC1 result: TC (Transaction approved)");
        if ((CID & EMVAC_AC_MASK) == EMVAC_ARQC)    PrintAndLogEx(INFO, "AC1 result: ARQC (Online authorisation requested)");
        if ((CID & EMVAC_AC_MASK) == EMVAC_AC_MASK) PrintAndLogEx(INFO, "AC1 result: RFU");

        // decode Issuer Application Data (IAD)
        uint8_t CryptoVersion = 0;
        const struct tlv *IAD = tlvdb_get(tlvRoot, 0x9f10, NULL);
        if (IAD && (IAD->len > 1)) {
            PrintAndLogEx(NORMAL, "\n* * Issuer Application Data (IAD):");
            uint8_t VDDlen = IAD->value[0]; // Visa discretionary data length
            uint8_t IDDlen = 0;             // Issuer discretionary data length
            PrintAndLogEx(NORMAL, "IAD length: %d", IAD->len);
            PrintAndLogEx(NORMAL, "VDDlen: %d", VDDlen);
            if (VDDlen < IAD->len - 1)
                IDDlen = IAD->value[VDDlen + 1];
            PrintAndLogEx(NORMAL, "IDDlen: %d", IDDlen);

            uint8_t DerivKeyIndex = IAD->value[1];
            CryptoVersion = IAD->value[2];

            PrintAndLogEx(NORMAL, "CryptoVersion: %d", CryptoVersion);
            PrintAndLogEx(NORMAL, "DerivKeyIndex: %d", DerivKeyIndex);

            // Card Verification Results (CVR) decode
            if ((VDDlen - 2) > 0) {
                uint8_t CVRlen = IAD->value[3];
                if (CVRlen == (VDDlen - 2 - 1)) {
                    PrintAndLogEx(NORMAL, "CVR length: %d", CVRlen);
                    PrintAndLogEx(NORMAL, "CVR: %s", sprint_hex(&IAD->value[4], CVRlen));
                } else {
                    PrintAndLogEx(WARNING, "Wrong CVR length! CVR: %s", sprint_hex(&IAD->value[3], VDDlen - 2));
                }
            }
            if (IDDlen)
                PrintAndLogEx(NORMAL, "IDD: %s", sprint_hex(&IAD->value[VDDlen + 1], IDDlen));
        } else {
            PrintAndLogEx(WARNING, "Issuer Application Data (IAD) not found.");
        }

        PrintAndLogEx(NORMAL, "\n* * Processing online request");

        // authorization response code from acquirer
        const char HostResponse[] = "00"; // 0x3030
        size_t HostResponseLen = sizeof(HostResponse) - 1;

        PrintAndLogEx(NORMAL, "Host Response: `%s`", HostResponse);

        tlvdb_change_or_add_node(tlvRoot, 0x8a, HostResponseLen, (const unsigned char *)HostResponse);

        if (CryptoVersion == 10) {
            PrintAndLogEx(NORMAL, "\n* * Generate ARPC");

            // Application Cryptogram (AC)
            const struct tlv *AC = tlvdb_get(tlvRoot, 0x9f26, NULL);
            if (AC && (AC->len > 0)) {
                PrintAndLogEx(NORMAL, "AC: %s", sprint_hex(AC->value, AC->len));

                size_t rawARPClen = AC->len;
                uint8_t rawARPC[rawARPClen];
                memcpy(rawARPC, AC->value, AC->len);
                for (int i = 0; (i < HostResponseLen) && (i < rawARPClen); i++)
                    rawARPC[i] ^= HostResponse[i];
                PrintAndLogEx(NORMAL, "raw ARPC: %s", sprint_hex(rawARPC, rawARPClen));

                // here must be calculation of ARPC, but we dont know a bank keys.
                PrintAndLogEx(NORMAL, "ARPC: n/a");

            } else {
                PrintAndLogEx(WARNING, "Application Cryptogram (AC) not found.");
            }
            // here must be external authenticate, but we dont know ARPC
        }

        // needs to send AC2 command (res == ARQC)
        if ((CID & EMVAC_AC_MASK) == EMVAC_ARQC) {
            PrintAndLogEx(NORMAL, "\n* * Calc CDOL2");
            struct tlv *cdol2_data_tlv = dol_process(tlvdb_get(tlvRoot, 0x8d, NULL), tlvRoot, 0x01); // 0x01 - dummy tag
            if (!cdol2_data_tlv) {
                PrintAndLogEx(ERR, "Error: can't create CDOL2 TLV.");
                dreturn(PM3_ESOFT);
            }

            PrintAndLogEx(NORMAL, "CDOL2 data[%d]: %s", cdol2_data_tlv->len, sprint_hex(cdol2_data_tlv->value, cdol2_data_tlv->len));
            //PrintAndLogEx(NORMAL, "* * AC2");
            // here must be AC2, but we dont make external authenticate (
            /*          // AC2
                        PRINT_INDENT(level);
                        if ((CID & EMVAC_AC2_MASK) == EMVAC_AAC2)     fprintf(f, "\tAC2: AAC (Transaction declined)\n");
                        if ((CID & EMVAC_AC2_MASK) == EMVAC_TC2)      fprintf(f, "\tAC2: TC (Transaction approved)\n");
                        if ((CID & EMVAC_AC2_MASK) == EMVAC_ARQC2)    fprintf(f, "\tAC2: not requested (ARQC)\n");
                        if ((CID & EMVAC_AC2_MASK) == EMVAC_AC2_MASK) fprintf(f, "\tAC2: RFU\n");
            */
        }
    }

    DropFieldEx(channel);

    // Destroy TLV's
    free(pdol_data_tlv);
    tlvdb_free(tlvSelect);
    tlvdb_free(tlvRoot);

    PrintAndLogEx(NORMAL, "\n* Transaction completed.");
    return PM3_SUCCESS;
}

static int CmdEMVScan(const char *Cmd) {
    uint8_t AID[APDU_AID_LEN] = {0};
    size_t AIDlen = 0;
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res;
    json_t *root;
    json_error_t error;

    CLIParserInit("emv scan",
                  "Scan EMV card and save it contents to a file.",
                  "It executes EMV contactless transaction and saves result to a file which can be used for emulation\n"
                  "Usage:\n\temv scan -at -> scan MSD transaction mode and show APDU and TLV\n"
                  "\temv scan -c -> scan CDA transaction mode\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("aA",  "apdu",     "show APDU reqests and responses."),
        arg_lit0("tT",  "tlv",      "TLV decode results."),
        arg_lit0("eE",  "extract",  "Extract TLV elements and fill Application Data"),
        arg_lit0("jJ",  "jload",    "Load transaction parameters from `emv/defparams.json` file."),
        arg_rem("By default:",      "Transaction type - MSD"),
        arg_lit0("vV",  "qvsdc",    "Transaction type - qVSDC or M/Chip."),
        arg_lit0("cC",  "qvsdccda", "Transaction type - qVSDC or M/Chip plus CDA (SDAD generation)."),
        arg_lit0("xX",  "vsdc",     "Transaction type - VSDC. For test only. Not a standart behavior."),
        arg_lit0("gG",  "acgpo",    "VISA. generate AC from GPO."),
        arg_lit0("mM",  "merge",    "Merge output file with card's data. (warning: the file may be corrupted!)"),
        arg_lit0("wW",  "wired",    "Send data via contact (iso7816) interface. Contactless interface set by default."),
        arg_str1(NULL,  NULL,       "output.json", "JSON output file name"),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, true);

    bool showAPDU = arg_get_lit(1);
    bool decodeTLV = arg_get_lit(2);
    bool extractTLVElements = arg_get_lit(3);
    bool paramLoadJSON = arg_get_lit(4);

    enum TransactionType TrType = TT_MSD;
    if (arg_get_lit(6))
        TrType = TT_QVSDCMCHIP;
    if (arg_get_lit(7))
        TrType = TT_CDA;
    if (arg_get_lit(8))
        TrType = TT_VSDC;

    bool GenACGPO = arg_get_lit(9);
    bool MergeJSON = arg_get_lit(10);
    EMVCommandChannel channel = ECC_CONTACTLESS;
    if (arg_get_lit(11))
        channel = ECC_CONTACT;
    PrintChannel(channel);
    uint8_t psenum = (channel == ECC_CONTACT) ? 1 : 2;
    uint8_t relfname[250] = {0};
    char *crelfname = (char *)relfname;
    int relfnamelen = 0;
    CLIGetStrWithReturn(12, relfname, &relfnamelen);
    CLIParserFree();

    if (!IfPm3Smartcard()) {
        if (channel == ECC_CONTACT) {
            PrintAndLogEx(WARNING, "PM3 does not have SMARTCARD support. Exiting.");
            return PM3_EDEVNOTSUPP;
        }
    }

    SetAPDULogging(showAPDU);

    // current path + file name
    if (!strstr(crelfname, ".json"))
        strcat(crelfname, ".json");
    char fname[strlen(get_my_executable_directory()) + strlen(crelfname) + 1];
    strcpy(fname, get_my_executable_directory());
    strcat(fname, crelfname);

    if (MergeJSON) {
        root = json_load_file(fname, 0, &error);
        if (!root) {
            PrintAndLogEx(ERR, "Json error on line %d: %s", error.line, error.text);
            return PM3_EFILE;
        }

        if (!json_is_object(root)) {
            PrintAndLogEx(ERR, "Invalid json format. root must be an object.");
            return PM3_EFILE;
        }
    } else {
        root = json_object();
    }

    // drop field at start
    DropFieldEx(channel);

    JsonSaveStr(root, "$.File.Created", "proxmark3 `emv scan`");

    if (channel == ECC_CONTACTLESS) {
        // iso 14443 select
        PrintAndLogEx(NORMAL, "--> GET UID, ATS.");

        iso14a_card_select_t card;
        if (Hf14443_4aGetCardData(&card)) {
            return PM3_ERFTRANS;
        }

        JsonSaveStr(root, "$.Card.Contactless.Communication", "iso14443-4a");
        JsonSaveBufAsHex(root, "$.Card.Contactless.UID", (uint8_t *)&card.uid, card.uidlen);
        JsonSaveHex(root, "$.Card.Contactless.ATQA", card.atqa[0] + (card.atqa[1] << 2), 2);
        JsonSaveHex(root, "$.Card.Contactless.SAK", card.sak, 0);
        JsonSaveBufAsHex(root, "$.Card.Contactless.ATS", (uint8_t *)card.ats, card.ats_len);
    } else {
        PrintAndLogEx(NORMAL, "--> GET ATR.");

        smart_card_atr_t card;
        smart_select(true, &card);
        if (!card.atr_len) {
            PrintAndLogEx(ERR, "Can't get ATR from a smart card.");
            return PM3_ERFTRANS;
        }

        JsonSaveStr(root, "$.Card.Contact.Communication", "iso7816");
        JsonSaveBufAsHex(root, "$.Card.Contact.ATR", (uint8_t *)card.atr, card.atr_len);
    }

    // init applets list tree
    const char *al = "Applets list";
    struct tlvdb *tlvSelect = tlvdb_fixed(1, strlen(al), (const unsigned char *)al);

    // EMV PPSE
    PrintAndLogEx(NORMAL, "--> PPSE.");
    res = EMVSelectPSE(channel, true, true, 2, buf, sizeof(buf), &len, &sw);

    if (!res && sw == 0x9000) {
        if (decodeTLV)
            TLVPrintFromBuffer(buf, len);

        JsonSaveBufAsHex(root, "$.PPSE.AID", (uint8_t *)"2PAY.SYS.DDF01", 14);

        struct tlvdb *fci = tlvdb_parse_multi(buf, len);
        if (extractTLVElements)
            JsonSaveTLVTree(root, root, "$.PPSE.FCITemplate", fci);
        else
            JsonSaveTLVTreeElm(root, "$.PPSE.FCITemplate", fci, true, true, false);
        JsonSaveTLVValue(root, "$.Application.KernelID", tlvdb_find_full(fci, 0x9f2a));
        tlvdb_free(fci);
    }

    res = EMVSearchPSE(channel, false, true, psenum, decodeTLV, tlvSelect);

    // check PPSE and select application id
    if (!res) {
        TLVPrintAIDlistFromSelectTLV(tlvSelect);
    } else {
        // EMV SEARCH with AID list
        SetAPDULogging(false);
        PrintAndLogEx(NORMAL, "--> AID search.");
        if (EMVSearch(channel, false, true, decodeTLV, tlvSelect)) {
            PrintAndLogEx(ERR, "Can't found any of EMV AID. Exit...");
            tlvdb_free(tlvSelect);
            DropFieldEx(channel);
            return PM3_ERFTRANS;
        }

        // check search and select application id
        TLVPrintAIDlistFromSelectTLV(tlvSelect);
    }

    // EMV SELECT application
    SetAPDULogging(showAPDU);
    EMVSelectApplication(tlvSelect, AID, &AIDlen);

    tlvdb_free(tlvSelect);

    if (!AIDlen) {
        PrintAndLogEx(INFO, "Can't select AID. EMV AID not found. Exit...");
        DropFieldEx(channel);
        return PM3_ERFTRANS;
    }

    JsonSaveBufAsHex(root, "$.Application.AID", AID, AIDlen);

    // Init TLV tree
    const char *alr = "Root terminal TLV tree";
    struct tlvdb *tlvRoot = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);

    // EMV SELECT applet

    PrintAndLogEx(NORMAL, "\n-->Selecting AID:%s.", sprint_hex_inrow(AID, AIDlen));
    SetAPDULogging(showAPDU);
    res = EMVSelect(channel, false, true, AID, AIDlen, buf, sizeof(buf), &len, &sw, tlvRoot);

    if (res) {
        PrintAndLogEx(ERR, "Can't select AID (%d). Exit...", res);
        tlvdb_free(tlvRoot);
        DropFieldEx(channel);
        return PM3_ERFTRANS;
    }

    if (decodeTLV)
        TLVPrintFromBuffer(buf, len);

    // save mode
    if (tlvdb_get(tlvRoot, 0x9f38, NULL)) {
        JsonSaveStr(root, "$.Application.Mode", TransactionTypeStr[TrType]);
    }

    struct tlvdb *fci = tlvdb_parse_multi(buf, len);
    if (extractTLVElements)
        JsonSaveTLVTree(root, root, "$.Application.FCITemplate", fci);
    else
        JsonSaveTLVTreeElm(root, "$.Application.FCITemplate", fci, true, true, false);
    tlvdb_free(fci);

    // create transaction parameters
    PrintAndLogEx(NORMAL, "-->Init transaction parameters.");
    InitTransactionParameters(tlvRoot, paramLoadJSON, TrType, GenACGPO);

    PrintAndLogEx(NORMAL, "-->Calc PDOL.");
    struct tlv *pdol_data_tlv = dol_process(tlvdb_get(tlvRoot, 0x9f38, NULL), tlvRoot, 0x83);
    if (!pdol_data_tlv) {
        PrintAndLogEx(ERR, "Can't create PDOL TLV.");
        tlvdb_free(tlvRoot);
        DropFieldEx(channel);
        return PM3_ESOFT;
    }

    size_t pdol_data_tlv_data_len;
    unsigned char *pdol_data_tlv_data = tlv_encode(pdol_data_tlv, &pdol_data_tlv_data_len);
    if (!pdol_data_tlv_data) {
        PrintAndLogEx(ERR, "Can't create PDOL data.");
        tlvdb_free(tlvRoot);
        free(pdol_data_tlv);
        DropFieldEx(channel);
        return PM3_ESOFT;
    }
    PrintAndLogEx(INFO, "PDOL data[%d]: %s", pdol_data_tlv_data_len, sprint_hex(pdol_data_tlv_data, pdol_data_tlv_data_len));

    PrintAndLogEx(INFO, "-->GPO.");
    res = EMVGPO(channel, true, pdol_data_tlv_data, pdol_data_tlv_data_len, buf, sizeof(buf), &len, &sw, tlvRoot);

    free(pdol_data_tlv_data);
    free(pdol_data_tlv);

    if (res) {
        PrintAndLogEx(ERR, "GPO error(%d): %4x. Exit...", res, sw);
        tlvdb_free(tlvRoot);
        DropFieldEx(channel);
        return PM3_ERFTRANS;
    }
    ProcessGPOResponseFormat1(tlvRoot, buf, len, decodeTLV);

    struct tlvdb *gpofci = tlvdb_parse_multi(buf, len);
    if (extractTLVElements)
        JsonSaveTLVTree(root, root, "$.Application.GPO", gpofci);
    else
        JsonSaveTLVTreeElm(root, "$.Application.GPO", gpofci, true, true, false);

    JsonSaveTLVValue(root, "$.ApplicationData.AIP", tlvdb_find_full(gpofci, 0x82));
    JsonSaveTLVValue(root, "$.ApplicationData.AFL", tlvdb_find_full(gpofci, 0x94));

    tlvdb_free(gpofci);

    PrintAndLogEx(INFO, "-->Read records from AFL.");
    const struct tlv *AFL = tlvdb_get(tlvRoot, 0x94, NULL);

    while (AFL && AFL->len) {
        if (AFL->len % 4) {
            PrintAndLogEx(ERR, "Wrong AFL length: %d", AFL->len);
            break;
        }

        json_t *sfijson = json_path_get(root, "$.Application.Records");
        if (!sfijson) {
            json_t *app = json_path_get(root, "$.Application");
            json_object_set_new(app, "Records", json_array());

            sfijson = json_path_get(root, "$.Application.Records");
        }
        if (!json_is_array(sfijson)) {
            PrintAndLogEx(ERR, "Internal logic error. `$.Application.Records` is not an array.");
            break;
        }
        for (int i = 0; i < AFL->len / 4; i++) {
            uint8_t SFI = AFL->value[i * 4 + 0] >> 3;
            uint8_t SFIstart = AFL->value[i * 4 + 1];
            uint8_t SFIend = AFL->value[i * 4 + 2];
            uint8_t SFIoffline = AFL->value[i * 4 + 3];

            PrintAndLogEx(INFO, "--->SFI[%02x] start:%02x end:%02x offline:%02x", SFI, SFIstart, SFIend, SFIoffline);
            if (SFI == 0 || SFI == 31 || SFIstart == 0 || SFIstart > SFIend) {
                PrintAndLogEx(ERR, "SFI ERROR! Skipped...");
                continue;
            }

            for (int n = SFIstart; n <= SFIend; n++) {
                PrintAndLogEx(INFO, "---->SFI[%02x] %d", SFI, n);

                res = EMVReadRecord(channel, true, SFI, n, buf, sizeof(buf), &len, &sw, tlvRoot);
                if (res) {
                    PrintAndLogEx(ERR, "SFI[%02x]. APDU error %4x", SFI, sw);
                    continue;
                }

                if (decodeTLV) {
                    TLVPrintFromBuffer(buf, len);
                    PrintAndLogEx(NORMAL, "");
                }

                json_t *jsonelm = json_object();
                json_array_append_new(sfijson, jsonelm);

                JsonSaveHex(jsonelm, "SFI", SFI, 1);
                JsonSaveHex(jsonelm, "RecordNum", n, 1);
                JsonSaveHex(jsonelm, "Offline", SFIoffline, 1);

                struct tlvdb *rsfi = tlvdb_parse_multi(buf, len);
                if (extractTLVElements)
                    JsonSaveTLVTree(root, jsonelm, "$.Data", rsfi);
                else
                    JsonSaveTLVTreeElm(jsonelm, "$.Data", rsfi, true, true, false);
                tlvdb_free(rsfi);
            }
        }

        break;
    }

    // getting certificates
    if (tlvdb_get(tlvRoot, 0x90, NULL)) {
        PrintAndLogEx(INFO, "-->Recovering certificates.");
        PKISetStrictExecution(false);
        RecoveryCertificates(tlvRoot, root);
        PKISetStrictExecution(true);
    }

    // free tlv object
    tlvdb_free(tlvRoot);

    DropFieldEx(channel);

    res = json_dump_file(root, fname, JSON_INDENT(2));
    if (res) {
        PrintAndLogEx(ERR, "Can't save the file: %s", fname);
        return PM3_EFILE;
    }
    PrintAndLogEx(SUCCESS, "File " _YELLOW_("`%s`") " saved.", fname);

    // free json object
    json_decref(root);

    return PM3_SUCCESS;
}

static int CmdEMVList(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    return CmdTraceList("7816");
}

static int CmdEMVTest(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    return ExecuteCryptoTests(true);
}

static int CmdEMVRoca(const char *Cmd) {
    uint8_t AID[APDU_AID_LEN] = {0};
    size_t AIDlen = 0;
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res;

    CLIParserInit("emv roca",
                  "Tries to extract public keys and run the ROCA test against them.\n",
                  "Usage:\n"
                  "\temv roca -w -> select --CONTACT-- card and run test\n"
                  "\temv roca -> select --CONTACTLESS-- card and run test\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("tT",  "selftest",   "self test"),
        arg_lit0("wW",  "wired",   "Send data via contact (iso7816) interface. Contactless interface set by default."),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, true);

    EMVCommandChannel channel = ECC_CONTACTLESS;
    if (arg_get_lit(1))
        return roca_self_test();

    if (arg_get_lit(2))
        channel = ECC_CONTACT;
    PrintChannel(channel);
    CLIParserFree();

    if (!IfPm3Smartcard()) {
        if (channel == ECC_CONTACT) {
            PrintAndLogEx(WARNING, "PM3 does not have SMARTCARD support. Exiting.");
            return PM3_EDEVNOTSUPP;
        }
    }

    // select card
    uint8_t psenum = (channel == ECC_CONTACT) ? 1 : 2;

    SetAPDULogging(false);

    // init applets list tree
    const char *al = "Applets list";
    struct tlvdb *tlvSelect = tlvdb_fixed(1, strlen(al), (const unsigned char *)al);

    // EMV PPSE
    PrintAndLogEx(NORMAL, "--> PPSE.");
    res = EMVSearchPSE(channel, false, true, psenum, false, tlvSelect);

    // check PPSE and select application id
    if (!res) {
        TLVPrintAIDlistFromSelectTLV(tlvSelect);
    } else {
        // EMV SEARCH with AID list
        PrintAndLogEx(NORMAL, "--> AID search.");
        if (EMVSearch(channel, false, true, false, tlvSelect)) {
            PrintAndLogEx(ERR, "Can't found any of EMV AID. Exit...");
            tlvdb_free(tlvSelect);
            DropFieldEx(channel);
            return PM3_ERFTRANS;
        }

        // check search and select application id
        TLVPrintAIDlistFromSelectTLV(tlvSelect);
    }

    // EMV SELECT application
    SetAPDULogging(false);
    EMVSelectApplication(tlvSelect, AID, &AIDlen);

    tlvdb_free(tlvSelect);

    if (!AIDlen) {
        PrintAndLogEx(INFO, "Can't select AID. EMV AID not found. Exit...");
        DropFieldEx(channel);
        return PM3_ERFTRANS;
    }

    // Init TLV tree
    const char *alr = "Root terminal TLV tree";
    struct tlvdb *tlvRoot = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);

    // EMV SELECT applet
    PrintAndLogEx(NORMAL, "\n-->Selecting AID:%s.", sprint_hex_inrow(AID, AIDlen));
    res = EMVSelect(channel, false, true, AID, AIDlen, buf, sizeof(buf), &len, &sw, tlvRoot);

    if (res) {
        PrintAndLogEx(ERR, "Can't select AID (%d). Exit...", res);
        tlvdb_free(tlvRoot);
        DropFieldEx(channel);
        return PM3_ERFTRANS;
    }

    PrintAndLogEx(NORMAL, "\n* Init transaction parameters.");
    InitTransactionParameters(tlvRoot, true, TT_QVSDCMCHIP, false);

    PrintAndLogEx(NORMAL, "-->Calc PDOL.");
    struct tlv *pdol_data_tlv = dol_process(tlvdb_get(tlvRoot, 0x9f38, NULL), tlvRoot, 0x83);
    if (!pdol_data_tlv) {
        PrintAndLogEx(ERR, "Can't create PDOL TLV.");
        tlvdb_free(tlvRoot);
        DropFieldEx(channel);
        return PM3_ESOFT;
    }

    size_t pdol_data_tlv_data_len;
    unsigned char *pdol_data_tlv_data = tlv_encode(pdol_data_tlv, &pdol_data_tlv_data_len);
    if (!pdol_data_tlv_data) {
        PrintAndLogEx(ERR, "Can't create PDOL data.");
        tlvdb_free(tlvRoot);
        DropFieldEx(channel);
        free(pdol_data_tlv);
        return PM3_ESOFT;
    }
    PrintAndLogEx(INFO, "PDOL data[%d]: %s", pdol_data_tlv_data_len, sprint_hex(pdol_data_tlv_data, pdol_data_tlv_data_len));

    PrintAndLogEx(INFO, "-->GPO.");
    res = EMVGPO(channel, true, pdol_data_tlv_data, pdol_data_tlv_data_len, buf, sizeof(buf), &len, &sw, tlvRoot);

    free(pdol_data_tlv_data);
    free(pdol_data_tlv);

    if (res) {
        PrintAndLogEx(ERR, "GPO error(%d): %4x. Exit...", res, sw);
        tlvdb_free(tlvRoot);
        DropFieldEx(channel);
        return PM3_ERFTRANS;
    }
    ProcessGPOResponseFormat1(tlvRoot, buf, len, false);

    PrintAndLogEx(INFO, "-->Read records from AFL.");
    const struct tlv *AFL = tlvdb_get(tlvRoot, 0x94, NULL);

    while (AFL && AFL->len) {
        if (AFL->len % 4) {
            PrintAndLogEx(ERR, "Wrong AFL length: %d", AFL->len);
            break;
        }

        for (int i = 0; i < AFL->len / 4; i++) {
            uint8_t SFI = AFL->value[i * 4 + 0] >> 3;
            uint8_t SFIstart = AFL->value[i * 4 + 1];
            uint8_t SFIend = AFL->value[i * 4 + 2];
            uint8_t SFIoffline = AFL->value[i * 4 + 3];

            PrintAndLogEx(INFO, "--->SFI[%02x] start:%02x end:%02x offline:%02x", SFI, SFIstart, SFIend, SFIoffline);
            if (SFI == 0 || SFI == 31 || SFIstart == 0 || SFIstart > SFIend) {
                PrintAndLogEx(ERR, "SFI ERROR! Skipped...");
                continue;
            }

            for (int n = SFIstart; n <= SFIend; n++) {
                PrintAndLogEx(INFO, "---->SFI[%02x] %d", SFI, n);

                res = EMVReadRecord(channel, true, SFI, n, buf, sizeof(buf), &len, &sw, tlvRoot);
                if (res) {
                    PrintAndLogEx(ERR, "SFI[%02x]. APDU error %4x", SFI, sw);
                    continue;
                }
            }
        }

        break;
    }

    // getting certificates
    int ret = PM3_SUCCESS;
    if (tlvdb_get(tlvRoot, 0x90, NULL)) {
        PrintAndLogEx(INFO, "-->Recovering certificates.");
        PKISetStrictExecution(false);

        struct emv_pk *pk = get_ca_pk(tlvRoot);
        if (!pk) {
            PrintAndLogEx(ERR, "ERROR: Key not found. Exit.");
            ret = PM3_ESOFT;
            goto out;
        }

        struct emv_pk *issuer_pk = emv_pki_recover_issuer_cert(pk, tlvRoot);
        if (!issuer_pk) {
            emv_pk_free(pk);
            PrintAndLogEx(WARNING, "WARNING: Issuer certificate not found. Exit.");
            ret = PM3_ESOFT;
            goto out;
        }

        PrintAndLogEx(SUCCESS, "Issuer PK recovered. RID %s IDX %02hhx CSN %s",
                      sprint_hex(issuer_pk->rid, 5),
                      issuer_pk->index,
                      sprint_hex(issuer_pk->serial, 3)
                     );


        struct emv_pk *icc_pk = emv_pki_recover_icc_cert(issuer_pk, tlvRoot, NULL);
        if (!icc_pk) {
            emv_pk_free(pk);
            emv_pk_free(issuer_pk);
            PrintAndLogEx(WARNING, "WARNING: ICC certificate not found. Exit.");
            ret = PM3_ESOFT;
            goto out;
        }
        PrintAndLogEx(SUCCESS, "ICC PK recovered. RID %s IDX %02hhx CSN %s\n",
                      sprint_hex(icc_pk->rid, 5),
                      icc_pk->index,
                      sprint_hex(icc_pk->serial, 3)
                     );

        PrintAndLogEx(INFO, "ICC pk modulus: %s", sprint_hex_inrow(icc_pk->modulus, icc_pk->mlen));

        // icc_pk->exp, icc_pk->elen
        // icc_pk->modulus, icc_pk->mlen
        if (icc_pk->elen > 0 && icc_pk->mlen > 0) {
            if (emv_rocacheck(icc_pk->modulus, icc_pk->mlen, true)) {
                PrintAndLogEx(INFO, "ICC pk is a subject to ROCA vulnerability, insecure..");
            } else {
                PrintAndLogEx(INFO, "ICC pk is OK(");
            }
        }

        PKISetStrictExecution(true);
    }

out:

    // free tlv object
    tlvdb_free(tlvRoot);

    DropFieldEx(channel);
    return ret;
}

static command_t CommandTable[] =  {
    {"help",        CmdHelp,                        AlwaysAvailable, "This help"},
    {"exec",        CmdEMVExec,                     IfPm3Iso14443,   "Executes EMV contactless transaction."},
    {"pse",         CmdEMVPPSE,                     IfPm3Iso14443,   "Execute PPSE. It selects 2PAY.SYS.DDF01 or 1PAY.SYS.DDF01 directory."},
    {"search",      CmdEMVSearch,                   IfPm3Iso14443,   "Try to select all applets from applets list and print installed applets."},
    {"select",      CmdEMVSelect,                   IfPm3Iso14443,   "Select applet."},
    {"gpo",         CmdEMVGPO,                      IfPm3Iso14443,   "Execute GetProcessingOptions."},
    {"readrec",     CmdEMVReadRecord,               IfPm3Iso14443,   "Read files from card."},
    {"genac",       CmdEMVAC,                       IfPm3Iso14443,   "Generate ApplicationCryptogram."},
    {"challenge",   CmdEMVGenerateChallenge,        IfPm3Iso14443,   "Generate challenge."},
    {"intauth",     CmdEMVInternalAuthenticate,     IfPm3Iso14443,   "Internal authentication."},
    {"scan",        CmdEMVScan,                     IfPm3Iso14443,   "Scan EMV card and save it contents to json file for emulator."},
    {"test",        CmdEMVTest,                     AlwaysAvailable, "Crypto logic test."},
    /*
    {"getrng",      CmdEMVGetrng,                   IfPm3Iso14443,   "get random number from terminal"},
    {"eload",       CmdEmvELoad,                    IfPm3Iso14443,   "load EMV tag into device"},
    {"dump",        CmdEmvDump,                     IfPm3Iso14443,   "dump EMV tag values"},
    {"sim",         CmdEmvSim,                      IfPm3Iso14443,   "simulate EMV tag"},
    {"clone",       CmdEmvClone,                    IfPm3Iso14443,   "clone an EMV tag"},
    */
    {"list",        CmdEMVList,                     AlwaysAvailable,   "List ISO7816 history"},
    {"roca",        CmdEMVRoca,                     IfPm3Iso14443,   "Extract public keys and run ROCA test"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdEMV(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

