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
//  Documentation here:
//
// FIDO Alliance specifications
// https://fidoalliance.org/download/
// FIDO NFC Protocol Specification v1.0
// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-nfc-protocol-v1.2-ps-20170411.html
// FIDO U2F Raw Message Formats
// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html
//-----------------------------------------------------------------------------

#include "cmdhffido.h"
#include <unistd.h>
#include "cmdparser.h"    // command_t
#include "commonutil.h"
#include "comms.h"
#include "proxmark3.h"
#include "iso7816/iso7816core.h"
#include "emv/emvjson.h"
#include "cliparser.h"
#include "crypto/asn1utils.h"
#include "crypto/libpcrypto.h"
#include "fido/cbortools.h"
#include "fido/fidocore.h"
#include "ui.h"
#include "cmdhf14a.h"
#include "cmdtrace.h"
#include "util.h"
#include "fileutils.h"   // laodFileJSONroot
#include "protocols.h"   // ISO7816 APDU return codes

#define DEF_FIDO_SIZE        2048
#define DEF_FIDO_PARAM_FILE  "hf_fido2_defparams.json"

static int CmdHelp(const char *Cmd);

static int CmdHFFidoList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf fido", "14a");
}

static int CmdHFFidoInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fido info",
                  "Get info from Fido tags",
                  "hf fido info");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    // info about 14a part
    infoHF14A(false, false, false);

    // FIDO info
    PrintAndLogEx(INFO, "-----------" _CYAN_("FIDO Info") "---------------------------------");
    SetAPDULogging(false);

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    int res = FIDOSelect(true, true, buf, sizeof(buf), &len, &sw);
    if (res) {
        DropField();
        return res;
    }

    if (sw != ISO7816_OK) {
        if (sw) {
            PrintAndLogEx(INFO, "Not a FIDO card. APDU response: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        } else {
            PrintAndLogEx(ERR, "APDU exchange error. Card returns 0x0000");
        }
        DropField();
        return PM3_SUCCESS;
    }

    if (strncmp((char *)buf, "U2F_V2", 7) == 0) {
        if (strncmp((char *)buf, "FIDO_2_0", 8) == 0) {
            PrintAndLogEx(INFO, "FIDO2 authenticator");
            PrintAndLogEx(INFO, "Version... " _YELLOW_("%.*s"), (int)len, buf);
        } else {
            PrintAndLogEx(INFO, "FIDO authenticator (not standard U2F)");
            PrintAndLogEx(INFO, "Non U2F authenticator");
            PrintAndLogEx(INFO, "version... ");
            print_buffer((const unsigned char *)buf, len, 1);
        }
    } else {
        PrintAndLogEx(INFO, "FIDO U2F authenticator detected");
        PrintAndLogEx(INFO, "Version... " _YELLOW_("%.*s"), (int)len, buf);
    }

    res = FIDO2GetInfo(buf, sizeof(buf), &len, &sw);
    DropField();
    if (res) {
        return res;
    }

    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "FIDO2 version doesn't exist (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return PM3_SUCCESS;
    }

    if (buf[0]) {
        PrintAndLogEx(ERR, "FIDO2 get version error: %d - %s", buf[0], fido2GetCmdErrorDescription(buf[0]));
        return PM3_SUCCESS;
    }

    if (len > 1) {
        PrintAndLogEx(SUCCESS, "FIDO2 version CBOR decoded:");
        TinyCborPrintFIDOPackage(fido2CmdGetInfo, true, &buf[1], len - 1);
    } else {
        PrintAndLogEx(ERR, "FIDO2 version length error");
    }
    return PM3_SUCCESS;
}

static int CmdHFFidoRegister(const char *cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fido reg",
                  "Initiate a U2F token registration. Needs two 32-byte hash numbers.\n"
                  "challenge parameter (32b) and application parameter (32b).\n"
                  "The default config filename is  `fido2_defparams.json`\n"
                  "\n",
                  "hf fido reg                   -> execute command with 2 parameters, filled 0x00\n"
                  "hf fido reg --cp s0 --ap s1   -> execute command with plain parameters\n"
                  "hf fido reg --cpx 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f --apx 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f\n"
                  "hf fido reg -f fido2-params   -> execute command with custom config file\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu", "Show APDU requests and responses"),
        arg_litn("v",  "verbose",  0, 2, "Verbose mode. vv - show full certificates data"),
        arg_lit0("t",  "tlv",  "Show DER certificate contents in TLV representation"),
        arg_str0("f",  "file", "<fn>",  "JSON input file name for parameters"),
        arg_str0(NULL, "cp",   "<str>", "Challenge parameter (1..16 chars)"),
        arg_str0(NULL, "ap",   "<str>", "Application parameter (1..16 chars)"),
        arg_str0(NULL, "cpx",  "<hex>", "Challenge parameter (32 bytes hex)"),
        arg_str0(NULL, "apx",  "<hex>", "Application parameter (32 bytes hex)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool verbose2 = arg_get_lit(ctx, 2) > 1;
    bool showDERTLV = arg_get_lit(ctx, 3);
    bool cpplain = arg_get_str_len(ctx, 5);
    bool applain = arg_get_str_len(ctx, 6);
    bool cphex = arg_get_str_len(ctx, 7);
    bool aphex = arg_get_str_len(ctx, 8);

    uint8_t data[64] = {0};
    int chlen = 0;
    uint8_t cdata[250] = {0};
    int applen = 0;
    uint8_t adata[250] = {0};

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 4), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    // default name
    if (fnlen == 0) {
        strcat(filename, DEF_FIDO_PARAM_FILE);
        fnlen = strlen(filename);
    }

    json_t *root = NULL;
    int res = loadFileJSONroot(filename, (void **)&root, verbose);
    if (res != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    size_t jlen = 0;
    JsonLoadBufAsHex(root, "$.ChallengeParam", data, 32, &jlen);
    JsonLoadBufAsHex(root, "$.ApplicationParam", &data[32], 32, &jlen);

    if (cpplain) {
        memset(cdata, 0x00, 32);
        chlen = sizeof(cdata);
        CLIGetStrWithReturn(ctx, 5, cdata, &chlen);
        if (chlen > 16) {
            PrintAndLogEx(ERR, "ERROR: challenge parameter length in ASCII mode must be less than 16 chars instead of: %d", chlen);
            CLIParserFree(ctx);
            json_decref(root);
            return PM3_EINVARG;
        }
    }
    if (cphex && cpplain == false) {
        chlen = sizeof(cdata);
        CLIGetHexWithReturn(ctx, 7, cdata, &chlen);
        if (chlen && chlen != 32) {
            PrintAndLogEx(ERR, "ERROR: challenge parameter length must be 32 bytes only.");
            CLIParserFree(ctx);
            json_decref(root);
            return PM3_EINVARG;
        }
    }
    if (chlen)
        memmove(data, cdata, 32);

    if (applain) {
        memset(adata, 0x00, 32);
        applen = sizeof(adata);
        CLIGetStrWithReturn(ctx, 6, adata, &applen);
        if (applen > 16) {
            PrintAndLogEx(ERR, "ERROR: application parameter length in ASCII mode must be less than 16 chars instead of: %d", applen);
            CLIParserFree(ctx);
            json_decref(root);
            return PM3_EINVARG;
        }
    }
    if (aphex && applain == false) {
        applen = sizeof(adata);
        CLIGetHexWithReturn(ctx, 8, adata, &applen);
        if (applen && applen != 32) {
            PrintAndLogEx(ERR, "ERROR: application parameter length must be 32 bytes only.");
            CLIParserFree(ctx);
            json_decref(root);
            return PM3_EINVARG;
        }
    }
    if (applen)
        memmove(&data[32], adata, 32);

    CLIParserFree(ctx);

    SetAPDULogging(APDULogging);

    // challenge parameter [32 bytes] - The challenge parameter is the SHA-256 hash of the Client Data, a stringified JSON data structure that the FIDO Client prepares
    // application parameter [32 bytes] - The application parameter is the SHA-256 hash of the UTF-8 encoding of the application identity

    uint8_t buf[2048] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    DropField();
    res = FIDOSelect(true, true, buf, sizeof(buf), &len, &sw);

    if (res) {
        PrintAndLogEx(ERR, "Can't select authenticator. res=%x. Exit...", res);
        DropField();
        json_decref(root);
        return res;
    }

    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Can't select FIDO application. APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        json_decref(root);
        return PM3_ESOFT;
    }

    res = FIDORegister(data, buf,  sizeof(buf), &len, &sw);
    DropField();
    if (res) {
        PrintAndLogEx(ERR, "Can't execute register command. res=%x. Exit...", res);
        json_decref(root);
        return res;
    }

    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "ERROR execute register command. APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return PM3_ESOFT;
    }

    PrintAndLogEx(NORMAL, "");
    if (APDULogging)
        PrintAndLogEx(INFO, "---------------------------------------------------------------");

    PrintAndLogEx(INFO, "data len: %zu", len);

    if (verbose2) {
        PrintAndLogEx(INFO, "------------ " _CYAN_("data") " ----------------------");
        print_buffer((const unsigned char *)buf, len, 1);
        PrintAndLogEx(INFO, "-------------" _CYAN_("data") " ----------------------");
    }

    if (buf[0] != 0x05) {
        PrintAndLogEx(ERR, "ERROR: First byte must be 0x05, but it %2x", buf[0]);
        json_decref(root);
        return PM3_ESOFT;
    }
    PrintAndLogEx(SUCCESS, "User public key: %s", sprint_hex(&buf[1], 65));

    uint8_t keyHandleLen = buf[66];
    PrintAndLogEx(SUCCESS, "Key handle[%d]: %s", keyHandleLen, sprint_hex(&buf[67], keyHandleLen));

    int derp = 67 + keyHandleLen;
    int derLen = (buf[derp + 2] << 8) + buf[derp + 3] + 4;
    if (verbose2) {
        PrintAndLogEx(INFO, "DER certificate[%d]:", derLen);
        PrintAndLogEx(INFO, "------------------DER-------------------");
        PrintAndLogEx(INFO, "%s", sprint_hex(buf + derp, derLen));
        PrintAndLogEx(INFO, "----------------DER---------------------");
    } else {
        if (verbose)
            PrintAndLogEx(INFO, "------------------DER-------------------");
        PrintAndLogEx(INFO, "DER certificate[%d]: %s...", derLen, sprint_hex(&buf[derp], 20));
    }

    // check and print DER certificate
    uint8_t public_key[65] = {0};

    // print DER certificate in TLV view
    if (showDERTLV) {
        PrintAndLogEx(INFO, "----------------DER TLV-----------------");
        asn1_print(&buf[derp], derLen, "  ");
        PrintAndLogEx(INFO, "----------------DER TLV-----------------");
    }

    FIDOCheckDERAndGetKey(&buf[derp], derLen, verbose, public_key, sizeof(public_key));

    // get hash
    int hashp = 1 + 65 + 1 + keyHandleLen + derLen;
    PrintAndLogEx(SUCCESS, "Hash[%zu]: %s", len - hashp, sprint_hex(&buf[hashp], len - hashp));

    // check ANSI X9.62 format ECDSA signature (on P-256)
    uint8_t rval[300] = {0};
    uint8_t sval[300] = {0};
    res = ecdsa_asn1_get_signature(&buf[hashp], len - hashp, rval, sval);
    if (res == PM3_SUCCESS) {
        if (verbose) {
            PrintAndLogEx(INFO, "  r: %s", sprint_hex(rval, 32));
            PrintAndLogEx(INFO, "  s: %s", sprint_hex(sval, 32));
        }

        uint8_t xbuf[4096] = {0};
        size_t xbuflen = 0;
        res = FillBuffer(xbuf, sizeof(xbuf), &xbuflen,
                         "\x00", 1,
                         &data[32], 32,           // application parameter
                         &data[0], 32,            // challenge parameter
                         &buf[67], keyHandleLen,  // keyHandle
                         &buf[1], 65,             // user public key
                         (uint8_t *)NULL, 0);
        (void)res;
        //PrintAndLogEx(INFO, "--xbuf(%d)[%d]: %s", res, xbuflen, sprint_hex(xbuf, xbuflen));
        res = ecdsa_signature_verify(MBEDTLS_ECP_DP_SECP256R1, public_key, xbuf, xbuflen, &buf[hashp], len - hashp, true);
        if (res) {
            if (res == MBEDTLS_ERR_ECP_VERIFY_FAILED) {
                PrintAndLogEx(WARNING, "Signature is ( " _RED_("not valid") " )");
            } else {
                PrintAndLogEx(WARNING, "Other signature check error: %x %s", (res < 0) ? -res : res, ecdsa_get_error(res));
            }
        } else {
            PrintAndLogEx(SUCCESS, "Signature is ( " _GREEN_("ok") " )");
        }

    } else {
        PrintAndLogEx(WARNING, "Invalid signature. res = %d. ( " _RED_("fail") " )", res);
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "auth command: ");
    char command[500] = {0};
    snprintf(command, sizeof(command), "hf fido auth --kh %s", sprint_hex_inrow(&buf[67], keyHandleLen));
    if (chlen) {
        size_t command_len = strlen(command);
        snprintf(command + command_len, sizeof(command) - command_len, " --%s %s", cpplain ? "cp" : "cpx", cpplain ? (char *)cdata : sprint_hex_inrow(cdata, 32));
    }
    if (applen) {
        size_t command_len = strlen(command);
        snprintf(command + command_len, sizeof(command) - command_len, " --%s %s", applain ? "cp" : "cpx", applain ? (char *)adata : sprint_hex_inrow(adata, 32));
    }
    PrintAndLogEx(INFO, "%s", command);

    if (root) {
        JsonSaveBufAsHex(root, "ChallengeParam", data, 32);
        JsonSaveBufAsHex(root, "ApplicationParam", &data[32], 32);
        JsonSaveBufAsHexCompact(root, "PublicKey", &buf[1], 65);
        JsonSaveInt(root, "KeyHandleLen", keyHandleLen);
        JsonSaveBufAsHexCompact(root, "KeyHandle", &buf[67], keyHandleLen);
        JsonSaveBufAsHexCompact(root, "DER", &buf[67 + keyHandleLen], derLen);

        res = saveFileJSONrootEx(filename, root, JSON_INDENT(2), verbose, true);
        (void)res;
    }
    json_decref(root);
    return PM3_SUCCESS;
}

static int CmdHFFidoAuthenticate(const char *cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fido auth",
                  "Initiate a U2F token authentication. Needs key handle and two 32-byte hash numbers.\n"
                  "key handle(var 0..255), challenge parameter (32b) and application parameter (32b)\n"
                  "The default config filename is  `fido2_defparams.json`\n"
                  "\n",
                  "hf fido auth --kh 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f -> execute command with 2 parameters, filled 0x00 and key handle\n"
                  "hf fido auth \n"
                  "--kh 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f\n"
                  "--cpx 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f \n"
                  "--apx 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f -> execute command with parameters");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",      "Show APDU requests and responses"),
        arg_lit0("v",  "verbose",   "Verbose mode"),
        arg_rem("default mode:",    "dont-enforce-user-presence-and-sign"),
        arg_lit0("u",  "user",      "mode: enforce-user-presence-and-sign"),
        arg_lit0("c",  "check",     "mode: check-only"),
        arg_str0("f",  "file",  "<fn>",  "JSON file name for parameters"),
        arg_str0("k",  "key",   "<hex>", "Public key to verify signature"),
        arg_str0(NULL, "kh",    "<hex>", "Key handle (var 0..255b)"),
        arg_str0(NULL, "cp",    "<str>", "Challenge parameter (1..16 chars)"),
        arg_str0(NULL, "ap",    "<str>", "Application parameter (1..16 chars)"),
        arg_str0(NULL, "cpx",   "<hex>", "Challenge parameter (32 bytes hex)"),
        arg_str0(NULL, "apx",   "<hex>", "Application parameter (32 bytes hex)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    uint8_t controlByte = 0x08;
    if (arg_get_lit(ctx, 4))
        controlByte = 0x03;

    if (arg_get_lit(ctx, 5))
        controlByte = 0x07;

    uint8_t data[512] = {0};
    uint8_t hdata[256] = {0};
    bool public_key_loaded = false;
    uint8_t public_key[65] = {0};
    int hdatalen = 0;
    uint8_t keyHandleLen = 0;

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 6), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    // default name
    if (fnlen == 0) {
        strcat(filename, DEF_FIDO_PARAM_FILE);
        fnlen = strlen(filename);
    }

    json_t *root = NULL;
    int res = loadFileJSONroot(filename, (void **)&root, verbose);
    if (res != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    size_t jlen = 0;
    JsonLoadBufAsHex(root, "$.ChallengeParam", data, 32, &jlen);
    JsonLoadBufAsHex(root, "$.ApplicationParam", &data[32], 32, &jlen);
    JsonLoadBufAsHex(root, "$.KeyHandle", &data[65], 512 - 67, &jlen);
    keyHandleLen = jlen & 0xff;
    data[64] = keyHandleLen;
    JsonLoadBufAsHex(root, "$.PublicKey", public_key, 65, &jlen);
    public_key_loaded = (jlen > 0);

    // public key
    CLIGetHexWithReturn(ctx, 7, hdata, &hdatalen);
    if (hdatalen && hdatalen != 65) {
        PrintAndLogEx(ERR, "ERROR: public key length must be 65 bytes only.");
        CLIParserFree(ctx);
        json_decref(root);
        return PM3_EINVARG;
    }

    if (hdatalen) {
        memmove(public_key, hdata, hdatalen);
        public_key_loaded = true;
    }

    CLIGetHexWithReturn(ctx, 8, hdata, &hdatalen);
    if (hdatalen > 255) {
        PrintAndLogEx(ERR, "ERROR: key handle length must be less than 255.");
        CLIParserFree(ctx);
        json_decref(root);
        return PM3_EINVARG;
    }

    printf("-- hlen=%d\n", hdatalen);
    if (hdatalen) {
        keyHandleLen = hdatalen;
        data[64] = keyHandleLen;
        memmove(&data[65], hdata, keyHandleLen);
        hdatalen = 0;
    }

    bool cpplain = arg_get_str_len(ctx, 9);
    bool applain = arg_get_str_len(ctx, 10);
    bool cphex = arg_get_str_len(ctx, 11);
    bool aphex = arg_get_str_len(ctx, 12);

    if (cpplain) {
        memset(hdata, 0x00, 32);
        hdatalen = sizeof(hdata);
        CLIGetStrWithReturn(ctx, 9, hdata, &hdatalen);
        if (hdatalen > 16) {
            PrintAndLogEx(ERR, "ERROR: challenge parameter length in ASCII mode must be less than 16 chars instead of: %d", hdatalen);
            CLIParserFree(ctx);
            json_decref(root);
            return PM3_EINVARG;
        }
    }
    if (cphex && cpplain == false) {
        hdatalen = sizeof(hdata);
        CLIGetHexWithReturn(ctx, 11, hdata, &hdatalen);
        if (hdatalen && hdatalen != 32) {
            PrintAndLogEx(ERR, "ERROR: challenge parameter length must be 32 bytes only.");
            CLIParserFree(ctx);
            json_decref(root);
            return PM3_EINVARG;
        }
    }
    if (hdatalen) {
        memmove(data, hdata, 32);
        hdatalen = 0;
    }

    if (applain) {
        memset(hdata, 0x00, 32);
        hdatalen = sizeof(hdata);
        CLIGetStrWithReturn(ctx, 10, hdata, &hdatalen);
        if (hdatalen > 16) {
            PrintAndLogEx(ERR, "ERROR: application parameter length in ASCII mode must be less than 16 chars instead of: %d", hdatalen);
            CLIParserFree(ctx);
            json_decref(root);
            return PM3_EINVARG;
        }
    }
    if (aphex && applain == false) {
        hdatalen = sizeof(hdata);
        CLIGetHexWithReturn(ctx, 12, hdata, &hdatalen);
        if (hdatalen && hdatalen != 32) {
            PrintAndLogEx(ERR, "ERROR: application parameter length must be 32 bytes only.");
            CLIParserFree(ctx);
            json_decref(root);
            return PM3_EINVARG;
        }
    }
    if (hdatalen) {
        memmove(&data[32], hdata, 32);
        hdatalen = 0;
    }

    CLIParserFree(ctx);

    SetAPDULogging(APDULogging);

    // (in parameter) control byte 0x07 - check only, 0x03 - user presence + cign. 0x08 - sign only
    // challenge parameter [32 bytes]
    // application parameter [32 bytes]
    // key handle length [1b] = N
    // key handle [N]

    uint8_t datalen = 32 + 32 + 1 + keyHandleLen;

    uint8_t buf[2048] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    DropField();
    res = FIDOSelect(true, true, buf, sizeof(buf), &len, &sw);
    if (res) {
        PrintAndLogEx(ERR, "Can't select authenticator. res=%x. Exit...", res);
        DropField();
        json_decref(root);
        return res;
    }

    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Can't select FIDO application. APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        json_decref(root);
        return PM3_ESOFT;
    }

    res = FIDOAuthentication(data, datalen, controlByte,  buf,  sizeof(buf), &len, &sw);
    DropField();
    if (res) {
        PrintAndLogEx(ERR, "Can't execute authentication command. res=%x. Exit...", res);
        json_decref(root);
        return res;
    }

    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "ERROR execute authentication command. APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        json_decref(root);
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "---------------------------------------------------------------");
    PrintAndLogEx(SUCCESS, "User presence: %s", (buf[0] ? "verified" : "not verified"));
    uint32_t cntr = (uint32_t)bytes_to_num(&buf[1], 4);
    PrintAndLogEx(SUCCESS, "Counter: %d", cntr);
    PrintAndLogEx(SUCCESS, "Hash[%zu]: %s", len - 5, sprint_hex(&buf[5], len - 5));

    // check ANSI X9.62 format ECDSA signature (on P-256)
    uint8_t rval[300] = {0};
    uint8_t sval[300] = {0};
    res = ecdsa_asn1_get_signature(&buf[5], len - 5, rval, sval);
    if (res == PM3_SUCCESS) {
        if (verbose) {
            PrintAndLogEx(INFO, "  r: %s", sprint_hex(rval, 32));
            PrintAndLogEx(INFO, "  s: %s", sprint_hex(sval, 32));
        }
        if (public_key_loaded) {
            uint8_t xbuf[4096] = {0};
            size_t xbuflen = 0;
            res = FillBuffer(xbuf, sizeof(xbuf), &xbuflen,
                             &data[32], 32, // application parameter
                             &buf[0], 1,    // user presence
                             &buf[1], 4,    // counter
                             data, 32,      // challenge parameter
                             (uint8_t *)NULL, 0);
            (void)res;
            //PrintAndLogEx(INFO, "--xbuf(%d)[%d]: %s", res, xbuflen, sprint_hex(xbuf, xbuflen));
            res = ecdsa_signature_verify(MBEDTLS_ECP_DP_SECP256R1, public_key, xbuf, xbuflen, &buf[5], len - 5, true);
            if (res) {
                if (res == MBEDTLS_ERR_ECP_VERIFY_FAILED) {
                    PrintAndLogEx(WARNING, "Signature is ( " _RED_("not valid") " )");
                } else {
                    PrintAndLogEx(WARNING, "Other signature check error: %x %s", (res < 0) ? -res : res, ecdsa_get_error(res));
                }
            } else {
                PrintAndLogEx(SUCCESS, "Signature is ( " _GREEN_("ok") " )");
            }
        } else {
            PrintAndLogEx(WARNING, "No public key provided. can't check signature.");
        }
    } else {
        PrintAndLogEx(WARNING, "Invalid signature. res = %d. ( " _RED_("fail") " )", res);
    }

    if (root) {
        JsonSaveBufAsHex(root, "ChallengeParam", data, 32);
        JsonSaveBufAsHex(root, "ApplicationParam", &data[32], 32);
        JsonSaveInt(root, "KeyHandleLen", keyHandleLen);
        JsonSaveBufAsHexCompact(root, "KeyHandle", &data[65], keyHandleLen);
        JsonSaveInt(root, "Counter", cntr);

        res = saveFileJSONrootEx(filename, root, JSON_INDENT(2), verbose, true);
        (void)res;
    }
    json_decref(root);
    return PM3_ESOFT;
}

static int CmdHFFido2MakeCredential(const char *cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fido make",
                  "Execute a FIDO2 Make Credential command. Needs json file with parameters.\n"
                  "Sample file `fido2_defparams.json` in `client/resources/`.\n"
                  "- for yubikey there must be only one option `\"rk\": true` or false"
                  ,
                  "hf fido make               --> use default parameters file `fido2_defparams.json`\n"
                  "hf fido make -f test.json  --> use parameters file `text.json`"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a", "apdu", "Show APDU requests and responses"),
        arg_litn("v", "verbose", 0, 2, "Verbose mode. vv - show full certificates data"),
        arg_lit0("t", "tlv",  "Show DER certificate contents in TLV representation"),
        arg_lit0("c", "cbor", "Show CBOR decoded data"),
        arg_str0("f", "file", "<fn>", "Parameter JSON file name"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool verbose2 = arg_get_lit(ctx, 2) > 1;
    bool showDERTLV = arg_get_lit(ctx, 3);
    bool showCBOR = arg_get_lit(ctx, 4);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 5), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    // default name
    if (fnlen == 0) {
        strcat(filename, DEF_FIDO_PARAM_FILE);
        fnlen = strlen(filename);
    }

    json_t *root = NULL;
    loadFileJSONroot(filename, (void **)&root, verbose);
    if (root == NULL) {
        return PM3_EFILE;
    }

    SetAPDULogging(APDULogging);

    uint8_t data[DEF_FIDO_SIZE] = {0};
    size_t datalen = 0;
    uint8_t buf[DEF_FIDO_SIZE] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    DropField();
    int res = FIDOSelect(true, true, buf, sizeof(buf), &len, &sw);
    if (res) {
        PrintAndLogEx(ERR, "Can't select authenticator. res=%x. Exit...", res);
        DropField();
        json_decref(root);
        return res;
    }

    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Can't select FIDO application. APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        json_decref(root);
        return PM3_ESOFT;
    }

    res = FIDO2CreateMakeCredentionalReq(root, data, sizeof(data), &datalen);
    if (res) {
        json_decref(root);
        return res;
    }

    if (showCBOR) {
        PrintAndLogEx(INFO, "CBOR make credential request:");
        PrintAndLogEx(INFO, "---------------- " _CYAN_("CBOR") " ------------------");
        TinyCborPrintFIDOPackage(fido2CmdMakeCredential, false, data, datalen);
        PrintAndLogEx(INFO, "---------------- " _CYAN_("CBOR") " ------------------");
    }

    res = FIDO2MakeCredential(data, datalen, buf,  sizeof(buf), &len, &sw);
    DropField();
    if (res) {
        PrintAndLogEx(ERR, "Can't execute make credential command. res=%x. exit...", res);
        json_decref(root);
        return res;
    }

    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "ERROR execute make credential command. APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        json_decref(root);
        return PM3_EFILE;
    }

    if (buf[0]) {
        PrintAndLogEx(ERR, "FIDO2 make credential error: %d - %s", buf[0], fido2GetCmdErrorDescription(buf[0]));
        json_decref(root);
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "MakeCredential result %zu b ( ok )", len);
    if (showCBOR) {
        PrintAndLogEx(SUCCESS, "CBOR make credential response:");
        PrintAndLogEx(INFO, "---------------- " _CYAN_("CBOR") " ------------------");
        TinyCborPrintFIDOPackage(fido2CmdMakeCredential, true, &buf[1], len - 1);
        PrintAndLogEx(INFO, "---------------- " _CYAN_("CBOR") " ------------------");
    }

    // parse returned cbor
    FIDO2MakeCredentionalParseRes(root, &buf[1], len - 1, verbose, verbose2, showCBOR, showDERTLV);

    res = saveFileJSONrootEx(filename, root, JSON_INDENT(2), verbose, true);
    (void)res;
    json_decref(root);
    return res;
}

static int CmdHFFido2GetAssertion(const char *cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fido assert",
                  "Execute a FIDO2 Get Assertion command. Needs json file with parameters.\n"
                  "Sample file `fido2_defparams.json` in `client/resources/`.\n"
                  "- Needs if `rk` option is `false` (authenticator doesn't store credential to its memory)\n"
                  "- for yubikey there must be only one option `\"up\": true` or false"
                  ,
                  "hf fido assert                  --> default parameters file `fido2_defparams.json`\n"
                  "hf fido assert -f test.json -l  --> use parameters file `text.json` and add to request CredentialId");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a", "apdu", "Show APDU requests and responses"),
        arg_litn("v", "verbose", 0, 2, "Verbose mode. vv - show full certificates data"),
        arg_lit0("c", "cbor", "Show CBOR decoded data"),
        arg_lit0("l", "list", "Add CredentialId from json to allowList"),
        arg_str0("f", "file", "<fn>", "Parameter JSON file name"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool verbose2 = arg_get_lit(ctx, 2) > 1;
    bool showCBOR = arg_get_lit(ctx, 3);
    bool createAllowList = arg_get_lit(ctx, 4);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 5), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    // default name
    if (fnlen == 0) {
        strcat(filename, DEF_FIDO_PARAM_FILE);
        fnlen = strlen(filename);
    }

    json_t *root = NULL;
    loadFileJSONroot(filename, (void **)&root, verbose);
    if (root == NULL) {
        return PM3_EFILE;
    }

    SetAPDULogging(APDULogging);

    uint8_t data[DEF_FIDO_SIZE] = {0};
    size_t datalen = 0;
    uint8_t buf[DEF_FIDO_SIZE] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    DropField();
    int res = FIDOSelect(true, true, buf, sizeof(buf), &len, &sw);
    if (res) {
        PrintAndLogEx(ERR, "Can't select authenticator. res=%x. exiting...", res);
        DropField();
        json_decref(root);
        return res;
    }

    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Can't select FIDO application. APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        json_decref(root);
        return PM3_ESOFT;
    }

    res = FIDO2CreateGetAssertionReq(root, data, sizeof(data), &datalen, createAllowList);
    if (res) {
        json_decref(root);
        return res;
    }

    if (showCBOR) {
        PrintAndLogEx(SUCCESS, "CBOR get assertion request:");
        PrintAndLogEx(INFO, "---------------- " _CYAN_("CBOR") " ------------------");
        TinyCborPrintFIDOPackage(fido2CmdGetAssertion, false, data, datalen);
        PrintAndLogEx(INFO, "---------------- " _CYAN_("CBOR") " ------------------");
    }

    res = FIDO2GetAssertion(data, datalen, buf,  sizeof(buf), &len, &sw);
    DropField();
    if (res) {
        PrintAndLogEx(ERR, "Can't execute get assertion command. res=%x. Exit...", res);
        json_decref(root);
        return res;
    }

    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "ERROR execute get assertion command. APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        json_decref(root);
        return PM3_ESOFT;
    }

    if (buf[0]) {
        PrintAndLogEx(ERR, "FIDO2 get assertion error: %d - %s", buf[0], fido2GetCmdErrorDescription(buf[0]));
        json_decref(root);
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "GetAssertion result (%zu b) OK.", len);
    if (showCBOR) {
        PrintAndLogEx(SUCCESS, "CBOR get assertion response:");
        PrintAndLogEx(INFO, "---------------- " _CYAN_("CBOR") " ------------------");
        TinyCborPrintFIDOPackage(fido2CmdGetAssertion, true, &buf[1], len - 1);
        PrintAndLogEx(INFO, "---------------- " _CYAN_("CBOR") " ------------------");
    }

    // parse returned cbor
    FIDO2GetAssertionParseRes(root, &buf[1], len - 1, verbose, verbose2, showCBOR);

    res = saveFileJSONrootEx(filename, root, JSON_INDENT(2), verbose, true);
    (void)res;
    json_decref(root);
    return res;
}

static command_t CommandTable[] = {
    {"help",      CmdHelp,                   AlwaysAvailable, "This help."},
    {"list",      CmdHFFidoList,             AlwaysAvailable, "List ISO 14443A history"},
    {"info",      CmdHFFidoInfo,             IfPm3Iso14443a,  "Info about FIDO tag."},
    {"reg",       CmdHFFidoRegister,         IfPm3Iso14443a,  "FIDO U2F Registration Message."},
    {"auth",      CmdHFFidoAuthenticate,     IfPm3Iso14443a,  "FIDO U2F Authentication Message."},
    {"make",      CmdHFFido2MakeCredential,  IfPm3Iso14443a,  "FIDO2 MakeCredential command."},
    {"assert",    CmdHFFido2GetAssertion,    IfPm3Iso14443a,  "FIDO2 GetAssertion command."},
    {NULL, NULL, 0, NULL}
};

int CmdHFFido(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}
