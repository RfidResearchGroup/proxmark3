//-----------------------------------------------------------------------------
// Copyright (C) 2018 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency MIFARE  Plus commands
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

#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <jansson.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509.h>
#include <mbedtls/pk.h>
#include "comms.h"
#include "cmdmain.h"
#include "util.h"
#include "ui.h"
#include "proxmark3.h"
#include "mifare.h"
#include "emv/emvcore.h"
#include "emv/emvjson.h"
#include "emv/dump.h"
#include "cliparser/cliparser.h"
#include "crypto/asn1utils.h"
#include "crypto/libpcrypto.h"
#include "fido/cbortools.h"
#include "fido/fidocore.h"
#include "fido/cose.h"

static int CmdHelp(const char *Cmd);

int CmdHFFidoInfo(const char *cmd) {

    if (cmd && strlen(cmd) > 0)
        PrintAndLog("WARNING: command don't have any parameters.\n");

    // info about 14a part
    CmdHF14AInfo("");

    // FIDO info
    PrintAndLog("--------------------------------------------");
    SetAPDULogging(false);

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = FIDOSelect(true, true, buf, sizeof(buf), &len, &sw);

    if (res) {
        DropField();
        return res;
    }

    if (sw != 0x9000) {
        if (sw)
            PrintAndLog("Not a FIDO card! APDU response: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        else
            PrintAndLog("APDU exchange error. Card returns 0x0000.");

        DropField();
        return 0;
    }

    if (!strncmp((char *)buf, "U2F_V2", 7)) {
        if (!strncmp((char *)buf, "FIDO_2_0", 8)) {
            PrintAndLog("FIDO2 authenricator detected. Version: %.*s", len, buf);
        } else {
            PrintAndLog("FIDO authenricator detected (not standard U2F).");
            PrintAndLog("Non U2F authenticator version:");
            dump_buffer((const unsigned char *)buf, len, NULL, 0);
        }
    } else {
        PrintAndLog("FIDO U2F authenricator detected. Version: %.*s", len, buf);
    }

    res = FIDO2GetInfo(buf, sizeof(buf), &len, &sw);
    DropField();
    if (res) {
        return res;
    }
    if (sw != 0x9000) {
        PrintAndLog("FIDO2 version not exists (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));

        return 0;
    }

    if (buf[0]) {
        PrintAndLog("FIDO2 ger version error: %d - %s", buf[0], fido2GetCmdErrorDescription(buf[0]));
        return 0;
    }

    if (len > 1) {
//      if (false) {
//          PrintAndLog("FIDO2 version: (len=%d)", len);
//          dump_buffer((const unsigned char *)buf, len, NULL, 0);
//      }

        PrintAndLog("FIDO2 version CBOR decoded:");
        TinyCborPrintFIDOPackage(fido2CmdGetInfo, true, &buf[1], len - 1);
    } else {
        PrintAndLog("FIDO2 version length error");
    }

    return 0;
}

json_t *OpenJson(int paramnum, char *fname, void *argtable[], bool *err) {
    json_t *root = NULL;
    json_error_t error;
    *err = false;

    uint8_t jsonname[250] = {0};
    char *cjsonname = (char *)jsonname;
    int jsonnamelen = 0;

    // CLIGetStrWithReturn(paramnum, jsonname, &jsonnamelen);
    if (CLIParamStrToBuf(arg_get_str(paramnum), jsonname, sizeof(jsonname), &jsonnamelen))  {
        CLIParserFree();
        return NULL;
    }

    // current path + file name
    if (!strstr(cjsonname, ".json"))
        strcat(cjsonname, ".json");

    if (jsonnamelen) {
        strcpy(fname, get_my_executable_directory());
        strcat(fname, cjsonname);
        if (access(fname, F_OK) != -1) {
            root = json_load_file(fname, 0, &error);
            if (!root) {
                PrintAndLog("ERROR: json error on line %d: %s", error.line, error.text);
                *err = true;
                return NULL;
            }

            if (!json_is_object(root)) {
                PrintAndLog("ERROR: Invalid json format. root must be an object.");
                json_decref(root);
                *err = true;
                return NULL;
            }

        } else {
            root = json_object();
        }
    }
    return root;
}

int CmdHFFidoRegister(const char *cmd) {
    uint8_t data[64] = {0};
    int chlen = 0;
    uint8_t cdata[250] = {0};
    int applen = 0;
    uint8_t adata[250] = {0};
    json_t *root = NULL;

    CLIParserInit("hf fido reg",
                  "Initiate a U2F token registration. Needs two 32-byte hash number. \nchallenge parameter (32b) and application parameter (32b).",
                  "Usage:\n\thf fido reg -> execute command with 2 parameters, filled 0x00\n"
                  "\thf fido reg 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f -> execute command with parameters"
                  "\thf fido reg -p s0 s1 -> execute command with plain parameters");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("aA",  "apdu",     "show APDU reqests and responses"),
        arg_litn("vV",  "verbose",  0, 2, "show technical data. vv - show full certificates data"),
        arg_lit0("pP",  "plain",    "send plain ASCII to challenge and application parameters instead of HEX"),
        arg_lit0("tT",  "tlv",      "Show DER certificate contents in TLV representation"),
        arg_str0("jJ",  "json",     "fido.json", "JSON input / output file name for parameters."),
        arg_str0(NULL,  NULL,       "<HEX/ASCII challenge parameter (32b HEX/1..16 chars)>", NULL),
        arg_str0(NULL,  NULL,       "<HEX/ASCII application parameter (32b HEX/1..16 chars)>", NULL),
        arg_param_end
    };
    CLIExecWithReturn(cmd, argtable, true);

    bool APDULogging = arg_get_lit(1);
    bool verbose = arg_get_lit(2);
    bool verbose2 = arg_get_lit(2) > 1;
    bool paramsPlain = arg_get_lit(3);
    bool showDERTLV = arg_get_lit(4);

    char fname[250] = {0};
    bool err;
    root = OpenJson(5, fname, argtable, &err);
    if (err)
        return 1;
    if (root) {
        size_t jlen;
        JsonLoadBufAsHex(root, "$.ChallengeParam", data, 32, &jlen);
        JsonLoadBufAsHex(root, "$.ApplicationParam", &data[32], 32, &jlen);
    }

    if (paramsPlain) {
        memset(cdata, 0x00, 32);
        CLIGetStrWithReturn(6, cdata, &chlen);
        if (chlen > 16) {
            PrintAndLog("ERROR: challenge parameter length in ASCII mode must be less than 16 chars instead of: %d", chlen);
            return 1;
        }
    } else {
        CLIGetHexWithReturn(6, cdata, &chlen);
        if (chlen && chlen != 32) {
            PrintAndLog("ERROR: challenge parameter length must be 32 bytes only.");
            return 1;
        }
    }
    if (chlen)
        memmove(data, cdata, 32);


    if (paramsPlain) {
        memset(adata, 0x00, 32);
        CLIGetStrWithReturn(7, adata, &applen);
        if (applen > 16) {
            PrintAndLog("ERROR: application parameter length in ASCII mode must be less than 16 chars instead of: %d", applen);
            return 1;
        }
    } else {
        CLIGetHexWithReturn(7, adata, &applen);
        if (applen && applen != 32) {
            PrintAndLog("ERROR: application parameter length must be 32 bytes only.");
            return 1;
        }
    }
    if (applen)
        memmove(&data[32], adata, 32);

    CLIParserFree();

    SetAPDULogging(APDULogging);

    // challenge parameter [32 bytes] - The challenge parameter is the SHA-256 hash of the Client Data, a stringified JSON data structure that the FIDO Client prepares
    // application parameter [32 bytes] - The application parameter is the SHA-256 hash of the UTF-8 encoding of the application identity

    uint8_t buf[2048] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    DropField();
    int res = FIDOSelect(true, true, buf, sizeof(buf), &len, &sw);

    if (res) {
        PrintAndLog("Can't select authenticator. res=%x. Exit...", res);
        DropField();
        return res;
    }

    if (sw != 0x9000) {
        PrintAndLog("Can't select FIDO application. APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return 2;
    }

    res = FIDORegister(data, buf,  sizeof(buf), &len, &sw);
    DropField();
    if (res) {
        PrintAndLog("Can't execute register command. res=%x. Exit...", res);
        return res;
    }

    if (sw != 0x9000) {
        PrintAndLog("ERROR execute register command. APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return 3;
    }

    PrintAndLog("");
    if (APDULogging)
        PrintAndLog("---------------------------------------------------------------");
    PrintAndLog("data len: %d", len);
    if (verbose2) {
        PrintAndLog("--------------data----------------------");
        dump_buffer((const unsigned char *)buf, len, NULL, 0);
        PrintAndLog("--------------data----------------------");
    }

    if (buf[0] != 0x05) {
        PrintAndLog("ERROR: First byte must be 0x05, but it %2x", buf[0]);
        return 5;
    }
    PrintAndLog("User public key: %s", sprint_hex(&buf[1], 65));

    uint8_t keyHandleLen = buf[66];
    PrintAndLog("Key handle[%d]: %s", keyHandleLen, sprint_hex(&buf[67], keyHandleLen));

    int derp = 67 + keyHandleLen;
    int derLen = (buf[derp + 2] << 8) + buf[derp + 3] + 4;
    if (verbose2) {
        PrintAndLog("DER certificate[%d]:\n------------------DER-------------------", derLen);
        dump_buffer_simple((const unsigned char *)&buf[derp], derLen, NULL);
        PrintAndLog("\n----------------DER---------------------");
    } else {
        if (verbose)
            PrintAndLog("------------------DER-------------------");
        PrintAndLog("DER certificate[%d]: %s...", derLen, sprint_hex(&buf[derp], 20));
    }

    // check and print DER certificate
    uint8_t public_key[65] = {0};

    // print DER certificate in TLV view
    if (showDERTLV) {
        PrintAndLog("----------------DER TLV-----------------");
        asn1_print(&buf[derp], derLen, "  ");
        PrintAndLog("----------------DER TLV-----------------");
    }

    FIDOCheckDERAndGetKey(&buf[derp], derLen, verbose, public_key, sizeof(public_key));

    // get hash
    int hashp = 1 + 65 + 1 + keyHandleLen + derLen;
    PrintAndLog("Hash[%d]: %s", len - hashp, sprint_hex(&buf[hashp], len - hashp));

    // check ANSI X9.62 format ECDSA signature (on P-256)
    uint8_t rval[300] = {0};
    uint8_t sval[300] = {0};
    res = ecdsa_asn1_get_signature(&buf[hashp], len - hashp, rval, sval);
    if (!res) {
        if (verbose) {
            PrintAndLog("  r: %s", sprint_hex(rval, 32));
            PrintAndLog("  s: %s", sprint_hex(sval, 32));
        }

        uint8_t xbuf[4096] = {0};
        size_t xbuflen = 0;
        res = FillBuffer(xbuf, sizeof(xbuf), &xbuflen,
                         "\x00", 1,
                         &data[32], 32,           // application parameter
                         &data[0], 32,            // challenge parameter
                         &buf[67], keyHandleLen,  // keyHandle
                         &buf[1], 65,             // user public key
                         NULL, 0);
        //PrintAndLog("--xbuf(%d)[%d]: %s", res, xbuflen, sprint_hex(xbuf, xbuflen));
        res = ecdsa_signature_verify(public_key, xbuf, xbuflen, &buf[hashp], len - hashp);
        if (res) {
            if (res == -0x4e00) {
                PrintAndLog("Signature is NOT VALID.");
            } else {
                PrintAndLog("Other signature check error: %x %s", (res < 0) ? -res : res, ecdsa_get_error(res));
            }
        } else {
            PrintAndLog("Signature is OK.");
        }

    } else {
        PrintAndLog("Invalid signature. res=%d.", res);
    }

    PrintAndLog("\nauth command: ");
    printf("hf fido auth %s%s", paramsPlain ? "-p " : "", sprint_hex_inrow(&buf[67], keyHandleLen));
    if (chlen || applen)
        printf(" %s", paramsPlain ? (char *)cdata : sprint_hex_inrow(cdata, 32));
    if (applen)
        printf(" %s", paramsPlain ? (char *)adata : sprint_hex_inrow(adata, 32));
    printf("\n");

    if (root) {
        JsonSaveBufAsHex(root, "ChallengeParam", data, 32);
        JsonSaveBufAsHex(root, "ApplicationParam", &data[32], 32);
        JsonSaveBufAsHexCompact(root, "PublicKey", &buf[1], 65);
        JsonSaveInt(root, "KeyHandleLen", keyHandleLen);
        JsonSaveBufAsHexCompact(root, "KeyHandle", &buf[67], keyHandleLen);
        JsonSaveBufAsHexCompact(root, "DER", &buf[67 + keyHandleLen], derLen);

        res = json_dump_file(root, fname, JSON_INDENT(2));
        if (res) {
            PrintAndLog("ERROR: can't save the file: %s", fname);
            return 200;
        }
        PrintAndLog("File `%s` saved.", fname);

        // free json object
        json_decref(root);
    }

    return 0;
};

int CmdHFFidoAuthenticate(const char *cmd) {
    uint8_t data[512] = {0};
    uint8_t hdata[250] = {0};
    bool public_key_loaded = false;
    uint8_t public_key[65] = {0};
    int hdatalen = 0;
    uint8_t keyHandleLen = 0;
    json_t *root = NULL;

    CLIParserInit("hf fido auth",
                  "Initiate a U2F token authentication. Needs key handle and two 32-byte hash number. \nkey handle(var 0..255), challenge parameter (32b) and application parameter (32b).",
                  "Usage:\n\thf fido auth 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f -> execute command with 2 parameters, filled 0x00 and key handle\n"
                  "\thf fido auth 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f "
                  "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f -> execute command with parameters");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("aA",  "apdu",     "show APDU reqests and responses"),
        arg_lit0("vV",  "verbose",  "show technical data"),
        arg_lit0("pP",  "plain",    "send plain ASCII to challenge and application parameters instead of HEX"),
        arg_rem("default mode:",    "dont-enforce-user-presence-and-sign"),
        arg_lit0("uU",  "user",     "mode: enforce-user-presence-and-sign"),
        arg_lit0("cC",  "check",    "mode: check-only"),
        arg_str0("jJ",  "json",     "fido.json", "JSON input / output file name for parameters."),
        arg_str0("kK",  "key",      "public key to verify signature", NULL),
        arg_str0(NULL,  NULL,       "<HEX key handle (var 0..255b)>", NULL),
        arg_str0(NULL,  NULL,       "<HEX/ASCII challenge parameter (32b HEX/1..16 chars)>", NULL),
        arg_str0(NULL,  NULL,       "<HEX/ASCII application parameter (32b HEX/1..16 chars)>", NULL),
        arg_param_end
    };
    CLIExecWithReturn(cmd, argtable, true);

    bool APDULogging = arg_get_lit(1);
    bool verbose = arg_get_lit(2);
    bool paramsPlain = arg_get_lit(3);
    uint8_t controlByte = 0x08;
    if (arg_get_lit(5))
        controlByte = 0x03;
    if (arg_get_lit(6))
        controlByte = 0x07;

    char fname[250] = {0};
    bool err;
    root = OpenJson(7, fname, argtable, &err);
    if (err)
        return 1;
    if (root) {
        size_t jlen;
        JsonLoadBufAsHex(root, "$.ChallengeParam", data, 32, &jlen);
        JsonLoadBufAsHex(root, "$.ApplicationParam", &data[32], 32, &jlen);
        JsonLoadBufAsHex(root, "$.KeyHandle", &data[65], 512 - 67, &jlen);
        keyHandleLen = jlen & 0xff;
        data[64] = keyHandleLen;
        JsonLoadBufAsHex(root, "$.PublicKey", public_key, 65, &jlen);
        public_key_loaded = (jlen > 0);
    }

    // public key
    CLIGetHexWithReturn(8, hdata, &hdatalen);
    if (hdatalen && hdatalen != 65) {
        PrintAndLog("ERROR: public key length must be 65 bytes only.");
        return 1;
    }
    if (hdatalen) {
        memmove(public_key, hdata, hdatalen);
        public_key_loaded = true;
    }

    CLIGetHexWithReturn(9, hdata, &hdatalen);
    if (hdatalen > 255) {
        PrintAndLog("ERROR: application parameter length must be less than 255.");
        return 1;
    }
    if (hdatalen) {
        keyHandleLen = hdatalen;
        data[64] = keyHandleLen;
        memmove(&data[65], hdata, keyHandleLen);
    }

    if (paramsPlain) {
        memset(hdata, 0x00, 32);
        CLIGetStrWithReturn(9, hdata, &hdatalen);
        if (hdatalen > 16) {
            PrintAndLog("ERROR: challenge parameter length in ASCII mode must be less than 16 chars instead of: %d", hdatalen);
            return 1;
        }
    } else {
        CLIGetHexWithReturn(10, hdata, &hdatalen);
        if (hdatalen && hdatalen != 32) {
            PrintAndLog("ERROR: challenge parameter length must be 32 bytes only.");
            return 1;
        }
    }
    if (hdatalen)
        memmove(data, hdata, 32);

    if (paramsPlain) {
        memset(hdata, 0x00, 32);
        CLIGetStrWithReturn(11, hdata, &hdatalen);
        if (hdatalen > 16) {
            PrintAndLog("ERROR: application parameter length in ASCII mode must be less than 16 chars instead of: %d", hdatalen);
            return 1;
        }
    } else {
        CLIGetHexWithReturn(10, hdata, &hdatalen);
        if (hdatalen && hdatalen != 32) {
            PrintAndLog("ERROR: application parameter length must be 32 bytes only.");
            return 1;
        }
    }
    if (hdatalen)
        memmove(&data[32], hdata, 32);

    CLIParserFree();

    SetAPDULogging(APDULogging);

    // (in parameter) conrtol byte 0x07 - check only, 0x03 - user presense + cign. 0x08 - sign only
    // challenge parameter [32 bytes]
    // application parameter [32 bytes]
    // key handle length [1b] = N
    // key handle [N]

    uint8_t datalen = 32 + 32 + 1 + keyHandleLen;

    uint8_t buf[2048] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    DropField();
    int res = FIDOSelect(true, true, buf, sizeof(buf), &len, &sw);

    if (res) {
        PrintAndLog("Can't select authenticator. res=%x. Exit...", res);
        DropField();
        return res;
    }

    if (sw != 0x9000) {
        PrintAndLog("Can't select FIDO application. APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return 2;
    }

    res = FIDOAuthentication(data, datalen, controlByte,  buf,  sizeof(buf), &len, &sw);
    DropField();
    if (res) {
        PrintAndLog("Can't execute authentication command. res=%x. Exit...", res);
        return res;
    }

    if (sw != 0x9000) {
        PrintAndLog("ERROR execute authentication command. APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return 3;
    }

    PrintAndLog("---------------------------------------------------------------");
    PrintAndLog("User presence: %s", (buf[0] ? "verified" : "not verified"));
    uint32_t cntr = (uint32_t)bytes_to_num(&buf[1], 4);
    PrintAndLog("Counter: %d", cntr);
    PrintAndLog("Hash[%d]: %s", len - 5, sprint_hex(&buf[5], len - 5));

    // check ANSI X9.62 format ECDSA signature (on P-256)
    uint8_t rval[300] = {0};
    uint8_t sval[300] = {0};
    res = ecdsa_asn1_get_signature(&buf[5], len - 5, rval, sval);
    if (!res) {
        if (verbose) {
            PrintAndLog("  r: %s", sprint_hex(rval, 32));
            PrintAndLog("  s: %s", sprint_hex(sval, 32));
        }
        if (public_key_loaded) {
            uint8_t xbuf[4096] = {0};
            size_t xbuflen = 0;
            res = FillBuffer(xbuf, sizeof(xbuf), &xbuflen,
                             &data[32], 32, // application parameter
                             &buf[0], 1,    // user presence
                             &buf[1], 4,    // counter
                             data, 32,      // challenge parameter
                             NULL, 0);
            //PrintAndLog("--xbuf(%d)[%d]: %s", res, xbuflen, sprint_hex(xbuf, xbuflen));
            res = ecdsa_signature_verify(public_key, xbuf, xbuflen, &buf[5], len - 5);
            if (res) {
                if (res == -0x4e00) {
                    PrintAndLog("Signature is NOT VALID.");
                } else {
                    PrintAndLog("Other signature check error: %x %s", (res < 0) ? -res : res, ecdsa_get_error(res));
                }
            } else {
                PrintAndLog("Signature is OK.");
            }
        } else {
            PrintAndLog("No public key provided. can't check signature.");
        }
    } else {
        PrintAndLog("Invalid signature. res=%d.", res);
    }

    if (root) {
        JsonSaveBufAsHex(root, "ChallengeParam", data, 32);
        JsonSaveBufAsHex(root, "ApplicationParam", &data[32], 32);
        JsonSaveInt(root, "KeyHandleLen", keyHandleLen);
        JsonSaveBufAsHexCompact(root, "KeyHandle", &data[65], keyHandleLen);
        JsonSaveInt(root, "Counter", cntr);

        res = json_dump_file(root, fname, JSON_INDENT(2));
        if (res) {
            PrintAndLog("ERROR: can't save the file: %s", fname);
            return 200;
        }
        PrintAndLog("File `%s` saved.", fname);

        // free json object
        json_decref(root);
    }
    return 0;
};

void CheckSlash(char *fileName) {
    if ((fileName[strlen(fileName) - 1] != '/') &&
            (fileName[strlen(fileName) - 1] != '\\'))
        strcat(fileName, "/");
}

int GetExistsFileNameJson(char *prefixDir, char *reqestedFileName, char *fileName) {
    fileName[0] = 0x00;
    strcpy(fileName, get_my_executable_directory());
    CheckSlash(fileName);

    strcat(fileName, prefixDir);
    CheckSlash(fileName);

    strcat(fileName, reqestedFileName);
    if (!strstr(fileName, ".json"))
        strcat(fileName, ".json");

    if (access(fileName, F_OK) < 0) {
        strcpy(fileName, get_my_executable_directory());
        CheckSlash(fileName);

        strcat(fileName, reqestedFileName);
        if (!strstr(fileName, ".json"))
            strcat(fileName, ".json");

        if (access(fileName, F_OK) < 0) {
            return 1; // file not found
        }
    }
    return 0;
}

int CmdHFFido2MakeCredential(const char *cmd) {
    json_error_t error;
    json_t *root = NULL;
    char fname[300] = {0};

    CLIParserInit("hf fido make",
                  "Execute a FIDO2 Make Credentional command. Needs json file with parameters. Sample file `fido2.json`. File can be placed in proxmark directory or in `proxmark/fido` directory.",
                  "Usage:\n\thf fido make -> execute command default parameters file `fido2.json`\n"
                  "\thf fido make test.json -> execute command with parameters file `text.json`");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("aA",  "apdu",     "show APDU reqests and responses"),
        arg_litn("vV",  "verbose",  0, 2, "show technical data. vv - show full certificates data"),
        arg_lit0("tT",  "tlv",      "Show DER certificate contents in TLV representation"),
        arg_lit0("cC",  "cbor",     "show CBOR decoded data"),
        arg_str0(NULL,  NULL,       "<json file name>", "JSON input / output file name for parameters. Default `fido2.json`"),
        arg_param_end
    };
    CLIExecWithReturn(cmd, argtable, true);

    bool APDULogging = arg_get_lit(1);
    bool verbose = arg_get_lit(2);
    bool verbose2 = arg_get_lit(2) > 1;
    bool showDERTLV = arg_get_lit(3);
    bool showCBOR = arg_get_lit(4);

    uint8_t jsonname[250] = {0};
    char *cjsonname = (char *)jsonname;
    int jsonnamelen = 0;
    CLIGetStrWithReturn(5, jsonname, &jsonnamelen);

    if (!jsonnamelen) {
        strcat(cjsonname, "fido2");
        jsonnamelen = strlen(cjsonname);
    }

    CLIParserFree();

    SetAPDULogging(APDULogging);

    int res = GetExistsFileNameJson("fido", cjsonname, fname);
    if (res) {
        PrintAndLog("ERROR: Can't found the json file.");
        return res;
    }
    PrintAndLog("fname: %s\n", fname);
    root = json_load_file(fname, 0, &error);
    if (!root) {
        PrintAndLog("ERROR: json error on line %d: %s", error.line, error.text);
        return 1;
    }

    uint8_t data[2048] = {0};
    size_t datalen = 0;
    uint8_t buf[2048] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    DropField();
    res = FIDOSelect(true, true, buf, sizeof(buf), &len, &sw);

    if (res) {
        PrintAndLog("Can't select authenticator. res=%x. Exit...", res);
        DropField();
        return res;
    }

    if (sw != 0x9000) {
        PrintAndLog("Can't select FIDO application. APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return 2;
    }

    res = FIDO2CreateMakeCredentionalReq(root, data, sizeof(data), &datalen);
    if (res)
        return res;

    if (showCBOR) {
        PrintAndLog("CBOR make credentional request:");
        PrintAndLog("---------------- CBOR ------------------");
        TinyCborPrintFIDOPackage(fido2CmdMakeCredential, false, data, datalen);
        PrintAndLog("---------------- CBOR ------------------");
    }

    res = FIDO2MakeCredential(data, datalen, buf,  sizeof(buf), &len, &sw);
    DropField();
    if (res) {
        PrintAndLog("Can't execute make credential command. res=%x. Exit...", res);
        return res;
    }

    if (sw != 0x9000) {
        PrintAndLog("ERROR execute make credential command. APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return 3;
    }

    if (buf[0]) {
        PrintAndLog("FIDO2 make credential error: %d - %s", buf[0], fido2GetCmdErrorDescription(buf[0]));
        return 0;
    }

    PrintAndLog("MakeCredential result (%d b) OK.", len);
    if (showCBOR) {
        PrintAndLog("CBOR make credentional response:");
        PrintAndLog("---------------- CBOR ------------------");
        TinyCborPrintFIDOPackage(fido2CmdMakeCredential, true, &buf[1], len - 1);
        PrintAndLog("---------------- CBOR ------------------");
    }

    // parse returned cbor
    FIDO2MakeCredentionalParseRes(root, &buf[1], len - 1, verbose, verbose2, showCBOR, showDERTLV);

    if (root) {
        res = json_dump_file(root, fname, JSON_INDENT(2));
        if (res) {
            PrintAndLog("ERROR: can't save the file: %s", fname);
            return 200;
        }
        PrintAndLog("File `%s` saved.", fname);
    }

    json_decref(root);

    return 0;
};

int CmdHFFido2GetAssertion(const char *cmd) {
    json_error_t error;
    json_t *root = NULL;
    char fname[300] = {0};

    CLIParserInit("hf fido assert",
                  "Execute a FIDO2 Get Assertion command. Needs json file with parameters. Sample file `fido2.json`. File can be placed in proxmark directory or in `proxmark/fido` directory.",
                  "Usage:\n\thf fido assert -> execute command default parameters file `fido2.json`\n"
                  "\thf fido assert test.json -l -> execute command with parameters file `text.json` and add to request CredentialId");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("aA",  "apdu",     "show APDU reqests and responses"),
        arg_litn("vV",  "verbose",  0, 2, "show technical data. vv - show full certificates data"),
        arg_lit0("cC",  "cbor",     "show CBOR decoded data"),
        arg_lit0("lL",  "list",     "add CredentialId from json to allowList. Needs if `rk` option is `false` (authenticator don't store credential to its memory)"),
        arg_str0(NULL,  NULL,       "<json file name>", "JSON input / output file name for parameters. Default `fido2.json`"),
        arg_param_end
    };
    CLIExecWithReturn(cmd, argtable, true);

    bool APDULogging = arg_get_lit(1);
    bool verbose = arg_get_lit(2);
    bool verbose2 = arg_get_lit(2) > 1;
    bool showCBOR = arg_get_lit(3);
    bool createAllowList = arg_get_lit(4);

    uint8_t jsonname[250] = {0};
    char *cjsonname = (char *)jsonname;
    int jsonnamelen = 0;
    CLIGetStrWithReturn(5, jsonname, &jsonnamelen);

    if (!jsonnamelen) {
        strcat(cjsonname, "fido2");
        jsonnamelen = strlen(cjsonname);
    }

    CLIParserFree();

    SetAPDULogging(APDULogging);

    int res = GetExistsFileNameJson("fido", "fido2", fname);
    if (res) {
        PrintAndLog("ERROR: Can't found the json file.");
        return res;
    }
    PrintAndLog("fname: %s\n", fname);
    root = json_load_file(fname, 0, &error);
    if (!root) {
        PrintAndLog("ERROR: json error on line %d: %s", error.line, error.text);
        return 1;
    }

    uint8_t data[2048] = {0};
    size_t datalen = 0;
    uint8_t buf[2048] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    DropField();
    res = FIDOSelect(true, true, buf, sizeof(buf), &len, &sw);

    if (res) {
        PrintAndLog("Can't select authenticator. res=%x. Exit...", res);
        DropField();
        return res;
    }

    if (sw != 0x9000) {
        PrintAndLog("Can't select FIDO application. APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return 2;
    }

    res = FIDO2CreateGetAssertionReq(root, data, sizeof(data), &datalen, createAllowList);
    if (res)
        return res;

    if (showCBOR) {
        PrintAndLog("CBOR get assertion request:");
        PrintAndLog("---------------- CBOR ------------------");
        TinyCborPrintFIDOPackage(fido2CmdGetAssertion, false, data, datalen);
        PrintAndLog("---------------- CBOR ------------------");
    }

    res = FIDO2GetAssertion(data, datalen, buf,  sizeof(buf), &len, &sw);
    DropField();
    if (res) {
        PrintAndLog("Can't execute get assertion command. res=%x. Exit...", res);
        return res;
    }

    if (sw != 0x9000) {
        PrintAndLog("ERROR execute get assertion command. APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return 3;
    }

    if (buf[0]) {
        PrintAndLog("FIDO2 get assertion error: %d - %s", buf[0], fido2GetCmdErrorDescription(buf[0]));
        return 0;
    }

    PrintAndLog("GetAssertion result (%d b) OK.", len);
    if (showCBOR) {
        PrintAndLog("CBOR get assertion response:");
        PrintAndLog("---------------- CBOR ------------------");
        TinyCborPrintFIDOPackage(fido2CmdGetAssertion, true, &buf[1], len - 1);
        PrintAndLog("---------------- CBOR ------------------");
    }

    // parse returned cbor
    FIDO2GetAssertionParseRes(root, &buf[1], len - 1, verbose, verbose2, showCBOR);

    if (root) {
        res = json_dump_file(root, fname, JSON_INDENT(2));
        if (res) {
            PrintAndLog("ERROR: can't save the file: %s", fname);
            return 200;
        }
        PrintAndLog("File `%s` saved.", fname);
    }

    json_decref(root);

    return 0;
};

static command_t CommandTable[] = {
    {"help",             CmdHelp,                    1, "This help."},
    {"info",             CmdHFFidoInfo,              0, "Info about FIDO tag."},
    {"reg",              CmdHFFidoRegister,          0, "FIDO U2F Registration Message."},
    {"auth",             CmdHFFidoAuthenticate,      0, "FIDO U2F Authentication Message."},
    {"make",             CmdHFFido2MakeCredential,   0, "FIDO2 MakeCredential command."},
    {"assert",           CmdHFFido2GetAssertion,     0, "FIDO2 GetAssertion command."},
    {NULL,               NULL,                       0, NULL}
};

int CmdHFFido(const char *Cmd) {
    (void)WaitForResponseTimeout(CMD_ACK, NULL, 100);
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}
