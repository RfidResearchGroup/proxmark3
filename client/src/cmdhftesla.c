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
// High frequency ISO14443A / TESLA  commands
//-----------------------------------------------------------------------------

#include "cmdhftesla.h"
#include <ctype.h>
#include <string.h>
#include "cmdparser.h"         // command_t
#include "comms.h"             // clearCommandBuffer
#include "cmdtrace.h"
#include "cliparser.h"
#include "cmdhf14a.h"
#include "crypto/asn1utils.h"  // ASN1 decode / print
#include "protocols.h"         // definitions of ISO14A/7816 protocol
#include "iso7816/apduinfo.h"  // GetAPDUCodeDescription
#include "commonutil.h"        // get_sw
#include "protocols.h"         // ISO7816 APDU return co-des
#include "ui.h"
#include "cmdhf14a.h"          // apdu chaining

#define TIMEOUT 2000
#define MAX_CERT_SIZE 768

static int CmdHelp(const char *Cmd);

/**
 *  0x80 0x00 0x00 0x00      - get interface object
    0x80 0x01 0x00 0x00      - load data from storage
    0x80 0x02 KEY_INDEX 0x00 - initialize key pair
    0x80 0x03 KEY_INDEX 0x00 - generate key pair
    0x80 0x04 KEY_INDEX 0x00 - get public key
    0x80 0x05 CRT_INDEX 0x00 - load certificate
    0x80 0x06 CRT_INDEX 0x00 - get certificate
    0x80 0x07 0x00 0x00      - get version
    0x80 0x08 0x00 0x00      - confirm prepersonalization
    0x80 0x10 KEY_INDEX 0x00 - sign challenge
    0x80 0x11 KEY_INDEX 0x00 - dh key exchange

*/

// TESLA
static int info_hf_tesla(bool parse_certs) {

    bool activate_field = true;
    bool keep_field_on = true;
    uint8_t response[MAX_CERT_SIZE]; // Some cards have pretty large certificates
    int resplen = 0;


    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
    PrintAndLogEx(NORMAL, "");

    // ---------------  Select TESLA application ----------------
    uint8_t aSELECT_AID[80];
    int aSELECT_AID_n = 0;
    param_gethex_to_eol("00a404000a7465736c614c6f67696300", 0, aSELECT_AID, sizeof(aSELECT_AID), &aSELECT_AID_n);
    int res = ExchangeAPDU14a(aSELECT_AID, aSELECT_AID_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return PM3_ESOFT;
    }

    activate_field = false;
    uint16_t sw = get_sw(response, resplen);

    if ((resplen < 2) || (sw != ISO7816_OK)) {

        param_gethex_to_eol("00a404000af465736c614c6f67696300", 0, aSELECT_AID, sizeof(aSELECT_AID), &aSELECT_AID_n);
        res = ExchangeAPDU14a(aSELECT_AID, aSELECT_AID_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
        if (res != PM3_SUCCESS) {
            DropField();
            return res;
        }
    }

    if ((resplen < 2) || (sw != ISO7816_OK)) {
        PrintAndLogEx(ERR, "Selecting TESLA aid failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        // DropField();
        // return PM3_ESOFT;
    }


    keep_field_on = true;


    // ---------------  ECDH public key file reading ----------------
    uint8_t pk[4][65] = {{0}};

    for (uint8_t i = 0; i < 4; i++) {

        uint8_t aSELECT_PK[5] = {0x80, 0x04, i, 0x00, 0x00};
        res = ExchangeAPDU14a(aSELECT_PK, sizeof(aSELECT_PK), activate_field, keep_field_on, response, sizeof(response), &resplen);
        if (res != PM3_SUCCESS) {
            continue;
        }

        sw = get_sw(response, resplen);
        if (sw == ISO7816_OK) {
            memcpy(pk[i], response, resplen - 2);
        }
    }

    uint8_t aREAD_FORM_FACTOR[30];
    int aREAD_FORM_FACTOR_n = 0;
    param_gethex_to_eol("8014000000", 0, aREAD_FORM_FACTOR, sizeof(aREAD_FORM_FACTOR), &aREAD_FORM_FACTOR_n);
    res = ExchangeAPDU14a(aREAD_FORM_FACTOR, aREAD_FORM_FACTOR_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "reading FORM FACTOR file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    // store form factor for later
    uint8_t form_factor[resplen - 2];
    memcpy(form_factor, response, sizeof(form_factor));

    uint8_t aREAD_VERSION[30];
    int aREAD_VERSION_n = 0;
    param_gethex_to_eol("80170000", 0, aREAD_VERSION, sizeof(aREAD_VERSION), &aREAD_VERSION_n);
    res = ExchangeAPDU14a(aREAD_VERSION, aREAD_VERSION_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    uint8_t version[resplen - 2];

    sw = get_sw(response, resplen);
    if (sw == ISO7816_OK) {
        // store version for later
        memcpy(version, response, sizeof(version));
    }

    // ---------------  CERT reading ----------------
    Set_apdu_in_framing(true);
    for (uint8_t i = 0; i < 5; i++) {

        // First, read the certificate length
        uint8_t aSELECT_CERT[PM3_CMD_DATA_SIZE] = {0x80, 0x06, i, 0x00, 0x04};
        int aSELECT_CERT_n = 5;

        res = ExchangeAPDU14a(aSELECT_CERT, aSELECT_CERT_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Could not read certificate %i length", i);
            continue;
        }

        sw = get_sw(response, resplen);
        bool cert_len_present = false;

        if (sw == ISO7816_OK && resplen > 3) {
            uint16_t cert_len = response[0] << 8 | response[1];
            PrintAndLogEx(INFO, "CERT # %i", i);
            if (cert_len == 0x3082) {
                cert_len = (response[2] << 8 | response[3]) + 4;
                PrintAndLogEx(INFO, "Length (calculated from ASN.1): %i", cert_len);
            } else {
                PrintAndLogEx(INFO, "Length (included at start of cert slot): %i", cert_len);
                cert_len_present = true;
            }
            cert_len += 2; // Add 2 bytes for the 9000 at the end
            // Read the entire cert (extended length APDU)
            aSELECT_CERT[4] = 0x00;
            aSELECT_CERT[5] = (cert_len >> 8) & 0xff;
            aSELECT_CERT[6] = cert_len & 0xff;
            aSELECT_CERT_n = 7;

            res = ExchangeAPDU14a(aSELECT_CERT, aSELECT_CERT_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
            if (res != PM3_SUCCESS) {
                PrintAndLogEx(ERR, "Could not read certificate %i (return code %i)", i, res);
                continue;
            }

            sw = get_sw(response, resplen);
            if (sw == ISO7816_OK) {
                // save CERT for later
                uint8_t cert[MAX_CERT_SIZE] = {0};
                memcpy(cert, response, resplen - 2);

                PrintAndLogEx(INFO, "%s", sprint_hex_inrow(cert + (cert_len_present ? 2 : 0), resplen - 2));
                if (parse_certs) {
                    asn1_print(cert + (cert_len_present ? 2 : 0), cert_len - 2, "  ");
                }
            }
        } else if (sw == 0x6f17) {
            PrintAndLogEx(INFO, "CERT # %i", i);
            PrintAndLogEx(INFO, "No certificate in slot %i", i);
        } else {
            PrintAndLogEx(ERR, "Could not read certificate %i", i);
        }
    }
    Set_apdu_in_framing(false);

    uint8_t aAUTH[90];
    int aAUTH_n = 0;
    // vehicle public key ,  16 byte CHALLENGE
    // 00112233445566778899AABBCCDDEEFF
    // 0x51 = 81 dec
    // param_gethex_to_eol("8011000051 046F08AE62526ABB5690643458152AC963CF5D7C113949F3C2453D1DDC6E4385B430523524045A22F5747BF236F1B5F60F0EA32DC2B8276D75ACDE9813EF77C330  00112233445566778899AABBCCDDEEFF", 0, aAUTH, sizeof(aAUTH), &aAUTH_n);
    param_gethex_to_eol("8011000051046F08AE62526ABB5690643458152AC963CF5D7C113949F3C2453D1DDC6E4385B430523524045A22F5747BF236F1B5F60F0EA32DC2B8276D75ACDE9813EF77C33000112233445566778899AABBCCDDEEFF00", 0, aAUTH, sizeof(aAUTH), &aAUTH_n);
    res = ExchangeAPDU14a(aAUTH, aAUTH_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Could not exchange authentication challenge");
    } else {

        uint8_t auth[resplen - 2];

        sw = get_sw(response, resplen);
        if (sw == ISO7816_OK) {
            // store CHALLENGE for later
            memcpy(auth, response, sizeof(auth));
        }
        PrintAndLogEx(INFO, "CHALL......... %s", sprint_hex_inrow(auth, sizeof(auth)));
    }

    keep_field_on = false;
    DropField(); // No further interaction with the card is needed

    PrintAndLogEx(INFO, "PUBLIC KEY");
    for (int i = 0; i < 4; i++) {
        PrintAndLogEx(INFO, "%d - %s", i, sprint_hex_inrow(pk[i], 65));
    }
    PrintAndLogEx(INFO, "Form factor... %s " NOLF, sprint_hex_inrow(form_factor, sizeof(form_factor)));

    uint16_t form_factor_value = MemBeToUint2byte(form_factor);

    switch (form_factor_value) {
        case 0x0001:
            PrintAndLogEx(NORMAL, "(NXP P60 card)");
            break;
        case 0x0002:
            PrintAndLogEx(NORMAL, "(NXP P71 card)");
            break;
        case 0x0021:
            PrintAndLogEx(NORMAL, "(Model 3 fob without passive entry)");
            break;
        case 0x0022:
            PrintAndLogEx(NORMAL, "(Model 3 fob with passive entry)");
            break;
        case 0x0023:
        case 0x0025:
        case 0x0026:
            PrintAndLogEx(NORMAL, "(Model S fob)");
            break;
        case 0x0024:
            PrintAndLogEx(NORMAL, "(Model X fob)");
            break;
        case 0x0031:
            PrintAndLogEx(NORMAL, "(Android phone app with NFC)");
            break;
        case 0x0032:
            PrintAndLogEx(NORMAL, "(iOS phone app with NFC)");
            break;
        default:
            PrintAndLogEx(NORMAL, "(Unknown)");
            break;
    }

    if (sizeof(version) > 0) {
        PrintAndLogEx(INFO, "Version....... %s", sprint_hex_inrow(version, sizeof(version)));
    }

    PrintAndLogEx(INFO, "Fingerprint");
    if ((memcmp(pk[0], pk[1], 65) == 0)) {
        PrintAndLogEx(INFO, "  GaussKey detected");
    }
    //
    return PM3_SUCCESS;
}

// menu command to get and print all info known about any known ST25TA tag
static int CmdHFTeslaInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf telsa info",
                  "Get info about TESLA Key tag",
                  "hf tesla info"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("p", "parse", "Parse the certificates as ASN.1"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool parse_certs = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);
    return info_hf_tesla(parse_certs);
}

static int CmdHFTeslaList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf tesla", "7816");
}

static command_t CommandTable[] = {
    {"help",     CmdHelp,              AlwaysAvailable, "This help"},
    {"info",     CmdHFTeslaInfo,       IfPm3Iso14443a,  "Tag information"},
    {"list",     CmdHFTeslaList,       AlwaysAvailable, "List ISO 14443A/7816 history"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFTESLA(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
