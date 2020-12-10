//-----------------------------------------------------------------------------
// Copyright (C) 2020 A. Ozkal
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency Electronic Machine Readable Travel Document commands
//-----------------------------------------------------------------------------

// This code is heavily based on mrpkey.py of RFIDIOt

#include "cmdhfemrtd.h"
#include <ctype.h>
#include "fileutils.h"
#include "cmdparser.h"              // command_t
#include "comms.h"                  // clearCommandBuffer
#include "cmdtrace.h"
#include "cliparser.h"
#include "crc16.h"
#include "cmdhf14a.h"
#include "protocols.h"              // definitions of ISO14A/7816 protocol
#include "emv/apduinfo.h"           // GetAPDUCodeDescription
#include "sha1.h"                   // KSeed calculation etc
#include "mifare/desfire_crypto.h"  // des_encrypt/des_decrypt
#include "des.h"                    // mbedtls_des_key_set_parity

#define TIMEOUT 2000

// ISO7816 commands
#define SELECT "A4"
#define EXTERNAL_AUTHENTICATE "82"
#define GET_CHALLENGE "84"
#define READ_BINARY "B0"
#define P1_SELECT_BY_EF "02"
#define P1_SELECT_BY_NAME "04"
#define P2_PROPRIETARY "0C"

// File IDs
#define EF_CARDACCESS "011C"
#define EF_COM "011E"
#define EF_DG1 "0101"

// App IDs
#define AID_MRTD "A0000002471001"

static int CmdHelp(const char *Cmd);

static uint16_t get_sw(uint8_t *d, uint8_t n) {
    if (n < 2)
        return 0;

    n -= 2;
    return d[n] * 0x0100 + d[n + 1];
}

static int exchange_commands(const char *cmd, uint8_t *dataout, int *dataoutlen, bool activate_field, bool keep_field_on) {
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;

    PrintAndLogEx(INFO, "Sending: %s", cmd);

    uint8_t aCMD[80];
    int aCMD_n = 0;
    param_gethex_to_eol(cmd, 0, aCMD, sizeof(aCMD), &aCMD_n);
    int res = ExchangeAPDU14a(aCMD, aCMD_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res) {
        DropField();
        return false;
    }

    if (resplen < 2) {
        return false;
    }
    PrintAndLogEx(INFO, "Response: %s", sprint_hex(response, resplen));

    // drop sw
    memcpy(dataout, &response, resplen - 2);
    *dataoutlen = (resplen - 2);

    uint16_t sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "Command %s failed (%04x - %s).", cmd, sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return false;
    }
    return true;
}

static char calculate_check_digit(char *data) {
    int mrz_weight[] = {7, 3, 1};
    int cd = 0;
    int value = 0;
    char d;

    for (int i = 0; i < strlen(data); i++) {
        d = data[i];
        if ('A' <= d && d <= 'Z') {
            value = d - 55;
        } else if ('a' <= d && d <= 'z') {
            value = d - 87;
        } else if (d == '<') {
            value = 0;
        } else {  // Numbers
            value = d - 48;
        }
        cd += value * mrz_weight[i % 3];
    }
    return cd % 10;
}

static int asn1datalength(uint8_t *datain, int datainlen) {
    char* dataintext = sprint_hex_inrow(datain, datainlen);

    // lazy - https://stackoverflow.com/a/4214350/3286892
    char subbuff[8];
    memcpy(subbuff, &dataintext[2], 2);
    subbuff[2] = '\0';

    int thing = (int)strtol(subbuff, NULL, 16);
    if (thing <= 0x7f) {
        return thing;
    } else if (thing == 0x81) {
        memcpy(subbuff, &dataintext[2], 3);
        subbuff[3] = '\0';
        return (int)strtol(subbuff, NULL, 16);
    } else if (thing == 0x82) {
        memcpy(subbuff, &dataintext[2], 5);
        subbuff[5] = '\0';
        return (int)strtol(subbuff, NULL, 16);
    } else if (thing == 0x83) {
        memcpy(subbuff, &dataintext[2], 7);
        subbuff[7] = '\0';
        return (int)strtol(subbuff, NULL, 16);
    }
    return false;
}

static int asn1fieldlength(uint8_t *datain, int datainlen) {
    char* dataintext = sprint_hex_inrow(datain, datainlen);

    // lazy - https://stackoverflow.com/a/4214350/3286892
    char subbuff[8];
    memcpy(subbuff, &dataintext[2], 2);
    subbuff[2] = '\0';

    int thing = (int)strtol(subbuff, NULL, 16);
    if (thing <= 0x7f) {
        return 2;
    } else if (thing == 0x81) {
        return 4;
    } else if (thing == 0x82) {
        return 6;
    } else if (thing == 0x83) {
        return 8;
    }
    return false;
}

static void des3_encrypt(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *output) {
    mbedtls_des3_context ctx;
    mbedtls_des3_set2key_enc(&ctx, key);

    mbedtls_des3_crypt_cbc(&ctx  // des3_context
                           , MBEDTLS_DES_ENCRYPT    // int mode
                           , sizeof(input)          // length
                           , iv                     // iv[8]
                           , input                  // input
                           , output                 // output
                          );
}

static void deskey(uint8_t *seed, uint8_t *type, int length, uint8_t *dataout) {
    PrintAndLogEx(INFO, "seed: %s", sprint_hex_inrow(seed, 16));

    // combine seed and type
    uint8_t data[50];
    memcpy(data, seed, 16);
    memcpy(data + 16, type, 4);
    PrintAndLogEx(INFO, "data: %s", sprint_hex_inrow(data, 20));

    // SHA1 the key
    unsigned char key[20];
    mbedtls_sha1(data, 20, key);
    PrintAndLogEx(INFO, "key: %s", sprint_hex_inrow(key, 20));

    // Set parity bits
    mbedtls_des_key_set_parity(key);
    mbedtls_des_key_set_parity(key + 8);
    PrintAndLogEx(INFO, "post-parity key: %s", sprint_hex_inrow(key, 20));

    memcpy(dataout, &key, length);
}

static int select_file(const char *select_by, const char *file_id, bool activate_field, bool keep_field_on) {
    size_t file_id_len = strlen(file_id) / 2;

    // Get data even tho we'll not use it
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;

    char cmd[50];
    sprintf(cmd, "00%s%s0C%02lu%s", SELECT, select_by, file_id_len, file_id);

    return exchange_commands(cmd, response, &resplen, activate_field, keep_field_on);
}

static int get_challenge(int length, uint8_t *dataout, int *dataoutlen) {
    char cmd[50];
    sprintf(cmd, "00%s0000%02X", GET_CHALLENGE, length);

    return exchange_commands(cmd, dataout, dataoutlen, false, true);
}

// static int external_authenticate(const char *response, int length, uint8_t *dataout, int *dataoutlen) {
//     char cmd[50];
//     sprintf(cmd, "00%s00%02i%02X%02i", EXTERNAL_AUTHENTICATE, length, sprint_hex_inrow(response, length), length);

//     return exchange_commands(cmd, dataout, dataoutlen, false, true);
// }

static int _read_binary(int offset, int bytes_to_read, uint8_t *dataout, int *dataoutlen) {
    char cmd[50];
    sprintf(cmd, "00%s%04i%02i", READ_BINARY, offset, bytes_to_read);

    return exchange_commands(cmd, dataout, dataoutlen, false, true);
}

static int read_file(uint8_t *dataout, int *dataoutlen) {
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;
    uint8_t tempresponse[PM3_CMD_DATA_SIZE];
    int tempresplen = 0;

    if (!_read_binary(0, 4, response, &resplen)) {
        return false;
    }

    int datalen = asn1datalength(response, resplen);
    int readlen = datalen - (3 - asn1fieldlength(response, resplen) / 2);
    int offset = 4;
    int toread;

    while (readlen > 0) {
        toread = readlen;
        if (readlen > 118) {
            toread = 118;
        }

        if (!_read_binary(offset, toread, tempresponse, &tempresplen)) {
            return false;
        }

        memcpy(&response[resplen], &tempresponse, tempresplen);
        offset += toread;
        readlen -= toread;
        resplen += tempresplen;
    }

    memcpy(dataout, &response, resplen);
    *dataoutlen = resplen;
    return true;
}

int infoHF_EMRTD(char *documentnumber, char *dob, char *expiry) {
    uint8_t response[PM3_CMD_DATA_SIZE];
    uint8_t rnd_ic[8];
    uint8_t kenc[50];
    uint8_t kmac[50];
    int resplen = 0;
    // bool BAC = true;
    uint8_t S[32];
    // TODO: Code sponsored jointly by duracell and sony
    uint8_t rnd_ifd[8] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
    uint8_t k_ifd[16] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
    // TODO: get these _types into a better spot
    uint8_t KENC_type[4] = {0x00, 0x00, 0x00, 0x01};
    uint8_t KMAC_type[4] = {0x00, 0x00, 0x00, 0x02};

    // Select and read EF_CardAccess
    if (select_file(P1_SELECT_BY_EF, EF_CARDACCESS, true, true)) {
        read_file(response, &resplen);
        PrintAndLogEx(INFO, "EF_CardAccess: %s", sprint_hex(response, resplen));
    } else {
        PrintAndLogEx(INFO, "PACE unsupported. Will not read EF_CardAccess.");
    }

    // Select MRTD applet
    if (select_file(P1_SELECT_BY_NAME, AID_MRTD, false, true) == false) {
        PrintAndLogEx(ERR, "Couldn't select the MRTD application.");
        DropField();
        return PM3_ESOFT;
    }

    // Select EF_COM
    if (select_file(P1_SELECT_BY_EF, EF_COM, false, true) == false) {
        // BAC = true;
        PrintAndLogEx(INFO, "Basic Access Control is enforced. Will attempt auth.");
    } else {
        // BAC = false;
        // Select EF_DG1
        select_file(P1_SELECT_BY_EF, EF_DG1, false, true);

        if (read_file(response, &resplen) == false) {
            // BAC = true;
            PrintAndLogEx(INFO, "Basic Access Control is enforced. Will attempt auth.");
        } else {
            // BAC = false;
            PrintAndLogEx(INFO, "EF_DG1: %s", sprint_hex(response, resplen));
        }
    }
    PrintAndLogEx(INFO, "doc: %s", documentnumber);
    PrintAndLogEx(INFO, "dob: %s", dob);
    PrintAndLogEx(INFO, "exp: %s", expiry);

    char documentnumbercd = calculate_check_digit(documentnumber);
    char dobcd = calculate_check_digit(dob);
    char expirycd = calculate_check_digit(expiry);

    char kmrz[25];
    sprintf(kmrz, "%s%i%s%i%s%i", documentnumber, documentnumbercd, dob, dobcd, expiry, expirycd);
    PrintAndLogEx(INFO, "kmrz: %s", kmrz);

    unsigned char kseed[20] = {0x00};
    mbedtls_sha1((unsigned char *)kmrz, strlen(kmrz), kseed);
    PrintAndLogEx(INFO, "kseed: %s", sprint_hex_inrow(kseed, 16));

    deskey(kseed, KENC_type, 16, kenc);
    deskey(kseed, KMAC_type, 16, kmac);
    PrintAndLogEx(INFO, "kenc: %s", sprint_hex_inrow(kenc, 16));
    PrintAndLogEx(INFO, "kmac: %s", sprint_hex_inrow(kmac, 16));

    // Get Challenge
    if (get_challenge(8, rnd_ic, &resplen) == false) {
        PrintAndLogEx(ERR, "Couldn't get challenge.");
        DropField();
        return PM3_ESOFT;
    }
    PrintAndLogEx(INFO, "rnd_ic: %s", sprint_hex_inrow(rnd_ic, 8));

    memcpy(S, rnd_ifd, 8);
    memcpy(S + 8, rnd_ic, 8);
    memcpy(S + 16, k_ifd, 16);

    PrintAndLogEx(INFO, "S: %s", sprint_hex_inrow(S, 32));

    uint8_t iv[8] = { 0x00 };
    uint8_t e_ifd[8] = { 0x00 };

    des3_encrypt(iv, kenc, S, e_ifd);
    PrintAndLogEx(INFO, "e_ifd: %s", sprint_hex_inrow(e_ifd, 8));

    // TODO: get m_ifd by ISO 9797-1 Algo 3(e_ifd, m_mac)
    // TODO: get cmd_data by e_ifd + m_ifd
    // TODO: iso_7816_external_authenticate(passport.ToHex(cmd_data),Kmac)

    DropField();
    return PM3_SUCCESS;
}

static int cmd_hf_emrtd_info(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf emrtd info",
                  "Get info about an eMRTD",
                  "hf emrtd info"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("n", "documentnumber", "<number>", "9 character document number"),
        arg_str1("d", "dateofbirth", "<number>", "date of birth in YYMMDD format"),
        arg_str1("e", "expiry", "<number>", "expiry in YYMMDD format"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t docnum[10];
    uint8_t dob[7];
    uint8_t expiry[7];
    int docnumlen = 9;
    int doblen = 6;
    int expirylen = 6;
    CLIGetStrWithReturn(ctx, 1, docnum, &docnumlen);
    CLIGetStrWithReturn(ctx, 2, dob, &doblen);
    CLIGetStrWithReturn(ctx, 3, expiry, &expirylen);

    CLIParserFree(ctx);
    return infoHF_EMRTD((char *)docnum, (char *)dob, (char *)expiry);
}

static int cmd_hf_emrtd_list(const char *Cmd) {
    char args[128] = {0};
    if (strlen(Cmd) == 0) {
        snprintf(args, sizeof(args), "-t 7816");
    } else {
        strncpy(args, Cmd, sizeof(args) - 1);
    }
    return CmdTraceList(args);
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,           AlwaysAvailable, "This help"},
    {"info",    cmd_hf_emrtd_info, IfPm3Iso14443a,  "Tag information"},
    {"list",    cmd_hf_emrtd_list, AlwaysAvailable, "List ISO 14443A/7816 history"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFeMRTD(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
