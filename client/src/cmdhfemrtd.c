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

    PrintAndLogEx(DEBUG, "Sending: %s", cmd);

    uint8_t aCMD[100];
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
    PrintAndLogEx(DEBUG, "Response: %s", sprint_hex(response, resplen));

    // drop sw
    memcpy(dataout, &response, resplen - 2);
    *dataoutlen = (resplen - 2);

    uint16_t sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(DEBUG, "Command %s failed (%04x - %s).", cmd, sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
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
    char *dataintext = sprint_hex_inrow(datain, datainlen);

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
    char *dataintext = sprint_hex_inrow(datain, datainlen);

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

static void des_encrypt_ecb(uint8_t *key, uint8_t *input, uint8_t *output) {
    mbedtls_des_context ctx_enc;
    mbedtls_des_setkey_enc(&ctx_enc, key);
    mbedtls_des_crypt_ecb(&ctx_enc, input, output);
    mbedtls_des_free(&ctx_enc);
}

static void des_decrypt_ecb(uint8_t *key, uint8_t *input, uint8_t *output) {
    mbedtls_des_context ctx_dec;
    mbedtls_des_setkey_dec(&ctx_dec, key);
    mbedtls_des_crypt_ecb(&ctx_dec, input, output);
    mbedtls_des_free(&ctx_dec);
}

static void des3_encrypt_cbc(uint8_t *iv, uint8_t *key, uint8_t *input, int inputlen, uint8_t *output) {
    mbedtls_des3_context ctx;
    mbedtls_des3_set2key_enc(&ctx, key);

    mbedtls_des3_crypt_cbc(&ctx  // des3_context
                           , MBEDTLS_DES_ENCRYPT    // int mode
                           , inputlen               // length
                           , iv                     // iv[8]
                           , input                  // input
                           , output                 // output
                          );
    mbedtls_des3_free(&ctx);
}

static void des3_decrypt_cbc(uint8_t *iv, uint8_t *key, uint8_t *input, int inputlen, uint8_t *output) {
    mbedtls_des3_context ctx;
    mbedtls_des3_set2key_dec(&ctx, key);

    mbedtls_des3_crypt_cbc(&ctx  // des3_context
                           , MBEDTLS_DES_DECRYPT    // int mode
                           , inputlen               // length
                           , iv                     // iv[8]
                           , input                  // input
                           , output                 // output
                          );
    mbedtls_des3_free(&ctx);
}

static int pad_block(uint8_t *input, int inputlen, uint8_t *output) {
    uint8_t padding[8] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    memcpy(output, input, inputlen);

    int to_pad = (8 - (inputlen % 8));

    for (int i = 0; i < to_pad; i++) {
        output[inputlen + i] = padding[i];
    }

    return inputlen + to_pad;
}

static void retail_mac(uint8_t *key, uint8_t *input, int inputlen, uint8_t *output) {
    // This code assumes blocklength (n) = 8, and input len of up to 56 chars
    // This code takes inspirations from https://github.com/devinvenable/iso9797algorithm3
    uint8_t k0[8];
    uint8_t k1[8];
    uint8_t intermediate[8] = {0x00};
    uint8_t intermediate_des[32];
    uint8_t block[8];
    uint8_t message[64];

    // Populate keys
    memcpy(k0, key, 8);
    memcpy(k1, key + 8, 8);

    // Prepare message
    int blocksize = pad_block(input, inputlen, message);

    // Do chaining and encryption
    for (int i = 0; i < (blocksize / 8); i++) {
        memcpy(block, message + (i * 8), 8);

        // XOR
        for (int x = 0; x < 8; x++) {
            intermediate[x] = intermediate[x] ^ block[x];
        }

        des_encrypt_ecb(k0, intermediate, intermediate_des);
        memcpy(intermediate, intermediate_des, 8);
    }


    des_decrypt_ecb(k1, intermediate, intermediate_des);
    memcpy(intermediate, intermediate_des, 8);

    des_encrypt_ecb(k0, intermediate, intermediate_des);
    memcpy(output, intermediate_des, 8);
}


static void deskey(uint8_t *seed, uint8_t *type, int length, uint8_t *dataout) {
    PrintAndLogEx(DEBUG, "seed: %s", sprint_hex_inrow(seed, 16));

    // combine seed and type
    uint8_t data[50];
    memcpy(data, seed, length);
    memcpy(data + length, type, 4);
    PrintAndLogEx(DEBUG, "data: %s", sprint_hex_inrow(data, length + 4));

    // SHA1 the key
    unsigned char key[64];
    mbedtls_sha1(data, length + 4, key);
    PrintAndLogEx(DEBUG, "key: %s", sprint_hex_inrow(key, length + 4));

    // Set parity bits
    for (int i = 0; i < ((length + 4) / 8); i++) {
        mbedtls_des_key_set_parity(key + (i * 8));
    }
    PrintAndLogEx(DEBUG, "post-parity key: %s", sprint_hex_inrow(key, 20));

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

static int external_authenticate(uint8_t *data, int length, uint8_t *dataout, int *dataoutlen) {
    char cmd[100];

    sprintf(cmd, "00%s0000%02X%s%02X", EXTERNAL_AUTHENTICATE, length, sprint_hex_inrow(data, length), length);

    return exchange_commands(cmd, dataout, dataoutlen, false, true);
}

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

static int secure_select_file(uint8_t *kenc, uint8_t *kmac, uint8_t *ssc, uint8_t *file) {
    // Get data even tho we'll not use it
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;

    uint8_t iv[8] = { 0x00 };
    char command[54];
    uint8_t cmd[8];
    uint8_t data[21];
    uint8_t temp[8] = {0x0c, 0xa4, 0x02, 0x0c};

    int cmdlen = pad_block(temp, 4, cmd);
    int datalen = pad_block(file, 2, data);
    PrintAndLogEx(DEBUG, "cmd: %s", sprint_hex_inrow(cmd, cmdlen));
    PrintAndLogEx(DEBUG, "data: %s", sprint_hex_inrow(data, datalen));

    des3_encrypt_cbc(iv, kenc, data, datalen, temp);
    PrintAndLogEx(DEBUG, "temp: %s", sprint_hex_inrow(temp, datalen));
    uint8_t do87[11] = {0x87, 0x09, 0x01};
    memcpy(do87 + 3, temp, datalen);
    PrintAndLogEx(DEBUG, "do87: %s", sprint_hex_inrow(do87, datalen + 3));

    uint8_t m[19];
    memcpy(m, cmd, cmdlen);
    memcpy(m + cmdlen, do87, (datalen + 3));
    PrintAndLogEx(DEBUG, "m: %s", sprint_hex_inrow(m, datalen + cmdlen + 3));

    // TODO: this is hacky
    PrintAndLogEx(DEBUG, "ssc-b: %s", sprint_hex_inrow(ssc, 8));
    (*(ssc + 7)) += 1;
    PrintAndLogEx(DEBUG, "ssc-a: %s", sprint_hex_inrow(ssc, 8));

    uint8_t n[27];
    memcpy(n, ssc, 8);
    memcpy(n + 8, m, (cmdlen + datalen + 3));
    PrintAndLogEx(DEBUG, "n: %s", sprint_hex_inrow(n, (cmdlen + datalen + 11)));

    uint8_t cc[8];
    retail_mac(kmac, n, (cmdlen + datalen + 11), cc);
    PrintAndLogEx(DEBUG, "cc: %s", sprint_hex_inrow(cc, 8));

    uint8_t do8e[10] = {0x8E, 0x08};
    memcpy(do8e + 2, cc, 8);
    PrintAndLogEx(DEBUG, "do8e: %s", sprint_hex_inrow(do8e, 10));

    int lc = datalen + 3 + 10;
    PrintAndLogEx(DEBUG, "lc: %i", lc);

    memcpy(data, do87, datalen + 3);
    memcpy(data + (datalen + 3), do8e, 10);
    PrintAndLogEx(DEBUG, "data: %s", sprint_hex_inrow(data, lc));

    sprintf(command, "0C%s020C%02X%s00", SELECT, lc, sprint_hex_inrow(data, lc));
    PrintAndLogEx(DEBUG, "command: %s", command);

    // TODO: Impl CC check, which will handle incrementing itself
    (*(ssc + 7)) += 1;

    return exchange_commands(command, response, &resplen, false, true);
}

static int secure_read_binary(uint8_t *kmac, uint8_t *ssc, int offset, int bytes_to_read, uint8_t *dataout, int *dataoutlen) {
    char command[54];
    uint8_t cmd[8];
    uint8_t data[21];
    uint8_t temp[8] = {0x0c, 0xb0};

    PrintAndLogEx(DEBUG, "kmac: %s", sprint_hex_inrow(kmac, 20));

    // TODO: hacky
    char offsethex[5];
    sprintf(offsethex, "%04X", offset);
    char offsetbuffer[8];
    memcpy(offsetbuffer, offsethex, 2);
    int p1 = (int)strtol(offsetbuffer, NULL, 16);
    memcpy(offsetbuffer, offsethex + 2, 2);
    int p2 = (int)strtol(offsetbuffer, NULL, 16);
    temp[2] = p1;
    temp[3] = p2;

    int cmdlen = pad_block(temp, 4, cmd);
    PrintAndLogEx(DEBUG, "cmd: %s", sprint_hex_inrow(cmd, cmdlen));

    uint8_t do97[3] = {0x97, 0x01, bytes_to_read};

    uint8_t m[11];
    memcpy(m, cmd, 8);
    memcpy(m + 8, do97, 3);

    // TODO: this is hacky
    PrintAndLogEx(DEBUG, "ssc-b: %s", sprint_hex_inrow(ssc, 8));
    (*(ssc + 7)) += 1;
    PrintAndLogEx(DEBUG, "ssc-a: %s", sprint_hex_inrow(ssc, 8));

    uint8_t n[19];
    memcpy(n, ssc, 8);
    memcpy(n + 8, m, 11);
    PrintAndLogEx(DEBUG, "n: %s", sprint_hex_inrow(n, 19));

    uint8_t cc[8];
    retail_mac(kmac, n, 19, cc);
    PrintAndLogEx(DEBUG, "cc: %s", sprint_hex_inrow(cc, 8));

    uint8_t do8e[10] = {0x8E, 0x08};
    memcpy(do8e + 2, cc, 8);
    PrintAndLogEx(DEBUG, "do8e: %s", sprint_hex_inrow(do8e, 10));

    int lc = 13;
    PrintAndLogEx(DEBUG, "lc: %i", lc);

    memcpy(data, do97, 3);
    memcpy(data + 3, do8e, 10);
    PrintAndLogEx(DEBUG, "data: %s", sprint_hex_inrow(data, lc));

    sprintf(command, "0C%s%02X%02X%02X%s00", READ_BINARY, p1, p2, lc, sprint_hex_inrow(data, lc));
    PrintAndLogEx(DEBUG, "command: %s", command);

    return exchange_commands(command, dataout, dataoutlen, false, true);
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
        PrintAndLogEx(INFO, "Basic Access Control is enforced. Will attempt external authentication.");
    } else {
        // BAC = false;
        // Select EF_DG1
        select_file(P1_SELECT_BY_EF, EF_DG1, false, true);

        if (read_file(response, &resplen) == false) {
            // BAC = true;
            PrintAndLogEx(INFO, "Basic Access Control is enforced. Will attempt external authentication.");
        } else {
            // BAC = false;
            PrintAndLogEx(INFO, "EF_DG1: %s", sprint_hex(response, resplen));
        }
    }
    PrintAndLogEx(DEBUG, "doc: %s", documentnumber);
    PrintAndLogEx(DEBUG, "dob: %s", dob);
    PrintAndLogEx(DEBUG, "exp: %s", expiry);

    char documentnumbercd = calculate_check_digit(documentnumber);
    char dobcd = calculate_check_digit(dob);
    char expirycd = calculate_check_digit(expiry);

    char kmrz[25];
    sprintf(kmrz, "%s%i%s%i%s%i", documentnumber, documentnumbercd, dob, dobcd, expiry, expirycd);
    PrintAndLogEx(DEBUG, "kmrz: %s", kmrz);

    uint8_t kseed[16] = {0x00};
    mbedtls_sha1((unsigned char *)kmrz, strlen(kmrz), kseed);
    PrintAndLogEx(DEBUG, "kseed: %s", sprint_hex_inrow(kseed, 16));

    deskey(kseed, KENC_type, 16, kenc);
    deskey(kseed, KMAC_type, 16, kmac);
    PrintAndLogEx(DEBUG, "kenc: %s", sprint_hex_inrow(kenc, 16));
    PrintAndLogEx(DEBUG, "kmac: %s", sprint_hex_inrow(kmac, 16));

    // Get Challenge
    if (get_challenge(8, rnd_ic, &resplen) == false) {
        PrintAndLogEx(ERR, "Couldn't get challenge.");
        DropField();
        return PM3_ESOFT;
    }
    PrintAndLogEx(DEBUG, "rnd_ic: %s", sprint_hex_inrow(rnd_ic, 8));

    memcpy(S, rnd_ifd, 8);
    memcpy(S + 8, rnd_ic, 8);
    memcpy(S + 16, k_ifd, 16);

    PrintAndLogEx(DEBUG, "S: %s", sprint_hex_inrow(S, 32));

    uint8_t iv[8] = { 0x00 };
    uint8_t e_ifd[32] = { 0x00 };

    des3_encrypt_cbc(iv, kenc, S, sizeof(S), e_ifd);
    PrintAndLogEx(DEBUG, "e_ifd: %s", sprint_hex_inrow(e_ifd, 32));

    uint8_t m_ifd[8] = { 0x00 };

    retail_mac(kmac, e_ifd, 32, m_ifd);
    PrintAndLogEx(DEBUG, "m_ifd: %s", sprint_hex_inrow(m_ifd, 8));

    uint8_t cmd_data[40];
    memcpy(cmd_data, e_ifd, 32);
    memcpy(cmd_data + 32, m_ifd, 8);

    // Do external authentication
    if (external_authenticate(cmd_data, sizeof(cmd_data), response, &resplen) == false) {
        PrintAndLogEx(ERR, "Couldn't do external authentication. Did you supply the correct MRZ info?");
        DropField();
        return PM3_ESOFT;
    }
    PrintAndLogEx(INFO, "External authentication successful.");

    uint8_t dec_output[32] = { 0x00 };
    des3_decrypt_cbc(iv, kenc, response, 32, dec_output);
    PrintAndLogEx(DEBUG, "dec_output: %s", sprint_hex_inrow(dec_output, 32));

    if (memcmp(rnd_ifd, dec_output + 8, 8) != 0) {
        PrintAndLogEx(ERR, "Challenge failed, rnd_ifd does not match.");
        DropField();
        return PM3_ESOFT;
    }

    uint8_t ssc[8] = { 0x00 };
    uint8_t ks_enc[16] = { 0x00 };
    uint8_t ks_mac[16] = { 0x00 };
    uint8_t k_icc[16] = { 0x00 };
    memcpy(k_icc, dec_output + 16, 16);

    // Calculate session keys
    for (int x = 0; x < 16; x++) {
        kseed[x] = k_ifd[x] ^ k_icc[x];
    }

    PrintAndLogEx(DEBUG, "kseed: %s", sprint_hex_inrow(kseed, 16));

    deskey(kseed, KENC_type, 16, ks_enc);
    deskey(kseed, KMAC_type, 16, ks_mac);

    PrintAndLogEx(DEBUG, "ks_enc: %s", sprint_hex_inrow(ks_enc, 16));
    PrintAndLogEx(DEBUG, "ks_mac: %s", sprint_hex_inrow(ks_mac, 16));

    memcpy(ssc, rnd_ic + 4, 4);
    memcpy(ssc + 4, rnd_ifd + 4, 4);

    PrintAndLogEx(DEBUG, "ssc: %s", sprint_hex_inrow(ssc, 8));

    // Select EF_COM
    uint8_t file_id[2] = {0x01, 0x1E};
    secure_select_file(ks_enc, ks_mac, ssc, file_id);

    secure_read_binary(ks_mac, ssc, 0, 4, response, &resplen);
    // TODO: impl secure read file

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
