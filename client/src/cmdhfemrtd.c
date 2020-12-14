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
#include "fileutils.h"              // saveFile
#include "cmdparser.h"              // command_t
#include "cmdtrace.h"               // CmdTraceList
#include "cliparser.h"              // CLIParserContext etc
#include "cmdhf14a.h"               // ExchangeAPDU14a
#include "protocols.h"              // definitions of ISO14A/7816 protocol
#include "emv/apduinfo.h"           // GetAPDUCodeDescription
#include "sha1.h"                   // KSeed calculation etc
#include "mifare/desfire_crypto.h"  // des_encrypt/des_decrypt
#include "des.h"                    // mbedtls_des_key_set_parity
#include "cmdhf14b.h"               // exchange_14b_apdu
#include "iso14b.h"                 // ISO14B_CONNECT etc
#include "crapto1/crapto1.h"        // prng_successor
#include "commonutil.h"             // num_to_bytes
#include "util_posix.h"             // msclock

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
#define EF_DG2 "0102"
#define EF_DG3 "0103"
#define EF_DG4 "0104"
#define EF_DG5 "0105"
#define EF_DG6 "0106"
#define EF_DG7 "0107"
#define EF_DG8 "0108"
#define EF_DG9 "0109"
#define EF_DG10 "010A"
#define EF_DG11 "010B"
#define EF_DG12 "010C"
#define EF_DG13 "010D"
#define EF_DG14 "010E"
#define EF_DG15 "010F"
#define EF_DG16 "0110"
#define EF_SOD "011D"

// App IDs
#define AID_MRTD "A0000002471001"

// DESKey Types
const uint8_t KENC_type[4] = {0x00, 0x00, 0x00, 0x01};
const uint8_t KMAC_type[4] = {0x00, 0x00, 0x00, 0x02};

static int CmdHelp(const char *Cmd);

static uint16_t get_sw(uint8_t *d, uint8_t n) {
    if (n < 2)
        return 0;

    n -= 2;
    return d[n] * 0x0100 + d[n + 1];
}

static bool exchange_commands(const char *cmd, uint8_t *dataout, int *dataoutlen, bool activate_field, bool keep_field_on, bool use_14b) {
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;

    PrintAndLogEx(DEBUG, "Sending: %s", cmd);

    uint8_t aCMD[PM3_CMD_DATA_SIZE];
    int aCMD_n = 0;
    param_gethex_to_eol(cmd, 0, aCMD, sizeof(aCMD), &aCMD_n);
    int res;
    if (use_14b) {
        res = exchange_14b_apdu(aCMD, aCMD_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    } else {
        res = ExchangeAPDU14a(aCMD, aCMD_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    }
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

static int exchange_commands_noout(const char *cmd, bool activate_field, bool keep_field_on, bool use_14b) {
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;

    return exchange_commands(cmd, response, &resplen, activate_field, keep_field_on, use_14b);
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

static int asn1datalength(uint8_t *datain, int datainlen, int offset) {
    PrintAndLogEx(DEBUG, "asn1datalength, datain: %s", sprint_hex_inrow(datain, datainlen));
    int lenfield = (int) * (datain + offset);
    PrintAndLogEx(DEBUG, "asn1datalength, lenfield: %i", lenfield);
    if (lenfield <= 0x7f) {
        return lenfield;
    } else if (lenfield == 0x81) {
        return ((int) * (datain + offset + 1));
    } else if (lenfield == 0x82) {
        return ((int) * (datain + offset + 1) << 8) | ((int) * (datain + offset + 2));
    } else if (lenfield == 0x83) {
        return (((int) * (datain + offset + 1) << 16) | ((int) * (datain + offset + 2)) << 8) | ((int) * (datain + offset + 3));
    }
    return false;
}

static int asn1fieldlength(uint8_t *datain, int datainlen, int offset) {
    PrintAndLogEx(DEBUG, "asn1fieldlength, datain: %s", sprint_hex_inrow(datain, datainlen));
    int lenfield = (int) * (datain + offset);
    PrintAndLogEx(DEBUG, "asn1fieldlength, thing: %i", lenfield);
    if (lenfield <= 0x7f) {
        return 1;
    } else if (lenfield == 0x81) {
        return 2;
    } else if (lenfield == 0x82) {
        return 3;
    } else if (lenfield == 0x83) {
        return 4;
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
    // This code assumes blocklength (n) = 8, and input len of up to 240 or so chars
    // This code takes inspirations from https://github.com/devinvenable/iso9797algorithm3
    uint8_t k0[8];
    uint8_t k1[8];
    uint8_t intermediate[8] = {0x00};
    uint8_t intermediate_des[256];
    uint8_t block[8];
    uint8_t message[256];

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

static void deskey(uint8_t *seed, const uint8_t *type, int length, uint8_t *dataout) {
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

static int select_file(const char *select_by, const char *file_id, bool use_14b) {
    size_t file_id_len = strlen(file_id) / 2;

    char cmd[50];
    sprintf(cmd, "00%s%s0C%02lu%s", SELECT, select_by, file_id_len, file_id);

    return exchange_commands_noout(cmd, false, true, use_14b);
}

static int get_challenge(int length, uint8_t *dataout, int *dataoutlen, bool use_14b) {
    char cmd[50];
    sprintf(cmd, "00%s0000%02X", GET_CHALLENGE, length);

    return exchange_commands(cmd, dataout, dataoutlen, false, true, use_14b);
}

static int external_authenticate(uint8_t *data, int length, uint8_t *dataout, int *dataoutlen, bool use_14b) {
    char cmd[100];

    sprintf(cmd, "00%s0000%02X%s%02X", EXTERNAL_AUTHENTICATE, length, sprint_hex_inrow(data, length), length);

    return exchange_commands(cmd, dataout, dataoutlen, false, true, use_14b);
}

static int _read_binary(int offset, int bytes_to_read, uint8_t *dataout, int *dataoutlen, bool use_14b) {
    char cmd[50];
    sprintf(cmd, "00%s%04i%02i", READ_BINARY, offset, bytes_to_read);

    return exchange_commands(cmd, dataout, dataoutlen, false, true, use_14b);
}

static void bump_ssc(uint8_t *ssc) {
    PrintAndLogEx(DEBUG, "ssc-b: %s", sprint_hex_inrow(ssc, 8));
    for (int i = 7; i > 0; i--) {
        if ((*(ssc + i)) == 0xFF) {
            // Set anything already FF to 0, we'll do + 1 on num to left anyways
            (*(ssc + i)) = 0;
            continue;
        }
        (*(ssc + i)) += 1;
        PrintAndLogEx(DEBUG, "ssc-a: %s", sprint_hex_inrow(ssc, 8));
        return;
    }
}

static bool check_cc(uint8_t *ssc, uint8_t *key, uint8_t *rapdu, int rapdulength) {
    // https://elixi.re/i/clarkson.png
    uint8_t k[500];
    uint8_t cc[500];

    bump_ssc(ssc);

    memcpy(k, ssc, 8);
    int length = 0;
    int length2 = 0;

    if (*(rapdu) == 0x87) {
        length += 2 + (*(rapdu + 1));
        memcpy(k + 8, rapdu, length);
        PrintAndLogEx(DEBUG, "len1: %i", length);
    }

    if ((*(rapdu + length)) == 0x99) {
        length2 += 2 + (*(rapdu + (length + 1)));
        memcpy(k + length + 8, rapdu + length, length2);
        PrintAndLogEx(DEBUG, "len2: %i", length2);
    }

    int klength = length + length2 + 8;

    retail_mac(key, k, klength, cc);
    PrintAndLogEx(DEBUG, "cc: %s", sprint_hex_inrow(cc, 8));
    PrintAndLogEx(DEBUG, "rapdu: %s", sprint_hex_inrow(rapdu, rapdulength));
    PrintAndLogEx(DEBUG, "rapdu cut: %s", sprint_hex_inrow(rapdu + (rapdulength - 8), 8));
    PrintAndLogEx(DEBUG, "k: %s", sprint_hex_inrow(k, klength));

    return memcmp(cc, rapdu + (rapdulength - 8), 8) == 0;
}

static void _convert_filename(const char *file, uint8_t *dataout) {
    char temp[3] = {0x00};
    memcpy(temp, file, 2);
    dataout[0] = (int)strtol(temp, NULL, 16);
    memcpy(temp, file + 2, 2);
    dataout[1] = (int)strtol(temp, NULL, 16);
}

static bool secure_select_file(uint8_t *kenc, uint8_t *kmac, uint8_t *ssc, const char *select_by, const char *file, bool use_14b) {
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;

    // convert filename of string to bytes
    uint8_t file_id[2];
    _convert_filename(file, file_id);

    uint8_t iv[8] = { 0x00 };
    char command[54];
    uint8_t cmd[8];
    uint8_t data[21];
    uint8_t temp[8] = {0x0c, 0xa4, strtol(select_by, NULL, 16), 0x0c};

    int cmdlen = pad_block(temp, 4, cmd);
    int datalen = pad_block(file_id, 2, data);
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

    bump_ssc(ssc);

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

    sprintf(command, "0C%s%s0C%02X%s00", SELECT, select_by, lc, sprint_hex_inrow(data, lc));
    PrintAndLogEx(DEBUG, "command: %s", command);

    if (exchange_commands(command, response, &resplen, false, true, use_14b) == false) {
        return false;
    }

    return check_cc(ssc, kmac, response, resplen);
}

static bool _secure_read_binary(uint8_t *kmac, uint8_t *ssc, int offset, int bytes_to_read, uint8_t *dataout, int *dataoutlen, bool use_14b) {
    char command[54];
    uint8_t cmd[8];
    uint8_t data[21];
    uint8_t temp[8] = {0x0c, 0xb0};

    PrintAndLogEx(DEBUG, "kmac: %s", sprint_hex_inrow(kmac, 20));

    // Set p1 and p2
    temp[2] = (uint8_t)(offset >> 8);
    temp[3] = (uint8_t)(offset >> 0);

    int cmdlen = pad_block(temp, 4, cmd);
    PrintAndLogEx(DEBUG, "cmd: %s", sprint_hex_inrow(cmd, cmdlen));

    uint8_t do97[3] = {0x97, 0x01, bytes_to_read};

    uint8_t m[11];
    memcpy(m, cmd, 8);
    memcpy(m + 8, do97, 3);

    bump_ssc(ssc);

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

    sprintf(command, "0C%s%04X%02X%s00", READ_BINARY, offset, lc, sprint_hex_inrow(data, lc));
    PrintAndLogEx(DEBUG, "command: %s", command);

    if (exchange_commands(command, dataout, dataoutlen, false, true, use_14b) == false) {
        return false;
    }

    return check_cc(ssc, kmac, dataout, *dataoutlen);
}

static bool _secure_read_binary_decrypt(uint8_t *kenc, uint8_t *kmac, uint8_t *ssc, int offset, int bytes_to_read, uint8_t *dataout, int *dataoutlen, bool use_14b) {
    uint8_t response[500];
    uint8_t temp[500];
    int resplen, cutat = 0;
    uint8_t iv[8] = { 0x00 };

    if (_secure_read_binary(kmac, ssc, offset, bytes_to_read, response, &resplen, use_14b) == false) {
        return false;
    }

    PrintAndLogEx(DEBUG, "secreadbindec, offset %i on read %i: encrypted: %s", offset, bytes_to_read, sprint_hex_inrow(response, resplen));

    cutat = ((int) response[1]) - 1;

    des3_decrypt_cbc(iv, kenc, response + 3, cutat, temp);
    memcpy(dataout, temp, bytes_to_read);
    PrintAndLogEx(DEBUG, "secreadbindec, offset %i on read %i: decrypted: %s", offset, bytes_to_read, sprint_hex_inrow(temp, cutat));
    PrintAndLogEx(DEBUG, "secreadbindec, offset %i on read %i: decrypted and cut: %s", offset, bytes_to_read, sprint_hex_inrow(dataout, bytes_to_read));
    *dataoutlen = bytes_to_read;
    return true;
}


static int read_file(uint8_t *dataout, int *dataoutlen, uint8_t *kenc, uint8_t *kmac, uint8_t *ssc, bool use_secure, bool use_14b) {
    uint8_t response[35000];
    int resplen = 0;
    uint8_t tempresponse[500];
    int tempresplen = 0;
    int toread = 4;
    int offset = 0;

    if (use_secure == true) {
        if (_secure_read_binary_decrypt(kenc, kmac, ssc, offset, toread, response, &resplen, use_14b) == false) {
            return false;
        }
    } else {
        if (_read_binary(offset, toread, response, &resplen, use_14b) == false) {
            return false;
        }
    }

    int datalen = asn1datalength(response, resplen, 1);
    int readlen = datalen - (3 - asn1fieldlength(response, resplen, 1));
    offset = 4;

    while (readlen > 0) {
        toread = readlen;
        if (readlen > 118) {
            toread = 118;
        }

        if (kenc == NULL) {
            if (_read_binary(offset, toread, tempresponse, &tempresplen, use_14b) == false) {
                return false;
            }
        } else {
            if (_secure_read_binary_decrypt(kenc, kmac, ssc, offset, toread, tempresponse, &tempresplen, use_14b) == false) {
                return false;
            }
        }

        memcpy(response + resplen, tempresponse, tempresplen);
        offset += toread;
        readlen -= toread;
        resplen += tempresplen;
    }

    memcpy(dataout, &response, resplen);
    *dataoutlen = resplen;
    return true;
}

static bool ef_com_get_file_list(uint8_t *datain, int *datainlen, uint8_t *dataout, int *dataoutlen) {
    int offset = 2;
    int elementidlen = 0;
    int elementlen = 0;
    while (offset < *datainlen) {
        PrintAndLogEx(DEBUG, "ef_com_get_file_list, offset: %i, data: %X", offset, *(datain + offset));
        // Determine element ID length to set as offset on asn1datalength
        if (*(datain + offset) == 0x5f) {
            elementidlen = 2;
        } else {
            elementidlen = 1;
        }

        // Get the length of the element
        elementlen = asn1datalength(datain + offset, *datainlen - offset, elementidlen);

        // If the element is what we're looking for, get the data and return true
        if (*(datain + offset) == 0x5c) {
            *dataoutlen = elementlen;
            memcpy(dataout, datain + offset + elementidlen + 1, elementlen);
            return true;
        }
        offset += elementidlen + elementlen + 1;
    }
    // Return false if we can't find the relevant element
    return false;
}

static bool file_tag_to_file_id(uint8_t *datain, char *filenameout, char *dataout) {
    // imagine bothering with a hashmap or writing good code
    // couldn't be me
    switch (*datain) {
        case 0x60:
            memcpy(dataout, EF_COM, 4);
            memcpy(filenameout, "EF_COM", 6);
            break;
        case 0x61:
            memcpy(dataout, EF_DG1, 4);
            memcpy(filenameout, "EF_DG1", 6);
            break;
        case 0x75:
            memcpy(dataout, EF_DG2, 4);
            memcpy(filenameout, "EF_DG2", 6);
            break;
        // These cases are commented out as they require PACE
        // Trying to read a PACE file without doing PACE auth kills the session
        // case 0x63:
        //     memcpy(dataout, EF_DG3, 4);
        //     memcpy(filenameout, "EF_DG3", 6);
        //     break;
        // case 0x76:
        //     memcpy(dataout, EF_DG4, 4);
        //     memcpy(filenameout, "EF_DG4", 6);
        //     break;
        case 0x65:
            memcpy(dataout, EF_DG5, 4);
            memcpy(filenameout, "EF_DG5", 6);
            break;
        case 0x66:
            memcpy(dataout, EF_DG6, 4);
            memcpy(filenameout, "EF_DG6", 6);
            break;
        case 0x67:
            memcpy(dataout, EF_DG7, 4);
            memcpy(filenameout, "EF_DG7", 6);
            break;
        case 0x68:
            memcpy(dataout, EF_DG8, 4);
            memcpy(filenameout, "EF_DG8", 6);
            break;
        case 0x69:
            memcpy(dataout, EF_DG9, 4);
            memcpy(filenameout, "EF_DG9", 6);
            break;
        case 0x6a:
            memcpy(dataout, EF_DG10, 4);
            memcpy(filenameout, "EF_DG10", 7);
            break;
        case 0x6b:
            memcpy(dataout, EF_DG11, 4);
            memcpy(filenameout, "EF_DG11", 7);
            break;
        case 0x6c:
            memcpy(dataout, EF_DG12, 4);
            memcpy(filenameout, "EF_DG12", 7);
            break;
        case 0x6d:
            memcpy(dataout, EF_DG13, 4);
            memcpy(filenameout, "EF_DG13", 7);
            break;
        case 0x6e:
            memcpy(dataout, EF_DG14, 4);
            memcpy(filenameout, "EF_DG14", 7);
            break;
        case 0x6f:
            memcpy(dataout, EF_DG15, 4);
            memcpy(filenameout, "EF_DG15", 7);
            break;
        case 0x70:
            memcpy(dataout, EF_DG16, 4);
            memcpy(filenameout, "EF_DG16", 7);
            break;
        case 0x77:
            memcpy(dataout, EF_SOD, 4);
            memcpy(filenameout, "EF_SOD", 6);
            break;
        default:
            return false;
    }
    return true;
}

static bool select_and_read(uint8_t *dataout, int *dataoutlen, const char *file, uint8_t *ks_enc, uint8_t *ks_mac, uint8_t *ssc, bool use_secure, bool use_14b) {
    if (use_secure == true) {
        if (secure_select_file(ks_enc, ks_mac, ssc, P1_SELECT_BY_EF, file, use_14b) == false) {
            PrintAndLogEx(ERR, "Failed to secure select %s.", file);
            return false;
        }
    } else {
        if (select_file(P1_SELECT_BY_EF, file, use_14b) == false) {
            PrintAndLogEx(ERR, "Failed to select %s.", file);
            return false;
        }
    }

    if (read_file(dataout, dataoutlen, ks_enc, ks_mac, ssc, use_secure, use_14b) == false) {
        PrintAndLogEx(ERR, "Failed to read %s.", file);
        return false;
    }
    return true;
}

static bool dump_file(uint8_t *ks_enc, uint8_t *ks_mac, uint8_t *ssc, const char *file, const char *name, bool use_secure, bool use_14b) {
    uint8_t response[35000];
    int resplen = 0;

    if (select_and_read(response, &resplen, file, ks_enc, ks_mac, ssc, use_secure, use_14b) == false) {
        return false;
    }

    PrintAndLogEx(INFO, "Read %s, len: %i.", name, resplen);
    PrintAndLogEx(DEBUG, "Contents (may be incomplete over 2k chars): %s", sprint_hex_inrow(response, resplen));
    saveFile(name, ".BIN", response, resplen);

    return true;
}

static void rng(int length, uint8_t *dataout) {
    // Do very very secure prng operations
    for (int i = 0; i < (length / 4); i++) {
        num_to_bytes(prng_successor(msclock() + i, 32), 4, &dataout[i * 4]);
    }
}

int dumpHF_EMRTD(char *documentnumber, char *dob, char *expiry, bool BAC_available) {
    uint8_t response[35000] = { 0x00 };
    uint8_t ssc[8] = { 0x00 };
    uint8_t ks_enc[16] = { 0x00 };
    uint8_t ks_mac[16] = { 0x00 };
    int resplen = 0;
    bool BAC = false;
    bool use_14b = false;

    // Try to 14a
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_NO_DISCONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;
    bool failed_14a = false;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
        DropField();
        failed_14a = true;
    }

    if (failed_14a || resp.oldarg[0] == 0) {
        PrintAndLogEx(INFO, "No eMRTD spotted with 14a, trying 14b.");
        // If not 14a, try to 14b
        SendCommandMIX(CMD_HF_ISO14443B_COMMAND, ISO14B_CONNECT | ISO14B_SELECT_STD, 0, 0, NULL, 0);
        if (!WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, 2500)) {
            DropField();
            PrintAndLogEx(INFO, "No eMRTD spotted with 14b, exiting.");
            return PM3_ESOFT;
        }

        if (resp.oldarg[0] != 0) {
            DropField();
            PrintAndLogEx(INFO, "No eMRTD spotted with 14b, exiting.");
            return PM3_ESOFT;
        }
        use_14b = true;
    }

    // Select and read EF_CardAccess
    if (select_file(P1_SELECT_BY_EF, EF_CARDACCESS, use_14b)) {
        read_file(response, &resplen, NULL, NULL, NULL, false, use_14b);
        PrintAndLogEx(INFO, "Read EF_CardAccess, len: %i.", resplen);
        PrintAndLogEx(DEBUG, "Contents (may be incomplete over 2k chars): %s", sprint_hex_inrow(response, resplen));
    } else {
        PrintAndLogEx(INFO, "PACE unsupported. Will not read EF_CardAccess.");
    }

    // Select MRTD applet
    if (select_file(P1_SELECT_BY_NAME, AID_MRTD, use_14b) == false) {
        PrintAndLogEx(ERR, "Couldn't select the MRTD application.");
        DropField();
        return PM3_ESOFT;
    }

    // Select EF_COM
    if (select_file(P1_SELECT_BY_EF, EF_COM, use_14b) == false) {
        BAC = true;
        PrintAndLogEx(INFO, "Basic Access Control is enforced. Will attempt external authentication.");
    } else {
        BAC = false;
        // Select EF_DG1
        select_file(P1_SELECT_BY_EF, EF_DG1, use_14b);

        if (read_file(response, &resplen, NULL, NULL, NULL, false, use_14b) == false) {
            BAC = true;
            PrintAndLogEx(INFO, "Basic Access Control is enforced. Will attempt external authentication.");
        } else {
            BAC = false;
            PrintAndLogEx(INFO, "EF_DG1: %s", sprint_hex(response, resplen));
        }
    }

    if (BAC == true && BAC_available == false) {
        PrintAndLogEx(ERR, "This eMRTD enforces Basic Access Control, but you didn't supplied MRZ data. Cannot proceed.");
        PrintAndLogEx(HINT, "Check out hf emrtd dump --help, supply data with -n -d and -e.");
        DropField();
        return PM3_ESOFT;
    }

    if (BAC) {
        uint8_t rnd_ic[8] = { 0x00 };
        uint8_t kenc[50] = { 0x00 };
        uint8_t kmac[50] = { 0x00 };
        uint8_t k_icc[16] = { 0x00 };
        uint8_t S[32] = { 0x00 };

        uint8_t rnd_ifd[8], k_ifd[16];
        rng(8, rnd_ifd);
        rng(16, k_ifd);

        PrintAndLogEx(DEBUG, "doc: %s", documentnumber);
        PrintAndLogEx(DEBUG, "dob: %s", dob);
        PrintAndLogEx(DEBUG, "exp: %s", expiry);

        char documentnumbercd = calculate_check_digit(documentnumber);
        char dobcd = calculate_check_digit(dob);
        char expirycd = calculate_check_digit(expiry);

        char kmrz[25];
        sprintf(kmrz, "%s%i%s%i%s%i", documentnumber, documentnumbercd, dob, dobcd, expiry, expirycd);
        PrintAndLogEx(DEBUG, "kmrz: %s", kmrz);

        uint8_t kseed[16] = { 0x00 };
        mbedtls_sha1((unsigned char *)kmrz, strlen(kmrz), kseed);
        PrintAndLogEx(DEBUG, "kseed: %s", sprint_hex_inrow(kseed, 16));

        deskey(kseed, KENC_type, 16, kenc);
        deskey(kseed, KMAC_type, 16, kmac);
        PrintAndLogEx(DEBUG, "kenc: %s", sprint_hex_inrow(kenc, 16));
        PrintAndLogEx(DEBUG, "kmac: %s", sprint_hex_inrow(kmac, 16));

        // Get Challenge
        if (get_challenge(8, rnd_ic, &resplen, use_14b) == false) {
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
        if (external_authenticate(cmd_data, sizeof(cmd_data), response, &resplen, use_14b) == false) {
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
    }

    // Select EF_COM
    if (select_and_read(response, &resplen, EF_COM, ks_enc, ks_mac, ssc, BAC, use_14b) == false) {
        PrintAndLogEx(ERR, "Failed to read EF_COM.");
        DropField();
        return PM3_ESOFT;
    }
    PrintAndLogEx(INFO, "Read EF_COM, len: %i.", resplen);
    PrintAndLogEx(DEBUG, "Contents (may be incomplete over 2k chars): %s", sprint_hex_inrow(response, resplen));
    saveFile("EF_COM", ".BIN", response, resplen);

    uint8_t filelist[50];
    int filelistlen = 0;

    if (ef_com_get_file_list(response, &resplen, filelist, &filelistlen) == false) {
        PrintAndLogEx(ERR, "Failed to read file list from EF_COM.");
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(DEBUG, "File List: %s", sprint_hex_inrow(filelist, filelistlen));

    // Dump all files in the file list
    for (int i = 0; i < filelistlen; i++) {
        char file_id[5] = { 0x00 };
        char file_name[8] = { 0x00 };
        if (file_tag_to_file_id(&filelist[i], file_name, file_id) == false) {
            PrintAndLogEx(INFO, "File tag not found, skipping: %02X", filelist[i]);
            continue;
        }
        PrintAndLogEx(DEBUG, "Current file: %s", file_name);
        dump_file(ks_enc, ks_mac, ssc, file_id, file_name, BAC, use_14b);
    }

    // Dump EF_SOD
    dump_file(ks_enc, ks_mac, ssc, EF_SOD, "EF_SOD", BAC, use_14b);

    DropField();
    return PM3_SUCCESS;
}

static int cmd_hf_emrtd_dump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf emrtd dump",
                  "Dump all files on an eMRTD",
                  "hf emrtd dump"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("n", "documentnumber", "<alphanum>", "9 character document number"),
        arg_str0("d", "dateofbirth", "<YYMMDD>", "date of birth in YYMMDD format"),
        arg_str0("e", "expiry", "<YYMMDD>", "expiry in YYMMDD format"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t docnum[10] = { 0x00 };
    uint8_t dob[7] = { 0x00 };
    uint8_t expiry[7] = { 0x00 };
    bool BAC = true;
    int slen = 0;  // unused
    // Go through all args, if even one isn't supplied, mark BAC as unavailable
    if (CLIParamStrToBuf(arg_get_str(ctx, 1), docnum, 9, &slen) != 0 || slen == 0) {
        BAC = false;
    } else if (CLIParamStrToBuf(arg_get_str(ctx, 2), dob, 6, &slen) != 0 || slen == 0) {
        BAC = false;
    } else if (CLIParamStrToBuf(arg_get_str(ctx, 3), expiry, 6, &slen) != 0 || slen == 0) {
        BAC = false;
    }

    CLIParserFree(ctx);
    return dumpHF_EMRTD((char *)docnum, (char *)dob, (char *)expiry, BAC);
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
    {"dump",    cmd_hf_emrtd_dump, IfPm3Iso14443,   "Dump eMRTD files to binary files"},
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
