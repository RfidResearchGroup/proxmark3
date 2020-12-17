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

// Max file size in bytes. Used in several places.
// Average EF_DG2 seems to be around 20-25kB or so, but ICAO doesn't set an upper limit
// Iris data seems to be suggested to be around 35kB per eye (Presumably bumping up the file size to around 70kB)
// but as we cannot read that until we implement PACE, 35k seems to be a safe point.
#define EMRTD_MAX_FILE_SIZE 35000

// ISO7816 commands
#define EMRTD_SELECT "A4"
#define EMRTD_EXTERNAL_AUTHENTICATE "82"
#define EMRTD_GET_CHALLENGE "84"
#define EMRTD_READ_BINARY "B0"
#define EMRTD_P1_SELECT_BY_EF "02"
#define EMRTD_P1_SELECT_BY_NAME "04"
#define EMRTD_P2_PROPRIETARY "0C"

// File IDs
#define EMRTD_EF_CARDACCESS "011C"
#define EMRTD_EF_COM "011E"
#define EMRTD_EF_DG1 "0101"
#define EMRTD_EF_DG2 "0102"
#define EMRTD_EF_DG3 "0103"
#define EMRTD_EF_DG4 "0104"
#define EMRTD_EF_DG5 "0105"
#define EMRTD_EF_DG6 "0106"
#define EMRTD_EF_DG7 "0107"
#define EMRTD_EF_DG8 "0108"
#define EMRTD_EF_DG9 "0109"
#define EMRTD_EF_DG10 "010A"
#define EMRTD_EF_DG11 "010B"
#define EMRTD_EF_DG12 "010C"
#define EMRTD_EF_DG13 "010D"
#define EMRTD_EF_DG14 "010E"
#define EMRTD_EF_DG15 "010F"
#define EMRTD_EF_DG16 "0110"
#define EMRTD_EF_SOD "011D"

// App IDs
#define EMRTD_AID_MRTD "A0000002471001"

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

static bool emrtd_exchange_commands(const char *cmd, uint8_t *dataout, int *dataoutlen, bool activate_field, bool keep_field_on, bool use_14b) {
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;

    PrintAndLogEx(DEBUG, "Sending: %s", cmd);

    uint8_t aCMD[PM3_CMD_DATA_SIZE];
    int aCMD_n = 0;
    param_gethex_to_eol(cmd, 0, aCMD, sizeof(aCMD), &aCMD_n);
    int res;
    if (use_14b) {
        // need to add a long timeout for passports with activated anti-bruteforce measure
        res = exchange_14b_apdu(aCMD, aCMD_n, activate_field, keep_field_on, response, sizeof(response), &resplen, 15000);
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

static int emrtd_exchange_commands_noout(const char *cmd, bool activate_field, bool keep_field_on, bool use_14b) {
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;

    return emrtd_exchange_commands(cmd, response, &resplen, activate_field, keep_field_on, use_14b);
}

static char emrtd_calculate_check_digit(char *data) {
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

static int emrtd_get_asn1_data_length(uint8_t *datain, int datainlen, int offset) {
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

static int emrtd_get_asn1_field_length(uint8_t *datain, int datainlen, int offset) {
    PrintAndLogEx(DEBUG, "asn1 fieldlength, datain: %s", sprint_hex_inrow(datain, datainlen));
    int lenfield = (int) * (datain + offset);
    PrintAndLogEx(DEBUG, "asn1 fieldlength, thing: %i", lenfield);
    if (lenfield <= 0x7F) {
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

static void emrtd_deskey(uint8_t *seed, const uint8_t *type, int length, uint8_t *dataout) {
    PrintAndLogEx(DEBUG, "seed.............. %s", sprint_hex_inrow(seed, 16));

    // combine seed and type
    uint8_t data[50];
    memcpy(data, seed, length);
    memcpy(data + length, type, 4);
    PrintAndLogEx(DEBUG, "data.............. %s", sprint_hex_inrow(data, length + 4));

    // SHA1 the key
    unsigned char key[64];
    mbedtls_sha1(data, length + 4, key);
    PrintAndLogEx(DEBUG, "key............... %s", sprint_hex_inrow(key, length + 4));

    // Set parity bits
    for (int i = 0; i < ((length + 4) / 8); i++) {
        mbedtls_des_key_set_parity(key + (i * 8));
    }
    PrintAndLogEx(DEBUG, "post-parity key... %s", sprint_hex_inrow(key, 20));

    memcpy(dataout, &key, length);
}

static int emrtd_select_file(const char *select_by, const char *file_id, bool use_14b) {
    int file_id_len = strlen(file_id) / 2;

    char cmd[50];
    sprintf(cmd, "00%s%s0C%02X%s", EMRTD_SELECT, select_by, file_id_len, file_id);

    return emrtd_exchange_commands_noout(cmd, false, true, use_14b);
}

static int emrtd_get_challenge(int length, uint8_t *dataout, int *dataoutlen, bool use_14b) {
    char cmd[50];
    sprintf(cmd, "00%s0000%02X", EMRTD_GET_CHALLENGE, length);

    return emrtd_exchange_commands(cmd, dataout, dataoutlen, false, true, use_14b);
}

static int emrtd_external_authenticate(uint8_t *data, int length, uint8_t *dataout, int *dataoutlen, bool use_14b) {
    char cmd[100];
    sprintf(cmd, "00%s0000%02X%s%02X", EMRTD_EXTERNAL_AUTHENTICATE, length, sprint_hex_inrow(data, length), length);
    return emrtd_exchange_commands(cmd, dataout, dataoutlen, false, true, use_14b);
}

static int _emrtd_read_binary(int offset, int bytes_to_read, uint8_t *dataout, int *dataoutlen, bool use_14b) {
    char cmd[50];
    sprintf(cmd, "00%s%04X%02X", EMRTD_READ_BINARY, offset, bytes_to_read);

    return emrtd_exchange_commands(cmd, dataout, dataoutlen, false, true, use_14b);
}

static void emrtd_bump_ssc(uint8_t *ssc) {
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

static bool emrtd_check_cc(uint8_t *ssc, uint8_t *key, uint8_t *rapdu, int rapdulength) {
    // https://elixi.re/i/clarkson.png
    uint8_t k[500];
    uint8_t cc[500];

    emrtd_bump_ssc(ssc);

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

static void _emrtd_convert_filename(const char *file, uint8_t *dataout) {
    char temp[3] = {0x00};
    memcpy(temp, file, 2);
    dataout[0] = (int)strtol(temp, NULL, 16);
    memcpy(temp, file + 2, 2);
    dataout[1] = (int)strtol(temp, NULL, 16);
}

static bool emrtd_secure_select_file(uint8_t *kenc, uint8_t *kmac, uint8_t *ssc, const char *select_by, const char *file, bool use_14b) {
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;

    // convert filename of string to bytes
    uint8_t file_id[2];
    _emrtd_convert_filename(file, file_id);

    uint8_t iv[8] = { 0x00 };
    char command[PM3_CMD_DATA_SIZE];
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

    emrtd_bump_ssc(ssc);

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

    sprintf(command, "0C%s%s0C%02X%s00", EMRTD_SELECT, select_by, lc, sprint_hex_inrow(data, lc));
    PrintAndLogEx(DEBUG, "command: %s", command);

    if (emrtd_exchange_commands(command, response, &resplen, false, true, use_14b) == false) {
        return false;
    }

    return emrtd_check_cc(ssc, kmac, response, resplen);
}

static bool _emrtd_secure_read_binary(uint8_t *kmac, uint8_t *ssc, int offset, int bytes_to_read, uint8_t *dataout, int *dataoutlen, bool use_14b) {
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

    emrtd_bump_ssc(ssc);

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

    sprintf(command, "0C%s%04X%02X%s00", EMRTD_READ_BINARY, offset, lc, sprint_hex_inrow(data, lc));
    PrintAndLogEx(DEBUG, "command: %s", command);

    if (emrtd_exchange_commands(command, dataout, dataoutlen, false, true, use_14b) == false) {
        return false;
    }

    return emrtd_check_cc(ssc, kmac, dataout, *dataoutlen);
}

static bool _emrtd_secure_read_binary_decrypt(uint8_t *kenc, uint8_t *kmac, uint8_t *ssc, int offset, int bytes_to_read, uint8_t *dataout, int *dataoutlen, bool use_14b) {
    uint8_t response[500];
    uint8_t temp[500];
    int resplen, cutat = 0;
    uint8_t iv[8] = { 0x00 };

    if (_emrtd_secure_read_binary(kmac, ssc, offset, bytes_to_read, response, &resplen, use_14b) == false) {
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

static int emrtd_read_file(uint8_t *dataout, int *dataoutlen, uint8_t *kenc, uint8_t *kmac, uint8_t *ssc, bool use_secure, bool use_14b) {
    uint8_t response[EMRTD_MAX_FILE_SIZE];
    int resplen = 0;
    uint8_t tempresponse[500];
    int tempresplen = 0;
    int toread = 4;
    int offset = 0;

    if (use_secure == true) {
        if (_emrtd_secure_read_binary_decrypt(kenc, kmac, ssc, offset, toread, response, &resplen, use_14b) == false) {
            return false;
        }
    } else {
        if (_emrtd_read_binary(offset, toread, response, &resplen, use_14b) == false) {
            return false;
        }
    }

    int datalen = emrtd_get_asn1_data_length(response, resplen, 1);
    int readlen = datalen - (3 - emrtd_get_asn1_field_length(response, resplen, 1));
    offset = 4;

    while (readlen > 0) {
        toread = readlen;
        if (readlen > 118) {
            toread = 118;
        }

        if (kenc == NULL) {
            if (_emrtd_read_binary(offset, toread, tempresponse, &tempresplen, use_14b) == false) {
                return false;
            }
        } else {
            if (_emrtd_secure_read_binary_decrypt(kenc, kmac, ssc, offset, toread, tempresponse, &tempresplen, use_14b) == false) {
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

static bool emrtd_lds_get_data_by_tag(uint8_t *datain, int *datainlen, uint8_t *dataout, int *dataoutlen, int tag1, int tag2, bool twobytetag) {
    int offset = 1;
    offset += emrtd_get_asn1_field_length(datain, *datainlen, offset);

    int e_idlen = 0;
    int e_datalen = 0;
    int e_fieldlen = 0;
    while (offset < *datainlen) {
        PrintAndLogEx(DEBUG, "emrtd_lds_get_data_by_tag, offset: %i, data: %X", offset, *(datain + offset));
        // Determine element ID length to set as offset on asn1datalength
        if ((*(datain + offset) == 0x5F) || (*(datain + offset) == 0x7F)) {
            e_idlen = 2;
        } else {
            e_idlen = 1;
        }

        // Get the length of the element
        e_datalen = emrtd_get_asn1_data_length(datain + offset, *datainlen - offset, e_idlen);

        // Get the length of the element's length
        e_fieldlen = emrtd_get_asn1_field_length(datain + offset, *datainlen - offset, e_idlen);

        // If the element is what we're looking for, get the data and return true
        if (*(datain + offset) == tag1 && (!twobytetag || *(datain + offset + 1) == tag2)) {

            if ( *datainlen > e_datalen) {
                *dataoutlen = e_datalen;
                memcpy(dataout, datain + offset + e_idlen + e_fieldlen, e_datalen);
                return true;
            } else {
                PrintAndLogEx(ERR, "error (emrtd_lds_get_data_by_tag) e_datalen out-of-bounds");
                return false;
            }
        }
        offset += e_idlen + e_datalen + e_fieldlen;
    }
    // Return false if we can't find the relevant element
    return false;
}

static bool emrtd_file_tag_to_file_id(uint8_t *datain, char *filenameout, char *dataout) {
    // imagine bothering with a hashmap or writing good code
    // couldn't be me
    switch (*datain) {
        case 0x60:
            memcpy(dataout, EMRTD_EF_COM, 4);
            memcpy(filenameout, "EF_COM", 6);
            break;
        case 0x61:
            memcpy(dataout, EMRTD_EF_DG1, 4);
            memcpy(filenameout, "EF_DG1", 6);
            break;
        case 0x75:
            memcpy(dataout, EMRTD_EF_DG2, 4);
            memcpy(filenameout, "EF_DG2", 6);
            break;
        // These cases are commented out as they require PACE
        // case 0x63:
        //     memcpy(dataout, EMRTD_EF_DG3, 4);
        //     memcpy(filenameout, "EF_DG3", 6);
        //     break;
        // case 0x76:
        //     memcpy(dataout, EMRTD_EF_DG4, 4);
        //     memcpy(filenameout, "EF_DG4", 6);
        //     break;
        case 0x65:
            memcpy(dataout, EMRTD_EF_DG5, 4);
            memcpy(filenameout, "EF_DG5", 6);
            break;
        case 0x66:
            memcpy(dataout, EMRTD_EF_DG6, 4);
            memcpy(filenameout, "EF_DG6", 6);
            break;
        case 0x67:
            memcpy(dataout, EMRTD_EF_DG7, 4);
            memcpy(filenameout, "EF_DG7", 6);
            break;
        case 0x68:
            memcpy(dataout, EMRTD_EF_DG8, 4);
            memcpy(filenameout, "EF_DG8", 6);
            break;
        case 0x69:
            memcpy(dataout, EMRTD_EF_DG9, 4);
            memcpy(filenameout, "EF_DG9", 6);
            break;
        case 0x6a:
            memcpy(dataout, EMRTD_EF_DG10, 4);
            memcpy(filenameout, "EF_DG10", 7);
            break;
        case 0x6b:
            memcpy(dataout, EMRTD_EF_DG11, 4);
            memcpy(filenameout, "EF_DG11", 7);
            break;
        case 0x6c:
            memcpy(dataout, EMRTD_EF_DG12, 4);
            memcpy(filenameout, "EF_DG12", 7);
            break;
        case 0x6d:
            memcpy(dataout, EMRTD_EF_DG13, 4);
            memcpy(filenameout, "EF_DG13", 7);
            break;
        case 0x6e:
            memcpy(dataout, EMRTD_EF_DG14, 4);
            memcpy(filenameout, "EF_DG14", 7);
            break;
        case 0x6f:
            memcpy(dataout, EMRTD_EF_DG15, 4);
            memcpy(filenameout, "EF_DG15", 7);
            break;
        case 0x70:
            memcpy(dataout, EMRTD_EF_DG16, 4);
            memcpy(filenameout, "EF_DG16", 7);
            break;
        case 0x77:
            memcpy(dataout, EMRTD_EF_SOD, 4);
            memcpy(filenameout, "EF_SOD", 6);
            break;
        default:
            return false;
    }
    return true;
}

static bool emrtd_select_and_read(uint8_t *dataout, int *dataoutlen, const char *file, uint8_t *ks_enc, uint8_t *ks_mac, uint8_t *ssc, bool use_secure, bool use_14b) {
    if (use_secure == true) {
        if (emrtd_secure_select_file(ks_enc, ks_mac, ssc, EMRTD_P1_SELECT_BY_EF, file, use_14b) == false) {
            PrintAndLogEx(ERR, "Failed to secure select %s.", file);
            return false;
        }
    } else {
        if (emrtd_select_file(EMRTD_P1_SELECT_BY_EF, file, use_14b) == false) {
            PrintAndLogEx(ERR, "Failed to select %s.", file);
            return false;
        }
    }

    if (emrtd_read_file(dataout, dataoutlen, ks_enc, ks_mac, ssc, use_secure, use_14b) == false) {
        PrintAndLogEx(ERR, "Failed to read %s.", file);
        return false;
    }
    return true;
}

static bool emrtd_dump_ef_dg2(uint8_t *file_contents, int file_length) {
    uint8_t data[EMRTD_MAX_FILE_SIZE];
    int datalen = 0;

    // This is a hacky impl that just looks for the image header. I'll improve it eventually.
    // based on mrpkey.py
    // FF D8 FF E0 -> JPEG
    // 00 00 00 0C 6A 50 -> JPEG 2000
    for (int i = 0; i < file_length - 6; i++) {
        if ((file_contents[i] == 0xFF && file_contents[i + 1] == 0xD8 && file_contents[i + 2] == 0xFF && file_contents[i + 3] == 0xE0) ||
            (file_contents[i] == 0x00 && file_contents[i + 1] == 0x00 && file_contents[i + 2] == 0x00 && file_contents[i + 3] == 0x0C && file_contents[i + 4] == 0x6A && file_contents[i + 5] == 0x50)) {
            datalen = file_length - i;
            memcpy(data, file_contents + i, datalen);
            break;
        }
    }

    // If we didn't get any data, return false.
    if (datalen == 0) {
        return false;
    }

    saveFile("EF_DG2", ".jpg", data, datalen);
    return true;
}


static bool emrtd_dump_ef_dg5(uint8_t *file_contents, int file_length) {
    uint8_t data[EMRTD_MAX_FILE_SIZE];
    int datalen = 0;

    // If we can't find image in EF_DG5, return false.
    if (emrtd_lds_get_data_by_tag(file_contents, &file_length, data, &datalen, 0x5F, 0x40, true) == false) {
        return false;
    }

    if (datalen < EMRTD_MAX_FILE_SIZE) {
        saveFile("EF_DG5", ".jpg", data, datalen);
    } else {
        PrintAndLogEx(ERR, "error (emrtd_dump_ef_dg5) datalen out-of-bounds");
        return false;
    }
    return true;
}

static bool emrtd_dump_ef_sod(uint8_t *file_contents, int file_length) {
    uint8_t data[EMRTD_MAX_FILE_SIZE];

    int fieldlen = emrtd_get_asn1_field_length(file_contents, file_length, 1);
    int datalen = emrtd_get_asn1_data_length(file_contents, file_length, 1);
    
    if (fieldlen + 1 < EMRTD_MAX_FILE_SIZE) {
        memcpy(data, file_contents + fieldlen + 1, datalen);
    } else {
        PrintAndLogEx(ERR, "error (emrtd_dump_ef_sod) fieldlen out-of-bounds");
        return false;
    }

    saveFile("EF_SOD", ".p7b", data, datalen);
    return true;
}

static bool emrtd_dump_file(uint8_t *ks_enc, uint8_t *ks_mac, uint8_t *ssc, const char *file, const char *name, bool use_secure, bool use_14b) {
    uint8_t response[EMRTD_MAX_FILE_SIZE];
    int resplen = 0;

    if (emrtd_select_and_read(response, &resplen, file, ks_enc, ks_mac, ssc, use_secure, use_14b) == false) {
        return false;
    }

    PrintAndLogEx(INFO, "Read %s, len: %i.", name, resplen);
    PrintAndLogEx(DEBUG, "Contents (may be incomplete over 2k chars): %s", sprint_hex_inrow(response, resplen));
    saveFile(name, ".BIN", response, resplen);

    if (strcmp(file, EMRTD_EF_DG2) == 0) {
        emrtd_dump_ef_dg2(response, resplen);
    } else if (strcmp(file, EMRTD_EF_DG5) == 0) {
        emrtd_dump_ef_dg5(response, resplen);
    } else if (strcmp(file, EMRTD_EF_SOD) == 0) {
        emrtd_dump_ef_sod(response, resplen);
    }

    return true;
}

static void rng(int length, uint8_t *dataout) {
    // Do very very secure prng operations
    //for (int i = 0; i < (length / 4); i++) {
    //    num_to_bytes(prng_successor(msclock() + i, 32), 4, &dataout[i * 4]);
    //}
    memset(dataout, 0x00, length);   
}

static bool emrtd_do_bac(char *documentnumber, char *dob, char *expiry, uint8_t *ssc, uint8_t *ks_enc, uint8_t *ks_mac, bool use_14b) {
    uint8_t response[EMRTD_MAX_FILE_SIZE] = { 0x00 };
    int resplen = 0;

    uint8_t rnd_ic[8] = { 0x00 };
    uint8_t kenc[50] = { 0x00 };
    uint8_t kmac[50] = { 0x00 };
    uint8_t k_icc[16] = { 0x00 };
    uint8_t S[32] = { 0x00 };

    uint8_t rnd_ifd[8], k_ifd[16];
    rng(8, rnd_ifd);
    rng(16, k_ifd);

    PrintAndLogEx(DEBUG, "doc............... " _GREEN_("%s"), documentnumber);
    PrintAndLogEx(DEBUG, "dob............... " _GREEN_("%s"), dob);
    PrintAndLogEx(DEBUG, "exp............... " _GREEN_("%s"), expiry);

    char documentnumbercd = emrtd_calculate_check_digit(documentnumber);
    char dobcd = emrtd_calculate_check_digit(dob);
    char expirycd = emrtd_calculate_check_digit(expiry);

    char kmrz[25];
    sprintf(kmrz, "%s%i%s%i%s%i", documentnumber, documentnumbercd, dob, dobcd, expiry, expirycd);
    PrintAndLogEx(DEBUG, "kmrz.............. " _GREEN_("%s"), kmrz);

    uint8_t kseed[20] = { 0x00 };
    mbedtls_sha1((unsigned char *)kmrz, strlen(kmrz), kseed);
    PrintAndLogEx(DEBUG, "kseed (sha1)...... %s ", sprint_hex_inrow(kseed, 16));

    emrtd_deskey(kseed, KENC_type, 16, kenc);
    emrtd_deskey(kseed, KMAC_type, 16, kmac);
    PrintAndLogEx(DEBUG, "kenc.............. %s", sprint_hex_inrow(kenc, 16));
    PrintAndLogEx(DEBUG, "kmac.............. %s", sprint_hex_inrow(kmac, 16));

    // Get Challenge
    if (emrtd_get_challenge(8, rnd_ic, &resplen, use_14b) == false) {
        PrintAndLogEx(ERR, "Couldn't get challenge.");
        return false;
    }
    PrintAndLogEx(DEBUG, "rnd_ic............ %s", sprint_hex_inrow(rnd_ic, 8));

    memcpy(S, rnd_ifd, 8);
    memcpy(S + 8, rnd_ic, 8);
    memcpy(S + 16, k_ifd, 16);

    PrintAndLogEx(DEBUG, "S................. %s", sprint_hex_inrow(S, 32));

    uint8_t iv[8] = { 0x00 };
    uint8_t e_ifd[32] = { 0x00 };

    des3_encrypt_cbc(iv, kenc, S, sizeof(S), e_ifd);
    PrintAndLogEx(DEBUG, "e_ifd............. %s", sprint_hex_inrow(e_ifd, 32));

    uint8_t m_ifd[8] = { 0x00 };

    retail_mac(kmac, e_ifd, 32, m_ifd);
    PrintAndLogEx(DEBUG, "m_ifd............. %s", sprint_hex_inrow(m_ifd, 8));

    uint8_t cmd_data[40];
    memcpy(cmd_data, e_ifd, 32);
    memcpy(cmd_data + 32, m_ifd, 8);

    // Do external authentication
    if (emrtd_external_authenticate(cmd_data, sizeof(cmd_data), response, &resplen, use_14b) == false) {
        PrintAndLogEx(ERR, "Couldn't do external authentication. Did you supply the correct MRZ info?");
        return false;
    }
    PrintAndLogEx(INFO, "External authentication with BAC successful.");

    uint8_t dec_output[32] = { 0x00 };
    des3_decrypt_cbc(iv, kenc, response, 32, dec_output);
    PrintAndLogEx(DEBUG, "dec_output........ %s", sprint_hex_inrow(dec_output, 32));

    if (memcmp(rnd_ifd, dec_output + 8, 8) != 0) {
        PrintAndLogEx(ERR, "Challenge failed, rnd_ifd does not match.");
        return false;
    }

    memcpy(k_icc, dec_output + 16, 16);

    // Calculate session keys
    for (int x = 0; x < 16; x++) {
        kseed[x] = k_ifd[x] ^ k_icc[x];
    }

    PrintAndLogEx(DEBUG, "kseed............ %s", sprint_hex_inrow(kseed, 16));

    emrtd_deskey(kseed, KENC_type, 16, ks_enc);
    emrtd_deskey(kseed, KMAC_type, 16, ks_mac);

    PrintAndLogEx(DEBUG, "ks_enc........ %s", sprint_hex_inrow(ks_enc, 16));
    PrintAndLogEx(DEBUG, "ks_mac........ %s", sprint_hex_inrow(ks_mac, 16));

    memcpy(ssc, rnd_ic + 4, 4);
    memcpy(ssc + 4, rnd_ifd + 4, 4);

    PrintAndLogEx(DEBUG, "ssc........... %s", sprint_hex_inrow(ssc, 8));

    return true;
}

static bool emrtd_connect(bool *use_14b) {
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
            PrintAndLogEx(INFO, "No eMRTD spotted with 14b, exiting.");
            return false;
        }

        if (resp.oldarg[0] != 0) {
            PrintAndLogEx(INFO, "No eMRTD spotted with 14b, exiting.");
            return false;
        }
        *use_14b = true;
    }
    return true;
}

static bool emrtd_do_auth(char *documentnumber, char *dob, char *expiry, bool BAC_available, bool *BAC, uint8_t *ssc, uint8_t *ks_enc, uint8_t *ks_mac, bool *use_14b) {
    uint8_t response[EMRTD_MAX_FILE_SIZE] = { 0x00 };
    int resplen = 0;

    // Select and read EF_CardAccess
    if (emrtd_select_file(EMRTD_P1_SELECT_BY_EF, EMRTD_EF_CARDACCESS, *use_14b)) {
        emrtd_read_file(response, &resplen, NULL, NULL, NULL, false, *use_14b);
        PrintAndLogEx(INFO, "Read EF_CardAccess, len: %i.", resplen);
        PrintAndLogEx(DEBUG, "Contents (may be incomplete over 2k chars): %s", sprint_hex_inrow(response, resplen));
    } else {
        PrintAndLogEx(INFO, "PACE unsupported. Will not read EF_CardAccess.");
    }

    // Select MRTD applet
    if (emrtd_select_file(EMRTD_P1_SELECT_BY_NAME, EMRTD_AID_MRTD, *use_14b) == false) {
        PrintAndLogEx(ERR, "Couldn't select the MRTD application.");
        return false;
    }

    // Select EF_COM
    if (emrtd_select_file(EMRTD_P1_SELECT_BY_EF, EMRTD_EF_COM, *use_14b) == false) {
        *BAC = true;
        PrintAndLogEx(INFO, "Basic Access Control is enforced. Will attempt external authentication.");
    } else {
        *BAC = false;
        // Select EF_DG1
        emrtd_select_file(EMRTD_P1_SELECT_BY_EF, EMRTD_EF_DG1, *use_14b);

        if (emrtd_read_file(response, &resplen, NULL, NULL, NULL, false, *use_14b) == false) {
            *BAC = true;
            PrintAndLogEx(INFO, "Basic Access Control is enforced. Will attempt external authentication.");
        } else {
            *BAC = false;
            PrintAndLogEx(INFO, "EF_DG1: %s", sprint_hex(response, resplen));
        }
    }

    // Do Basic Access Aontrol
    if (*BAC) {
        // If BAC isn't available, exit out and warn user.
        if (!BAC_available) {
            PrintAndLogEx(ERR, "This eMRTD enforces Basic Access Control, but you didn't supply MRZ data. Cannot proceed.");
            PrintAndLogEx(HINT, "Check out hf emrtd info/dump --help, supply data with -n -d and -e.");
            return false;
        }

        if (emrtd_do_bac(documentnumber, dob, expiry, ssc, ks_enc, ks_mac, *use_14b) == false) {
            return false;
        }
    }

    return true;
}

int dumpHF_EMRTD(char *documentnumber, char *dob, char *expiry, bool BAC_available) {
    uint8_t response[EMRTD_MAX_FILE_SIZE] = { 0x00 };
    int resplen = 0;
    uint8_t ssc[8] = { 0x00 };
    uint8_t ks_enc[16] = { 0x00 };
    uint8_t ks_mac[16] = { 0x00 };
    bool BAC = false;
    bool use_14b = false;

    // Select the eMRTD
    if (!emrtd_connect(&use_14b)) {
        DropField();
        return PM3_ESOFT;
    }

    // Authenticate with the eMRTD
    if (!emrtd_do_auth(documentnumber, dob, expiry, BAC_available, &BAC, ssc, ks_enc, ks_mac, &use_14b)) {
        DropField();
        return PM3_ESOFT;
    }

    // Select EF_COM
    if (!emrtd_select_and_read(response, &resplen, EMRTD_EF_COM, ks_enc, ks_mac, ssc, BAC, use_14b)) {
        PrintAndLogEx(ERR, "Failed to read EF_COM.");
        DropField();
        return PM3_ESOFT;
    }
    PrintAndLogEx(INFO, "Read EF_COM, len: %i.", resplen);
    PrintAndLogEx(DEBUG, "Contents (may be incomplete over 2k chars): %s", sprint_hex_inrow(response, resplen));
    saveFile("EF_COM", ".BIN", response, resplen);

    uint8_t filelist[50];
    int filelistlen = 0;

    if (!emrtd_lds_get_data_by_tag(response, &resplen, filelist, &filelistlen, 0x5c, 0x00, false)) {
        PrintAndLogEx(ERR, "Failed to read file list from EF_COM.");
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(DEBUG, "File List: %s", sprint_hex_inrow(filelist, filelistlen));

    // Dump all files in the file list
    for (int i = 0; i < filelistlen; i++) {
        char file_id[5] = { 0x00 };
        char file_name[8] = { 0x00 };
        if (emrtd_file_tag_to_file_id(&filelist[i], file_name, file_id) == false) {
            PrintAndLogEx(INFO, "File tag not found, skipping: %02X", filelist[i]);
            continue;
        }
        PrintAndLogEx(DEBUG, "Current file: %s", file_name);
        emrtd_dump_file(ks_enc, ks_mac, ssc, file_id, file_name, BAC, use_14b);
    }

    // Dump EF_SOD
    emrtd_dump_file(ks_enc, ks_mac, ssc, EMRTD_EF_SOD, "EF_SOD", BAC, use_14b);

    DropField();
    return PM3_SUCCESS;
}

static bool emrtd_compare_check_digit(char *datain, int datalen, char expected_check_digit) {
    char tempdata[90] = { 0x00 };
    memcpy(tempdata, datain, datalen);

    uint8_t check_digit = emrtd_calculate_check_digit(tempdata) + 0x30;
    bool res =check_digit == expected_check_digit;
    PrintAndLogEx(DEBUG, "emrtd_compare_check_digit, expected %c == %c calculated ( %s )"
        , expected_check_digit
        , check_digit
        , (res) ? _GREEN_("ok") : _RED_("fail"));
    return res;
}

static bool emrtd_mrz_verify_check_digit(char *mrz, int offset, int datalen) {
    char tempdata[90] = { 0x00 };
    memcpy(tempdata, mrz + offset, datalen);
    return emrtd_compare_check_digit(tempdata, datalen, mrz[offset + datalen]);
}

static void emrtd_print_legal_sex(char *legal_sex) {
    char sex[12] = { 0x00 };
    switch (*legal_sex) {
        case 'M':
            strncpy(sex, "Male", 5);
            break;
        case 'F':
            strncpy(sex, "Female", 7);
            break;
        case '<':
            strncpy(sex, "Unspecified", 12);
            break;
    }
    PrintAndLogEx(SUCCESS, "Legal Sex Marker......: " _YELLOW_("%s"), sex);
}

static int emrtd_mrz_determine_length(char *mrz, int offset, int max_length) {
    int i;
    for (i = max_length; i >= 0; i--) {
        if (mrz[offset + i - 1] != '<') {
            break;
        }
    }
    return i;
}

static int emrtd_mrz_determine_separator(char *mrz, int offset, int max_length) {
    int i;
    for (i = max_length; i >= 0; i--) {
        if (mrz[offset + i - 1] == '<' && mrz[offset + i] == '<') {
            break;
        }
    }
    return i - 1;
}

static void emrtd_print_optional_elements(char *mrz, int offset, int length, bool verify_check_digit) {
    int i = emrtd_mrz_determine_length(mrz, offset, length);

    // Only print optional elements if they're available
    if (i != 0) {
        PrintAndLogEx(SUCCESS, "Optional elements.....: " _YELLOW_("%.*s"), i, mrz + offset);
    }

    if (verify_check_digit && !emrtd_mrz_verify_check_digit(mrz, offset, length)) {
        PrintAndLogEx(SUCCESS, _RED_("Optional element check digit is invalid."));
    }
}

static void emrtd_print_document_number(char *mrz, int offset) {
    int i = emrtd_mrz_determine_length(mrz, offset, 9);

    PrintAndLogEx(SUCCESS, "Document Number.......: " _YELLOW_("%.*s"), i, mrz + offset);

    if (!emrtd_mrz_verify_check_digit(mrz, offset, 9)) {
        PrintAndLogEx(SUCCESS, _RED_("Document number check digit is invalid."));
    }
}

static void emrtd_print_name(char *mrz, int offset, int max_length) {
    char final_name[100] = { 0x00 };
    int i = emrtd_mrz_determine_length(mrz, offset, max_length);
    int sep = emrtd_mrz_determine_separator(mrz, offset, i);
    int namelen = (i - (sep + 2));

    memcpy(final_name, mrz + offset + sep + 2, namelen);
    final_name[namelen] = ' ';
    memcpy(final_name + namelen + 1, mrz + offset, sep);

    PrintAndLogEx(SUCCESS, "Legal Name............: " _YELLOW_("%s"), final_name);
}

static void emrtd_mrz_convert_date(char *mrz, int offset, char *final_date, bool is_expiry) {
    char temp_year[3] = { 0x00 };

    memcpy(temp_year, mrz + offset, 2);
    // If it's > 20, assume 19xx.
    if (strtol(temp_year, NULL, 10) < 20 || is_expiry) {
        final_date[0] = '2';
        final_date[1] = '0';
    } else {
        final_date[0] = '1';
        final_date[1] = '9';
    }

    memcpy(final_date + 2, mrz + offset, 2);
    final_date[4] = '-';
    memcpy(final_date + 5, mrz + offset + 2, 2);
    final_date[7] = '-';
    memcpy(final_date + 8, mrz + offset + 4, 2);
}

static void emrtd_print_dob(char *mrz, int offset) {
    char final_date[12] = { 0x00 };
    emrtd_mrz_convert_date(mrz, offset, final_date, false);

    PrintAndLogEx(SUCCESS, "Date of birth.........: " _YELLOW_("%s"), final_date);

    if (!emrtd_mrz_verify_check_digit(mrz, offset, 6)) {
        PrintAndLogEx(SUCCESS, _RED_("Date of Birth check digit is invalid."));
    }
}

static void emrtd_print_expiry(char *mrz, int offset) {
    char final_date[12] = { 0x00 };
    emrtd_mrz_convert_date(mrz, offset, final_date, true);

    PrintAndLogEx(SUCCESS, "Date of expiry........: " _YELLOW_("%s"), final_date);

    if (!emrtd_mrz_verify_check_digit(mrz, offset, 6)) {
        PrintAndLogEx(SUCCESS, _RED_("Date of expiry check digit is invalid."));
    }
}

int infoHF_EMRTD(char *documentnumber, char *dob, char *expiry, bool BAC_available) {
    uint8_t response[EMRTD_MAX_FILE_SIZE] = { 0x00 };
    int resplen = 0;
    uint8_t ssc[8] = { 0x00 };
    uint8_t ks_enc[16] = { 0x00 };
    uint8_t ks_mac[16] = { 0x00 };
    bool BAC = false;
    bool use_14b = false;

    int td_variant = 0;

    // Select the eMRTD
    if (!emrtd_connect(&use_14b)) {
        DropField();
        return PM3_ESOFT;
    }

    // Select and authenticate with the eMRTD
    bool auth_result = emrtd_do_auth(documentnumber, dob, expiry, BAC_available, &BAC, ssc, ks_enc, ks_mac, &use_14b);
    PrintAndLogEx(SUCCESS, "Communication standard: %s", use_14b ? _YELLOW_("ISO/IEC 14443(B)") : _YELLOW_("ISO/IEC 14443(A)"));
    PrintAndLogEx(SUCCESS, "BAC...................: %s", BAC ? _GREEN_("Enforced") : _RED_("Not enforced"));
    PrintAndLogEx(SUCCESS, "Authentication result.: %s", auth_result ? _GREEN_("Successful") : _RED_("Failed"));

    if (!auth_result) {
        DropField();
        return PM3_ESOFT;
    }

    // Select EF_DG1
    if (emrtd_select_and_read(response, &resplen, EMRTD_EF_DG1, ks_enc, ks_mac, ssc, BAC, use_14b) == false) {
        PrintAndLogEx(ERR, "Failed to read EF_DG1.");
        DropField();
        return PM3_ESOFT;
    }

    // MRZ on TD1 is 90 characters, 30 on each row.
    // MRZ on TD3 is 88 characters, 44 on each row.
    char mrz[90] = { 0x00 };
    int mrzlen = 0;

    if (!emrtd_lds_get_data_by_tag(response, &resplen, (uint8_t *) mrz, &mrzlen, 0x5f, 0x1f, true)) {
        PrintAndLogEx(ERR, "Failed to read MRZ from EF_DG1.");
        DropField();
        return PM3_ESOFT;
    }

    // Determine and print the document type
    if (mrz[0] == 'I' && mrz[1] == 'P') {
        td_variant = 1;
        PrintAndLogEx(SUCCESS, "Document Type.........: " _YELLOW_("Passport Card"));
    } else if (mrz[0] == 'I') {
        td_variant = 1;
        PrintAndLogEx(SUCCESS, "Document Type.........: " _YELLOW_("ID Card"));
    } else if (mrz[0] == 'P') {
        td_variant = 3;
        PrintAndLogEx(SUCCESS, "Document Type.........: " _YELLOW_("Passport"));
    } else {
        td_variant = 1;
        PrintAndLogEx(SUCCESS, "Document Type.........: " _YELLOW_("Unknown"));
        PrintAndLogEx(INFO, "Assuming ID-style MRZ.");
    }
    PrintAndLogEx(SUCCESS, "Document Form Factor..: " _YELLOW_("TD%i"), td_variant);

    // Print the MRZ
    if (td_variant == 1) {
        PrintAndLogEx(DEBUG, "MRZ Row 1: " _YELLOW_("%.30s"), mrz);
        PrintAndLogEx(DEBUG, "MRZ Row 2: " _YELLOW_("%.30s"), mrz + 30);
        PrintAndLogEx(DEBUG, "MRZ Row 3: " _YELLOW_("%.30s"), mrz + 60);
    } else if (td_variant == 3) {
        PrintAndLogEx(DEBUG, "MRZ Row 1: " _YELLOW_("%.44s"), mrz);
        PrintAndLogEx(DEBUG, "MRZ Row 2: " _YELLOW_("%.44s"), mrz + 44);
    }

    PrintAndLogEx(SUCCESS, "Issuing state.........: " _YELLOW_("%.3s"), mrz + 2);

    if (td_variant == 3) {
        // Passport form factor
        PrintAndLogEx(SUCCESS, "Nationality...........: " _YELLOW_("%.3s"), mrz + 44 + 10);
        emrtd_print_name(mrz, 5, 38);
        emrtd_print_document_number(mrz, 44);
        emrtd_print_dob(mrz, 44 + 13);
        emrtd_print_legal_sex(&mrz[44 + 20]);
        emrtd_print_expiry(mrz, 44 + 21);
        emrtd_print_optional_elements(mrz, 44 + 28, 14, true);

        // Calculate and verify composite check digit
        char composite_check_data[50] = { 0x00 };
        memcpy(composite_check_data, mrz + 44, 10);
        memcpy(composite_check_data + 10, mrz + 44 + 13, 7);
        memcpy(composite_check_data + 17, mrz + 44 + 21, 23);

        if (!emrtd_compare_check_digit(composite_check_data, 39, mrz[87])) {
            PrintAndLogEx(SUCCESS, _RED_("Composite check digit is invalid."));
        }
    } else if (td_variant == 1) {
        // ID form factor
        PrintAndLogEx(SUCCESS, "Nationality...........: " _YELLOW_("%.3s"), mrz + 30 + 15);
        emrtd_print_name(mrz, 60, 30);
        emrtd_print_document_number(mrz, 5);
        emrtd_print_dob(mrz, 30);
        emrtd_print_legal_sex(&mrz[30 + 7]);
        emrtd_print_expiry(mrz, 30 + 8);
        emrtd_print_optional_elements(mrz, 15, 15, false);
        emrtd_print_optional_elements(mrz, 30 + 18, 11, false);

        // Calculate and verify composite check digit
        if (!emrtd_compare_check_digit(mrz, 59, mrz[59])) {
            PrintAndLogEx(SUCCESS, _RED_("Composite check digit is invalid."));
        }
    }

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
        arg_str0("n", "documentnumber", "<alphanum>", "document number, up to 9 chars"),
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
    } else {
        if (slen != 9) {
            // Pad to 9 with <
            memset(docnum + slen, 0x3c, 9 - slen);
        }
    }
    
    if (CLIParamStrToBuf(arg_get_str(ctx, 2), dob, 6, &slen) != 0 || slen == 0) {
        BAC = false;
    } 
    
    if (CLIParamStrToBuf(arg_get_str(ctx, 3), expiry, 6, &slen) != 0 || slen == 0) {
        BAC = false;
    }

    CLIParserFree(ctx);
    return dumpHF_EMRTD((char *)docnum, (char *)dob, (char *)expiry, BAC);
}

static int cmd_hf_emrtd_info(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf emrtd info",
                  "Display info about an eMRTD",
                  "hf emrtd info"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("n", "documentnumber", "<alphanum>", "document number, up to 9 chars"),
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
    } else {
        if ( slen != 9) {
            memset(docnum + slen, 0x3c, 9 - slen);
        }
    }
    
    if (CLIParamStrToBuf(arg_get_str(ctx, 2), dob, 6, &slen) != 0 || slen == 0) {
        BAC = false;
    } 
    
    if (CLIParamStrToBuf(arg_get_str(ctx, 3), expiry, 6, &slen) != 0 || slen == 0) {
        BAC = false;
    }

    CLIParserFree(ctx);
    return infoHF_EMRTD((char *)docnum, (char *)dob, (char *)expiry, BAC);
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
    {"info",    cmd_hf_emrtd_info, IfPm3Iso14443,   "Display info about an eMRTD"},
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
