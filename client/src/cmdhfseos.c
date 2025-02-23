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
// SEOS commands
//-----------------------------------------------------------------------------
#include "cmdhfseos.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>              // tolower
#include "cliparser.h"
#include "cmdparser.h"          // command_t
#include "comms.h"              // clearCommandBuffer
#include "cmdtrace.h"
#include <mbedtls/cmac.h>
#include <mbedtls/des.h>
#include "fileutils.h"
#include "crc16.h"
#include "ui.h"
#include "cmdhf14a.h"           // manufacture
#include "protocols.h"          // definitions of ISO14A/7816 protocol
#include "cardhelper.h"
#include "wiegand_formats.h"
#include "wiegand_formatutils.h"
#include "iso7816/apduinfo.h"   // GetAPDUCodeDescription
#include "crypto/asn1utils.h"   // ASN1 decode / print
#include "crypto/libpcrypto.h"  // AES decrypt
#include "commonutil.h"         // get_sw
#include "protocols.h"          // ISO7816 APDU return codes
#include "hidsio.h"

static uint8_t zeros[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static int CmdHelp(const char *Cmd);

typedef struct {
    uint8_t nonce[8];
    uint8_t privEncKey[16];
    uint8_t privMacKey[16];
    uint8_t readKey[16];
    uint8_t writeKey[16];
    uint8_t adminKey[16];
} keyset_t;

keyset_t keys[] = {
    {
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },                                         // Nonce
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // privEncKey
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // privMacKey
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // readKey
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // writeKey
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } // adminKey
    },
    {
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },                                         // Nonce
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // privEncKey
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // privMacKey
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // readKey
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // writeKey
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } // adminKey
    },
    {
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },                                         // Nonce
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // privEncKey
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // privMacKey
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // readKey
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // writeKey
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } // adminKey
    },
    {
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },                                         // Nonce
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // privEncKey
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // privMacKey
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // readKey
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // writeKey
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } // adminKey
    },
};

typedef struct {
    const int value;
    const char *name;
} known_algo_t;

static const known_algo_t known_algorithm_map[] = {
    {2, "2K3DES_CBC_MODE"},
    {4, "3K3DES_CBC_MODE"},
    {6, "SHA-1"},
    {7, "SHA-256"},
    {9, "AES-128_CBC_MODE"},
};

static int create_cmac(uint8_t *key, uint8_t *input, uint8_t *out, int input_len, int encryption_algorithm) {
    uint8_t iv[16] = {0x00};

    if (encryption_algorithm == 0x09) {
        // Working as expected
        aes_cmac(iv, key, input, out, input_len);
    } else if (encryption_algorithm == 0x02) {
        // CMAC Requires a 24 byte key, but the 2k3DES uses the 1st part for the 3rd part of the key
        memcpy(&key[16], &key[0], 8);

        const mbedtls_cipher_info_t *ctx;
        ctx = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_DES_EDE3_ECB);
        mbedtls_cipher_cmac(ctx, key, 192, input, input_len, out);
    } else {
        PrintAndLogEx(ERR, _RED_("Unknown Encryption Algorithm"));
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

static int create_cryptogram(uint8_t *key, uint8_t *input, uint8_t *out, int input_len, int encryption_algorithm) {
    uint8_t iv[16] = {};

    if (encryption_algorithm == 0x09) {
        aes_encode(iv, key, input, out, input_len);
    } else if (encryption_algorithm == 0x02) {
        mbedtls_des3_context ctx3;
        mbedtls_des3_set2key_enc(&ctx3, key);
        mbedtls_des3_crypt_cbc(&ctx3, MBEDTLS_DES_ENCRYPT, input_len, iv, input, out);
        mbedtls_des3_free(&ctx3);
    } else {
        PrintAndLogEx(ERR, _RED_("Unknown Encryption Algorithm"));
        return PM3_ESOFT;
    }

    return PM3_SUCCESS;
}

static int decrypt_cryptogram(uint8_t *key, uint8_t *input, uint8_t *out, int input_len, int encryption_algorithm) {
    uint8_t iv[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    if (encryption_algorithm == 0x09) {
        aes_decode(iv, key, input, out, input_len);
    } else if (encryption_algorithm == 0x02) {
        mbedtls_des3_context ctx3;
        mbedtls_des3_set2key_dec(&ctx3, key);
        mbedtls_des3_crypt_cbc(&ctx3, MBEDTLS_DES_DECRYPT, input_len, iv, input, out);
        mbedtls_des3_free(&ctx3);
    } else {
        PrintAndLogEx(ERR, "Unknown Encryption Algorithm");
        return PM3_ESOFT;
    }

    return PM3_SUCCESS;
}

static void increment_command_wrapper(uint8_t *input, int input_len) {
    input[input_len - 1]++; // Increment the last element of the header by 1
}

static void padToBlockSize(const uint8_t *input, int inputSize, int blockSize, uint8_t *output) {
    int paddingSize = blockSize - (inputSize % blockSize);
    memcpy(output, input, inputSize);
    memset(output + inputSize, 0x80, 1);
    memset(output + inputSize + 1, 0x00, paddingSize - 1);
}

static void generate_command_wrapping(uint8_t *command_Header, int command_header_len, uint8_t *unencrypted_Command, int unencrypted_command_len, uint8_t *rndICC, uint8_t *rndIFD, uint8_t *diversified_enc_key, uint8_t *diversified_mac_key, int encryption_algorithm, uint8_t *command, int *command_len) {
    int block_size = 0;

    if (encryption_algorithm == 0x02) {
        block_size = 8;
    } else if (encryption_algorithm == 0x09) {
        block_size = 16;
    } else {
        PrintAndLogEx(ERR, _RED_("Unknown Encryption Algorithm"));
        return;
    }

    uint8_t rndCounter[block_size];
    memcpy(rndCounter, rndICC, block_size / 2);
    memcpy(rndCounter + block_size / 2, rndIFD, block_size / 2);
    increment_command_wrapper(rndCounter, block_size);

    // Command Header is for the APDU Command to be sent
    uint8_t padded_Command_Header[block_size];
    padToBlockSize(command_Header, command_header_len, block_size, padded_Command_Header);

    // Unencrypted Command is our actual command data
    uint8_t padded_unencrypted_Command[block_size];
    padToBlockSize(unencrypted_Command, unencrypted_command_len, block_size, padded_unencrypted_Command);

    uint8_t padded_encrypted_Command[block_size];
    create_cryptogram(diversified_enc_key, padded_unencrypted_Command, padded_encrypted_Command, sizeof(padded_unencrypted_Command), encryption_algorithm);

    uint8_t asn1_tag_cryptograph[2] = {0x85, ARRAYLEN(padded_encrypted_Command)};
    uint8_t asn1_tag_mac[2] = {0x8e, 0x08};
    uint8_t command_trailer[2] = {0x97, 0x00};
    uint8_t padded_command_trailer[block_size - ARRAYLEN(command_trailer)];
    padToBlockSize(command_trailer, sizeof(command_trailer), block_size, padded_command_trailer);

    uint8_t toEncrypt[ARRAYLEN(rndCounter) + ARRAYLEN(padded_Command_Header) + ARRAYLEN(asn1_tag_cryptograph) + ARRAYLEN(padded_encrypted_Command) + ARRAYLEN(padded_command_trailer)];

    memcpy(toEncrypt, rndCounter, ARRAYLEN(rndCounter));
    memcpy(toEncrypt + ARRAYLEN(rndCounter), padded_Command_Header, ARRAYLEN(padded_Command_Header));
    memcpy(toEncrypt + ARRAYLEN(rndCounter) + ARRAYLEN(padded_Command_Header), asn1_tag_cryptograph, ARRAYLEN(asn1_tag_cryptograph));
    memcpy(toEncrypt + ARRAYLEN(rndCounter) + ARRAYLEN(padded_Command_Header) + ARRAYLEN(asn1_tag_cryptograph), padded_encrypted_Command, ARRAYLEN(padded_encrypted_Command));
    memcpy(toEncrypt + ARRAYLEN(rndCounter) + ARRAYLEN(padded_Command_Header) + ARRAYLEN(asn1_tag_cryptograph) + ARRAYLEN(padded_encrypted_Command), padded_command_trailer, ARRAYLEN(padded_command_trailer));

    // Breakdown
    // 0181e43801010201 + 0000000000000001 + 0CCB3FFF800000000000000000000000 + 8510EB54DA90CB43AEE7FBFE816ECA25A10D + 9700 + 800000000000000000000000

    uint8_t mac[8];
    create_cmac(diversified_mac_key, toEncrypt, mac, sizeof(toEncrypt), encryption_algorithm);

    // PrintAndLogEx(SUCCESS, "Encryption Key................... " _YELLOW_("%s"), sprint_hex_inrow(diversified_enc_key, 24));
    // PrintAndLogEx(SUCCESS, "MAC Key.......................... " _YELLOW_("%s"), sprint_hex_inrow(diversified_mac_key, 24));
    // PrintAndLogEx(SUCCESS, "rndCounter....................... " _YELLOW_("%s"), sprint_hex_inrow(rndCounter,sizeof(rndCounter)));
    // PrintAndLogEx(SUCCESS, "padded_encrypted_Command......... " _YELLOW_("%s"), sprint_hex_inrow(padded_encrypted_Command,sizeof(padded_encrypted_Command)));
    // PrintAndLogEx(SUCCESS, "toEncrypt........................ " _YELLOW_("%s"), sprint_hex_inrow(toEncrypt,sizeof(toEncrypt)));
    // PrintAndLogEx(SUCCESS, "MAC.............................. " _YELLOW_("%s"), sprint_hex_inrow(mac,sizeof(mac)));

    uint8_t sizeofcommand[1] = {ARRAYLEN(asn1_tag_cryptograph) + ARRAYLEN(padded_encrypted_Command) + ARRAYLEN(command_trailer) + ARRAYLEN(asn1_tag_mac) + ARRAYLEN(mac)};
    uint8_t respondTo[1] = {0x00};

    uint8_t completedCommand[command_header_len + 1 + ARRAYLEN(asn1_tag_cryptograph) + ARRAYLEN(padded_encrypted_Command) + ARRAYLEN(command_trailer) + ARRAYLEN(asn1_tag_mac) + ARRAYLEN(mac) + 1];
    memcpy(completedCommand, command_Header, command_header_len);
    memcpy(completedCommand + command_header_len, sizeofcommand, ARRAYLEN(sizeofcommand));
    memcpy(completedCommand + command_header_len + ARRAYLEN(sizeofcommand), asn1_tag_cryptograph, ARRAYLEN(asn1_tag_cryptograph));
    memcpy(completedCommand + command_header_len + ARRAYLEN(sizeofcommand) + ARRAYLEN(asn1_tag_cryptograph), padded_encrypted_Command, ARRAYLEN(padded_encrypted_Command));
    memcpy(completedCommand + command_header_len + ARRAYLEN(sizeofcommand) + ARRAYLEN(asn1_tag_cryptograph) + ARRAYLEN(padded_encrypted_Command), command_trailer, ARRAYLEN(command_trailer));
    memcpy(completedCommand + command_header_len + ARRAYLEN(sizeofcommand) + ARRAYLEN(asn1_tag_cryptograph) + ARRAYLEN(padded_encrypted_Command) + ARRAYLEN(command_trailer), asn1_tag_mac, ARRAYLEN(asn1_tag_mac));
    memcpy(completedCommand + command_header_len + ARRAYLEN(sizeofcommand) + ARRAYLEN(asn1_tag_cryptograph) + ARRAYLEN(padded_encrypted_Command) + ARRAYLEN(command_trailer) + ARRAYLEN(asn1_tag_mac), mac, ARRAYLEN(mac));
    memcpy(completedCommand + command_header_len + ARRAYLEN(sizeofcommand) + ARRAYLEN(asn1_tag_cryptograph) + ARRAYLEN(padded_encrypted_Command) + ARRAYLEN(command_trailer) + ARRAYLEN(asn1_tag_mac) + ARRAYLEN(mac), respondTo, 1);

    // PrintAndLogEx(INFO, "--- " _CYAN_("Command Generation") " ---------------------------");
    // PrintAndLogEx(SUCCESS, "Command Header................... " _YELLOW_("%s"), sprint_hex_inrow(command_Header,sizeof(command_Header)));
    // PrintAndLogEx(SUCCESS, "Payload.......................... " _YELLOW_("%s"), sprint_hex_inrow(unencrypted_Command,sizeof(unencrypted_Command)));
    // PrintAndLogEx(SUCCESS, "completedCommand................. " _YELLOW_("%s"), sprint_hex_inrow(completedCommand,sizeof(completedCommand)));

    memcpy(command, completedCommand, ARRAYLEN(completedCommand));
    *command_len = ARRAYLEN(completedCommand);
    //return;
}

static int seos_get_data(uint8_t *rndICC, uint8_t *rndIFD, uint8_t *diversified_enc_key, uint8_t *diversified_mac_key, uint8_t *sioOutput,  int *sio_size, int encryption_algorithm, uint8_t *get_data_tlv, int get_data_tlv_len) {
    // Intergrating our command generation with the GetData request to make my life easier in the future

    // Command Header is for the Get Data Command using
    // `0C` - Secure messaging – ISO/IEC 7816 standard, command header authenticated (C-MAC)
    // `CB` - GET DATA
    //     uint8_t command_header[4] = {0x0c,0xcb,0x3f,0xff};
    uint8_t cla[1] = {0x0c};    // Secure Messaging Command Header
    uint8_t ins[1] = {0xcb};    // GET DATA Instruction
    uint8_t p1[1] = {0x3f};     // High order tag value (accoring to NIST.SP.800-73pt2-5.pdf, this is the hardcoded tag value)
    uint8_t p2[1] = {0xff};     // Low order tag value

    // command builder
    uint8_t command_header[ARRAYLEN(cla) + ARRAYLEN(ins) + ARRAYLEN(p1) + ARRAYLEN(p2)];
    memcpy(command_header, cla, ARRAYLEN(cla));
    memcpy(command_header + ARRAYLEN(cla), ins, ARRAYLEN(ins));
    memcpy(command_header + ARRAYLEN(cla) + ARRAYLEN(ins), p1, ARRAYLEN(p1));
    memcpy(command_header + ARRAYLEN(cla) + ARRAYLEN(ins) + ARRAYLEN(p1), p2, ARRAYLEN(p2));

    int command_header_len = ARRAYLEN(command_header);

    // Command to be sent
    // 5c [02] ff 00
    // 5c = tag list data object
    // BER-TLV tag of the data object to be retrieved
    // uint8_t unencrypted_command[4] = {0x5c,0x02,0xff,0x00};
    // Modification of the tags 2nd place from 00 can return other data

    uint8_t unencrypted_command[get_data_tlv_len];
    memcpy(unencrypted_command, get_data_tlv, get_data_tlv_len);

    int unencrypted_command_len = ARRAYLEN(unencrypted_command);

    uint8_t command_buffer[254];
    int command_len = 0;

    // PrintAndLogEx(SUCCESS, "Raw Command...................... " _YELLOW_("%s"), sprint_hex_inrow(unencrypted_command, get_data_tlv_len));
    generate_command_wrapping(command_header, command_header_len, unencrypted_command, unencrypted_command_len, rndICC, rndIFD, diversified_enc_key, diversified_mac_key, encryption_algorithm, command_buffer, &command_len);

    // Convert command from buffer to stream
    uint8_t command_convert[command_len];
    memcpy(command_convert, command_buffer, command_len);
    char completedCommandChar[sizeof(command_len) * 2 + 1];
    for (int i = 0; i < sizeof(command_convert); i++) {
        snprintf(&completedCommandChar[i * 2], 3, "%02X", command_convert[i]);
    }
    // PrintAndLogEx(SUCCESS, "Command.......................... " _YELLOW_("%s"), completedCommandChar);

    // ------------------- Send Command -------------------
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;

    bool activate_field = false;
    bool keep_field_on = true;

    uint8_t aGET_CHALLENGE[100];
    int aGET_CHALLENGE_n = command_len;
    param_gethex_to_eol(completedCommandChar, 0, aGET_CHALLENGE, sizeof(aGET_CHALLENGE), &aGET_CHALLENGE_n);
    int res = ExchangeAPDU14a(aGET_CHALLENGE, aGET_CHALLENGE_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }
    uint16_t sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Get Data Failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "--- " _CYAN_("Get Data") " ---------------------------");
    // Raw response contains a few values
    // 85 is our cryptogram response (64 bytes)
    // 99 is our status word response (2 bytes)
    // 8E is our MAC response (8 bytes)
    // PrintAndLogEx(SUCCESS, "Raw Response..................... " _YELLOW_("%s"), sprint_hex_inrow(response, (resplen - 2)));

    uint8_t cryptogram[64];
    uint8_t responseCode[2];
    uint8_t tag[2] = {0x00, 0x00};
    int getDataSize = 0;

    // ------------------- Cryptogram Response -------------------
    if (resplen >= 2 && response[0] == 0x85 && response[1] == 0x40) {
        uint8_t decrypted[64];
        memcpy(cryptogram, response + 2, 64);
        memcpy(responseCode, response + 68, 2);

        // Decrypt the response
        decrypt_cryptogram(diversified_enc_key, cryptogram, decrypted, sizeof(cryptogram), encryption_algorithm);

        // Response Format
        // FF0038302F8102578CA5020500A6088101010403030008A7178515D65ED945996AB9107CD6D3E6011F56FFDD9CFFC780A9020500050000000000008000000000

        // FF00 is our inputed tag value
        // 38 is our len

        // PrintAndLogEx(SUCCESS, "Cryptogram....................... " _YELLOW_("%s"), sprint_hex_inrow(cryptogram, sizeof(cryptogram)));
        // PrintAndLogEx(SUCCESS, "Decrypted........................ " _YELLOW_("%s"), sprint_hex_inrow(decrypted, sizeof(decrypted)));

        getDataSize = decrypted[2];
        memcpy(tag, decrypted, ARRAYLEN(tag));
        memmove(decrypted, decrypted + 1, sizeof(decrypted) - 1);
        memmove(sioOutput, decrypted + 2, getDataSize);
        *sio_size = getDataSize;
        memcpy(responseCode, response + 68, 2);

        PrintAndLogEx(SUCCESS, "Response Code.................... " _YELLOW_("%s"), sprint_hex_inrow(responseCode, (ARRAYLEN(responseCode))));
        PrintAndLogEx(SUCCESS, "Output........................... " _YELLOW_("%s"), sprint_hex_inrow(sioOutput, getDataSize));
    } else if (resplen >= 2 && response[0] == 0x99) {
        memcpy(responseCode, response + 2, 2);
        // PrintAndLogEx(SUCCESS, "Raw Response..................... " _YELLOW_("%s"), sprint_hex_inrow(response, (resplen - 2)));
        PrintAndLogEx(SUCCESS, "Response Code.................... " _YELLOW_("%s"), sprint_hex_inrow(responseCode, (ARRAYLEN(responseCode))));
    }

    return PM3_SUCCESS;
};

static void set_counter_big_endian(uint8_t *buffer, uint32_t counter) {
    buffer[0] = (counter >> 24) & 0xFF;
    buffer[1] = (counter >> 16) & 0xFF;
    buffer[2] = (counter >> 8) & 0xFF;
    buffer[3] = counter & 0xFF;
}

static void create_mutual_auth_key(uint8_t *KEYIFD, uint8_t *KEYICC, uint8_t *RNDICC, uint8_t *RNDIFD, uint8_t *EncryptionKey, uint8_t *MACKey, int encryptionAlgorithm, int HashingAlgorithm) {
    // Creating Mutual Authentication Keys
    // Structure
    // Prefix               = 00000000
    // keyIFD.substring(16) = 0000000000000000      IFD = Interface Device
    // keyICC.substring(16) = 0000000000000000      ICC = Integrated Circuit Card
    // hashing algorithm x2 = 09 09
    // randomICC            = 0000000000000000      ICC = Integrated Circuit Card
    // RandomIFD            = 0000000000000000      IFD = Interface Device
    // Will always be 38 bytes
    //
    // 00000000 E0EC1F2D7B000000 F0EC1F2D7B000000 09 09 B0EC1F2D7B000000B8EC1F2D7B000000

    uint8_t prefix[4] = {0x00, 0x00, 0x00, 0x00};
    uint8_t aHashingAlgorithm[2] = {encryptionAlgorithm, encryptionAlgorithm};
    uint8_t hash_in[38];

    memcpy(hash_in, prefix, 4);
    memcpy(hash_in + 4, KEYIFD, 8);
    memcpy(hash_in + 12, KEYICC, 8);
    memcpy(hash_in + 20, aHashingAlgorithm, 2);
    memcpy(hash_in + 22, RNDICC, 8);
    memcpy(hash_in + 30, RNDIFD, 8);

    // PrintAndLogEx(INFO, "--- " _CYAN_("Mutual Auth Keys") " ---------------------------");
    // PrintAndLogEx(SUCCESS, "Prefix........................... " _YELLOW_("%s"), sprint_hex_inrow(prefix, ARRAYLEN(prefix)));
    // PrintAndLogEx(SUCCESS, "KeyIFD........................... " _YELLOW_("%s"), sprint_hex_inrow(KEYIFD, 8));
    // PrintAndLogEx(SUCCESS, "KeyICC........................... " _YELLOW_("%s"), sprint_hex_inrow(KEYICC, 8));
    // PrintAndLogEx(SUCCESS, "HashingAlgo...................... " _YELLOW_("%s"), sprint_hex_inrow(aHashingAlgorithm, ARRAYLEN(aHashingAlgorithm)));
    // PrintAndLogEx(SUCCESS, "RandomICC........................ " _YELLOW_("%s"), sprint_hex_inrow(RNDICC, 8));
    // PrintAndLogEx(SUCCESS, "RandomIFD........................ " _YELLOW_("%s"), sprint_hex_inrow(RNDIFD, 8));
    // PrintAndLogEx(SUCCESS, "hash Input....................... " _YELLOW_("%s"), sprint_hex_inrow(hash_in,ARRAYLEN(hash_in)));

    uint8_t output[128]; // Buffer to store the two 32-byte keys
    uint8_t hashedOutput[128];
    uint32_t counter = 1;

    // Generate the first key
    set_counter_big_endian(hash_in, counter); // Set the counter in big-endian format
    // PrintAndLogEx(SUCCESS, "key_out_temp..................... " _YELLOW_("%s"), sprint_hex_inrow(hash_in,ARRAYLEN(hash_in)));

    if (HashingAlgorithm == 0x06) {
        sha1hash(hash_in, sizeof(hash_in), hashedOutput);
        //PrintAndLogEx(SUCCESS, "key_out_temp..................... " _YELLOW_("%s"), sprint_hex_inrow(hash_in,ARRAYLEN(hash_in)));
        memcpy(output, hashedOutput, 20);
        counter++;
        set_counter_big_endian(hash_in, counter);
        sha1hash(hash_in, sizeof(hash_in), hashedOutput);
        memcpy(output + 20, hashedOutput, 20);
        //PrintAndLogEx(SUCCESS, "key_out_temp..................... " _YELLOW_("%s"), sprint_hex_inrow(hash_in,ARRAYLEN(hash_in)));
    } else if (HashingAlgorithm == 0x07) {
        sha256hash(hash_in, sizeof(hash_in), hashedOutput);
        memcpy(output, hashedOutput, 32);
    } else {
        // Yes they generate their encryption keys and mac keys in a weird way for no fucking reason, the 2nd cycle isn't required.
        PrintAndLogEx(ERR, _RED_("Unknown Hashing Algorithm"));
        return;
    }


    memcpy(EncryptionKey, output, 16);
    memcpy(MACKey, output + 16, 16);


    // PrintAndLogEx(INFO, "--- " _CYAN_("New Key Generation") " ---------------------------");
    // PrintAndLogEx(SUCCESS, "Hash Output...................... " _YELLOW_("%s"), sprint_hex_inrow(output,ARRAYLEN(output)));
    // PrintAndLogEx(SUCCESS, "Encryption Key................... " _YELLOW_("%s"), sprint_hex_inrow(EncryptionKey, 16));
    // PrintAndLogEx(SUCCESS, "MAC Key.......................... " _YELLOW_("%s"), sprint_hex_inrow(MACKey, 16));
}

static int seos_challenge_get(uint8_t *RNDICC, uint8_t RNDICC_len, uint8_t keyslot) {
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;

    bool activate_field = false;
    bool keep_field_on = true;

    // The Get Challenge seems to be static across all tested cards
    // 00870001047c02810000

    char getChallengePre[21];
    strcpy(getChallengePre, "008700");

    // const char keyslot_str[3] = "01";
    //strcat(getChallengePre, keyslot_str);
    snprintf(getChallengePre + strlen(getChallengePre), 3, "%02u", keyslot);
    strcat(getChallengePre, "047c02810000");

    uint8_t aGET_CHALLENGE[12];
    int aGET_CHALLENGE_n = 0;
    param_gethex_to_eol(getChallengePre, 0, aGET_CHALLENGE, sizeof(aGET_CHALLENGE), &aGET_CHALLENGE_n);
    int res = ExchangeAPDU14a(aGET_CHALLENGE, aGET_CHALLENGE_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    uint16_t sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Get Challenge Failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }
    memcpy(RNDICC, &response[4], 8);

    // Response looks like
    // 7C0A810897460AC7535731F8
    // |----------|------------------|
    // | 7C0A8108 | 97460AC7535731F8 |
    // |  Static  |      RND.ICC     |
    // |----------|------------------|
    // 7C 0A 81 08 18 1E 43 80 10 10 20 11
    // 81 is the ASN.1 tag

    uint8_t staticResponse[8] = {0x01, 0x81, 0xE4, 0x38, 0x01, 0x01, 0x02, 0x01};

    PrintAndLogEx(INFO, "--- " _CYAN_("Get Challenge") " ---------------------------");
    //PrintAndLogEx(SUCCESS, "Challenge Input: " _YELLOW_("%s"), getChallengePre);
    if (memcmp(RNDICC, staticResponse, 8) == 0) {
        PrintAndLogEx(SUCCESS, "Static Response Detected......... " _GREEN_("%s"), sprint_hex_inrow(RNDICC, sizeof(RNDICC)));
    } else {
        PrintAndLogEx(SUCCESS, "RND.ICC.......................... " _YELLOW_("%s"), sprint_hex_inrow(RNDICC, sizeof(RNDICC)));
    }

    return PM3_SUCCESS;
};

int seos_kdf(bool encryption, uint8_t *masterKey, uint8_t keyslot,
             uint8_t *adfOid, size_t adfoid_len, uint8_t *diversifier, uint8_t diversifier_len, uint8_t *out, int encryption_algorithm, int hash_algorithm) {

    // Encryption key      = 04
    // KEK Encryption key  = 05
    // MAC key             = 06
    // KEK MAC key         = 07

    uint8_t typeOfKey = 0x06;
    if (encryption == true) {
        typeOfKey = 0x04;
    }

    uint8_t inputPre[] = {
        // Padding
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, typeOfKey, 0x00, 0x00, 0x80, 0x01,
        encryption_algorithm, hash_algorithm, keyslot
    };

    // 00000000000000000000000600008001 09 07 00 06112B0601040181E438010102011801010202 EFB08A28B0529F
    // 00000000000000000000000400008001 09 07 00 06112B0601040181E438010102011801010202 EFB08A28B0529F
    // 06112B0601040181E438010102011801010202 CF 07 EFB08A28B0529F DBA240413B0969B7111F4B6133A3DEFAD934B6DC


    uint8_t input[sizeof(inputPre) + adfoid_len + diversifier_len];

    memset(input, 0, sizeof(input));

    memcpy(input, inputPre, sizeof(inputPre));
    memcpy(input + sizeof(inputPre), adfOid, adfoid_len);
    memcpy(input + sizeof(inputPre) + adfoid_len, diversifier, diversifier_len);

    // PrintAndLogEx(SUCCESS, "adfOid: " _YELLOW_("%s"), sprint_hex_inrow(adfOid, 16));
    // PrintAndLogEx(SUCCESS, "diversifier: " _YELLOW_("%s"), sprint_hex_inrow(diversifier, 7));
    // PrintAndLogEx(SUCCESS, "Input: " _YELLOW_("%s"), sprint_hex_inrow(input, (sizeof(input))));

    // ----------------- AES Key Generation -----------------
    uint8_t AES_iv[16] = {};

    aes_cmac(AES_iv, masterKey, input, out, sizeof(input));
    return PM3_SUCCESS;
};

static int select_DF_verify(uint8_t *response, uint8_t response_length, uint8_t *MAC_value, size_t MAC_value_len, int encryption_algorithm, int key_index) {
    uint8_t input[response_length - 10];
    // Response is an ASN.1 encoded structure
    // Extract everything before the 8E tag

    int res = PM3_EWRONGANSWER;
    for (int i = 0; i < response_length; i++) {
        // extract MAC
        if (response[i] == 0x8E) {
            memcpy(input, response, i);
            memcpy(MAC_value, response + (i + 2), MAC_value_len);
            res = PM3_SUCCESS;
            break;
        }
    }
    if (res != PM3_SUCCESS) {
        goto out;
    }

    // ----------------- MAC Key Generation -----------------
    uint8_t cmac[8];
    uint8_t MAC_key[24] = {0x00};
    memcpy(MAC_key, keys[key_index].privMacKey, 16);
    create_cmac(MAC_key, input, cmac, sizeof(input), encryption_algorithm);

    // PrintAndLogEx(INFO, "--- " _CYAN_("MAC") " ---------------------------");
    // PrintAndLogEx(SUCCESS, "MAC Key: "_YELLOW_("%s"), sprint_hex_inrow(MAC_key,sizeof(MAC_key)));
    // PrintAndLogEx(SUCCESS, "Message: " _YELLOW_("%s"), sprint_hex_inrow(input,sizeof(input)));

    if (memcmp(cmac, MAC_value, MAC_value_len) == 0) {
        // PrintAndLogEx(SUCCESS, _GREEN_("MAC Verification successful"));
        return PM3_SUCCESS;
    }
    // PrintAndLogEx(INFO, "MAC Type......................... " _YELLOW_("%s"), algorithm_name1);
    // PrintAndLogEx(INFO, "Supp MAC......................... " _YELLOW_("%s"), sprint_hex_inrow(MAC_value, MAC_value_len));
    // PrintAndLogEx(INFO, "Calc MAC......................... " _YELLOW_("%s"), sprint_hex_inrow(cmac, sizeof(cmac)));

out:
    PrintAndLogEx(INFO, "--- " _CYAN_("MAC") " ---------------------------");
    PrintAndLogEx(ERR, _RED_("MAC Verification Failed"));
    return PM3_ESOFT;
}

static int select_df_decode(uint8_t *response, uint8_t response_length, int *ALGORITHM_INFO_value1, int *ALGORITHM_INFO_value2, uint8_t *CRYPTOGRAM_encrypted_data, uint8_t *MAC_value) {
    // Response is an ASN.1 encoded structure
    // ASN.1 Information
    // CF = Diversifier
    //
    // CD = ALGORITHM_INFO
    //      02 = 3DES 2K    (TWO_KEY_3DES_CBC_MODE)
    //      04 = 3K3DES     (THREE_KEY_3DES_CBC_MODE)
    //      06 = SHA-1      (hash assigned to RSA-1024)
    //      07 = SHA-256
    //      09 = AES-128    (AES_128_CBC)
    // 85 = CRYPTOGRAM
    //      First 16 bytes what I guess is a nonce
    //      Followed with the ADF selected, then the diversifier
    // 8E = MAC

    /*
    [+] Raw ADF Response: CD0209078540EAA1E1966D666D1FBA14098700071D1DEE24B74CAC87D182EF1700B9946D697E60F87B0FB703C12AE0F83F579A9BF4888DF6B7691BBA6A404C797356F8457E488E088149C86A535EF86A
    [=]  -- CD [02] 'elem'
    [=]     00: 09 07                                           | ..
    [=]  -- 85 [40] 'elem'
    [=]     00: EA A1 E1 96 6D 66 6D 1F BA 14 09 87 00 07 1D 1D | ....mfm.........
    [=]     10: EE 24 B7 4C AC 87 D1 82 EF 17 00 B9 94 6D 69 7E | .$.L.........mi~
    [=]     20: 60 F8 7B 0F B7 03 C1 2A E0 F8 3F 57 9A 9B F4 88 | `.{....*..?W....
    [=]     30: 8D F6 B7 69 1B BA 6A 40 4C 79 73 56 F8 45 7E 48 | ...i..j@LysV.E~H
    [=]  -- 8E [08] 'elem'
    [=]     00: 81 49 C8 6A 53 5E F8 6A                         | .I.jS^.j
    */
    int ALGORITHM_INFO_value1_n = 0;
    int ALGORITHM_INFO_value2_n = 0;
    int bufferPoint = 0;

    for (int i = 0; i < response_length; i++) {
        // ALGORITHM_INFO
        if (response[i] == 0xCD) {
            *ALGORITHM_INFO_value1 = (int)response[i + 2];
            ALGORITHM_INFO_value1_n = response[i + 2];
            *ALGORITHM_INFO_value2 = (int)response[i + 3];
            ALGORITHM_INFO_value2_n = response[i + 3];
            bufferPoint = i + (i + 1);
            break;
        }
    }

    for (int i = bufferPoint ; i < response_length; i++) {
        // CRYPTOGRAM
        if (response[i] == 0x85) {
            memcpy(CRYPTOGRAM_encrypted_data, &response[i + 2], 64);
            bufferPoint = i + (i + 1);
            break;
        }
    }

    for (int i = bufferPoint; i < response_length; i++) {
        // MAC
        if (response[i] == 0x8E) {
            memcpy(MAC_value, &response[i + 2], 8);
        }
    }

    const char *algorithm_name1 = NULL;
    for (int i = 0; i < ARRAYLEN(known_algorithm_map); i++) {
        if ((known_algorithm_map[i].value) == ALGORITHM_INFO_value1_n) {
            algorithm_name1 = known_algorithm_map[i].name;
            break;
        }
    }

    const char *algorithm_name2 = NULL;
    for (int i = 0; i < ARRAYLEN(known_algorithm_map); i++) {
        if (known_algorithm_map[i].value == ALGORITHM_INFO_value2_n) {
            algorithm_name2 = known_algorithm_map[i].name;
            break;
        }
    }

    PrintAndLogEx(INFO, "--- " _CYAN_("Raw ADF Information") " ---------------------------");
    if (algorithm_name1 != NULL) {
        PrintAndLogEx(SUCCESS, "algoIdCipher (Encryption)........ "_YELLOW_("%i (%s)"), ALGORITHM_INFO_value1_n, algorithm_name1);
    } else {
        PrintAndLogEx(ERR, "algoIdCipher (Encryption)........ %d (Unknown)", ALGORITHM_INFO_value1_n);
    }

    if (algorithm_name2 != NULL) {
        PrintAndLogEx(SUCCESS, "algoIdHash (MAC)................. "_YELLOW_("%i (%s)"), ALGORITHM_INFO_value2_n, algorithm_name2);
    } else {
        PrintAndLogEx(ERR, "algoIdHash (MAC)............... %d (Unknown)", ALGORITHM_INFO_value2_n);
    }

    // PrintAndLogEx(SUCCESS, "Raw Data......................... " _YELLOW_("%s"), sprint_hex_inrow(response, 80));
    PrintAndLogEx(SUCCESS, "CRYPTOGRAM Encrypted Data........ " _YELLOW_("%s"), sprint_hex_inrow(CRYPTOGRAM_encrypted_data, 64));
    // PrintAndLogEx(SUCCESS, "MAC.............................. " _YELLOW_("%s"), sprint_hex_inrow(MAC_value, 8));

    return PM3_SUCCESS;
}

static int select_ADF_decrypt(const char *selectADFOID, uint8_t *CRYPTOGRAM_encrypted_data_raw, uint8_t *CRYPTOGRAM_Diversifier, int encryption_algorithm, int key_index) {
    // --------------- Decrypt ----------------

    // 1. MAC Verify - AES/CBC-decrypt (IV || cryptogram || 16 bytes after 8e 08) with the MAC key & keep the last block
    // 2. Decrypt the CRYPTOGRAM_encrypted_data - AES/CBC-decrypt with the encryption key & IV (the previous 16 bytes)
    // 3. Verify the Decryption
    // 3.1 - CF tag for diversifier at 44 chars in
    // 4. Extract the data
    // 4.1 Selected ADF
    // 4.2 Diversifier
    // 4.3 Nonce
    uint8_t privEncKey[16] = {};
    memcpy(privEncKey, keys[key_index].privEncKey, 16);
    uint8_t CRYPTOGRAM_decrypted_data[64];

    decrypt_cryptogram(privEncKey, CRYPTOGRAM_encrypted_data_raw, CRYPTOGRAM_decrypted_data, ARRAYLEN(CRYPTOGRAM_decrypted_data), encryption_algorithm);

    // PrintAndLogEx(SUCCESS, "CRYPTOGRAM_encrypted_data_raw: " _YELLOW_("%s"), sprint_hex_inrow(CRYPTOGRAM_encrypted_data_raw, 64));
    // PrintAndLogEx(SUCCESS, "Raw Decrypted Data............... "_YELLOW_("%s"), sprint_hex_inrow(CRYPTOGRAM_decrypted_data,sizeof(CRYPTOGRAM_decrypted_data)));

    // Rough Output
    // 06112B0601040181E438010102011801010202 CF 07 EFB08A28B0529F 5282752803B485BABF8CD88F3DA5515DF7712CF3


    // Extract the data
    int diversifier_length = 0;
    int adf_length = 0;

    int CRYPTOGRAM_decrypted_data_length = sizeof(CRYPTOGRAM_decrypted_data);

    for (int i = 0; i < CRYPTOGRAM_decrypted_data_length; i++) {
        // ADF OID tag
        if (CRYPTOGRAM_decrypted_data[i] == 0x06 && CRYPTOGRAM_decrypted_data[i + 1] < 20) {
            adf_length = ((CRYPTOGRAM_decrypted_data[i + 1]));
            diversifier_length = CRYPTOGRAM_decrypted_data[i + adf_length + 3];

            uint8_t CRYPTOGRAM_ADF[strlen(selectADFOID) / 2];

            memcpy(CRYPTOGRAM_ADF, &CRYPTOGRAM_decrypted_data[i], strlen(selectADFOID) / 2);
            memcpy(CRYPTOGRAM_Diversifier, &CRYPTOGRAM_decrypted_data[i + adf_length + 4], diversifier_length);

            const char *CRYPTOGRAM_ADF_CMP = (sprint_hex_inrow(CRYPTOGRAM_ADF, ARRAYLEN(CRYPTOGRAM_ADF)));

            char *CRYPTOGRAM_ADF_UPPER = strdup(CRYPTOGRAM_ADF_CMP);
            char *selectADFOID_UPPER = strdup(selectADFOID);

            // Convert both strings to uppercase
            for (int x = 0; CRYPTOGRAM_ADF_UPPER[x]; x++) {
                CRYPTOGRAM_ADF_UPPER[x] = toupper(CRYPTOGRAM_ADF_UPPER[x]);
            }
            for (int x = 0; selectADFOID_UPPER[x]; x++) {
                selectADFOID_UPPER[x] = toupper(selectADFOID_UPPER[x]);
            }


            // Compare the 2 ADF responses, if they don't match then the decryption is wrong
            // We do the + 4 to remove the first 4 bytes of the ADF OID ASN.1 Tag (0611)
            if (strcmp(CRYPTOGRAM_ADF_UPPER + 4, selectADFOID_UPPER + 4) != 0) {
                PrintAndLogEx(ERR, "ADF does not match decrypted ADF");
                PrintAndLogEx(ERR, "Likely wrong Key or IV");
                // PrintAndLogEx(SUCCESS, "Decoded ADF....................... "_YELLOW_("%s"), CRYPTOGRAM_ADF_UPPER);                              // ADF Selected
                // PrintAndLogEx(SUCCESS, "Supplied ADF...................... "_YELLOW_("%s"), selectADFOID_UPPER);                                // ADF Selected
                return PM3_ESOFT;
            }

            // PrintAndLogEx(INFO, "--- " _CYAN_("Decrypted Response") " ---------------------------");
            // PrintAndLogEx(SUCCESS, "Decoded ADF...................... "_YELLOW_("%s"), sprint_hex_inrow(&CRYPTOGRAM_ADF[2],adf_length));                 // ADF Selected
            // PrintAndLogEx(SUCCESS, "Diversifier...................... "_YELLOW_("%s"), sprint_hex_inrow(CRYPTOGRAM_Diversifier,diversifier_length));     // ADF Diversifier
            return PM3_SUCCESS;

        }
    }
    return PM3_ESOFT;
};

static int seos_mutual_auth(uint8_t *randomICC, uint8_t *CRYPTOGRAM_Diversifier, uint8_t diversifier_len, uint8_t *mutual_auth_randomIFD, uint8_t *mutual_auth_keyICC, uint8_t *randomIFD, uint8_t randomIFD_len, uint8_t *keyIFD, uint8_t keyIFD_len, int encryption_algorithm, int hash_algorithm, int key_index) {
    uint8_t response[PM3_CMD_DATA_SIZE];

    // ---------------- Diversify Keys ----------------
    uint8_t mk[16] = { 0x00 };
    memcpy(mk, keys[key_index].readKey, 16);
    uint8_t keyslot = 0x01; // up to 0x0F
    uint8_t AES_key[24] = {0x00};
    uint8_t MAC_key[24] = {0x00};
    uint8_t adfOID[17] = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xe4, 0x38, 0x01, 0x01, 0x02, 0x01, 0x18, 0x01, 0x01, 0x02, 0x02};

    // Null AES IV
    uint8_t nullDiversifier[7] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    if (memcmp(CRYPTOGRAM_Diversifier, nullDiversifier, sizeof(nullDiversifier)) == 0) {
        PrintAndLogEx(ERR, "No Diversifier found");
        return PM3_ESOFT;
    }

    seos_kdf(true, mk, keyslot, adfOID, sizeof(adfOID), CRYPTOGRAM_Diversifier, diversifier_len, AES_key, encryption_algorithm, hash_algorithm);
    seos_kdf(false, mk, keyslot, adfOID, sizeof(adfOID), CRYPTOGRAM_Diversifier, diversifier_len, MAC_key, encryption_algorithm, hash_algorithm);

    memcpy(&MAC_key[16], &MAC_key[0], 8);
    memcpy(&AES_key[16], &AES_key[0], 8);

    // PrintAndLogEx(INFO, "--- " _CYAN_("Diversified Keys") " ---------------------------");
    // PrintAndLogEx(SUCCESS, "Diversified Enc Key.............. " _YELLOW_("%s"), sprint_hex_inrow(AES_key, (sizeof(AES_key))));
    // PrintAndLogEx(SUCCESS, "Diversified Mac Key.............. " _YELLOW_("%s"), sprint_hex_inrow(MAC_key, (sizeof(MAC_key))));
    // PrintAndLogEx(INFO, "--- " _CYAN_("Mutual Auth") " ---------------------------");

    // ----------------- Command Generation -----------------
    uint8_t mutual_auth_plain[32];
    memcpy(mutual_auth_plain, randomIFD, 8);
    memcpy(mutual_auth_plain + 8, randomICC, 8);
    memcpy(mutual_auth_plain + 8 + 8, keyIFD, 16);

    // ----------------- Encryption and MAC Generation -----------------
    uint8_t mac[8];
    uint8_t mutual_auth_enc[32];
    create_cryptogram(AES_key, mutual_auth_plain, mutual_auth_enc, sizeof(mutual_auth_plain), encryption_algorithm);
    create_cmac(MAC_key, mutual_auth_enc, mac, sizeof(mutual_auth_enc), encryption_algorithm);

    uint8_t message_authenticated[40];
    memcpy(message_authenticated, mutual_auth_enc, sizeof(mutual_auth_enc));
    memcpy(message_authenticated + sizeof(mutual_auth_enc), mac, sizeof(mac));

    // ----------------- Debugging -----------------
    // PrintAndLogEx(SUCCESS, "AES IV : "_YELLOW_("%s"), sprint_hex_inrow(AES_iv,sizeof(AES_iv)));
    // PrintAndLogEx(SUCCESS, "AES Key: "_YELLOW_("%s"), sprint_hex_inrow(AES_key,sizeof(AES_key)));
    // PrintAndLogEx(SUCCESS, "mutual_auth_plain... " _YELLOW_("%s"), sprint_hex_inrow(mutual_auth_plain, sizeof(mutual_auth_plain)));
    // PrintAndLogEx(SUCCESS, "mutual_auth_enc..... " _YELLOW_("%s"), sprint_hex_inrow(mutual_auth_enc, sizeof(mutual_auth_enc)));

    // PrintAndLogEx(INFO, "--- " _CYAN_("MAC") " ---------------------------");
    // PrintAndLogEx(SUCCESS, "AES IV: "_YELLOW_("%s"), sprint_hex_inrow(AES_iv,sizeof(AES_iv)));
    // PrintAndLogEx(SUCCESS, "MAC Key: "_YELLOW_("%s"), sprint_hex_inrow(MAC_key,sizeof(MAC_key)));
    // PrintAndLogEx(SUCCESS, "Message.......................... " _YELLOW_("%s"), sprint_hex_inrow(mutual_auth_enc,sizeof(mutual_auth_enc)));
    // PrintAndLogEx(SUCCESS, "MAC.............................. " _YELLOW_("%s"), sprint_hex_inrow(mac,sizeof(mac)));

    // ----------------- Command Generation -----------------

    const char *prefixLenHex = "2c";
    const char *ASN1_tagAboveLenHex = "2a";
    const char *ASN1_auth_encryptedLenHex = "28";

    const char *mutual_auth_message = sprint_hex_inrow(message_authenticated, sizeof(message_authenticated));

    char keyslot_str[3];
    snprintf(keyslot_str, sizeof(keyslot_str), "%02X", keyslot);

    const char *prefix = "008700";
    const char *ASN1_tagAbove = "7c";
    const char *ASN1_auth_encrypted = "82";
    const char *suffix = "00";

    char mutual_auth[102];
    snprintf(mutual_auth, sizeof(mutual_auth), "%s%s%s%s%s%s%s%s%s", prefix, keyslot_str, prefixLenHex, ASN1_tagAbove, ASN1_tagAboveLenHex, ASN1_auth_encrypted, ASN1_auth_encryptedLenHex, mutual_auth_message, suffix);
    // PrintAndLogEx(SUCCESS, "Mutual Auth Encrypted Request.... " _YELLOW_("%s"), mutual_auth);

    // BLOCKS MUTUAL AUTH BEFORE REQUIRED
    // return PM3_SUCCESS;
    //

    int resplen = 0;
    bool activate_field = false;
    bool keep_field_on = true;

    uint8_t aMUTUAL_AUTH[102] = {0};
    int aMUTUAL_AUTH_n = 0;
    param_gethex_to_eol(mutual_auth, 0, aMUTUAL_AUTH, sizeof(aMUTUAL_AUTH), &aMUTUAL_AUTH_n);
    int res = ExchangeAPDU14a(aMUTUAL_AUTH, aMUTUAL_AUTH_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Mutual Auth Request Failed");
        DropField();
        return PM3_ESOFT;
    }

    uint16_t sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Mutual Auth Request Failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    // PrintAndLogEx(INFO, "--- " _CYAN_("Get Challenge") " ---------------------------");
    // PrintAndLogEx(SUCCESS, "Raw Mutual Auth Response: " _YELLOW_("%s"), sprint_hex_inrow(response, (resplen - 2)));
    // PrintAndLogEx(SUCCESS, "Mutual Auth Encrypted Response... " _YELLOW_("%s"), sprint_hex_inrow(mutual_auth_response, sizeof(mutual_auth_response)));
    // PrintAndLogEx(SUCCESS, "Mutual Auth MAC Response: " _YELLOW_("%s"), sprint_hex_inrow(mutual_auth_mac_response, sizeof(mutual_auth_mac_response)));
    // PrintAndLogEx(SUCCESS, "Mutual Auth MAC Input: " _YELLOW_("%s"), sprint_hex_inrow(mutual_auth_validate, sizeof(mutual_auth_validate)));
    // PrintAndLogEx(SUCCESS, "Mutual Auth MAC Calculated: " _YELLOW_("%s"), sprint_hex_inrow(mac_calculated, sizeof(mac_calculated)));

    // Process Response
    uint8_t iv[16] = {};
    uint8_t mutual_auth_response[32];
    uint8_t mutual_auth_mac_response[8];
    memcpy(mutual_auth_response, &response[4], 32);
    memcpy(mutual_auth_mac_response, &response[4 + 32], 8);

    // PrintAndLogEx(SUCCESS, "Mutual Auth Encrypted Response... " _YELLOW_("%s"), sprint_hex_inrow(mutual_auth_response, sizeof(mutual_auth_response)));
    // PrintAndLogEx(SUCCESS, "Mutual Auth MAC Response: " _YELLOW_("%s"), sprint_hex_inrow(mutual_auth_mac_response, sizeof(mutual_auth_mac_response)));

    uint8_t mutual_auth_response_decrypted[32];
    if (encryption_algorithm == 0x09) {
        aes_decode(iv, AES_key, mutual_auth_response, mutual_auth_response_decrypted, sizeof(mutual_auth_response));
    } else if (encryption_algorithm == 0x02) {
        mbedtls_des3_context ctx3;
        mbedtls_des3_set2key_dec(&ctx3, AES_key);
        mbedtls_des3_crypt_cbc(&ctx3, MBEDTLS_DES_DECRYPT, sizeof(mutual_auth_response), iv, mutual_auth_response, mutual_auth_response_decrypted);
        mbedtls_des3_free(&ctx3);
    }

    // Validate response with comparison between nonce and randomICC
    uint8_t mutual_auth_RandomICC[8];
    memcpy(mutual_auth_RandomICC, &mutual_auth_response_decrypted, 8);

    // PrintAndLogEx(SUCCESS, "Mutual Auth Decrypted Response... " _YELLOW_("%s"), sprint_hex_inrow(mutual_auth_response_decrypted, sizeof(mutual_auth_response_decrypted)));

    if (memcmp(randomICC, mutual_auth_RandomICC, 8) != 0) {
        PrintAndLogEx(ERR, "RandomICC does not match decrypted RandomICC");
        PrintAndLogEx(ERR, "Likely wrong Key or IV");
        return PM3_ESOFT;
    }

    memcpy(mutual_auth_randomIFD, &mutual_auth_response_decrypted[8], 8);
    memcpy(mutual_auth_keyICC, &mutual_auth_response_decrypted[16], 16);

    // PrintAndLogEx(SUCCESS, _GREEN_("Mutual Auth Completed"));
    // PrintAndLogEx(INFO, "--- " _CYAN_("Decrypted Response") " ---------------------------");
    // PrintAndLogEx(SUCCESS, "Mutual Auth Decrypted Response... " _YELLOW_("%s"), sprint_hex_inrow(mutual_auth_response_decrypted, sizeof(mutual_auth_response_decrypted)));
    // PrintAndLogEx(SUCCESS, "Mutual Auth RandomICC............ " _YELLOW_("%s"), sprint_hex_inrow(mutual_auth_RandomICC, sizeof(mutual_auth_RandomICC)));
    // PrintAndLogEx(SUCCESS, "Mutual Auth RandomIFD............ " _YELLOW_("%s"), sprint_hex_inrow(mutual_auth_randomIFD, sizeof(mutual_auth_randomIFD)));
    // PrintAndLogEx(SUCCESS, "Mutual Auth KeyICC............... " _YELLOW_("%s"), sprint_hex_inrow(mutual_auth_keyICC, sizeof(mutual_auth_keyICC)));

    return PM3_SUCCESS;
};

static int seos_aid_select(void) {
    // Working 100%, pulls from live card
    bool activate_field = true;
    bool keep_field_on = true;
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;

    // ---------------  Select AID for SEOS Card ----------------
    typedef struct {
        const char *name;
        const char *value;
    } seos_aid_t;

    static const seos_aid_t known_AID_map[] = {
        {"STANDARD_SEOS", "A00000044000010100010"},
        {"MOBILE_SEOS_ADMIN_CARD", "A000000382002D0001010"},
    };

    int i;
    int res = PM3_ESOFT;
    //PrintAndLogEx(INFO, "--- " _CYAN_("AID Selection") " ---------------------------");
    for (i = 0; i < ARRAYLEN(known_AID_map); i++) {

        const char *selectedAID = known_AID_map[i].value;

        // Select command prefixed with a 00
        const char *prefix = "00A404";
        uint16_t aidlen = strlen(selectedAID) >> 1;

        char aidlenHex[5];
        snprintf(aidlenHex, sizeof(aidlenHex), "%04X", aidlen);

        const char *suffix = "0";
        char combinedString[100];

        snprintf(combinedString, sizeof(combinedString), "%s%s%s%s", prefix, aidlenHex, selectedAID, suffix);
        //PrintAndLogEx(SUCCESS, "AID Selected: " _YELLOW_("%s"), known_AID_map[i].name);
        //PrintAndLogEx(SUCCESS, "AID Select Command: " _YELLOW_("%s"), combinedString);

        // ---------------  Select AID for SEOS Card ----------------
        uint8_t aSELECT_AID[80];
        int aSELECT_AID_n = 0;
        param_gethex_to_eol(combinedString, 0, aSELECT_AID, sizeof(aSELECT_AID), &aSELECT_AID_n);
        res = ExchangeAPDU14a(aSELECT_AID, aSELECT_AID_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
        if (res != PM3_SUCCESS) {
            DropField();
            continue;
        }

        if (resplen < 2) {
            DropField();
            continue;
        }

        uint16_t sw = get_sw(response, resplen);
        if (sw != ISO7816_OK) {
            PrintAndLogEx(ERR, "Selecting SEOS applet aid failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
            DropField();
            continue;
        }

        // if we made it here,  its a success and we break :)
        break;
    }
    if (i == ARRAYLEN(known_AID_map)) {
        return PM3_ESOFT;
    }
    return res;
};

static int seos_pacs_adf_select(char *oid, int oid_len, uint8_t *get_data, int get_data_len, int key_index) {
    int resplen = 0;
    uint8_t response[PM3_CMD_DATA_SIZE];
    bool activate_field = false;
    bool keep_field_on = true;

    // --------------- ADF file Selection ----------------

    // breaks down to
    // 06 = ASN.1 Tag
    // 11 = Len
    // 2b0601040181e438010102011801010202 = ADF-OID

    // --------------- OID Selection ----------------
    const char *ADFprefix = "06";
    char selectedOID[100];
    snprintf(selectedOID, sizeof(selectedOID), "%s", oid);

    uint16_t selectedOIDLen = strlen(selectedOID);
    char selectedOIDLenHex[3];
    snprintf(selectedOIDLenHex, sizeof(selectedOIDLenHex), "%02X", (selectedOIDLen >> 1) & 0xFF);

    char selectedADF[strlen(ADFprefix) + strlen(selectedOIDLenHex) + selectedOIDLen + 1];
    snprintf(selectedADF, sizeof(selectedADF), "%s%s%s", ADFprefix, selectedOIDLenHex, selectedOID);

    // --------------- Command Builder Selection ----------------
    // prefix is the APDU command we are sending
    const char *prefix = "80A504";
    const char *suffix = "00";
    const char *keyReference = "00";

    uint16_t selectedADFLen = strlen(selectedADF);

    char adflenHex[3];
    snprintf(adflenHex, sizeof(adflenHex), "%02X", (selectedADFLen >> 1) & 0xFF);

    char selectADF[strlen(prefix) + strlen(adflenHex) + selectedADFLen + strlen(suffix) + 1];

    // 80 A5 04 00 13 06 11 2B 06 01 04 01 81 E4 38 01 01 02 01 18 01 01 02 02 00
    snprintf(selectADF, sizeof(selectADF), "%s%s%s%s%s", prefix, keyReference, adflenHex, selectedADF, suffix);


    PrintAndLogEx(INFO, "--- " _CYAN_("Select ADF") " ---------------------------");
    PrintAndLogEx(SUCCESS, "Selected ADF..................... "_YELLOW_("%s"), selectedOID);

    // ---------------  Send APDU Command ----------------

    uint8_t aSELECT_FILE_ADF[124];
    int aSELECT_FILE_ADF_n = 0;
    // Input into getHextoEOL is a Char string
    param_gethex_to_eol(selectADF, 0, aSELECT_FILE_ADF, sizeof(aSELECT_FILE_ADF), &aSELECT_FILE_ADF_n);
    int res = ExchangeAPDU14a(aSELECT_FILE_ADF, aSELECT_FILE_ADF_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    uint16_t sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Selecting ADF file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    // --------------- Decrypt ADF Response ----------------
    // Information returned from the GetChallenge command
    int ALGORITHM_INFO_value1 = 0;              // Encryption Algorithm
    int ALGORITHM_INFO_value2 = 0;              // Hash Algorithm
    uint8_t CRYPTOGRAM_encrypted_data[64];      // Encrypted Data
    uint8_t MAC_value[8] = {0};                 // MAC Value

    uint8_t diversifier[7] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t RNDICC[8] = {0};
    uint8_t KeyICC[16] = {0};
    uint8_t RNDIFD[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t KeyIFD[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    uint8_t Diversified_New_EncryptionKey[24] = {0};
    uint8_t Diversified_New_MACKey[24] = {0};

    resplen -= 2;

    seos_challenge_get(RNDICC, sizeof(RNDICC), 0x01);
    select_df_decode(response, resplen, &ALGORITHM_INFO_value1, &ALGORITHM_INFO_value2, CRYPTOGRAM_encrypted_data, MAC_value);
    res = select_DF_verify(response, resplen, MAC_value, sizeof(MAC_value), ALGORITHM_INFO_value1, key_index);

    if (res != PM3_SUCCESS) {
        return res;
    }

    if (ALGORITHM_INFO_value1 == 0x09 || ALGORITHM_INFO_value1 == 0x02) {

        select_ADF_decrypt(selectedADF, CRYPTOGRAM_encrypted_data, diversifier, ALGORITHM_INFO_value1, key_index);
        seos_mutual_auth(RNDICC, diversifier, sizeof(diversifier), RNDIFD, KeyICC, RNDIFD, sizeof(RNDIFD), KeyIFD, sizeof(KeyIFD), ALGORITHM_INFO_value1, ALGORITHM_INFO_value2, key_index);
        create_mutual_auth_key(KeyIFD, KeyICC, RNDICC, RNDIFD, Diversified_New_EncryptionKey, Diversified_New_MACKey, ALGORITHM_INFO_value1, ALGORITHM_INFO_value2);

        uint8_t sio_buffer_out[PM3_CMD_DATA_SIZE];
        int sio_size = 0;
        seos_get_data(RNDICC, RNDIFD, Diversified_New_EncryptionKey, Diversified_New_MACKey, sio_buffer_out, &sio_size, ALGORITHM_INFO_value1, get_data, get_data_len);

        if (sio_size == 0) {
            return PM3_ESOFT;
        }

        if (sio_buffer_out[0] == 0x30) {
            uint8_t sioOutput[sio_size];
            memcpy(sioOutput, sio_buffer_out, sio_size);

            PrintAndLogEx(INFO, "--- " _CYAN_("Key Data") " ---------------------------");
            PrintAndLogEx(SUCCESS, "SIO.............................. "_YELLOW_("%s"), sprint_hex_inrow(sioOutput, sizeof(sioOutput)));             // SIO
            PrintAndLogEx(SUCCESS, "SIO Size......................... "_YELLOW_("%i"), sio_size);                                                   // SIO Size
            PrintAndLogEx(SUCCESS, "Diversifier...................... "_YELLOW_("%s"), sprint_hex_inrow(diversifier, ARRAYLEN(diversifier)));       // Diversifier
        };

    } else {
        PrintAndLogEx(ERR, "Unknown encryption algorithm");
        return PM3_ESOFT;
    };

    return PM3_SUCCESS;
};

static int seos_adf_select(char *oid, int oid_len, int key_index) {
    int resplen = 0;
    uint8_t response[PM3_CMD_DATA_SIZE];
    bool activate_field = false;
    bool keep_field_on = true;

    // --------------- OID Selection ----------------
    const char *ADFprefix = "06";
    char selectedOID[100];
    snprintf(selectedOID, sizeof(selectedOID), "%s", oid);
    uint16_t selectedOIDLen = strlen(selectedOID);
    char selectedOIDLenHex[3];
    snprintf(selectedOIDLenHex, sizeof(selectedOIDLenHex), "%02X", (selectedOIDLen >> 1) & 0xFF);

    char selectedADF[strlen(ADFprefix) + strlen(selectedOIDLenHex) + selectedOIDLen + 1];
    snprintf(selectedADF, sizeof(selectedADF), "%s%s%s", ADFprefix, selectedOIDLenHex, selectedOID);

    // --------------- Command Builder Selection ----------------
    // prefix is the APDU command we are sending
    const char *prefix = "80A504";
    const char *suffix = "00";
    const char *keyReference = "00";

    uint16_t selectedADFLen = strlen(selectedADF);
    char adflenHex[3];
    snprintf(adflenHex, sizeof(adflenHex), "%02X", (selectedADFLen >> 1) & 0xFF);
    char selectADF[strlen(prefix) + strlen(adflenHex) + selectedADFLen + strlen(suffix) + 1];

    // 80 A5 04 00 13 06 11 2B 06 01 04 01 81 E4 38 01 01 02 01 18 01 01 02 02 00
    snprintf(selectADF, sizeof(selectADF), "%s%s%s%s%s", prefix, keyReference, adflenHex, selectedADF, suffix);
    PrintAndLogEx(INFO, "--- " _CYAN_("Select ADF") " ---------------------------");
    PrintAndLogEx(SUCCESS, "Selected ADF..................... "_YELLOW_("%s"), selectedADF);

    // ---------------  Send APDU Command ----------------
    uint8_t aSELECT_FILE_ADF[124];
    int aSELECT_FILE_ADF_n = 0;

    // Input into getHextoEOL is a Char string
    param_gethex_to_eol(selectADF, 0, aSELECT_FILE_ADF, sizeof(aSELECT_FILE_ADF), &aSELECT_FILE_ADF_n);

    int res = ExchangeAPDU14a(aSELECT_FILE_ADF, aSELECT_FILE_ADF_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    uint16_t sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Selecting ADF file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    // --------------- Decrypt ADF Response ----------------
    // Information returned from the GetChallenge command
    int ALGORITHM_INFO_value1 = 0;               // Encryption Algorithm
    int ALGORITHM_INFO_value2 = 0;               // Hash Algorithm
    uint8_t CRYPTOGRAM_encrypted_data[64] = {0}; // Encrypted Data
    uint8_t MAC_value[8] = {0};                  // MAC Value
    uint8_t RNDICC[8] = {0};

    resplen -= 2;

    seos_challenge_get(RNDICC, sizeof(RNDICC), 0x01);
    select_df_decode(response, resplen, &ALGORITHM_INFO_value1, &ALGORITHM_INFO_value2, CRYPTOGRAM_encrypted_data, MAC_value);
    select_DF_verify(response, resplen, MAC_value, sizeof(MAC_value), ALGORITHM_INFO_value1, key_index);
    return PM3_SUCCESS;
};

static int seos_gdf_select(int key_index) {
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;

    bool activate_field = false;
    bool keep_field_on = true;
    // ---------------  Select Global_df for SEOS Card ----------------
    // SelectGDF = 00A507 + referenceDataQualifier + 00
    // 00A5070600
    // SelectGlobalDF = 00A50000

    const char *getGDF = "00A5070600";

    uint8_t agetGDF[10];
    int agetGDF_n = 0;
    param_gethex_to_eol(getGDF, 0, agetGDF, sizeof(agetGDF), &agetGDF_n);
    int res = ExchangeAPDU14a(agetGDF, agetGDF_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    uint16_t sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Get Global_df failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    // --------------- Decrypt GDF Response ----------------
    // Information returned from the GetChallenge command
    int ALGORITHM_INFO_value1 = 0;               // Encryption Algorithm
    int ALGORITHM_INFO_value2 = 0;               // Hash Algorithm
    uint8_t CRYPTOGRAM_encrypted_data[64] = {0}; // Encrypted Data
    uint8_t MAC_value[8] = {0};                  // MAC Value
    uint8_t RNDICC[8] = {0};

    seos_challenge_get(RNDICC, sizeof(RNDICC), 0x09);
    select_df_decode(response, (resplen - 2), &ALGORITHM_INFO_value1, &ALGORITHM_INFO_value2, CRYPTOGRAM_encrypted_data, MAC_value);
    select_DF_verify(response, resplen, MAC_value, sizeof(MAC_value), ALGORITHM_INFO_value1, key_index);

    return PM3_SUCCESS;
};

static int seos_select(void) {
    int res = seos_aid_select();
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    const char *oid = "2B0601040181E438010102011801010202";
    int oid_len = strlen(oid);
    res = seos_adf_select((char *)oid, oid_len, 0);
    DropField();
    return res;
}

static int seos_pacs(char *oid, int oid_len, uint8_t *get_data, int get_data_len, int key_index) {
    int res = seos_aid_select();
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    res = seos_pacs_adf_select(oid, oid_len, get_data, get_data_len, key_index);
    DropField();
    return res;
}

static int seos_global_df(int key_index) {
    int res = seos_aid_select();
    if (res == PM3_SUCCESS) {
        res = seos_gdf_select(key_index);
    }
    DropField();
    return res;
}

static int seos_print_keys(bool verbose) {
    PrintAndLogEx(NORMAL, "");
    if (verbose) {
        for (int i = 0; i < ARRAYLEN(keys); i++) {
            PrintAndLogEx(INFO, "Key Index........................ " _YELLOW_("%u"), i);
            PrintAndLogEx(INFO, "Nonce............................ " _YELLOW_("%s"), sprint_hex(keys[i].nonce, 8));
            PrintAndLogEx(INFO, "Privacy Encryption Key........... " _YELLOW_("%s"), sprint_hex(keys[i].privEncKey, 16));
            PrintAndLogEx(INFO, "Privacy MAC Key.................. " _YELLOW_("%s"), sprint_hex(keys[i].privMacKey, 16));
            PrintAndLogEx(INFO, "Read Key......................... " _YELLOW_("%s"), sprint_hex(keys[i].readKey, 16));
            PrintAndLogEx(INFO, "Write Key........................ " _YELLOW_("%s"), sprint_hex(keys[i].writeKey, 16));
            PrintAndLogEx(INFO, "Admin Key........................ " _YELLOW_("%s"), sprint_hex(keys[i].adminKey, 16));
            PrintAndLogEx(INFO, "----------------------------");
        }
    } else {
        PrintAndLogEx(INFO, "idx| key");
        PrintAndLogEx(INFO, "---+------------------------");
        for (uint8_t i = 0; i < ARRAYLEN(keys); i++) {
            if (memcmp(keys[i].privEncKey, zeros, sizeof(zeros)) == 0)
                PrintAndLogEx(INFO, " %u |", i);
            else
                PrintAndLogEx(INFO, " %u | " _YELLOW_("%s"), i, sprint_hex(keys[i].nonce, 8));
        }
        PrintAndLogEx(INFO, "---+------------------------");
    };
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int seos_load_keys(char *filename) {
    uint8_t *dump = NULL;
    size_t bytes_read = 0;
    if (loadFile_safe(filename, "", (void **)&dump, &bytes_read) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "File: " _YELLOW_("%s") ": not found or locked.", filename);
        return PM3_EFILE;
    }

    // 16 = max line size
    // 8 = 8 items per keyset
    // 4 = 4 keysets
    if (bytes_read > 382) {
        PrintAndLogEx(WARNING, "File is too long to load - exp: %zu got: %zu", sizeof(keys), bytes_read);
        free(dump);
        return PM3_EFILE;
    }

    size_t kn = sizeof(keyset_t);

    size_t i = 0;
    for (; i < bytes_read / kn; i++) {
        memcpy(keys[i].nonce, dump + (i * kn), 8);
        memcpy(keys[i].privEncKey, dump + ((i * kn) + 8), 16);
        memcpy(keys[i].privMacKey, dump + ((i * kn) + 24), 16);
        memcpy(keys[i].readKey, dump + ((i * kn) + 40), 16);
        memcpy(keys[i].writeKey, dump + ((i * kn) + 56), 16);
        memcpy(keys[i].adminKey, dump + ((i * kn) + 72), 16);
    }

    free(dump);
    PrintAndLogEx(SUCCESS, "Loaded" _GREEN_("%2zd") " keys from %s", i, filename);
    return PM3_SUCCESS;
}

int infoSeos(bool verbose) {
    return seos_select();
}

static int CmdHfSeosInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf seos info",
                  "Requests the unauthenticated information from the default ADF of a SEOS card\n"
                  "- If the card is a SEOS card\n"
                  "- Are static RND.ICC keys used (can detect SEOS default keyset)\n"
                  "- What encryption and hashing algorithm is use\n",
                  "hf seos info"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return infoSeos(true);
}

static int CmdHfSeosGDF(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf seos gdf",
                  "Get Global Data File (GDF) from SEOS card\n\n"
                  "By default:\n"
                  "  - Key Index: 0\n",
                  "hf seos gdf"
                  "hf seos gdf --ki 0"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int0(NULL, "ki", "<dec>", "Specify key index to set key in memory"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int key_index = arg_get_int_def(ctx, 1, -1);

    CLIParserFree(ctx);
    return seos_global_df(key_index);
}

static int CmdHfSeosPACS(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf seos pacs",
                  "Make a GET DATA request to an ADF of a SEOS card\n\n"
                  "By default:\n"
                  "  - ADF OID  : 2B0601040181E438010102011801010202\n"
                  "  - Key Index: 0\n",
                  "hf seos pacs\n"
                  "hf seos pacs --ki 1\n"
                  "hf seos pacs -o 2B0601040181E438010102011801010202 --ki 0\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("o", "oid", "<hex>", "<0-100> hex bytes for OID (Default: 2B0601040181E438010102011801010202)"),
        arg_int0(NULL, "ki", "<dec>", "Specify key index to set key in memory"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int get_data_len = 4;
    uint8_t get_data[] = {0x5c, 0x02, 0xff, 0x00};

    int oid_len = 0;
    uint8_t oid_hex[256] = {0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xE4, 0x38, 0x01, 0x01, 0x02, 0x01, 0x18, 0x01, 0x01, 0x02};
    CLIGetHexWithReturn(ctx, 1, oid_hex, &oid_len);

    int key_index = arg_get_int_def(ctx, 2, 0);

    CLIParserFree(ctx);

    // Fall back to default OID
    if (oid_len == 0) {
        oid_len = 16;
    }

    // convert OID hex to literal string

    char oid_buffer[256] = "";
    for (int i = 0; i < oid_len; i++) {
        sprintf(oid_buffer + (i * 2), "%02X", oid_hex[i]);
    }

    const char *oid = oid_buffer;

    if (oid_len == 0) {
        PrintAndLogEx(ERR, "OID value must be supplied");
        return PM3_ESOFT;
    }

    return seos_pacs((char *)oid, oid_len, get_data, get_data_len, key_index);
}

static int CmdHfSeosADF(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf seos adf",
                  "Make a GET DATA request to an Application Data File (ADF) of a SEOS Tag\n"
                  "The ADF is meant to be read by an application\n"
                  "You still need the valid authentication keys to read a card\n\n"
                  "By default:\n"
                  "  - ADF OID  : 2B0601040181E438010102011801010202\n"
                  "  - Key Index: 0\n"
                  "  - Tag List : 5c02ff00\n",
                  "hf seos adf\n"
                  "hf seos adf -o 2B0601040181E438010102011801010202\n"
                  "hf seos adf -o 2B0601040181E438010102011801010202 --ki 0\n"
                  "hf seos adf -o 2B0601040181E438010102011801010202 -c 5c02ff41\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("c", "getdata", "<hex>", "<0-100> hex bytes for the tag list to Get Data request (Default: 5c02ff00)"),
        arg_str0("o", "oid", "<hex>", "<0-100> hex bytes for OID (Default: 2B0601040181E438010102011801010202)"),
        arg_int0(NULL, "ki", "<dec>", "Specify key index to set key in memory"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int get_data_len = 0;
    uint8_t get_data[256] = {0x5c, 0x02, 0xff, 0x00};
    CLIGetHexWithReturn(ctx, 1, get_data, &get_data_len);

    int oid_len = 0;
    uint8_t oid_hex[256] = {0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xE4, 0x38, 0x01, 0x01, 0x02, 0x01, 0x18, 0x01, 0x01, 0x02};
    CLIGetHexWithReturn(ctx, 2, oid_hex, &oid_len);

    int key_index = arg_get_int_def(ctx, 3, 0);

    CLIParserFree(ctx);

    if (get_data_len == 0) {
        get_data_len = 4;
    }

    // Catching when the OID value is not supplied
    if (oid_len == 0) {
        oid_len = 16;
    }

    // convert OID hex to literal string
    char oid_buffer[256] = "";
    for (int i = 0; i < oid_len; i++) {
        sprintf(oid_buffer + (i * 2), "%02X", oid_hex[i]);
    }

    const char *oid = oid_buffer;

    if (oid_len == 0) {
        PrintAndLogEx(ERR, "OID value must be supplied");
        return PM3_ESOFT;
    }

    return seos_pacs((char *)oid, oid_len, get_data, get_data_len, key_index);
}

static int CmdHfSeosManageKeys(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf seos managekeys",
                  "Manage SEOS Keys in client memory, keys are required to authenticate with SEOS cards\n",
                  "hf seos managekeys -p\n"
                  "hf seos managekeys -p -v\n"
                  "hf seos managekeys --ki 0 --nonce 0102030405060708  -> Set nonce value at key index 0\n"
                  "hf seos managekeys --load -f mykeys.bin -p          -> load from file and prints keys\n"
                  "hf seos managekeys --save -f mykeys.bin             -> saves keys to file\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0(NULL, "ki", "<dec>", "Specify key index to set key in memory"),
        arg_str0(NULL, "nonce", "<hex>", "Nonce value as 8 hex bytes"),
        arg_str0(NULL, "privenc", "<hex>", "Privacy Encryption key as 16 hex bytes"),
        arg_str0(NULL, "privmac", "<hex>", "Privacy MAC key as 16 hex bytes"),
        arg_str0(NULL, "read", "<hex>", "Undiversified Read key as 16 hex bytes"),
        arg_str0(NULL, "write", "<hex>", "Undiversified Write key as 16 hex bytes"),
        arg_str0(NULL, "admin", "<hex>", "Undiversified Admin key as 16 hex bytes"),

        arg_str0("f", "file", "<fn>", "Specify a filename for load / save operations"),
        arg_lit0(NULL, "save", "Save keys in memory to file specified by filename"),
        arg_lit0(NULL, "load", "Load keys to memory from file specified by filename"),

        arg_lit0("p", "print", "Print keys loaded into memory"),
        arg_lit0("v", "verbose", "verbose (print all key info)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    uint8_t operation = 0;

    uint8_t nonce[8] = {0};
    uint8_t privenc[16] = {0};
    uint8_t privmac[16] = {0};
    uint8_t read[16] = {0};
    uint8_t write[16] = {0};
    uint8_t admin[16] = {0};
    int nonce_len = 0;
    int privenc_len = 0;
    int privmac_len = 0;
    int read_len = 0;
    int write_len = 0;
    int admin_len = 0;

    int key_index = arg_get_int_def(ctx, 1, -1);

    CLIGetHexWithReturn(ctx, 2, nonce, &nonce_len);
    CLIGetHexWithReturn(ctx, 3, privenc, &privenc_len);
    CLIGetHexWithReturn(ctx, 4, privmac, &privmac_len);
    CLIGetHexWithReturn(ctx, 5, read, &read_len);
    CLIGetHexWithReturn(ctx, 6, write, &write_len);
    CLIGetHexWithReturn(ctx, 7, admin, &admin_len);

    CLIParamStrToBuf(arg_get_str(ctx, 8), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    if (key_index >= 0) {
        operation += 3;
        if (key_index < 4) {
            if (nonce_len != 0) {
                PrintAndLogEx(SUCCESS, "Current value for nonce[%d] " _GREEN_("%s"), key_index, sprint_hex_inrow(keys[key_index].nonce, 8));
            }
            if (privenc_len != 0) {
                PrintAndLogEx(SUCCESS, "Current value for Priv Enc[%d] " _GREEN_("%s"), key_index, sprint_hex_inrow(keys[key_index].privEncKey, 16));
            }
            if (privmac_len != 0) {
                PrintAndLogEx(SUCCESS, "Current value for Priv Mac[%d] " _GREEN_("%s"), key_index, sprint_hex_inrow(keys[key_index].privMacKey, 16));
            }
            if (read_len != 0) {
                PrintAndLogEx(SUCCESS, "Current value for Read Key[%d] " _GREEN_("%s"), key_index, sprint_hex_inrow(keys[key_index].readKey, 16));
            }
            if (write_len != 0) {
                PrintAndLogEx(SUCCESS, "Current value for Write Key[%d] " _GREEN_("%s"), key_index, sprint_hex_inrow(keys[key_index].writeKey, 16));
            }
            if (admin_len != 0) {
                PrintAndLogEx(SUCCESS, "Current value for Admin Key[%d] " _GREEN_("%s"), key_index, sprint_hex_inrow(keys[key_index].adminKey, 16));
            }
        } else {
            PrintAndLogEx(ERR, "Key index is out-of-range");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }

    if (arg_get_lit(ctx, 9)) {  //save
        operation += 6;
    }
    if (arg_get_lit(ctx, 10)) {  //load
        operation += 5;
    }
    if (arg_get_lit(ctx, 11)) {  //print
        operation += 4;
    }

    bool verbose = arg_get_lit(ctx, 12);

    CLIParserFree(ctx);

    if (operation == 0) {
        PrintAndLogEx(ERR, "No operation specified (load, save, or print)\n");
        return PM3_EINVARG;
    }
    if (operation > 6) {
        PrintAndLogEx(ERR, "Too many operations specified\n");
        return PM3_EINVARG;
    }
    if (operation > 4 && fnlen == 0) {
        PrintAndLogEx(ERR, "You must enter a filename when loading or saving\n");
        return PM3_EINVARG;
    }
    if (((nonce_len > 0) || (privenc_len > 0) || (privmac_len > 0) || (read_len > 0) || (write_len > 0) || (admin_len > 0)) && key_index == -1) {
        PrintAndLogEx(ERR, "Please specify key index when specifying key");
        return PM3_EINVARG;
    }

    switch (operation) {
        case 3:
            if (nonce_len != 0) {
                memcpy(keys[key_index].nonce, nonce, 8);
                PrintAndLogEx(SUCCESS, "New value for nonce[%d] " _GREEN_("%s"), key_index, sprint_hex_inrow(keys[key_index].nonce, 8));
            }
            if (privenc_len != 0) {
                memcpy(keys[key_index].privEncKey, privenc, 16);
                PrintAndLogEx(SUCCESS, "New value for Priv Enc[%d] " _GREEN_("%s"), key_index, sprint_hex_inrow(keys[key_index].privEncKey, 16));
            }
            if (privmac_len != 0) {
                memcpy(keys[key_index].privMacKey, privmac, 16);
                PrintAndLogEx(SUCCESS, "New value for Priv Mac[%d] " _GREEN_("%s"), key_index, sprint_hex_inrow(keys[key_index].privMacKey, 16));
            }
            if (read_len != 0) {
                memcpy(keys[key_index].readKey, read, 16);
                PrintAndLogEx(SUCCESS, "New value for Read Key[%d] " _GREEN_("%s"), key_index, sprint_hex_inrow(keys[key_index].readKey, 16));
            }
            if (write_len != 0) {
                memcpy(keys[key_index].writeKey, write, 16);
                PrintAndLogEx(SUCCESS, "New value for Write Key[%d] " _GREEN_("%s"), key_index, sprint_hex_inrow(keys[key_index].writeKey, 16));
            }
            if (admin_len != 0) {
                memcpy(keys[key_index].adminKey, admin, 16);
                PrintAndLogEx(SUCCESS, "New value for Admin Key[%d] " _GREEN_("%s"), key_index, sprint_hex_inrow(keys[key_index].adminKey, 16));
            }
            return PM3_SUCCESS;
        case 4:
            return seos_print_keys(verbose);
        case 5:
            return seos_load_keys(filename);
        case 6: {
            bool isOK = saveFile(filename, ".bin", keys, sizeof(keys));
            if (isOK == false) {
                return PM3_EFILE;
            }
            return PM3_SUCCESS;
        }
    }

    return PM3_SUCCESS;
}

static int CmdHfSeosList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf seos", "seos -c");
}

static int CmdHfSeosSAM(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf seos sam",
                  "Extract PACS via a HID SAM\n",
                  "hf seos sam\n"
                  "hf seos sam -d a005a103800104 -> get PACS data\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0("k", "keep", "keep the field active after command executed"),
        arg_lit0("n", "nodetect", "skip selecting the card and sending card details to SAM"),
        arg_lit0("t",  "tlv",      "decode TLV"),
        arg_strx0("d", "data",     "<hex>", "DER encoded command to send to SAM"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool verbose = arg_get_lit(ctx, 1);
    bool disconnectAfter = !arg_get_lit(ctx, 2);
    bool skipDetect = arg_get_lit(ctx, 3);
    bool decodeTLV = arg_get_lit(ctx, 4);

    uint8_t flags = 0;
    if (disconnectAfter) flags |= BITMASK(0);
    if (skipDetect) flags |= BITMASK(1);

    uint8_t data[PM3_CMD_DATA_SIZE] = {0};
    data[0] = flags;

    int cmdlen = 0;
    if (CLIParamHexToBuf(arg_get_str(ctx, 5), data + 1, PM3_CMD_DATA_SIZE - 1, &cmdlen) != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    CLIParserFree(ctx);

    if (IsHIDSamPresent(verbose) == false) {
        return PM3_ESOFT;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_SAM_SEOS, data, cmdlen + 1);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_SAM_SEOS, &resp, 4000) == false) {
        PrintAndLogEx(WARNING, "SAM timeout");
        return PM3_ETIMEOUT;
    }

    switch (resp.status) {
        case PM3_SUCCESS:
            break;
        case PM3_ENOPACS:
            PrintAndLogEx(SUCCESS, "No PACS data found. Card empty?");
            return resp.status;
        default:
            PrintAndLogEx(WARNING, "SAM select failed");
            return resp.status;
    }

    uint8_t *d = resp.data.asBytes;
    // check for standard SamCommandGetContentElement response
    // bd 09
    //    8a 07
    //       03 05 <- tag + length
    //          06 85 80 6d c0 <- decoded PACS data
    if (d[0] == 0xbd && d[2] == 0x8a && d[4] == 0x03) {
        uint8_t pacs_length = d[5];
        uint8_t *pacs_data = d + 6;
        int res = HIDDumpPACSBits(pacs_data, pacs_length, verbose);
        if (res != PM3_SUCCESS) {
            return res;
        }
        // check for standard samCommandGetContentElement2:
        // bd 1e
        //    b3 1c
        //       a0 1a
        //          80 05
        //             06 85 80 6d c0
        //          81 0e
        //             2b 06 01 04 01 81 e4 38 01 01 02 04 3c ff
        //          82 01
        //             07
    } else if (d[0] == 0xbd && d[2] == 0xb3 && d[4] == 0xa0) {
        const uint8_t *pacs = d + 6;
        const uint8_t pacs_length = pacs[1];
        const uint8_t *pacs_data = pacs + 2;
        int res = HIDDumpPACSBits(pacs_data, pacs_length, verbose);
        if (res != PM3_SUCCESS) {
            return res;
        }

        const uint8_t *oid = pacs + 2 + pacs_length;
        const uint8_t oid_length = oid[1];
        const uint8_t *oid_data = oid + 2;
        PrintAndLogEx(SUCCESS, "SIO OID.......: " _GREEN_("%s"), sprint_hex_inrow(oid_data, oid_length));

        const uint8_t *mediaType = oid + 2 + oid_length;
        const uint8_t mediaType_data = mediaType[2];
        PrintAndLogEx(SUCCESS, "SIO Media Type: " _GREEN_("%s"), getSioMediaTypeInfo(mediaType_data));

    } else {
        print_hex(d, resp.length);
    }
    if (decodeTLV) {
        asn1_print(d, d[1] + 2, " ");
    }

    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"-----------", CmdHelp,            AlwaysAvailable, "----------------------- " _CYAN_("General") " -----------------------"},
    {"help",    CmdHelp,                AlwaysAvailable, "This help"},
    {"list",    CmdHfSeosList,          AlwaysAvailable, "List SEOS history"},
    {"sam",     CmdHfSeosSAM,           IfPm3Smartcard,  "SAM tests"},
    {"-----------", CmdHelp,            AlwaysAvailable, "----------------------- " _CYAN_("Operations") " -----------------------"},
    {"info",    CmdHfSeosInfo,          IfPm3Iso14443a, "Tag information"},
    {"pacs",    CmdHfSeosPACS,          AlwaysAvailable, "Extract PACS Information from card"},
    {"adf",     CmdHfSeosADF,           AlwaysAvailable, "Read an ADF from the card"},
    {"gdf",     CmdHfSeosGDF,           AlwaysAvailable, "Read an GDF from card"},
    {"-----------", CmdHelp,            AlwaysAvailable, "----------------------- " _CYAN_("Utils") " -----------------------"},
    {"managekeys", CmdHfSeosManageKeys, AlwaysAvailable, "Manage keys to use with SEOS commands"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFSeos(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

