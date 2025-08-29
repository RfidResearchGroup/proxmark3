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
// Saflok commands
//-----------------------------------------------------------------------------
#include "cmdhfsaflok.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "cliparser.h"
#include "cmdparser.h"
#include "comms.h"
#include "ui.h"
#include "util.h"
#include "mifare/mifarehost.h"
#include "mifare.h"
#include "commonutil.h"
#include "generator.h"
#include "cmdhfmf.h"

#define KEY_LENGTH 6

static const uint8_t c_aDecode[256] = {
    234, 13, 217, 116, 78, 40, 253, 186, 123, 152,
    135, 120, 221, 141, 181, 26, 14, 48, 243, 47,
    106, 59, 172, 9, 185, 32, 110, 91, 43, 182,
    33, 170, 23, 68, 90, 84, 87, 190, 10, 82,
    103, 201, 80, 53, 245, 65, 160, 148, 96, 254,
    36, 162, 54, 239, 30, 107, 247, 156, 105, 218,
    155, 111, 173, 216, 251, 151, 98, 95, 31, 56,
    194, 215, 113, 49, 240, 19, 238, 15, 163, 167,
    28, 213, 17, 76, 69, 44, 4, 219, 166, 46,
    248, 100, 154, 184, 83, 102, 220, 122, 93, 3,
    7, 128, 55, 255, 252, 6, 188, 38, 192, 149,
    74, 241, 81, 45, 34, 24, 1, 121, 94, 118,
    29, 127, 20, 227, 158, 138, 187, 52, 191, 244,
    171, 72, 99, 85, 62, 86, 140, 209, 18, 237,
    195, 73, 142, 146, 157, 202, 177, 229, 206, 77,
    63, 250, 115, 5, 224, 75, 147, 178, 203, 8,
    225, 150, 25, 61, 131, 57, 117, 236, 214, 60,
    208, 112, 129, 22, 41, 21, 108, 199, 231, 226,
    246, 183, 232, 37, 109, 58, 230, 200, 153, 70,
    176, 133, 2, 97, 27, 139, 179, 159, 11, 42,
    168, 119, 16, 193, 136, 204, 164, 222, 67, 88,
    35, 180, 161, 165, 92, 174, 169, 126, 66, 64,
    144, 210, 233, 132, 207, 228, 235, 71, 79, 130,
    212, 197, 143, 205, 211, 134, 0, 89, 223, 242,
    12, 124, 198, 189, 249, 125, 196, 145, 39, 137,
    50, 114, 51, 101, 104, 175
};

static const uint8_t c_aEncode[256] = {
    236, 116, 192, 99, 86, 153, 105, 100, 159, 23,
    38, 198, 240, 1, 16, 77, 202, 82, 138, 75,
    122, 175, 173, 32, 115, 162, 15, 194, 80, 120,
    54, 68, 25, 30, 114, 210, 50, 183, 107, 248,
    5, 174, 199, 28, 85, 113, 89, 19, 17, 73,
    250, 252, 127, 43, 52, 102, 69, 165, 185, 21,
    169, 163, 134, 150, 219, 45, 218, 208, 33, 84,
    189, 227, 131, 141, 110, 155, 83, 149, 4, 228,
    42, 112, 39, 94, 35, 133, 135, 36, 209, 237,
    34, 27, 214, 98, 118, 67, 48, 193, 66, 132,
    91, 253, 95, 40, 254, 58, 20, 55, 176, 184,
    26, 61, 171, 72, 251, 152, 3, 166, 119, 201,
    11, 117, 97, 8, 241, 245, 217, 121, 101, 172,
    229, 164, 223, 191, 235, 10, 204, 249, 125, 195,
    136, 13, 142, 232, 220, 247, 143, 156, 47, 109,
    161, 65, 9, 188, 92, 60, 57, 144, 124, 197,
    46, 212, 51, 78, 206, 213, 88, 79, 200, 216,
    31, 130, 22, 62, 215, 255, 190, 146, 157, 196,
    211, 14, 29, 181, 93, 24, 7, 126, 106, 243,
    37, 128, 108, 203, 70, 140, 246, 231, 242, 177,
    187, 41, 145, 158, 205, 233, 148, 224, 170, 137,
    221, 234, 230, 81, 168, 71, 63, 2, 59, 87,
    96, 12, 207, 238, 154, 160, 179, 123, 225, 147,
    186, 178, 182, 222, 0, 226, 167, 139, 76, 53,
    74, 111, 239, 18, 129, 44, 180, 56, 90, 244,
    151, 64, 104, 6, 49, 103
};

uint8_t magic_table[192] = {
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0xF0, 0x57, 0xB3, 0x9E, 0xE3, 0xD8,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x96, 0x9D, 0x95, 0x4A, 0xC1, 0x57,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x8F, 0x43, 0x58, 0x0D, 0x2C, 0x9D,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0xFF, 0xCC, 0xE0, 0x05, 0x0C, 0x43,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x34, 0x1B, 0x15, 0xA6, 0x90, 0xCC,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x89, 0x58, 0x56, 0x12, 0xE7, 0x1B,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0xBB, 0x74, 0xB0, 0x95, 0x36, 0x58,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0xFB, 0x97, 0xF8, 0x4B, 0x5B, 0x74,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0xC9, 0xD1, 0x88, 0x35, 0x9F, 0x92,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x8F, 0x92, 0xE9, 0x7F, 0x58, 0x97,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x16, 0x6C, 0xA2, 0xB0, 0x9F, 0xD1,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x27, 0xDD, 0x93, 0x10, 0x1C, 0x6C,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0xDA, 0x3E, 0x3F, 0xD6, 0x49, 0xDD,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x58, 0xDD, 0xED, 0x07, 0x8E, 0x3E,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x5C, 0xD0, 0x05, 0xCF, 0xD9, 0x07,
    0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x11, 0x8D, 0xD0, 0x01, 0x87, 0xD0
};

static const char *level_names[] = {
    "Guest Key",                     // Index 0
    "Connectors",                    // Index 1
    "Suite",                         // Index 2
    "Limited Use",                   // Index 3
    "Failsafe",                      // Index 4
    "Inhibit",                       // Index 5
    "Pool/Meeting Master",           // Index 6
    "Housekeeping",                  // Index 7
    "Floor Key",                     // Index 8
    "Section Key",                   // Index 9
    "Rooms Master",                  // Index 10
    "Grand Master",                  // Index 11
    "Emergency",                     // Index 12
    "Electronic Lockout",            // Index 13
    "Secondary Programming Key (SPK)", // Index 14
    "Primary Programming Key (PPK)",  // Index 15
};


static int CmdHelp(const char *Cmd);

static void saflok_decrypt(uint8_t *strCard, int length, uint8_t *decryptedCard) {

    for (int i = 0; i < length; i++) {
        int num = c_aDecode[strCard[i]] - (i + 1);
        if (num < 0) {
            num += 256;
        }
        decryptedCard[i] = num;
    }

    int b = 0;
    int b2 = 0;

    if (length == 17) {
        b = decryptedCard[10];
        b2 = b & 1;
    }

    for (int num2 = length; num2 > 0; num2--) {
        b = decryptedCard[num2 - 1];
        for (int num3 = 8; num3 > 0; num3--) {
            int num4 = num2 + num3;
            if (num4 > length) {
                num4 -= length;
            }
            int b3 = decryptedCard[num4 - 1];
            int b4 = (b3 & 0x80) >> 7;
            b3 = ((b3 << 1) & 0xFF) | b2;
            b2 = (b & 0x80) >> 7;
            b = ((b << 1) & 0xFF) | b4;
            decryptedCard[num4 - 1] = b3;
        }
        decryptedCard[num2 - 1] = b;
    }
}


static void saflok_encrypt(uint8_t *keyCard, int length, uint8_t *encryptedCard) {
    int b = 0;
    memcpy(encryptedCard, keyCard, length);
    for (int i = 0; i < length; i++) {
        int b2 = encryptedCard[i];
        int num2 = i;
        for (int j = 0; j < 8; j++) {
            num2 += 1;
            if (num2 >= length) {
                num2 -= length;
            }
            int b3 = encryptedCard[num2];
            int b4 = b2 & 1;
            b2 = (b2 >> 1) | (b << 7);
            b = b3 & 1;
            b3 = (b3 >> 1) | (b4 << 7);
            encryptedCard[num2] = b3;
        }
        encryptedCard[i] = b2;
    }
    if (length == 17) {
        int b2 = encryptedCard[10];
        b2 |= b;
        encryptedCard[10] = b2;
    }
    for (int i = 0; i < length; i++) {
        int j = encryptedCard[i] + (i + 1);
        if (j > 255) {
            j -= 256;
        }
        encryptedCard[i] = c_aEncode[j];
    }
}

static uint32_t extract_bits(const uint8_t *data, size_t start_bit, size_t num_bits) {
    uint32_t result = 0;
    for (size_t i = 0; i < num_bits; i++) {
        size_t byte_index = (start_bit + i) / 8;
        size_t bit_index = (start_bit + i) % 8;
        if (data[byte_index] & (1 << (7 - bit_index))) {
            result |= (1ULL << (num_bits - 1 - i));
        }
    }
    return result;
}

static void insert_bits(uint8_t *data, size_t start_bit, size_t num_bits, uint32_t value) {
    for (size_t i = 0; i < num_bits; i++) {
        size_t current_bit = start_bit + i;
        size_t byte_index = current_bit / 8;
        size_t bit_index = 7 - (current_bit % 8);

        uint32_t bit_value = (value >> (num_bits - 1 - i)) & 1U;

        data[byte_index] = (data[byte_index] & ~(1 << bit_index)) | (bit_value << bit_index);
    }
}

static char *bytes_to_hex(const uint8_t *data, size_t len) {
    static char buf[256];
    for (size_t i = 0; i < len; i++) {
        sprintf(buf + (i * 2), "%02X", data[i]);
    }
    buf[len * 2] = '\0';
    return buf;
}


static int pack_datetime_expr(char *exp_datetime, uint8_t *data) {
    int year, month, day, hour, minute;

    if (sscanf(exp_datetime, "%4d-%2d-%2dT%2d:%2d",
               &year, &month, &day, &hour, &minute) != 5) {
        return -1;
    }

    data[8] = ((year & 0x0F) << 4) | (month & 0x0F);
    data[9] = ((day & 0x1F) << 3) | ((hour & 0x1C) >> 2);
    data[10] = ((hour & 0x03) << 6) | (minute & 0x3F);

    return 0;
}

static int pack_datetime(char *datetime_str, uint8_t *data) {
    int year, month, day, hour, minute;

    if (sscanf(datetime_str, "%4d-%2d-%2dT%2d:%2d",
               &year, &month, &day, &hour, &minute) != 5) {
        return -1;
    }

    uint8_t year_offset = year - 1980;

    data[11] = ((year_offset & 0x0F) << 4) | (month & 0x0F);
    data[12] = ((day & 0x1F) << 3) | ((hour & 0x1C) >> 2);
    data[13] = ((hour & 0x03) << 6) | (minute & 0x3F);
    data[14] = (data[14] & 0x0F) | ((year_offset & 0x70) << 0);

    return 0;
}


static uint8_t saflok_checksum(unsigned char *data, int length) {
    int sum = 0;
    for (int i = 0; i < length; i++) {
        sum += data[i];
    }
    sum = 255 - (sum & 0xFF);
    return sum & 0xFF;
}

static void saflok_kdf(const uint8_t *uid, uint8_t *key_out) {

    uint8_t magic_byte = (uid[3] >> 4) + (uid[2] >> 4) + (uid[0] & 0x0F);
    uint8_t magickal_index = (magic_byte & 0x0F) * 12 + 11;
    uint8_t carry_sum = 0;

    uint8_t key[KEY_LENGTH] = {magic_byte, uid[0], uid[1], uid[2], uid[3], magic_byte};

    for (int i = KEY_LENGTH - 1; i >= 0; i--, magickal_index--) {
        uint16_t keysum = key[i] + magic_table[magickal_index];
        key[i] = (keysum & 0xFF) + carry_sum;
        carry_sum = keysum >> 8;
    }

    memcpy(key_out, key, KEY_LENGTH);
}

static void saflok_decode(uint8_t *data) {

    uint32_t card_level = extract_bits(data, 0, 4);
    uint32_t card_type = extract_bits(data, 4, 4);
    uint32_t card_id = extract_bits(data, 8, 8);
    uint32_t opening_key = extract_bits(data, 16, 2);
    uint32_t lock_id = extract_bits(data, 18, 14);
    uint32_t pass_number = extract_bits(data, 32, 12);
    uint32_t sequence_and_combination = extract_bits(data, 44, 12);
    uint32_t deadbolt_override = extract_bits(data, 56, 1);
    uint32_t restricted_days = extract_bits(data, 57, 7);
    //uint32_t expire_date = extract_bits(data, 64, 24);
    //uint32_t card_creation_date = extract_bits(data, 88, 28);
    uint32_t property_id = extract_bits(data, 116, 12);
    uint32_t checksum = extract_bits(data, 128, 8);

    //date parsing, stolen from flipper code
    uint16_t interval_year = (data[8] >> 4);
    uint8_t interval_month = data[8] & 0x0F;
    uint8_t interval_day = (data[9] >> 3) & 0x1F;
    uint8_t interval_hour = ((data[9] & 0x07) << 2) | (data[10] >> 6);
    uint8_t interval_minute = data[10] & 0x3F;

    uint8_t creation_year_bits = (data[14] & 0xF0);
    uint16_t creation_year =
        (creation_year_bits | ((data[11] & 0xF0) >> 4)) + 1980;
    uint8_t creation_month = data[11] & 0x0F;
    uint8_t creation_day = (data[12] >> 3) & 0x1F;
    uint8_t creation_hour = ((data[12] & 0x07) << 2) | (data[13] >> 6);
    uint8_t creation_minute = data[13] & 0x3F;

    uint16_t expire_year = creation_year + interval_year;
    uint8_t expire_month = creation_month + interval_month;
    uint8_t expire_day = creation_day + interval_day;
    uint8_t expire_hour = interval_hour;
    uint8_t expire_minute = interval_minute;

    // Handle month rollover
    while (expire_month > 12) {
        expire_month -= 12;
        expire_year++;
    }

    // Handle day rollover
    static const uint8_t days_in_month[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    while (true) {
        uint8_t max_days = days_in_month[expire_month - 1];
        // Adjust for leap years
        if (expire_month == 2 &&
                (expire_year % 4 == 0 && (expire_year % 100 != 0 || expire_year % 400 == 0))) {
            max_days = 29;
        }
        if (expire_day <= max_days) {
            break;
        }
        expire_day -= max_days;
        expire_month++;
        if (expire_month > 12) {
            expire_month = 1;
            expire_year++;
        }
    }

    PrintAndLogEx(SUCCESS, "Card Level: " _GREEN_("%u (%s)"), card_level, level_names[card_level]);
    PrintAndLogEx(SUCCESS, "Card Type: " _GREEN_("%u"), card_type);
    PrintAndLogEx(SUCCESS, "Card ID: " _GREEN_("%u"), card_id);
    PrintAndLogEx(SUCCESS, "Opening Key: " _GREEN_("%u"), opening_key);
    PrintAndLogEx(SUCCESS, "Lock ID: " _GREEN_("%u"), lock_id);
    PrintAndLogEx(SUCCESS, "Pass Number: " _GREEN_("%u"), pass_number);
    PrintAndLogEx(SUCCESS, "Sequence and Combination: " _GREEN_("%u"), sequence_and_combination);
    PrintAndLogEx(SUCCESS, "Deadbolt Override: " _GREEN_("%u"), deadbolt_override);
    PrintAndLogEx(SUCCESS, "Restricted Days: " _GREEN_("%u"), restricted_days);
    PrintAndLogEx(SUCCESS, "Card Creation Date: " _GREEN_("%u-%02d-%02d %02d:%02d"),
                  creation_year,
                  creation_month,
                  creation_day,
                  creation_hour,
                  creation_minute);
    PrintAndLogEx(SUCCESS, "Expire Date: " _GREEN_("%u-%02d-%02d %02d:%02d"),
                  expire_year,
                  expire_month,
                  expire_day,
                  expire_hour,
                  expire_minute);
    PrintAndLogEx(SUCCESS, "Property ID: " _GREEN_("%u"), property_id);
    PrintAndLogEx(SUCCESS, "Checksum: " _GREEN_("0x%X") " (%s)", checksum, (checksum == saflok_checksum(data, 16)) ? _GREEN_("ok") : _RED_("bad"));
    PrintAndLogEx(NORMAL, "");

}

static void saflok_encode(uint8_t *data, uint32_t card_level, uint32_t card_type, uint32_t card_id,
                          uint32_t opening_key, uint32_t lock_id, uint32_t pass_number,
                          uint32_t sequence_and_combination, uint32_t deadbolt_override,
                          uint32_t restricted_days, uint32_t expire_date, uint32_t card_creation_date,
                          uint32_t property_id, char *dt_e, char *dt) {
    insert_bits(data, 0, 4, card_level);
    insert_bits(data, 4, 4, card_type);
    insert_bits(data, 8, 8, card_id);
    insert_bits(data, 16, 2, opening_key);
    insert_bits(data, 18, 14, lock_id);
    insert_bits(data, 32, 12, pass_number);
    insert_bits(data, 44, 12, sequence_and_combination);
    insert_bits(data, 56, 1, deadbolt_override);
    insert_bits(data, 57, 7, restricted_days);
    insert_bits(data, 64, 24, expire_date);
    insert_bits(data, 88, 28, card_creation_date);
    insert_bits(data, 116, 12, property_id);

    int year, month, day, hour, minute;

    if (sscanf(dt, "%4d-%2d-%2dT%2d:%2d",
               &year, &month, &day, &hour, &minute) == 5) {
        pack_datetime(dt, data);
    }
    //else{
    //insert_bits(data, 88, 28,card_creation_date);
    //PrintAndLogEx(SUCCESS, "DT BITS INSERTED");
    //}

    if (sscanf(dt_e, "%4d-%2d-%2dT%2d:%2d",
               &year, &month, &day, &hour, &minute) == 5) {
        pack_datetime_expr(dt_e, data);
    }
    //else{
    //insert_bits(data, 64, 24, expire_date);
    //PrintAndLogEx(SUCCESS, "DTE BITS INSERTED");
    //}

    uint8_t checksum = saflok_checksum(data, 16);
    insert_bits(data, 128, 8, checksum);

}

static int saflok_read_sector(int sector, uint8_t *secdata) {
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 2500) == false) {
        PrintAndLogEx(DEBUG, "iso14443a card select failed");
        DropField();
        return PM3_ERFTRANS;
    }

    iso14a_card_select_t card;
    memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

    uint8_t key[6];
    uint64_t tmpkey = 0;
    mfc_algo_saflok_one(card.uid, sector, MF_KEY_A, &tmpkey);
    num_to_bytes(tmpkey, MIFARE_KEY_SIZE, key);

    return mf_read_sector(sector, MF_KEY_A, key, secdata);
}


static int CmdHFSaflokRead(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf saflok read",
                  "Read Saflok card (MIFARE Classic only)",
                  "hf saflok read");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    uint8_t secdata[64];
    int res = saflok_read_sector(1, secdata);

    if (res == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Valid Saflok card found!");
    } else {
        PrintAndLogEx(FAILED, "Not a valid Saflok card");
        return PM3_EFAILED;
    }

    uint8_t saflokdata[17];
    saflok_read_sector(0, secdata);
    saflok_decrypt(secdata + 16, 17, saflokdata);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Card Information"));
    PrintAndLogEx(SUCCESS, "Encrypted Data: " _GREEN_("%s"), bytes_to_hex(secdata + 16, 17));

    saflok_decode(saflokdata);

    return PM3_SUCCESS;
}


static int CmdHFSaflokEncode(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf saflok encode",
                  "Encode Saflok data",
                  "hf saflok encode");

    void *argtable[] = {
        arg_param_begin,
        arg_u64_1(NULL, "level", "<decimal>", "Card Level"),
        arg_u64_1(NULL, "type", "<decimal>", "Card Type"),
        arg_u64_1(NULL, "id", "<decimal>", "Card ID"),
        arg_u64_1(NULL, "open", "<decimal>", "Opening Bits"),
        arg_u64_1(NULL, "lock_id", "<decimal>", "Lock ID"),
        arg_u64_1(NULL, "pass_num", "<decimal>", "Pass Number"),
        arg_u64_1(NULL, "seq_combo", "<decimal>", "Sequence and Combination"),
        arg_u64_1(NULL, "deadbolt", "<decimal>", "Deadbolt Override"),
        arg_u64_1(NULL, "days", "<decimal>", "Restricted Days"),
        arg_str1(NULL, "expire", "<YYYY-MM-DDTHH:mm>", "Expire Date Offset"),
        arg_str1(NULL, "created", "<YYYY-MM-DDTHH:mm>", "Card Creation Date"),
        arg_u64_1(NULL, "prop_id", "<decimal>", "Property ID"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);


    uint8_t rsaflokdata[17] = {0};
    uint8_t esaflokdata[17] = {0};

    int slen = 0;
    char dt[100];
    CLIParamStrToBuf(arg_get_str(ctx, 11), (uint8_t *)dt, 100, &slen);

    char dt_e[100];
    CLIParamStrToBuf(arg_get_str(ctx, 10), (uint8_t *)dt_e, 100, &slen);


    saflok_encode(rsaflokdata,
                  arg_get_u32_def(ctx, 1, 0),
                  arg_get_u32_def(ctx, 2, 0),
                  arg_get_u32_def(ctx, 3, 0),
                  arg_get_u32_def(ctx, 4, 0),
                  arg_get_u32_def(ctx, 5, 0),
                  arg_get_u32_def(ctx, 6, 0),
                  arg_get_u32_def(ctx, 7, 0),
                  arg_get_u32_def(ctx, 8, 0),
                  arg_get_u32_def(ctx, 9, 0),
                  0,
                  0,
                  arg_get_u32_def(ctx, 12, 0),
                  dt_e,
                  dt);

    saflok_encrypt(rsaflokdata, 17, esaflokdata);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Encoded Card Data"));
    PrintAndLogEx(SUCCESS, "Encrypted Data: " _GREEN_("%s"), bytes_to_hex(esaflokdata, 17));


    CLIParserFree(ctx);
    return PM3_SUCCESS;
}

static int CmdHFSaflokDecode(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf saflok decode",
                  "Decode saflok data",
                  "hf saflok decode");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", NULL, "data", "Encrypted 17 byte card data"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint8_t saflokdata[17];
    uint8_t dsaflokdata[17];
    int dlen;
    CLIGetHexWithReturn(ctx, 1, saflokdata, &dlen);
    CLIParserFree(ctx);


    if (dlen != 17) {
        PrintAndLogEx(WARNING, "saflok data must include 17 HEX bytes. Got %i", dlen);
        return PM3_EINVARG;
    }

    saflok_decrypt(saflokdata, 17, dsaflokdata);
    saflok_decode(dsaflokdata);

    return PM3_SUCCESS;
}



static int CmdHFSaflokModify(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf saflok modify",
                  "Modify Saflok card data",
                  "hf saflok modify");

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0(NULL, "level", "<decimal>", "Card Level"),
        arg_u64_0(NULL, "type", "<decimal>", "Card Type"),
        arg_u64_0(NULL, "id", "<decimal>", "Card ID"),
        arg_u64_0(NULL, "open", "<decimal>", "Opening Bits"),
        arg_u64_0(NULL, "lock_id", "<decimal>", "Lock ID"),
        arg_u64_0(NULL, "pass_num", "<decimal>", "Pass Number"),
        arg_u64_0(NULL, "seq_combo", "<decimal>", "Sequence and Combination"),
        arg_u64_0(NULL, "deadbolt", "<decimal>", "Deadbolt Override"),
        arg_u64_0(NULL, "days", "<decimal>", "Restricted Days"),
        arg_str0(NULL, "expire", "<YYYY-MM-DDTHH:mm>", "Expire Date Offset"),
        arg_str0(NULL, "created", "<YYYY-MM-DDTHH:mm>", "Card Creation Date"),
        arg_u64_0(NULL, "prop_id", "<decimal>", "Property ID"),
        arg_str1("d", NULL, "data", "Unencrypted 17 byte card data"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);


    uint8_t user_saflokdata[17];
    uint8_t rsaflokdata[17];
    uint8_t esaflokdata[17] = {0};

    int dlen;
    CLIGetHexWithReturn(ctx, 13, user_saflokdata, &dlen);

    if (dlen != 17) {
        PrintAndLogEx(WARNING, "block data must include 17 HEX bytes. Got %i", dlen);
        return PM3_EINVARG;
    }

    saflok_decrypt(user_saflokdata, 17, rsaflokdata);

    uint32_t card_level = extract_bits(rsaflokdata, 0, 4);
    card_level = arg_get_u32_def(ctx, 1, card_level);

    uint32_t card_type = extract_bits(rsaflokdata, 4, 4);
    card_type = arg_get_u32_def(ctx, 2, card_type);

    uint32_t card_id = extract_bits(rsaflokdata, 8, 8);
    card_id = arg_get_u32_def(ctx, 3, card_id);

    uint32_t opening_key = extract_bits(rsaflokdata, 16, 2);
    opening_key = arg_get_u32_def(ctx, 4, opening_key);

    uint32_t lock_id = extract_bits(rsaflokdata, 18, 14);
    lock_id = arg_get_u32_def(ctx, 5, lock_id);

    uint32_t pass_number = extract_bits(rsaflokdata, 32, 12);
    pass_number = arg_get_u32_def(ctx, 6, pass_number);

    uint32_t sequence_and_combination = extract_bits(rsaflokdata, 44, 12);
    sequence_and_combination = arg_get_u32_def(ctx, 7, sequence_and_combination);

    uint32_t deadbolt_override = extract_bits(rsaflokdata, 56, 1);
    deadbolt_override = arg_get_u32_def(ctx, 8, deadbolt_override);

    uint32_t restricted_days = extract_bits(rsaflokdata, 57, 7);
    restricted_days = arg_get_u32_def(ctx, 9, restricted_days);

    uint32_t expire_date = extract_bits(rsaflokdata, 64, 24);
    //expire_date = arg_get_u32_def(ctx, 10, expire_date);

    uint32_t card_creation_date = extract_bits(rsaflokdata, 88, 28);
    //card_creation_date = arg_get_u32_def(ctx, 11, card_creation_date);

    uint32_t property_id = extract_bits(rsaflokdata, 116, 12);
    property_id = arg_get_u32_def(ctx, 12, property_id);

    int slen = 0;
    char dt[100];
    CLIParamStrToBuf(arg_get_str(ctx, 11), (uint8_t *)dt, 100, &slen);

    int slen2 = 0;
    char dt_e[100];
    CLIParamStrToBuf(arg_get_str(ctx, 10), (uint8_t *)dt_e, 100, &slen2);

    saflok_encode(rsaflokdata,
                  card_level,
                  card_type,
                  card_id,
                  opening_key,
                  lock_id,
                  pass_number,
                  sequence_and_combination,
                  deadbolt_override,
                  restricted_days,
                  expire_date,
                  card_creation_date,
                  property_id,
                  dt_e,
                  dt);


    saflok_encrypt(rsaflokdata, 17, esaflokdata);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Modified Card Data"));
    PrintAndLogEx(SUCCESS, "Encrypted Data: " _GREEN_("%s"), bytes_to_hex(esaflokdata, 17));


    CLIParserFree(ctx);
    return PM3_SUCCESS;
}


static int CmdHFSaflokEncrypt(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf saflok encrypt",
                  "Encrypt a 17-byte Saflok block",
                  "hf saflok encrypt -d <17 byte hex>");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", NULL, "data", "17-byte unencrypted hex block"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t raw[17], encrypted[17];
    int len;
    CLIGetHexWithReturn(ctx, 1, raw, &len);

    if (len != 17) {
        PrintAndLogEx(WARNING, "Expected 17 bytes. Got %d.", len);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    saflok_encrypt(raw, 17, encrypted);
    PrintAndLogEx(SUCCESS, "Encrypted: " _GREEN_("%s"), bytes_to_hex(encrypted, 17));

    CLIParserFree(ctx);
    return PM3_SUCCESS;
}

static int CmdHFSaflokDecrypt(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf saflok decrypt",
                  "Decrypt a 17-byte Saflok block",
                  "hf saflok decrypt -d <17 byte hex>");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", NULL, "data", "17-byte encrypted hex block"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t encrypted[17], decrypted[17];
    int len;
    CLIGetHexWithReturn(ctx, 1, encrypted, &len);

    if (len != 17) {
        PrintAndLogEx(WARNING, "Expected 17 bytes. Got %d.", len);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    saflok_decrypt(encrypted, 17, decrypted);
    PrintAndLogEx(SUCCESS, "Decrypted: " _GREEN_("%s"), bytes_to_hex(decrypted, 17));

    CLIParserFree(ctx);
    return PM3_SUCCESS;
}

static int CmdHFSaflokChecksum(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf saflok cksum",
                  "Generate Saflok checksum and append to block",
                  "hf saflok cksum -d <16 byte hex>");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", NULL, "data", "16-byte decrypted Saflok block"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t data[17];
    int len;
    CLIGetHexWithReturn(ctx, 1, data, &len);

    if (len != 16) {
        PrintAndLogEx(WARNING, "Expected 16 bytes. Got %d.", len);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    data[16] = saflok_checksum(data, 16);

    PrintAndLogEx(SUCCESS, "Block + checksum: " _GREEN_("%s"), bytes_to_hex(data, 17));
    PrintAndLogEx(SUCCESS, "Checksum byte: " _GREEN_("0x%02X"), data[16]);

    CLIParserFree(ctx);
    return PM3_SUCCESS;
}

static int CmdHFSaflokProvision(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf saflok provision",
                  "Provision a Saflok card",
                  "hf saflok provision -d <17-byte encrypted hex block>");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", NULL, "data", "17-byte block"),
        arg_param_end,
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t data[17];
    int len;
    CLIGetHexWithReturn(ctx, 1, data, &len);

    if (len != 17) {
        PrintAndLogEx(WARNING, "Expected 17 bytes, got %d", len);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t uid[8];
    int uid_len;
    if (mf_read_uid(uid, &uid_len, NULL) != PM3_SUCCESS || uid_len < 4) {
        PrintAndLogEx(WARNING, "Failed to read UID from card.");
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    uint8_t keyA[6];
    saflok_kdf(uid, keyA);
    PrintAndLogEx(INFO, "Generated UID-derived key: " _GREEN_("%s"), bytes_to_hex(keyA, 6));

    uint8_t all_F[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t block1[16];
    uint8_t block2[16] = {0};
    memcpy(block1, data, 16);
    block2[0] = data[16];
    block2[1] = 0x00;
    block2[2] = 0x04;
    block2[3] = 0x00;
    block2[4] = 0x01;

    bool write_success = mf_write_block(1, 0, keyA, block1) == PM3_SUCCESS &&
                         mf_write_block(2, 0, keyA, block2) == PM3_SUCCESS;

    uint8_t trailer0[16] = {0};
    uint8_t set_keys = 0;
    if (!write_success) {
        PrintAndLogEx(WARNING, "Initial write failed. Attempting to set sector 0 keys...");

        memcpy(trailer0, keyA, 6);
        trailer0[6] = 0xFF;
        trailer0[7] = 0x07;
        trailer0[8] = 0x80;
        trailer0[9] = 0x69;
        memcpy(trailer0 + 10, all_F, 6);

        if (mf_write_block(3, 1, all_F, trailer0) != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "Failed to set key in sector 0. Try wiping the card first.");
            CLIParserFree(ctx);
            return PM3_ESOFT;
        }

        write_success = mf_write_block(1, 0, keyA, block1) == PM3_SUCCESS &&
                        mf_write_block(2, 0, keyA, block2) == PM3_SUCCESS;
        if (!write_success) {
            PrintAndLogEx(WARNING, "Write still failed after setting keys.");
            CLIParserFree(ctx);
            return PM3_ESOFT;
        }
        set_keys = 1;
    }

    if (set_keys) {
        uint8_t trailer7[16] = {
            0x2A, 0x2C, 0x13, 0xCC, 0x24, 0x2A,
            0xFF, 0x07, 0x80, 0x69,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        };
        if (mf_write_block(7, 0, all_F, trailer7) != PM3_SUCCESS) {
            //PrintAndLogEx(WARNING, "Failed to write trailer block 7.");
        }

        for (int block = 19; block <= 63; block += 4) {
            if (mf_write_block(block, 0, all_F, trailer0) != PM3_SUCCESS) {
                //PrintAndLogEx(WARNING, "Failed to write trailer at block %d", block);
            }
        }
    }
    PrintAndLogEx(SUCCESS, "Saflok card provisioned successfully.");
    CLIParserFree(ctx);
    return PM3_SUCCESS;
}

static int CmdHFSaflokInterrogate(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf saflok interrogate",
                  "Interrogate Saflok card",
                  "hf saflok interrogate");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end,
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    uint8_t uid[8];
    int uid_len;

    if (mf_read_uid(uid, &uid_len, NULL) != PM3_SUCCESS || uid_len < 4) {
        PrintAndLogEx(WARNING, "Failed to read UID.");
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    uint8_t key[6];
    saflok_kdf(uid, key);

    uint8_t block2[16];
    if (mf_read_block(2, 0, key, block2) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Failed to read block 2 with derived key.");
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    uint8_t control_byte = block2[5];
    uint8_t subblock_stop = (control_byte >> 3);
    if (subblock_stop == 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t buffer[512] = {0};
    int current_block = 16;
    int total_bytes = 0;

    while (1) {
        int current_subblocks = (current_block - 16) * 2;
        if (current_subblocks >= subblock_stop) break;

        if (current_block % 4 == 3) {
            current_block++;
            continue;
        }

        if (mf_read_block(current_block, 0, key, buffer + total_bytes) != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "Failed to read block %d", current_block);
            break;
        }

        total_bytes += 16;
        current_block++;

    }

    if (subblock_stop % 2 != 0) {
        total_bytes -= 8;
    }

    if (total_bytes > 0) {
        PrintAndLogEx(SUCCESS, "Card has variable keys to the following locks:");
    } else {
        PrintAndLogEx(SUCCESS, "Card has no variable keys");
    }
    int cursor = 0;

    while (cursor + 6 <= total_bytes) {
        uint8_t val = buffer[cursor + 1];
        if (val != 0) {
            PrintAndLogEx(SUCCESS, "%u", val);
        }
        cursor += 6;
    }

    CLIParserFree(ctx);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,            AlwaysAvailable, "This help"},
    {"read",  CmdHFSaflokRead,  IfPm3NfcBarcode, "Read Saflok card"},
    {"provision",  CmdHFSaflokProvision,  IfPm3NfcBarcode, "Provision Saflok card"},
    {"encode",  CmdHFSaflokEncode,  AlwaysAvailable, "Encode Saflok card data"},
    {"decode",  CmdHFSaflokDecode,  AlwaysAvailable, "Decode Saflok card data"},
    {"modify",  CmdHFSaflokModify,  AlwaysAvailable, "Modify Saflok card data"},
    {"encrypt", CmdHFSaflokEncrypt, AlwaysAvailable, "Encrypt 17-byte decrypted block"},
    {"decrypt", CmdHFSaflokDecrypt, AlwaysAvailable, "Decrypt 17-byte encrypted block"},
    {"interrogate", CmdHFSaflokInterrogate, IfPm3NfcBarcode, "Interrogate saflok card"},
    {"cksum",   CmdHFSaflokChecksum, IfPm3NfcBarcode, "Generate checksum for data block"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd;
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFSaflok(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

