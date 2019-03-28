//-----------------------------------------------------------------------------
// Ultralight Code (c) 2013,2014 Midnitesnake & Andy Davies of Pentura
// 2015,2016,2017 Iceman, Marshmellow
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency MIFARE ULTRALIGHT (C) commands
//-----------------------------------------------------------------------------
#include "cmdhfmfu.h"

#define MAX_UL_BLOCKS       0x0F
#define MAX_ULC_BLOCKS      0x2B
#define MAX_ULEV1a_BLOCKS   0x13
#define MAX_ULEV1b_BLOCKS   0x28
#define MAX_NTAG_203        0x29
#define MAX_NTAG_210        0x13
#define MAX_NTAG_212        0x28
#define MAX_NTAG_213        0x2C
#define MAX_NTAG_215        0x86
#define MAX_NTAG_216        0xE6
#define MAX_MY_D_NFC        0xFF
#define MAX_MY_D_MOVE       0x25
#define MAX_MY_D_MOVE_LEAN  0x0F
#define MAX_UL_NANO_40      0x0A

static int CmdHelp(const char *Cmd);

#define PUBLIC_ECDA_KEYLEN 33
uint8_t public_ecda_key[PUBLIC_ECDA_KEYLEN] = {
    0x04, 0x49, 0x4e, 0x1a, 0x38, 0x6d, 0x3d, 0x3c,
    0xfe, 0x3d, 0xc1, 0x0e, 0x5d, 0xe6, 0x8a, 0x49,
    0x9b, 0x1c, 0x20, 0x2d, 0xb5, 0xb1, 0x32, 0x39,
    0x3e, 0x89, 0xed, 0x19, 0xfe, 0x5b, 0xe8, 0xbc,
    0x61
};

#define KEYS_3DES_COUNT 7
uint8_t default_3des_keys[KEYS_3DES_COUNT][16] = {
    { 0x42, 0x52, 0x45, 0x41, 0x4b, 0x4d, 0x45, 0x49, 0x46, 0x59, 0x4f, 0x55, 0x43, 0x41, 0x4e, 0x21 }, // 3des std key
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // all zeroes
    { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }, // 0x00-0x0F
    { 0x49, 0x45, 0x4D, 0x4B, 0x41, 0x45, 0x52, 0x42, 0x21, 0x4E, 0x41, 0x43, 0x55, 0x4F, 0x59, 0x46 }, // NFC-key
    { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 }, // all ones
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, // all FF
    { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF } // 11 22 33
};

#define KEYS_PWD_COUNT 1
uint8_t default_pwd_pack[KEYS_PWD_COUNT][4] = {
    {0xFF, 0xFF, 0xFF, 0xFF}, // PACK 0x00,0x00 -- factory default
};

#define MAX_UL_TYPES 22
uint32_t UL_TYPES_ARRAY[MAX_UL_TYPES] = {
    UNKNOWN,   UL,          UL_C,        UL_EV1_48,       UL_EV1_128,      NTAG,
    NTAG_203,  NTAG_210,    NTAG_212,    NTAG_213,        NTAG_215,        NTAG_216,
    MY_D,      MY_D_NFC,    MY_D_MOVE,   MY_D_MOVE_NFC,   MY_D_MOVE_LEAN,  FUDAN_UL,
    UL_EV1,    NTAG_213_F,  NTAG_216_F,  UL_NANO_40
};

uint8_t UL_MEMORY_ARRAY[MAX_UL_TYPES] = {
    MAX_UL_BLOCKS,     MAX_UL_BLOCKS, MAX_ULC_BLOCKS, MAX_ULEV1a_BLOCKS, MAX_ULEV1b_BLOCKS,  MAX_NTAG_203,
    MAX_NTAG_203,      MAX_NTAG_210,  MAX_NTAG_212,   MAX_NTAG_213,      MAX_NTAG_215,       MAX_NTAG_216,
    MAX_UL_BLOCKS,     MAX_MY_D_NFC,  MAX_MY_D_MOVE,  MAX_MY_D_MOVE,     MAX_MY_D_MOVE_LEAN, MAX_UL_BLOCKS,
    MAX_ULEV1a_BLOCKS, MAX_NTAG_213,  MAX_NTAG_216,   MAX_UL_NANO_40
};

//------------------------------------
// Pwd & Pack generation Stuff
//------------------------------------
const uint32_t c_D[] = {
    0x6D835AFC, 0x7D15CD97, 0x0942B409, 0x32F9C923, 0xA811FB02, 0x64F121E8,
    0xD1CC8B4E, 0xE8873E6F, 0x61399BBB, 0xF1B91926, 0xAC661520, 0xA21A31C9,
    0xD424808D, 0xFE118E07, 0xD18E728D, 0xABAC9E17, 0x18066433, 0x00E18E79,
    0x65A77305, 0x5AE9E297, 0x11FC628C, 0x7BB3431F, 0x942A8308, 0xB2F8FD20,
    0x5728B869, 0x30726D5A
};

void transform_D(uint8_t *ru) {
    //Transform
    uint8_t i;
    uint8_t p = 0;
    uint32_t v1 = ((ru[3] << 24) | (ru[2] << 16) | (ru[1] << 8) | ru[0]) + c_D[p++];
    uint32_t v2 = ((ru[7] << 24) | (ru[6] << 16) | (ru[5] << 8) | ru[4]) + c_D[p++];
    for (i = 0; i < 12; i += 2) {

        uint32_t xor1 = v1 ^ v2;
        uint32_t t1 = ROTL(xor1, v2 & 0x1F) + c_D[p++];
        uint32_t xor2 = v2 ^ t1;
        uint32_t t2 = ROTL(xor2, t1 & 0x1F) + c_D[p++];
        uint32_t xor3 = t1 ^ t2;
        uint32_t xor4 = t2 ^ v1;
        v1 = ROTL(xor3, t2 & 0x1F) + c_D[p++];
        v2 = ROTL(xor4, v1 & 0x1F) + c_D[p++];
    }

    //Re-use ru
    ru[0] = v1 & 0xFF;
    ru[1] = (v1 >> 8) & 0xFF;
    ru[2] = (v1 >> 16) & 0xFF;
    ru[3] = (v1 >> 24) & 0xFF;
    ru[4] = v2 & 0xFF;
    ru[5] = (v2 >> 8) & 0xFF;
    ru[6] = (v2 >> 16) & 0xFF;
    ru[7] = (v2 >> 24) & 0xFF;
}

// Certain pwd generation algo nickname A.
uint32_t ul_ev1_pwdgenA(uint8_t *uid) {

    uint8_t pos = (uid[3] ^ uid[4] ^ uid[5] ^ uid[6]) % 32;

    uint32_t xortable[] = {
        0x4f2711c1, 0x07D7BB83, 0x9636EF07, 0xB5F4460E, 0xF271141C, 0x7D7BB038, 0x636EF871, 0x5F4468E3,
        0x271149C7, 0xD7BB0B8F, 0x36EF8F1E, 0xF446863D, 0x7114947A, 0x7BB0B0F5, 0x6EF8F9EB, 0x44686BD7,
        0x11494fAF, 0xBB0B075F, 0xEF8F96BE, 0x4686B57C, 0x1494F2F9, 0xB0B07DF3, 0xF8F963E6, 0x686B5FCC,
        0x494F2799, 0x0B07D733, 0x8F963667, 0x86B5F4CE, 0x94F2719C, 0xB07D7B38, 0xF9636E70, 0x6B5F44E0
    };

    uint8_t entry[] = {0x00, 0x00, 0x00, 0x00};
    uint8_t pwd[] = {0x00, 0x00, 0x00, 0x00};

    num_to_bytes(xortable[pos], 4, entry);

    pwd[0] = entry[0] ^ uid[1] ^ uid[2] ^ uid[3];
    pwd[1] = entry[1] ^ uid[0] ^ uid[2] ^ uid[4];
    pwd[2] = entry[2] ^ uid[0] ^ uid[1] ^ uid[5];
    pwd[3] = entry[3] ^ uid[6];

    return (uint32_t)bytes_to_num(pwd, 4);
}

// Certain pwd generation algo nickname B. (very simple)
uint32_t ul_ev1_pwdgenB(uint8_t *uid) {

    uint8_t pwd[] = {0x00, 0x00, 0x00, 0x00};

    pwd[0] = uid[1] ^ uid[3] ^ 0xAA;
    pwd[1] = uid[2] ^ uid[4] ^ 0x55;
    pwd[2] = uid[3] ^ uid[5] ^ 0xAA;
    pwd[3] = uid[4] ^ uid[6] ^ 0x55;
    return (uint32_t)bytes_to_num(pwd, 4);
}

// Certain pwd generation algo nickname C.
uint32_t ul_ev1_pwdgenC(uint8_t *uid) {
    uint32_t pwd = 0;
    uint8_t base[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x28,
        0x63, 0x29, 0x20, 0x43, 0x6f, 0x70, 0x79, 0x72,
        0x69, 0x67, 0x68, 0x74, 0x20, 0x4c, 0x45, 0x47,
        0x4f, 0x20, 0x32, 0x30, 0x31, 0x34, 0xaa, 0xaa
    };

    memcpy(base, uid, 7);

    for (int i = 0; i < 32; i += 4) {
        uint32_t b = *(uint32_t *)(base + i);
        pwd = b + ROTR(pwd, 25) + ROTR(pwd, 10) - pwd;
    }
    return BSWAP_32(pwd);
}
// Certain pwd generation algo nickname D.
// a.k.a xzy
uint32_t ul_ev1_pwdgenD(uint8_t *uid) {
    uint8_t i;
    //Rotate
    uint8_t r = (uid[1] + uid[3] + uid[5]) & 7; //Rotation offset
    uint8_t ru[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; //Rotated UID
    for (i = 0; i < 7; i++)
        ru[(i + r) & 7] = uid[i];

    transform_D(ru);

    //Calc key
    uint32_t pwd = 0; //Key as int
    r = (ru[0] + ru[2] + ru[4] + ru[6]) & 3; //Offset
    for (i = 0; i < 4; i++)
        pwd = ru[i + r] + (pwd << 8);

    return BSWAP_32(pwd);
}
// pack generation for algo 1-3
uint16_t ul_ev1_packgenA(uint8_t *uid) {
    uint16_t pack = (uid[0] ^ uid[1] ^ uid[2]) << 8 | (uid[2] ^ 8);
    return pack;
}
uint16_t ul_ev1_packgenB(uint8_t *uid) {
    return 0x8080;
}
uint16_t ul_ev1_packgenC(uint8_t *uid) {
    return 0xaa55;
}
uint16_t ul_ev1_packgenD(uint8_t *uid) {
    uint8_t i;
    //Rotate
    uint8_t r = (uid[2] + uid[5]) & 7; //Rotation offset
    uint8_t ru[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; //Rotated UID
    for (i = 0; i < 7; i++)
        ru[(i + r) & 7] = uid[i];

    transform_D(ru);

    //Calc pack
    uint32_t p = 0;
    for (i = 0; i < 8; i++)
        p += ru[i] * 13;

    p ^= 0x5555;
    return BSWAP_16(p & 0xFFFF);
}

int ul_ev1_pwdgen_selftest() {

    uint8_t uid1[] = {0x04, 0x11, 0x12, 0x11, 0x12, 0x11, 0x10};
    uint32_t pwd1 = ul_ev1_pwdgenA(uid1);
    PrintAndLogEx(NORMAL, "UID | %s | %08X | %s", sprint_hex(uid1, 7), pwd1, (pwd1 == 0x8432EB17) ? "OK" : "->8432EB17<-");

    uint8_t uid2[] = {0x04, 0x1f, 0x98, 0xea, 0x1e, 0x3e, 0x81};
    uint32_t pwd2 = ul_ev1_pwdgenB(uid2);
    PrintAndLogEx(NORMAL, "UID | %s | %08X | %s", sprint_hex(uid2, 7), pwd2, (pwd2 == 0x5fd37eca) ? "OK" : "->5fd37eca<--");

    uint8_t uid3[] = {0x04, 0x62, 0xB6, 0x8A, 0xB4, 0x42, 0x80};
    uint32_t pwd3 = ul_ev1_pwdgenC(uid3);
    PrintAndLogEx(NORMAL, "UID | %s | %08X | %s", sprint_hex(uid3, 7), pwd3, (pwd3 == 0x5a349515) ? "OK" : "->5a349515<--");

    uint8_t uid4[] = {0x04, 0xC5, 0xDF, 0x4A, 0x6D, 0x51, 0x80};
    uint32_t pwd4 = ul_ev1_pwdgenD(uid4);
    PrintAndLogEx(NORMAL, "UID | %s | %08X | %s", sprint_hex(uid4, 7), pwd4, (pwd4 == 0x72B1EC61) ? "OK" : "->72B1EC61<--");
    return 0;
}

//------------------------------------
// get version nxp product type
char *getProductTypeStr(uint8_t id) {

    static char buf[20];
    char *retStr = buf;

    switch (id) {
        case 3:
            sprintf(retStr, "%02X, Ultralight", id);
            break;
        case 4:
            sprintf(retStr, "%02X, NTAG", id);
            break;
        default:
            sprintf(retStr, "%02X, unknown", id);
            break;
    }
    return buf;
}

/*
  The 7 MSBits (=n) code the storage size itself based on 2^n,
  the LSBit is set to '0' if the size is exactly 2^n
  and set to '1' if the storage size is between 2^n and 2^(n+1).
*/
char *getUlev1CardSizeStr(uint8_t fsize) {

    static char buf[40];
    char *retStr = buf;
    memset(buf, 0, sizeof(buf));

    uint16_t usize = 1 << ((fsize >> 1) + 1);
    uint16_t lsize = 1 << (fsize >> 1);

    // is  LSB set?
    if (fsize & 1)
        sprintf(retStr, "%02X, (%u <-> %u bytes)", fsize, usize, lsize);
    else
        sprintf(retStr, "%02X, (%u bytes)", fsize, lsize);
    return buf;
}

static void ul_switch_on_field(void) {
    UsbCommand c = {CMD_READER_ISO_14443a, {ISO14A_CONNECT | ISO14A_NO_DISCONNECT | ISO14A_NO_RATS, 0, 0}};
    clearCommandBuffer();
    SendCommand(&c);
}

static int ul_send_cmd_raw(uint8_t *cmd, uint8_t cmdlen, uint8_t *response, uint16_t responseLength) {
    UsbCommand c = {CMD_READER_ISO_14443a, {ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_APPEND_CRC | ISO14A_NO_RATS, cmdlen, 0}};
    memcpy(c.d.asBytes, cmd, cmdlen);
    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) return -1;
    if (!resp.arg[0] && responseLength) return -1;

    uint16_t resplen = (resp.arg[0] < responseLength) ? resp.arg[0] : responseLength;
    memcpy(response, resp.d.asBytes, resplen);
    return resplen;
}

static int ul_select(iso14a_card_select_t *card) {

    ul_switch_on_field();

    UsbCommand resp;
    bool ans = false;
    ans = WaitForResponseTimeout(CMD_ACK, &resp, 1500);

    if (!ans || resp.arg[0] < 1) {
        PrintAndLogEx(WARNING, "iso14443a card select failed");
        DropField();
        return 0;
    }

    memcpy(card, resp.d.asBytes, sizeof(iso14a_card_select_t));
    return 1;
}

// This read command will at least return 16bytes.
static int ul_read(uint8_t page, uint8_t *response, uint16_t responseLength) {

    uint8_t cmd[] = {ISO14443A_CMD_READBLOCK, page};
    int len = ul_send_cmd_raw(cmd, sizeof(cmd), response, responseLength);
    return len;
}

static int ul_comp_write(uint8_t page, uint8_t *data, uint8_t datalen) {

    if (data == NULL)
        return -1;

    uint8_t cmd[18];
    memset(cmd, 0x00, sizeof(cmd));
    datalen = (datalen > 16) ? 16 : datalen;

    cmd[0] = ISO14443A_CMD_WRITEBLOCK;
    cmd[1] = page;
    memcpy(cmd + 2, data, datalen);

    uint8_t response[1] = {0xFF};
    ul_send_cmd_raw(cmd, 2 + datalen, response, sizeof(response));
    // ACK
    if (response[0] == 0x0a) return 0;
    // NACK
    return -1;
}

static int ulc_requestAuthentication(uint8_t *nonce, uint16_t nonceLength) {

    uint8_t cmd[] = {MIFARE_ULC_AUTH_1, 0x00};
    int len = ul_send_cmd_raw(cmd, sizeof(cmd), nonce, nonceLength);
    return len;
}

static int ulc_authentication(uint8_t *key, bool switch_off_field) {

    UsbCommand c = {CMD_MIFAREUC_AUTH, {switch_off_field}};
    memcpy(c.d.asBytes, key, 16);
    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) return 0;
    if (resp.arg[0] == 1) return 1;

    return 0;
}

static int ulev1_requestAuthentication(uint8_t *pwd, uint8_t *pack, uint16_t packLength) {

    uint8_t cmd[] = {MIFARE_ULEV1_AUTH, pwd[0], pwd[1], pwd[2], pwd[3]};
    int len = ul_send_cmd_raw(cmd, sizeof(cmd), pack, packLength);
    // NACK tables different tags,  but between 0-9 is a NEGATIVE response.
    // ACK == 0xA
    if (len == 1 && pack[0] <= 0x09)
        return -1;
    return len;
}

static int ul_auth_select(iso14a_card_select_t *card, TagTypeUL_t tagtype, bool hasAuthKey, uint8_t *authkey, uint8_t *pack, uint8_t packSize) {
    if (hasAuthKey && (tagtype & UL_C)) {
        //will select card automatically and close connection on error
        if (!ulc_authentication(authkey, false)) {
            PrintAndLogEx(WARNING, "Authentication Failed UL-C");
            return 0;
        }
    } else {
        if (!ul_select(card)) return 0;

        if (hasAuthKey) {
            if (ulev1_requestAuthentication(authkey, pack, packSize) == -1) {
                DropField();
                PrintAndLogEx(WARNING, "Authentication Failed UL-EV1/NTAG");
                return 0;
            }
        }
    }
    return 1;
}

static int ulev1_getVersion(uint8_t *response, uint16_t responseLength) {
    uint8_t cmd[] = {MIFARE_ULEV1_VERSION};
    int len = ul_send_cmd_raw(cmd, sizeof(cmd), response, responseLength);
    return len;
}

static int ulev1_readCounter(uint8_t counter, uint8_t *response, uint16_t responseLength) {

    uint8_t cmd[] = {MIFARE_ULEV1_READ_CNT, counter};
    int len = ul_send_cmd_raw(cmd, sizeof(cmd), response, responseLength);
    return len;
}

static int ulev1_readTearing(uint8_t counter, uint8_t *response, uint16_t responseLength) {

    uint8_t cmd[] = {MIFARE_ULEV1_CHECKTEAR, counter};
    int len = ul_send_cmd_raw(cmd, sizeof(cmd), response, responseLength);
    return len;
}

static int ulev1_readSignature(uint8_t *response, uint16_t responseLength) {

    uint8_t cmd[] = {MIFARE_ULEV1_READSIG, 0x00};
    int len = ul_send_cmd_raw(cmd, sizeof(cmd), response, responseLength);
    return len;
}

// Fudan check checks for which error is given for a command with incorrect crc
// NXP UL chip responds with 01, fudan 00.
// other possible checks:
//  send a0 + crc
//  UL responds with 00, fudan doesn't respond
//  or
//  send a200 + crc
//  UL doesn't respond, fudan responds with 00
//  or
//  send 300000 + crc (read with extra byte(s))
//  UL responds with read of page 0, fudan doesn't respond.
//
// make sure field is off before calling this function
static int ul_fudan_check(void) {
    iso14a_card_select_t card;
    if (!ul_select(&card))
        return UL_ERROR;

    UsbCommand c = {CMD_READER_ISO_14443a, {ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_NO_RATS, 4, 0}};

    uint8_t cmd[4] = {0x30, 0x00, 0x02, 0xa7}; //wrong crc on purpose  should be 0xa8
    memcpy(c.d.asBytes, cmd, 4);
    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) return UL_ERROR;
    if (resp.arg[0] != 1) return UL_ERROR;

    return (!resp.d.asBytes[0]) ? FUDAN_UL : UL; //if response == 0x00 then Fudan, else Genuine NXP
}

static int ul_print_default(uint8_t *data) {

    uint8_t uid[7];
    uid[0] = data[0];
    uid[1] = data[1];
    uid[2] = data[2];
    uid[3] = data[4];
    uid[4] = data[5];
    uid[5] = data[6];
    uid[6] = data[7];

    PrintAndLogEx(NORMAL, "       UID : %s ", sprint_hex(uid, 7));
    PrintAndLogEx(NORMAL, "    UID[0] : %02X, %s",  uid[0], getTagInfo(uid[0]));
    if (uid[0] == 0x05 && ((uid[1] & 0xf0) >> 4) == 2) {   // is infineon and 66RxxP
        uint8_t chip = (data[8] & 0xC7); // 11000111  mask, bit 3,4,5 RFU
        switch (chip) {
            case 0xc2:
                PrintAndLogEx(NORMAL, "   IC type : SLE 66R04P 770 Bytes");
                break; //77 pages
            case 0xc4:
                PrintAndLogEx(NORMAL, "   IC type : SLE 66R16P 2560 Bytes");
                break; //256 pages
            case 0xc6:
                PrintAndLogEx(NORMAL, "   IC type : SLE 66R32P 5120 Bytes");
                break; //512 pages /2 sectors
        }
    }
    // CT (cascade tag byte) 0x88 xor SN0 xor SN1 xor SN2
    int crc0 = 0x88 ^ data[0] ^ data[1] ^ data[2];
    if (data[3] == crc0)
        PrintAndLogEx(NORMAL, "      BCC0 : %02X, Ok", data[3]);
    else
        PrintAndLogEx(NORMAL, "      BCC0 : %02X, crc should be %02X", data[3], crc0);

    int crc1 = data[4] ^ data[5] ^ data[6] ^ data[7];
    if (data[8] == crc1)
        PrintAndLogEx(NORMAL, "      BCC1 : %02X, Ok", data[8]);
    else
        PrintAndLogEx(NORMAL, "      BCC1 : %02X, crc should be %02X", data[8], crc1);

    PrintAndLogEx(NORMAL, "  Internal : %02X, %sdefault", data[9], (data[9] == 0x48) ? "" : "not ");

    PrintAndLogEx(NORMAL, "      Lock : %s - %s",
                  sprint_hex(data + 10, 2),
                  sprint_bin(data + 10, 2)
                 );

    PrintAndLogEx(NORMAL, "OneTimePad : %s - %s\n",
                  sprint_hex(data + 12, 4),
                  sprint_bin(data + 12, 4)
                 );

    return 0;
}

static int ndef_print_CC(uint8_t *data) {
    // no NDEF message
    if (data[0] != 0xE1)
        return -1;

    PrintAndLogEx(NORMAL, "--- NDEF Message");
    PrintAndLogEx(NORMAL, "Capability Container: %s", sprint_hex(data, 4));
    PrintAndLogEx(NORMAL, "  %02X : NDEF Magic Number", data[0]);
    PrintAndLogEx(NORMAL, "  %02X : version %d.%d supported by tag", data[1], (data[1] & 0xF0) >> 4, data[1] & 0x0F);
    PrintAndLogEx(NORMAL, "  %02X : Physical Memory Size: %d bytes", data[2], (data[2] + 1) * 8);
    if (data[2] == 0x96)
        PrintAndLogEx(NORMAL, "  %02X : NDEF Memory Size: %d bytes", data[2], 48);
    else if (data[2] == 0x12)
        PrintAndLogEx(NORMAL, "  %02X : NDEF Memory Size: %d bytes", data[2], 144);
    else if (data[2] == 0x3E)
        PrintAndLogEx(NORMAL, "  %02X : NDEF Memory Size: %d bytes", data[2], 496);
    else if (data[2] == 0x6D)
        PrintAndLogEx(NORMAL, "  %02X : NDEF Memory Size: %d bytes", data[2], 872);

    PrintAndLogEx(NORMAL, "  %02X : %s / %s", data[3],
                  (data[3] & 0xF0) ? "(RFU)" : "Read access granted without any security",
                  (data[3] & 0x0F) == 0 ? "Write access granted without any security" : (data[3] & 0x0F) == 0x0F ? "No write access granted at all" : "(RFU)");
    return 0;
}

int ul_print_type(uint32_t tagtype, uint8_t spaces) {
    char spc[11] = "          ";
    spc[10] = 0x00;
    char *spacer = spc + (10 - spaces);

    if (tagtype & UL)
        PrintAndLogEx(NORMAL, "%sTYPE : MIFARE Ultralight (MF0ICU1) %s", spacer, (tagtype & MAGIC) ? "<magic>" : "");
    else if (tagtype & UL_C)
        PrintAndLogEx(NORMAL, "%sTYPE : MIFARE Ultralight C (MF0ULC) %s", spacer, (tagtype & MAGIC) ? "<magic>" : "");
    else if (tagtype & UL_NANO_40)
        PrintAndLogEx(NORMAL, "%sTYPE : MIFARE Ultralight Nano 40bytes (MF0UNH00)", spacer);
    else if (tagtype & UL_EV1_48)
        PrintAndLogEx(NORMAL, "%sTYPE : MIFARE Ultralight EV1 48bytes (MF0UL1101)", spacer);
    else if (tagtype & UL_EV1_128)
        PrintAndLogEx(NORMAL, "%sTYPE : MIFARE Ultralight EV1 128bytes (MF0UL2101)", spacer);
    else if (tagtype & UL_EV1)
        PrintAndLogEx(NORMAL, "%sTYPE : MIFARE Ultralight EV1 UNKNOWN", spacer);
    else if (tagtype & NTAG)
        PrintAndLogEx(NORMAL, "%sTYPE : NTAG UNKNOWN", spacer);
    else if (tagtype & NTAG_203)
        PrintAndLogEx(NORMAL, "%sTYPE : NTAG 203 144bytes (NT2H0301F0DT)", spacer);
    else if (tagtype & NTAG_210)
        PrintAndLogEx(NORMAL, "%sTYPE : NTAG 210 48bytes (NT2L1011G0DU)", spacer);
    else if (tagtype & NTAG_212)
        PrintAndLogEx(NORMAL, "%sTYPE : NTAG 212 128bytes (NT2L1211G0DU)", spacer);
    else if (tagtype & NTAG_213)
        PrintAndLogEx(NORMAL, "%sTYPE : NTAG 213 144bytes (NT2H1311G0DU)", spacer);
    else if (tagtype & NTAG_213_F)
        PrintAndLogEx(NORMAL, "%sTYPE : NTAG 213F 144bytes (NT2H1311F0DTL)", spacer);
    else if (tagtype & NTAG_215)
        PrintAndLogEx(NORMAL, "%sTYPE : NTAG 215 504bytes (NT2H1511G0DU)", spacer);
    else if (tagtype & NTAG_216)
        PrintAndLogEx(NORMAL, "%sTYPE : NTAG 216 888bytes (NT2H1611G0DU)", spacer);
    else if (tagtype & NTAG_216_F)
        PrintAndLogEx(NORMAL, "%sTYPE : NTAG 216F 888bytes (NT2H1611F0DTL)", spacer);
    else if (tagtype & NTAG_I2C_1K)
        PrintAndLogEx(NORMAL, "%sTYPE : NTAG I%sC 888bytes (NT3H1101FHK)", spacer, "\xFD");
    else if (tagtype & NTAG_I2C_2K)
        PrintAndLogEx(NORMAL, "%sTYPE : NTAG I%sC 1904bytes (NT3H1201FHK)", spacer, "\xFD");
    else if (tagtype & NTAG_I2C_1K_PLUS)
        PrintAndLogEx(NORMAL, "%sTYPE : NTAG I%sC plus 888bytes (NT3H2111FHK)", spacer, "\xFD");
    else if (tagtype & NTAG_I2C_2K_PLUS)
        PrintAndLogEx(NORMAL, "%sTYPE : NTAG I%sC plus 1912bytes (NT3H2211FHK)", spacer, "\xFD");
    else if (tagtype & MY_D)
        PrintAndLogEx(NORMAL, "%sTYPE : INFINEON my-d\x99 (SLE 66RxxS)", spacer);
    else if (tagtype & MY_D_NFC)
        PrintAndLogEx(NORMAL, "%sTYPE : INFINEON my-d\x99 NFC (SLE 66RxxP)", spacer);
    else if (tagtype & MY_D_MOVE)
        PrintAndLogEx(NORMAL, "%sTYPE : INFINEON my-d\x99 move (SLE 66R01P)", spacer);
    else if (tagtype & MY_D_MOVE_NFC)
        PrintAndLogEx(NORMAL, "%sTYPE : INFINEON my-d\x99 move NFC (SLE 66R01P)", spacer);
    else if (tagtype & MY_D_MOVE_LEAN)
        PrintAndLogEx(NORMAL, "%sTYPE : INFINEON my-d\x99 move lean (SLE 66R01L)", spacer);
    else if (tagtype & FUDAN_UL)
        PrintAndLogEx(NORMAL, "%sTYPE : FUDAN Ultralight Compatible (or other compatible) %s", spacer, (tagtype & MAGIC) ? "<magic>" : "");
    else
        PrintAndLogEx(NORMAL, "%sTYPE : Unknown %06x", spacer, tagtype);
    return 0;
}

static int ulc_print_3deskey(uint8_t *data) {
    PrintAndLogEx(NORMAL, "         deskey1 [44/0x2C] : %s [s]", sprint_hex(data, 4), sprint_ascii(data, 4));
    PrintAndLogEx(NORMAL, "         deskey1 [45/0x2D] : %s [s]", sprint_hex(data + 4, 4), sprint_ascii(data + 4, 4));
    PrintAndLogEx(NORMAL, "         deskey2 [46/0x2E] : %s [s]", sprint_hex(data + 8, 4), sprint_ascii(data + 8, 4));
    PrintAndLogEx(NORMAL, "         deskey2 [47/0x2F] : %s [s]", sprint_hex(data + 12, 4), sprint_ascii(data + 12, 4));
    PrintAndLogEx(NORMAL, "\n 3des key : %s", sprint_hex(SwapEndian64(data, 16, 8), 16));
    return 0;
}

static int ulc_print_configuration(uint8_t *data) {

    PrintAndLogEx(NORMAL, "--- UL-C Configuration");
    PrintAndLogEx(NORMAL, " Higher Lockbits [40/0x28] : %s - %s", sprint_hex(data, 4), sprint_bin(data, 2));
    PrintAndLogEx(NORMAL, "         Counter [41/0x29] : %s - %s", sprint_hex(data + 4, 4), sprint_bin(data + 4, 2));

    bool validAuth = (data[8] >= 0x03 && data[8] <= 0x30);
    if (validAuth)
        PrintAndLogEx(NORMAL, "           Auth0 [42/0x2A] : %s page %d/0x%02X and above need authentication", sprint_hex(data + 8, 4), data[8], data[8]);
    else {
        if (data[8] == 0) {
            PrintAndLogEx(NORMAL, "           Auth0 [42/0x2A] : %s default", sprint_hex(data + 8, 4));
        } else {
            PrintAndLogEx(NORMAL, "           Auth0 [42/0x2A] : %s auth byte is out-of-range", sprint_hex(data + 8, 4));
        }
    }
    PrintAndLogEx(NORMAL, "           Auth1 [43/0x2B] : %s %s",
                  sprint_hex(data + 12, 4),
                  (data[12] & 1) ? "write access restricted" : "read and write access restricted"
                 );
    return 0;
}

static int ulev1_print_configuration(uint32_t tagtype, uint8_t *data, uint8_t startPage) {

    PrintAndLogEx(NORMAL, "\n--- Tag Configuration");

    bool strg_mod_en = (data[0] & 2);
    uint8_t authlim = (data[4] & 0x07);
    bool nfc_cnf_en = (data[4] & 0x08);
    bool nfc_cnf_prot_pwd = (data[4] & 0x10);
    bool cfglck = (data[4] & 0x40);
    bool prot = (data[4] & 0x80);
    uint8_t vctid = data[5];

    PrintAndLogEx(NORMAL, "  cfg0 [%u/0x%02X] : %s", startPage, startPage, sprint_hex(data, 4));

    if ((tagtype & (NTAG_213_F | NTAG_216_F))) {
        uint8_t mirror_conf = (data[0] & 0xC0);
        uint8_t mirror_byte = (data[0] & 0x30);
        bool sleep_en = (data[0] & 0x08);
        strg_mod_en = (data[0] & 0x04);
        uint8_t fdp_conf = (data[0] & 0x03);

        switch (mirror_conf) {
            case 0:
                PrintAndLogEx(NORMAL, "                    - no ASCII mirror");
                break;
            case 1:
                PrintAndLogEx(NORMAL, "                    - UID ASCII mirror");
                break;
            case 2:
                PrintAndLogEx(NORMAL, "                    - NFC counter ASCII mirror");
                break;
            case 3:
                PrintAndLogEx(NORMAL, "                    - UID and NFC counter ASCII mirror");
                break;
            default:
                break;
        }

        PrintAndLogEx(NORMAL, "                    - SLEEP mode %s", (sleep_en) ? "enabled" : "disabled");

        switch (fdp_conf) {
            case 0:
                PrintAndLogEx(NORMAL, "                    - no field detect");
                break;
            case 1:
                PrintAndLogEx(NORMAL, "                    - enabled by first State-of-Frame (start of communication)");
                break;
            case 2:
                PrintAndLogEx(NORMAL, "                    - enabled by selection of the tag");
                break;
            case 3:
                PrintAndLogEx(NORMAL, "                    - enabled by field presence");
                break;
            default:
                break;
        }
        // valid mirror start page and byte position within start page.
        if (tagtype & NTAG_213_F) {
            switch (mirror_conf) {
                case 1:
                { PrintAndLogEx(NORMAL, "         mirror start block %02X | byte pos %02X - %s", data[2], mirror_byte, (data[2] >= 0x4 && data[2] <= 0x24) ? "OK" : "Invalid value"); break;}
                case 2:
                { PrintAndLogEx(NORMAL, "         mirror start block %02X | byte pos %02X - %s", data[2], mirror_byte, (data[2] >= 0x4 && data[2] <= 0x26) ? "OK" : "Invalid value"); break;}
                case 3:
                { PrintAndLogEx(NORMAL, "         mirror start block %02X | byte pos %02X - %s", data[2], mirror_byte, (data[2] >= 0x4 && data[2] <= 0x22) ? "OK" : "Invalid value"); break;}
                default:
                    break;
            }
        } else if (tagtype & NTAG_216_F) {
            switch (mirror_conf) {
                case 1:
                { PrintAndLogEx(NORMAL, "         mirror start block %02X | byte pos %02X - %s", data[2], mirror_byte, (data[2] >= 0x4 && data[2] <= 0xDE) ? "OK" : "Invalid value"); break;}
                case 2:
                { PrintAndLogEx(NORMAL, "         mirror start block %02X | byte pos %02X - %s", data[2], mirror_byte, (data[2] >= 0x4 && data[2] <= 0xE0) ? "OK" : "Invalid value"); break;}
                case 3:
                { PrintAndLogEx(NORMAL, "         mirror start block %02X | byte pos %02X - %s", data[2], mirror_byte, (data[2] >= 0x4 && data[2] <= 0xDC) ? "OK" : "Invalid value"); break;}
                default:
                    break;
            }
        }
    }
    PrintAndLogEx(NORMAL, "                    - strong modulation mode %s", (strg_mod_en) ? "enabled" : "disabled");

    if (data[3] < 0xff)
        PrintAndLogEx(NORMAL, "                    - page %d and above need authentication", data[3]);
    else
        PrintAndLogEx(NORMAL, "                    - pages don't need authentication");

    PrintAndLogEx(NORMAL, "  cfg1 [%u/0x%02X] : %s", startPage + 1, startPage + 1,  sprint_hex(data + 4, 4));
    if (authlim == 0)
        PrintAndLogEx(NORMAL, "                    - Unlimited password attempts");
    else
        PrintAndLogEx(NORMAL, "                    - Max number of password attempts is %d", authlim);

    PrintAndLogEx(NORMAL, "                    - NFC counter %s", (nfc_cnf_en) ? "enabled" : "disabled");
    PrintAndLogEx(NORMAL, "                    - NFC counter %s", (nfc_cnf_prot_pwd) ? "not protected" : "password protection enabled");

    PrintAndLogEx(NORMAL, "                    - user configuration %s", cfglck ? "permanently locked" : "writeable");
    PrintAndLogEx(NORMAL, "                    - %s access is protected with password", prot ? "read and write" : "write");
    PrintAndLogEx(NORMAL, "                    - %02X, Virtual Card Type Identifier is %s default", vctid, (vctid == 0x05) ? "" : "not");
    PrintAndLogEx(NORMAL, "  PWD  [%u/0x%02X] : %s- (cannot be read)", startPage + 2, startPage + 2,  sprint_hex(data + 8, 4));
    PrintAndLogEx(NORMAL, "  PACK [%u/0x%02X] : %s      - (cannot be read)", startPage + 3, startPage + 3,  sprint_hex(data + 12, 2));
    PrintAndLogEx(NORMAL, "  RFU  [%u/0x%02X] :       %s- (cannot be read)", startPage + 3, startPage + 3,  sprint_hex(data + 14, 2));
    return 0;
}

static int ulev1_print_counters() {
    PrintAndLogEx(NORMAL, "--- Tag Counters");
    uint8_t tear[1] = {0};
    uint8_t counter[3] = {0, 0, 0};
    uint16_t len = 0;
    for (uint8_t i = 0; i < 3; ++i) {
        ulev1_readTearing(i, tear, sizeof(tear));
        len = ulev1_readCounter(i, counter, sizeof(counter));
        if (len == 3) {
            PrintAndLogEx(NORMAL, "       [%0d] : %s", i, sprint_hex(counter, 3));
            PrintAndLogEx(NORMAL, "                    - %02X tearing %s", tear[0], (tear[0] == 0xBD) ? "Ok" : "failure");
        }
    }
    return len;
}

static int ulev1_print_signature(uint8_t *data, uint8_t len) {
    PrintAndLogEx(NORMAL, "\n--- Tag Signature");
    PrintAndLogEx(NORMAL, "IC signature public key name  : NXP NTAG21x (2013)");
    PrintAndLogEx(NORMAL, "IC signature public key value : %s", sprint_hex(public_ecda_key, PUBLIC_ECDA_KEYLEN));
    PrintAndLogEx(NORMAL, "    Elliptic curve parameters : secp128r1");
    PrintAndLogEx(NORMAL, "            Tag ECC Signature : %s", sprint_hex(data, len));
    //to do:  verify if signature is valid
    // only UID is signed.
    //PrintAndLogEx(NORMAL, "IC signature status: %s valid", (iseccvalid() )?"":"not");
    return 0;
}

static int ulev1_print_version(uint8_t *data) {
    PrintAndLogEx(NORMAL, "\n--- Tag Version");
    PrintAndLogEx(NORMAL, "       Raw bytes : %s", sprint_hex(data, 8));
    PrintAndLogEx(NORMAL, "       Vendor ID : %02X, %s", data[1], getTagInfo(data[1]));
    PrintAndLogEx(NORMAL, "    Product type : %s", getProductTypeStr(data[2]));
    PrintAndLogEx(NORMAL, " Product subtype : %02X, %s", data[3], (data[3] == 1) ? "17 pF" : "50pF");
    PrintAndLogEx(NORMAL, "   Major version : %02X", data[4]);
    PrintAndLogEx(NORMAL, "   Minor version : %02X", data[5]);
    PrintAndLogEx(NORMAL, "            Size : %s", getUlev1CardSizeStr(data[6]));
    PrintAndLogEx(NORMAL, "   Protocol type : %02X %s", data[7], (data[7] == 0x3) ? "(ISO14443-3 Compliant)" : "");
    return 0;
}

/*
static int ulc_magic_test(){
    // Magic Ultralight test
        // Magic UL-C, by observation,
    // 1) it seems to have a static nonce response to 0x1A command.
    // 2) the deskey bytes is not-zero:d out on as datasheet states.
    // 3) UID - changeable, not only, but pages 0-1-2-3.
    // 4) use the ul_magic_test !  magic tags answers specially!
    int returnValue = UL_ERROR;
    iso14a_card_select_t card;
    uint8_t nonce1[11] = {0x00};
    uint8_t nonce2[11] = {0x00};
    int status = ul_select(&card);
    if ( !status ){
        return UL_ERROR;
    }
    status = ulc_requestAuthentication(nonce1, sizeof(nonce1));
    if ( status > 0 ) {
        status = ulc_requestAuthentication(nonce2, sizeof(nonce2));
        returnValue =  ( !memcmp(nonce1, nonce2, 11) ) ? UL_C_MAGIC : UL_C;
    } else {
        returnValue = UL;
    }
    DropField();
    return returnValue;
}
*/
static int ul_magic_test() {
    // Magic Ultralight tests
    // 1) take present UID, and try to write it back. OBSOLETE
    // 2) make a wrong length write to page0, and see if tag answers with ACK/NACK:

    iso14a_card_select_t card;
    if (!ul_select(&card))
        return UL_ERROR;
    int status = ul_comp_write(0, NULL, 0);
    DropField();
    if (status == 0)
        return MAGIC;
    return 0;
}

uint32_t GetHF14AMfU_Type(void) {

    TagTypeUL_t tagtype = UNKNOWN;
    iso14a_card_select_t card;
    uint8_t version[10] = {0x00};
    int status = 0;
    int len;

    if (!ul_select(&card)) return UL_ERROR;

    // Ultralight - ATQA / SAK
    if (card.atqa[1] != 0x00 || card.atqa[0] != 0x44 || card.sak != 0x00) {
        //PrintAndLogEx(NORMAL, "Tag is not Ultralight | NTAG | MY-D  [ATQA: %02X %02X SAK: %02X]\n", card.atqa[1], card.atqa[0], card.sak);
        DropField();
        return UL_ERROR;
    }

    if (card.uid[0] != 0x05) {

        len  = ulev1_getVersion(version, sizeof(version));
        DropField();

        switch (len) {
            case 0x0A: {

                if (memcmp(version, "\x00\x04\x03\x01\x01\x00\x0B", 7) == 0)      { tagtype = UL_EV1_48; break; }
                else if (memcmp(version, "\x00\x04\x03\x01\x02\x00\x0B", 7) == 0) { tagtype = UL_NANO_40; break; }
                else if (memcmp(version, "\x00\x04\x03\x02\x01\x00\x0B", 7) == 0) { tagtype = UL_EV1_48; break; }
                else if (memcmp(version, "\x00\x04\x03\x01\x01\x00\x0E", 7) == 0) { tagtype = UL_EV1_128; break; }
                else if (memcmp(version, "\x00\x04\x03\x02\x01\x00\x0E", 7) == 0) { tagtype = UL_EV1_128; break; }
                else if (memcmp(version, "\x00\x04\x04\x01\x01\x00\x0B", 7) == 0) { tagtype = NTAG_210; break; }
                else if (memcmp(version, "\x00\x04\x04\x01\x01\x00\x0E", 7) == 0) { tagtype = NTAG_212; break; }
                else if (memcmp(version, "\x00\x04\x04\x02\x01\x00\x0F", 7) == 0) { tagtype = NTAG_213; break; }
                else if (memcmp(version, "\x00\x04\x04\x02\x01\x00\x11", 7) == 0) { tagtype = NTAG_215; break; }
                else if (memcmp(version, "\x00\x04\x04\x02\x01\x00\x13", 7) == 0) { tagtype = NTAG_216; break; }
                else if (memcmp(version, "\x00\x04\x04\x04\x01\x00\x0F", 7) == 0) { tagtype = NTAG_213_F; break; }
                else if (memcmp(version, "\x00\x04\x04\x04\x01\x00\x13", 7) == 0) { tagtype = NTAG_216_F; break; }
                else if (memcmp(version, "\x00\x04\x04\x05\x02\x01\x13", 7) == 0) { tagtype = NTAG_I2C_1K; break; }
                else if (memcmp(version, "\x00\x04\x04\x05\x02\x01\x15", 7) == 0) { tagtype = NTAG_I2C_2K; break; }
                else if (memcmp(version, "\x00\x04\x04\x05\x02\x02\x13", 7) == 0) { tagtype = NTAG_I2C_1K_PLUS; break; }
                else if (memcmp(version, "\x00\x04\x04\x05\x02\x02\x15", 7) == 0) { tagtype = NTAG_I2C_2K_PLUS; break; }
                else if (version[2] == 0x04) { tagtype = NTAG; break; }
                else if (version[2] == 0x03) { tagtype = UL_EV1; }
                break;
            }
            case 0x01:
                tagtype = UL_C;
                break;
            case 0x00:
                tagtype = UL;
                break;
            case -1  :
                tagtype = (UL | UL_C | NTAG_203);
                break;  // could be UL | UL_C magic tags
            default  :
                tagtype = UNKNOWN;
                break;
        }

        // UL vs UL-C vs ntag203 test
        if (tagtype & (UL | UL_C | NTAG_203)) {
            if (!ul_select(&card)) return UL_ERROR;

            // do UL_C check first...
            uint8_t nonce[11] = {0x00};
            status = ulc_requestAuthentication(nonce, sizeof(nonce));
            DropField();
            if (status > 1) {
                tagtype = UL_C;
            } else {
                // need to re-select after authentication error
                if (!ul_select(&card)) return UL_ERROR;

                uint8_t data[16] = {0x00};
                // read page 0x26-0x29 (last valid ntag203 page)
                status = ul_read(0x26, data, sizeof(data));
                if (status <= 1) {
                    tagtype = UL;
                } else {
                    // read page 0x30 (should error if it is a ntag203)
                    status = ul_read(0x30, data, sizeof(data));
                    if (status <= 1) {
                        tagtype = NTAG_203;
                    } else {
                        tagtype = UNKNOWN;
                    }
                }
                DropField();
            }
        }
        if (tagtype & UL) {
            tagtype = ul_fudan_check();
            DropField();
        }
    } else {
        DropField();
        // Infinition MY-D tests   Exam high nibble
        uint8_t nib = (card.uid[1] & 0xf0) >> 4;
        switch (nib) {
            // case 0: tagtype =  SLE66R35E7; break; //or SLE 66R35E7 - mifare compat... should have different sak/atqa for mf 1k
            case 1:
                tagtype =  MY_D;
                break; // or SLE 66RxxS ... up to 512 pages of 8 user bytes...
            case 2:
                tagtype = (MY_D_NFC);
                break; // or SLE 66RxxP ... up to 512 pages of 8 user bytes... (or in nfc mode FF pages of 4 bytes)
            case 3:
                tagtype = (MY_D_MOVE | MY_D_MOVE_NFC);
                break; // or SLE 66R01P // 38 pages of 4 bytes //notice: we can not currently distinguish between these two
            case 7:
                tagtype =  MY_D_MOVE_LEAN;
                break; // or SLE 66R01L  // 16 pages of 4 bytes
        }
    }

    tagtype |= ul_magic_test();
    if (tagtype == (UNKNOWN | MAGIC)) tagtype = (UL_MAGIC);
    return tagtype;
}
//
//  extended tag information
//
int CmdHF14AMfUInfo(const char *Cmd) {

    uint8_t authlim = 0xff;
    uint8_t data[16] = {0x00};
    iso14a_card_select_t card;
    int status;
    bool errors = false;
    bool hasAuthKey = false;
    bool locked = false;
    bool swapEndian = false;
    uint8_t cmdp = 0;
    uint8_t dataLen = 0;
    uint8_t authenticationkey[16] = {0x00};
    uint8_t *authkeyptr = authenticationkey;
    uint8_t pwd[4] = {0, 0, 0, 0};
    uint8_t *key = pwd;
    uint8_t pack[4] = {0, 0, 0, 0};
    int len;
    char tempStr[50];

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_mfu_info();
            case 'k':
                dataLen = param_getstr(Cmd, cmdp + 1, tempStr, sizeof(tempStr));
                if (dataLen == 32 || dataLen == 8) { //ul-c or ev1/ntag key length
                    errors = param_gethex(tempStr, 0, authenticationkey, dataLen);
                    dataLen /= 2; // handled as bytes from now on
                } else {
                    PrintAndLogEx(WARNING, "ERROR: Key is incorrect length\n");
                    errors = true;
                }
                cmdp += 2;
                hasAuthKey = true;
                break;
            case 'l':
                swapEndian = true;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    //Validations
    if (errors) return usage_hf_mfu_info();

    TagTypeUL_t tagtype = GetHF14AMfU_Type();
    if (tagtype == UL_ERROR) return -1;

    PrintAndLogEx(NORMAL, "\n--- Tag Information ---------");
    PrintAndLogEx(NORMAL, "-------------------------------------------------------------");
    ul_print_type(tagtype, 6);

    // Swap endianness
    if (swapEndian && hasAuthKey) authkeyptr = SwapEndian64(authenticationkey, dataLen, (dataLen == 16) ? 8 : 4);

    if (!ul_auth_select(&card, tagtype, hasAuthKey, authkeyptr, pack, sizeof(pack))) return -1;

    // read pages 0,1,2,3 (should read 4pages)
    status = ul_read(0, data, sizeof(data));
    if (status == -1) {
        DropField();
        PrintAndLogEx(WARNING, "Error: tag didn't answer to READ");
        return status;
    } else if (status == 16) {
        ul_print_default(data);
        ndef_print_CC(data + 12);
    } else {
        locked = true;
    }

    // UL_C Specific
    if ((tagtype & UL_C)) {

        // read pages 0x28, 0x29, 0x2A, 0x2B
        uint8_t ulc_conf[16] = {0x00};
        status = ul_read(0x28, ulc_conf, sizeof(ulc_conf));
        if (status == -1) {
            PrintAndLogEx(WARNING, "Error: tag didn't answer to READ UL-C");
            DropField();
            return status;
        }
        if (status == 16)
            ulc_print_configuration(ulc_conf);
        else
            locked = true;

        if ((tagtype & MAGIC)) {
            //just read key
            uint8_t ulc_deskey[16] = {0x00};
            status = ul_read(0x2C, ulc_deskey, sizeof(ulc_deskey));
            if (status == -1) {
                DropField();
                PrintAndLogEx(WARNING, "Error: tag didn't answer to READ magic");
                return status;
            }
            if (status == 16) ulc_print_3deskey(ulc_deskey);

        } else {
            DropField();
            // if we called info with key, just return
            if (hasAuthKey) return 1;

            // also try to diversify default keys..  look into CmdHF14AMfuGenDiverseKeys
            PrintAndLogEx(INFO, "Trying some default 3des keys");
            for (uint8_t i = 0; i < KEYS_3DES_COUNT; ++i) {
                key = default_3des_keys[i];
                if (ulc_authentication(key, true)) {
                    PrintAndLogEx(SUCCESS, "Found default 3des key: ");
                    uint8_t keySwap[16];
                    memcpy(keySwap, SwapEndian64(key, 16, 8), 16);
                    ulc_print_3deskey(keySwap);
                    return 1;
                }
            }
            return 1;
        }
    }

    // do counters and signature first (don't neet auth)

    // ul counters are different than ntag counters
    if ((tagtype & (UL_EV1_48 | UL_EV1_128 | UL_EV1))) {
        if (ulev1_print_counters() != 3) {
            // failed - re-select
            if (!ul_auth_select(&card, tagtype, hasAuthKey, authkeyptr, pack, sizeof(pack))) return -1;
        }
    }

    // NTAG counters?

    // Read signature
    if ((tagtype & (UL_EV1_48 | UL_EV1_128 | UL_EV1 | UL_NANO_40 | NTAG_213 | NTAG_213_F | NTAG_215 | NTAG_216 | NTAG_216_F | NTAG_I2C_1K | NTAG_I2C_2K | NTAG_I2C_1K_PLUS | NTAG_I2C_2K_PLUS))) {
        uint8_t ulev1_signature[32] = {0x00};
        status = ulev1_readSignature(ulev1_signature, sizeof(ulev1_signature));
        if (status == -1) {
            PrintAndLogEx(WARNING, "Error: tag didn't answer to READ SIGNATURE");
            DropField();
            return status;
        }
        if (status == 32) ulev1_print_signature(ulev1_signature, sizeof(ulev1_signature));
        else {
            // re-select
            if (!ul_auth_select(&card, tagtype, hasAuthKey, authkeyptr, pack, sizeof(pack))) return -1;
        }
    }

    // Get Version
    if ((tagtype & (UL_EV1_48 | UL_EV1_128 | UL_EV1 | UL_NANO_40 | NTAG_213 | NTAG_213_F | NTAG_215 | NTAG_216 | NTAG_216_F | NTAG_I2C_1K | NTAG_I2C_2K | NTAG_I2C_1K_PLUS | NTAG_I2C_2K_PLUS))) {
        uint8_t version[10] = {0x00};
        status  = ulev1_getVersion(version, sizeof(version));
        if (status == -1) {
            PrintAndLogEx(WARNING, "Error: tag didn't answer to GETVERSION");
            DropField();
            return status;
        } else if (status == 10) {
            ulev1_print_version(version);
        } else {
            locked = true;
            if (!ul_auth_select(&card, tagtype, hasAuthKey, authkeyptr, pack, sizeof(pack))) return -1;
        }

        uint8_t startconfigblock = 0;
        uint8_t ulev1_conf[16] = {0x00};

        // config blocks always are last 4 pages
        for (uint8_t i = 0; i < MAX_UL_TYPES; i++) {
            if (tagtype & UL_TYPES_ARRAY[i]) {
                startconfigblock = UL_MEMORY_ARRAY[i] - 3;
                break;
            }
        }

        if (startconfigblock) { // if we know where the config block is...
            status = ul_read(startconfigblock, ulev1_conf, sizeof(ulev1_conf));
            if (status == -1) {
                PrintAndLogEx(WARNING, "Error: tag didn't answer to READ EV1");
                DropField();
                return status;
            } else if (status == 16) {
                // save AUTHENTICATION LIMITS for later:
                authlim = (ulev1_conf[4] & 0x07);
                // add pwd / pack if used from cli
                if (hasAuthKey) {
                    memcpy(ulev1_conf + 8, authkeyptr, 4);
                    memcpy(ulev1_conf + 12, pack, 2);
                }
                ulev1_print_configuration(tagtype, ulev1_conf, startconfigblock);
            }
        }

        // AUTHLIMIT, (number of failed authentications)
        // 0 = limitless.
        // 1-7 = limit. No automatic tries then.
        // hasAuthKey,  if we was called with key, skip test.
        if (!authlim && !hasAuthKey) {
            PrintAndLogEx(NORMAL, "\n--- Known EV1/NTAG passwords.");
            len = 0;

            // test pwd gen A
            num_to_bytes(ul_ev1_pwdgenA(card.uid), 4, key);
            len = ulev1_requestAuthentication(key, pack, sizeof(pack));
            if (len > -1) {
                PrintAndLogEx(SUCCESS, "Found a default password: %s || Pack: %02X %02X", sprint_hex(key, 4), pack[0], pack[1]);
                goto out;
            }

            if (!ul_auth_select(&card, tagtype, hasAuthKey, authkeyptr, pack, sizeof(pack))) return -1;

            // test pwd gen B
            num_to_bytes(ul_ev1_pwdgenB(card.uid), 4, key);
            len = ulev1_requestAuthentication(key, pack, sizeof(pack));
            if (len > -1) {
                PrintAndLogEx(SUCCESS, "Found a default password: %s || Pack: %02X %02X", sprint_hex(key, 4), pack[0], pack[1]);
                goto out;
            }

            if (!ul_auth_select(&card, tagtype, hasAuthKey, authkeyptr, pack, sizeof(pack))) return -1;

            // test pwd gen C
            num_to_bytes(ul_ev1_pwdgenC(card.uid), 4, key);
            len = ulev1_requestAuthentication(key, pack, sizeof(pack));
            if (len > -1) {
                PrintAndLogEx(SUCCESS, "Found a default password: %s || Pack: %02X %02X", sprint_hex(key, 4), pack[0], pack[1]);
                goto out;
            }

            if (!ul_auth_select(&card, tagtype, hasAuthKey, authkeyptr, pack, sizeof(pack))) return -1;

            // test pwd gen D
            num_to_bytes(ul_ev1_pwdgenD(card.uid), 4, key);
            len = ulev1_requestAuthentication(key, pack, sizeof(pack));
            if (len > -1) {
                PrintAndLogEx(SUCCESS, "Found a default password: %s || Pack: %02X %02X", sprint_hex(key, 4), pack[0], pack[1]);
                goto out;
            }

            if (!ul_auth_select(&card, tagtype, hasAuthKey, authkeyptr, pack, sizeof(pack))) return -1;

            for (uint8_t i = 0; i < KEYS_PWD_COUNT; ++i) {
                key = default_pwd_pack[i];
                len = ulev1_requestAuthentication(key, pack, sizeof(pack));
                if (len > -1) {
                    PrintAndLogEx(SUCCESS, "Found a default password: %s || Pack: %02X %02X", sprint_hex(key, 4), pack[0], pack[1]);
                    break;
                } else {
                    if (!ul_auth_select(&card, tagtype, hasAuthKey, authkeyptr, pack, sizeof(pack))) return -1;
                }
            }
            if (len < 1) PrintAndLogEx(WARNING, "password not known");
        }
    }
out:
    DropField();
    if (locked) PrintAndLogEx(FAILED, "\nTag appears to be locked, try using the key to get more info");
    PrintAndLogEx(NORMAL, "");
    return 1;
}

//
//  Write Single Block
//
int CmdHF14AMfUWrBl(const char *Cmd) {

    int blockNo = -1;
    bool errors = false;
    bool hasAuthKey = false;
    bool hasPwdKey = false;
    bool swapEndian = false;

    uint8_t cmdp = 0;
    uint8_t keylen = 0;
    uint8_t blockdata[20] = {0x00};
    uint8_t data[16] = {0x00};
    uint8_t authenticationkey[16] = {0x00};
    uint8_t *authKeyPtr = authenticationkey;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_mfu_wrbl();
            case 'k':
                // EV1/NTAG size key
                keylen = param_gethex(Cmd, cmdp + 1, data, 8);
                if (!keylen) {
                    memcpy(authenticationkey, data, 4);
                    cmdp += 2;
                    hasPwdKey = true;
                    break;
                }
                // UL-C size key
                keylen = param_gethex(Cmd, cmdp + 1, data, 32);
                if (!keylen) {
                    memcpy(authenticationkey, data, 16);
                    cmdp += 2;
                    hasAuthKey = true;
                    break;
                }
                PrintAndLogEx(WARNING, "ERROR: Key is incorrect length\n");
                errors = true;
                break;
            case 'b':
                blockNo = param_get8(Cmd, cmdp + 1);
                if (blockNo < 0) {
                    PrintAndLogEx(WARNING, "Wrong block number");
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'l':
                swapEndian = true;
                cmdp++;
                break;
            case 'd':
                if (param_gethex(Cmd, cmdp + 1, blockdata, 8)) {
                    PrintAndLogEx(WARNING, "Block data must include 8 HEX symbols");
                    errors = true;
                    break;
                }
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    //Validations
    if (errors || cmdp == 0) return usage_hf_mfu_wrbl();

    if (blockNo == -1) return usage_hf_mfu_wrbl();
    // starting with getting tagtype
    TagTypeUL_t tagtype = GetHF14AMfU_Type();
    if (tagtype == UL_ERROR) return -1;

    uint8_t maxblockno = 0;
    for (uint8_t idx = 0; idx < MAX_UL_TYPES; idx++) {
        if (tagtype & UL_TYPES_ARRAY[idx]) {
            maxblockno = UL_MEMORY_ARRAY[idx];
            break;
        }
    }
    if (blockNo > maxblockno) {
        PrintAndLogEx(WARNING, "block number too large. Max block is %u/0x%02X \n", maxblockno, maxblockno);
        return usage_hf_mfu_wrbl();
    }

    // Swap endianness
    if (swapEndian && hasAuthKey) authKeyPtr = SwapEndian64(authenticationkey, 16, 8);
    if (swapEndian && hasPwdKey)  authKeyPtr = SwapEndian64(authenticationkey, 4, 4);

    if (blockNo <= 3)
        PrintAndLogEx(NORMAL, "Special Block: %0d (0x%02X) [ %s]", blockNo, blockNo, sprint_hex(blockdata, 4));
    else
        PrintAndLogEx(NORMAL, "Block: %0d (0x%02X) [ %s]", blockNo, blockNo, sprint_hex(blockdata, 4));

    //Send write Block
    UsbCommand c = {CMD_MIFAREU_WRITEBL, {blockNo}};
    memcpy(c.d.asBytes, blockdata, 4);

    if (hasAuthKey) {
        c.arg[1] = 1;
        memcpy(c.d.asBytes + 4, authKeyPtr, 16);
    } else if (hasPwdKey) {
        c.arg[1] = 2;
        memcpy(c.d.asBytes + 4, authKeyPtr, 4);
    }

    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        uint8_t isOK  = resp.arg[0] & 0xff;
        PrintAndLogEx(SUCCESS, "isOk:%02x", isOK);
    } else {
        PrintAndLogEx(WARNING, "Command execute timeout");
    }

    return 0;
}
//
//  Read Single Block
//
int CmdHF14AMfURdBl(const char *Cmd) {

    int blockNo = -1;
    bool errors = false;
    bool hasAuthKey = false;
    bool hasPwdKey = false;
    bool swapEndian = false;
    uint8_t cmdp = 0;
    uint8_t keylen = 0;
    uint8_t data[16] = {0x00};
    uint8_t authenticationkey[16] = {0x00};
    uint8_t *authKeyPtr = authenticationkey;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_mfu_rdbl();
            case 'k':
                // EV1/NTAG size key
                keylen = param_gethex(Cmd, cmdp + 1, data, 8);
                if (!keylen) {
                    memcpy(authenticationkey, data, 4);
                    cmdp += 2;
                    hasPwdKey = true;
                    break;
                }
                // UL-C size key
                keylen = param_gethex(Cmd, cmdp + 1, data, 32);
                if (!keylen) {
                    memcpy(authenticationkey, data, 16);
                    cmdp += 2;
                    hasAuthKey = true;
                    break;
                }
                PrintAndLogEx(WARNING, "ERROR: Key is incorrect length\n");
                errors = true;
                break;
            case 'b':
                blockNo = param_get8(Cmd, cmdp + 1);
                if (blockNo < 0) {
                    PrintAndLogEx(WARNING, "Wrong block number");
                    errors = true;
                }
                cmdp += 2;
                break;
            case 'l':
                swapEndian = true;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    //Validations
    if (errors || cmdp == 0) return usage_hf_mfu_rdbl();

    if (blockNo == -1) return usage_hf_mfu_rdbl();
    // start with getting tagtype
    TagTypeUL_t tagtype = GetHF14AMfU_Type();
    if (tagtype == UL_ERROR) return -1;

    uint8_t maxblockno = 0;
    for (uint8_t idx = 0; idx < MAX_UL_TYPES; idx++) {
        if (tagtype & UL_TYPES_ARRAY[idx]) {
            maxblockno = UL_MEMORY_ARRAY[idx];
            break;
        }
    }
    if (blockNo > maxblockno) {
        PrintAndLogEx(WARNING, "block number to large. Max block is %u/0x%02X \n", maxblockno, maxblockno);
        return usage_hf_mfu_rdbl();
    }

    // Swap endianness
    if (swapEndian && hasAuthKey) authKeyPtr = SwapEndian64(authenticationkey, 16, 8);
    if (swapEndian && hasPwdKey)  authKeyPtr = SwapEndian64(authenticationkey, 4, 4);

    //Read Block
    UsbCommand c = {CMD_MIFAREU_READBL, {blockNo}};
    if (hasAuthKey) {
        c.arg[1] = 1;
        memcpy(c.d.asBytes, authKeyPtr, 16);
    } else if (hasPwdKey) {
        c.arg[1] = 2;
        memcpy(c.d.asBytes, authKeyPtr, 4);
    }

    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        uint8_t isOK = resp.arg[0] & 0xff;
        if (isOK) {
            uint8_t *data = resp.d.asBytes;
            PrintAndLogEx(NORMAL, "\nBlock#  | Data        | Ascii");
            PrintAndLogEx(NORMAL, "-----------------------------");
            PrintAndLogEx(NORMAL, "%02d/0x%02X | %s| %s\n", blockNo, blockNo, sprint_hex(data, 4), sprint_ascii(data, 4));
        } else {
            PrintAndLogEx(WARNING, "Failed reading block: (%02x)", isOK);
        }
    } else {
        PrintAndLogEx(WARNING, "Command execute time-out");
    }
    return 0;
}

int usage_hf_mfu_info(void) {
    PrintAndLogEx(NORMAL, "It gathers information about the tag and tries to detect what kind it is.");
    PrintAndLogEx(NORMAL, "Sometimes the tags are locked down, and you may need a key to be able to read the information");
    PrintAndLogEx(NORMAL, "The following tags can be identified:\n");
    PrintAndLogEx(NORMAL, "Ultralight, Ultralight-C, Ultralight EV1, NTAG 203, NTAG 210,");
    PrintAndLogEx(NORMAL, "NTAG 212, NTAG 213, NTAG 215, NTAG 216, NTAG I2C 1K & 2K");
    PrintAndLogEx(NORMAL, "my-d, my-d NFC, my-d move, my-d move NFC\n");
    PrintAndLogEx(NORMAL, "Usage:  hf mfu info k <key> l");
    PrintAndLogEx(NORMAL, "  Options : ");
    PrintAndLogEx(NORMAL, "  k <key> : (optional) key for authentication [UL-C 16bytes, EV1/NTAG 4bytes]");
    PrintAndLogEx(NORMAL, "  l       : (optional) swap entered key's endianness");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       hf mfu info");
    PrintAndLogEx(NORMAL, "       hf mfu info k 00112233445566778899AABBCCDDEEFF");
    PrintAndLogEx(NORMAL, "       hf mfu info k AABBCCDD");
    return 0;
}

int usage_hf_mfu_dump(void) {
    PrintAndLogEx(NORMAL, "Reads all pages from Ultralight, Ultralight-C, Ultralight EV1");
    PrintAndLogEx(NORMAL, "NTAG 203, NTAG 210, NTAG 212, NTAG 213, NTAG 215, NTAG 216");
    PrintAndLogEx(NORMAL, "and saves binary dump into the file `filename.bin` or `cardUID.bin`");
    PrintAndLogEx(NORMAL, "It autodetects card type.\n");
    PrintAndLogEx(NORMAL, "Usage:  hf mfu dump k <key> l f <filename w/o .bin> p <page#> q <#pages>");
    PrintAndLogEx(NORMAL, "  Options :");
    PrintAndLogEx(NORMAL, "  k <key> : (optional) key for authentication [UL-C 16bytes, EV1/NTAG 4bytes]");
    PrintAndLogEx(NORMAL, "  l       : (optional) swap entered key's endianness");
    PrintAndLogEx(NORMAL, "  f <FN > : filename w/o .bin to save the dump as");
    PrintAndLogEx(NORMAL, "  p <Pg > : starting Page number to manually set a page to start the dump at");
    PrintAndLogEx(NORMAL, "  q <qty> : number of Pages to manually set how many pages to dump");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       hf mfu dump");
    PrintAndLogEx(NORMAL, "       hf mfu dump n myfile");
    PrintAndLogEx(NORMAL, "       hf mfu dump k 00112233445566778899AABBCCDDEEFF");
    PrintAndLogEx(NORMAL, "       hf mfu dump k AABBCCDD\n");
    return 0;
}

int usage_hf_mfu_restore(void) {
    PrintAndLogEx(NORMAL, "Restore dumpfile onto card.");
    PrintAndLogEx(NORMAL, "Usage:  hf mfu restore [h] [l] [s] k <key> n <filename w/o .bin> ");
    PrintAndLogEx(NORMAL, "  Options :");
    PrintAndLogEx(NORMAL, "  k <key> : (optional) key for authentication [UL-C 16bytes, EV1/NTAG 4bytes]");
    PrintAndLogEx(NORMAL, "  l       : (optional) swap entered key's endianness");
    PrintAndLogEx(NORMAL, "  s       : (optional) enable special write UID -MAGIC TAG ONLY-");
    PrintAndLogEx(NORMAL, "  e       : (optional) enable special write version/signature -MAGIC NTAG 21* ONLY-");
    PrintAndLogEx(NORMAL, "  r       : (optional) use the password found in dumpfile to configure tag. requires 'e' parameter to work");
    PrintAndLogEx(NORMAL, "  f <FN>  : filename w/o .bin to restore");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       hf mfu restore s f myfile");
    PrintAndLogEx(NORMAL, "       hf mfu restore k AABBCCDD s f myfile\n");
    PrintAndLogEx(NORMAL, "       hf mfu restore k AABBCCDD s e r f myfile\n");
    return 0;
}

int usage_hf_mfu_rdbl(void) {
    PrintAndLogEx(NORMAL, "Read a block and print. It autodetects card type.\n");
    PrintAndLogEx(NORMAL, "Usage:  hf mfu rdbl b <block number> k <key> l\n");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  b <no>  : block to read");
    PrintAndLogEx(NORMAL, "  k <key> : (optional) key for authentication [UL-C 16bytes, EV1/NTAG 4bytes]");
    PrintAndLogEx(NORMAL, "  l       : (optional) swap entered key's endianness");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       hf mfu rdbl b 0");
    PrintAndLogEx(NORMAL, "       hf mfu rdbl b 0 k 00112233445566778899AABBCCDDEEFF");
    PrintAndLogEx(NORMAL, "       hf mfu rdbl b 0 k AABBCCDD\n");
    return 0;
}

int usage_hf_mfu_wrbl(void) {
    PrintAndLogEx(NORMAL, "Write a block. It autodetects card type.\n");
    PrintAndLogEx(NORMAL, "Usage:  hf mfu wrbl b <block number> d <data> k <key> l\n");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  b <no>   : block to write");
    PrintAndLogEx(NORMAL, "  d <data> : block data - (8 hex symbols)");
    PrintAndLogEx(NORMAL, "  k <key>  : (optional) key for authentication [UL-C 16bytes, EV1/NTAG 4bytes]");
    PrintAndLogEx(NORMAL, "  l        : (optional) swap entered key's endianness");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        hf mfu wrbl b 0 d 01234567");
    PrintAndLogEx(NORMAL, "        hf mfu wrbl b 0 d 01234567 k AABBCCDD\n");
    return 0;
}

int usage_hf_mfu_eload(void) {
    PrintAndLogEx(NORMAL, "It loads emul dump from the file `filename.eml`");
    PrintAndLogEx(NORMAL, "Hint: See script dumptoemul-mfu.lua to convert the .bin to the eml");
    PrintAndLogEx(NORMAL, "Usage:  hf mfu eload u <file name w/o `.eml`> [numblocks]");
    PrintAndLogEx(NORMAL, "  Options:");
    PrintAndLogEx(NORMAL, "    h          : this help");
    PrintAndLogEx(NORMAL, "    u          : UL (required)");
    PrintAndLogEx(NORMAL, "    [filename] : without `.eml` (required)");
    PrintAndLogEx(NORMAL, "    numblocks  : number of blocks to load from eml file (optional)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "  sample: hf mfu eload u filename");
    PrintAndLogEx(NORMAL, "          hf mfu eload u filename 57");
    return 0;
}

int usage_hf_mfu_sim(void) {
    PrintAndLogEx(NORMAL, "\nEmulating Ultralight tag from emulator memory\n");
    PrintAndLogEx(NORMAL, "\nBe sure to load the emulator memory first!\n");
    PrintAndLogEx(NORMAL, "Usage: hf mfu sim t 7 u <uid>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "    h       : this help");
    PrintAndLogEx(NORMAL, "    t 7     : 7 = NTAG or Ultralight sim (required)");
    PrintAndLogEx(NORMAL, "    u <uid> : 4 or 7 byte UID (optional)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        hf mfu sim t 7");
    PrintAndLogEx(NORMAL, "        hf mfu sim t 7 u 1122344556677\n");

    return 0;
}

int usage_hf_mfu_ucauth(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf mfu cauth k <key number>");
    PrintAndLogEx(NORMAL, "      0 (default): 3DES standard key");
    PrintAndLogEx(NORMAL, "      1 : all 0x00 key");
    PrintAndLogEx(NORMAL, "      2 : 0x00-0x0F key");
    PrintAndLogEx(NORMAL, "      3 : nfc key");
    PrintAndLogEx(NORMAL, "      4 : all 0x01 key");
    PrintAndLogEx(NORMAL, "      5 : all 0xff key");
    PrintAndLogEx(NORMAL, "      6 : 0x00-0xFF key");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       hf mfu cauth k");
    PrintAndLogEx(NORMAL, "       hf mfu cauth k 3");
    return 0;
}

int usage_hf_mfu_ucsetpwd(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf mfu setpwd <password (32 hex symbols)>");
    PrintAndLogEx(NORMAL, "       [password] - (32 hex symbols)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "         hf mfu setpwd 000102030405060708090a0b0c0d0e0f");
    PrintAndLogEx(NORMAL, "");
    return 0;
}

int usage_hf_mfu_ucsetuid(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf mfu setuid <uid (14 hex symbols)>");
    PrintAndLogEx(NORMAL, "       [uid] - (14 hex symbols)");
    PrintAndLogEx(NORMAL, "\nThis only works for Magic Ultralight tags.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "         hf mfu setuid 11223344556677");
    PrintAndLogEx(NORMAL, "");
    return 0;
}

int usage_hf_mfu_gendiverse(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf mfu gen [h] [r] <uid (8 hex symbols)>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "    h       : this help");
    PrintAndLogEx(NORMAL, "    r       : read uid from tag");
    PrintAndLogEx(NORMAL, "    <uid>   : 4 byte UID (optional)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        hf mfu gen r");
    PrintAndLogEx(NORMAL, "        hf mfu gen 11223344");
    PrintAndLogEx(NORMAL, "");
    return 0;
}

int usage_hf_mfu_pwdgen(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf mfu pwdgen [h|t] [r] <uid (14 hex symbols)>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "    h       : this help");
    PrintAndLogEx(NORMAL, "    t       : selftest");
    PrintAndLogEx(NORMAL, "    r       : read uid from tag");
    PrintAndLogEx(NORMAL, "    <uid>   : 7 byte UID (optional)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        hf mfu pwdgen r");
    PrintAndLogEx(NORMAL, "        hf mfu pwdgen 11223344556677");
    PrintAndLogEx(NORMAL, "        hf mfu pwdgen t");
    PrintAndLogEx(NORMAL, "");
    return 0;
}

void printMFUdump(mfu_dump_t *card) {
    printMFUdumpEx(card, 255, 0);
}

void printMFUdumpEx(mfu_dump_t *card, uint16_t pages, uint8_t startpage) {
    PrintAndLogEx(NORMAL, "\n*special* data\n");
    PrintAndLogEx(NORMAL, "\nDataType  | Data                    | Ascii");
    PrintAndLogEx(NORMAL, "----------+-------------------------+---------");
    PrintAndLogEx(NORMAL, "Version   | %s| %s", sprint_hex(card->version, sizeof(card->version)), sprint_ascii(card->version, sizeof(card->version)));
    PrintAndLogEx(NORMAL, "TBD       | %-24s| %s", sprint_hex(card->tbo, sizeof(card->tbo)), sprint_ascii(card->tbo, sizeof(card->tbo)));
    PrintAndLogEx(NORMAL, "Tearing   | %-24s| %s", sprint_hex(card->tearing, sizeof(card->tearing)), sprint_ascii(card->tearing, sizeof(card->tearing)));
    PrintAndLogEx(NORMAL, "Pack      | %-24s| %s", sprint_hex(card->pack, sizeof(card->pack)), sprint_ascii(card->pack, sizeof(card->pack)));
    PrintAndLogEx(NORMAL, "TBD       | %-24s| %s", sprint_hex(card->tbo1, sizeof(card->tbo1)), sprint_ascii(card->tbo1, sizeof(card->tbo1)));
    PrintAndLogEx(NORMAL, "Signature1| %s| %s", sprint_hex(card->signature, 16), sprint_ascii(card->signature, 16));
    PrintAndLogEx(NORMAL, "Signature2| %s| %s", sprint_hex(card->signature + 16, 16), sprint_ascii(card->signature + 16, 16));
    PrintAndLogEx(NORMAL, "-------------------------------------------------------------");
    PrintAndLogEx(NORMAL, "\nBlock#   | Data        |lck| Ascii");
    PrintAndLogEx(NORMAL, "---------+-------------+---+------");

    uint8_t j = 0;
    bool lckbit = false;
    uint8_t *data = card->data;

    uint8_t lockbytes_sta[] = {0, 0};
    uint8_t lockbytes_dyn[] = {0, 0, 0};
    bool bit_stat[16]  = {0};
    bool bit_dyn[16] = {0};

    // Load static lock bytes.
    memcpy(lockbytes_sta, data + 10, sizeof(lockbytes_sta));
    for (j = 0; j < 16; j++) {
        bit_stat[j] = lockbytes_sta[j / 8] & (1 << (7 - j % 8));
    }

    // Load dynamic lockbytes if available
    // TODO -- FIGURE OUT LOCK BYTES FOR TO EV1 and/or NTAG
    if (pages == 44) {

        memcpy(lockbytes_dyn, data + (40 * 4), sizeof(lockbytes_dyn));

        for (j = 0; j < 16; j++) {
            bit_dyn[j] = lockbytes_dyn[j / 8] & (1 << (7 - j % 8));
        }
        PrintAndLogEx(NORMAL, "DYNAMIC LOCK: %s\n", sprint_hex(lockbytes_dyn, 3));
    }

    for (uint8_t i = 0; i < pages; ++i) {
        if (i < 3) {
            PrintAndLogEx(NORMAL, "%3d/0x%02X | %s|   | %s", i + startpage, i + startpage, sprint_hex(data + i * 4, 4), sprint_ascii(data + i * 4, 4));
            continue;
        }
        switch (i) {
            case  3:
                lckbit = bit_stat[4];
                break;
            case  4:
                lckbit = bit_stat[3];
                break;
            case  5:
                lckbit = bit_stat[2];
                break;
            case  6:
                lckbit = bit_stat[1];
                break;
            case  7:
                lckbit = bit_stat[0];
                break;
            case  8:
                lckbit = bit_stat[15];
                break;
            case  9:
                lckbit = bit_stat[14];
                break;
            case 10:
                lckbit = bit_stat[13];
                break;
            case 11:
                lckbit = bit_stat[12];
                break;
            case 12:
                lckbit = bit_stat[11];
                break;
            case 13:
                lckbit = bit_stat[10];
                break;
            case 14:
                lckbit = bit_stat[9];
                break;
            case 15:
                lckbit = bit_stat[8];
                break;
            case 16:
            case 17:
            case 18:
            case 19:
                lckbit = bit_dyn[6];
                break;
            case 20:
            case 21:
            case 22:
            case 23:
                lckbit = bit_dyn[5];
                break;
            case 24:
            case 25:
            case 26:
            case 27:
                lckbit = bit_dyn[4];
                break;
            case 28:
            case 29:
            case 30:
            case 31:
                lckbit = bit_dyn[2];
                break;
            case 32:
            case 33:
            case 34:
            case 35:
                lckbit = bit_dyn[1];
                break;
            case 36:
            case 37:
            case 38:
            case 39:
                lckbit = bit_dyn[0];
                break;
            case 40:
                lckbit = bit_dyn[12];
                break;
            case 41:
                lckbit = bit_dyn[11];
                break;
            case 42:
                lckbit = bit_dyn[10];
                break; //auth0
            case 43:
                lckbit = bit_dyn[9];
                break;  //auth1
            default:
                break;
        }
        PrintAndLogEx(NORMAL, "%3d/0x%02X | %s| %d | %s", i + startpage, i + startpage, sprint_hex(data + i * 4, 4), lckbit, sprint_ascii(data + i * 4, 4));
    }
    PrintAndLogEx(NORMAL, "---------------------------------");
}

//
//  Mifare Ultralight / Ultralight-C / Ultralight-EV1
//  Read and Dump Card Contents,  using auto detection of tag size.
int CmdHF14AMfUDump(const char *Cmd) {

    uint8_t fileNameLen = 0;
    char filename[FILE_PATH_SIZE] = {0x00};
    char *fptr = filename;

    uint8_t data[1024] = {0x00};
    memset(data, 0x00, sizeof(data));

    bool hasAuthKey = false;
    int i = 0;
    int pages = 16;
    uint8_t dataLen = 0;
    uint8_t cmdp = 0;
    uint8_t authenticationkey[16] = {0x00};
    memset(authenticationkey, 0x00, sizeof(authenticationkey));
    uint8_t *authKeyPtr = authenticationkey;

    bool errors = false;
    bool swapEndian = false;
    bool manualPages = false;
    uint8_t startPage = 0;
    uint8_t card_mem_size = 0;
    char tempStr[50];

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_mfu_dump();
            case 'k':
                dataLen = param_getstr(Cmd, cmdp + 1, tempStr, sizeof(tempStr));
                if (dataLen == 32 || dataLen == 8) { //ul-c or ev1/ntag key length
                    errors = param_gethex(tempStr, 0, authenticationkey, dataLen);
                    dataLen /= 2;
                } else {
                    PrintAndLogEx(WARNING, "ERROR: Key is incorrect length\n");
                    errors = true;
                }
                cmdp += 2;
                hasAuthKey = true;
                break;
            case 'l':
                swapEndian = true;
                cmdp++;
                break;
            case 'f':
                fileNameLen = param_getstr(Cmd, cmdp + 1, filename, sizeof(filename));
                cmdp += 2;
                break;
            case 'p': //set start page
                startPage = param_get8(Cmd, cmdp + 1);
                manualPages = true;
                cmdp += 2;
                break;
            case 'q':
                pages = param_get8(Cmd, cmdp + 1);
                cmdp += 2;
                manualPages = true;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors) return usage_hf_mfu_dump();

    //if we entered a key in little endian and set the swapEndian switch - switch it...
    if (swapEndian && hasAuthKey)
        authKeyPtr = SwapEndian64(authenticationkey, dataLen, (dataLen == 16) ? 8 : 4);

    TagTypeUL_t tagtype = GetHF14AMfU_Type();
    if (tagtype == UL_ERROR) return -1;

    //get number of pages to read
    if (!manualPages) {
        for (uint8_t idx = 0; idx < MAX_UL_TYPES; idx++) {
            if (tagtype & UL_TYPES_ARRAY[idx]) {
                //add one as maxblks starts at 0
                card_mem_size = pages = UL_MEMORY_ARRAY[idx] + 1;
                break;
            }
        }
    }
    ul_print_type(tagtype, 0);
    PrintAndLogEx(SUCCESS, "Reading tag memory...");
    UsbCommand c = {CMD_MIFAREU_READCARD, {startPage, pages}};
    if (hasAuthKey) {
        if (tagtype & UL_C)
            c.arg[2] = 1; //UL_C auth
        else
            c.arg[2] = 2; //UL_EV1/NTAG auth

        memcpy(c.d.asBytes, authKeyPtr, dataLen);
    }

    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
        PrintAndLogEx(WARNING, "Command execute time-out");
        return 1;
    }
    if (resp.arg[0] != 1) {
        PrintAndLogEx(WARNING, "Failed reading block: (%02x)", i);
        return 1;
    }

    uint32_t startindex = resp.arg[2];
    uint32_t bufferSize = resp.arg[1];
    if (bufferSize > sizeof(data)) {
        PrintAndLogEx(FAILED, "Data exceeded Buffer size!");
        bufferSize = sizeof(data);
    }

    if (!GetFromDevice(BIG_BUF, data, bufferSize, startindex, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return 1;
    }

    bool is_partial = (pages != bufferSize / 4);

    pages = bufferSize / 4;

    iso14a_card_select_t card;
    mfu_dump_t dump_file_data;
    uint8_t get_pack[] = {0, 0};
    uint8_t get_version[] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t get_tearing[] = {0, 0, 0};
    uint8_t get_counter[] = {0, 0, 0};
    uint8_t dummy_pack[] = {0, 0};
    uint8_t get_signature[32];
    memset(get_signature, 0, sizeof(get_signature));

    // not ul_c and not std ul then attempt to collect info like
    //  VERSION, SIGNATURE, COUNTERS, TEARING, PACK,
    if (!(tagtype & UL_C || tagtype & UL)) {
        //attempt to read pack
        if (!ul_auth_select(&card, tagtype, true, authKeyPtr, get_pack, sizeof(get_pack))) {
            //reset pack
            get_pack[0] = 0;
            get_pack[1] = 0;
        }
        DropField();

        // only add pack if not partial read,  and complete pages read.
        if (!is_partial && pages == card_mem_size) {

            // add pack to block read
            memcpy(data + (pages * 4) - 4, get_pack, sizeof(get_pack));
        }

        if (hasAuthKey)
            ul_auth_select(&card, tagtype, hasAuthKey, authKeyPtr, dummy_pack, sizeof(dummy_pack));
        else
            ul_select(&card);

        ulev1_getVersion(get_version, sizeof(get_version));
        for (uint8_t i = 0; i < 3; ++i) {
            ulev1_readTearing(i, get_tearing + i, 1);
            ulev1_readCounter(i, get_counter, sizeof(get_counter));
        }

        DropField();
        if (hasAuthKey)
            ul_auth_select(&card, tagtype, hasAuthKey, authKeyPtr, dummy_pack, sizeof(dummy_pack));
        else
            ul_select(&card);

        ulev1_readSignature(get_signature, sizeof(get_signature));
        DropField();
    }

    // format and add keys to block dump output
    if (hasAuthKey) {
        // if we didn't swapendian before - do it now for the sprint_hex call
        // NOTE: default entry is bigendian (unless swapped), sprint_hex outputs little endian
        //       need to swap to keep it the same
        if (!swapEndian) {
            authKeyPtr = SwapEndian64(authenticationkey, dataLen, (dataLen == 16) ? 8 : 4);
        } else {
            authKeyPtr = authenticationkey;
        }

        if (tagtype & UL_C) { //add 4 pages
            memcpy(data + pages * 4, authKeyPtr, dataLen);
            pages += dataLen / 4;
        } else { // 2nd page from end
            memcpy(data + (pages * 4) - 8, authenticationkey, dataLen);
        }
    }

    //add *special* blocks to dump
    //iceman:  need to add counters and pwd values to the dump format
    memcpy(dump_file_data.version, get_version, sizeof(dump_file_data.version));
    memcpy(dump_file_data.tearing, get_tearing, sizeof(dump_file_data.tearing));
    memcpy(dump_file_data.pack, get_pack, sizeof(dump_file_data.pack));
    memcpy(dump_file_data.signature, get_signature, sizeof(dump_file_data.signature));
    memcpy(dump_file_data.data, data, pages * 4);

    printMFUdumpEx(&dump_file_data, pages, startPage);

    // user supplied filename?
    if (fileNameLen < 1) {

        PrintAndLogEx(INFO, "Using UID as filename");

        fptr += sprintf(fptr, "hf-mfu-");
        FillFileNameByUID(fptr, card.uid, "-dump", card.uidlen);
    }
    uint16_t datalen = pages * 4 + DUMP_PREFIX_LENGTH;
    saveFile(filename, "bin", (uint8_t *)&dump_file_data, datalen);
    saveFileJSON(filename, "json", jsfMfuMemory, (uint8_t *)&dump_file_data, datalen);

    if (is_partial)
        PrintAndLogEx(WARNING, "Partial dump created. (%d of %d blocks)", pages, card_mem_size);

    return 0;
}

static void wait4response(uint8_t b) {
    UsbCommand resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        uint8_t isOK  = resp.arg[0] & 0xff;
        if (!isOK)
            PrintAndLogEx(WARNING, "failed to write block %d", b);
    } else {
        PrintAndLogEx(WARNING, "Command execute timeout");
    }
}

//
//  Restore dump file onto tag
//
int CmdHF14AMfURestore(const char *Cmd) {

    char tempStr[50] = {0};
    char filename[FILE_PATH_SIZE] = {0};
    uint8_t authkey[16] = {0};
    uint8_t *p_authkey = authkey;
    uint8_t cmdp = 0, keylen = 0;
    bool hasKey = false;
    bool swapEndian = false;
    bool errors = false;
    bool write_special = false;
    bool write_extra = false;
    bool read_key = false;
    size_t filelen = 0;
    FILE *f;
    UsbCommand c = {CMD_MIFAREU_WRITEBL, {0, 0, 0}};

    memset(authkey, 0x00, sizeof(authkey));

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_mfu_restore();
            case 'k':
                keylen = param_getstr(Cmd, cmdp + 1, tempStr, sizeof(tempStr));
                if (keylen == 32 || keylen == 8) { //ul-c or ev1/ntag key length
                    errors = param_gethex(tempStr, 0, authkey, keylen);
                    keylen /= 2;
                } else {
                    PrintAndLogEx(WARNING, "ERROR: Key is incorrect length\n");
                    errors = true;
                }
                cmdp += 2;
                hasKey = true;
                break;
            case 'l':
                swapEndian = true;
                cmdp++;
                break;
            case 'f':
                filelen = param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE);

                if (filelen > FILE_PATH_SIZE - 5)
                    filelen = FILE_PATH_SIZE - 5;

                if (filelen < 1)
                    sprintf(filename, "dumpdata.bin");

                cmdp += 2;
                break;
            case 's':
                cmdp++;
                write_special = true;
                break;
            case 'e':
                cmdp++;
                write_extra = true;
                break;
            case 'r':
                cmdp++;
                read_key = true;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors || cmdp == 0) return usage_hf_mfu_restore();

    if ((f = fopen(filename, "rb")) == NULL) {
        PrintAndLogEx(WARNING, "Could not find file " _YELLOW_("%s"), filename);
        return 1;
    }

    // get filesize to know how memory to allocate
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize < 0) {
        PrintAndLogEx(WARNING, "Error, when getting filesize");
        fclose(f);
        return 1;
    }

    uint8_t *dump = calloc(fsize, sizeof(uint8_t));
    if (!dump) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        fclose(f);
        return 1;
    }

    // read all data
    size_t bytes_read = fread(dump, 1, fsize, f);
    fclose(f);
    if (bytes_read < 48) {
        PrintAndLogEx(WARNING, "Error, dump file is too small");
        free(dump);
        return 1;
    }

    PrintAndLogEx(INFO, "Restoring " _YELLOW_("%s")" to card", filename);

    mfu_dump_t *mem = (mfu_dump_t *)dump;
    uint8_t pages = (bytes_read - 48) / 4;

    // print dump
    printMFUdumpEx(mem, pages, 0);

    // Swap endianness
    if (swapEndian && hasKey) {
        if (keylen == 16)
            p_authkey = SwapEndian64(authkey, keylen, 8);
        else
            p_authkey = SwapEndian64(authkey, keylen, 4);
    }

    // set key - only once
    if (hasKey) {
        c.arg[1] = (keylen == 16) ? 1 : 2;
        memcpy(c.d.asBytes + 4, p_authkey, keylen);
    }

    // write version, signature, pack
    // only magic NTAG cards
    if (write_extra) {

#define MFU_NTAG_SPECIAL_PWD        0xF0
#define MFU_NTAG_SPECIAL_PACK       0xF1
#define MFU_NTAG_SPECIAL_VERSION    0xFA
#define MFU_NTAG_SPECIAL_SIGNATURE  0xF2
        // pwd
        if (hasKey || read_key) {
            c.arg[0] = MFU_NTAG_SPECIAL_PWD;

            if (read_key) {
                // try reading key from dump and use.
                memcpy(c.d.asBytes, mem->data + (bytes_read - 48 - 8), 4);
            } else {
                memcpy(c.d.asBytes,  p_authkey, 4);
            }

            PrintAndLogEx(NORMAL, "special PWD     block written 0x%X - %s\n", MFU_NTAG_SPECIAL_PWD, sprint_hex(c.d.asBytes, 4));
            clearCommandBuffer();
            SendCommand(&c);
            wait4response(MFU_NTAG_SPECIAL_PWD);

            // copy the new key
            c.arg[1] = 2;
            memcpy(authkey, c.d.asBytes, 4);
            memcpy(c.d.asBytes + 4, authkey, 4);
        }

        // pack
        c.arg[0] = MFU_NTAG_SPECIAL_PACK;
        c.d.asBytes[0] = mem->pack[0];
        c.d.asBytes[1] = mem->pack[1];
        c.d.asBytes[2] = 0;
        c.d.asBytes[3] = 0;
        PrintAndLogEx(NORMAL, "special PACK    block written 0x%X - %s\n", MFU_NTAG_SPECIAL_PACK, sprint_hex(c.d.asBytes, 4));
        clearCommandBuffer();
        SendCommand(&c);
        wait4response(MFU_NTAG_SPECIAL_PACK);

        // Signature
        for (uint8_t s = MFU_NTAG_SPECIAL_SIGNATURE, i = 0; s < MFU_NTAG_SPECIAL_SIGNATURE + 8; s++, i += 4) {
            c.arg[0] = s;
            memcpy(c.d.asBytes, mem->signature + i, 4);
            PrintAndLogEx(NORMAL, "special SIG     block written 0x%X - %s\n", s, sprint_hex(c.d.asBytes, 4));
            clearCommandBuffer();
            SendCommand(&c);
            wait4response(s);
        }

        // Version
        for (uint8_t s = MFU_NTAG_SPECIAL_VERSION, i = 0; s < MFU_NTAG_SPECIAL_VERSION + 2; s++, i += 4) {
            c.arg[0] = s;
            memcpy(c.d.asBytes, mem->version + i, 4);
            PrintAndLogEx(NORMAL, "special VERSION block written 0x%X - %s\n", s, sprint_hex(c.d.asBytes, 4));
            clearCommandBuffer();
            SendCommand(&c);
            wait4response(s);
        }
    }

    PrintAndLogEx(INFO, "Restoring data blocks.");
    // write all other data
    // Skip block 0,1,2,3 (only magic tags can write to them)
    // Skip last 5 blocks usually is configuration
    for (uint8_t b = 4; b < pages - 5; b++) {

        //Send write Block
        c.arg[0] = b;
        memcpy(c.d.asBytes, mem->data + (b * 4), 4);
        clearCommandBuffer();
        SendCommand(&c);
        wait4response(b);
        printf(".");
        fflush(stdout);
    }
    PrintAndLogEx(NORMAL, "\n");

    // write special data last
    if (write_special) {

        PrintAndLogEx(INFO, "Restoring configuration blocks.\n");

        PrintAndLogEx(NORMAL, "authentication with keytype[%x]  %s\n", (uint8_t)(c.arg[1] & 0xff), sprint_hex(p_authkey, 4));

        // otp, uid, lock, cfg1, cfg0, dynlockbits
        uint8_t blocks[] = {3, 0, 1, 2, pages - 5, pages - 4, pages - 3};
        for (uint8_t i = 0; i < sizeof(blocks); i++) {
            uint8_t b = blocks[i];
            c.arg[0] = b;
            memcpy(c.d.asBytes, mem->data + (b * 4), 4);
            clearCommandBuffer();
            SendCommand(&c);
            wait4response(b);
            PrintAndLogEx(NORMAL, "special block written %u - %s\n", b, sprint_hex(c.d.asBytes, 4));
        }
    }

    DropField();
    free(dump);
    return 0;
}
//
//  Load emulator with dump file
//
int CmdHF14AMfUeLoad(const char *Cmd) {
    char c = tolower(param_getchar(Cmd, 0));
    if (c == 'h' || c == 0x00) return usage_hf_mfu_eload();
    return CmdHF14AMfELoad(Cmd);
}
//
//  Simulate tag
//
int CmdHF14AMfUSim(const char *Cmd) {
    char c = tolower(param_getchar(Cmd, 0));
    if (c == 'h' || c == 0x00) return usage_hf_mfu_sim();
    return CmdHF14ASim(Cmd);
}

//-------------------------------------------------------------------------------
// Ultralight C Methods
//-------------------------------------------------------------------------------

//
// Ultralight C Authentication Demo {currently uses hard-coded key}
//
int CmdHF14AMfucAuth(const char *Cmd) {

    uint8_t keyNo = 3;
    bool errors = false;

    char cmdp = tolower(param_getchar(Cmd, 0));

    //Change key to user defined one
    if (cmdp == 'k') {
        keyNo = param_get8(Cmd, 1);
        if (keyNo >= KEYS_3DES_COUNT)
            errors = true;
    }

    if (cmdp == 'h') errors = true;

    if (errors) return usage_hf_mfu_ucauth();

    uint8_t *key = default_3des_keys[keyNo];
    if (ulc_authentication(key, true))
        PrintAndLogEx(SUCCESS, "Authentication successful. 3des key: %s", sprint_hex(key, 16));
    else
        PrintAndLogEx(WARNING, "Authentication failed");

    return 0;
}

/**
A test function to validate that the polarssl-function works the same
was as the openssl-implementation.
Commented out, since it requires openssl

int CmdTestDES(const char * cmd)
{
    uint8_t key[16] = {0x00};

    memcpy(key,key3_3des_data,16);
    DES_cblock RndA, RndB;

    PrintAndLogEx(NORMAL, "----------OpenSSL DES implementation----------");
    {
        uint8_t e_RndB[8] = {0x00};
        unsigned char RndARndB[16] = {0x00};

        DES_cblock iv = { 0 };
        DES_key_schedule ks1,ks2;
        DES_cblock key1,key2;

        memcpy(key,key3_3des_data,16);
        memcpy(key1,key,8);
        memcpy(key2,key+8,8);


        DES_set_key((DES_cblock *)key1,&ks1);
        DES_set_key((DES_cblock *)key2,&ks2);

        DES_random_key(&RndA);
        PrintAndLogEx(NORMAL, "     RndA:%s",sprint_hex(RndA, 8));
        PrintAndLogEx(NORMAL, "     e_RndB:%s",sprint_hex(e_RndB, 8));
        //void DES_ede2_cbc_encrypt(const unsigned char *input,
        //    unsigned char *output, long length, DES_key_schedule *ks1,
        //    DES_key_schedule *ks2, DES_cblock *ivec, int enc);
        DES_ede2_cbc_encrypt(e_RndB,RndB,sizeof(e_RndB),&ks1,&ks2,&iv,0);

        PrintAndLogEx(NORMAL, "     RndB:%s",sprint_hex(RndB, 8));
        rol(RndB,8);
        memcpy(RndARndB,RndA,8);
        memcpy(RndARndB+8,RndB,8);
        PrintAndLogEx(NORMAL, "     RA+B:%s",sprint_hex(RndARndB, 16));
        DES_ede2_cbc_encrypt(RndARndB,RndARndB,sizeof(RndARndB),&ks1,&ks2,&e_RndB,1);
        PrintAndLogEx(NORMAL, "enc(RA+B):%s",sprint_hex(RndARndB, 16));

    }
    PrintAndLogEx(NORMAL, "----------PolarSSL implementation----------");
    {
        uint8_t random_a[8]     = { 0 };
        uint8_t enc_random_a[8] = { 0 };
        uint8_t random_b[8]     = { 0 };
        uint8_t enc_random_b[8] = { 0 };
        uint8_t random_a_and_b[16] = { 0 };
        des3_context ctx        = { 0 };

        memcpy(random_a, RndA,8);

        uint8_t output[8]       = { 0 };
        uint8_t iv[8]           = { 0 };

        PrintAndLogEx(NORMAL, "     RndA  :%s",sprint_hex(random_a, 8));
        PrintAndLogEx(NORMAL, "     e_RndB:%s",sprint_hex(enc_random_b, 8));

        des3_set2key_dec(&ctx, key);

        des3_crypt_cbc(&ctx      // des3_context *ctx
            , DES_DECRYPT        // int mode
            , sizeof(random_b)   // size_t length
            , iv                 // unsigned char iv[8]
            , enc_random_b       // const unsigned char *input
            , random_b           // unsigned char *output
            );

        PrintAndLogEx(NORMAL, "     RndB:%s",sprint_hex(random_b, 8));

        rol(random_b,8);
        memcpy(random_a_and_b  ,random_a,8);
        memcpy(random_a_and_b+8,random_b,8);

        PrintAndLogEx(NORMAL, "     RA+B:%s",sprint_hex(random_a_and_b, 16));

        des3_set2key_enc(&ctx, key);

        des3_crypt_cbc(&ctx          // des3_context *ctx
            , DES_ENCRYPT            // int mode
            , sizeof(random_a_and_b)   // size_t length
            , enc_random_b           // unsigned char iv[8]
            , random_a_and_b         // const unsigned char *input
            , random_a_and_b         // unsigned char *output
            );

        PrintAndLogEx(NORMAL, "enc(RA+B):%s",sprint_hex(random_a_and_b, 16));
    }
    return 0;
}
**/

//
// Mifare Ultralight C - Set password
//
int CmdHF14AMfucSetPwd(const char *Cmd) {

    uint8_t pwd[16] = {0x00};
    char cmdp = tolower(param_getchar(Cmd, 0));

    if (strlen(Cmd) == 0  || cmdp == 'h') return usage_hf_mfu_ucsetpwd();

    if (param_gethex(Cmd, 0, pwd, 32)) {
        PrintAndLogEx(WARNING, "Password must include 32 HEX symbols");
        return 1;
    }

    UsbCommand c = {CMD_MIFAREUC_SETPWD};
    memcpy(c.d.asBytes, pwd, 16);
    clearCommandBuffer();
    SendCommand(&c);

    UsbCommand resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        if ((resp.arg[0] & 0xff) == 1) {
            PrintAndLogEx(INFO, "Ultralight-C new password: %s", sprint_hex(pwd, 16));
        } else {
            PrintAndLogEx(WARNING, "Failed writing at block %d", resp.arg[1] & 0xff);
            return 1;
        }
    } else {
        PrintAndLogEx(WARNING, "command execution time out");
        return 1;
    }
    return 0;
}

//
// Magic UL / UL-C tags  - Set UID
//
int CmdHF14AMfucSetUid(const char *Cmd) {

    UsbCommand c = {CMD_MIFAREU_READBL};
    UsbCommand resp;
    uint8_t uid[7] = {0x00};
    char cmdp = tolower(param_getchar(Cmd, 0));

    if (strlen(Cmd) == 0  || cmdp == 'h') return usage_hf_mfu_ucsetuid();

    if (param_gethex(Cmd, 0, uid, 14)) {
        PrintAndLogEx(WARNING, "UID must include 14 HEX symbols");
        return 1;
    }

    // read block2.
    c.arg[0] = 2;
    clearCommandBuffer();
    SendCommand(&c);
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        PrintAndLogEx(WARNING, "Command execute timeout");
        return 2;
    }

    // save old block2.
    uint8_t oldblock2[4] = {0x00};
    memcpy(resp.d.asBytes, oldblock2, 4);

    // block 0.
    c.cmd = CMD_MIFAREU_WRITEBL;
    c.arg[0] = 0;
    c.d.asBytes[0] = uid[0];
    c.d.asBytes[1] = uid[1];
    c.d.asBytes[2] = uid[2];
    c.d.asBytes[3] =  0x88 ^ uid[0] ^ uid[1] ^ uid[2];
    clearCommandBuffer();
    SendCommand(&c);
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        PrintAndLogEx(WARNING, "Command execute timeout");
        return 3;
    }

    // block 1.
    c.arg[0] = 1;
    c.d.asBytes[0] = uid[3];
    c.d.asBytes[1] = uid[4];
    c.d.asBytes[2] = uid[5];
    c.d.asBytes[3] = uid[6];
    clearCommandBuffer();
    SendCommand(&c);
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        PrintAndLogEx(WARNING, "Command execute timeout");
        return 4;
    }

    // block 2.
    c.arg[0] = 2;
    c.d.asBytes[0] = uid[3] ^ uid[4] ^ uid[5] ^ uid[6];
    c.d.asBytes[1] = oldblock2[1];
    c.d.asBytes[2] = oldblock2[2];
    c.d.asBytes[3] = oldblock2[3];
    clearCommandBuffer();
    SendCommand(&c);
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        PrintAndLogEx(WARNING, "Command execute timeout");
        return 5;
    }
    return 0;
}

int CmdHF14AMfuGenDiverseKeys(const char *Cmd) {

    uint8_t uid[4];
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0  || cmdp == 'h') return usage_hf_mfu_gendiverse();

    if (cmdp == 'r') {
        // read uid from tag
        UsbCommand c = {CMD_READER_ISO_14443a, {ISO14A_CONNECT | ISO14A_NO_RATS, 0, 0}};
        clearCommandBuffer();
        SendCommand(&c);
        UsbCommand resp;
        WaitForResponse(CMD_ACK, &resp);
        iso14a_card_select_t card;
        memcpy(&card, (iso14a_card_select_t *)resp.d.asBytes, sizeof(iso14a_card_select_t));

        uint64_t select_status = resp.arg[0];
        // 0: couldn't read,
        // 1: OK, with ATS
        // 2: OK, no ATS
        // 3: proprietary Anticollision

        if (select_status == 0) {
            PrintAndLogEx(WARNING, "iso14443a card select failed");
            return 1;
        }
        if (card.uidlen != 4) {
            PrintAndLogEx(WARNING, "Wrong sized UID, expected 4bytes got %d", card.uidlen);
            return 1;
        }
        memcpy(uid, card.uid, sizeof(uid));
    } else {
        if (param_gethex(Cmd, 0, uid, 8)) return usage_hf_mfu_gendiverse();
    }


    uint8_t iv[8] = { 0x00 };
    uint8_t block = 0x01;

    uint8_t mifarekeyA[] = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5 };
    uint8_t mifarekeyB[] = { 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5 };
    uint8_t dkeyA[8] = { 0x00 };
    uint8_t dkeyB[8] = { 0x00 };

    uint8_t masterkey[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

    uint8_t mix[8] = { 0x00 };
    uint8_t divkey[8] = { 0x00 };

    memcpy(mix, mifarekeyA, 4);

    mix[4] = mifarekeyA[4] ^ uid[0];
    mix[5] = mifarekeyA[5] ^ uid[1];
    mix[6] = block ^ uid[2];
    mix[7] = uid[3];

    mbedtls_des3_context ctx;
    mbedtls_des3_set2key_enc(&ctx, masterkey);

    mbedtls_des3_crypt_cbc(&ctx  // des3_context
                           , MBEDTLS_DES_ENCRYPT    // int mode
                           , sizeof(mix)    // length
                           , iv             // iv[8]
                           , mix            // input
                           , divkey         // output
                          );

    PrintAndLogEx(NORMAL, "-- 3DES version");
    PrintAndLogEx(NORMAL, "Masterkey    :\t %s", sprint_hex(masterkey, sizeof(masterkey)));
    PrintAndLogEx(NORMAL, "UID          :\t %s", sprint_hex(uid, sizeof(uid)));
    PrintAndLogEx(NORMAL, "block        :\t %0d", block);
    PrintAndLogEx(NORMAL, "Mifare key   :\t %s", sprint_hex(mifarekeyA, sizeof(mifarekeyA)));
    PrintAndLogEx(NORMAL, "Message      :\t %s", sprint_hex(mix, sizeof(mix)));
    PrintAndLogEx(NORMAL, "Diversified key: %s", sprint_hex(divkey + 1, 6));

    for (int i = 0; i < sizeof(mifarekeyA); ++i) {
        dkeyA[i]  = (mifarekeyA[i] << 1) & 0xff;
        dkeyA[6] |= ((mifarekeyA[i] >> 7) & 1) << (i + 1);
    }

    for (int i = 0; i < sizeof(mifarekeyB); ++i) {
        dkeyB[1]  |= ((mifarekeyB[i] >> 7) & 1) << (i + 1);
        dkeyB[2 + i] = (mifarekeyB[i] << 1) & 0xff;
    }

    uint8_t zeros[8] = {0x00};
    uint8_t newpwd[8] = {0x00};
    uint8_t dmkey[24] = {0x00};
    memcpy(dmkey, dkeyA, 8);
    memcpy(dmkey + 8, dkeyB, 8);
    memcpy(dmkey + 16, dkeyA, 8);
    memset(iv, 0x00, 8);

    mbedtls_des3_set3key_enc(&ctx, dmkey);

    mbedtls_des3_crypt_cbc(&ctx  // des3_context
                           , MBEDTLS_DES_ENCRYPT    // int mode
                           , sizeof(newpwd) // length
                           , iv             // iv[8]
                           , zeros         // input
                           , newpwd         // output
                          );

    PrintAndLogEx(NORMAL, "\n-- DES version");
    PrintAndLogEx(NORMAL, "Mifare dkeyA :\t %s", sprint_hex(dkeyA, sizeof(dkeyA)));
    PrintAndLogEx(NORMAL, "Mifare dkeyB :\t %s", sprint_hex(dkeyB, sizeof(dkeyB)));
    PrintAndLogEx(NORMAL, "Mifare ABA   :\t %s", sprint_hex(dmkey, sizeof(dmkey)));
    PrintAndLogEx(NORMAL, "Mifare Pwd   :\t %s", sprint_hex(newpwd, sizeof(newpwd)));

    // next. from the diversify_key method.
    return 0;
}

int CmdHF14AMfuPwdGen(const char *Cmd) {

    uint8_t uid[7] = {0x00};
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0  || cmdp == 'h') return usage_hf_mfu_pwdgen();

    if (cmdp == 't') return ul_ev1_pwdgen_selftest();

    if (cmdp == 'r') {
        // read uid from tag
        UsbCommand c = {CMD_READER_ISO_14443a, {ISO14A_CONNECT | ISO14A_NO_RATS, 0, 0}};
        clearCommandBuffer();
        SendCommand(&c);
        UsbCommand resp;
        WaitForResponse(CMD_ACK, &resp);
        iso14a_card_select_t card;
        memcpy(&card, (iso14a_card_select_t *)resp.d.asBytes, sizeof(iso14a_card_select_t));

        uint64_t select_status = resp.arg[0];
        // 0: couldn't read
        // 1: OK with ATS
        // 2: OK, no ATS
        // 3: proprietary Anticollision
        if (select_status == 0) {
            PrintAndLogEx(WARNING, "iso14443a card select failed");
            return 1;
        }
        if (card.uidlen != 7) {
            PrintAndLogEx(WARNING, "Wrong sized UID, expected 7bytes got %d", card.uidlen);
            return 1;
        }
        memcpy(uid, card.uid, sizeof(uid));
    } else {
        if (param_gethex(Cmd, 0, uid, 14)) return usage_hf_mfu_pwdgen();
    }

    PrintAndLogEx(NORMAL, "---------------------------------");
    PrintAndLogEx(NORMAL, " Using UID : %s", sprint_hex(uid, 7));
    PrintAndLogEx(NORMAL, "---------------------------------");
    PrintAndLogEx(NORMAL, " algo | pwd      | pack");
    PrintAndLogEx(NORMAL, "------+----------+-----");
    PrintAndLogEx(NORMAL, " EV1  | %08X | %04X", ul_ev1_pwdgenA(uid), ul_ev1_packgenA(uid));
    PrintAndLogEx(NORMAL, " Ami  | %08X | %04X", ul_ev1_pwdgenB(uid), ul_ev1_packgenB(uid));
    PrintAndLogEx(NORMAL, " LD   | %08X | %04X", ul_ev1_pwdgenC(uid), ul_ev1_packgenC(uid));
    PrintAndLogEx(NORMAL, " XYZ  | %08X | %04X", ul_ev1_pwdgenD(uid), ul_ev1_packgenD(uid));
    PrintAndLogEx(NORMAL, "------+----------+-----");
    PrintAndLogEx(NORMAL, " Vingcard algo");
    PrintAndLogEx(NORMAL, "--------------------");
    return 0;
}
//------------------------------------
// Menu Stuff
//------------------------------------
static command_t CommandTable[] = {
    {"help",    CmdHelp,            1, "This help"},
    {"dbg",     CmdHF14AMfDbg,      0, "Set default debug mode"},
    {"info",    CmdHF14AMfUInfo,    0, "Tag information"},
    {"dump",    CmdHF14AMfUDump,    0, "Dump Ultralight / Ultralight-C / NTAG tag to binary file"},
    {"restore", CmdHF14AMfURestore, 0, "Restore a dump onto a MFU MAGIC tag"},
    {"eload",   CmdHF14AMfUeLoad,   0, "load Ultralight .eml dump file into emulator memory"},
    {"rdbl",    CmdHF14AMfURdBl,    0, "Read block"},
    {"wrbl",    CmdHF14AMfUWrBl,    0, "Write block"},
    {"cauth",   CmdHF14AMfucAuth,   0, "Authentication    - Ultralight C"},
    {"setpwd",  CmdHF14AMfucSetPwd, 0, "Set 3des password - Ultralight-C"},
    {"setuid",  CmdHF14AMfucSetUid, 0, "Set UID - MAGIC tags only"},
    {"sim",     CmdHF14AMfUSim,     0, "Simulate Ultralight from emulator memory"},
    {"gen",     CmdHF14AMfuGenDiverseKeys, 1, "Generate 3des mifare diversified keys"},
    {"pwdgen",  CmdHF14AMfuPwdGen,  1, "Generate pwd from known algos"},
    {NULL, NULL, 0, NULL}
};

int CmdHFMFUltra(const char *Cmd) {
    clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}
