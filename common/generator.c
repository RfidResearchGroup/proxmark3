//-----------------------------------------------------------------------------
// Copyright (C) 2019 iceman <iceman at iuse.se>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Generator commands
//-----------------------------------------------------------------------------
#include "generator.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <inttypes.h>
#include <string.h>
#include "commonutil.h"
#include "util.h"
#include "pm3_cmd.h"
#include "ui.h"

// Implemetation tips:
// For each implementation of the algos, I recommend adding a self test for easy "simple unit" tests when Travic CI / Appveyour runs.
// See special note for MFC based algos.

//------------------------------------
// MFU/NTAG PWD/PACK generation stuff
// Italian transport system 
// Amiibo
// Lego Dimension
// XYZ 3D printing
// Vinglock
//------------------------------------
const uint32_t c_D[] = {
    0x6D835AFC, 0x7D15CD97, 0x0942B409, 0x32F9C923, 0xA811FB02, 0x64F121E8,
    0xD1CC8B4E, 0xE8873E6F, 0x61399BBB, 0xF1B91926, 0xAC661520, 0xA21A31C9,
    0xD424808D, 0xFE118E07, 0xD18E728D, 0xABAC9E17, 0x18066433, 0x00E18E79,
    0x65A77305, 0x5AE9E297, 0x11FC628C, 0x7BB3431F, 0x942A8308, 0xB2F8FD20,
    0x5728B869, 0x30726D5A
};

static void transform_D(uint8_t *ru) {
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

// Transport system (IT) pwd generation algo nickname A.
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

// Amiibo pwd generation algo nickname B. (very simple)
uint32_t ul_ev1_pwdgenB(uint8_t *uid) {

    uint8_t pwd[] = {0x00, 0x00, 0x00, 0x00};

    pwd[0] = uid[1] ^ uid[3] ^ 0xAA;
    pwd[1] = uid[2] ^ uid[4] ^ 0x55;
    pwd[2] = uid[3] ^ uid[5] ^ 0xAA;
    pwd[3] = uid[4] ^ uid[6] ^ 0x55;
    return (uint32_t)bytes_to_num(pwd, 4);
}

// Lego Dimension pwd generation algo nickname C.
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

// XYZ 3d printing pwd generation algo nickname D.
uint32_t ul_ev1_pwdgenD(uint8_t *uid) {
    uint8_t i;
    uint8_t r = (uid[1] + uid[3] + uid[5]) & 7; // rotation offset
    uint8_t ru[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // rotated UID
    for (i = 0; i < 7; i++)
        ru[(i + r) & 7] = uid[i];

    transform_D(ru);

    // calc key
    uint32_t pwd = 0;
    r = (ru[0] + ru[2] + ru[4] + ru[6]) & 3; // offset
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

//------------------------------------
// MFC key generation stuff
// Each algo implementation should offer two key generation functions.
// 1. function that returns all keys
// 2. function that returns one key, target sector | block
//------------------------------------

//------------------------------------
// MFC keyfile generation stuff
//------------------------------------
// Vinglock
int mfc_algo_ving_one(uint8_t *uid, uint8_t sector, uint64_t *key) {
    if (sector > 15) return PM3_EINVARG;
    if (key == NULL) return PM3_EINVARG;
    return PM3_SUCCESS;
}
int mfc_algo_ving_all(uint8_t *uid, uint8_t *keys) {
    if (keys == NULL) return PM3_EINVARG;
    return PM3_SUCCESS;
}

// Yale Doorman
int mfc_algo_yale_one(uint8_t *uid, uint8_t sector, uint64_t *key) {
    if (sector > 15) return PM3_EINVARG;
    if (key == NULL) return PM3_EINVARG;
    return PM3_SUCCESS;
}
int mfc_algo_yale_all(uint8_t *uid, uint8_t *keys) {
    if (keys == NULL) return PM3_EINVARG;
    return PM3_SUCCESS;
}

// Saflok / Maid UID to key.
int mfc_algo_saflok_one(uint8_t *uid, uint8_t sector, uint64_t *key) {
    if (sector > 15) return PM3_EINVARG;
    if (key == NULL) return PM3_EINVARG;
    return PM3_SUCCESS;
}
int mfc_algo_saflok_all(uint8_t *uid, uint8_t *keys) {
    if (keys == NULL) return PM3_EINVARG;
    return PM3_SUCCESS;
}

// MIZIP algo
int mfc_algo_mizip_one(uint8_t *uid, uint8_t sector, uint64_t *key) {
    if (sector > 4) return PM3_EINVARG;
    if (key == NULL) return PM3_EINVARG;
    return PM3_SUCCESS;
}
// returns all Mifare Mini (MFM) 10 keys.
// keys must have 5*2*6 = 60bytes space
int mfc_algo_mizip_all(uint8_t *uid, uint8_t *keys) {  
    if (keys == NULL) return PM3_EINVARG;
    
    uint64_t xor_tbl[] = {
        0x09125a2589e5ULL, 0xF12C8453D821ULL,
        0xAB75C937922FULL, 0x73E799FE3241ULL,
        0xE27241AF2C09ULL, 0xAA4D137656AEULL,
        0x317AB72F4490ULL, 0xB01327272DFDULL
    };

    // A
    num_to_bytes(0xA0A1A2A3A4A5ULL, 6, keys);
    for (uint8_t i = 0; i < 4; i++) {
        uint64_t a =
            (uint64_t)(uid[0] ^ xor_tbl[i]) << 40 |
            (uint64_t)(uid[1] ^ xor_tbl[i]) << 32 |
            (uint64_t)(uid[2] ^ xor_tbl[i]) << 24 |
            (uint64_t)(uid[3] ^ xor_tbl[i]) << 16 |
            (uint64_t)(uid[1] ^ xor_tbl[i]) <<  8 |
            (uint64_t)(uid[2] ^ xor_tbl[i])
            ;
        num_to_bytes(a, 6, keys + (1 * i * 6));
    }

    // B
    num_to_bytes(0xB4C132439eefULL, 6, keys + (5 * 6));
    for (uint8_t i = 0; i < 4; i++) {
        uint64_t b =
            (uint64_t)(uid[2] ^ xor_tbl[i + 1]) << 40 |
            (uint64_t)(uid[3] ^ xor_tbl[i + 1]) << 32 |
            (uint64_t)(uid[0] ^ xor_tbl[i + 1]) << 24 |
            (uint64_t)(uid[1] ^ xor_tbl[i + 1]) << 16 |
            (uint64_t)(uid[2] ^ xor_tbl[i + 1]) <<  8 |
            (uint64_t)(uid[3] ^ xor_tbl[i + 1])
            ;
        num_to_bytes(b, 6, keys + 30 + (1 * i * 6));
    }
    return PM3_SUCCESS;
}

// Disney Infinity algo
int mfc_algo_di_one(uint8_t *uid, uint8_t sector, uint64_t *key) {
    if (sector > 15) return PM3_EINVARG;
    if (key == NULL) return PM3_EINVARG;
    return PM3_SUCCESS;
}
int mfc_algo_di_all(uint8_t *uid, uint8_t *keys) {
    if (keys == NULL) return PM3_EINVARG;
    return PM3_SUCCESS;
}

// Skylanders
int mfc_algo_sky_one(uint8_t *uid, uint8_t sector, uint64_t *key) {
    if (sector > 15) return PM3_EINVARG;
    if (key == NULL) return PM3_EINVARG;
    return PM3_SUCCESS;
}
int mfc_algo_sky_all(uint8_t *uid, uint8_t *keys) {
    if (keys == NULL) return PM3_EINVARG;
    return PM3_SUCCESS;
}


//------------------------------------
// Self tests
//------------------------------------
int generator_selftest() {

    PrintAndLogEx(SUCCESS, "Generators selftest");
    PrintAndLogEx(SUCCESS, "-------------------");

    bool success;

    uint8_t uid1[] = {0x04, 0x11, 0x12, 0x11, 0x12, 0x11, 0x10};
    uint32_t pwd1 = ul_ev1_pwdgenA(uid1);
    success = (pwd1 == 0x8432EB17);
    PrintAndLogEx(success ? SUCCESS : WARNING, "UID | %s | %08X | %s", sprint_hex(uid1, 7), pwd1, success ? "OK" : "->8432EB17<-");

    uint8_t uid2[] = {0x04, 0x1f, 0x98, 0xea, 0x1e, 0x3e, 0x81};
    uint32_t pwd2 = ul_ev1_pwdgenB(uid2);
    success = (pwd2 == 0x5fd37eca);
    PrintAndLogEx(success ? SUCCESS : WARNING, "UID | %s | %08X | %s", sprint_hex(uid2, 7), pwd2, success ? "OK" : "->5fd37eca<--");

    uint8_t uid3[] = {0x04, 0x62, 0xB6, 0x8A, 0xB4, 0x42, 0x80};
    uint32_t pwd3 = ul_ev1_pwdgenC(uid3);
    success = (pwd3 == 0x5a349515);
    PrintAndLogEx(success ? SUCCESS : WARNING, "UID | %s | %08X | %s", sprint_hex(uid3, 7), pwd3, success ? "OK" : "->5a349515<--");

    uint8_t uid4[] = {0x04, 0xC5, 0xDF, 0x4A, 0x6D, 0x51, 0x80};
    uint32_t pwd4 = ul_ev1_pwdgenD(uid4);
    success = (pwd4 == 0x72B1EC61);
    PrintAndLogEx(success ? SUCCESS : WARNING, "UID | %s | %08X | %s", sprint_hex(uid4, 7), pwd4, success ? "OK" : "->72B1EC61<--");

//    uint8_t uid5[] = {0x11, 0x22, 0x33, 0x44};
//    uint64_t key1 = mfc_algo_a(uid5);
//    success = (key1 == 0xD1E2AA68E39A);
//    PrintAndLogEx(success ? SUCCESS : WARNING, "UID | %s | %"PRIx64" | %s", sprint_hex(uid5, 4), key1, success ? "OK" : "->D1E2AA68E39A<--");

    PrintAndLogEx(SUCCESS, "-------------------");
    return PM3_SUCCESS;
}

