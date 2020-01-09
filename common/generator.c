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
#include "commonutil.h"   //BSWAP_16
#include "common.h"       //BSWAP_32/64
#include "util.h"
#include "pm3_cmd.h"
#include "ui.h"
#include "mbedtls/sha1.h"

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
static void transform_D(uint8_t *ru) {

const uint32_t c_D[] = {
    0x6D835AFC, 0x7D15CD97, 0x0942B409, 0x32F9C923, 0xA811FB02, 0x64F121E8,
    0xD1CC8B4E, 0xE8873E6F, 0x61399BBB, 0xF1B91926, 0xAC661520, 0xA21A31C9,
    0xD424808D, 0xFE118E07, 0xD18E728D, 0xABAC9E17, 0x18066433, 0x00E18E79,
    0x65A77305, 0x5AE9E297, 0x11FC628C, 0x7BB3431F, 0x942A8308, 0xB2F8FD20,
    0x5728B869, 0x30726D5A
};

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
int mfc_algo_ving_one(uint8_t *uid, uint8_t sector, uint8_t keytype, uint64_t *key) {
    if (sector > 15) return PM3_EINVARG;
    if (key == NULL) return PM3_EINVARG;
    *key = 0;
    return PM3_SUCCESS;
}
int mfc_algo_ving_all(uint8_t *uid, uint8_t *keys) {
    if (keys == NULL) return PM3_EINVARG;
    for (int keytype = 0; keytype < 2; keytype++) {
        for (int sector = 0; sector < 16; sector++){
            uint64_t key = 0;
            mfc_algo_ving_one(uid, sector, keytype, &key );
            num_to_bytes(key, 6, keys + (keytype * 16 * 6) + (sector * 6));
        }
    }
    return PM3_SUCCESS;
}

// Yale Doorman
int mfc_algo_yale_one(uint8_t *uid, uint8_t sector, uint8_t keytype, uint64_t *key) {
    if (sector > 15) return PM3_EINVARG;
    if (key == NULL) return PM3_EINVARG;
    *key = 0;
    return PM3_SUCCESS;
}
int mfc_algo_yale_all(uint8_t *uid, uint8_t *keys) {
    if (keys == NULL) return PM3_EINVARG;
    for (int keytype = 0; keytype < 2; keytype++) {
        for (int sector = 0; sector < 16; sector++){
            uint64_t key = 0;
            mfc_algo_yale_one(uid, sector, keytype, &key );
            num_to_bytes(key, 6, keys + (keytype * 16 * 6) + (sector * 6));
        }
    }
    return PM3_SUCCESS;
}

// Saflok / Maid UID to key.
int mfc_algo_saflok_one(uint8_t *uid, uint8_t sector, uint8_t keytype, uint64_t *key) {
    if (sector > 15) return PM3_EINVARG;
    if (key == NULL) return PM3_EINVARG;
    *key = 0;
    return PM3_SUCCESS;
}
int mfc_algo_saflok_all(uint8_t *uid, uint8_t *keys) {
    if (keys == NULL) return PM3_EINVARG;

    for (int keytype = 0; keytype < 2; keytype++) {
        for (int sector = 0; sector < 16; sector++){
            uint64_t key = 0;
            mfc_algo_saflok_one(uid, sector, keytype, &key );
            num_to_bytes(key, 6, keys + (keytype * 16 * 6) + (sector * 6));
        }
    }
    return PM3_SUCCESS;
}

// MIZIP algo
int mfc_algo_mizip_one(uint8_t *uid, uint8_t sector, uint8_t keytype, uint64_t *key) {
    if (sector > 4) return PM3_EINVARG;
    if (key == NULL) return PM3_EINVARG;

    if (sector == 0) {
        // A
        if (keytype == 0)
	    *key = 0xA0A1A2A3A4A5U;
	else    // B
	    *key = 0xB4C132439eef;

    } else {

       uint8_t xor[6];

        if ( keytype == 0 ) {

            uint64_t xor_tbl_a[] = {
                0x09125a2589e5,
                0xAB75C937922F,
                0xE27241AF2C09,
                0x317AB72F4490,
            };

            num_to_bytes(xor_tbl_a[sector - 1], 6, xor);

            *key =
                (uint64_t)(uid[0] ^ xor[0] ) << 40 |
                (uint64_t)(uid[1] ^ xor[1]) << 32 |
                (uint64_t)(uid[2] ^ xor[2]) << 24 |
                (uint64_t)(uid[3] ^ xor[3]) << 16 |
                (uint64_t)(uid[0] ^ xor[4]) <<  8 |
                (uint64_t)(uid[1] ^ xor[5])
                ;

        } else {
            uint64_t xor_tbl_b[] = {
                0xF12C8453D821,
                0x73E799FE3241,
                0xAA4D137656AE,
                0xB01327272DFD
            };

            // B
            num_to_bytes(xor_tbl_b[sector - 1], 6, xor);

            *key =
                (uint64_t)(uid[2] ^ xor[0]) << 40 |
                (uint64_t)(uid[3] ^ xor[1]) << 32 |
                (uint64_t)(uid[0] ^ xor[2]) << 24 |
                (uint64_t)(uid[1] ^ xor[3]) << 16 |
                (uint64_t)(uid[2] ^ xor[4]) <<  8 |
                (uint64_t)(uid[3] ^ xor[5])
                ;

        }
    }
    return PM3_SUCCESS;
}
// returns all Mifare Mini (MFM) 10 keys.
// keys must have 5*2*6 = 60bytes space
int mfc_algo_mizip_all(uint8_t *uid, uint8_t *keys) {
    if (keys == NULL) return PM3_EINVARG;

    for (int keytype = 0; keytype < 2; keytype++) {
        for (int sector = 0; sector < 5; sector++){
            uint64_t key = 0;
            mfc_algo_mizip_one(uid, sector, keytype, &key);
            num_to_bytes(key, 6, keys + (keytype * 5 * 6) + (sector * 6));
    }
    }
    return PM3_SUCCESS;
}

// Disney Infinity algo
int mfc_algo_di_one(uint8_t *uid, uint8_t sector, uint8_t keytype, uint64_t *key) {
    if (sector > 4) return PM3_EINVARG;
    if (key == NULL) return PM3_EINVARG;

    uint8_t hash[64];
    uint8_t input[] = {
        0x0A, 0x14, 0xFD, 0x05, 0x07, 0xFF, 0x4B, 0xCD,
        0x02, 0x6B, 0xA8, 0x3F, 0x0A, 0x3B, 0x89, 0xA9,
        uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6],
        0x28, 0x63, 0x29, 0x20, 0x44, 0x69, 0x73, 0x6E,
        0x65, 0x79, 0x20, 0x32, 0x30, 0x31, 0x33
    };

    mbedtls_sha1(input, sizeof(input), hash);

    *key = (
        (uint64_t)hash[3] << 40 |
        (uint64_t)hash[2] << 32 |
        (uint64_t)hash[1] << 24 |
        (uint64_t)hash[0] << 16 |
        (uint64_t)hash[7] << 8 |
        hash[6]
        );

    return PM3_SUCCESS;
}
int mfc_algo_di_all(uint8_t *uid, uint8_t *keys) {
    if (keys == NULL) return PM3_EINVARG;
    for (int keytype = 0; keytype < 2; keytype++) {
        for (int sector = 0; sector < 5; sector++){
            uint64_t key = 0;
            mfc_algo_di_one(uid, sector, keytype, &key);
            num_to_bytes(key, 6, keys + (keytype * 5 * 6) + (sector * 6));
        }
    }
    return PM3_SUCCESS;
}

// Skylanders
static uint64_t sky_crc64_like(uint64_t result, uint8_t sector) {
    #define SKY_POLY UINT64_C(0x42f0e1eba9ea3693)
    #define SKY_TOP UINT64_C(0x800000000000)
    result ^= (uint64_t)sector << 40;
    for(int i = 0; i < 8; i++) {
        result = (result & SKY_TOP) ? (result << 1) ^ SKY_POLY : result << 1;
    }
    return result;
}
int mfc_algo_sky_one(uint8_t *uid, uint8_t sector, uint8_t keytype, uint64_t *key) {

#define SKY_KEY_MASK 0xFFFFFFFFFFFF

    if (sector > 15) return PM3_EINVARG;
    if (key == NULL) return PM3_EINVARG;
    
    if (sector == 0 && keytype == 0) {
        *key = 0x4B0B20107CCB;
        return PM3_SUCCESS;
    }
    if (keytype == 1) {
        *key = 0x000000000000;
        return PM3_SUCCESS;
    }
    
    // hash UID
    uint64_t hash = 0x9AE903260CC4;
    for(int i = 0; i < 4; i++) {
        hash = sky_crc64_like(hash, uid[i]);
    }

    uint64_t sectorhash = sky_crc64_like(hash, sector);   
    *key = BSWAP_64(sectorhash & SKY_KEY_MASK) >> 16;
    return PM3_SUCCESS;
}
int mfc_algo_sky_all(uint8_t *uid, uint8_t *keys) {
    if (keys == NULL) return PM3_EINVARG;
    for (int keytype = 0; keytype < 2; keytype++) {
        for (int sector = 0; sector < 16; sector++){
            uint64_t key = 0;
            mfc_algo_sky_one(uid, sector, keytype, &key);
            num_to_bytes(key, 6, keys + (keytype * 16 * 6) + (sector * 6));
        }
    }
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

    uint8_t uid6[] = {0x74, 0x57, 0xCA, 0xA9};
    uint64_t key6 = 0;
    mfc_algo_sky_one(uid6, 15, 0, &key6);
    success = (key6 == 0x82c7e64bc565);
    PrintAndLogEx(success ? SUCCESS : WARNING, "UID | %s | %"PRIx64" | %s", sprint_hex(uid6, 4), key6, success ? "OK" : "->82C7E64BC565<--");

    PrintAndLogEx(SUCCESS, "-------------------");
    return PM3_SUCCESS;
}

