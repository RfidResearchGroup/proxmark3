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
#include "crc16.h"        // crc16 ccitt
#include "mbedtls/sha1.h"
#include "mbedtls/md5.h"
#include "mbedtls/cmac.h"
#include "mbedtls/cipher.h"
#include "mbedtls/md.h"

#ifndef ON_DEVICE
#include "ui.h"
# define prnt(args...) PrintAndLogEx(DEBUG, ## args );
#else
# include "dbprint.h"
# define prnt Dbprintf
#endif

// Implementation tips:
// For each implementation of the algos, I recommend adding a self test for easy "simple unit" tests when Travis CI / Appveyor runs.
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
        uint32_t tempA = v1 ^ v2;
        uint32_t t1 = PM3_ROTL(tempA, v2 & 0x1F) + c_D[p++];
        uint32_t tempB = v2 ^ t1;
        uint32_t t2 = PM3_ROTL(tempB, t1 & 0x1F) + c_D[p++];
        tempA = t1 ^ t2;
        v1 = PM3_ROTL(tempA, t2 & 0x1F) + c_D[p++];
        tempB = t2 ^ v1;
        v2 = PM3_ROTL(tempB, v1 & 0x1F) + c_D[p++];
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
uint32_t ul_ev1_pwdgenA(const uint8_t *uid) {

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
uint32_t ul_ev1_pwdgenB(const uint8_t *uid) {

    uint8_t pwd[] = {0x00, 0x00, 0x00, 0x00};

    pwd[0] = uid[1] ^ uid[3] ^ 0xAA;
    pwd[1] = uid[2] ^ uid[4] ^ 0x55;
    pwd[2] = uid[3] ^ uid[5] ^ 0xAA;
    pwd[3] = uid[4] ^ uid[6] ^ 0x55;
    return (uint32_t)bytes_to_num(pwd, 4);
}

// Lego Dimension pwd generation algo nickname C.
uint32_t ul_ev1_pwdgenC(const uint8_t *uid) {
    uint32_t pwd = 0;
    uint32_t base[] = {
        0xffffffff, 0x28ffffff,
        0x43202963, 0x7279706f,
        0x74686769, 0x47454c20,
        0x3032204f, 0xaaaa3431
    };

    memcpy(base, uid, 7);

    for (int i = 0; i < 8; i++) {
        pwd = base[i] + ROTR(pwd, 25) + ROTR(pwd, 10) - pwd;
    }
    return BSWAP_32(pwd);
}

// XYZ 3d printing pwd generation algo nickname D.
uint32_t ul_ev1_pwdgenD(const uint8_t *uid) {

    uint8_t i;
    // rotation offset
    uint8_t r = (uid[1] + uid[3] + uid[5]) & 7;

    // rotated UID
    uint8_t ru[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    for (i = 0; i < 7; i++)
        ru[(i + r) & 7] = uid[i];

    transform_D(ru);

    // offset
    r = (ru[0] + ru[2] + ru[4] + ru[6]) & 3;

    // calc key
    uint32_t pwd = 0;
    for (i = 0; i < 4; i++)
        pwd = ru[i + r] + (pwd << 8);

    return BSWAP_32(pwd);
}

// AIR purifier Xiaomi
uint32_t ul_ev1_pwdgenE(const uint8_t *uid) {
    uint8_t hash[20] = {0};
    mbedtls_sha1(uid, 7, hash);
    uint32_t pwd = 0;
    pwd |= (hash[ hash[0] % 20 ]) << 24 ;
    pwd |= (hash[(hash[0] + 5) % 20 ]) << 16;
    pwd |= (hash[(hash[0] + 13) % 20 ]) << 8;
    pwd |= (hash[(hash[0] + 17) % 20 ]);
    return pwd;
}

// NDEF tools format password generator
uint32_t ul_ev1_pwdgenF(const uint8_t *uid) {
    uint8_t hash[16] = {0};;
    mbedtls_md5(uid, 7, hash);
    uint32_t pwd = 0;
    pwd |= hash[0] << 24;
    pwd |= hash[1] << 16;
    pwd |= hash[2] << 8;
    pwd |= hash[3];
    return pwd;
}

// Solution from @atc1441
// https://gist.github.com/atc1441/41af75048e4c22af1f5f0d4c1d94bb56
// Philips Sonicare toothbrush NFC head
uint32_t ul_ev1_pwdgenG(const uint8_t *uid, const uint8_t *mfg) {

    init_table(CRC_PHILIPS);
    // UID
    uint32_t crc1 = crc16_philips(uid, 7);
    // MFG string
    uint32_t crc2 = crc16_fast(mfg, 10, crc1, false, false);

    return (BSWAP_16(crc2) << 16 | BSWAP_16(crc1));
}

// pack generation for algo 1-3
uint16_t ul_ev1_packgenA(const uint8_t *uid) {
    uint16_t pack = (uid[0] ^ uid[1] ^ uid[2]) << 8 | (uid[2] ^ 8);
    return pack;
}
uint16_t ul_ev1_packgenB(const uint8_t *uid) {
    return 0x8080;
}
uint16_t ul_ev1_packgenC(const uint8_t *uid) {
    return 0xaa55;
}
uint16_t ul_ev1_packgenD(const uint8_t *uid) {
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
uint16_t ul_ev1_packgenE(const uint8_t *uid) {

    uint32_t pwd = ul_ev1_pwdgenE(uid);
    return (0xAD << 8 | ((pwd >> 24) & 0xFF));
}

uint16_t ul_ev1_packgenG(const uint8_t *uid, const uint8_t *mfg) {
    init_table(CRC_PHILIPS);
    // UID
    uint32_t crc1 = crc16_philips(uid, 7);
    // MFG string
    uint32_t crc2 = crc16_fast(mfg, 10, crc1, false, false);
    // PWD
    uint32_t pwd = (BSWAP_16(crc2) << 16 | BSWAP_16(crc1));

    uint8_t pb[4];
    num_to_bytes(pwd, 4, pb);
    return BSWAP_16(crc16_fast(pb, 4, crc2, false, false));
}


// default shims
uint32_t ul_ev1_pwdgen_def(const uint8_t *uid) {
    return 0xFFFFFFFF;
}
uint16_t ul_ev1_packgen_def(const uint8_t *uid) {
    return 0x0000;
}

// MIFARE ULTRALIGHT OTP generators
uint32_t ul_c_otpgenA(const uint8_t *uid) {
    return 0x534C544F;
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
        for (int sector = 0; sector < 16; sector++) {
            uint64_t key = 0;
            mfc_algo_ving_one(uid, sector, keytype, &key);
            num_to_bytes(key, 6, keys + (keytype * 16 * 6) + (sector * 6));
        }
    }
    return PM3_SUCCESS;
}

// Yale Doorman
int mfc_algo_yale_one(uint8_t *uid, uint8_t sector, uint8_t keytype, uint64_t *key) {
    if (sector > 15) return PM3_EINVARG;
    if (key == NULL) return PM3_EINVARG;
    if (keytype > 2) return PM3_EINVARG;
    *key = 0;
    return PM3_SUCCESS;
}
int mfc_algo_yale_all(uint8_t *uid, uint8_t *keys) {
    if (keys == NULL) return PM3_EINVARG;
    for (int keytype = 0; keytype < 2; keytype++) {
        for (int sector = 0; sector < 16; sector++) {
            uint64_t key = 0;
            mfc_algo_yale_one(uid, sector, keytype, &key);
            num_to_bytes(key, 6, keys + (keytype * 16 * 6) + (sector * 6));
        }
    }
    return PM3_SUCCESS;
}

// Saflok / Maid UID to key.
int mfc_algo_saflok_one(uint8_t *uid, uint8_t sector, uint8_t keytype, uint64_t *key) {
    if (sector > 15) return PM3_EINVARG;
    if (key == NULL) return PM3_EINVARG;
    if (keytype > 2) return PM3_EINVARG;
    *key = 0;
    return PM3_SUCCESS;
}
int mfc_algo_saflok_all(uint8_t *uid, uint8_t *keys) {
    if (keys == NULL) return PM3_EINVARG;

    for (int keytype = 0; keytype < 2; keytype++) {
        for (int sector = 0; sector < 16; sector++) {
            uint64_t key = 0;
            mfc_algo_saflok_one(uid, sector, keytype, &key);
            num_to_bytes(key, 6, keys + (keytype * 16 * 6) + (sector * 6));
        }
    }
    return PM3_SUCCESS;
}

// MIZIP algo
int mfc_algo_mizip_one(const uint8_t *uid, uint8_t sector, uint8_t keytype, uint64_t *key) {
    if (sector > 4) return PM3_EINVARG;
    if (key == NULL) return PM3_EINVARG;
    if (keytype > 2) return PM3_EINVARG;

    if (sector == 0) {
        // A
        if (keytype == 0)
            *key = 0xA0A1A2A3A4A5U;
        else    // B
            *key = 0xB4C132439eef;

    } else {

        uint8_t xor[6];

        if (keytype == 0) {

            uint64_t xor_tbl_a[] = {
                0x09125a2589e5,
                0xAB75C937922F,
                0xE27241AF2C09,
                0x317AB72F4490,
            };

            num_to_bytes(xor_tbl_a[sector - 1], 6, xor);

            *key =
                (uint64_t)(uid[0] ^ xor[0]) << 40 |
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
        for (int sector = 0; sector < 5; sector++) {
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
        for (int sector = 0; sector < 5; sector++) {
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
    for (int i = 0; i < 8; i++) {
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
    for (int i = 0; i < 4; i++) {
        hash = sky_crc64_like(hash, uid[i]);
    }

    uint64_t sectorhash = sky_crc64_like(hash, sector);
    *key = BSWAP_64(sectorhash & SKY_KEY_MASK) >> 16;
    return PM3_SUCCESS;
}
int mfc_algo_sky_all(uint8_t *uid, uint8_t *keys) {
    if (keys == NULL) return PM3_EINVARG;
    for (int keytype = 0; keytype < 2; keytype++) {
        for (int sector = 0; sector < 16; sector++) {
            uint64_t key = 0;
            mfc_algo_sky_one(uid, sector, keytype, &key);
            num_to_bytes(key, 6, keys + (keytype * 16 * 6) + (sector * 6));
        }
    }
    return PM3_SUCCESS;
}

// LF T55x7 White gun cloner algo
uint32_t lf_t55xx_white_pwdgen(uint32_t id) {
    uint32_t r1 = rotl(id & 0x000000ec, 8);
    uint32_t r2 = rotl(id & 0x86000000, 16);
    uint32_t pwd = 0x10303;
    pwd += ((id & 0x86ee00ec) ^ r1 ^ r2);
    return pwd;
}

// Gallagher Desfire Key Diversification Input for Cardax Card Data Application
int mfdes_kdf_input_gallagher(uint8_t *uid, uint8_t uidLen, uint8_t keyNo, uint32_t aid, uint8_t *kdfInputOut, uint8_t *kdfInputLen) {
    if (uid == NULL || (uidLen != 4 && uidLen != 7) || keyNo > 2 || kdfInputOut == NULL || kdfInputLen == NULL) {
        prnt("Invalid arguments");
        return PM3_EINVARG;
    }

    int len = 0;
    // If the keyNo == 1 or the aid is 000000, then omit the UID.
    // On the other hand, if the aid is 1f81f4 (config card) always include the UID.
    if ((keyNo != 1 && aid != 0x000000) || (aid == 0x1f81f4)) {
        if (*kdfInputLen < (4 + uidLen)) {
            return PM3_EINVARG;
        }

        memcpy(kdfInputOut, uid, uidLen);
        len += uidLen;
    } else if (*kdfInputLen < 4) {
        return PM3_EINVARG;
    }

    kdfInputOut[len++] = keyNo;

    kdfInputOut[len++] = aid & 0xff;
    kdfInputOut[len++] = (aid >> 8) & 0xff;
    kdfInputOut[len++] = (aid >> 16) & 0xff;

    *kdfInputLen = len;

    return PM3_SUCCESS;
}

int mfc_generate4b_nuid(uint8_t *uid, uint8_t *nuid) {
    uint16_t crc;
    uint8_t b1 = 0, b2 = 0;

    compute_crc(CRC_14443_A, uid, 3, &b1, &b2);
    nuid[0] = (b2 & 0xE0) | 0xF;
    nuid[1] = b1;
    crc = b1;
    crc |= b2 << 8;
    crc = crc16_fast(&uid[3], 4, reflect16(crc), true, true);
    nuid[2] = (crc >> 8) & 0xFF ;
    nuid[3] = crc & 0xFF;
    return PM3_SUCCESS;
}

int mfc_algo_touch_one(uint8_t *uid, uint8_t sector, uint8_t keytype, uint64_t *key) {
    if (uid == NULL) return PM3_EINVARG;
    if (key == NULL) return PM3_EINVARG;

    *key = (
               (uint64_t)(uid[1] ^ uid[2] ^ uid[3]) << 40 |
               (uint64_t)uid[1] << 32 |
               (uint64_t)uid[2] << 24 |
               (uint64_t)(((uid[0] + uid[1] + uid[2] + uid[3]) % 0x100) ^ uid[3]) << 16 |
               (uint64_t)0  << 8 |
               (uint64_t)0
           );
    return PM3_SUCCESS;
}

//------------------------------------
// Self tests
//------------------------------------

int generator_selftest(void) {
#ifndef ON_DEVICE
#define NUM_OF_TEST     9

    PrintAndLogEx(INFO, "PWD / KEY generator selftest");
    PrintAndLogEx(INFO, "----------------------------");

    uint8_t testresult = 0;

    uint8_t uid1[] = {0x04, 0x11, 0x12, 0x11, 0x12, 0x11, 0x10};
    uint32_t pwd1 = ul_ev1_pwdgenA(uid1);
    bool success = (pwd1 == 0x8432EB17);
    if (success)
        testresult++;

    PrintAndLogEx(success ? SUCCESS : WARNING, "UID | %s | %08X - %s", sprint_hex(uid1, 7), pwd1, success ? "OK" : "->8432EB17<-");

    uint8_t uid2[] = {0x04, 0x1f, 0x98, 0xea, 0x1e, 0x3e, 0x81};
    uint32_t pwd2 = ul_ev1_pwdgenB(uid2);
    success = (pwd2 == 0x5fd37eca);
    if (success)
        testresult++;
    PrintAndLogEx(success ? SUCCESS : WARNING, "UID | %s | %08X - %s", sprint_hex(uid2, 7), pwd2, success ? "OK" : "->5fd37eca<--");

    uint8_t uid3[] = {0x04, 0x62, 0xB6, 0x8A, 0xB4, 0x42, 0x80};
    uint32_t pwd3 = ul_ev1_pwdgenC(uid3);
    success = (pwd3 == 0x5a349515);
    if (success)
        testresult++;
    PrintAndLogEx(success ? SUCCESS : WARNING, "UID | %s | %08X - %s", sprint_hex(uid3, 7), pwd3, success ? "OK" : "->5a349515<--");

    uint8_t uid4[] = {0x04, 0xC5, 0xDF, 0x4A, 0x6D, 0x51, 0x80};
    uint32_t pwd4 = ul_ev1_pwdgenD(uid4);
    success = (pwd4 == 0x72B1EC61);
    if (success)
        testresult++;
    PrintAndLogEx(success ? SUCCESS : WARNING, "UID | %s | %08X - %s", sprint_hex(uid4, 7), pwd4, success ? "OK" : "->72B1EC61<--");

    uint8_t uid5[] = {0x04, 0xA0, 0x3C, 0xAA, 0x1E, 0x70, 0x80};
    uint32_t pwd5 = ul_ev1_pwdgenE(uid5);
    success = (pwd5 == 0xCD91AFCC);
    if (success)
        testresult++;
    PrintAndLogEx(success ? SUCCESS : WARNING, "UID | %s | %08X - %s", sprint_hex(uid5, 7), pwd5, success ? "OK" : "->CD91AFCC<--");

    uint8_t uid6[] = {0x04, 0x77, 0x42, 0xAB, 0xEF, 0x42, 0x70};
    uint32_t pwd6 = ul_ev1_pwdgenF(uid6);
    success = (pwd6 == 0xA9C4C3C0);
    if (success)
        testresult++;
    PrintAndLogEx(success ? SUCCESS : WARNING, "UID | %s | %08X - %s", sprint_hex(uid6, 7), pwd6, success ? "OK" : "->A9C4C3C0<--");

    uint8_t uid7[] = {0x04, 0x0D, 0x4B, 0x5A, 0xC5, 0x71, 0x81};
    uint8_t mfg[] = {0x32, 0x31, 0x30, 0x36, 0x32, 0x38, 0x20, 0x35, 0x32, 0x4D};
    uint32_t pwd7 = ul_ev1_pwdgenG(uid7, mfg);
    success = (pwd7 == 0xFBCFACC1);
    if (success)
        testresult++;
    PrintAndLogEx(success ? SUCCESS : WARNING, "UID | %s | %08X - %s", sprint_hex(uid7, 7), pwd7, success ? "OK" : "->FBCFACC1<--");


//    uint8_t uid5[] = {0x11, 0x22, 0x33, 0x44};
//    uint64_t key1 = mfc_algo_a(uid5);
//    success = (key1 == 0xD1E2AA68E39A);
//    PrintAndLogEx(success ? SUCCESS : WARNING, "UID | %s | %"PRIx64" - %s", sprint_hex(uid5, 4), key1, success ? "OK" : "->D1E2AA68E39A<--");

    uint8_t uid8[] = {0x74, 0x57, 0xCA, 0xA9};
    uint64_t key8 = 0;
    mfc_algo_sky_one(uid8, 15, 0, &key8);
    success = (key8 == 0x82c7e64bc565);
    if (success)
        testresult++;
    PrintAndLogEx(success ? SUCCESS : WARNING, "UID | %s          | %"PRIx64" - %s", sprint_hex(uid8, 4), key8, success ? "OK" : "->82C7E64BC565<--");


    uint32_t lf_id = lf_t55xx_white_pwdgen(0x00000080);
    success = (lf_id == 0x00018383);
    if (success)
        testresult++;
    PrintAndLogEx(success ? SUCCESS : WARNING, "ID  | 0x00000080            | %08"PRIx32 " - %s", lf_id, success ? "OK" : "->00018383<--");

    PrintAndLogEx(SUCCESS, "------------------- Selftest %s", (testresult == NUM_OF_TEST) ? "OK" : "fail");

#endif
    return PM3_SUCCESS;
}

