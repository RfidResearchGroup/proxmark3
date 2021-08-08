//-----------------------------------------------------------------------------
// Copyright (C) 2021 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
//  tests for desfire
//-----------------------------------------------------------------------------

#include "desfiretest.h"

#include <unistd.h>
#include <string.h>      // memcpy memset
#include "fileutils.h"

#include "crypto/libpcrypto.h"
#include "mifare/desfirecrypto.h"

static uint8_t CMACData[] = {0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
                             0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
                             0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C,
                             0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51
                            };


static bool TestCRC16(void) {
    uint8_t data[] = {0x04, 0x44, 0x0F, 0x32, 0x76, 0x31, 0x80, 0x27, 0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    bool res = true;
    size_t len = DesfireSearchCRCPos(data, 16, 0x00, 2);
    res = res && (len == 7);

    len = DesfireSearchCRCPos(data, 7 + 2, 0x00, 2);
    res = res && (len == 7);

    len = DesfireSearchCRCPos(data, 7, 0x00, 2);
    res = res && (len == 0);

    len = DesfireSearchCRCPos(data, 3, 0x00, 2);
    res = res && (len == 0);

    len = DesfireSearchCRCPos(data, 1, 0x00, 2);
    res = res && (len == 0);

    if (res)
        PrintAndLogEx(INFO, "crc16............. " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR, "crc16............. " _RED_("fail"));

    return res;
}

static bool TestCRC32(void) {
    uint8_t data[] = {0x04, 0x44, 0x0F, 0x32, 0x76, 0x31, 0x80, 0x99, 0xCE, 0x1A, 0xD4, 0x00, 0x00, 0x00, 0x00, 0x00};

    bool res = true;
    size_t len = DesfireSearchCRCPos(data, 16, 0x00, 4);
    res = res && (len == 7);

    len = DesfireSearchCRCPos(data, 7 + 4, 0x00, 4);
    res = res && (len == 7);

    len = DesfireSearchCRCPos(data, 5, 0x00, 4);
    res = res && (len == 0);

    len = DesfireSearchCRCPos(data, 4, 0x00, 4);
    res = res && (len == 0);

    len = DesfireSearchCRCPos(data, 2, 0x00, 4);
    res = res && (len == 0);

    if (res)
        PrintAndLogEx(INFO, "crc32............. " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR, "crc32............. " _RED_("fail"));

    return res;
}

// https://www.nxp.com/docs/en/application-note/AN10922.pdf
static bool TestCMACSubkeys(void) {
    bool res = true;
    
    uint8_t key[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    
    uint8_t sk1[DESFIRE_MAX_CRYPTO_BLOCK_SIZE] = {0};
    uint8_t sk2[DESFIRE_MAX_CRYPTO_BLOCK_SIZE] = {0};
    DesfireContext dctx;
    // AES
    DesfireSetKey(&dctx, 0, T_AES, key);

    DesfireCMACGenerateSubkeys(&dctx, DCOMainKey, sk1, sk2);

    uint8_t sk1test[] = {0xFB, 0xC9, 0xF7, 0x5C, 0x94, 0x13, 0xC0, 0x41, 0xDF, 0xEE, 0x45, 0x2D, 0x3F, 0x07, 0x06, 0xD1};
    uint8_t sk2test[] = {0xF7, 0x93, 0xEE, 0xB9, 0x28, 0x27, 0x80, 0x83, 0xBF, 0xDC, 0x8A, 0x5A, 0x7E, 0x0E, 0x0D, 0x25};
    
    res = res && (memcmp(sk1, sk1test, sizeof(sk1test)) == 0);
    res = res && (memcmp(sk2, sk2test, sizeof(sk2test)) == 0);

    // 2tdea
    DesfireSetKey(&dctx, 0, T_3DES, key);

    DesfireCMACGenerateSubkeys(&dctx, DCOMainKey, sk1, sk2);

    uint8_t sk1_2tdea[] = {0xF6, 0x12, 0xEB, 0x32, 0xE4, 0x60, 0x35, 0xF3};
    uint8_t sk2_2tdea[] = {0xEC, 0x25, 0xD6, 0x65, 0xC8, 0xC0, 0x6B, 0xFD};
    
    res = res && (memcmp(sk1, sk1_2tdea, sizeof(sk1_2tdea)) == 0);
    res = res && (memcmp(sk2, sk2_2tdea, sizeof(sk2_2tdea)) == 0);

    // 3tdea
    uint8_t key3[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    DesfireSetKey(&dctx, 0, T_3K3DES, key3);

    DesfireCMACGenerateSubkeys(&dctx, DCOMainKey, sk1, sk2);

    uint8_t sk1_3tdea[] = {0xA3, 0xED, 0x58, 0xF8, 0xE6, 0x94, 0x1B, 0xCA};
    uint8_t sk2_3tdea[] = {0x47, 0xDA, 0xB1, 0xF1, 0xCD, 0x28, 0x37, 0x8F};
    
    res = res && (memcmp(sk1, sk1_3tdea, sizeof(sk1_3tdea)) == 0);
    res = res && (memcmp(sk2, sk2_3tdea, sizeof(sk2_3tdea)) == 0);

    if (res)
        PrintAndLogEx(INFO, "CMAC subkeys...... " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR,  "CMAC subkeys...... " _RED_("fail"));

    return res;
}

// https://www.nxp.com/docs/en/application-note/AN10922.pdf
// page 8
static bool TestAn10922KDFAES(void) {
    bool res = true;
    
    uint8_t key[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    
    DesfireContext dctx;
    DesfireSetKey(&dctx, 0, T_AES, key);
    memcpy(dctx.sessionKeyMAC, key, sizeof(key));
    
    uint8_t kdfInput[] = {0x04, 0x78, 0x2E, 0x21, 0x80, 0x1D, 0x80, 0x30, 0x42, 0xF5, 0x4E, 0x58, 0x50, 0x20, 0x41, 0x62, 0x75};
    MifareKdfAn10922(&dctx, kdfInput, sizeof(kdfInput));
    
    uint8_t dkey[] = {0xA8, 0xDD, 0x63, 0xA3, 0xB8, 0x9D, 0x54, 0xB3, 0x7C, 0xA8, 0x02, 0x47, 0x3F, 0xDA, 0x91, 0x75};
    res = res && (memcmp(dctx.key, dkey, sizeof(dkey)) == 0);

    if (res)
        PrintAndLogEx(INFO, "AES An10922....... " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR,  "AES An10922....... " _RED_("fail"));

    return res;
}

static bool TestAn10922KDF2TDEA(void) {
    bool res = true;
    
    uint8_t key[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    
    DesfireContext dctx;
    DesfireSetKey(&dctx, 0, T_3DES, key);
    memcpy(dctx.sessionKeyMAC, key, sizeof(key));

    uint8_t kdfInput[] = {0x04, 0x78, 0x2E, 0x21, 0x80, 0x1D, 0x80, 0x30, 0x42, 0xF5, 0x4E, 0x58, 0x50, 0x20, 0x41};
    MifareKdfAn10922(&dctx, kdfInput, sizeof(kdfInput));
    
    uint8_t dkey[] = {0x16, 0xF8, 0x59, 0x7C, 0x9E, 0x89, 0x10, 0xC8, 0x6B, 0x96, 0x48, 0xD0, 0x06, 0x10, 0x7D, 0xD7};
    res = res && (memcmp(dctx.key, dkey, sizeof(dkey)) == 0);

    if (res)
        PrintAndLogEx(INFO, "2TDEA An10922..... " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR,  "2TDEA An10922..... " _RED_("fail"));

    return res;
}

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_CMAC.pdf
static bool TestCMAC3TDEA(void) {
    bool res = true;

    uint8_t key[DESFIRE_MAX_KEY_SIZE] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                                         0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
                                         0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23
                                        };
    DesfireContext dctx;
    DesfireSetKey(&dctx, 0, T_3K3DES, key);
    memcpy(dctx.sessionKeyMAC, key, DESFIRE_MAX_KEY_SIZE);
    uint8_t cmac[DESFIRE_MAX_KEY_SIZE] = {0};

    uint8_t cmac1[] = {0x7D, 0xB0, 0xD3, 0x7D, 0xF9, 0x36, 0xC5, 0x50};
    memset(dctx.IV, 0, DESFIRE_MAX_KEY_SIZE);
    DesfireCryptoCMAC(&dctx, CMACData, 0, cmac);
    res = res && (memcmp(cmac, cmac1, sizeof(cmac1)) == 0);

    uint8_t cmac2[] = {0x30, 0x23, 0x9C, 0xF1, 0xF5, 0x2E, 0x66, 0x09};
    memset(cmac, 0, sizeof(cmac));
    memset(dctx.IV, 0, DESFIRE_MAX_KEY_SIZE);
    DesfireCryptoCMAC(&dctx, CMACData, 16, cmac);
    res = res && (memcmp(cmac, cmac2, sizeof(cmac1)) == 0);

    uint8_t cmac3[] = {0x6C, 0x9F, 0x3E, 0xE4, 0x92, 0x3F, 0x6B, 0xE2};
    memset(cmac, 0, sizeof(cmac));
    memset(dctx.IV, 0, DESFIRE_MAX_KEY_SIZE);
    DesfireCryptoCMAC(&dctx, CMACData, 20, cmac);
    res = res && (memcmp(cmac, cmac3, sizeof(cmac1)) == 0);

    uint8_t cmac4[] = {0x99, 0x42, 0x9B, 0xD0, 0xBF, 0x79, 0x04, 0xE5};
    memset(cmac, 0, sizeof(cmac));
    memset(dctx.IV, 0, DESFIRE_MAX_KEY_SIZE);
    DesfireCryptoCMAC(&dctx, CMACData, 32, cmac);
    res = res && (memcmp(cmac, cmac4, sizeof(cmac1)) == 0);

    if (res)
        PrintAndLogEx(INFO, "CMAC 3TDEA........ " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR, "CMAC 3TDEA........ " _RED_("fail"));

    return res;
}

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_CMAC.pdf
static bool TestCMAC2TDEA(void) {
    bool res = true;

    uint8_t key[DESFIRE_MAX_KEY_SIZE] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                                         0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01
                                        };
    DesfireContext dctx;
    DesfireSetKey(&dctx, 0, T_3DES, key);
    memcpy(dctx.sessionKeyMAC, key, DESFIRE_MAX_KEY_SIZE);
    uint8_t cmac[DESFIRE_MAX_KEY_SIZE] = {0};

    uint8_t cmac1[] = {0x79, 0xCE, 0x52, 0xA7, 0xF7, 0x86, 0xA9, 0x60};
    memset(dctx.IV, 0, DESFIRE_MAX_KEY_SIZE);
    DesfireCryptoCMAC(&dctx, CMACData, 0, cmac);
//    PrintAndLogEx(INFO, "cmac: %s", sprint_hex(cmac, 16));
    res = res && (memcmp(cmac, cmac1, sizeof(cmac1)) == 0);

    uint8_t cmac2[] = {0xCC, 0x18, 0xA0, 0xB7, 0x9A, 0xF2, 0x41, 0x3B};
    memset(cmac, 0, sizeof(cmac));
    memset(dctx.IV, 0, DESFIRE_MAX_KEY_SIZE);
    DesfireCryptoCMAC(&dctx, CMACData, 16, cmac);
    res = res && (memcmp(cmac, cmac2, sizeof(cmac1)) == 0);

    uint8_t cmac3[] = {0xC0, 0x6D, 0x37, 0x7E, 0xCD, 0x10, 0x19, 0x69};
    memset(cmac, 0, sizeof(cmac));
    memset(dctx.IV, 0, DESFIRE_MAX_KEY_SIZE);
    DesfireCryptoCMAC(&dctx, CMACData, 20, cmac);
    res = res && (memcmp(cmac, cmac3, sizeof(cmac1)) == 0);

    uint8_t cmac4[] = {0x9C, 0xD3, 0x35, 0x80, 0xF9, 0xB6, 0x4D, 0xFB};
    memset(cmac, 0, sizeof(cmac));
    memset(dctx.IV, 0, DESFIRE_MAX_KEY_SIZE);
    DesfireCryptoCMAC(&dctx, CMACData, 32, cmac);
    res = res && (memcmp(cmac, cmac4, sizeof(cmac1)) == 0);

    if (res)
        PrintAndLogEx(INFO, "CMAC 2TDEA........ " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR, "CMAC 2TDEA........ " _RED_("fail"));

    return res;
}

static bool TestCMACDES(void) {
    bool res = true;

    uint8_t key[DESFIRE_MAX_KEY_SIZE] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    DesfireContext dctx;
    DesfireSetKey(&dctx, 0, T_DES, key);
    memcpy(dctx.sessionKeyMAC, key, DESFIRE_MAX_KEY_SIZE);
    uint8_t cmac[DESFIRE_MAX_KEY_SIZE] = {0};

    uint8_t cmac1[] = {0x86, 0xF7, 0x9C, 0x13, 0xFD, 0x30, 0x6E, 0x67};
    memset(dctx.IV, 0, DESFIRE_MAX_KEY_SIZE);
    DesfireCryptoCMAC(&dctx, CMACData, 0, cmac);
    res = res && (memcmp(cmac, cmac1, sizeof(cmac1)) == 0);

    uint8_t cmac2[] = {0xBE, 0xA4, 0x21, 0x22, 0x92, 0x46, 0x2A, 0x85};
    memset(cmac, 0, sizeof(cmac));
    memset(dctx.IV, 0, DESFIRE_MAX_KEY_SIZE);
    DesfireCryptoCMAC(&dctx, CMACData, 16, cmac);
    res = res && (memcmp(cmac, cmac2, sizeof(cmac1)) == 0);

    uint8_t cmac3[] = {0x3E, 0x2F, 0x83, 0x10, 0xC5, 0x69, 0x27, 0x5E};
    memset(cmac, 0, sizeof(cmac));
    memset(dctx.IV, 0, DESFIRE_MAX_KEY_SIZE);
    DesfireCryptoCMAC(&dctx, CMACData, 20, cmac);
    res = res && (memcmp(cmac, cmac3, sizeof(cmac1)) == 0);

    uint8_t cmac4[] = {0x9D, 0x1F, 0xC4, 0xD4, 0xC0, 0x25, 0x91, 0x32};
    memset(cmac, 0, sizeof(cmac));
    memset(dctx.IV, 0, DESFIRE_MAX_KEY_SIZE);
    DesfireCryptoCMAC(&dctx, CMACData, 32, cmac);
    res = res && (memcmp(cmac, cmac4, sizeof(cmac1)) == 0);

    if (res)
        PrintAndLogEx(INFO, "CMAC DES.......... " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR, "CMAC DES.......... " _RED_("fail"));

    return res;
}

// https://www.nxp.com/docs/en/application-note/AN12343.pdf
// page 33-34
static bool TestEV2SessionKeys(void) {
    bool res = true;

    uint8_t key[16] = {0};
    uint8_t rnda[] = {0xB0, 0x4D, 0x07, 0x87, 0xC9, 0x3E, 0xE0, 0xCC, 0x8C, 0xAC, 0xC8, 0xE8, 0x6F, 0x16, 0xC6, 0xFE};
    uint8_t rndb[] = {0xFA, 0x65, 0x9A, 0xD0, 0xDC, 0xA7, 0x38, 0xDD, 0x65, 0xDC, 0x7D, 0xC3, 0x86, 0x12, 0xAD, 0x81};
    uint8_t sessionkeyauth[] = {0x63, 0xDC, 0x07, 0x28, 0x62, 0x89, 0xA7, 0xA6, 0xC0, 0x33, 0x4C, 0xA3, 0x1C, 0x31, 0x4A, 0x04};
    uint8_t sessionkeymac[] = {0x77, 0x4F, 0x26, 0x74, 0x3E, 0xCE, 0x6A, 0xF5, 0x03, 0x3B, 0x6A, 0xE8, 0x52, 0x29, 0x46, 0xF6};

    uint8_t sessionkey[16] = {0};
    DesfireGenSessionKeyEV2(key, rnda, rndb, true, sessionkey);
    res = res && (memcmp(sessionkey, sessionkeyauth, sizeof(sessionkeyauth)) == 0);

    memset(sessionkey, 0, sizeof(sessionkey));
    DesfireGenSessionKeyEV2(key, rnda, rndb, false, sessionkey);
    res = res && (memcmp(sessionkey, sessionkeymac, sizeof(sessionkeymac)) == 0);

    if (res)
        PrintAndLogEx(INFO, "EV2 session keys.. " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR,  "EV2 session keys.. " _RED_("fail"));

    return res;
}

static bool TestEV2IVEncode(void) {
    bool res = true;

    uint8_t key[] = {0x66, 0xA8, 0xCB, 0x93, 0x26, 0x9D, 0xC9, 0xBC, 0x28, 0x85, 0xB7, 0xA9, 0x1B, 0x9C, 0x69, 0x7B};
    uint8_t ti[] = {0xED, 0x56, 0xF6, 0xE6};
    uint8_t ivres[] = {0xDA, 0x0F, 0x64, 0x4A, 0x49, 0x86, 0x27, 0x59, 0x57, 0xCF, 0x1E, 0xC3, 0xAF, 0x4C, 0xCE, 0x53};

    DesfireContext ctx = {0};
    ctx.keyType = T_AES;
    memcpy(ctx.sessionKeyEnc, key, 16);
    memcpy(ctx.TI, ti, 4);
    ctx.cmdCntr = 0;

    uint8_t iv[16] = {0};
    DesfireEV2FillIV(&ctx, true, iv);
    res = res && (memcmp(iv, ivres, sizeof(ivres)) == 0);

    uint8_t key2[] = {0x44, 0x5A, 0x86, 0x26, 0xB3, 0x33, 0x84, 0x59, 0x32, 0x12, 0x32, 0xfA, 0xDf, 0x6a, 0xDe, 0x2B};
    uint8_t ti2[] = {0x11, 0x22, 0x33, 0x44};
    uint8_t ivres2[] = {0x17, 0x74, 0x94, 0xFC, 0xC4, 0xF1, 0xDA, 0xB2, 0xAF, 0xBE, 0x8F, 0xAE, 0x20, 0x57, 0xA9, 0xD2};
    memcpy(ctx.sessionKeyEnc, key2, 16);
    memcpy(ctx.TI, ti2, 4);
    ctx.cmdCntr = 5;

    memset(iv, 0, 16);
    DesfireEV2FillIV(&ctx, true, iv);
    res = res && (memcmp(iv, ivres2, sizeof(ivres2)) == 0);

    if (res)
        PrintAndLogEx(INFO, "EV2 IV calc....... " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR,  "EV2 IV calc....... " _RED_("fail"));

    return res;
}

// https://www.nxp.com/docs/en/application-note/AN12343.pdf
// page 54
static bool TestEV2MAC(void) {
    bool res = true;

    uint8_t key[] = {0x93, 0x66, 0xFA, 0x19, 0x5E, 0xB5, 0x66, 0xF5, 0xBD, 0x2B, 0xAD, 0x40, 0x20, 0xB8, 0x30, 0x02};
    uint8_t ti[] = {0xE2, 0xD3, 0xAF, 0x69};
    uint8_t cmd = 0x8D;
    uint8_t cmddata[] = {0x00, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                         0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22
                        };
    uint8_t macres[] = {0x68, 0xF2, 0xC2, 0x8C, 0x57, 0x5A, 0x16, 0x28};

    // init
    DesfireContext ctx = {0};
    ctx.keyType = T_AES;
    memcpy(ctx.sessionKeyMAC, key, 16);
    memcpy(ctx.TI, ti, 4);
    ctx.cmdCntr = 0;

    // tx 1
    uint8_t mac[16] = {0};
    DesfireEV2CalcCMAC(&ctx, cmd, cmddata, sizeof(cmddata), mac);
    res = res && (memcmp(mac, macres, sizeof(macres)) == 0);

    // rx 1
    memset(mac, 0, sizeof(mac));
    uint8_t macres2[] = {0x08, 0x20, 0xF6, 0x88, 0x98, 0xC2, 0xA7, 0xF1};
    uint8_t rc = 0;
    ctx.cmdCntr++;
    DesfireEV2CalcCMAC(&ctx, rc, NULL, 0, mac);
    res = res && (memcmp(mac, macres2, sizeof(macres2)) == 0);

    // tx 2
    memset(mac, 0, sizeof(mac));
    cmd = 0xAD;
    uint8_t cmddata3[] = {0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00};
    uint8_t macres3[] = {0x0D, 0x9B, 0xE1, 0x91, 0xD5, 0x96, 0x08, 0x34};
    DesfireEV2CalcCMAC(&ctx, cmd, cmddata3, sizeof(cmddata3), mac);
    res = res && (memcmp(mac, macres3, sizeof(macres3)) == 0);

    // rx 2
    rc = 0;
    ctx.cmdCntr++;
    uint8_t cmddata4[] = {0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                          0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                         };
    uint8_t macres4[] = {0xA4, 0x9A, 0x44, 0x22, 0x2D, 0x92, 0x66, 0x66};
    DesfireEV2CalcCMAC(&ctx, rc, cmddata4, sizeof(cmddata4), mac);
    res = res && (memcmp(mac, macres4, sizeof(macres4)) == 0);

    if (res)
        PrintAndLogEx(INFO, "EV2 MAC calc...... " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR,  "EV2 MAC calc...... " _RED_("fail"));

    return res;
}

bool DesfireTest(bool verbose) {
    bool res = true;

    PrintAndLogEx(INFO, "------ " _CYAN_("Desfire Tests") " ------");

    res = res && TestCRC16();
    res = res && TestCRC32();
    res = res && TestCMACSubkeys();
    res = res && TestAn10922KDFAES();
    res = res && TestAn10922KDF2TDEA();
    res = res && TestCMAC3TDEA();
    res = res && TestCMAC2TDEA();
    res = res && TestCMACDES();
    res = res && TestEV2SessionKeys();
    res = res && TestEV2IVEncode();
    res = res && TestEV2MAC();

    PrintAndLogEx(INFO, "---------------------------");
    if (res)
        PrintAndLogEx(SUCCESS, "    Tests [ %s ]", _GREEN_("ok"));
    else
        PrintAndLogEx(FAILED, "    Tests [ %s ]", _RED_("fail"));

    PrintAndLogEx(NORMAL, "");
    return res;
}
