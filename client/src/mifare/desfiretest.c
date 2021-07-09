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
        PrintAndLogEx(INFO, "crc16............ " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR, "crc16............ " _RED_("fail"));

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
        PrintAndLogEx(INFO, "crc32............ " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR, "crc32............ " _RED_("fail"));

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
        PrintAndLogEx(INFO, "CMAC 3TDEA....... " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR, "CMAC 3TDEA....... " _RED_("fail"));

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
        PrintAndLogEx(INFO, "CMAC 2TDEA....... " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR, "CMAC 2TDEA....... " _RED_("fail"));

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
        PrintAndLogEx(INFO, "CMAC DES......... " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR, "CMAC DES......... " _RED_("fail"));

    return res;
}

bool DesfireTest(bool verbose) {
    bool res = true;

    PrintAndLogEx(INFO, "------ " _CYAN_("Desfire Tests") " ------");

    res = res && TestCRC16();
    res = res && TestCRC32();
    res = res && TestCMAC3TDEA();
    res = res && TestCMAC2TDEA();
    res = res && TestCMACDES();

    PrintAndLogEx(INFO, "---------------------------");
    if (res)
        PrintAndLogEx(SUCCESS, "    Tests [ %s ]", _GREEN_("ok"));
    else
        PrintAndLogEx(FAILED, "    Tests [ %s ]", _RED_("fail"));

    PrintAndLogEx(NORMAL, "");
    return res;
}
