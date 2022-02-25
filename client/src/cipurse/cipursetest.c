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
//  tests for crypto
//-----------------------------------------------------------------------------

#include "cipursetest.h"

#include <unistd.h>
#include <string.h>      // memcpy memset
#include "fileutils.h"

#include "crypto/libpcrypto.h"
#include "cipurse/cipursecrypto.h"
#include "cipurse/cipursecore.h"

uint8_t Key[] = CIPURSE_DEFAULT_KEY;
uint8_t KeyKvv[CIPURSE_KVV_LENGTH] = {0x5f, 0xd6, 0x7b, 0xcb};

uint8_t TestRandom[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22};

uint8_t TestData[16] = {0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint8_t TestDataPadded[16] = {0x11, 0x22, 0x33, 0x44, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static bool TestKVV(void) {
    uint8_t kvv[CIPURSE_KVV_LENGTH] = {0};
    CipurseCGetKVV(Key, kvv);

    bool res = memcmp(KeyKvv, kvv, CIPURSE_KVV_LENGTH) == 0;

    if (res)
        PrintAndLogEx(INFO, "kvv.............. " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR, "kvv.............. " _RED_("fail"));

    return res;
}

static bool TestISO9797M2(void) {
    uint8_t data[32] = {0};

    size_t ddatalen = 0;
    AddISO9797M2Padding(data, &ddatalen, TestData, 4, 16);
    bool res = (ddatalen == 16);
    res = res && (memcmp(data, TestDataPadded, ddatalen) == 0);

    res = res && (FindISO9797M2PaddingDataLen(data, ddatalen) == 4);

    if (res)
        PrintAndLogEx(INFO, "ISO9797M2........ " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR, "ISO9797M2........ " _RED_("fail"));

    return res;
}

static bool TestSMI(void) {
    CipurseContext_t ctx = {0};
    CipurseCClearContext(&ctx);

    bool res = (isCipurseCChannelSecuritySet(&ctx) == false);

    CipurseCChannelSetSecurityLevels(&ctx, CPSPlain, CPSPlain);
    res = res && (CipurseCGetSMI(&ctx, false) == 0x00);
    res = res && (CipurseCGetSMI(&ctx, true) == 0x01);

    CipurseCChannelSetSecurityLevels(&ctx, CPSPlain, CPSMACed);
    res = res && (CipurseCGetSMI(&ctx, false) == 0x04);
    res = res && (CipurseCGetSMI(&ctx, true) == 0x05);

    CipurseCChannelSetSecurityLevels(&ctx, CPSMACed, CPSMACed);
    res = res && (CipurseCGetSMI(&ctx, false) == 0x44);
    res = res && (CipurseCGetSMI(&ctx, true) == 0x45);

    CipurseCChannelSetSecurityLevels(&ctx, CPSMACed, CPSEncrypted);
    res = res && (CipurseCGetSMI(&ctx, false) == 0x48);
    res = res && (CipurseCGetSMI(&ctx, true) == 0x49);

    CipurseCChannelSetSecurityLevels(&ctx, CPSEncrypted, CPSEncrypted);
    res = res && (CipurseCGetSMI(&ctx, false) == 0x88);
    res = res && (CipurseCGetSMI(&ctx, true) == 0x89);

    if (res)
        PrintAndLogEx(INFO, "SMI.............. " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR, "SMI.............. " _RED_("fail"));

    return res;
}

static bool TestMIC(void) {
    uint8_t mic[4] = {0};

    CipurseCGenerateMIC(TestData, 4, mic);
    uint8_t valid_mic4[4] = {0xD4, 0x71, 0xA7, 0x73};
    bool res = (memcmp(mic, valid_mic4, 4) == 0);

    res = res && (CipurseCCheckMIC(TestData, 4, mic));

    CipurseCGenerateMIC(TestData, 6, mic);
    uint8_t valid_mic6[4] = {0xAA, 0x90, 0xFC, 0x5A};
    res = res && (memcmp(mic, valid_mic6, 4) == 0);

    res = res && (CipurseCCheckMIC(TestData, 6, mic));

    if (res)
        PrintAndLogEx(INFO, "MIC.............. " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR, "MIC.............. " _RED_("fail"));

    return res;
}


static bool TestAuth(void) {
    CipurseContext_t ctx = {0};
    CipurseCClearContext(&ctx);

    bool res = (isCipurseCChannelSecuritySet(&ctx) == false);

    CipurseCSetKey(&ctx, 1, Key);
    res = res && (memcmp(ctx.key, Key, 16) == 0);
    res = res && (ctx.keyId == 1);

    CipurseCSetRandomFromPICC(&ctx, TestRandom);
    res = res && (memcmp(ctx.RP, TestRandom, 16) == 0);
    res = res && (memcmp(ctx.rP, &TestRandom[16], 6) == 0);

    uint8_t hrandom[] = {0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20};
    CipurseCSetRandomHost(&ctx);
    res = res && (memcmp(ctx.RT, hrandom, 16) == 0);
    res = res && (memcmp(ctx.rT, &hrandom[16], 6) == 0);

    uint8_t authparams[16 + 16 + 6] = {0};
    CipurseCAuthenticateHost(&ctx, authparams);
    uint8_t aparamstest[] = {0x12, 0xAA, 0x79, 0xA9, 0x03, 0xC5, 0xB4, 0x6A, 0x27, 0x1B, 0x13, 0xAE, 0x02, 0x50, 0x1C, 0x99, 0x10, 0x10, 0x10, 0x10, 0x10,
                             0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20
                            };
    res = res && (memcmp(authparams, aparamstest, sizeof(authparams)) == 0);

    uint8_t ct[] = {0xBE, 0x10, 0x6B, 0xB9, 0xAD, 0x84, 0xBC, 0xE1, 0x9F, 0xAE, 0x0C, 0x62, 0xCC, 0xC7, 0x0D, 0x41};
    res = res && CipurseCCheckCT(&ctx, ct);

    CipurseCChannelSetSecurityLevels(&ctx, CPSMACed, CPSMACed);
    res = res && (isCipurseCChannelSecuritySet(&ctx) == true);

    uint8_t framekey[] = {0xCF, 0x6F, 0x3A, 0x47, 0xFC, 0xAC, 0x8D, 0x38, 0x25, 0x75, 0x8B, 0xFC, 0x8B, 0x61, 0x68, 0xF3};
    res = res && (memcmp(ctx.frameKey, framekey, sizeof(framekey)) == 0);

    if (res)
        PrintAndLogEx(INFO, "Auth............. " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR, "Auth............. " _RED_("fail"));

    return res;
}

static bool TestMAC(void) {
    CipurseContext_t ctx = {0};

    // authentication
    CipurseCClearContext(&ctx);
    CipurseCSetKey(&ctx, 1, Key);
    CipurseCSetRandomFromPICC(&ctx, TestRandom);
    uint8_t authparams[16 + 16 + 6] = {0};
    CipurseCAuthenticateHost(&ctx, authparams);
    uint8_t ct[] = {0xBE, 0x10, 0x6B, 0xB9, 0xAD, 0x84, 0xBC, 0xE1, 0x9F, 0xAE, 0x0C, 0x62, 0xCC, 0xC7, 0x0D, 0x41};
    bool res = CipurseCCheckCT(&ctx, ct);
    CipurseCChannelSetSecurityLevels(&ctx, CPSMACed, CPSMACed);
    res = res && (isCipurseCChannelSecuritySet(&ctx) == true);

    // check MAC
    uint8_t mac[8] = {0};

    CipurseCGenerateMAC(&ctx, TestData, 4, mac);
    uint8_t testmac1[8] = {0xAB, 0x5C, 0x86, 0x18, 0x7F, 0x73, 0xEC, 0x4E};
    res = res && (memcmp(mac, testmac1, 8) == 0);

    uint8_t framekey1[] = {0x7D, 0x6F, 0x31, 0x40, 0xC8, 0x47, 0xED, 0x3F, 0x0A, 0x21, 0xE6, 0xFB, 0xC7, 0xDB, 0x27, 0xB0};
    res = res && (memcmp(ctx.frameKey, framekey1, sizeof(framekey1)) == 0);

    CipurseCCalcMACPadded(&ctx, TestData, 4, mac);
    uint8_t testmac2[8] = {0x9F, 0xE9, 0x54, 0xBF, 0xFC, 0xA0, 0x7D, 0x75};
    res = res && (memcmp(mac, testmac2, 8) == 0);

    uint8_t framekey2[] = {0x1E, 0xD4, 0xB6, 0x87, 0x85, 0x93, 0x5B, 0xAF, 0xA9, 0xF2, 0xF0, 0x8F, 0xA9, 0xF0, 0xA5, 0xFB};
    res = res && (memcmp(ctx.frameKey, framekey2, sizeof(framekey2)) == 0);

    CipurseCCalcMACPadded(&ctx, TestData, 4, mac);
    uint8_t testmac3[8] = {0x15, 0x6F, 0x08, 0x5C, 0x0F, 0x80, 0xE7, 0x07};
    res = res && (memcmp(mac, testmac3, 8) == 0);

    uint8_t framekey3[] = {0x0C, 0x42, 0x93, 0x73, 0x88, 0x8F, 0x63, 0xB3, 0x10, 0x8E, 0xDF, 0xDB, 0xC1, 0x20, 0x63, 0x4C};
    res = res && (memcmp(ctx.frameKey, framekey3, sizeof(framekey3)) == 0);

    uint8_t testmac4[8] = {0x0E, 0xF0, 0x70, 0xA6, 0xA1, 0x15, 0x9A, 0xB6};
    res = res && CipurseCCheckMACPadded(&ctx, TestData, 4, testmac4);

    uint8_t framekey4[] = {0xA0, 0x65, 0x1A, 0x62, 0x56, 0x5D, 0xD7, 0xC9, 0x32, 0xAE, 0x1D, 0xE0, 0xCF, 0x8D, 0xC1, 0xB9};
    res = res && (memcmp(ctx.frameKey, framekey4, sizeof(framekey4)) == 0);

    if (res)
        PrintAndLogEx(INFO, "channel MAC...... " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR, "channel MAC...... " _RED_("fail"));

    return res;
}

static bool TestEncDec(void) {
    CipurseContext_t ctx = {0};

    // authentication
    CipurseCClearContext(&ctx);
    CipurseCSetKey(&ctx, 1, Key);
    CipurseCSetRandomFromPICC(&ctx, TestRandom);
    uint8_t authparams[16 + 16 + 6] = {0};
    CipurseCAuthenticateHost(&ctx, authparams);
    uint8_t ct[] = {0xBE, 0x10, 0x6B, 0xB9, 0xAD, 0x84, 0xBC, 0xE1, 0x9F, 0xAE, 0x0C, 0x62, 0xCC, 0xC7, 0x0D, 0x41};
    bool res = CipurseCCheckCT(&ctx, ct);
    CipurseCChannelSetSecurityLevels(&ctx, CPSMACed, CPSMACed);
    res = res && (isCipurseCChannelSecuritySet(&ctx) == true);

    // check Encode-Decode
    uint8_t dstdata[32] = {0};
    size_t dstdatalen = 0;

    CipurseCEncryptDecrypt(&ctx, TestData, 16, dstdata, true);
    uint8_t tested1[16] = {0x5F, 0x01, 0x18, 0x79, 0xE0, 0x57, 0xA7, 0xE5, 0x34, 0x39, 0x6E, 0x32, 0x62, 0xF2, 0x71, 0x27};
    res = res && (memcmp(dstdata, tested1, 16) == 0);

    uint8_t tested2[16] = {0xA6, 0x22, 0xB5, 0xCF, 0xE8, 0x6E, 0x67, 0xF4, 0xAA, 0x88, 0xB1, 0x19, 0x87, 0xCF, 0xC9, 0xD2};
    CipurseCEncryptDecrypt(&ctx, tested2, 16, dstdata, false);
    res = res && (memcmp(dstdata, TestData, 16) == 0);

    CipurseCChannelEncrypt(&ctx, TestData, 16, dstdata, &dstdatalen);
    uint8_t tested3[32] = {0x1E, 0x0C, 0xD1, 0xF5, 0x8E, 0x0B, 0xAE, 0xF0, 0x06, 0xC6, 0xED, 0x73, 0x3F, 0x8A, 0x87, 0xCF,
                           0x36, 0xCC, 0xF2, 0xF4, 0x7D, 0x33, 0x50, 0xF1, 0x8E, 0xFF, 0xD1, 0x7D, 0x42, 0x88, 0xD5, 0xEE
                          };
    res = res && (dstdatalen == 32);
    res = res && (memcmp(dstdata, tested3, 32) == 0);

    uint8_t tested4[32] = {0xC0, 0x42, 0xDB, 0xD9, 0x53, 0xFF, 0x01, 0xE5, 0xCC, 0x49, 0x8C, 0x9C, 0xDA, 0x60, 0x73, 0xA7,
                           0xE1, 0xEB, 0x14, 0x69, 0xF6, 0x39, 0xF3, 0xE1, 0x07, 0x03, 0x32, 0xF4, 0x27, 0xF9, 0x48, 0x3D
                          };
    CipurseCChannelDecrypt(&ctx, tested4, 32, dstdata, &dstdatalen);
    res = res && (dstdatalen == 16);
    res = res && (memcmp(dstdata, TestData, 16) == 0);

    if (res)
        PrintAndLogEx(INFO, "channel EncDec... " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR, "channel EncDec... " _RED_("fail"));

    return res;
}

//void CipurseCAPDUReqEncode(CipurseContext_t *ctx, sAPDU_t *srcapdu, sAPDU_t *dstapdu, uint8_t *dstdatabuf, bool includeLe, uint8_t Le);
//void CipurseCAPDURespDecode(CipurseContext_t *ctx, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, size_t *dstdatalen, uint16_t *sw);
static bool TestAPDU(void) {
    CipurseContext_t ctx = {0};

    // authentication
    CipurseCClearContext(&ctx);
    CipurseCSetKey(&ctx, 1, Key);
    CipurseCSetRandomFromPICC(&ctx, TestRandom);
    uint8_t authparams[16 + 16 + 6] = {0};
    CipurseCAuthenticateHost(&ctx, authparams);
    uint8_t ct[] = {0xBE, 0x10, 0x6B, 0xB9, 0xAD, 0x84, 0xBC, 0xE1, 0x9F, 0xAE, 0x0C, 0x62, 0xCC, 0xC7, 0x0D, 0x41};
    bool res = CipurseCCheckCT(&ctx, ct);
    CipurseCChannelSetSecurityLevels(&ctx, CPSMACed, CPSMACed);
    res = res && (isCipurseCChannelSecuritySet(&ctx) == true);

    // check APDU formatting
    sAPDU_t srcAPDU = {0};
    sAPDU_t dstAPDU = {0};
    uint8_t dstdata[256] = {0};
    size_t dstdatalen = 0;

    // MACED APDU
    srcAPDU.CLA = 0x00;
    srcAPDU.INS = 0x55;
    srcAPDU.P1 = 0x11;
    srcAPDU.P2 = 0x22;
    srcAPDU.data = TestData;
    srcAPDU.Lc = 5;

    CipurseCAPDUReqEncode(&ctx, &srcAPDU, &dstAPDU, dstdata, true, 0x88);
    uint8_t test1[] = {0x45, 0x11, 0x22, 0x33, 0x44, 0x00, 0x88, 0x79, 0x2B, 0xB7, 0xDD, 0xD1, 0x69, 0xA6, 0x66};
    res = res && ((srcAPDU.CLA | 0x04) == dstAPDU.CLA);
    res = res && (srcAPDU.INS == dstAPDU.INS);
    res = res && (srcAPDU.P1 == dstAPDU.P1);
    res = res && (srcAPDU.P2 == dstAPDU.P2);
    res = res && (dstAPDU.Lc == sizeof(test1));
    res = res && (memcmp(dstdata, test1, sizeof(test1)) == 0);

    uint16_t sw = 0;
    uint8_t test2[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x9D, 0x80, 0xE7, 0xE3, 0x34, 0xE9, 0x97, 0x82, 0xdd, 0xee};
    CipurseCAPDURespDecode(&ctx, test2, sizeof(test2), dstdata, &dstdatalen, &sw);
    res = res && (dstdatalen == 6);
    res = res && (memcmp(test2, dstdata, dstdatalen) == 0);
    res = res && (sw == 0xddee);

    // Plain APDU
    CipurseCChannelSetSecurityLevels(&ctx, CPSPlain, CPSPlain);
    CipurseCAPDUReqEncode(&ctx, &srcAPDU, &dstAPDU, dstdata, true, 0x55);
    uint8_t test3[] = {0x01, 0x11, 0x22, 0x33, 0x44, 0x00, 0x55};
    res = res && ((srcAPDU.CLA | 0x04) == dstAPDU.CLA);
    res = res && (srcAPDU.INS == dstAPDU.INS);
    res = res && (srcAPDU.P1 == dstAPDU.P1);
    res = res && (srcAPDU.P2 == dstAPDU.P2);
    res = res && (dstAPDU.Lc == sizeof(test3));
    res = res && (memcmp(dstdata, test3, sizeof(test3)) == 0);

    uint8_t test4[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xcc, 0xdd};
    CipurseCAPDURespDecode(&ctx, test4, sizeof(test4), dstdata, &dstdatalen, &sw);
    res = res && (dstdatalen == 6);
    res = res && (memcmp(test4, dstdata, dstdatalen) == 0);
    res = res && (sw == 0xccdd);

    // Encrypted APDU
    CipurseCChannelSetSecurityLevels(&ctx, CPSEncrypted, CPSEncrypted);
    CipurseCAPDUReqEncode(&ctx, &srcAPDU, &dstAPDU, dstdata, true, 0x55);
    uint8_t test5[] = {0x89, 0x7D, 0xED, 0x0D, 0x04, 0x8E, 0xE1, 0x99, 0x08, 0x70, 0x56, 0x7C, 0xEE, 0x67, 0xB3, 0x33, 0x6F, 0x00};
    res = res && ((srcAPDU.CLA | 0x04) == dstAPDU.CLA);
    res = res && (srcAPDU.INS == dstAPDU.INS);
    res = res && (srcAPDU.P1 == dstAPDU.P1);
    res = res && (srcAPDU.P2 == dstAPDU.P2);
    res = res && (dstAPDU.Lc == sizeof(test5));
    res = res && (memcmp(dstdata, test5, sizeof(test5)) == 0);

    uint8_t test6[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x7E, 0x4B, 0xA0, 0xB7, 0xcc, 0xdd};
    //CipurseCChannelEncrypt(&ctx, test6, sizeof(test6), dstdata, &dstdatalen);
    //PrintAndLogEx(INFO, "dstdata[%d]: %s", dstdatalen, sprint_hex(dstdata, dstdatalen));

    uint8_t test7[] = {0x07, 0xEF, 0x16, 0x91, 0xE7, 0x0F, 0xB5, 0x10, 0x63, 0xCE, 0x66, 0xDB, 0x3B, 0xC6, 0xD4, 0xE0, 0x90, 0x00};
    CipurseCAPDURespDecode(&ctx, test7, sizeof(test7), dstdata, &dstdatalen, &sw);
    res = res && (dstdatalen == 8);
    res = res && (memcmp(test6, dstdata, dstdatalen) == 0);
    res = res && (sw == 0xccdd);

    if (res)
        PrintAndLogEx(INFO, "apdu............. " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR, "apdu............. " _RED_("fail"));

    return res;
}

bool CIPURSETest(bool verbose) {
    bool res = true;

    PrintAndLogEx(INFO, "------ " _CYAN_("CIPURSE tests") " ------");

    res = res && TestKVV();
    res = res && TestISO9797M2();
    res = res && TestSMI();
    res = res && TestMIC();
    res = res && TestAuth();
    res = res && TestMAC();
    res = res && TestEncDec();
    res = res && TestAPDU();

    PrintAndLogEx(INFO, "---------------------------");
    if (res)
        PrintAndLogEx(SUCCESS, "    Tests [ %s ]", _GREEN_("ok"));
    else
        PrintAndLogEx(FAILED, "    Tests [ %s ]", _RED_("fail"));

    PrintAndLogEx(NORMAL, "");
    return res;
}
