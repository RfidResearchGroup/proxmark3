//-----------------------------------------------------------------------------
// Copyright (C) 2021 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
//  tests for crypto
//-----------------------------------------------------------------------------

#include "cipursetest.h"

#include <unistd.h>
#include <string.h>      // memcpy memset
#include "fileutils.h"  

#include "cipurse/cipursecrypto.h"
#include "cipurse/cipursecore.h"

uint8_t Key[] = CIPURSE_DEFAULT_KEY;
uint8_t KeyKvv[CIPURSE_KVV_LENGTH] = {0x5f, 0xd6, 0x7b, 0xcb};

uint8_t TestData[16] = {0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint8_t TestDataPadded[16] = {0x11, 0x22, 0x33, 0x44, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static bool TestKVV(void) {
    uint8_t kvv[CIPURSE_KVV_LENGTH] = {0};
    CipurseCGetKVV(Key, kvv);
    //PrintAndLogEx(INFO, "kvv: %s", sprint_hex(kvv, 4));
    bool res = memcmp(KeyKvv, kvv, CIPURSE_KVV_LENGTH) == 0;
    
    if (res)
        PrintAndLogEx(INFO, "kvv: " _GREEN_("passed"));
    else
        PrintAndLogEx(INFO, "kvv: " _RED_("fail"));

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
        PrintAndLogEx(INFO, "ISO9797M2: " _GREEN_("passed"));
    else
        PrintAndLogEx(INFO, "ISO9797M2: " _RED_("fail"));

    return res;
}

static bool TestSMI(void) {
    CipurseContext ctx = {0};
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
        PrintAndLogEx(INFO, "SMI: " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR, "SMI: " _RED_("fail"));

    return res;
}



bool CIPURSETest(bool verbose) {
    bool res = true;

    PrintAndLogEx(INFO, "------ " _CYAN_("CIPURSE TESTS") " ------");
    
    res = res && TestKVV();
    res = res && TestISO9797M2();
    res = res && TestSMI();



    PrintAndLogEx(INFO, "---------------------------");
    if (res)
        PrintAndLogEx(SUCCESS, "    Test(s) [ %s ]", _GREEN_("ok"));
    else
        PrintAndLogEx(FAILED, "    Test(s) [ %s ]", _RED_("fail"));
    
    return res;
}
