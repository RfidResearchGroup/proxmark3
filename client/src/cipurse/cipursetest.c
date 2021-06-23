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

bool CIPURSETest(bool verbose) {
    bool res = true;

    PrintAndLogEx(INFO, "------ " _CYAN_("CIPURSE TESTS") " ------");
    
    res = res && TestKVV();



    PrintAndLogEx(INFO, "---------------------------");
    if (res)
        PrintAndLogEx(SUCCESS, "    Test(s) [ %s ]", _GREEN_("ok"));
    else
        PrintAndLogEx(FAILED, "    Test(s) [ %s ]", _RED_("fail"));
    
    return res;
}
