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
static bool TestCMAC(void) {
    bool res = true;
    
    
    if (res)
        PrintAndLogEx(INFO, "CMAC............. " _GREEN_("passed"));
    else
        PrintAndLogEx(ERR, "CMAC............. " _RED_("fail"));

    return res;
}

bool DesfireTest(bool verbose) {
    bool res = true;

    PrintAndLogEx(INFO, "------ " _CYAN_("Desfire Tests") " ------");

    res = res && TestCRC16();
    res = res && TestCRC32();
    res = res && TestCMAC();

    PrintAndLogEx(INFO, "---------------------------");
    if (res)
        PrintAndLogEx(SUCCESS, "    Tests [ %s ]", _GREEN_("ok"));
    else
        PrintAndLogEx(FAILED, "    Tests [ %s ]", _RED_("fail"));

    PrintAndLogEx(NORMAL, "");
    return res;
}
