//-----------------------------------------------------------------------------
// Copyright (C) 2021 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// CIPURSE transport cards data and commands
//-----------------------------------------------------------------------------

#include "cipursecore.h"

#include "commonutil.h"  // ARRAYLEN
#include "comms.h"       // DropField
#include "util_posix.h"  // msleep

#include "cmdhf14a.h"
#include "emv/emvcore.h"
#include "emv/emvjson.h"
#include "ui.h"
#include "util.h"
#include "cipurse/cipursecrypto.h"

static int CIPURSEExchangeEx(bool ActivateField, bool LeaveFieldON, sAPDU apdu, bool IncludeLe, uint16_t Le, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    uint8_t data[APDU_RES_LEN] = {0};

    *ResultLen = 0;
    if (sw) *sw = 0;
    uint16_t isw = 0;
    int res = 0;

    if (ActivateField) {
        DropField();
        msleep(50);
    }

    // COMPUTE APDU
    int datalen = 0;
    uint16_t xle = IncludeLe ? 0x100 : 0x00;
    if (xle == 0x100 && Le != 0)
        xle = Le;
    if (APDUEncodeS(&apdu, false, xle, data, &datalen)) {
        PrintAndLogEx(ERR, "APDU encoding error.");
        return 201;
    }

    if (GetAPDULogging())
        PrintAndLogEx(SUCCESS, ">>>> %s", sprint_hex(data, datalen));

    res = ExchangeAPDU14a(data, datalen, ActivateField, LeaveFieldON, Result, (int)MaxResultLen, (int *)ResultLen);
    if (res) {
        return res;
    }

    if (GetAPDULogging())
        PrintAndLogEx(SUCCESS, "<<<< %s", sprint_hex(Result, *ResultLen));

    if (*ResultLen < 2) {
        return 200;
    }

    *ResultLen -= 2;
    isw = Result[*ResultLen] * 0x0100 + Result[*ResultLen + 1];
    if (sw)
        *sw = isw;

    if (isw != 0x9000) {
        if (GetAPDULogging()) {
            if (*sw >> 8 == 0x61) {
                PrintAndLogEx(ERR, "APDU chaining len:%02x -->", *sw & 0xff);
            } else {
                PrintAndLogEx(ERR, "APDU(%02x%02x) ERROR: [%4X] %s", apdu.CLA, apdu.INS, isw, GetAPDUCodeDescription(*sw >> 8, *sw & 0xff));
                return 5;
            }
        }
    }

    return PM3_SUCCESS;
}

/*static int CIPURSEExchange(sAPDU apdu, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    return CIPURSEExchangeEx(false, true, apdu, true, 0, Result, MaxResultLen, ResultLen, sw);
}*/

int CIPURSESelect(bool ActivateField, bool LeaveFieldON, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    uint8_t data[] = {0x41, 0x44, 0x20, 0x46, 0x31};

    return EMVSelect(ECC_CONTACTLESS, ActivateField, LeaveFieldON, data, sizeof(data), Result, MaxResultLen, ResultLen, sw, NULL);
}

int CIPURSEChallenge(uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    return CIPURSEExchangeEx(false, true, (sAPDU) {0x00, 0x84, 0x00, 0x00, 0x00, NULL}, true, 0x16, Result, MaxResultLen, ResultLen, sw);
}

int CIPURSEMutalAuthenticate(uint8_t keyIndex, uint8_t *params, uint8_t paramslen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    return CIPURSEExchangeEx(false, true, (sAPDU) {0x00, 0x82, 0x00, keyIndex, paramslen, params}, true, 0x10, Result, MaxResultLen, ResultLen, sw);
}
