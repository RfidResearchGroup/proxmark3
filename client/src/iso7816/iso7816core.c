//-----------------------------------------------------------------------------
// Copyright (C) 2017 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// ISO7816 core functions
//-----------------------------------------------------------------------------

#include "iso7816core.h"

#include <string.h>

#include "commonutil.h"  // ARRAYLEN
#include "comms.h"       // DropField
#include "cmdparser.h"
#include "cmdsmartcard.h" // ExchangeAPDUSC
#include "ui.h"
#include "cmdhf14a.h"
#include "cmdhf14b.h"
#include "util_posix.h"

//iceman:  this logging setting, should be unified with client debug etc.
static bool APDULogging = false;
void SetAPDULogging(bool logging) {
    APDULogging = logging;
}

bool GetAPDULogging(void) {
    return APDULogging;
}

int Iso7816ExchangeEx(Iso7816CommandChannel channel, bool ActivateField, bool LeaveFieldON, sAPDU apdu, bool IncludeLe, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    uint8_t data[APDU_RES_LEN] = {0};

    *ResultLen = 0;
    if (sw) *sw = 0;
    uint16_t isw = 0;
    int res = 0;

    if (ActivateField) {
        DropFieldEx(channel);
        msleep(50);
    }

    // COMPUTE APDU
    int datalen = 0;
    if (APDUEncodeS(&apdu, false, IncludeLe ? 0x100 : 0x00, data, &datalen)) {
        PrintAndLogEx(ERR, "APDU encoding error.");
        return 201;
    }

    if (APDULogging)
        PrintAndLogEx(SUCCESS, ">>>> %s", sprint_hex(data, datalen));

    switch (channel) {
        case CC_CONTACTLESS:
            res = ExchangeAPDU14a(data, datalen, ActivateField, LeaveFieldON, Result, (int)MaxResultLen, (int *)ResultLen);
            if (res != PM3_SUCCESS) {
                res = exchange_14b_apdu(data, datalen, ActivateField, LeaveFieldON, Result, (int)MaxResultLen, (int *)ResultLen, 4000);
                if (res != PM3_SUCCESS)
                    return res;
            }
            break;
        case CC_CONTACT:
            res = 1;
            if (IfPm3Smartcard())
                res = ExchangeAPDUSC(false, data, datalen, ActivateField, LeaveFieldON, Result, (int)MaxResultLen, (int *)ResultLen);

            if (res) {
                return res;
            }
            break;
    }

    if (APDULogging)
        PrintAndLogEx(SUCCESS, "<<<< %s", sprint_hex(Result, *ResultLen));

    if (*ResultLen < 2) {
        return 200;
    }

    *ResultLen -= 2;
    isw = Result[*ResultLen] * 0x0100 + Result[*ResultLen + 1];
    if (sw)
        *sw = isw;

    if (isw != 0x9000) {
        if (APDULogging) {
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

int Iso7816Exchange(Iso7816CommandChannel channel, bool LeaveFieldON, sAPDU apdu, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    return Iso7816ExchangeEx(channel, false, LeaveFieldON, apdu, false, Result, MaxResultLen, ResultLen, sw);
}

int Iso7816Select(Iso7816CommandChannel channel, bool ActivateField, bool LeaveFieldON, uint8_t *AID, size_t AIDLen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    return Iso7816ExchangeEx(channel, ActivateField, LeaveFieldON, (sAPDU) {0x00, 0xa4, 0x04, 0x00, AIDLen, AID}, (channel == CC_CONTACTLESS), Result, MaxResultLen, ResultLen, sw);
}
