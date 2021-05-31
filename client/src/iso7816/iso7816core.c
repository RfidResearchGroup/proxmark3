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
#include "iso14b.h"      // iso14b_raw_cmd_t
#include "util_posix.h"

//iceman:  this logging setting, should be unified with client debug etc.
static bool APDULogging = false;
void SetAPDULogging(bool logging) {
    APDULogging = logging;
}

bool GetAPDULogging(void) {
    return APDULogging;
}

static isodep_state_t isodep_state = ISODEP_INACTIVE;

void SetISODEPState(isodep_state_t state) {
    isodep_state = state;
    if (APDULogging) {
        PrintAndLogEx(SUCCESS, ">>>> ISODEP -> %s%s%s", isodep_state == ISODEP_INACTIVE ? "inactive" : "", isodep_state == ISODEP_NFCA ? "NFC-A" : "", isodep_state == ISODEP_NFCB ? "NFC-B" : "");
    }
}

isodep_state_t GetISODEPState(void) {
    return isodep_state;
}

int Iso7816Connect(Iso7816CommandChannel channel) {
    if (channel == CC_CONTACT) {
        return PM3_ENOTIMPL;
    }
    // Try to 14a
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_NO_DISCONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;
    bool failed_14a = false;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 2000) == false) {
        DropField();
        failed_14a = true;
    }

    if ((!failed_14a) && resp.oldarg[0] != 0) {
        SetISODEPState(ISODEP_NFCA);
        return PM3_SUCCESS;
    }

    PrintAndLogEx(DEBUG, "No 14a tag spotted, trying 14b");
    // If not 14a, try to 14b
    iso14b_raw_cmd_t packet = {
        .flags = (ISO14B_CONNECT | ISO14B_SELECT_STD),
        .timeout = 0,
        .rawlen = 0,
    };
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t));
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, 2000) == false) {
        PrintAndLogEx(DEBUG, "Timeout, no 14b tag spotted, exiting");
        return PM3_ETIMEOUT;
    }

    if (resp.oldarg[0] != 0) {
        PrintAndLogEx(DEBUG, "No 14b tag spotted, failed to find any tag.");
        return PM3_ENODATA;
    }
    SetISODEPState(ISODEP_NFCB);
    return PM3_SUCCESS;
}

int Iso7816ExchangeEx(Iso7816CommandChannel channel, bool ActivateField, bool LeaveFieldON, sAPDU apdu, bool includeLe, uint16_t Le, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
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
    if (includeLe) {
        if (Le == 0) {
            Le = 0x100;
        }
    } else {
        Le = 0;
    }
    if (APDUEncodeS(&apdu, false, Le, data, &datalen)) {
        PrintAndLogEx(ERR, "APDU encoding error.");
        return 201;
    }

    if (APDULogging)
        PrintAndLogEx(SUCCESS, ">>>> %s", sprint_hex(data, datalen));

    switch (channel) {
        case CC_CONTACTLESS:
            switch (GetISODEPState()) {
                case ISODEP_NFCA:
                    res = ExchangeAPDU14a(data, datalen, ActivateField, LeaveFieldON, Result, (int)MaxResultLen, (int *)ResultLen);
                    break;
                case ISODEP_NFCB:
                    res = exchange_14b_apdu(data, datalen, ActivateField, LeaveFieldON, Result, (int)MaxResultLen, (int *)ResultLen, 4000);
                    break;
                case ISODEP_INACTIVE:
                    if (! ActivateField) {
                        PrintAndLogEx(FAILED, "Field currently inactive, cannot send an APDU");
                        return PM3_EIO;
                    }
                    res = ExchangeAPDU14a(data, datalen, ActivateField, LeaveFieldON, Result, (int)MaxResultLen, (int *)ResultLen);
                    if (res != PM3_SUCCESS) {
                        res = exchange_14b_apdu(data, datalen, ActivateField, LeaveFieldON, Result, (int)MaxResultLen, (int *)ResultLen, 4000);
                    }
                    break;
            }
            if (res != PM3_SUCCESS) {
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
    return Iso7816ExchangeEx(channel, false, LeaveFieldON, apdu, false, 0, Result, MaxResultLen, ResultLen, sw);
}

int Iso7816Select(Iso7816CommandChannel channel, bool ActivateField, bool LeaveFieldON, uint8_t *AID, size_t AIDLen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    return Iso7816ExchangeEx(channel, ActivateField, LeaveFieldON, (sAPDU) {0x00, 0xa4, 0x04, 0x00, AIDLen, AID}, (channel == CC_CONTACTLESS), 0, Result, MaxResultLen, ResultLen, sw);
}
