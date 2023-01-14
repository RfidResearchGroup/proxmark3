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
#include "protocols.h"   // ISO7816 APDU return codes

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
        PrintAndLogEx(SUCCESS, "Setting ISODEP -> %s%s%s"
                      , isodep_state == ISODEP_INACTIVE ? "inactive" : ""
                      , isodep_state == ISODEP_NFCA ? _GREEN_("NFC-A") : ""
                      , isodep_state == ISODEP_NFCB ? _GREEN_("NFC-B") : ""
                     );
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
    // select with no disconnect and set frameLength
    int res = SelectCard14443A_4(false, false, NULL);
    if (res == PM3_SUCCESS) {
        SetISODEPState(ISODEP_NFCA);
        return PM3_SUCCESS;
    }

    PrintAndLogEx(DEBUG, "No 14a tag spotted, trying 14b");
    // If not 14a, try to 14b
    res = select_card_14443b_4(false, NULL);
    if (res == PM3_SUCCESS) {
        SetISODEPState(ISODEP_NFCB);
        return PM3_SUCCESS;
    }

    PrintAndLogEx(DEBUG, "No 14b tag spotted, failed to find any tag.");
    return res;
}

int Iso7816ExchangeEx(Iso7816CommandChannel channel, bool activate_field, bool leave_field_on,
                      sAPDU_t apdu, bool include_le, uint16_t le, uint8_t *result,
                      size_t max_result_len, size_t *result_len, uint16_t *sw) {

    *result_len = 0;
    if (sw) {
        *sw = 0;
    }

    if (activate_field) {
        DropFieldEx(channel);
        msleep(50);
    }

    // COMPUTE APDU
    int datalen = 0;
    if (include_le) {
        if (le == 0) {
            le = 0x100;
        }
    } else {
        le = 0;
    }

    uint8_t data[APDU_RES_LEN] = {0};
    if (APDUEncodeS(&apdu, false, le, data, &datalen)) {
        PrintAndLogEx(ERR, "APDU encoding error.");
        return 201;
    }

    if (APDULogging)
        PrintAndLogEx(SUCCESS, ">>>> %s", sprint_hex(data, datalen));

    int res = 0;

    switch (channel) {
        case CC_CONTACTLESS: {

            switch (GetISODEPState()) {
                case ISODEP_NFCA:
                    res = ExchangeAPDU14a(data, datalen, activate_field, leave_field_on, result, (int)max_result_len, (int *)result_len);
                    break;
                case ISODEP_NFCB:
                    res = exchange_14b_apdu(data, datalen, activate_field, leave_field_on, result, (int)max_result_len, (int *)result_len, 4000);
                    break;
                case ISODEP_INACTIVE:
                    if (activate_field == false) {
                        PrintAndLogEx(FAILED, "Field currently inactive, cannot send an APDU");
                        return PM3_EIO;
                    }
                    res = ExchangeAPDU14a(data, datalen, activate_field, leave_field_on, result, (int)max_result_len, (int *)result_len);
                    if (res != PM3_SUCCESS) {
                        res = exchange_14b_apdu(data, datalen, activate_field, leave_field_on, result, (int)max_result_len, (int *)result_len, 4000);
                    }
                    break;
            }

            if (res != PM3_SUCCESS) {
                return res;
            }
            break;
        }
        case CC_CONTACT: {
            res = 1;
            if (IfPm3Smartcard()) {
                res = ExchangeAPDUSC(false, data, datalen, activate_field, leave_field_on, result, (int)max_result_len, (int *)result_len);
            }

            if (res) {
                return res;
            }
            break;
        }
    }

    if (APDULogging)
        PrintAndLogEx(SUCCESS, "<<<< %s", sprint_hex(result, *result_len));

    if (*result_len < 2) {
        return 200;
    }

    *result_len -= 2;
    uint16_t isw = (result[*result_len] * 0x0100) + result[*result_len + 1];

    if (sw) {
        *sw = isw;
    }

    if (isw != ISO7816_OK) {
        if (APDULogging) {
            if (*sw >> 8 == 0x61) {
                PrintAndLogEx(ERR, "APDU chaining len %02x", *sw & 0xFF);
            } else {
                PrintAndLogEx(ERR, "APDU(%02x%02x) ERROR: [%4X] %s", apdu.CLA, apdu.INS, isw, GetAPDUCodeDescription(*sw >> 8, *sw & 0xFF));
                return 5;
            }
        }
    }
    return PM3_SUCCESS;
}

int Iso7816Exchange(Iso7816CommandChannel channel, bool leave_field_on, sAPDU_t apdu, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {
    return Iso7816ExchangeEx(channel
                             , false
                             , leave_field_on
                             , apdu
                             , false
                             , 0
                             , result
                             , max_result_len
                             , result_len
                             , sw
                            );
}

int Iso7816Select(Iso7816CommandChannel channel, bool activate_field, bool leave_field_on, uint8_t *aid, size_t aid_len,
                  uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {

    return Iso7816ExchangeEx(channel
                             , activate_field
                             , leave_field_on
    , (sAPDU_t) {0x00, 0xa4, 0x04, 0x00, aid_len, aid}
    , (channel == CC_CONTACTLESS)
    , 0
    , result
    , max_result_len
    , result_len
    , sw
                            );
}
