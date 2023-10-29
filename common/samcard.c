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
// Support functions for smart card
//-----------------------------------------------------------------------------
#include "samcard.h"
#include <string.h>
#include <stdio.h>
#include "cmdparser.h"
#include "cmdsmartcard.h"
#include "ui.h"
#include "util.h"

bool IsHIDSamPresent(bool verbose) {

    if (IfPm3Smartcard() == false) {
        PrintAndLogEx(WARNING, "Proxmark3 does not have SMARTCARD support enabled, exiting");
        return false;
    }

    // detect SAM
    smart_card_atr_t card;
    smart_select(verbose, &card);
    if (card.atr_len == 0) {
        PrintAndLogEx(ERR, "Can't get ATR from a smart card");
        return false;
    }

    // SAM identification
    smart_card_atr_t supported[] = {
        {15, {0x3B, 0x95, 0x96, 0x80, 0xB1, 0xFE, 0x55, 0x1F, 0xC7, 0x47, 0x72, 0x61, 0x63, 0x65, 0x13}},
        {11, {0x3b, 0x90, 0x96, 0x91, 0x81, 0xb1, 0xfe, 0x55, 0x1f, 0xc7, 0xd4}},
    };
    bool found = false;
    for (int i = 0; i < sizeof(supported) / sizeof(supported[0]); i++) {
        if ((card.atr_len == supported[i].atr_len) &&
                (memcmp(card.atr, supported[i].atr, supported[i].atr_len) == 0)) {
            found = true;
            break;
        }
    }
    if (found == false) {
        if (verbose) {
            PrintAndLogEx(SUCCESS, "Not detecting a SAM");
        }
        return false;
    }

    // Suspect some SAMs has version name in the historical bytes
    uint8_t T0 = card.atr[1];
    uint8_t K = T0 & 0x0F;  // Number of historical bytes
    if (K > 0 && (K < (card.atr_len - 3)) && verbose) {
        // Last byte of ATR is CRC and before that we have K bytes of
        // "historical bytes".
        // By construction K can't go above 15
        char sam_name[16] = {0};
        memcpy(sam_name, &card.atr[card.atr_len - 1 - K], K);
        PrintAndLogEx(SUCCESS, "SAM (%s) detected", sam_name);
    }
    return true;
}
