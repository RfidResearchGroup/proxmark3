//-----------------------------------------------------------------------------
// Copyright (C) 2021 Tim Mudford <tim.mudford1@gmail.com>
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
// main code for hf_tmudford
// `hf_tmudford` Continuously scans for ISO15693 card UID and then emulates it.
//-----------------------------------------------------------------------------

#include "standalone.h"
#include "proxmark3_arm.h"
#include "appmain.h"
#include "fpgaloader.h"
#include "util.h"
#include "dbprint.h"
#include "ticks.h"

#include "iso15693.h"
#include "iso15.h"

#define STATE_READ 0
#define STATE_EMUL 1

void ModInfo(void) {
    DbpString("HF TMUDFORD mode - Scans and emulates ISO15693 UID (Tim Mudford)");
}

void RunMod(void) {
    StandAloneMode();
    Dbprintf(_YELLOW_("HF TMUDFORD mode started"));
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    for (;;) {
        WDT_HIT();
        if (data_available()) break;

        SpinDelay(500);

        // 0 = search, 1 = read, 2 = emul
        int state = STATE_READ;
        iso15_card_select_t card;

        DbpString("Scanning...");
        int button_pressed = BUTTON_NO_CLICK;
        for (;;) {
            // Was our button held down or pressed?
            button_pressed = BUTTON_HELD(1000);

            if (button_pressed != BUTTON_NO_CLICK || data_available())
                break;
            else if (state == STATE_READ) {
                Iso15693InitReader();
                ReaderIso15693(&card);

                if (card.uidlen == 0) {
                    LED_D_OFF();
                    SpinDelay(500);
                    continue;
                } else {
                    Dbprintf("Found card with UID: ");
                    Dbhexdump(card.uidlen, card.uid, 0);
                    state = STATE_EMUL;
                }
            } else if (state == STATE_EMUL) {
                Iso15693InitTag();
                Dbprintf("Starting simulation, press pm3-button to stop and go back to search state.");
                // default block size is 4
                SimTagIso15693(card.uid, 4);

                state = STATE_READ;
            }
        }
        if (button_pressed  == BUTTON_HOLD)
            break;
    }

    Dbprintf("-=[ exit ]=-");
    LEDsoff();
}
