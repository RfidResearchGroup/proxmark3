//-----------------------------------------------------------------------------
// Copyright (C) 2020 Anze Jensterle <dev@anze.dev>
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
// main code for hf_craftbyte
// `hf_craftyte` continuously scans for ISO14443a card UID and then emulates it.
//-----------------------------------------------------------------------------

#include "standalone.h"
#include "proxmark3_arm.h"
#include "appmain.h"
#include "fpgaloader.h"
#include "util.h"
#include "dbprint.h"
#include "ticks.h"
#include "string.h"
#include "BigBuf.h"
#include "iso14443a.h"
#include "protocols.h"
#include "cmd.h"

#define STATE_READ 0
#define STATE_EMUL 1

void ModInfo(void) {
    DbpString("HF CRAFTBYTE mode - scans and emulates ISO14443a UID (craftbyte)");
}

void RunMod(void) {
    StandAloneMode();
    Dbprintf(_YELLOW_("HF CRAFTBYTE mode started"));
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    // the main loop for your standalone mode
    for (;;) {
        WDT_HIT();

        // exit from RunMod,   send a usbcommand.
        if (data_available()) break;

        iso14a_card_select_t card;

        SpinDelay(500);

        // 0 = search, 1 = read, 2 = emul
        int state = STATE_READ;

        DbpString("Scanning...");
        int button_pressed = BUTTON_NO_CLICK;
        for (;;) {
            // Was our button held down or pressed?
            button_pressed = BUTTON_HELD(1000);

            if (button_pressed != BUTTON_NO_CLICK || data_available())
                break;
            else if (state == STATE_READ) {
                iso14443a_setup(FPGA_HF_ISO14443A_READER_MOD);
                if (iso14443a_select_card(NULL, &card, NULL, true, 0, true) == false) {
                    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
                    LED_D_OFF();
                    SpinDelay(500);
                    continue;
                } else {
                    Dbprintf("Found card with SAK: %02X, ATQA: %02X %02X, UID: ", card.sak, card.atqa[0], card.atqa[1]);
                    Dbhexdump(card.uidlen, card.uid, 0);
                    state = STATE_EMUL;
                }
            } else if (state == STATE_EMUL) {
                uint16_t flags = 0;
                if (card.uidlen == 4) {
                    flags |= FLAG_4B_UID_IN_DATA;
                } else if (card.uidlen == 7) {
                    flags |= FLAG_7B_UID_IN_DATA;
                } else if (card.uidlen == 10) {
                    flags |= FLAG_10B_UID_IN_DATA;
                } else {
                    Dbprintf("Unusual UID length, something is wrong. Try again please.");
                    state = STATE_READ;
                    continue;
                }

                Dbprintf("Starting simulation, press pm3-button to stop and go back to search state.");
                if (card.sak == 0x08 && card.atqa[0] == 0x04 && card.atqa[1] == 0) {
                    DbpString("Mifare Classic 1k");
                    SimulateIso14443aTag(1, flags, card.uid, 0);
                } else if (card.sak == 0x08 && card.atqa[0] == 0x44 && card.atqa[1] == 0) {
                    DbpString("Mifare Classic 4k ");
                    SimulateIso14443aTag(8, flags, card.uid, 0);
                } else if (card.sak == 0x00 && card.atqa[0] == 0x44 && card.atqa[1] == 0) {
                    DbpString("Mifare Ultralight");
                    SimulateIso14443aTag(2, flags, card.uid, 0);
                } else if (card.sak == 0x20 && card.atqa[0] == 0x04 && card.atqa[1] == 0x03) {
                    DbpString("Mifare DESFire");
                    SimulateIso14443aTag(3, flags, card.uid, 0);
                } else if (card.sak == 0x20 && card.atqa[0] == 0x44 && card.atqa[1] == 0x03) {
                    DbpString("Mifare DESFire Ev1/Plus/JCOP");
                    SimulateIso14443aTag(3, flags, card.uid, 0);
                } else {
                    Dbprintf("Unrecognized tag type -- defaulting to Mifare Classic emulation");
                    SimulateIso14443aTag(1, flags, card.uid, 0);
                }

                // Go back to search state if user presses pm3-button
                state = STATE_READ;
            }
        }
        if (button_pressed  == BUTTON_HOLD)        //Holding down the button
            break;
    }

    Dbprintf("-=[ exit ]=-");
    LEDsoff();
}
