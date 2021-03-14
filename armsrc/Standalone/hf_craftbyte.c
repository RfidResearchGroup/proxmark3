//-----------------------------------------------------------------------------
// Copyright 2020 Anze Jensterle <dev@anze.dev>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// main code for standalone HF/iso14a emulator
//-----------------------------------------------------------------------------

/*
 * `hf_basicbreak` scans a card
 */

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

typedef struct {
    uint8_t uid[10];
    uint8_t uidlen;
    uint8_t atqa[2];
    uint8_t sak;
} PACKED card_clone_t;

void ModInfo(void) {
    DbpString("hf_craftbyte: standalone UID Stealer - Scans and emulates 14a UID");
}

void RunMod(void) {
    StandAloneMode();
    Dbprintf("HF UID emulator started");
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    // the main loop for your standalone mode
    for (;;) {
        WDT_HIT();

        // exit from RunMod,   send a usbcommand.
        if (data_available()) break;

        iso14a_card_select_t card;
        card_clone_t clone;

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
                if (!iso14443a_select_card(NULL, &card, NULL, true, 0, true)) {
                    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
                    LED_D_OFF();
                    SpinDelay(500);
                    continue;
                } else {
                    Dbprintf("Found card with SAQ: %02X, ATQA: %02X %02X, UID: ", card.sak, card.atqa[0], card.atqa[1]);
                    Dbhexdump(card.uidlen, card.uid, 0);
                    clone.uidlen = card.uidlen;
                    clone.sak = card.sak;
                    clone.atqa[0] = card.atqa[0];
                    clone.atqa[1] = card.atqa[1];
                    memcpy(clone.uid, card.uid, card.uidlen);
                    state = STATE_EMUL;
                }
            } else if (state == STATE_EMUL) {
                uint8_t flags;
                if (clone.uidlen == 4) flags |= FLAG_4B_UID_IN_DATA;
                else if (clone.uidlen == 7) flags |= FLAG_7B_UID_IN_DATA;
                else if (clone.uidlen == 10) flags |= FLAG_10B_UID_IN_DATA;
                else {
                    Dbprintf("Unusual UID length, something is wrong. Try again please.");
                    state = STATE_READ;
                    continue;
                }

                Dbprintf("Starting simulation, press pm3-button to stop and go back to search state.");
                SimulateIso14443aTag(3, flags, card.uid, 0);

                // Go back to search state if user presses pm3-button
                state = STATE_READ;
            }
        }
        if (button_pressed  == BUTTON_HOLD)        //Holding down the button
            break;
    }

    DbpString("exiting");
    LEDsoff();
}
