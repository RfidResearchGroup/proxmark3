//-----------------------------------------------------------------------------
// A. Ozkal, 2020
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// main code for HF Mifare Ultralight read/simulation by Ave Ozkal
//-----------------------------------------------------------------------------

// Several parts of this code is based on code by Craig Young from HF_YOUNG

// This code does not:
// - Account for cards with authentication (MFU EV1 etc)
// - Determine if cards have block count that's not the same as the BLOCKS def

#include "standalone.h" // standalone definitions
#include "proxmark3_arm.h"
#include "appmain.h"
#include "fpgaloader.h"
#include "util.h"
#include "dbprint.h"

#include "ticks.h"  // SpinDelay
#include "mifareutil.h"
#include "iso14443a.h"

#define BLOCKS 16
#define SAK 0x00
#define ATQA0 0x44
#define ATQA1 0x00

#define STATE_SEARCH 0
#define STATE_READ 1
#define STATE_EMUL 2

typedef struct {
    uint8_t uid[10];
    uint8_t uidlen;
    uint8_t atqa[2];
    uint8_t sak;
} PACKED card_clone_t;

void ModInfo(void) {
    DbpString("  HF Mifare Ultralight read/simulation by Ave Ozkal");
}

void RunMod(void) {
    StandAloneMode();
    Dbprintf("AveFUL (MF Ultralight read/emul) started");
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    // the main loop for your standalone mode
    for (;;) {
        WDT_HIT();

        // exit from RunMod,   send a usbcommand.
        if (data_available()) break;

        iso14a_card_select_t card;

        SpinDelay(500);
        iso14443a_setup(FPGA_HF_ISO14443A_READER_MOD);

        // 0 = search, 1 = read, 2 = emul
        int state = STATE_SEARCH;

        DbpString("Scanning...");
        for (;;) {
            // Was our button held down or pressed?
            int button_pressed = BUTTON_HELD(1000);

            if (button_pressed != BUTTON_NO_CLICK || data_available())
                break;
            else if (state == STATE_SEARCH) {
                if (!iso14443a_select_card(NULL, &card, NULL, true, 0, true)) {
                    continue;
                } else {
                    if (card.sak == SAK && card.atqa[0] == ATQA0 && card.atqa[1] == ATQA1 && card.uidlen == 7) {
                        DbpString("Found ultralight with UID: ");
                        Dbhexdump(card.uidlen, card.uid, 0);
                        state = STATE_READ;
                    } else {
                        DbpString("Found non-ultralight card, ignoring.");
                    }
                }
            } else if (state == STATE_READ) {
                iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
                iso14443a_select_card(NULL, NULL, NULL, true, 0, true);
                bool read_successful = true;
                Dbprintf("Contents:");

                for (int i = 0; i < BLOCKS; i++) {
                    uint8_t dataout[4] = {0x00};
                    if (mifare_ultra_readblock(i, dataout)) {
                        // If there's an error reading, go back to search state
                        read_successful = false;
                        break;
                    }
                    // We're skipping 14 blocks (56 bytes) here, as that "[...] has version/signature/counter data here" according to comments on dumptoemul-mfu
                    // When converting a bin, it's almost all 0 other than one 0x0F byte, and functionality seems to be unaffected if that byte is set to 0x00.
                    emlSetMem_xt(dataout, 14 + i, 1, 4);
                    Dbhexdump(4, dataout, 0);
                }

                if (read_successful) {
                    Dbprintf("Successfully loaded into emulator memory...");
                    state = STATE_EMUL;
                } else {
                    Dbprintf("Read failure, going back to search state.");
                    state = STATE_SEARCH;
                }
            } else if (state == 2) {
                uint8_t flags = FLAG_7B_UID_IN_DATA;

                Dbprintf("Starting simulation, press pm3-button to stop and go back to search state.");
                SimulateIso14443aTag(2, flags, card.uid);

                // Go back to search state if user presses pm3-button
                state = STATE_SEARCH;
            }
        }
    }

    DbpString("exiting");
    LEDsoff();
}
