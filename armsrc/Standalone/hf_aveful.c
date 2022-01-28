//-----------------------------------------------------------------------------
// Copyright (C) A. Ozkal, 2020
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
// main code for HF Mifare Ultralight read/simulation by Ave Ozkal
//-----------------------------------------------------------------------------

// Several parts of this code is based on code by Craig Young from HF_YOUNG

// This code does not:
// - Account for cards with non-default keys on authentication (MFU EV1 etc)

// This code is designed to work with:
// - MIFARE Ultralight
// - MIFARE Ultralight EV1 (default keys)
// - MIFARE Ultralight Nano (untested, but should work)
// - Infineon My-d Move (without password set)
// - Infineon My-d Move Lean
// - Any other Ultralight clones that have no auth and MAX_DEFAULT_BLOCKS (16) blocks

#include "standalone.h" // standalone definitions
#include "proxmark3_arm.h"
#include "appmain.h"
#include "fpgaloader.h"
#include "util.h"
#include "dbprint.h"

#include "ticks.h"  // SpinDelay
#include "protocols.h"  // MIFARE_ULEV1_VERSION, MIFARE_ULEV1_READSIG, MIFARE_ULEV1_READ_CNT, MIFARE_ULEV1_CHECKTEAR
#include <string.h>  // memcmp
#include "mifareutil.h"
#include "iso14443a.h"

#define SAK 0x00
#define ATQA0 0x44
#define ATQA1 0x00

#define STATE_SEARCH 0
#define STATE_READ 1
#define STATE_EMUL 2

// Taken from cmdhfmfu.c, increased by 01h to be 1 indexed
#define MAX_UL_BLOCKS       0x10
#define MAX_UL_NANO_40      0x0B
#define MAX_ULEV1a_BLOCKS   0x14
#define MAX_ULEV1b_BLOCKS   0x29
#define MAX_MY_D_MOVE       0x26
#define MAX_MY_D_MOVE_LEAN  0x10
#define MAX_DEFAULT_BLOCKS  0x10

typedef struct {
    uint8_t uid[10];
    uint8_t uidlen;
    uint8_t atqa[2];
    uint8_t sak;
} PACKED card_clone_t;

int get_block_count(iso14a_card_select_t card, uint8_t version[], uint16_t version_len);
uint16_t get_ev1_version(iso14a_card_select_t card, uint8_t *version);
uint16_t get_ev1_signature(iso14a_card_select_t card, uint8_t *signature);
uint16_t get_ev1_counter(iso14a_card_select_t card, uint8_t counter, uint8_t *response);
uint16_t get_ev1_tearing(iso14a_card_select_t card, uint8_t counter, uint8_t *response);

uint16_t get_ev1_version(iso14a_card_select_t card, uint8_t *version) {
    return mifare_sendcmd(MIFARE_ULEV1_VERSION, NULL, 0, version, NULL, NULL);
}

uint16_t get_ev1_signature(iso14a_card_select_t card, uint8_t *signature) {
    uint8_t cmd[4] = {MIFARE_ULEV1_READSIG, 0x00, 0x00, 0x00};
    AddCrc14A(cmd, 2);
    ReaderTransmit(cmd, sizeof(cmd), NULL);
    return ReaderReceive(signature, NULL);
}

uint16_t get_ev1_counter(iso14a_card_select_t card, uint8_t counter, uint8_t *response) {
    uint8_t cmd[4] = {MIFARE_ULEV1_READ_CNT, counter, 0x00, 0x00};
    AddCrc14A(cmd, 2);
    ReaderTransmit(cmd, sizeof(cmd), NULL);
    return ReaderReceive(response, NULL);
}

uint16_t get_ev1_tearing(iso14a_card_select_t card, uint8_t counter, uint8_t *response) {
    uint8_t cmd[4] = {MIFARE_ULEV1_CHECKTEAR, counter, 0x00, 0x00};
    AddCrc14A(cmd, 2);
    ReaderTransmit(cmd, sizeof(cmd), NULL);
    return ReaderReceive(response, NULL);
}

int get_block_count(iso14a_card_select_t card, uint8_t version[], uint16_t version_len) {
    // Default to MAX_DEFAULT_BLOCKS blocks
    int block_count = MAX_DEFAULT_BLOCKS;
    // Most of this code is from cmdhfmfu.c
    // Infineon manufacturer ID
    if (card.uid[0] == 0x05) {
        // Infinition MY-D tests   Exam high nibble
        uint8_t nib = (card.uid[1] & 0xf0) >> 4;
        switch (nib) {
            case 3:
                block_count = MAX_MY_D_MOVE;
                break; // or SLE 66R01P // 38 pages of 4 bytes
            case 7:
                block_count = MAX_MY_D_MOVE_LEAN;
                break; // or SLE 66R01L  // 16 pages of 4 bytes
        }
    } else {
        // Moved this from case to if as I only care about non-ultralight ev0.
        if (version_len == 0x0A) {
            if (memcmp(version, "\x00\x04\x03\x01\x01\x00\x0B", 7) == 0)      { block_count = MAX_ULEV1a_BLOCKS; }
            else if (memcmp(version, "\x00\x04\x03\x01\x02\x00\x0B", 7) == 0) { block_count = MAX_UL_NANO_40; }
            else if (memcmp(version, "\x00\x04\x03\x02\x01\x00\x0B", 7) == 0) { block_count = MAX_ULEV1a_BLOCKS; }
            else if (memcmp(version, "\x00\x04\x03\x01\x01\x00\x0E", 7) == 0) { block_count = MAX_ULEV1b_BLOCKS; }
            else if (memcmp(version, "\x00\x04\x03\x02\x01\x00\x0E", 7) == 0) { block_count = MAX_ULEV1b_BLOCKS; }
            else if (memcmp(version, "\x00\x34\x21\x01\x01\x00\x0E", 7) == 0) { block_count = MAX_ULEV1b_BLOCKS; } // Mikron JSC Russia EV1 41 pages tag
            else if (version[2] == 0x03) { block_count = MAX_ULEV1a_BLOCKS; }
        }
    }

    return block_count;
}

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
        int button_pressed = BUTTON_NO_CLICK;
        for (;;) {
            // Was our button held down or pressed?
            button_pressed = BUTTON_HELD(1000);

            if (button_pressed != BUTTON_NO_CLICK || data_available())
                break;
            else if (state == STATE_SEARCH) {
                if (!iso14443a_select_card(NULL, &card, NULL, true, 0, true)) {
                    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
                    LED_D_OFF();
                    SpinDelay(500);
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

                // Get version and re-select card as UL EV0s like to shut off after a 0x60
                uint8_t version[10] = {0x00};
                uint16_t version_len = 0;
                version_len = get_ev1_version(card, version);
                iso14443a_select_card(NULL, NULL, NULL, true, 0, true);

                int block_count = get_block_count(card, version, version_len);
                Dbprintf("Card was determined as having %d blocks.", block_count);
                Dbprintf("Contents:");

                for (int i = 0; i < block_count; i++) {
                    uint8_t dataout[16] = {0x00};
                    if (mifare_ultra_readblock(i, dataout)) {
                        // If there's an error reading, go back to search state
                        read_successful = false;
                        break;
                    }
                    // We're skipping 14 blocks (56 bytes) here, as that "[...] has version/signature/counter data here" according to comments on data_mfu_bin2eml
                    // When converting a bin, it's almost all 0 other than one 0x0F byte, and functionality seems to be unaffected if that byte is set to 0x00.
                    emlSetMem_xt(dataout, 14 + i, 1, 4);
                    Dbhexdump(4, dataout, 0);
                }

                // It's not the best way to determine this,
                // but with what I'm trying to support It Should Be Okay
                bool is_ev1 = (version_len != 0) && (block_count != 16);

                if (read_successful) {
                    uint8_t signature[34] = {0x00};
                    if (is_ev1) {
                        get_ev1_signature(card, signature);
                    }
                    Dbprintf("Preparing emulator memory with:");
                    // Fill first 14 blocks with 0x00 (see comment above)
                    for (int i = 0; i < 14; i++) {
                        uint8_t dataout[4] = {0x00, 0x00, 0x00, 0x00};

                        if (is_ev1 && (i == 0 || i == 1)) {
                            // On block 0 and 1, set version on EV1
                            memcpy(dataout, version + (i * 4), 4);
                        } else if (i == 2) {
                            // On block 2, set last byte to the card's block count
                            dataout[3] = block_count;
                        } else if (is_ev1 && ((i > 2 && i < 11))) {
                            // On 3-10 add signature on EV1
                            memcpy(dataout, signature + ((i - 3) * 4), 4);
                        } else if (is_ev1 && (i > 10)) {
                            // On 11-14 read and set counter and tearing on EV1
                            uint8_t counter[5];
                            uint8_t tearing[3];
                            get_ev1_counter(card, i - 11, counter);
                            get_ev1_tearing(card, i - 11, tearing);
                            memcpy(dataout, counter, 3);
                            memcpy(dataout + 3, tearing, 1);
                        }

                        Dbhexdump(4, dataout, 0);
                        emlSetMem_xt(dataout, i, 1, 4);
                    }
                    Dbprintf("Successfully loaded into emulator memory...");
                    state = STATE_EMUL;
                } else {
                    Dbprintf("Read failure, going back to search state.");
                    state = STATE_SEARCH;
                }
            } else if (state == STATE_EMUL) {
                uint16_t flags = FLAG_7B_UID_IN_DATA;

                Dbprintf("Starting simulation, press pm3-button to stop and go back to search state.");
                SimulateIso14443aTag(7, flags, card.uid, 0);

                // Go back to search state if user presses pm3-button
                state = STATE_SEARCH;
            }
        }
        if (button_pressed  == BUTTON_HOLD)        //Holding down the button
            break;
    }

    DbpString("exiting");
    LEDsoff();
}
