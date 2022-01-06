//-----------------------------------------------------------------------------
// Copyright (C) Samy Kamkar, 2012
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
// main code for LF aka SamyRun by Samy Kamkar
//-----------------------------------------------------------------------------
#include "standalone.h" // standalone definitions
#include "proxmark3_arm.h"
#include "appmain.h"
#include "fpgaloader.h"
#include "lfops.h"
#include "util.h"
#include "dbprint.h"
#include "ticks.h"

#define OPTS 2

void ModInfo(void) {
    DbpString("  LF HID26 standalone - aka SamyRun (Samy Kamkar)");
}

// samy's sniff and repeat routine for LF

//  LEDS.
//  A  ,  B  == which bank (recording)
//  FLASHING A, B =  clone bank
//  C = playing bank A
//  D = playing bank B

void RunMod(void) {
    StandAloneMode();
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    Dbprintf(">>  LF HID Read/Clone/Sim a.k.a SamyRun Started  <<");

    uint32_t high[OPTS], low[OPTS];
    int selected = 0;

#define STATE_READ 0
#define STATE_SIM 1
#define STATE_CLONE 2

    uint8_t state = STATE_READ;

    for (;;) {

        WDT_HIT();

        // exit from SamyRun,   send a usbcommand.
        if (data_available()) break;

        // Was our button held down or pressed?
        int button_pressed = BUTTON_HELD(280);
        if (button_pressed != BUTTON_HOLD)
            continue;

        if (state == STATE_READ) {

            if (selected == 0) {
                LED_A_ON();
                LED_B_OFF();
            } else {
                LED_B_ON();
                LED_A_OFF();
            }

            LED_C_OFF();
            LED_D_OFF();

            WAIT_BUTTON_RELEASED();

            // record
            DbpString("[=] start recording");

            // findone, high, low, no ledcontrol (A)
            uint32_t hi = 0, lo = 0;
            lf_hid_watch(1, &hi, &lo, true);
            high[selected] = hi;
            low[selected] = lo;

            Dbprintf("[=]   recorded %x | %x%08x", selected, high[selected], low[selected]);

            // got nothing. blink and loop.
            if (hi == 0 && lo == 0) {
                SpinErr((selected == 0) ? LED_A : LED_B, 100, 12);
                DbpString("[=] only got zeros, retry recording after click");
                continue;
            }

            SpinErr((selected == 0) ? LED_A : LED_B, 250, 2);
            state = STATE_SIM;
            continue;

        } else if (state == STATE_SIM) {

            LED_C_ON();   // Simulate
            LED_D_OFF();
            WAIT_BUTTON_RELEASED();

            Dbprintf("[=] simulating %x | %x%08x", selected, high[selected], low[selected]);

            // high, low, no led control(A)  no time limit
            CmdHIDsimTAGEx(0, high[selected], low[selected], 0, false, -1);

            DbpString("[=] simulating done");

            uint8_t leds = ((selected == 0) ? LED_A : LED_B) | LED_C;
            SpinErr(leds, 250, 2);
            state = STATE_CLONE;
            continue;

        } else if (state == STATE_CLONE) {

            LED_C_OFF();
            LED_D_ON();   // clone
            WAIT_BUTTON_RELEASED();

            Dbprintf("[=]    cloning %x | %x%08x", selected, high[selected], low[selected]);

            // high2, high, low,  no longFMT
            CopyHIDtoT55x7(0, high[selected], low[selected], 0, false, false, true);

            DbpString("[=] cloned done");

            state = STATE_READ;
            uint8_t leds = ((selected == 0) ? LED_A : LED_B) | LED_D;
            SpinErr(leds, 250, 2);
            selected = (selected + 1) % OPTS;
            LEDsoff();
        }
    }

    SpinErr((LED_A | LED_B | LED_C | LED_D), 250, 5);
    DbpString("[=] You can take shell back :) ...");
    LEDsoff();
}
