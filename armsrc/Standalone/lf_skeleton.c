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
// main code for skeleton  by Iceman
//-----------------------------------------------------------------------------
#include "standalone.h" // standalone definitions
#include "proxmark3_arm.h"
#include "appmain.h"
#include "fpgaloader.h"
#include "util.h"
#include "dbprint.h"

void ModInfo(void) {
    DbpString("  LF skeleton mode -  aka Skeleton (iceman)");
}

void RunMod(void) {
    StandAloneMode();
    Dbprintf("[=] LF skeleton code a.k.a Skeleton started");
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    // the main loop for your standalone mode
    for (;;) {
        WDT_HIT();

        // exit from RunMod,   send a usbcommand.
        if (data_available()) break;

        // Was our button held down or pressed?
        int button_pressed = BUTTON_HELD(1000);

        Dbprintf("button %d", button_pressed);

        if (button_pressed != BUTTON_NO_CLICK)
            break;
    }

    DbpString("[=] exiting");
    LEDsoff();
}
