//-----------------------------------------------------------------------------
// Christian Herrmann, 2019
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// main code for skeleton  aka IceRun by Iceman
//-----------------------------------------------------------------------------
#include "lf_icerun.h"

void ModInfo(void) {
    DbpString("   LF skeleton mode -  aka IceRun (iceman)");
}

// samy's sniff and repeat routine for LF
void RunMod() {
    StandAloneMode();
    Dbprintf("[=] LF skeleton code a.k.a IceRun started");
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    // the main loop for your standalone mode
    for (;;) {
        WDT_HIT();

        // exit from IceRun,   send a usbcommand.
        if (data_available()) break;

        // Was our button held down or pressed?
        int button_pressed = BUTTON_HELD(1000);

        Dbprintf("button %d", button_pressed);

        if (button_pressed)
            break;
    }

    DbpString("[=] exiting");
    LEDsoff();
}
