//-----------------------------------------------------------------------------
// Samy Kamkar, 2012
// Christian Herrmann, 2017
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// main code for LF aka SamyRun by Samy Kamkar
//-----------------------------------------------------------------------------
#include "lf_samyrun.h"

void ModInfo(void) {
    DbpString("   LF HID26 standalone - aka SamyRun (Samy Kamkar)");
}

// samy's sniff and repeat routine for LF
void RunMod() {
    StandAloneMode();
    Dbprintf(">>  LF HID Read/Clone/Sim a.k.a SamyRun Started  <<");
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    uint32_t high[OPTS], low[OPTS];
    int selected = 0;
    int playing = 0;
    int cardRead = 0;
    bool gotCard;
    // Turn on selected LED
    LED(selected + 1, 0);

    for (;;) {
        WDT_HIT();

        // exit from SamyRun,   send a usbcommand.
        if (data_available()) break;

        // Was our button held down or pressed?
        int button_pressed = BUTTON_HELD(1000);

        Dbprintf("button %d", button_pressed);
        SpinDelay(300);

        // Button was held for a second, begin recording
        if (button_pressed > 0 && cardRead == 0) {
            LEDsoff();
            LED(selected + 1, 0);
            LED(LED_D, 0);

            // record
            DbpString("[=] starting recording");

            // wait for button to be released
            while (BUTTON_PRESS())
                WDT_HIT();

            /* need this delay to prevent catching some weird data */
            SpinDelay(500);

            CmdHIDdemodFSK(1, &high[selected], &low[selected], 0);
            Dbprintf("[=] recorded bank %x | %x %08x", selected, high[selected], low[selected]);

            LEDsoff();
            LED(selected + 1, 0);
            // Finished recording
            // If we were previously playing, set playing off
            // so next button push begins playing what we recorded
            playing = 0;
            cardRead = 1;

            gotCard = true;
        } else if (button_pressed > 0 && cardRead == 1) {
            LEDsoff();
            LED(selected + 1, 0);
            LED(LED_A, 0);

            // record
            Dbprintf("[=] cloning %x %x %08x", selected, high[selected], low[selected]);

            // wait for button to be released
            while (BUTTON_PRESS())
                WDT_HIT();

            /* need this delay to prevent catching some weird data */
            SpinDelay(500);

            CopyHIDtoT55x7(0, high[selected], low[selected], 0);
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
        else if (button_pressed && gotCard) {
            // Next option if we were previously playing
            if (playing)
                selected = (selected + 1) % OPTS;

            playing = !playing;

            LEDsoff();
            LED(selected + 1, 0);

            // Begin transmitting
            if (playing) {

                LED(LED_B, 0);
                DbpString("[=] playing");

                // wait for button to be released
                while (BUTTON_PRESS())
                    WDT_HIT();

                Dbprintf("[=] %x %x %08x", selected, high[selected], low[selected]);
                CmdHIDsimTAG(high[selected], low[selected], false);
                DbpString("[=] done playing");

                if (BUTTON_HELD(1000) > 0)
                    goto out;

                /* We pressed a button so ignore it here with a delay */
                SpinDelay(300);

                // when done, we're done playing, move to next option
                selected = (selected + 1) % OPTS;
                playing = !playing;
                LEDsoff();
                LED(selected + 1, 0);
            } else {
                while (BUTTON_PRESS())
                    WDT_HIT();
            }
        }
    }

out:
    DbpString("[=] exiting");
    LEDsoff();
}
