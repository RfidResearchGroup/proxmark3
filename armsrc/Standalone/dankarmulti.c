//-----------------------------------------------------------------------------
// Daniel Karling, 2021
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// main code for Multi Loader
//-----------------------------------------------------------------------------
#include "standalone.h" // standalone definitions
#include "proxmark3_arm.h"
#include "appmain.h"
#include "fpgaloader.h"
#include "ticks.h"
#include "util.h"
#include "dbprint.h"

/*
 * This mode will allow you to access multiple different standalone
 * modes at the same time. The below section defines which modes are
 * available. Modes are added to the mode list according to the
 * following:
 *
 *  1) Include "dankarmulti.h"
 *  2) Define MODE_NAME and MODE_FILE for a mode (MODE_NAME can
 *     of your choosing, but must be a valid C token. I.e. pretend
 *     that you are naming a variable)
 *  3) Include "dankarmulti.h" again
 *  4) Repeat steps 2 and 3 for additional modes.
 *  5) Use the macros START_MODE_LIST, ADD_MODE and END_MODE_LIST
 *     to create the list of modes. You need to use the same names
 *     here as defined earlier.
 *
 *  Usage:
 *  Single press to cycle between the modes.
 *  The LEDs will show the currently selected mode.
 *  Hold button to start the selected mode.
 *
 *  How many modes can you have at the same time? Depends on memory,
 *  but the LEDs will overflow after 15.
 *
 *  I don't know if this works with all the different standalone modes.
 *  I would imagine that it doesn't. If two modes are included with
 *  functions that collide (name-wise) there will be issues.
 *
 *  NOTE: You will have to keep track of if the included modes require
 *  external memory or bluetooth yourself. The mode selection in
 *  the Makefiles is not able to do it.
 */


/*******************
 * Begin mode list *
 *******************/

#include "dankarmulti.h"

#define MODE_NAME sniff14a
#define MODE_FILE "hf_14asniff.c"
#include "dankarmulti.h"
#define MODE_NAME em4100
#define MODE_FILE "lf_em4100rswb.c"
#include "dankarmulti.h"
#define MODE_NAME icehid
#define MODE_FILE "lf_icehid.c"
#include "dankarmulti.h"

START_MODE_LIST
ADD_MODE(sniff14a)
ADD_MODE(em4100)
ADD_MODE(icehid)
END_MODE_LIST

/*******************
 *  End mode list  *
 *******************/

void update_mode(int selected);

void ModInfo(void) {
    DbpString("  Multi standalone loader aka dankarmulti (Daniel Karling)");
}

void update_mode(int selected) {
    if (selected >= NUM_MODES) {
        SpinDown(100);
        Dbprintf("Invalid mode selected");
        LEDsoff();
    } else {
        Dbprintf("Selected mode: '%s'", mode_list[selected]->name);
        LEDsoff();
        LED(selected + 1, 0);
    }
}


void RunMod(void) {
    int selected_mode = 0;

    StandAloneMode();
    Dbprintf("[=] Multi standalone loader aka dankarmulti (Daniel Karling)");
    Dbprintf("[=] Available modes:");

    for (int i = 0; i < NUM_MODES; i++) {
        Dbprintf("[=]   '%s'", mode_list[i]->name);
    }

    update_mode(selected_mode);

    // the main loop for your standalone mode
    for (;;) {
        WDT_HIT();

        // exit from RunMod,   send a usbcommand.
        if (data_available()) break;

        // Was our button held down or pressed?
        int button_pressed = BUTTON_HELD(1000);

        switch (button_pressed) {
            case BUTTON_SINGLE_CLICK:
                selected_mode = (selected_mode + 1) % NUM_MODES;
                update_mode(selected_mode);
                SpinDelay(300);
                break;
            case BUTTON_HOLD:
                Dbprintf("Starting selected mode ('%s')", mode_list[selected_mode]->name);
                mode_list[selected_mode]->run();
                Dbprintf("Exited from selected mode");
                return;
            default:
                break;
        }
    }

    DbpString("[=] exiting");
    LEDsoff();
}
