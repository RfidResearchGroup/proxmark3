//-----------------------------------------------------------------------------
// Copyright (C) Daniel Karling, 2021
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
 *  How this works:
 *  The basic idea is to simply include several c-files with additional
 *  modes into this file. Hopefully the only collision of symbols are
 *  the RunMod and ModInfo, and these are solved by dankarmulti.h.
 *
 *  First, dankarmulti.h is included once by itself to define some macros
 *  used later.
 *
 *  For each mode to be included we define MODE_NAME which is a unique
 *  name to give the mode and MODE_FILE which is the name of the C-file
 *  for the mode. dankarmulti.h will make sure that RunMod and
 *  ModInfo is renamed to RunMod_NAME where name is what we defined. It
 *  will also include the actual mode source code and create a struct
 *  with function pointer to the run and info functions of the mode.
 *  At the end of dankarmulti.h it does #undef on MODE_NAME and MODE_FILE
 *  so that they can be redefined for the next mode to include.
 *
 *  To create a list of the modes we now have available, it is necessary
 *  to use the START_MODE_LIST, ADD_MODE and END_MODE_LIST macros. This
 *  could also have been done with some linker magic and a new section,
 *  or by some other dirty hack. But this works for now.
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

#define MODE_NAME mattyrun
#define MODE_FILE "hf_mattyrun.c"
#include "dankarmulti.h"
#define MODE_NAME em4100
#define MODE_FILE "lf_em4100rswb.c"
#include "dankarmulti.h"
#define MODE_NAME tcprst
#define MODE_FILE "hf_tcprst.c"
#include "dankarmulti.h"

START_MODE_LIST
ADD_MODE(mattyrun)
ADD_MODE(em4100)
ADD_MODE(tcprst)
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
