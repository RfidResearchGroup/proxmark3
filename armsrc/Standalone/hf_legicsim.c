//-----------------------------------------------------------------------------
// Copyright (C) Uli Heilmeier, 2022
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
// Based on hf_mfcsim by Ray Lee
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
// main code for legic prime simulator aka LEGICSIM
//-----------------------------------------------------------------------------
#include <inttypes.h>
#include "ticks.h"
#include "proxmark3_arm.h"
#include "BigBuf.h"
#include "commonutil.h"
#include "fpgaloader.h"
#include "util.h"
#include "dbprint.h"
#include "spiffs.h"
#include "standalone.h" // standalone definitions
#include "appmain.h"
#include "string.h"
#include "legicrf.h"
#include "legicrfsim.h"
#include "legic.h"

/*
 * `hf_legicsim` simulates legic prime MIM1024 dumps uploaded to flash.
 * It requires RDV4 hardware (for flash and battery).
 *
 * On entering stand-alone mode, this module will start simulating.
 * Data is read from bin dump file uploaded to flash memory (hf_legicsim_dump_xx.bin).
 * Only support legic prime MIM1024
 *
 * To upload input file (eml format) to flash:
 * - mem spiffs upload -s <filename> -d hf_legicsim_dump_xx.bin (Notes: xx is form 01 to 15)
 * To delete the input file from flash:
 * - mem spiffs remove -f hf_legicsim_dump_xx.bin (Notes: xx is form 01 to 15)
 *
 */

#define HF_LEGICSIM_DUMPFILE_SIM "hf_legicsim_dump_%02d.bin"
#define DUMP_SIZE 1024

static char cur_dump_file[24] = {0};

static bool fill_eml_from_file(char *dumpfile) {
    // check file exist
    if (!exists_in_spiffs(dumpfile)) {
        Dbprintf(_RED_("Dump file %s not found!"), dumpfile);
        return false;
    }
    //check dumpfile size
    uint32_t size = size_in_spiffs(dumpfile);
    if (size != DUMP_SIZE) {
        Dbprintf(_RED_("File Size: %dB  The dump file size is incorrect! Only support Legic Prime MIM1024! Please check it."));
        BigBuf_free();
        return false;
    }
    //read and load dump file
    BigBuf_Clear();
    if (g_dbglevel >= DBG_INFO) {
        Dbprintf("Found dump file... `" _YELLOW_("%s") "`", dumpfile);
        Dbprintf("Uploading to emulator memory...");
    }
    uint8_t *emCARD = BigBuf_get_EM_addr();
    rdv40_spiffs_read_as_filetype(dumpfile, emCARD, size, RDV40_SPIFFS_SAFETY_SAFE);
    return true;
}

static bool write_file_from_eml(char *dumpfile) {
    if (!exists_in_spiffs(dumpfile)) {
        Dbprintf(_RED_("Dump file %s not found!"), dumpfile);
        return false;
    }
    uint8_t *emCARD = BigBuf_get_EM_addr();
    rdv40_spiffs_write(dumpfile, emCARD, DUMP_SIZE, RDV40_SPIFFS_SAFETY_SAFE);
    return true;
}

void ModInfo(void) {
    DbpString(_YELLOW_("  HF Legic Prime simulation mode") " - a.k.a LEGICSIM");
}

void RunMod(void) {
    //initializing
    StandAloneMode();
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    rdv40_spiffs_lazy_mount();
    Dbprintf(_YELLOW_("Standalone mode LEGICSIM started!"));

    bool flag_has_dumpfile = false;
    for (int i = 1;; i++) {
        //Exit! usbcommand break
        if (data_available()) break;

        //Infinite loop
        if (i > 15) {
            if (!flag_has_dumpfile)
                break; //still no dump file found
            i = 1;     //next loop
        }

        //Indicate which card will be simulated
        LED(i, 0);

        //Try to load dump from flash
        sprintf(cur_dump_file, HF_LEGICSIM_DUMPFILE_SIM, i);
        Dbprintf(_YELLOW_("[Slot: %d] Try to load dump file: %s"), i, cur_dump_file);
        if (!fill_eml_from_file(cur_dump_file)) {
            Dbprintf(_YELLOW_("[Slot: %d] Dump load Failed, Next one!"), i);
            LEDsoff();
            continue;
        }
        flag_has_dumpfile = true;

        //Exit! Button hold break
        int button_pressed = BUTTON_HELD(500);
        if (button_pressed == BUTTON_HOLD) {
            Dbprintf("Button hold, Break!");
            break;
        }

        //Hope there is enough time to see clearly
        SpinDelay(500);

        //Start to simulate

        Dbprintf(_YELLOW_("[Slot: %d] Simulation start, Press button to change next card."), i);
        LegicRfSimulate(2, false);
        Dbprintf(_YELLOW_("[Slot: %d] Simulation end, Write Back to dump file!"), i);

        //Simulation end, Write Back
        if (!write_file_from_eml(cur_dump_file)) {
            Dbprintf(_RED_("[Slot: %d] Write Failed! Anyway, Change to next one!"), i);
            continue;
        }
        Dbprintf(_YELLOW_("[Slot: %d] Write Success! Change to next one!"), i);
    }
    if (!flag_has_dumpfile)
        Dbprintf("No dump file found!");
    Dbprintf("Breaked! Exit standalone mode!");
    SpinErr(15, 200, 3);
    return;
}
