//-----------------------------------------------------------------------------
// Copyright (C) Stefanie Hofmann and Uli Heilmeier, 2020
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
// main code for Legic Prime read/sim
//-----------------------------------------------------------------------------

#include "standalone.h"
#include "proxmark3_arm.h"
#include "BigBuf.h"
#include "appmain.h"
#include "fpgaloader.h"
#include "util.h"
#include "dbprint.h"
#include "ticks.h"
#include "legicrf.h"
#include "legicrfsim.h"
#include "legic.h"          // legic_card_select_t struct
#include "spiffs.h"         // flashmem

/*
 * To list all dump files from flash:
 *
 * 1.  mem spiffs tree
 *
 *
 * To retrieve dump files from flash:
 *
 * 1. mem spiffs dump -s hf-legic-XXYYZZWW-dump.bin -d hf-legic-XXYYZZWW-dump.bin
 *    Copies log file from flash to your client.
 *
 *
 * This module emits debug strings during normal operation -- so try it out in
 * the lab connected to PM3 client before taking it into the field.
 *
 * To delete a dump file from flash:
 *
 * 1. mem spiffs remove -f hf-legic-XXYYZZWW-dump.bin
 *
*/

#ifdef WITH_FLASH
static void DownloadLogInstructions(void) {
    Dbprintf("");
    Dbprintf("[=] List all dumps from flash:");
    Dbprintf("[=]   " _YELLOW_("-") " mem spiffs tree");
    Dbprintf("");
    Dbprintf("[=] To save a dump file from flash to client:");
    Dbprintf("[=]   " _YELLOW_("-") " mem spiffs dump -s hf-legic-UID-dump.bin -d hf-legic-UID-dump.bin");
}
#endif

static void save_dump_to_file(legic_card_select_t *p_card) {

#ifdef WITH_FLASH

    // legic functions puts it memory in Emulator reserved memory.
    uint8_t *mem = BigBuf_get_EM_addr();

    char *preferredName = (char *)BigBuf_malloc(30);
    if (preferredName == NULL) {
        goto OUT;
    }

    sprintf(preferredName, "hf-legic-%02X%02X%02X%02X-dump", p_card->uid[0], p_card->uid[1], p_card->uid[2], p_card->uid[3]);
    uint16_t preferredNameLen = strlen(preferredName);

    char *filename = (char *)BigBuf_malloc(preferredNameLen + 4 + 1 + 10);
    if (filename == NULL) {
        goto OUT;
    }

    sprintf(filename, "%.*s%s", preferredNameLen, preferredName, ".bin");
    uint16_t num = 1;
    while (exists_in_spiffs(filename)) {
        sprintf(filename, "%.*s-%d%s", preferredNameLen, preferredName, num, ".bin");
        num++;
    }

    rdv40_spiffs_write(filename, mem, p_card->cardsize, RDV40_SPIFFS_SAFETY_SAFE);

    Dbprintf("[=] saved card dump to flashmem::" _YELLOW_("%s"), filename);
OUT:
    BigBuf_free_keep_EM();
#endif

}

void ModInfo(void) {
    DbpString("  HF Legic Prime standalone");
}

// Searching for Legic card until found and read.
// Simulating recorded Legic Prime card.
// C = Searching
// A, B, C = Reading
// A, D = Simulating

void RunMod(void) {
    StandAloneMode();
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    Dbprintf("[=] >>  HF Legic Prime Read/Simulate Started  <<");
    DbpString("[=] press and HOLD button to exit standalone mode");

    for (;;) {
        WDT_HIT();

        //exit from hf_legic,  send usbcommand
        if (data_available()) break;

        //Was our button held down or pressed?
        int button_pressed = BUTTON_HELD(280);
        if (button_pressed == BUTTON_HOLD) {
            break;
        }

        LEDsoff();
        LED_C_ON();

        DbpString("[=] looking for tags");
        int read_success = PM3_ESOFT;

        //search for legic card until reading successful or button pressed
        do {
            LED_C_ON();
            SpinDelay(500);
            // We don't care if we read a MIM256, MIM512 or MIM1024
            // we just read 1024 bytes
            read_success = LegicRfReaderEx(0, 1024, 0x55);

        } while ((read_success == PM3_ESOFT) && (BUTTON_PRESS() == false));

        LEDsoff();

        //simulate if read successfully
        if (read_success != PM3_ESOFT) {

            legic_card_select_t *p_card;
            p_card = getLegicCardInfo();
            if (p_card->cardsize == 0)
                continue;

            save_dump_to_file(p_card);

            LED_D_ON();
            uint8_t ct;
            switch (p_card->tagtype) {
                case 0x0D:
                    ct = 0;
                    break;
                case 0x1D:
                    ct = 1;
                    break;
                case 0x3D:
                    ct = 2;
                    break;
                default:
                    continue;
            }

            // The read data is migrated to a MIM1024 card
            LegicRfSimulate(ct, false);
        }
    }

    LEDsoff();
#ifdef WITH_FLASH
    DownloadLogInstructions();
#endif
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
}
