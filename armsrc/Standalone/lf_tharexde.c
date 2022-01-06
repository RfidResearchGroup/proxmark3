//-----------------------------------------------------------------------------
// Copyright (C) tharexde, 2021
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
// main code for EM4x50 simulator and collector aka THAREXDE
//-----------------------------------------------------------------------------
#include <inttypes.h>
#include "ticks.h"
#include "standalone.h"
#include "proxmark3_arm.h"
#include "appmain.h"
#include "BigBuf.h"
#include "commonutil.h"
#include "fpgaloader.h"
#include "util.h"
#include "dbprint.h"
#include "spiffs.h"
#include "../em4x50.h"

/*
 * `lf_tharexde` simulates EM4x50 dumps uploaded to flash, reads words
 * transmitted by EM4x50 tags in standard read mode and stores them in
 * internal flash.
 * It requires RDV4 hardware (for flash and battery).
 *
 * On entering stand-alone mode, this module will start simulating EM4x50 data.
 * Data is read from eml dump file uploaded to flash memory (lf_em4x50_simulate.eml).
 * If reader sends password different from dump file password, it is saved in
 * file lf_em4x50_passwords.log in flash memory.
 *
 * On switching to read/record mode by pressing pm3 button, module will start
 * reading EM4x50 data. Each collected data set will be written/appended to the
 * logfile in flash (lf_em4x50_collect.log) as a text string.
 *
 * LEDs:
 * - LED A: simulating
 * - LED A blinking: no simulation data or read error
 * - LED B: reading/recording
 * - LED D: unmounting/sync'ing flash (normally < 100ms)
 *
 * To upload input file (eml format) to flash:
 * - mem spiffs upload -s <filename> -d lf_em4x50_simulate.eml
 *
 * To retrieve password file from flash:
 * - mem spiffs dump -s lf_em4x50_passwords.log
 *
 * To retrieve log file from flash:
 * - mem spiffs dump -s lf_em4x50_collect.log
 *
 * This module emits debug strings during normal operation -- so try it out in
 * the lab connected to PM3 client before taking it into the field.
 *
 * To delete the input file from flash:
 * - mem spiffs remove -f lf_em4x50_simulate.eml
 *
 * To delete the log file from flash:
 * - mem spiffs remove -f lf_em4x50_passwords.log
 *
 * To delete the log file from flash:
 * - mem spiffs remove -f lf_em4x50_collect.log
 */

#define STATE_SIM                       0
#define STATE_READ                      1
#define LF_EM4X50_INPUTFILE_SIM         "lf_em4x50_simulate.eml"
#define LF_EM4X50_LOGFILE_SIM           "lf_em4x50_passwords.log"
#define LF_EM4X50_LOGFILE_COLLECT       "lf_em4x50_collect.log"
#define MAX_NO_PWDS_TO_SAVE             50

static void LoadDataInstructions(const char *inputfile) {
    Dbprintf("");
    Dbprintf("To load datafile to flash and display it:");
    Dbprintf("1. edit input file %s", inputfile);
    Dbprintf("2. start proxmark3 client");
    Dbprintf("3. mem spiffs upload -s <filename> -d %s", inputfile);
    Dbprintf("4. start standalone mode");
}

static void DownloadLogInstructions(const char *logfile) {
    Dbprintf("");
    Dbprintf("To get the logfile from flash and display it:");
    Dbprintf("1. mem spiffs dump -s %s", logfile);
    Dbprintf("2. exit proxmark3 client");
    Dbprintf("3. cat <filename>");
}

static bool get_input_data_from_file(uint32_t *tag, char *inputfile) {

    size_t now = 0;

    if (exists_in_spiffs(inputfile)) {

        uint32_t size = size_in_spiffs(inputfile);
        uint8_t *mem = BigBuf_malloc(size);

        Dbprintf(_YELLOW_("found input file %s"), inputfile);

        rdv40_spiffs_read_as_filetype(inputfile, mem, size, RDV40_SPIFFS_SAFETY_SAFE);

        now = (size + 1) / 9;
        for (int i = 0; i < now; i++) {
            for (int j = 0; j < 4; j++) {
                tag[i] |= (hex2int(mem[2 * j + 9 * i]) << 4 | hex2int(mem[2 * j + 1 + 9 * i])) << ((3 - j) * 8);
            }
        }

        Dbprintf(_YELLOW_("read tag data from input file"));
    } else {
        Dbprintf(_RED_("no input file %s"), inputfile);
    }

    BigBuf_free();

    return ((now == EM4X50_NO_WORDS) && (tag[EM4X50_DEVICE_SERIAL] != tag[EM4X50_DEVICE_ID]));
}

static void append(const char *filename, uint8_t *entry, size_t entry_len) {
    if (exists_in_spiffs(filename)) {
        rdv40_spiffs_append(filename, entry, entry_len, RDV40_SPIFFS_SAFETY_SAFE);
    } else {
        rdv40_spiffs_write(filename, entry, entry_len, RDV40_SPIFFS_SAFETY_SAFE);
    }
}

static void save_pwds(uint32_t *pwdlist, size_t no_pwd) {
    if (no_pwd > 0) {
        Dbprintf("");
        for (int i = 0; i < no_pwd; i++) {
            uint8_t entry[10] = {0};
            sprintf((char *)entry, "%08"PRIx32"\n", pwdlist[i]);
            append(LF_EM4X50_LOGFILE_SIM, entry, strlen((char *)entry));
            Dbprintf("received password: %08"PRIx32"", pwdlist[i]);
        }
    }
}

void ModInfo(void) {
    DbpString(_YELLOW_("  LF EM4x50 sim/collector mode") " - a.k.a tharexde");
}

void RunMod(void) {

    bool state_change = true, read_ok = false;
    int no_words = 0, command = 0, no_pwd = 0;
    uint8_t entry[400], state = STATE_SIM;
    uint32_t tag[EM4X50_NO_WORDS] = {0x0}, pwdlist[MAX_NO_PWDS_TO_SAVE];

    rdv40_spiffs_lazy_mount();
    StandAloneMode();
    Dbprintf(_YELLOW_("Standalone mode THAREXDE started"));

    for (;;) {

        WDT_HIT();
        if (data_available()) {
            break;
        }

        // press button - toggle between SIM and READ
        // hold button - exit
        int button_pressed = BUTTON_CLICKED(1000);
        if (button_pressed == BUTTON_SINGLE_CLICK) {

            switch (state) {
                case STATE_SIM:
                    // save and display passwords
                    save_pwds(pwdlist, no_pwd);
                    state = STATE_READ;
                    break;
                case STATE_READ:
                    state = STATE_SIM;
                    break;
                default:
                    break;
            }

            state_change = true;

        } else if (button_pressed == BUTTON_HOLD) {
            break;
        }

        if (state == STATE_SIM) {

            if (state_change) {

                // initialize simulation mode
                LEDsoff();
                LED_A_ON();
                Dbprintf("");
                Dbprintf(_YELLOW_("switched to EM4x50 simulating mode"));

                read_ok = get_input_data_from_file(tag, LF_EM4X50_INPUTFILE_SIM);
                if (read_ok) {
                    Dbprintf(_YELLOW_("tag data ok"));
                } else {
                    Dbprintf(_RED_("error in tag data"));
                    LoadDataInstructions(LF_EM4X50_INPUTFILE_SIM);
                }

                LED_D_OFF();
                g_Login = false;
                g_Password = reflect32(tag[0]);
                g_WritePasswordProcess = false;
                command = EM4X50_COMMAND_STANDARD_READ;
                no_pwd = 0;
                memset(pwdlist, 0, sizeof(pwdlist));

                em4x50_setup_sim();
                state_change = false;
            }

            // if no data or read error -> blink
            if (read_ok == false) {
                LED(LED_A, 200);
                SpinDelay(200);
            }

            em4x50_handle_commands(&command, tag, true);

            // check if new password was found
            if (g_Password != reflect32(tag[EM4X50_DEVICE_PASSWORD])) {
                if (no_pwd < MAX_NO_PWDS_TO_SAVE) {
                    pwdlist[no_pwd] = g_Password;
                    no_pwd++;
                }
                g_Password = reflect32(tag[EM4X50_DEVICE_PASSWORD]);
            }

            // if timeout (e.g. no reader field) continue with standard read
            // mode and reset former authentication
            if (command == PM3_ETIMEOUT) {
                command = EM4X50_COMMAND_STANDARD_READ;
                g_Login = false;
                LED_D_OFF();
            }

        } else if (state == STATE_READ) {

            if (state_change) {

                // initialize read mode
                LEDsoff();
                LED_B_ON();
                Dbprintf("");
                Dbprintf(_YELLOW_("switched to EM4x50 reading mode"));

                em4x50_setup_read();
                state_change = false;
            }

            no_words = 0;
            memset(tag, 0, sizeof(tag));
            standard_read(&no_words, tag);

            if (no_words > 0) {

                memset(entry, 0, sizeof(entry));

                sprintf((char *)entry, "found EM4x50 tag:\n");
                for (int i = 0; i < no_words; i++) {
                    sprintf((char *)entry + strlen((char *)entry), "%08"PRIx32"\n", tag[i]);
                }
                Dbprintf("%s", entry);
                sprintf((char *)entry + strlen((char *)entry), "\n");
                append(LF_EM4X50_LOGFILE_COLLECT, entry, strlen((char *)entry));
            }
        }

        // reset timer
        AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG; // re-enable timer and wait for TC0
        AT91C_BASE_TC0->TC_RC  = 0; // set TIOA (carry bit) on overflow, return to zero
        AT91C_BASE_TC0->TC_RA  = 1; // clear carry bit on next clock cycle
        AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG; // reset and re-enable timer
    }

    if (state == STATE_READ) {
        DownloadLogInstructions(LF_EM4X50_LOGFILE_COLLECT);
    } else {
        // save and display passwords
        save_pwds(pwdlist, no_pwd);
        DownloadLogInstructions(LF_EM4X50_LOGFILE_SIM);
    }

    LED_D_ON();
    rdv40_spiffs_lazy_unmount();
    LED_D_OFF();

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    LEDsoff();
    Dbprintf("");
    Dbprintf(_YELLOW_("[=] Standalone mode THAREXDE stopped"));
}
