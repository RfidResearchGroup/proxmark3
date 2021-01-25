//-----------------------------------------------------------------------------
// tharexde, 2021
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// main code for EM4x50 simulator and collector aka THAREXDE
//-----------------------------------------------------------------------------
#include <inttypes.h>
#include "ticks.h"
#include "standalone.h"
#include "proxmark3_arm.h"
#include "appmain.h"
#include "BigBuf.h"
#include "fpgaloader.h"
#include "util.h"
#include "dbprint.h"
#include "spiffs.h"
#include "../em4x50.h"

/*
 * `lf_tharexde` simulates EM4x50 dumps uploaded  words/blocks, reads words of standard read
 * mode of EM4x50 tags and stores them in internal flash.
 * It requires RDV4 hardware (for flash and battery).
 *
 * On entering stand-alone mode, this module will start simulating EM4x50 data.
 * Data is read from eml dump file uploaded to flash memory.
 *
 * On switching to read/record mode by pressing pm3 button, module will start
 * reading/recording EM4x50 data. Every found / collected data will be
 * written/appended to the logfile in flash as a text string.
 *
 * LEDs:
 * - LED A: simulating
 * - LED B: reading / record
 * - LED C: writing to flash
 * - LED D: unmounting/sync'ing flash (normally < 100ms)
 *
 * To upload input file (eml format) to flash:
 * - mem spiffs load f <filename> o lf_em4x50_simulate.eml
 *
 * To retrieve log file from flash:
 * - mem spiffs dump o lf_em4x50_collect.log f <filename>
 *
 * This module emits debug strings during normal operation -- so try it out in
 * the lab connected to PM3 client before taking it into the field.
 *
 * To delete the input file from flash:
 * - mem spiffs remove lf_em4x50_simulate.eml
 *
 * To delete the log file from flash:
 * - mem spiffs remove lf_em4x50_collect.log
 */

#define STATE_SIM                       0
#define STATE_READ                      1
#define EM4X50_TAG_WORD                 45
#define LF_EM4X50_INPUTFILE_SIM         "lf_em4x50_simulate.eml"
#define LF_EM4X50_LOGFILE_COLLECT       "lf_em4x50_collect.log"

bool input_exists;
bool log_exists;

static void LoadDataInstructions(const char *inputfile) {
    Dbprintf("");
    Dbprintf("To load datafile to flash and display it:");
    Dbprintf(_YELLOW_("1.") " edit input file %s", inputfile);
    Dbprintf(_YELLOW_("2.") " start proxmark3 client");
    Dbprintf(_YELLOW_("3.") " mem spiffs load f <filename> o %s", inputfile);
    Dbprintf(_YELLOW_("4.") " start standalone mode");
}

static void DownloadLogInstructions(const char *logfile) {
    Dbprintf("");
    Dbprintf("To get the logfile from flash and display it:");
    Dbprintf(_YELLOW_("1.") " mem spiffs dump o %s f <filename>", logfile);
    Dbprintf(_YELLOW_("2.") " exit proxmark3 client");
    Dbprintf(_YELLOW_("3.") " cat <filename>");
}

static bool get_input_data_from_file(uint32_t *tag, char *inputfile) {

    size_t now = 0;
    if (exists_in_spiffs(inputfile)) {

        uint32_t size = size_in_spiffs(inputfile);
        uint8_t *mem = BigBuf_malloc(size);

        Dbprintf(_YELLOW_("found input file %s"), inputfile);

        rdv40_spiffs_read_as_filetype(inputfile, mem, size, RDV40_SPIFFS_SAFETY_SAFE);

        now = size / 9;
        for (int i = 0; i < now; i++)
            for (int j = 0; j < 4; j++)
                tag[i] |= (hex2int(mem[2 * j + 9 * i]) << 4 | hex2int(mem[2 * j + 1 + 9 * i])) << ((3 - j) * 8);

        Dbprintf(_YELLOW_("read tag data from input file"));
    }

    BigBuf_free();

    return ((now == EM4X50_NO_WORDS) && (tag[EM4X50_DEVICE_SERIAL] != tag[EM4X50_DEVICE_ID]));
}

static void append(const char *filename, uint8_t *entry, size_t entry_len) {

    LED_D_ON();
    if (log_exists == false) {
        rdv40_spiffs_write(filename, entry, entry_len, RDV40_SPIFFS_SAFETY_SAFE);
        log_exists = true;
    } else {
        rdv40_spiffs_append(filename, entry, entry_len, RDV40_SPIFFS_SAFETY_SAFE);
    }
    LED_D_OFF();
}

void ModInfo(void) {
    DbpString(_YELLOW_("  LF EM4x50 sim/collector mode") " - a.k.a tharexde");
}

void RunMod(void) {

    bool state_change = true;
    int no_words = 0, command = 0;
    uint8_t entry[81], state = STATE_SIM;
    uint32_t tag[EM4X50_NO_WORDS] = {0x0};

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

            SpinUp(100);

            switch (state) {

                case STATE_SIM:
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
            SpinDown(100);
            break;
        }

        if (state == STATE_SIM) {

            if (state_change) {

                LEDsoff();
                LED_A_ON();
                Dbprintf("");
                Dbprintf(_YELLOW_("switched to EM4x50 simulating mode"));

                if (get_input_data_from_file(tag, LF_EM4X50_INPUTFILE_SIM)) {
                    Dbprintf(_YELLOW_("tag data ok"));
                } else {
                    Dbprintf(_RED_("error in tag data"));
                }
                
                // init; start with command = standard read mode
                em4x50_setup_sim();
                gLogin = false;
                gWritePasswordProcess = false;
                command = EM4X50_COMMAND_STANDARD_READ;

                state_change = false;
            }

            em4x50_handle_commands(&command, tag);

            // stop if key (pm3 button or enter key) has been pressed
            if (command == PM3_EOPABORTED) {
                break;
            }

            // if timeout (e.g. no reader field) continue with standard read
            // mode and reset former authentication
            if (command == PM3_ETIMEOUT) {
                command = EM4X50_COMMAND_STANDARD_READ;
                gLogin = false;
            }
            
        } else if (state == STATE_READ) {

            if (state_change) {

                LEDsoff();
                LED_B_ON();
                Dbprintf("");
                Dbprintf(_YELLOW_("switched to EM4x50 reading mode"));

                memset(entry, 0, sizeof(entry));
                memset(tag, 0, sizeof(tag));

                log_exists = exists_in_spiffs(LF_EM4X50_LOGFILE_COLLECT);
                
                em4x50_setup_read();
                
                state_change = false;
            }

            standard_read(&no_words, tag);

            // reset timers
            AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG; // re-enable timer and wait for TC0
            AT91C_BASE_TC0->TC_RC  = 0; // set TIOA (carry bit) on overflow, return to zero
            AT91C_BASE_TC0->TC_RA  = 1; // clear carry bit on next clock cycle
            AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG; // reset and re-enable timer

            if (no_words > 0) {

                memset(entry, 0, sizeof(entry));

                Dbprintf("");
                sprintf((char *)entry, "found new EM4x50 tag:");
                Dbprintf("%s", entry);
                strcat((char *)entry, "\n");
                append(LF_EM4X50_LOGFILE_COLLECT, entry, strlen((char *)entry));

                for (int i = 0; i < no_words; i++) {

                    sprintf((char *)entry, "  %2i -> 0x%08"PRIx32"", i + 1, tag[i]);
                    Dbprintf("%s", entry);
                    strcat((char *)entry, "\n");
                    append(LF_EM4X50_LOGFILE_COLLECT, entry, strlen((char *)entry));
                }
            }
            
            memset(tag, 0, sizeof(tag));
            no_words = 0;
        }
    }

    if (state == STATE_READ) {
        DownloadLogInstructions(LF_EM4X50_LOGFILE_COLLECT);
    } else {
        LoadDataInstructions(LF_EM4X50_INPUTFILE_SIM);
    }

    LED_D_ON();
    rdv40_spiffs_lazy_unmount();
    LED_D_OFF();

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    LEDsoff();
    Dbprintf("");
    Dbprintf(_YELLOW_("[=] Standalone mode THAREXDE stopped"));
}
