//-----------------------------------------------------------------------------
// Tharexde, 2020
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// main code for EM4x50 simulator and collector aka THAREXDE
//-----------------------------------------------------------------------------
#include <inttypes.h>
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
 * `lf_tharexde` simulates hardcoded words/blocks, reads words of standard read
 * mode of EM4x50 tags and stores them in internal flash.
 * It requires RDV4 hardware (for flash and battery).
 *
 * On entering stand-alone mode, this module will start reading/record EM4x50 data.
 * Every found / collected data will be written/appended to the logfile in flash
 * as a text string.
 *
 * LEDs:
 * - LED A: simulating
 * - LED B: reading / record
 * - LED C: writing to flash
 * - LED D: unmounting/sync'ing flash (normally < 100ms)
 *
 * To retrieve log file from flash:
 *
 * 1. mem spiffs dump o lf_em4x50collect.log f lf_em4x50collect.log
 *    Copies log file from flash to your client.
 *
 * 2. exit the Proxmark3 client
 *
 * 3. more lf_tharexdecollect.log
 *
 * This module emits debug strings during normal operation -- so try it out in
 * the lab connected to PM3 client before taking it into the field.
 *
 * To delete the log file from flash:
 *
 * 1. mem spiffs remove lf_tharexdecollect.log
 */

#define STATE_SIM                   0
#define STATE_READ                  1
#define STATE_BRUTE                 2
#define EM4X50_TAG_WORD             45
#define EM4X50_PWD_SPEED            27
#define LF_EM4X50SIMULATE_INPUTFILE "lf_em4x50simulate.eml"
#define LF_EM4X50COLLECT_LOGFILE    "lf_em4x50collect.log"
#define LF_EM4X50BRUTE_INPUTFILE    "lf_em4x50brute.eml"
#define LF_EM4X50BRUTE_LOGFILE      "lf_em4x50brute.log"

bool input_exists;
bool log_exists;

static void LoadDataInstructions(const char *inputfile) {
    Dbprintf("");
    Dbprintf("To load datafile into flash and display it:");
    Dbprintf(_YELLOW_("1.") " edit inputfile %s", inputfile);
    Dbprintf(_YELLOW_("2.") " start proxmark3 client");
    Dbprintf(_YELLOW_("3.") " mem spiffs load f %s o %s", inputfile, inputfile);
    Dbprintf(_YELLOW_("4.") " start standalone mode");
}

static void DownloadLogInstructions(const char *logfile) {
    Dbprintf("");
    Dbprintf("To get the logfile from flash and display it:");
    Dbprintf(_YELLOW_("1.") " mem spiffs dump o %s f %s", logfile, logfile);
    Dbprintf(_YELLOW_("2.") " exit proxmark3 client");
    Dbprintf(_YELLOW_("3.") " cat %s", logfile);
}

static bool strip_check_parities(uint64_t data, uint32_t *word) {

    uint8_t rparity = 0, cparity = 0;
    uint8_t rparity_m = 0, cparity_m = 0, stop_bit_m = 0;

    // strip parities
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            *word <<= 1;
            *word += (data >> (EM4X50_TAG_WORD - 1 - 9 * i - j)) & 1;
        }
    }

    // calculate row parities
    for (int i = 0; i < 4; i++) {
        rparity <<= 1;
        for (int j = 0; j < 8; j++) {
            rparity ^= (*word >> (31 - 8 * i - j)) & 1;
        }
    }

    // calculate column parities
    for (int i = 0; i < 8; i++) {
        cparity <<= 1;
        for (int j = 0; j < 4; j++) {
            cparity ^= (*word >> (31 - 8 * j - i)) & 1;
        }
    }

    // measured row parities
    for (int i = 0; i < 4; i++) {
        rparity_m <<= 1;
        rparity_m += (data >> (EM4X50_TAG_WORD - 9 * (i + 1))) & 1;
    }

    // measured column parities
    cparity_m = (data >> 1) & 0xFF;

    // measured stop bit
    stop_bit_m = data & 1;

    if ((cparity_m == cparity) && (rparity_m == rparity) && (stop_bit_m == 0))
        return true;

    return false;
}

static int get_input_data_from_file(uint32_t *words, char *inputfile) {

    size_t now = 0;

    if (exists_in_spiffs(inputfile)) {

        uint32_t size = size_in_spiffs(inputfile);
        uint8_t *mem = BigBuf_malloc(size);
        
        Dbprintf(_YELLOW_("found input file %s"), inputfile);

        rdv40_spiffs_read_as_filetype(inputfile, mem, size, RDV40_SPIFFS_SAFETY_SAFE);

        now = size / 9;
        for (int i = 0; i < now; i++)
            for (int j = 0; j < 4; j++)
                words[i] |= (hex2int(mem[2 * j + 9 * i]) << 4 | hex2int(mem[2 * j + 1 + 9 * i])) << ((3 - j) * 8);

        Dbprintf(_YELLOW_("read data from input file"));
    }

    BigBuf_free();

    return (now > 0) ? now : 0;
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
    DbpString(_YELLOW_("  LF EM4x50 sim/collector/bruteforce mode") " - a.k.a tharexde");
}

void RunMod(void) {

    bool state_change = true;//, password_found = false;
    int pwd_found = false;
    //int cnt = 0;
    //int iterprint = 0;
    uint8_t state = STATE_SIM;
    // declarations for simulating
    uint32_t words[33] = {0x0};
    uint32_t pwd = 0x0;
    uint32_t passwords[2] = {0x0};
    size_t now = 0;
    // declarations for reading
    int no_words = 0;
    uint64_t data[EM4X50_TAG_WORD];
    uint32_t word = 0;//, pwd = 0x0, rpwd = 0x0;
    uint8_t entry[81];

    rdv40_spiffs_lazy_mount();

    StandAloneMode();
    Dbprintf(_YELLOW_("Standalone mode THAREXDE started"));

    for (;;) {

        WDT_HIT();
        if (data_available()) break;

        // press button - toggle between SIM, READ and BRUTE
        // hold button - exit
        int button_pressed = BUTTON_CLICKED(1000);
        if (button_pressed == BUTTON_SINGLE_CLICK) {

            SpinUp(100);
            
            switch (state) {

                case STATE_SIM:
                    state = STATE_READ;
                    break;
                case STATE_READ:
                    state = STATE_BRUTE;
                    break;
                case STATE_BRUTE:
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

                FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
                FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT);
                FpgaSendCommand(FPGA_CMD_SET_DIVISOR, LF_DIVISOR_125);

                AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT | GPIO_SSC_CLK;
                AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;
                AT91C_BASE_PIOA->PIO_ODR = GPIO_SSC_CLK;

                LEDsoff();
                LED_A_ON();
                Dbprintf("");
                Dbprintf(_YELLOW_("switched to EM4x50 simulating mode"));

                now = get_input_data_from_file(words, LF_EM4X50SIMULATE_INPUTFILE);
                if (now > 0) {
                    Dbprintf(_YELLOW_("simulating %i blocks"), now);
                    for (int i = 0; i < now; i++)
                        Dbprintf("%2i -> %lx", i + 1, words[i]);

                } else {
                    Dbprintf(_RED_("error in input data"));
                }

                state_change = false;
            }

            em4x50_sim_send_listen_window();
            for (int i = 0; i < now; i++) {
                em4x50_sim_send_listen_window();
                em4x50_sim_send_word(words[i]);
            }

        } else if (state == STATE_READ) {

            if (state_change) {

                LEDsoff();
                LED_B_ON();
                Dbprintf("");
                Dbprintf(_YELLOW_("switched to EM4x50 reading mode"));

                memset(entry, 0, sizeof(entry));
                memset(data, 0, sizeof(data));

                log_exists = exists_in_spiffs(LF_EM4X50COLLECT_LOGFILE);

                state_change = false;
            }

            no_words = em4x50_standalone_read(data);

            if (no_words > 0) {

                memset(entry, 0, sizeof(entry));

                sprintf((char *)entry, "found new EM4x50 tag:");
                Dbprintf("%s", entry);
                strcat((char *)entry, "\n");
                append(LF_EM4X50COLLECT_LOGFILE, entry, strlen((char *)entry));

                for (int i = 0; i < no_words; i++) {

                    if (strip_check_parities(data[i], &word))
                        sprintf((char *)entry, "  %2i -> 0x%08"PRIx32"  (parity check ok)", i + 1, word);
                    else
                        sprintf((char *)entry, "  %2i -> 0x%08"PRIx32"  (parity check failed)", i + 1, word);

                    Dbprintf("%s", entry);
                    strcat((char *)entry, "\n");
                    append(LF_EM4X50COLLECT_LOGFILE, entry, strlen((char *)entry));
                }
            }

        } else if (state == STATE_BRUTE) {

            if (state_change) {

                LEDsoff();
                LED_C_ON();
                Dbprintf("");
                Dbprintf(_YELLOW_("switched to EM4x50 brute force mode"));

                log_exists = exists_in_spiffs(LF_EM4X50BRUTE_LOGFILE);
                now = get_input_data_from_file(passwords, LF_EM4X50BRUTE_INPUTFILE);
                
                if (now == 2) {
                    
                    // print some information
                    int no_iter = passwords[1] - passwords[0] + 1;
                    int dur_s = no_iter / EM4X50_PWD_SPEED;
                    int dur_h = dur_s / 3600;
                    int dur_m = (dur_s - dur_h * 3600) / 60;
                    dur_s -= dur_h * 3600 + dur_m * 60;

                    //iterprint = no_iter/10;

                    Dbprintf(_YELLOW_("trying %i passwords in range [0x%08x, 0x%08x]"),
                             no_iter, passwords[0], passwords[1]);
                    Dbprintf(_YELLOW_("estimated duration: %ih%im%is"),
                             dur_h, dur_m, dur_s);
                   
                } else {
                    Dbprintf(_RED_("error in input data"));
                    break;
                }

                state_change = false;
            }

            pwd_found = em4x50_standalone_brute(passwords[0], passwords[1], &pwd);
            
            if (pwd_found == PM3_ETIMEOUT) {

                // timeout -> no EM4x50 tag on reader?
                Dbprintf(_YELLOW_("timeout - no EM4x50 tag detected"));

            } else if (pwd_found == true) {

                // password found -> write to logfile
                sprintf((char *)entry, "password found: 0x%08"PRIx32, pwd);
                Dbprintf(_YELLOW_("%s"), entry);
                strcat((char *)entry, "\n");
                append(LF_EM4X50BRUTE_LOGFILE, entry, strlen((char *)entry));

                break;

            } else {

                if (pwd == passwords[1] + 1) {

                    // finished without success -> write to logfile
                    sprintf((char *)entry, "no password found");
                    Dbprintf(_YELLOW_("%s"), entry);
                    strcat((char *)entry, "\n");
                    append(LF_EM4X50BRUTE_LOGFILE, entry, strlen((char *)entry));

                    
                } else {
                    
                    // stopped -> write to logfile
                    sprintf((char *)entry, "stopped search - last password: 0x%08"PRIx32, pwd);
                    Dbprintf(_YELLOW_("%s"), entry);
                    strcat((char *)entry, "\n");
                    append(LF_EM4X50BRUTE_LOGFILE, entry, strlen((char *)entry));
                    
                    // replace start password by last tested password in
                    // inputfile (spiffs) so that brute forcing process will
                    // be continued when envoking brute force mode again
                    sprintf((char *)entry, "%08"PRIx32"\n%08"PRIx32"\n", pwd, passwords[1]);
                    rdv40_spiffs_write(LF_EM4X50BRUTE_INPUTFILE,
                                       entry,
                                       strlen((char *)entry),
                                       RDV40_SPIFFS_SAFETY_SAFE);

                }

                break;
            }
        }
    }

    if (state == STATE_READ) {
        DownloadLogInstructions(LF_EM4X50COLLECT_LOGFILE);
    } else if (state == STATE_BRUTE) {
        LoadDataInstructions(LF_EM4X50BRUTE_INPUTFILE);
        DownloadLogInstructions(LF_EM4X50BRUTE_LOGFILE);
    } else {
        LoadDataInstructions(LF_EM4X50SIMULATE_INPUTFILE);
    }

    LED_D_ON();
    rdv40_spiffs_lazy_unmount();
    LED_D_OFF();

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    LEDsoff();
    Dbprintf("");
    Dbprintf(_YELLOW_("[=] Standalone mode THAREXDE stopped"));

}
