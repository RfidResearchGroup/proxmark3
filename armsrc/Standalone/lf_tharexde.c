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
#define LF_EM4X50SIMULATE_INPUTFILE "lf_em4x50simulate.eml"
#define LF_EM4X50COLLECT_LOGFILE    "lf_em4x50collect"
#define EM4X50_TAG_WORD             45

bool input_exists;
bool log_exists;

static void LoadDataInstructions(void) {
    Dbprintf("");
    Dbprintf("[=] To load datafile into flash and display it:");
    Dbprintf("[=] " _YELLOW_("1.") " edit inputfile "LF_EM4X50SIMULATE_INPUTFILE);
    Dbprintf("[=] " _YELLOW_("2.") " start proxmark3 client");
    Dbprintf("[=] " _YELLOW_("3.") " mem spiffs load f "LF_EM4X50SIMULATE_INPUTFILE" o "LF_EM4X50SIMULATE_INPUTFILE);
    Dbprintf("[=] " _YELLOW_("4.") " start standalone mode");
}

static void DownloadLogInstructions(void) {
    Dbprintf("");
    Dbprintf("[=] To get the logfile from flash and display it:");
    Dbprintf("[=] " _YELLOW_("1.") " mem spiffs dump o "LF_EM4X50COLLECT_LOGFILE" f "LF_EM4X50COLLECT_LOGFILE);
    Dbprintf("[=] " _YELLOW_("2.") " exit proxmark3 client");
    Dbprintf("[=] " _YELLOW_("3.") " cat "LF_EM4X50COLLECT_LOGFILE);
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

static int get_input_data_from_file(uint32_t *words) {

    size_t now = 0;

    if (exists_in_spiffs(LF_EM4X50SIMULATE_INPUTFILE)) {
        
        uint32_t size = size_in_spiffs((char *)LF_EM4X50SIMULATE_INPUTFILE);
        uint8_t *mem = BigBuf_malloc(size);
        
        Dbprintf(_YELLOW_("[=] found input file %s"), LF_EM4X50SIMULATE_INPUTFILE);

        rdv40_spiffs_read_as_filetype((char *)LF_EM4X50SIMULATE_INPUTFILE, mem, size, RDV40_SPIFFS_SAFETY_SAFE);
        
        now = size / 9;
        for (int i = 0; i < now; i++)
            for (int j = 0; j < 4; j++)
                words[i] |= (hex2int(mem[2 * j + 9 * i]) << 4 | hex2int(mem[2 * j + 1 + 9 * i])) << ((3 - j) * 8);
        
        Dbprintf(_YELLOW_("[=] read data from input file"));
    }
                 
    BigBuf_free();
    
    return (now > 0) ? now : 0;
}

static void append(uint8_t *entry, size_t entry_len) {

    LED_C_ON();
    if (log_exists == false) {
        rdv40_spiffs_write(LF_EM4X50COLLECT_LOGFILE, entry, entry_len, RDV40_SPIFFS_SAFETY_SAFE);
        log_exists = true;
    } else {
        rdv40_spiffs_append(LF_EM4X50COLLECT_LOGFILE, entry, entry_len, RDV40_SPIFFS_SAFETY_SAFE);
    }
    LED_C_OFF();
}
 
void ModInfo(void) {
    DbpString(_YELLOW_("  LF EM4x50 collector mode") " - a.k.a tharexde");
}

void RunMod(void) {

    bool state_change = true;
    uint8_t state = STATE_SIM;
    // declarations for simulating
    uint32_t words[33] = {0x0};
    size_t now = 0;
    // declarations for reading
    int no_words = 0;
    uint64_t data[EM4X50_TAG_WORD];
    uint32_t word = 0;
    uint8_t entry[81];

    rdv40_spiffs_lazy_mount();

    StandAloneMode();
    Dbprintf(_YELLOW_("[=] Standalone mode THAREXDE started"));

    for (;;) {

        WDT_HIT();
        if (data_available()) break;

        // press button - toggle between SIM and READ
        // hold button - exit
        int button_pressed = BUTTON_CLICKED(1000);
        if (button_pressed == BUTTON_SINGLE_CLICK) {

            SpinUp(100);
            state = (state == STATE_SIM) ? STATE_READ : STATE_SIM;
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
                
                LED_A_ON();
                LED_B_OFF();
                Dbprintf(_YELLOW_("[=] switched to EM4x50 simulating mode"));

                now = get_input_data_from_file(words);
                if (now > 0) {
                    Dbprintf(_YELLOW_("[=] simulating %i blocks"), now);
                    for (int i = 0; i < now; i++)
                        Dbprintf(_YELLOW_("[=] %2i -> %lx"), i + 1, words[i]);
                
                } else {
                    Dbprintf(_RED_("[!] error in input data"));
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

                LED_B_ON();
                LED_A_OFF();
                Dbprintf(_YELLOW_("[=] switched to EM4x50 reading mode"));

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
                append(entry, strlen((char *)entry));

                for (int i = 0; i < no_words; i++) {
                    
                    if (strip_check_parities(data[i], &word))
                        sprintf((char *)entry, "  %2i -> 0x%08"PRIx32"  (parity check ok)", i + 1, word);
                    else
                        sprintf((char *)entry, "  %2i -> 0x%08"PRIx32"  (parity check failed)", i + 1, word);
                    
                    Dbprintf("%s", entry);
                    strcat((char *)entry, "\n");
                    append(entry, strlen((char *)entry));
                }
            }

        }
    }
    
    if (state == STATE_READ)
        DownloadLogInstructions();
    else
        LoadDataInstructions();

    LED_D_ON();
    rdv40_spiffs_lazy_unmount();
    LED_D_OFF();

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    LEDsoff();
    Dbprintf(_YELLOW_("[=] Standalone mode THAREXDE stopped"));

}
