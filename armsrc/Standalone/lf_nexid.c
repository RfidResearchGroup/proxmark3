//-----------------------------------------------------------------------------
// Copyright (C) BOSCA Maxime and RIOUX Guilhem 2021
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
// main code for Nexwatch ID / Magic number collector.
//-----------------------------------------------------------------------------

#include <inttypes.h>
#include "standalone.h" // standalone definitions
#include "proxmark3_arm.h"
#include "appmain.h"
#include "lfops.h"
#include "lfsampling.h"
#include "BigBuf.h"
#include "fpgaloader.h"
#include "util.h"
#include "dbprint.h"
#include "printf.h"
#include "spiffs.h"
#include "ticks.h"
#include "lfdemod.h"
#include "commonutil.h"

/*
 * `lf_nexid` sniffs after LF Nexwatch ID credentials, and stores them in internal
 * flash. It requires RDV4 hardware (for flash and battery).
 *
 * On entering stand-alone mode, this module will start reading/record LF Nexwatch ID credentials.
 * Every found / collected credential will be written/appended to the logfile in flash
 * as a text string.
 *
 * LEDs:
 * - LED A: reading / record
 * - LED B: writing to flash
 * - LED C: unmounting/sync'ing flash (normally < 100ms)
 *
 * To retrieve log file from flash:
 *
 * 1. mem spiffs dump -s lf_nexcollect.log -d lf_nexcollect.log
 *    Copies log file from flash to your client.
 *
 * 2. exit the Proxmark3 client
 *
 * 3. more lf_nexcollect.log
 *
 * This module emits debug strings during normal operation -- so try it out in
 * the lab connected to PM3 client before taking it into the field.
 *
 * To delete the log file from flash:
 *
 * 1. mem spiffs remove -f lf_nexcollect.log
 */

#define LF_NEXCOLLECT_LOGFILE "lf_nexcollect.log"
typedef enum {
    SCRAMBLE,
    DESCRAMBLE
} NexWatchScramble_t;


static void DownloadLogInstructions(void) {
    Dbprintf("");
    Dbprintf("[=] To get the logfile from flash and display it:");
    Dbprintf("[=] " _YELLOW_("1.") " mem spiffs dump -s "LF_NEXCOLLECT_LOGFILE" -d "LF_NEXCOLLECT_LOGFILE);
    Dbprintf("[=] " _YELLOW_("2.") " exit proxmark3 client");
    Dbprintf("[=] " _YELLOW_("3.") " cat "LF_NEXCOLLECT_LOGFILE);
}

bool log_exists;

// scramble parity (1234) -> (4231)
static uint8_t nexwatch_parity_swap(uint8_t parity) {
    uint8_t a = (((parity >> 3) & 1));
    a |= (((parity >> 1) & 1) << 1);
    a |= (((parity >> 2) & 1) << 2);
    a |= ((parity & 1) << 3);
    return a;
}
// parity check
// from 32b hex id, 4b mode,
static uint8_t nexwatch_parity(const uint8_t hexid[5]) {
    uint8_t p = 0;
    for (uint8_t i = 0; i < 5; i++) {
        p ^= NIBBLE_HIGH(hexid[i]);
        p ^= NIBBLE_LOW(hexid[i]);
    }
    return nexwatch_parity_swap(p);
}

/// NETWATCH checksum
/// @param magic =  0xBE  Quadrakey,  0x88 Nexkey
/// @param id = descrambled id (printed card number)
/// @param parity =  the parity based upon the scrambled raw id.
static uint8_t nexwatch_checksum(uint8_t magic, uint32_t id, uint8_t parity) {
    uint8_t a = ((id >> 24) & 0xFF);
    a -= ((id >> 16) & 0xFF);
    a -= ((id >> 8) & 0xFF);
    a -= (id & 0xFF);
    a -= magic;
    a -= (reflect8(parity) >> 4);
    return reflect8(a);
}

// Scrambled id ( 88 bit cardnumber format)
// ref::  http://www.proxmark.org/forum/viewtopic.php?pid=14662#p14662
static int nexwatch_scamble(NexWatchScramble_t action, uint32_t *id, uint32_t *scambled) {

    // 255 = Not used/Unknown other values are the bit offset in the ID/FC values
    const uint8_t hex_2_id [] = {
        31, 27, 23, 19, 15, 11, 7, 3,
        30, 26, 22, 18, 14, 10, 6, 2,
        29, 25, 21, 17, 13, 9, 5, 1,
        28, 24, 20, 16, 12, 8, 4, 0
    };

    switch (action) {
        case DESCRAMBLE: {
            *id = 0;
            for (uint8_t idx = 0; idx < 32; idx++) {

                if (hex_2_id[idx] == 255)
                    continue;

                bool bit_state = (*scambled >> hex_2_id[idx]) & 1;
                *id |= (bit_state << (31 - idx));
            }
            break;
        }
        case SCRAMBLE: {
            *scambled = 0;
            for (uint8_t idx = 0; idx < 32; idx++) {

                if (hex_2_id[idx] == 255)
                    continue;

                bool bit_state = (*id >> idx) & 1;
                *scambled |= (bit_state << (31 - hex_2_id[idx]));
            }
            break;
        }
        default:
            break;
    }
    return PM3_SUCCESS;
}


static void append(uint8_t *entry, size_t entry_len) {

    LED_B_ON();
    if (log_exists == false) {
        rdv40_spiffs_write(LF_NEXCOLLECT_LOGFILE, entry, entry_len, RDV40_SPIFFS_SAFETY_SAFE);
        log_exists = true;
    } else {
        rdv40_spiffs_append(LF_NEXCOLLECT_LOGFILE, entry, entry_len, RDV40_SPIFFS_SAFETY_SAFE);
    }
    LED_B_OFF();
}


static int detectNexWatch(uint8_t *dest, size_t *size, bool *invert) {

    uint8_t preamble[28]   = {0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    // sanity check.
    if (*size < 96) return -1;

    size_t startIdx = 0;

    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx)) {
        // if didn't find preamble try again inverting
        uint8_t preamble_i[28] = {1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
        if (!preambleSearch(dest, preamble_i, sizeof(preamble_i), size, &startIdx)) return -4;
        *invert ^= 1;
    }
    // size tests?
    return (int) startIdx;
}

static uint32_t PSKDemod(uint8_t *dest, size_t *size, int *startIdx) {
    //buffer for result
    int clk = 0, invert = 0;
    //checks if the signal is just noise
    if (getSignalProperties()->isnoise) {
        return PM3_ESOFT;
    }

    //int pskRawDemod_ext(uint8_t *dest, size_t *size, int *clock, int *invert, int *startIdx)
    int errCnt = pskRawDemod_ext(dest, size, &clk, &invert, startIdx);
    if (errCnt > 100) {
        BigBuf_free();
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

static int demodNexWatch(void) {
    uint8_t *dest = BigBuf_get_addr();
    size_t size = MIN(16385, BigBuf_max_traceLen());
    int startIdx = 0;

    if (PSKDemod(dest, &size, &startIdx) != PM3_SUCCESS) {
        return PM3_ESOFT;
    }
    bool invert = false;
    int idx = detectNexWatch(dest, &size, &invert);
    if (idx < 0) {
        return PM3_ESOFT;
    }

    // skip the 4 first bits from the nexwatch preamble identification (we use 4 extra zeros..)
    idx += 4;

    // size = size -idx;
    dest = dest + idx;
    Dbprintf("[+] Id: %d, Size: %d", idx, size);
    //setClockGrid(g_DemodClock, g_DemodStartIdx + (idx * g_DemodClock));

    if (invert) {
        Dbprintf("Inverted the demodulated data");
        for (size_t i = 0; i < size; i++)
            dest[i] ^= 1;
    }

    //got a good demod
    uint32_t raw1 = bytebits_to_byte(dest, 32);
    uint32_t raw2 = bytebits_to_byte(dest + 32, 32);
    uint32_t raw3 = bytebits_to_byte(dest + 32 + 32, 32);

    // get rawid
    uint32_t rawid = 0;
    for (uint8_t k = 0; k < 4; k++) {
        for (uint8_t m = 0; m < 8; m++) {
            rawid = (rawid << 1) | dest[m + k + (m * 4)];
        }
    }

    // descrambled id
    uint32_t cn = 0;
    uint32_t scambled = bytebits_to_byte(dest + 8 + 32, 32);
    nexwatch_scamble(DESCRAMBLE, &cn, &scambled);

    uint8_t mode = bytebits_to_byte(dest + 72, 4);
    uint8_t chk = bytebits_to_byte(dest + 80, 8);

    // parity check
    // from 32b hex id, 4b mode
    uint8_t hex[5] = {0};
    for (uint8_t i = 0; i < 5; i++) {
        hex[i] = bytebits_to_byte(dest + 8 + 32 + (i * 8), 8);
    }
    // mode is only 4 bits.
    hex[4] &= 0xf0;
    uint8_t calc_parity = nexwatch_parity(hex);

    uint8_t magic = 0;
    // output
    Dbprintf(" NexWatch raw id : " _YELLOW_("0x%08"PRIx32), rawid);

    for (; magic < 255; magic++) {
        uint8_t temp_checksum = nexwatch_checksum(magic, cn, calc_parity);
        if (temp_checksum == chk) {
            Dbprintf("    Magic number : " _GREEN_("0x%X"),  magic);
            break;
        }
    }

    Dbprintf("        88bit id : " _YELLOW_("%"PRIu32) " ("  _YELLOW_("0x%08"PRIx32)")", cn, cn);
    Dbprintf("            mode : %x", mode);

    Dbprintf(" Raw : " _YELLOW_("%08"PRIX32"%08"PRIX32"%08"PRIX32), raw1, raw2, raw3);

    uint8_t entry[81];
    memset(entry, 0, sizeof(entry));

    sprintf((char *)entry, "Nexwatch ID: %"PRIu32", Magic bytes: 0x%X, Mode: %x\n",
            cn,
            magic,
            mode);

    append(entry, strlen((char *)entry));
    Dbprintf("%s", entry);

    BigBuf_free();
    return PM3_SUCCESS;
}

void ModInfo(void) {
    DbpString(_YELLOW_(" Nexwatch credentials detection mode") " - a.k.a NexID (jrjgjk & Zolorah)");
}

void RunMod(void) {

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    LFSetupFPGAForADC(LF_DIVISOR_125, true);
    BigBuf_Clear();

    StandAloneMode();

    Dbprintf(_YELLOW_("[=] Standalone mode nexid started"));

    rdv40_spiffs_lazy_mount();

    log_exists = exists_in_spiffs(LF_NEXCOLLECT_LOGFILE);

    // the main loop for your standalone mode
    for (;;) {
        WDT_HIT();

        // exit from IceHID, send a usbcommand.
        if (data_available()) break;

        // Was our button held down or pressed?
        int button_pressed = BUTTON_HELD(280);
        if (button_pressed == BUTTON_HOLD)
            break;

        LED_A_ON();

        uint32_t res;


        size_t size = MIN(16385, BigBuf_max_traceLen());
        DoAcquisition_config(false, size, true);
        res = demodNexWatch();
        if (res == PM3_SUCCESS) {
            LED_A_OFF();
            continue;
        }

    }

    LED_C_ON();
    rdv40_spiffs_lazy_unmount();
    LED_C_OFF();

    LEDsoff();
    DownloadLogInstructions();
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
}
