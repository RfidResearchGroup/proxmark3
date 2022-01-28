//-----------------------------------------------------------------------------
// Copyright (C) Christian Herrmann, 2020
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
// main code for HID collector aka IceHID by Iceman
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
/*
 * `lf_hidcollect` sniffs after LF HID credentials, and stores them in internal
 * flash. It requires RDV4 hardware (for flash and battery).
 *
 * On entering stand-alone mode, this module will start reading/record HID credentials.
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
 * 1. mem spiffs dump -s lf_hidcollect.log -d lf_hidcollect.log
 *    Copies log file from flash to your client.
 *
 * 2. exit the Proxmark3 client
 *
 * 3. more lf_hidcollect.log
 *
 * This module emits debug strings during normal operation -- so try it out in
 * the lab connected to PM3 client before taking it into the field.
 *
 * To delete the log file from flash:
 *
 * 1. mem spiffs remove -f lf_hidcollect.log
 */

#define LF_HIDCOLLECT_LOGFILE "lf_hidcollect.log"


static void DownloadLogInstructions(void) {
    Dbprintf("");
    Dbprintf("[=] To get the logfile from flash and display it:");
    Dbprintf("[=] " _YELLOW_("1.") " mem spiffs dump -s "LF_HIDCOLLECT_LOGFILE" -d "LF_HIDCOLLECT_LOGFILE);
    Dbprintf("[=] " _YELLOW_("2.") " exit proxmark3 client");
    Dbprintf("[=] " _YELLOW_("3.") " cat "LF_HIDCOLLECT_LOGFILE);
}

bool log_exists;

static void append(uint8_t *entry, size_t entry_len) {

    LED_B_ON();
    if (log_exists == false) {
        rdv40_spiffs_write(LF_HIDCOLLECT_LOGFILE, entry, entry_len, RDV40_SPIFFS_SAFETY_SAFE);
        log_exists = true;
    } else {
        rdv40_spiffs_append(LF_HIDCOLLECT_LOGFILE, entry, entry_len, RDV40_SPIFFS_SAFETY_SAFE);
    }
    LED_B_OFF();
}

static uint32_t IceEM410xdemod(void) {

    uint8_t *dest = BigBuf_get_addr();
    size_t idx = 0;
    int clk = 0, invert = 0, maxErr = 20;
    uint32_t hi = 0;
    uint64_t lo = 0;

    size_t size = MIN(16385, BigBuf_max_traceLen());

    //askdemod and manchester decode
    int errCnt = askdemod(dest, &size, &clk, &invert, maxErr, 0, 1);

    WDT_HIT();

    if (errCnt > 50) {
        BigBuf_free();
        return PM3_ESOFT;
    }

    int type = Em410xDecode(dest, &size, &idx, &hi, &lo);
    // Did we find a Short EM or a Long EM?
    if ((type < 0) || ((type & (0x1 | 0x2)) == 0)) {
        BigBuf_free();
        return PM3_ESOFT;
    }

    uint8_t entry[81];
    memset(entry, 0, sizeof(entry));

    if (size == 128) {
        sprintf((char *)entry, "EM XL TAG ID: %06"PRIx32"%08"PRIx32"%08"PRIx32" - (%05"PRIu32"_%03"PRIu32"_%08"PRIu32")\n",
                hi,
                (uint32_t)(lo >> 32),
                (uint32_t)lo,
                (uint32_t)(lo & 0xFFFF),
                (uint32_t)((lo >> 16LL) & 0xFF),
                (uint32_t)(lo & 0xFFFFFF));
    } else {
        sprintf((char *)entry, "EM TAG ID: %02"PRIx32"%08"PRIx32" - (%05"PRIu32"_%03"PRIu32"_%08"PRIu32")\n",
                (uint32_t)(lo >> 32),
                (uint32_t)lo,
                (uint32_t)(lo & 0xFFFF),
                (uint32_t)((lo >> 16LL) & 0xFF),
                (uint32_t)(lo & 0xFFFFFF));
    }

    append(entry, strlen((char *)entry));
    Dbprintf("%s", entry);
    BigBuf_free();
    return PM3_SUCCESS;
}

static uint32_t IceAWIDdemod(void) {

    uint8_t *dest = BigBuf_get_addr();
    size_t size = MIN(12800, BigBuf_max_traceLen());
    int dummyIdx = 0;

    //askdemod and manchester decode
    int idx = detectAWID(dest, &size, &dummyIdx);

    if (idx <= 0 || size != 96) {
        BigBuf_free();
        return PM3_ESOFT;
    }

    //get raw ID before removing parities
    uint32_t rawLo = bytebits_to_byte(dest + idx + 64, 32);
    uint32_t rawHi = bytebits_to_byte(dest + idx + 32, 32);
    uint32_t rawHi2 = bytebits_to_byte(dest + idx, 32);

    size = removeParity(dest, idx + 8, 4, 1, 88);
    if (size != 66) {
        BigBuf_free();
        return PM3_ESOFT;
    }

    uint8_t entry[110];
    memset(entry, 0, sizeof(entry));

    uint8_t fmtLen = bytebits_to_byte(dest, 8);
    if (fmtLen == 26) {
        uint8_t fac = bytebits_to_byte(dest + 9, 8);
        uint32_t cardnum = bytebits_to_byte(dest + 17, 16);
        uint32_t code1 = bytebits_to_byte(dest + 8, fmtLen);
        sprintf((char *)entry, "AWID bit len: %d, FC: %d, Card: %"PRIu32" - Wiegand: %"PRIx32", Raw: %08"PRIx32"%08"PRIx32"%08"PRIx32"\n", fmtLen, fac, cardnum, code1, rawHi2, rawHi, rawLo);
    } else {
        uint32_t cardnum = bytebits_to_byte(dest + 8 + (fmtLen - 17), 16);
        if (fmtLen > 32) {
            uint32_t code1 = bytebits_to_byte(dest + 8, fmtLen - 32);
            uint32_t code2 = bytebits_to_byte(dest + 8 + (fmtLen - 32), 32);
            sprintf((char *)entry, "AWID bit len: %d -unk bit len - Card: %"PRIu32" - Wiegand: %"PRIx32"%08"PRIx32", Raw: %08"PRIx32"%08"PRIx32"%08"PRIx32"\n", fmtLen, cardnum, code1, code2, rawHi2, rawHi, rawLo);
        } else {
            uint32_t code1 = bytebits_to_byte(dest + 8, fmtLen);
            sprintf((char *)entry, "AWID bit len: %d -unk bit len - Card: %"PRIu32" - Wiegand: %"PRIx32", Raw: %08"PRIx32"%08"PRIx32"%08"PRIx32"\n", fmtLen, cardnum, code1, rawHi2, rawHi, rawLo);
        }
    }

    append(entry, strlen((char *)entry));
    Dbprintf("%s", entry);
    BigBuf_free();
    return PM3_SUCCESS;
}

static uint32_t IceIOdemod(void) {

    int dummyIdx = 0;
    uint8_t version = 0, facilitycode = 0;
    uint16_t number = 0;
    uint32_t hi = 0, lo = 0;

    size_t size = MIN(12000, BigBuf_max_traceLen());

//    uint8_t *dest = BigBuf_malloc(size);
    uint8_t *dest = BigBuf_get_addr();

    //fskdemod and get start index
    int idx = detectIOProx(dest, &size, &dummyIdx);

    if (idx < 0) {
        BigBuf_free();
        return PM3_ESOFT;
    }

    hi = bytebits_to_byte(dest + idx, 32);
    lo = bytebits_to_byte(dest + idx + 32, 32);

    version = bytebits_to_byte(dest + idx + 27, 8); //14,4
    facilitycode = bytebits_to_byte(dest + idx + 18, 8);
    number = (bytebits_to_byte(dest + idx + 36, 8) << 8) | (bytebits_to_byte(dest + idx + 45, 8)); //36,9

    uint8_t entry[64];
    memset(entry, 0, sizeof(entry));

    sprintf((char *)entry, "IO Prox XSF(%02u)%02x:%05u (%08"PRIx32"%08"PRIx32")\n"
            , version
            , facilitycode
            , number
            , hi
            , lo
           );

    append(entry, strlen((char *)entry));
    Dbprintf("%s", entry);
    BigBuf_free();
    return PM3_SUCCESS;
}

static uint32_t IceHIDDemod(void) {

    int dummyIdx = 0;

    uint32_t hi2 = 0, hi = 0, lo = 0;

    // large enough to catch 2 sequences of largest format
//    size_t size = 50 * 128 * 2;  // 12800 bytes
    size_t size = MIN(12800, BigBuf_max_traceLen());
    //uint8_t *dest = BigBuf_malloc(size);
    uint8_t *dest = BigBuf_get_addr();

    // FSK demodulator
    int idx = HIDdemodFSK(dest, &size, &hi2, &hi, &lo, &dummyIdx);
    if (idx < 0) {
        BigBuf_free();
        return PM3_ESOFT;
    }

    if ((size == 96 || size == 192)) {

        uint8_t entry[80];
        memset(entry, 0, sizeof(entry));

        // go over previously decoded manchester data and decode into usable tag ID
        if (hi2 != 0) { //extra large HID tags  88/192 bits

            sprintf((char *)entry, "HID large: %"PRIx32"%08"PRIx32"%08"PRIx32" (%"PRIu32")\n",
                    hi2,
                    hi,
                    lo,
                    (lo >> 1) & 0xFFFF
                   );

            append(entry, strlen((char *)entry));

        } else {  //standard HID tags 44/96 bits
            uint8_t bitlen = 0;
            uint32_t fac = 0;
            uint32_t cardnum = 0;

            if (((hi >> 5) & 1) == 1) { //if bit 38 is set then < 37 bit format is used
                uint32_t lo2 = 0;
                lo2 = (((hi & 31) << 12) | (lo >> 20)); //get bits 21-37 to check for format len bit
                uint8_t idx3 = 1;
                while (lo2 > 1) { //find last bit set to 1 (format len bit)
                    lo2 >>= 1;
                    idx3++;
                }
                bitlen = idx3 + 19;
                fac = 0;
                cardnum = 0;
                if (bitlen == 26) {
                    cardnum = (lo >> 1) & 0xFFFF;
                    fac = (lo >> 17) & 0xFF;
                }
                if (bitlen == 37) {
                    cardnum = (lo >> 1) & 0x7FFFF;
                    fac = ((hi & 0xF) << 12) | (lo >> 20);
                }
                if (bitlen == 34) {
                    cardnum = (lo >> 1) & 0xFFFF;
                    fac = ((hi & 1) << 15) | (lo >> 17);
                }
                if (bitlen == 35) {
                    cardnum = (lo >> 1) & 0xFFFFF;
                    fac = ((hi & 1) << 11) | (lo >> 21);
                }
            } else { //if bit 38 is not set then 37 bit format is used
                bitlen = 37;
                cardnum = (lo >> 1) & 0x7FFFF;
                fac = ((hi & 0xF) << 12) | (lo >> 20);
            }

            sprintf((char *)entry, "HID: %"PRIx32"%08"PRIx32" (%"PRIu32") Format: %d bit FC: %"PRIu32" Card: %"PRIu32"\n",
                    hi,
                    lo,
                    (lo >> 1) & 0xFFFF,
                    bitlen,
                    fac,
                    cardnum
                   );

            append(entry, strlen((char *)entry));
        }

        Dbprintf("%s", entry);
    }

    BigBuf_free();
    return PM3_SUCCESS;
}

void ModInfo(void) {
    DbpString(_YELLOW_("  LF HID / IOprox / AWID / EM4100 collector mode") " - a.k.a IceHID (Iceman)");
}

void RunMod(void) {

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    LFSetupFPGAForADC(LF_DIVISOR_125, true);
    BigBuf_Clear();

    StandAloneMode();

    Dbprintf(_YELLOW_("[=] Standalone mode IceHID started"));

    rdv40_spiffs_lazy_mount();

    log_exists = exists_in_spiffs(LF_HIDCOLLECT_LOGFILE);

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

        // since we steal 12800 from bigbuffer, no need to sample it.
        size_t size = MIN(28000, BigBuf_max_traceLen());
        DoAcquisition_config(false, size, true);
        res = IceHIDDemod();
        if (res == PM3_SUCCESS) {
            LED_A_OFF();
            continue;
        }

        DoAcquisition_config(false, size, true);
        res = IceAWIDdemod();
        if (res == PM3_SUCCESS) {
            LED_A_OFF();
            continue;
        }

        DoAcquisition_config(false, size, true);
        res = IceIOdemod();
        if (res == PM3_SUCCESS) {
            LED_A_OFF();
            continue;
        }

        size = MIN(20000, BigBuf_max_traceLen());
        DoAcquisition_config(false, size, true);
        res = IceEM410xdemod();
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
