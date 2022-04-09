//-----------------------------------------------------------------------------
// Copyright (C) 2020 Michael Farrell <micolous+git@gmail.com>
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
// main code for standalone HF/iso14a Sniff to flash
//-----------------------------------------------------------------------------

/*
 * `hf_14asniff` passively sniffs ISO14a frames, and stores them in internal
 * flash. It requires RDV4 hardware (for flash and battery).
 *
 * This module is similar to hf_bog (which only logs ULC/NTAG/ULEV1 auth).
 *
 * On entering stand-alone mode, this module will start sniffing ISO14a frames.
 * This will be stored in the normal trace buffer (ie: in RAM -- will be lost
 * at power-off).
 *
 * Short-pressing the button again will stop sniffing, and at _this_ point
 * append trace data from RAM to a file in flash (hf_14asniff.trace) and unmount.
 *
 * Once the data is saved, standalone mode will exit.
 *
 * LEDs:
 * - LED1: sniffing
 * - LED2: sniffed tag command, turns off when finished sniffing reader command
 * - LED3: sniffed reader command, turns off when finished sniffing tag command
 * - LED4: unmounting/sync'ing flash (normally < 100ms)
 *
 * To retrieve trace data from flash:
 *
 * 1. mem spiffs dump -s hf_14asniff.trace -d hf_14asniff.trace
 *    Copies trace data file from flash to your PC.
 *
 * 2. trace load hf_14asniff.trace
 *    Loads trace data from a file into PC-side buffers.
 *
 * 3. For ISO14a: trace list -t 14a -1
 *    For MIFARE Classic: trace list -t mf -1
 *
 *    Lists trace data from buffer without requesting it from PM3.
 *
 * This module emits debug strings during normal operation -- so try it out in
 * the lab connected to PM3 client before taking it into the field.
 *
 * To delete the trace data from flash:
 *
 * Caveats / notes:
 * - Trace buffer will be cleared on starting stand-alone mode. Data in flash
 *   will remain unless explicitly deleted.
 * - This module will terminate if the trace buffer is full (and save data to
 *   flash).
 * - Like normal sniffing mode, timestamps overflow after 5 min 16 sec.
 *   However, the trace buffer is sequential, so will be in the correct order.
 */

#include "standalone.h" // standalone definitions
#include "proxmark3_arm.h"
#include "iso14443a.h"
#include "util.h"
#include "spiffs.h"
#include "appmain.h"
#include "dbprint.h"
#include "ticks.h"
#include "BigBuf.h"

#define HF_14ASNIFF_LOGFILE "hf_14asniff.trace"

static void DownloadTraceInstructions(void) {
    Dbprintf("");
    Dbprintf("To get the trace from flash and display it:");
    Dbprintf("1. mem spiffs dump -s "HF_14ASNIFF_LOGFILE" -d hf_14asniff.trace");
    Dbprintf("2. trace load -f hf_14asniff.trace");
    Dbprintf("3. trace list -t 14a -1");
}

void ModInfo(void) {
    DbpString(" HF 14A SNIFF,  a ISO14443a sniffer with storing in flashmem");
    DownloadTraceInstructions();
}

void RunMod(void) {
    StandAloneMode();

    Dbprintf(_YELLOW_("HF 14A SNIFF started"));
#ifdef WITH_FLASH
    rdv40_spiffs_lazy_mount();
#endif

    SniffIso14443a(0);

    Dbprintf("Stopped sniffing");
    SpinDelay(200);

    uint32_t trace_len = BigBuf_get_traceLen();
#ifndef WITH_FLASH
    // Keep stuff in BigBuf for USB/BT dumping
    if (trace_len > 0)
        Dbprintf("[!] Trace length (bytes) = %u", trace_len);
#else
    // Write stuff to spiffs logfile
    if (trace_len > 0) {
        Dbprintf("[!] Trace length (bytes) = %u", trace_len);

        uint8_t *trace_buffer = BigBuf_get_addr();
        if (!exists_in_spiffs(HF_14ASNIFF_LOGFILE)) {
            rdv40_spiffs_write(
                HF_14ASNIFF_LOGFILE, trace_buffer, trace_len, RDV40_SPIFFS_SAFETY_SAFE);
            Dbprintf("[!] Wrote trace to "HF_14ASNIFF_LOGFILE);
        } else {
            rdv40_spiffs_append(
                HF_14ASNIFF_LOGFILE, trace_buffer, trace_len, RDV40_SPIFFS_SAFETY_SAFE);
            Dbprintf("[!] Appended trace to "HF_14ASNIFF_LOGFILE);
        }
    } else {
        Dbprintf("[!] Trace buffer is empty, nothing to write!");
    }

    LED_D_ON();
    rdv40_spiffs_lazy_unmount();
    LED_D_OFF();

    SpinErr(LED_A, 200, 5);
    SpinDelay(100);
#endif

    Dbprintf("-=[ exit ]=-");
    LEDsoff();
#ifdef WITH_FLASH
    DownloadTraceInstructions();
#endif

}
