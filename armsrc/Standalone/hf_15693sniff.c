//-----------------------------------------------------------------------------
// Copyright 2020 Michael Farrell <micolous+git@gmail.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// main code for standalone HF/iso15693 Sniff to flash
//-----------------------------------------------------------------------------

/*
 * `hf_15693sniff` passively sniffs ISO15693 frames, and stores them in internal
 * flash. It requires RDV4 hardware (for flash and battery).
 *
 * This module is similar to hf_bog (which only logs ULC/NTAG/ULEV1 auth).
 *
 * On entering stand-alone mode, this module will start sniffing ISO15693 frames.
 * This will be stored in the normal trace buffer (ie: in RAM -- will be lost
 * at power-off).
 *
 * Short-pressing the button again will stop sniffing, and at _this_ point
 * append trace data from RAM to a file in flash (hf_15693sniff.trace) and unmount.
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
 * 1. mem spiffs dump -s hf_15693sniff.trace -d hf_15693sniff.trace
 *    Copies trace data file from flash to your PC.
 *
 * 2. trace load hf_15693sniff.trace
 *    Loads trace data from a file into PC-side buffers.
 *
 * 3. For ISO15693: trace list -t 15 -1
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
#include "fpgaloader.h"
#include "iso15693.h"
#include "iso15.h"
#include "util.h"
#include "spiffs.h"
#include "appmain.h"
#include "dbprint.h"
#include "ticks.h"
#include "BigBuf.h"




#define HF_15693SNIFF_LOGFILE "hf_15693sniff.trace"

static void DownloadTraceInstructions(void) {
    Dbprintf("");
    Dbprintf("To get the trace from flash and display it:");
    Dbprintf("1. mem spiffs dump -s "HF_15693SNIFF_LOGFILE" -d hf_15693sniff.trace");
    Dbprintf("2. trace load -f hf_15693sniff.trace");
    Dbprintf("3. trace list -t 15 -1");
}

void ModInfo(void) {
    DbpString(" HF 15693 SNIFF,  a ISO15693 sniffer with storing in flashmem");
    DownloadTraceInstructions();
}

void RunMod(void) {
    StandAloneMode();

    Dbprintf(_YELLOW_("HF 15693 SNIFF started"));
    rdv40_spiffs_lazy_mount();

    SniffIso15693(0, NULL);

    Dbprintf("Stopped sniffing");
    SpinDelay(200);

    // Write stuff to spiffs logfile
    uint32_t trace_len = BigBuf_get_traceLen();
    if (trace_len > 0) {
        Dbprintf("[!] Trace length (bytes) = %u", trace_len);

        uint8_t *trace_buffer = BigBuf_get_addr();
        if (!exists_in_spiffs(HF_15693SNIFF_LOGFILE)) {
            rdv40_spiffs_write(
                HF_15693SNIFF_LOGFILE, trace_buffer, trace_len, RDV40_SPIFFS_SAFETY_SAFE);
            Dbprintf("[!] Wrote trace to "HF_15693SNIFF_LOGFILE);
        } else {
            rdv40_spiffs_append(
                HF_15693SNIFF_LOGFILE, trace_buffer, trace_len, RDV40_SPIFFS_SAFETY_SAFE);
            Dbprintf("[!] Appended trace to "HF_15693SNIFF_LOGFILE);
        }
    } else {
        Dbprintf("[!] Trace buffer is empty, nothing to write!");
    }

    LED_D_ON();
    rdv40_spiffs_lazy_unmount();
    LED_D_OFF();

    SpinErr(LED_A, 200, 5);
    SpinDelay(100);

    Dbprintf("-=[ exit ]=-");
    LEDsoff();
    DownloadTraceInstructions();
}
