/*
 * `hf_14bsniff` passively sniffs ISO14b frames.
 * *
 * On entering stand-alone mode, this module will start sniffing ISO14b frames.
 * This will be stored in the normal trace buffer (ie: in RAM -- will be lost
 * at power-off).
 *
 * Short-pressing the button again will stop sniffing and standalone mode will
 * exit.
 *
 * LEDs:
 * - LED1: sniffing
 * - LED2: sniffed tag command, turns off when finished sniffing reader command
 * - LED3: sniffed reader command, turns off when finished sniffing tag command
 * - LED4: unmounting/sync'ing flash (normally < 100ms)
 *
 * This module emits debug strings during normal operation -- so try it out in
 * the lab connected to PM3 client before taking it into the field.
 *
 * Caveats / notes:
 * - Trace buffer will be cleared on starting stand-alone mode.
 * - This module will terminate if the trace buffer is full.
 * - Like normal sniffing mode, timestamps overflow after 5 min 16 sec.
 *   However, the trace buffer is sequential, so will be in the correct order.
 */

#include "standalone.h" // standalone definitions
#include "proxmark3_arm.h"
#include "iso14443b.h"
#include "util.h"
#include "spiffs.h"
#include "appmain.h"
#include "dbprint.h"
#include "ticks.h"
#include "BigBuf.h"

#define HF_14BSNIFF_LOGFILE "hf_14bsniff.trace"

static void DownloadTraceInstructions(void) {
    Dbprintf("");
    Dbprintf("To get the trace from flash and display it:");
    Dbprintf("1. mem spiffs dump -s "HF_14BSNIFF_LOGFILE" -d hf_14bsniff.trace");
    Dbprintf("2. trace load -f hf_14bsniff.trace");
    Dbprintf("3. trace list -t 14b -1");
}

void ModInfo(void) {
    DbpString(" HF 14B SNIFF,  a ISO14443b sniffer");
    DownloadTraceInstructions();
}

void RunMod(void) {
    StandAloneMode();

    Dbprintf(_YELLOW_("HF 14B SNIFF started"));
#ifdef WITH_FLASH
    rdv40_spiffs_lazy_mount();
#endif

    SniffIso14443b();

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
        if (!exists_in_spiffs(HF_14BSNIFF_LOGFILE)) {
            rdv40_spiffs_write(
                HF_14BSNIFF_LOGFILE, trace_buffer, trace_len, RDV40_SPIFFS_SAFETY_SAFE);
            Dbprintf("[!] Wrote trace to "HF_14BSNIFF_LOGFILE);
        } else {
            rdv40_spiffs_append(
                HF_14BSNIFF_LOGFILE, trace_buffer, trace_len, RDV40_SPIFFS_SAFETY_SAFE);
            Dbprintf("[!] Appended trace to "HF_14BSNIFF_LOGFILE);
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
