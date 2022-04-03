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
#include "appmain.h"
#include "dbprint.h"
#include "ticks.h"
#include "BigBuf.h"

void ModInfo(void) {
    DbpString(" HF 14B SNIFF,  a ISO14443b sniffer");
}

void RunMod(void) {
    StandAloneMode();

    Dbprintf(_YELLOW_("HF 14B SNIFF started"));

    SniffIso14443b();

    Dbprintf("Stopped sniffing");
    SpinDelay(200);

    Dbprintf("-=[ exit ]=-");
    LEDsoff();
}
