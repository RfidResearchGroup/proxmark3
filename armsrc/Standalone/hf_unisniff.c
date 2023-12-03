//-----------------------------------------------------------------------------
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
// HF_UNISNIFF: Integrated 14a/14b/15 sniffer
//-----------------------------------------------------------------------------

/*
 * 'hf_unisniff' integrates existing sniffer functionality for 14a/14b/15a into
 * one standalone module.  It can sniff to the RAM trace buffer, or if you have
 * a PM3 with Flash it will (optionally) save traces to SPIFFS.
 *
 * You can select which protocol will be sniffed with compile-time flags, or at
 * runtime via button presses or a config file in SPIFFS.  You can also choose
 * whether it will append to the trace file for each sniffing session
 * or create new ones.
 *
 * If the protocol to sniff is configured at compile time or in config file:
 *   Once the module is launched, it will begin sniffing immediately.
 *
 * If configured for runtime selection:
 *   Flashing LED(s) indicate selected sniffer protocol: A=14a, B=14b, A+B=15
 *   Short press cycles through options.  Long press begins sniffing.
 *
 * Short-pressing the button again will stop sniffing, with the sniffed data in
 * the trace buffer.  If you have Flash, and have not set the 'save=none'
 * option in the config file, trace data will be saved to SPIFFS.  The default
 * is to create a new file for each sniffing session, but you may configure it
 * to append instead.
 *
 * Once the data is saved, standalone mode will exit.
 *
 * LEDs:
 * - LED1: sniffing
 * - LED2: sniffed tag command, turns off when finished sniffing reader command
 * - LED3: sniffed reader command, turns off when finished sniffing tag command
 * - LED4: unmounting/sync'ing flash (normally < 100ms)
 *
 * Config file: 'hf_unisniff.conf' is a plain text file, one option per line.
 * Settings here will override the compile-time options.
 *
 * Currently available options:
 *   save = [new|append|none]
 *     new    = create a new file with a numbered name for each session.
 *     append = append to existing file, create if not existing.
 *     none   = do not save to SPIFFS, leave in trace buffer only.
 *
 *   protocol = [14a|14b|15|ask]
 *     which protocol to sniff.  If you choose a protocol it will go directly
 *     to work.  If you choose 'ask' you may select the protocol at the start
 *     of each session.
 *
 * To retrieve trace data from flash:
 *
 * 1. mem spiffs dump -s hf_unisniff_[protocol]_[number].trace -d hf_unisniff.trace
 *    Copies trace data file from flash to your PC.
 *
 * 2. trace load -f hf_unisniff.trace
 *    Loads trace data from a file into PC-side buffers.
 *
 * 3. For ISO14a: trace list -t [protocol] -1
 *    For MIFARE Classic: trace list -t mf -1
 *
 *    Lists trace data from buffer without requesting it from PM3.
 *
 * This module emits debug strings during normal operation -- so try it out in
 * the lab connected to PM3 client before taking it into the field.
 *
 * To delete the trace data from flash:
 *    mem spiffs remove -f [filename]
 *
 * Caveats / notes:
 * - Trace buffer will be cleared on starting stand-alone mode. Data in flash
 *   will remain unless explicitly deleted.
 * - This module will terminate if the trace buffer is full (and save data to
 *   flash).
 * - Like normal sniffing mode, timestamps overflow after 5 min 16 sec.
 *   However, the trace buffer is sequential, so will be in the correct order.
 *
 * Mostly this is based on existing code, i.e. the hf_1*sniff modules and dankarmulti.
 * I find it handy to have multiprotocol sniffing on the go, and prefer separate trace
 * files rather than appends, so here it is.
 *
 * If you really like navigating menus with one button and some LEDs, it also works
 * with dankarmulti :)
 *
 * Enjoy!
 */

#include "standalone.h" // standalone definitions
#include "proxmark3_arm.h"
#include "iso14443a.h"
#include "iso14443b.h"
#include "iso15693.h"
#include "iso15.h"
#include "util.h"
#include "commonutil.h"
#include "spiffs.h"
#include "appmain.h"
#include "dbprint.h"
#include "ticks.h"
#include "BigBuf.h"
#include "string.h"

#undef HF_UNISNIFF_VERBOSE_DEBUG
#define HF_UNISNIFF_PROTOCOL "14a"
#define HF_UNISNIFF_LOGFILE "hf_unisniff"
#define HF_UNISNIFF_LOGEXT ".trace"
#define HF_UNISNIFF_CONFIG "hf_unisniff.conf"
#define HF_UNISNIFF_CONFIG_SIZE 128

#define HF_UNISNIFF_PROTOCOLS {"14a","14b","15", "ask"}     // The logic requires ASK be last.
#define HF_UNISNIFF_NUM_PROTOCOLS 4
#define HF_UNISNIFF_PROTO_14a 0
#define HF_UNISNIFF_PROTO_14b 1
#define HF_UNISNIFF_PROTO_15 2
#define HF_UNISNIFF_PROTO_ASK HF_UNISNIFF_NUM_PROTOCOLS-1

#define HF_UNISNIFF_SAVE_MODE HF_UNISNIFF_SAVE_MODE_NEW     // Default, override in .conf
#define HF_UNISNIFF_SAVE_MODE_NEW 0
#define HF_UNISNIFF_SAVE_MODE_APPEND 1
#define HF_UNISNIFF_SAVE_MODE_NONE 2

#ifdef WITH_FLASH
static void UniSniff_DownloadTraceInstructions(char *filename) {
    Dbprintf("");
    Dbprintf("To get the trace from flash and display it:");
    Dbprintf("1. mem spiffs dump -s %s -d hf_unisniff.trace", filename);
    Dbprintf("2. trace load -f hf_unisniff.trace");
    Dbprintf("3. trace list -t [protocol] -1");
}
#endif

void ModInfo(void) {
    DbpString("  HF UNISNIFF, multimode HF sniffer with optional flashmem & runtime select (hazardousvoltage)");
    Dbprintf("  Compile-time default protocol: %s", HF_UNISNIFF_PROTOCOL);
#ifdef WITH_FLASH
    DbpString("  WITH_FLASH support.");
#endif
}

void RunMod(void) {
    char *protocols[]=HF_UNISNIFF_PROTOCOLS;
    uint8_t sniff_protocol, default_sniff_protocol;
    StandAloneMode();

    Dbprintf(_YELLOW_("HF UNISNIFF started"));
    for (sniff_protocol=0; sniff_protocol<HF_UNISNIFF_NUM_PROTOCOLS; sniff_protocol++) {
        if (!strcmp(protocols[sniff_protocol], HF_UNISNIFF_PROTOCOL)) break;
    }
    default_sniff_protocol=sniff_protocol;
#ifdef HF_UNISNIFF_VERBOSE_DEBUG
    Dbprintf("Compile-time configured protocol: %d", sniff_protocol);
#endif
#ifdef WITH_FLASH
    uint8_t save_mode=HF_UNISNIFF_SAVE_MODE;
    rdv40_spiffs_lazy_mount();
    // Allocate memory now for buffer for filename to save to.  Who knows what'll be
    // available after filling the trace buffer.
    char *filename = (char *)BigBuf_malloc(64);
    if (filename == NULL) {
        Dbprintf("failed to allocate memory");
        return;
    }
    // Read the config file.  Size is limited to defined value so as not to consume
    // stupid amounts of stack
    if (exists_in_spiffs(HF_UNISNIFF_CONFIG)) {
        char config_buffer_array[HF_UNISNIFF_CONFIG_SIZE];
        char *config_buffer = &config_buffer_array[0];
        uint32_t config_size = size_in_spiffs(HF_UNISNIFF_CONFIG);
        if (config_size > HF_UNISNIFF_CONFIG_SIZE) config_size = HF_UNISNIFF_CONFIG_SIZE;
        rdv40_spiffs_read_as_filetype(HF_UNISNIFF_CONFIG, (uint8_t *)config_buffer, 
            config_size, RDV40_SPIFFS_SAFETY_SAFE);
        // This parser is terrible but I think fairly memory efficient?  Maybe better to use JSON?
        char *x = config_buffer;
        char *y = x;
        // strip out all the whitespace and Windows line-endings
    	do {
            while (*y == 0x20 || *y == 0x09 || *y == 0x0D) {
                ++y;
            }
        } while ((*x++ = c_tolower(*y++)));
        char *token  = strchr(config_buffer, '\n');
        while (token != NULL) {
            *token++ = '\0';
            char *tag = strtok(config_buffer, "=");
            char *value = strtok(NULL, "\n");
            if (tag != NULL && value != NULL) {
                if (!strcmp(tag,"protocol")) {
                    // If we got a selection here, override compile-time selection
                    uint8_t conf_protocol;
                    for (conf_protocol=0; conf_protocol<HF_UNISNIFF_NUM_PROTOCOLS; conf_protocol++) {
                        if (!strcmp(protocols[conf_protocol], value)) {
                            sniff_protocol = conf_protocol;
                            break;
                        }
                    }
#ifdef HF_UNISNIFF_VERBOSE_DEBUG
                    Dbprintf("Run-time configured protocol: %d", conf_protocol);
#endif
                } else if (!strcmp(tag,"save")) {
                    if (!strcmp(value,"append")) save_mode = HF_UNISNIFF_SAVE_MODE_APPEND;
                    else if (!strcmp(value, "none")) save_mode = HF_UNISNIFF_SAVE_MODE_NONE;
                    else save_mode = HF_UNISNIFF_SAVE_MODE_NEW;
#ifdef HF_UNISNIFF_VERBOSE_DEBUG
                    Dbprintf("Run-time configured save_mode: %d", save_mode);
#endif
                }
            }
            config_buffer = token;
            token = strchr(config_buffer, '\n');
        }

    }
#endif

    if (sniff_protocol >= HF_UNISNIFF_PROTO_ASK) {
        Dbprintf("[!] Protocol undefined, going to prompt loop");
        sniff_protocol = default_sniff_protocol;      // Default to compile-time setting.
        for (;;) {
            WDT_HIT();
            if (data_available()) {
                BigBuf_free();
                return;
            }
            if (GetTickCount() & 0x80)
                LED(sniff_protocol + 1, 0);
            else
                LEDsoff();

            // Was our button held down or pressed?
            int button_pressed = BUTTON_HELD(1000);
            if (button_pressed == BUTTON_SINGLE_CLICK) {
                sniff_protocol++;
                if (sniff_protocol >= HF_UNISNIFF_PROTO_ASK) sniff_protocol=0;
                SpinDelay(100);
                Dbprintf("Selected protocol: '%s'", protocols[sniff_protocol]);
            } else if (button_pressed == BUTTON_HOLD) {
                Dbprintf("Executing protocol %s", protocols[sniff_protocol]);
                for (uint8_t i=0; i<4; i++) {
                    LED(15,0);
                    SpinDelay(100);
                    LEDsoff();
                    SpinDelay(100);
                }
                WAIT_BUTTON_RELEASED();
                SpinDelay(300);
                LEDsoff();
                break;
            }
        }
    }

    switch(sniff_protocol) {
        case HF_UNISNIFF_PROTO_14a:
            SniffIso14443a(0);
            break;
        case HF_UNISNIFF_PROTO_14b:
            SniffIso14443b();
            break;
        case HF_UNISNIFF_PROTO_15:
            SniffIso15693(0, NULL, false);
            break;
        default:
            Dbprintf("No protocol selected, exiting.");
            BigBuf_free();
            LEDsoff();
            return;
    }

    Dbprintf("Stopped sniffing");
    SpinDelay(200);

    uint32_t trace_len = BigBuf_get_traceLen();
#ifndef WITH_FLASH
    // Keep stuff in BigBuf for USB/BT dumping
    if (trace_len > 0)
        Dbprintf("[!] Trace length (bytes) = %u", trace_len);
#else
    // Write stuff to spiffs logfile
    if (trace_len == 0) {
        Dbprintf("[!] Trace buffer is empty, nothing to write!");
    } else if (save_mode == HF_UNISNIFF_SAVE_MODE_NONE) {
        Dbprintf("[!] Trace save to flash disabled in config!");
    } else {
        Dbprintf("[!] Trace length (bytes) = %u", trace_len);

        uint8_t *trace_buffer = BigBuf_get_addr();

        sprintf(filename, "%s_%s%s", HF_UNISNIFF_LOGFILE, protocols[sniff_protocol], HF_UNISNIFF_LOGEXT);
        if (save_mode == HF_UNISNIFF_SAVE_MODE_NEW) {
            uint16_t file_index=0;
            while (exists_in_spiffs(filename)) {
                if (file_index++ == 1000) break;
                sprintf(filename, "%s_%s-%03d%s", HF_UNISNIFF_LOGFILE, protocols[sniff_protocol],
                 file_index, HF_UNISNIFF_LOGEXT);
            }
            if (file_index > 999) {
                Dbprintf("[!] Too many files!  Trace not saved.  Clean up your SPIFFS.");
            } else {
                rdv40_spiffs_write(filename, trace_buffer, trace_len, RDV40_SPIFFS_SAFETY_SAFE);
                Dbprintf("[!] Wrote trace to %s", filename);
            }
        } else if (save_mode == HF_UNISNIFF_SAVE_MODE_APPEND) {
            if (!exists_in_spiffs(filename)) {
                rdv40_spiffs_write(filename, trace_buffer, trace_len, RDV40_SPIFFS_SAFETY_SAFE);
                Dbprintf("[!] Wrote trace to %s", filename);
            } else {
                rdv40_spiffs_append(filename, trace_buffer, trace_len, RDV40_SPIFFS_SAFETY_SAFE);
                Dbprintf("[!] Appended trace to %s", filename);
            }
        }
        UniSniff_DownloadTraceInstructions(filename);
    }

    LED_D_ON();
    rdv40_spiffs_lazy_unmount();
    LED_D_OFF();

    SpinErr(LED_A, 200, 5);
    SpinDelay(100);
    BigBuf_free();
#endif

    Dbprintf("-=[ exit ]=-");
    LEDsoff();

    return;
}
