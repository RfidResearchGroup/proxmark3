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
// main code for Legic Prime 7-slot persistent read/sim (RDV4)
//-----------------------------------------------------------------------------

#include "standalone.h"
#include "proxmark3_arm.h"
#include "BigBuf.h"
#include "appmain.h"
#include "fpga_apis.h"
#include "fpga_loader.h"
#include "util.h"
#include "dbprint.h"
#include "ticks_apis.h"
#include "legicrf.h"
#include "legicrfsim.h"
#include "legic.h"          // legic_card_select_t struct
#include "spiffs.h"         // flashmem
#include "string.h"
#include <inttypes.h>

#define LEGIC_SLOT_COUNT 7
#define LEGIC_DUMP_FILENAME_FORMAT "hf-legic-slot-%u.bin"

typedef enum {
    MODE_SCAN = 0,
    MODE_EMULATE = 1
} legic_mode_t;

typedef struct {
    bool populated;
    uint16_t cardsize;
    uint8_t tagtype; // ct: 0=MIM22, 1=MIM256, 2=MIM1024
    uint8_t uid[4];
} legic_slot_t;

// Static module-level storage to minimize stack frame pressure
static legic_slot_t s_slots[LEGIC_SLOT_COUNT];
static char s_filename[32];

static uint8_t get_slot_led_mask(uint8_t slot_1_to_7) {
    uint8_t mask = 0;
    if (slot_1_to_7 & 1) mask |= LED_B;
    if (slot_1_to_7 & 2) mask |= LED_C;
    if (slot_1_to_7 & 4) mask |= LED_D;
    return mask;
}

static const char *get_tagtype_name(uint8_t tagtype) {
    switch (tagtype) {
        case 0: return "MIM22";
        case 1: return "MIM256";
        case 2: return "MIM1024";
        default: return "Unknown";
    }
}

static bool save_slot_from_emulator(uint8_t slot, uint16_t cardsize) {
#ifdef WITH_FLASH
    if (slot >= LEGIC_SLOT_COUNT) return false;
    sprintf(s_filename, LEGIC_DUMP_FILENAME_FORMAT, (unsigned int)(slot + 1));
    uint8_t *mem = BigBuf_get_EM_addr();
    if (!mem) return false;
    if (cardsize == 0 || cardsize > 1024) cardsize = 1024;
    rdv40_spiffs_write(s_filename, mem, cardsize, RDV40_SPIFFS_SAFETY_SAFE);
    return true;
#else
    return false;
#endif
}

static bool load_slot_to_emulator(uint8_t slot, uint16_t *out_cardsize, uint8_t *out_tagtype) {
#ifdef WITH_FLASH
    if (slot >= LEGIC_SLOT_COUNT) return false;
    sprintf(s_filename, LEGIC_DUMP_FILENAME_FORMAT, (unsigned int)(slot + 1));
    if (!exists_in_spiffs(s_filename)) {
        return false;
    }
    uint32_t size = size_in_spiffs(s_filename);
    if (size == 0) {
        return false;
    }
    if (size > 1024) size = 1024;

    uint8_t *emCARD = BigBuf_get_EM_addr();
    if (!emCARD) return false;
    memset(emCARD, 0, 1024);

    rdv40_spiffs_read_as_filetype(s_filename, emCARD, size, RDV40_SPIFFS_SAFETY_SAFE);

    if (out_cardsize) *out_cardsize = (uint16_t)size;
    if (out_tagtype) {
        if (size <= 22) *out_tagtype = 0;
        else if (size <= 256) *out_tagtype = 1;
        else *out_tagtype = 2;
    }
    return true;
#else
    return false;
#endif
}

static bool save_scanned_card(uint8_t slot, const legic_card_select_t *p_card) {
#ifdef WITH_FLASH
    if (slot >= LEGIC_SLOT_COUNT || !p_card) return false;
    sprintf(s_filename, LEGIC_DUMP_FILENAME_FORMAT, (unsigned int)(slot + 1));
    uint8_t *mem = BigBuf_get_EM_addr();
    if (!mem) return false;
    uint16_t size = p_card->cardsize;
    if (size == 0 || size > 1024) size = 1024;
    rdv40_spiffs_write(s_filename, mem, size, RDV40_SPIFFS_SAFETY_SAFE);
    return true;
#else
    return false;
#endif
}

static void wait_button_release(void) {
    while (BUTTON_PRESS()) {
        WDT_HIT();
        SpinDelay(10);
    }
    SpinDelay(20);
}

static int get_button_event(void) {
    uint32_t press_start = GetTickCount();

    // 1. Measure the first press duration
    while (BUTTON_PRESS()) {
        WDT_HIT();
        if (data_available()) return BUTTON_HOLD;

        if (GetTickCount() - press_start >= 1000) {
            wait_button_release();
            return BUTTON_HOLD;
        }
        SpinDelay(10);
    }
    SpinDelay(20);

    // 2. Wait up to 350ms for a second click
    uint32_t release_time = GetTickCount();
    while (GetTickCount() - release_time < 350) {
        WDT_HIT();
        if (data_available()) return BUTTON_HOLD;

        if (BUTTON_PRESS()) {
            uint32_t second_press_start = GetTickCount();
            while (BUTTON_PRESS()) {
                WDT_HIT();
                if (data_available()) return BUTTON_HOLD;

                if (GetTickCount() - second_press_start >= 1000) {
                    wait_button_release();
                    return BUTTON_HOLD;
                }
                SpinDelay(10);
            }
            wait_button_release();
            return BUTTON_DOUBLE_CLICK;
        }
        SpinDelay(10);
    }

    return BUTTON_SINGLE_CLICK;
}

static int wait_and_poll_button(uint32_t delay_ms) {
    uint32_t start = GetTickCount();
    while (GetTickCount() - start < delay_ms) {
        WDT_HIT();
        if (data_available()) {
            return BUTTON_HOLD;
        }
        if (BUTTON_PRESS()) {
            return get_button_event();
        }
        SpinDelay(10);
    }
    return BUTTON_NO_CLICK;
}

static int check_button_after_sim(void) {
    if (BUTTON_PRESS()) {
        return get_button_event();
    }
    // Button was released during sim exit (click 1 finished).
    // Wait up to 350ms for click 2.
    uint32_t release_time = GetTickCount();
    while (GetTickCount() - release_time < 350) {
        WDT_HIT();
        if (data_available()) return BUTTON_HOLD;

        if (BUTTON_PRESS()) {
            uint32_t second_press_start = GetTickCount();
            while (BUTTON_PRESS()) {
                WDT_HIT();
                if (data_available()) return BUTTON_HOLD;

                if (GetTickCount() - second_press_start >= 1000) {
                    wait_button_release();
                    return BUTTON_HOLD;
                }
                SpinDelay(10);
            }
            wait_button_release();
            return BUTTON_DOUBLE_CLICK;
        }
        SpinDelay(10);
    }
    return BUTTON_SINGLE_CLICK;
}

void ModInfo(void) {
    DbpString("  HF Legic Prime 7-slot RDV4 standalone");
}

void RunMod(void) {
    StandAloneMode();
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    BigBuf_Clear_ext(false);
    BigBuf_get_EM_addr();
#ifdef WITH_FLASH
    rdv40_spiffs_lazy_mount();
#endif

    Dbprintf("[=] =========================================================");
    Dbprintf("[=]   Proxmark3 RDV4: Legic Prime 7-Slot Standalone Mode     ");
    Dbprintf("[=] =========================================================");
    Dbprintf("[=] Controls:");
    Dbprintf("[=]   - Single Click : Cycle to next slot (1 -> 2 -> ... -> 7)");
    Dbprintf("[=]   - Double Click : Toggle between Scan and Emulation mode");
    Dbprintf("[=]   - Long Hold    : Exit standalone mode (1 second hold)");
    Dbprintf("[=] LED Signaling:");
    Dbprintf("[=]   - LEDs B, C, D : Binary slot number (1 to 7)");
    Dbprintf("[=]   - Blinking     : Scan Mode (searching for Legic tags)");
    Dbprintf("[=]   - Solid + LED A: Emulation Mode (tag simulated on HF)");
    Dbprintf("[=] ---------------------------------------------------------");

    memset(s_slots, 0, sizeof(s_slots));

    Dbprintf("[=] Checking SPIFFS memory slots (1 to 7)...");
    for (uint8_t i = 0; i < LEGIC_SLOT_COUNT; i++) {
        sprintf(s_filename, LEGIC_DUMP_FILENAME_FORMAT, (unsigned int)(i + 1));
#ifdef WITH_FLASH
        if (exists_in_spiffs(s_filename)) {
            uint32_t sz = size_in_spiffs(s_filename);
            if (sz > 0) {
                s_slots[i].populated = true;
                s_slots[i].cardsize = (uint16_t)sz;
                if (sz <= 22) s_slots[i].tagtype = 0;
                else if (sz <= 256) s_slots[i].tagtype = 1;
                else s_slots[i].tagtype = 2;

                rdv40_spiffs_read_as_filetype(s_filename, s_slots[i].uid, sizeof(s_slots[i].uid), RDV40_SPIFFS_SAFETY_SAFE);

                Dbprintf("[=]   Slot %u: [LOADED] %s (%s, %u bytes, UID: %02X %02X %02X %02X)",
                         (unsigned int)(i + 1), s_filename, get_tagtype_name(s_slots[i].tagtype), (unsigned int)sz,
                         s_slots[i].uid[0], s_slots[i].uid[1], s_slots[i].uid[2], s_slots[i].uid[3]);
                continue;
            }
        }
#endif
        Dbprintf("[=]   Slot %u: [ EMPTY ] (%s not found)", (unsigned int)(i + 1), s_filename);
    }
    Dbprintf("[=] ---------------------------------------------------------");

    uint8_t current_slot = 0;
    legic_mode_t current_mode = s_slots[0].populated ? MODE_EMULATE : MODE_SCAN;

    if (current_mode == MODE_EMULATE) {
        Dbprintf("[=] Slot 1 has stored card data -> Starting in EMULATION MODE");
    } else {
        Dbprintf("[=] Slot 1 is empty -> Starting in SCAN MODE");
    }

    for (;;) {
        WDT_HIT();
        if (data_available()) break;

        // ====================================================================
        // SCAN MODE (Searching for Legic tags)
        // ====================================================================
        if (current_mode == MODE_SCAN) {
            uint8_t slot_leds = get_slot_led_mask(current_slot + 1);

            // Phase 1: Slot LEDs ON (250ms)
            LEDsoff();
            LED(slot_leds, 0);
            int btn = wait_and_poll_button(250);
            if (btn == BUTTON_HOLD) {
                DbpString("[=] Long hold detected. Exiting standalone mode...");
                break;
            }
            if (btn == BUTTON_SINGLE_CLICK) {
                current_slot = (current_slot + 1) % LEGIC_SLOT_COUNT;
                Dbprintf("[=] Advanced to Slot %u", (unsigned int)(current_slot + 1));
                if (s_slots[current_slot].populated) {
                    current_mode = MODE_EMULATE;
                    Dbprintf("[=] Slot %u has card data -> Switched to EMULATION MODE", (unsigned int)(current_slot + 1));
                }
                continue;
            }
            if (btn == BUTTON_DOUBLE_CLICK) {
                if (s_slots[current_slot].populated) {
                    current_mode = MODE_EMULATE;
                    Dbprintf("[=] Double click -> Switched Slot %u to EMULATION MODE", (unsigned int)(current_slot + 1));
                } else {
                    Dbprintf("[!] Double click ignored: Slot %u is empty", (unsigned int)(current_slot + 1));
                }
                continue;
            }

            // Phase 2: Slot LEDs OFF (250ms)
            LEDsoff();
            btn = wait_and_poll_button(250);
            if (btn == BUTTON_HOLD) {
                DbpString("[=] Long hold detected. Exiting standalone mode...");
                break;
            }
            if (btn == BUTTON_SINGLE_CLICK) {
                current_slot = (current_slot + 1) % LEGIC_SLOT_COUNT;
                Dbprintf("[=] Advanced to Slot %u", (unsigned int)(current_slot + 1));
                if (s_slots[current_slot].populated) {
                    current_mode = MODE_EMULATE;
                    Dbprintf("[=] Slot %u has card data -> Switched to EMULATION MODE", (unsigned int)(current_slot + 1));
                }
                continue;
            }
            if (btn == BUTTON_DOUBLE_CLICK) {
                if (s_slots[current_slot].populated) {
                    current_mode = MODE_EMULATE;
                    Dbprintf("[=] Double click -> Switched Slot %u to EMULATION MODE", (unsigned int)(current_slot + 1));
                } else {
                    Dbprintf("[!] Double click ignored: Slot %u is empty", (unsigned int)(current_slot + 1));
                }
                continue;
            }

            // RF Reader poll attempt (identical to hf_legic.c)
            int read_success = LegicRfReaderEx(0, 1024, 0x55);
            if (read_success != PM3_ESOFT) {
                legic_card_select_t *p_card = getLegicCardInfo();
                if (p_card && p_card->cardsize > 0) {
                    uint8_t ct = 2;
                    switch (p_card->tagtype) {
                        case 0x0D: ct = 0; break;
                        case 0x1D: ct = 1; break;
                        case 0x3D: ct = 2; break;
                        default: ct = 2; break;
                    }

                    Dbprintf(_GREEN_("[+] [TAG DETECTED] Read successful on Slot %u!"), (unsigned int)(current_slot + 1));
                    Dbprintf("[+]   UID : %02X %02X %02X %02X", p_card->uid[0], p_card->uid[1], p_card->uid[2], p_card->uid[3]);
                    Dbprintf("[+]   Type: %s (0x%02X), Size: %u bytes",
                             get_tagtype_name(ct), (unsigned int)p_card->tagtype, (unsigned int)p_card->cardsize);

                    // Signal successful read with rapid all-LED blink
                    SpinErr(LED_A | LED_B | LED_C | LED_D, 80, 4);

                    if (save_scanned_card(current_slot, p_card)) {
                        s_slots[current_slot].populated = true;
                        s_slots[current_slot].cardsize = p_card->cardsize;
                        s_slots[current_slot].tagtype = ct;
                        memcpy(s_slots[current_slot].uid, p_card->uid, 4);

                        Dbprintf(_GREEN_("[+] Card dump saved to Slot %u! Switching to EMULATION MODE."), (unsigned int)(current_slot + 1));
                        current_mode = MODE_EMULATE;
                    } else {
                        DbpString(_RED_("[!] Failed to save card dump to flash memory."));
                    }
                }
            }
        }
        // ====================================================================
        // EMULATION MODE (Emulating Legic card on HF)
        // ====================================================================
        else if (current_mode == MODE_EMULATE) {
            uint16_t cardsize = 1024;
            uint8_t tagtype = 2;

            if (!load_slot_to_emulator(current_slot, &cardsize, &tagtype)) {
                Dbprintf("[!] Slot %u data could not be loaded from flash. Switching to SCAN MODE.", (unsigned int)(current_slot + 1));
                s_slots[current_slot].populated = false;
                current_mode = MODE_SCAN;
                continue;
            }

            uint8_t slot_leds = get_slot_led_mask(current_slot + 1);
            LEDsoff();
            LED(LED_A | slot_leds, 0);

            Dbprintf("[=] >>> Slot %u EMULATION ACTIVE (%s, %u bytes, UID: %02X %02X %02X %02X) <<<",
                     (unsigned int)(current_slot + 1), get_tagtype_name(tagtype), (unsigned int)cardsize,
                     s_slots[current_slot].uid[0], s_slots[current_slot].uid[1],
                     s_slots[current_slot].uid[2], s_slots[current_slot].uid[3]);

            // Run native simulation (blocks until button pressed or USB command received)
            LegicRfSimulate(tagtype, false);

            // Persist any reader writes back to flash
            save_slot_from_emulator(current_slot, cardsize);

            if (data_available()) {
                break;
            }

            int btn = check_button_after_sim();
            if (btn == BUTTON_HOLD) {
                DbpString("[=] Long hold detected. Exiting standalone mode...");
                break;
            }
            if (btn == BUTTON_DOUBLE_CLICK) {
                Dbprintf("[=] Double click -> Switched Slot %u to SCAN MODE (ready to overwrite)", (unsigned int)(current_slot + 1));
                current_mode = MODE_SCAN;
            } else if (btn == BUTTON_SINGLE_CLICK) {
                current_slot = (current_slot + 1) % LEGIC_SLOT_COUNT;
                Dbprintf("[=] Single click -> Advanced to Slot %u", (unsigned int)(current_slot + 1));
                if (s_slots[current_slot].populated) {
                    current_mode = MODE_EMULATE;
                } else {
                    Dbprintf("[=] Slot %u is empty -> Switched to SCAN MODE", (unsigned int)(current_slot + 1));
                    current_mode = MODE_SCAN;
                }
            }
        }
    }

    BigBuf_free_keep_EM();
    LEDsoff();
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    DbpString("[=] Standalone mode exited.");
}
