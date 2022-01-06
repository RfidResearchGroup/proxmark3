//-----------------------------------------------------------------------------
// Copyright (C) Artyom Gnatyuk, 2020
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
// LF rwc   -   This mode can simulate ID from selected slot, read ID to
//              selected slot, write from selected slot to T5555 tag and store
//              readed ID to flash (only RDV4). Also you can set predefined IDs
//              in any slot.
//              To recall stored ID from flash execute:
//                  mem spifss dump o emdump p
//              or:
//                  mem spifss dump o emdump f emdump
//              then from shell:
//                  hexdump emdump -e '5/1 "%02X" /0 "\n"'
//-----------------------------------------------------------------------------
#include "standalone.h"
#include "proxmark3_arm.h"
#include "appmain.h"
#include "fpgaloader.h"
#include "lfops.h"
#include "util.h"
#include "dbprint.h"
#include "ticks.h"
#include "string.h"
#include "BigBuf.h"
#include "spiffs.h"
#include "commonutil.h"

#ifdef WITH_FLASH
#include "flashmem.h"
#endif

#define MAX_IND 16 // 4 LEDs - 2^4 combinations
#define LF_CLOCK 64   // for 125kHz

// em4100rwc_low & em4100rwc_high - array for storage IDs. Its length must be equal.
// Predefined IDs must be stored in em4100rwc_low[].
// In em4100rwc_high[] must be nulls
static uint64_t em4100rwc_low[] = {0x565AF781C7, 0x540053E4E2, 0x1234567890, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static uint32_t em4100rwc_high[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static uint8_t em4100rwc_slots_count;
static int em4100rwc_buflen;

void ModInfo(void) {
    DbpString("  LF EM4100 read/write/clone mode");
}

static uint64_t rev_quads(uint64_t bits) {
    uint64_t result = 0;
    for (int i = 0; i < 16; i++) {
        result += ((bits >> (60 - 4 * i)) & 0xf) << (4 * i);
    }
    return result >> 24;
}

static void fill_buff(uint8_t bit) {
    uint8_t *bba = BigBuf_get_addr();
    memset(bba + em4100rwc_buflen, bit, LF_CLOCK / 2);
    em4100rwc_buflen += (LF_CLOCK / 2);
    memset(bba + em4100rwc_buflen, bit ^ 1, LF_CLOCK / 2);
    em4100rwc_buflen += (LF_CLOCK / 2);
}

static void construct_EM410x_emul(uint64_t id) {

    int i, j;
    int binary[4] = {0, 0, 0, 0};
    int parity[4] = {0, 0, 0, 0};
    em4100rwc_buflen = 0;

    for (i = 0; i < 9; i++)
        fill_buff(1);

    for (i = 0; i < 10; i++) {
        for (j = 3; j >= 0; j--, id /= 2)
            binary[j] = id % 2;

        for (j = 0; j < 4; j++)
            fill_buff(binary[j]);

        fill_buff(binary[0] ^ binary[1] ^ binary[2] ^ binary[3]);
        for (j = 0; j < 4; j++)
            parity[j] ^= binary[j];
    }

    for (j = 0; j < 4; j++)
        fill_buff(parity[j]);

    fill_buff(0);
}

static void led_slot(int i) {
    LEDsoff();
    if (em4100rwc_slots_count > 4) {
        LED(i % MAX_IND, 0); //binary indication, usefully for em4100rwc_slots_count > 4
    } else {
        LED(1 << i, 0); //simple indication for em4100rwc_slots_count <=4
    }
}

static void flash_leds(uint32_t speed, uint8_t times) {
    for (uint16_t i = 0; i < times * 2; i++) {
        LED_A_INV();
        LED_B_INV();
        LED_C_INV();
        LED_D_INV();
        SpinDelay(speed);
    }
}

#ifdef WITH_FLASH
static void SaveIDtoFlash(int addr, uint64_t id) {
    uint8_t bt[5];
    const char *filename = "emdump";
    rdv40_spiffs_mount();
    for (int i = 0; i < 5; i++) {
        bt[4 - i] = (uint8_t)(id >> 8 * i & 0xff);
    }
    if (exists_in_spiffs(filename) == false) {
        rdv40_spiffs_write(filename, &bt[0], 5, RDV40_SPIFFS_SAFETY_NORMAL);
    } else {
        rdv40_spiffs_append(filename, &bt[0], 5, RDV40_SPIFFS_SAFETY_NORMAL);
    }
}
#endif

void RunMod(void) {
    StandAloneMode();
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    Dbprintf("[=] >>  LF EM4100 read/write/clone started  <<");

    int selected = 0;
    //state 0 - select slot
    //      1 - read tag to selected slot,
    //      2 - simulate tag from selected slot
    //      3 - write to T5555 tag
    uint8_t state = 0;
    em4100rwc_slots_count = ARRAYLEN(em4100rwc_low);
    led_slot(selected);
    for (;;) {

        WDT_HIT();

        if (data_available()) break;

        int button_pressed = BUTTON_HELD(1000);
        SpinDelay(300);

        switch (state) {
            case 0:
                // Select mode
                if (button_pressed == BUTTON_HOLD) {
                    // Long press - switch to simulate mode
                    SpinUp(100);
                    led_slot(selected);
                    state = 2;
                } else if (button_pressed == BUTTON_SINGLE_CLICK) {
                    // Click - switch to next slot
                    selected = (selected + 1) % em4100rwc_slots_count;
                    led_slot(selected);
                }
                break;
            case 1:
                // Read mode.
                if (button_pressed == BUTTON_HOLD) {
                    // Long press - switch to read mode
                    SpinUp(100);
                    led_slot(selected);
                    state = 3;
                } else if (button_pressed == BUTTON_SINGLE_CLICK) {
                    // Click - exit to select mode
                    lf_em410x_watch(1, &em4100rwc_high[selected], &em4100rwc_low[selected], true);
                    flash_leds(100, 5);
#ifdef WITH_FLASH
                    SaveIDtoFlash(selected, em4100rwc_low[selected]);
#endif
                    state = 0;
                }
                break;
            case 2:
                // Simulate mode
                if (button_pressed == BUTTON_HOLD) {
                    // Long press - switch to read mode
                    SpinDown(100);
                    led_slot(selected);
                    state = 1;
                } else if (button_pressed == BUTTON_SINGLE_CLICK) {
                    // Click - start simulating. Click again to exit from simulate mode
                    led_slot(selected);

                    construct_EM410x_emul(rev_quads(em4100rwc_low[selected]));
                    flash_leds(100, 5);

                    SimulateTagLowFrequency(em4100rwc_buflen, 0, true);
                    led_slot(selected);
                    state = 0; // Switch to select mode
                }
                break;
            case 3:
                // Write tag mode
                if (button_pressed == BUTTON_HOLD) {
                    // Long press - switch to select mode
                    SpinDown(100);
                    led_slot(selected);
                    state = 0;
                } else if (button_pressed == BUTTON_SINGLE_CLICK) {
                    // Click - write ID to tag
                    copy_em410x_to_t55xx(0, LF_CLOCK, (uint32_t)(em4100rwc_low[selected] >> 32), (uint32_t)(em4100rwc_low[selected] & 0xffffffff), true);
                    led_slot(selected);
                    state = 0; // Switch to select mode
                }
                break;
        }
    }
}
