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
// LF emul  -   Very simple mode. Simulate only predefined in low[] IDs
//              Short click - select next slot and start simulation
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
#include "commonutil.h"

#define MAX_IND 16 // 4 LEDs - 2^4 combinations
#define LF_CLOCK 64 // for 125kHz

// Predefined IDs must be stored in em4100emul_low[].
static uint64_t em4100emul_low[] = {0x565A1140BE, 0x365A398149, 0x5555555555, 0xFFFFFFFFFF};
static uint8_t em4100emul_slots_count;
static int em4100emul_buflen;

void ModInfo(void) {
    DbpString("  LF EM4100 simulator standalone mode");
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
    memset(bba + em4100emul_buflen, bit, LF_CLOCK / 2);
    em4100emul_buflen += (LF_CLOCK / 2);
    memset(bba + em4100emul_buflen, bit ^ 1, LF_CLOCK / 2);
    em4100emul_buflen += (LF_CLOCK / 2);
}

static void construct_EM410x_emul(uint64_t id) {

    int i, j;
    int binary[4] = {0, 0, 0, 0};
    int parity[4] = {0, 0, 0, 0};
    em4100emul_buflen = 0;

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

static void LED_Slot(int i) {
    LEDsoff();
    if (em4100emul_slots_count > 4) {
        LED(i % MAX_IND, 0); //binary indication for em4100emul_slots_count > 4
    } else {
        LED(1 << i, 0); //simple indication for em4100emul_slots_count <=4
    }
}

void RunMod(void) {
    StandAloneMode();
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    Dbprintf("[=] >>  LF EM4100 simulator started  <<");

    int selected = 0; //selected slot after start
    em4100emul_slots_count = ARRAYLEN(em4100emul_low);
    for (;;) {
        WDT_HIT();
        if (data_available()) break;

        SpinDelay(100);
        SpinUp(100);
        LED_Slot(selected);
        construct_EM410x_emul(rev_quads(em4100emul_low[selected]));
        SimulateTagLowFrequency(em4100emul_buflen, 0, true);
        selected = (selected + 1) % em4100emul_slots_count;
    }
}
