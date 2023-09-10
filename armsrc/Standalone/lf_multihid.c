//-----------------------------------------------------------------------------
// Copyright (C) Shain Lakin, 2023
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
// LF HID 26 Bit (H10301) multi simulator:
// Simple LF HID26 (H10301) tag simulator
// Short click - select next slot and start simulation
// LEDS = LED ON for selected slot
// Add tags (raw) to the hid26_predefined_raw array
//-----------------------------------------------------------------------------


#include "standalone.h"
#include "proxmark3_arm.h"
#include "appmain.h"
#include "fpgaloader.h"
#include "util.h"
#include "dbprint.h"
#include "ticks.h"
#include "lfops.h"

#define ARRAYLEN(x) (sizeof(x) / sizeof((x)[0]))
#define MAX_IND 4

void LED_Slot(int i);

static uint64_t hid26_predefined_raw[] = {0x2004ec2e87, 0x2004421807, 0x20064312d6, 0x2006ec0c86};
static uint8_t hid26_slots_count;

void ModInfo(void) {
    DbpString("LF HID 26 Bit (H10301) multi simulator - aka MultiHID (Shain Lakin)");
}

void LED_Slot(int i) {
    LEDsoff();
    if (hid26_slots_count > 4) {
        LED(i % MAX_IND, 0);
    } else {
        LED(1 << i, 0);
    }
}

void RunMod(void) {
    StandAloneMode();
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    Dbprintf(">>  LF HID26 multi simulator started - aka MultiHID (Shain Lakin)  <<");

    int selected = 0; //selected slot after start
    hid26_slots_count = ARRAYLEN(hid26_predefined_raw);
    for (;;) {
        WDT_HIT();
        if (data_available()) {
            LEDsoff();
            break;
        }

        SpinDelay(100);
        SpinUp(100);
        LED_Slot(selected);
        uint64_t raw_data = hid26_predefined_raw[selected];
        CmdHIDsimTAG(0, raw_data >> 32, raw_data & 0xFFFFFFFF, 0, false);
        selected = (selected + 1) % hid26_slots_count;
    }
}
