//-----------------------------------------------------------------------------
// Copyright (C) 2020 Dmitriy Loginoov
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
// LF rswb   -  This mode can simulate ID from selected slot, read ID to
//              selected slot, write from selected slot to T5555/T55x7 tag and store
//              read ID to flash (only RDV4).
//              Predefining it is not recommended because you can incidentally rewrite your MANDATORY tag data.
//
//              To recall stored ID from flash execute:
//                  mem spifss dump o emdump p
//              or:
//                  mem spifss dump o emdump f emdump
//              then from shell:
//                  hexdump emdump -e '5/1 "%02X" /0 "\n"'
//
// Mode list (switched by single click):
//
// 0 - READ         Read source card ID and store it to current slot
//                  Will switch to SIM mode automatically.
//
// 1 - SIM          Simulate read ID
//
// 2 - WRITE(CLONE) Write read ID to T55x7 card
//                  !!! Warning, card id WILL BE OVERWRITTEN
//
// 3 - BRUTE        Brute upper or down from read card)
//                  You can PRESS SINGLE to exit brute mode OR
//                  PRESS DOUBLE to save bruted ID to current slot (will automatically switch to SIM mode) AND
//                  Also You can HOLD button to change brute speeds.
//
// Slots are switched by HOLD (LONG PRESS)
//-----------------------------------------------------------------------------
#include "standalone.h"
#include "proxmark3_arm.h"
#include "appmain.h"
#include "fpgaloader.h"
#include "util.h"
#include "dbprint.h"
#include "ticks.h"
#include "string.h"
#include "BigBuf.h"
#include "spiffs.h"
#include "inttypes.h"
#include "parity.h"
#include "lfops.h"

#ifdef WITH_FLASH
#include "flashmem.h"
#endif

#define LF_CLOCK 64 // for 125kHz
#define LF_RWSB_T55XX_TYPE 1 // Tag type: 0 - T5555, 1-T55x7, 2-EM4x05

#define LF_RWSB_UNKNOWN_RESULT 0
#define LF_RWSB_BRUTE_STOPED 1
#define LF_RWSB_BRUTE_SAVED 2

//modes
#define LF_RWSB_MODE_READ 0
#define LF_RWSB_MODE_SIM 1
#define LF_RWSB_MODE_WRITE 2
#define LF_RWSB_MODE_BRUTE 3

// Predefined bruteforce speed
// avg: 1s, 1.2s, 1.5s, 2s
static int em4100rswb_bruteforceSpeedCurrent = 1;
static int em4100rswb_bruteforceSpeed[] = {10, 12, 14, 16};

// em4100rswb_low & em4100rswb_high - array for storage IDs. Its length must be equal.
// Predefined IDs must be stored in em4100rswb_low[].
// In em4100rswb_high[] must be nulls
static uint64_t em4100rswb_low[] = {0, 0, 0, 0};
static uint32_t em4100rswb_high[] = {0, 0, 0, 0};
static int em4100rswb_buflen;

void ModInfo(void) {
    DbpString("  LF EM4100 read/sim/write/brute mode");
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
    memset(bba + em4100rswb_buflen, bit, LF_CLOCK / 2);
    em4100rswb_buflen += (LF_CLOCK / 2);
    memset(bba + em4100rswb_buflen, bit ^ 1, LF_CLOCK / 2);
    em4100rswb_buflen += (LF_CLOCK / 2);
}

static void construct_EM410x_emul(uint64_t id) {
    int i, j;
    int binary[4] = {0, 0, 0, 0};
    int parity[4] = {0, 0, 0, 0};
    em4100rswb_buflen = 0;

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

static void LED_Update(int mode, int slot) {
    LEDsoff();
    switch (mode) {
        case 0:
            break;
        case 1:
            LED_A_ON();
            break;
        case 2:
            LED_B_ON();
            break;
        case 3:
            LED_A_ON();
            LED_B_ON();
            break;
    }
    switch (slot) {
        case 0:
            break;
        case 1:
            LED_C_ON();
            break;
        case 2:
            LED_D_ON();
            break;
        case 3:
            LED_C_ON();
            LED_D_ON();
            break;
    }
}

static void FlashLEDs(uint32_t speed, uint8_t times) {
    for (int i = 0; i < times * 2; i++) {
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
    char *filename = "emdump";
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

static uint64_t PackEmID(uint64_t original, int newCardNum) {
    uint64_t buf = original;
    //clear pairity bits
    buf &= ~(1 << 0);
    buf &= ~(1 << 25);
    //clear card number
    for (int i = 1; i <= 16; i++) {
        buf &= ~(1 << i);
    }
    buf |= (newCardNum & 0xFFFF) << 1;
    buf |= oddparity32((buf >> 1) & 0xFFF);
    buf |= (evenparity32((buf >> 13) & 0xFFF)) << 25;

    uint32_t cardnumNew = (buf >> 1) & 0xFFFF;
    uint32_t fcNew = (buf >> 17) & 0xFF;
    Dbprintf("[=] RECONSTRUCT TAG ID: %"PRIx64" - FC: %u - Card: %u\n", buf, fcNew, cardnumNew);
    return buf;
}

static void PrintFcAndCardNum(uint64_t lowData) {
    // Calculate Facility Code and Card Number from high and low
    uint32_t fc = (lowData >> 17) & 0xFF;
    uint32_t cardnum = (lowData >> 1) & 0xFFFF;
    Dbprintf("[=] READ TAG ID: %"PRIx64" - FC: %u - Card: %u", lowData, fc, cardnum);
}

static int BruteEMTag(uint64_t originalCard, int slot) {
    int speed_count = 4;

    int direction = 1;

    uint32_t cardnum = (originalCard >> 1) & 0xFFFF;
    if (cardnum > 32767) {
        direction = -1;
    }

    while (cardnum > 1 && cardnum < 65535) {
        WDT_HIT();
        if (data_available()) break;

        cardnum = cardnum + direction;
        uint64_t currentCard = PackEmID(originalCard, cardnum);
        Dbprintf("[=] >>  Simulating card id %"PRIx64" <<", currentCard);
        construct_EM410x_emul(rev_quads(currentCard));
        SimulateTagLowFrequencyEx(em4100rswb_buflen, 0, 1, em4100rswb_bruteforceSpeed[em4100rswb_bruteforceSpeedCurrent] * 10000);

        int button_pressed = BUTTON_CLICKED(1000);
        if (button_pressed == BUTTON_SINGLE_CLICK) {
            Dbprintf("[=] >>  Exit bruteforce mode without saving. <<");
            return LF_RWSB_BRUTE_STOPED;
        } else if (button_pressed == BUTTON_DOUBLE_CLICK) {
            FlashLEDs(100, 10);
            Dbprintf("[=] >>  Saving bruteforced card to current slot  <<");
            em4100rswb_low[slot] = currentCard;
#ifdef WITH_FLASH
            SaveIDtoFlash(slot, em4100rswb_low[slot]);
#endif
            return LF_RWSB_BRUTE_SAVED;
        } else if (button_pressed == BUTTON_HOLD) {
            FlashLEDs(100, 1);
            WAIT_BUTTON_RELEASED();
            em4100rswb_bruteforceSpeedCurrent = (em4100rswb_bruteforceSpeedCurrent + 1) % speed_count;
            FlashLEDs(100, em4100rswb_bruteforceSpeedCurrent + 1);
            Dbprintf("[=] >>  Setting speed to %d (%d) <<", em4100rswb_bruteforceSpeedCurrent, em4100rswb_bruteforceSpeed[em4100rswb_bruteforceSpeedCurrent]);
        }
    }
    return LF_RWSB_BRUTE_STOPED;
}

static int ExecuteMode(int mode, int slot) {
    LED_Update(mode, slot);
    WDT_HIT();

    switch (mode) {
        //default first mode is simulate
        case LF_RWSB_MODE_READ:
            Dbprintf("[=] >>  Read mode started  <<");
            lf_em410x_watch(1, &em4100rswb_high[slot], &em4100rswb_low[slot], true);
            LED_Update(mode, slot);
            Dbprintf("[=] >>  Tag found. Saving. <<");
            FlashLEDs(100, 5);
            PrintFcAndCardNum(em4100rswb_low[slot]);
#ifdef WITH_FLASH
            SaveIDtoFlash(slot, em4100rswb_low[slot]);
#endif
            return LF_RWSB_UNKNOWN_RESULT;
        case LF_RWSB_MODE_SIM:
            Dbprintf("[=] >>  Sim mode started  <<");
            construct_EM410x_emul(rev_quads(em4100rswb_low[slot]));
            SimulateTagLowFrequency(em4100rswb_buflen, 0, true);
            return LF_RWSB_UNKNOWN_RESULT;
        case LF_RWSB_MODE_WRITE:
            Dbprintf("[!!] >>  Write mode started  <<");
            copy_em410x_to_t55xx(LF_RWSB_T55XX_TYPE, LF_CLOCK, (uint32_t)(em4100rswb_low[slot] >> 32), (uint32_t)(em4100rswb_low[slot] & 0xffffffff), true);
            return LF_RWSB_UNKNOWN_RESULT;
        case LF_RWSB_MODE_BRUTE:
            Dbprintf("[=] >>  Bruteforce mode started  <<");
            return BruteEMTag(em4100rswb_low[slot], slot);
    }
    return LF_RWSB_UNKNOWN_RESULT;
}

static int SwitchMode(int mode, int slot) {
    WDT_HIT();
    ExecuteMode(mode, slot);

    if (mode == LF_RWSB_MODE_READ) {
        //After read mode we need to switch to sim mode automatically
        Dbprintf("[=] >>  automatically switch to sim mode after read  <<");

        return SwitchMode(LF_RWSB_MODE_SIM, slot);
    } else if (mode == LF_RWSB_MODE_BRUTE) {
        //We have already have a click inside brute mode. Lets switch next mode
        Dbprintf("[=] >>  automatically switch to read mode after brute  <<");

        return SwitchMode(LF_RWSB_MODE_READ, slot);
    }
    return mode;
}

void RunMod() {
    StandAloneMode();
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    Dbprintf("[=] >>  LF EM4100 read/write/clone/brute started  <<");
    int slots_count = 4;
    int mode_count = 4;

    int mode = 0;
    int slot = 0;
    mode = SwitchMode(mode, slot);

    for (;;) {
        WDT_HIT();
        if (data_available()) break;

        int button_pressed = BUTTON_CLICKED(1000);
        LED_Update(mode, slot);

        //press button - switch mode
        //hold button - switch slot
        if (button_pressed == BUTTON_SINGLE_CLICK) {
            Dbprintf("[=] >>  Single click  <<");
            mode = (mode + 1) % mode_count;
            SpinDown(100);

            mode = SwitchMode(mode, slot);
        } else if (button_pressed == BUTTON_HOLD) {
            Dbprintf("[=] >>  Button hold  <<");
            slot = (slot + 1) % slots_count;
            SpinUp(100);
            SpinDelay(300);

            //automatically switch to SIM mode on slot selection
            mode = LF_RWSB_MODE_SIM;
            mode = SwitchMode(mode, slot);
        }
    }
}
