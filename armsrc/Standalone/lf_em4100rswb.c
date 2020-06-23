//-----------------------------------------------------------------------------
// Monster1024
// based on code by: Artyom Gnatyuk, 2020
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// LF rswb   -  This mode can simulate ID from selected slot, read ID to
//              selected slot, write from selected slot to T5555/T55x7 tag and store
//              readed ID to flash (only RDV4).
//              Predefined its is not recomended because you can incedently rewrite your MANDATORY tag data.
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
// 1 - SIM          Simulate readed ID
//
// 2 - WRITE(CLONE) Write readed ID to T55x7 card
//                  !!! Warning, card id WILL BE OVERRWRITED
//
// 3 - BRUTE        Brute upper or down from readed card)
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

#define LF_CLOCK 64 //for 125kHz
#define LF_RWSB_T55XX_TYPE 1 //Tag type: 0 - T5555, 1-T55x7

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
static int bruteforceSpeedCurrent = 1;
static int bruteforceSpeed[] = {10, 12, 14, 16};

// low & high - array for storage IDs. Its length must be equal.
// Predefined IDs must be stored in low[].
// In high[] must be nulls
static uint64_t low[] = {0, 0, 0, 0};
static uint32_t high[] = {0, 0, 0, 0};
static uint8_t *bba;
static int buflen;

void ModInfo(void) {
    DbpString("  LF EM4100 read/sim/write/brute mode");
}

static uint64_t ReversQuads(uint64_t bits) {
    uint64_t result = 0;
    for (int i = 0; i < 16; i++) {
        result += ((bits >> (60 - 4 * i)) & 0xf) << (4 * i);
    }
    return result >> 24;
}

static void FillBuff(uint8_t bit) {
    memset(bba + buflen, bit, LF_CLOCK / 2);
    buflen += (LF_CLOCK / 2);
    memset(bba + buflen, bit ^ 1, LF_CLOCK / 2);
    buflen += (LF_CLOCK / 2);
}

static void ConstructEM410xEmulBuf(uint64_t id) {
    bba = BigBuf_get_addr();

    int i, j, binary[4], parity[4];
    buflen = 0;
    for (i = 0; i < 9; i++)
        FillBuff(1);
    parity[0] = parity[1] = parity[2] = parity[3] = 0;
    for (i = 0; i < 10; i++) {
        for (j = 3; j >= 0; j--, id /= 2)
            binary[j] = id % 2;
        for (j = 0; j < 4; j++)
            FillBuff(binary[j]);
        FillBuff(binary[0] ^ binary[1] ^ binary[2] ^ binary[3]);
        for (j = 0; j < 4; j++)
            parity[j] ^= binary[j];
    }
    for (j = 0; j < 4; j++)
        FillBuff(parity[j]);
    FillBuff(0);
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
    buf |= oddparity32((buf >> 1) & 0xFFF) & 1;
    buf |= (evenparity32((buf >> 13) & 0xFFF) & 1) << 25;

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
        ConstructEM410xEmulBuf(ReversQuads(currentCard));
        SimulateTagLowFrequencyEx(buflen, 0, 1, bruteforceSpeed[bruteforceSpeedCurrent] * 10000);

        int button_pressed = BUTTON_CLICKED(1000);
        if (button_pressed == BUTTON_SINGLE_CLICK) {
            Dbprintf("[=] >>  Exit bruteforce mode without saving. <<");
            return LF_RWSB_BRUTE_STOPED;
        } else if (button_pressed == BUTTON_DOUBLE_CLICK) {
            FlashLEDs(100, 10);
            Dbprintf("[=] >>  Saving bruteforced card to current slot  <<");
            low[slot] = currentCard;
#ifdef WITH_FLASH
            SaveIDtoFlash(slot, low[slot]);
#endif
            return LF_RWSB_BRUTE_SAVED;
        } else if (button_pressed == BUTTON_HOLD) {
            FlashLEDs(100, 1);
            WAIT_BUTTON_RELEASED();
            bruteforceSpeedCurrent = (bruteforceSpeedCurrent + 1) % speed_count;
            FlashLEDs(100, bruteforceSpeedCurrent + 1);
            Dbprintf("[=] >>  Setting speed to %d (%d) <<", bruteforceSpeedCurrent, bruteforceSpeed[bruteforceSpeedCurrent]);
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
            lf_em410x_watch(1, &high[slot], &low[slot]);
            LED_Update(mode, slot);
            Dbprintf("[=] >>  Tag found. Saving. <<");
            FlashLEDs(100, 5);
            PrintFcAndCardNum(low[slot]);
#ifdef WITH_FLASH
            SaveIDtoFlash(slot, low[slot]);
#endif
            return LF_RWSB_UNKNOWN_RESULT;
        case LF_RWSB_MODE_SIM:
            Dbprintf("[=] >>  Sim mode started  <<");
            ConstructEM410xEmulBuf(ReversQuads(low[slot]));
            SimulateTagLowFrequency(buflen, 0, 1);
            return LF_RWSB_UNKNOWN_RESULT;
        case LF_RWSB_MODE_WRITE:
            Dbprintf("[!!] >>  Write mode started  <<");
            copy_em410x_to_t55xx(LF_RWSB_T55XX_TYPE, LF_CLOCK, (uint32_t)(low[slot] >> 32), (uint32_t)(low[slot] & 0xffffffff));
            return LF_RWSB_UNKNOWN_RESULT;
        case LF_RWSB_MODE_BRUTE:
            Dbprintf("[=] >>  Bruteforce mode started  <<");
            return BruteEMTag(low[slot], slot);
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

    bba = BigBuf_get_addr();
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
