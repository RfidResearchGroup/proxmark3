//-----------------------------------------------------------------------------
// Copyright by Łukasz Jurczyk, 2021-2022
//
// This code is licensed to you under the terms of the GNU GPL, version 3.
// See the LICENSE.txt file for the text of the license.
//-----------------------------------------------------------------------------
// LF rsww   -  This mode can read EM4100 tag, save it to flash (RDV4 only), emulate it, clone it to T55xx tag, validate the write and wipe T55xx tag.
//
//              To recall stored ID from flash execute:
//                  mem spiffs dump -s lf
//              then from shell:
//                  hexdump lf.bin -e '5/1 "%02X" /0 "\n"'
//
//              To recall only LAST stored ID from flash use lf-last instead of lf file.
//
//-----------------------------------------------------------------------------
// Modes of operation:
//
// --- Read ---
// Proxmark reads an EM4100 tag. LED A is turned on. When the tag is detected, it is saved to flash (RDV4 only) and proxmark enters the emulation mode.
// It's the default mode for non-RDV4 devices, and if no previous read is present in the flash it's the default mode for RDV4 devices.
// Pressing the button exists reading mode and enters emulation mode (only if any read is present in the memory).
// Double pressing the button enters wiping mode.
//
// --- Emulate ---
// Proxmark emulates last read tag. LED B is turned on.
// It's the default mode for RDV4 if lf-last file is present on the flash.
// Pressing the button enters writing mode and clones the emulated tag.
// Double pressing the button enters the validation mode.
// Holding the button enters the reading mode.
//
// --- Write ---
// Proxmarks writes the last read tag. LEDs A and B are turned on.
// When writing is complete LEDs A and B blink three times and proxmark enters the emulation mode.
//
// --- Validate ---
// Proxmark reads an EM4100 tag. LED C is turned on.
// If tag matches the last saved tag, LED C blinks three times. If it doesn't all LEDs blink three times. Proxmark enters the emulation mode afterwards.
// The result of the read is DISCARDED.
// Pressing the button enters the emulation mode.
//
// --- Wipe ---
// Proxmark continously wipes all approached T55xx tags. LED D is turned on, LEDs A-C are blinking.
// Pressing the button enters the default mode (reading or emulation).
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
char *filename = "lf";
char *filenameLast = "lf-last";
#endif

#define LF_CLOCK 64 // for 125kHz
#define LF_RWSB_T55XX_TYPE 1 // Tag type: 0 - T5555, 1-T55x7

static uint64_t low = 0;
static uint64_t low2 = 0;
static uint32_t high = 0;
static uint32_t high2 = 0;
static unsigned char mode = 0;
static int buflen;

void ModInfo(void) {
    DbpString("=== LF EM4100 read/sim/write/wipe/validate ===");
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
    memset(bba + buflen, bit, LF_CLOCK / 2);
    buflen += (LF_CLOCK / 2);
    memset(bba + buflen, bit ^ 1, LF_CLOCK / 2);
    buflen += (LF_CLOCK / 2);
}

static void construct_EM410x_emul(uint64_t id) {
    int i, j;
    int binary[4] = {0, 0, 0, 0};
    int parity[4] = {0, 0, 0, 0};
    buflen = 0;

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

#ifdef WITH_FLASH
static void SaveIDtoFlash(uint64_t id) {
    uint8_t bt[5];
    rdv40_spiffs_mount();
    for (int i = 0; i < 5; i++) {
        bt[4 - i] = (uint8_t)(id >> 8 * i & 0xff);
    }
    if (exists_in_spiffs(filename))
        rdv40_spiffs_append(filename, &bt[0], 5, RDV40_SPIFFS_SAFETY_NORMAL);
    else
        rdv40_spiffs_write(filename, &bt[0], 5, RDV40_SPIFFS_SAFETY_NORMAL);

    if (exists_in_spiffs(filenameLast))
        rdv40_spiffs_remove(filenameLast, RDV40_SPIFFS_SAFETY_NORMAL);

    rdv40_spiffs_write(filenameLast, &bt[0], 5, RDV40_SPIFFS_SAFETY_NORMAL);
}

static bool ReadFlash(void) {
    if (exists_in_spiffs(filenameLast) == false)
        return false;

    uint8_t bt[5];
    if (rdv40_spiffs_read(filenameLast, (uint8_t *) &bt, 5, RDV40_SPIFFS_SAFETY_NORMAL) < 0)
        return false;

    low = bt[0];
    low <<= 32;
    low |= (bt[1] << 24) | (bt[2] << 16) | (bt[3] << 8) | bt[4];
    low2 = low;
    high = 0;
    high2 = 0;
    return true;
}
#endif

static void Wipe(void) {
    DbpString("Wipe mode");
    LEDsoff();

    for (;;) {
        LED_A_ON();
        LED_B_ON();
        LED_C_ON();
        LED_D_ON();
        copy_em410x_to_t55xx(LF_RWSB_T55XX_TYPE, LF_CLOCK, (uint32_t) 0, (uint32_t) 0, false);
        SpinDelay(60);
        LEDsoff();
        LED_D_ON();

        int b = BUTTON_HELD(100);
        if (b != BUTTON_NO_CLICK || data_available())
            return;

        SpinDelay(100);

        b = BUTTON_HELD(100);
        if (b != BUTTON_NO_CLICK || data_available())
            return;
    }
}

static void Read(void) {
    mode = 0;

    while (low2 == 0 || mode == 0) {
        DbpString("Read");
        LEDsoff();
        LED_A_ON();

        low2 = 0;
        high2 = 0;
        lf_em410x_watch(1, &high2, &low2, false);

        if (low2 != 0) {
            LED_B_ON();
            low = low2;
            high = high2;
            mode = 1;

#ifdef WITH_FLASH
            SaveIDtoFlash(low2);
#endif

            SpinDelay(50);
            LED_C_ON();
            SpinDelay(50);
            LED_D_ON();
            SpinDelay(50);
            LEDsoff();
            return;
        }

        if (data_available())
            return;

        int b = BUTTON_CLICKED(1000);

        if ((b == BUTTON_SINGLE_CLICK || b == BUTTON_HOLD) && low != 0) {
            mode = 1;
            return;
        }

        if (b == BUTTON_DOUBLE_CLICK) {
            Wipe();

            if (low != 0) {
                mode = 1;
                return;
            }
        }
    }
}

static void Validate(void) {
    DbpString("Validate");
    LEDsoff();
    LED_C_ON();

    for (;;) {
        low2 = 0;
        high2 = 0;

        lf_em410x_watch(1, &high2, &low2, false);

        if (low == low2 && high == high2) {
            LED_C_OFF();
            SpinDelay(150);
            for (int i = 0; i < 3; i++) {
                LED_C_ON();
                SpinDelay(150);
                LED_C_OFF();
                SpinDelay(150);
            }

            return;
        } else if (low2 != 0 || high2 != 0) {
            LEDsoff();
            for (int i = 0; i < 3; i++) {
                LED_A_ON();
                LED_B_ON();
                LED_C_ON();
                LED_D_ON();
                SpinDelay(250);
                LEDsoff();
                SpinDelay(150);
            }

            return;
        } else
            SpinDelay(200);

        int b = BUTTON_HELD(200);
        if (b != BUTTON_NO_CLICK || data_available())
            return;
    }
}

static void Write(void) {
    DbpString("Write");
    LED_A_ON();
    LED_B_ON();
    copy_em410x_to_t55xx(LF_RWSB_T55XX_TYPE, LF_CLOCK, (uint32_t)(low >> 32), (uint32_t)(low & 0xffffffff), false);
    SpinDelay(75);
    LEDsoff();

    for (int i = 0; i < 3; i++) {
        LED_A_ON();
        LED_B_ON();
        SpinDelay(75);
        LED_A_OFF();
        LED_B_OFF();
        SpinDelay(75);
    }
}

static void Emulate(void) {
    DbpString("Emulate");
    LEDsoff();

    for (;;) {
        int bx = BUTTON_HELD(50);
        if (bx == BUTTON_NO_CLICK)
            break;
        SpinDelay(50);
    }

    LED_B_ON();
    construct_EM410x_emul(rev_quads(low));
    SimulateTagLowFrequencyEx(buflen, 0, false, -1);

    int b = BUTTON_CLICKED(800);

    if (b == BUTTON_NO_CLICK)
        return;

    for (;;) {
        int bx = BUTTON_HELD(50);
        if (bx == BUTTON_NO_CLICK)
            break;
        SpinDelay(50);
    }

    if (b == BUTTON_SINGLE_CLICK)
        Write();
    else if (b == BUTTON_HOLD)
        mode = 0;
    else if (b == BUTTON_DOUBLE_CLICK)
        Validate();
}

void RunMod() {
    StandAloneMode();
    LEDsoff();
    LED_D_ON();
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    WDT_HIT();

#ifdef WITH_FLASH
    if (ReadFlash())
        mode = 1;
    else Read();
#else
    Read();
#endif

    for (;;) {
        WDT_HIT();
        LEDsoff();

        if (data_available()) return;

        if (mode == 0)
            Read();
        else Emulate();
    }
}
