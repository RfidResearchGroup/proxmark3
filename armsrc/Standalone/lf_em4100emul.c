//-----------------------------------------------------------------------------
// Artyom Gnatyuk, 2020
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
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

#define MAX_IND 16 // 4 LEDs - 2^4 combinations
#define CLOCK 64 //for 125kHz

// low & high - array for storage IDs. Its length must be equal.
// Predefined IDs must be stored in low[].
// In high[] must be nulls
uint64_t low[] = {0x565A1140BE, 0x365A398149, 0x5555555555, 0xFFFFFFFFFF};
uint32_t high[] = {0, 0, 0, 0};
uint8_t *bba, slots_count;
int buflen;

void ModInfo(void) {
    DbpString("  LF EM4100 simulator standalone mode");
}

uint64_t ReversQuads(uint64_t bits) {
    uint64_t result = 0;
    for (int i = 0; i < 16; i++) {
        result += ((bits >> (60 - 4 * i)) & 0xf) << (4 * i);
    }
    return result >> 24;
}

void FillBuff(uint8_t bit) {
    memset(bba + buflen, bit, CLOCK / 2);
    buflen += (CLOCK / 2);
    memset(bba + buflen, bit ^ 1, CLOCK / 2);
    buflen += (CLOCK / 2);
}

void ConstructEM410xEmulBuf(uint64_t id) {

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

void LED_Slot(int i) {
    LEDsoff();
    if (slots_count > 4) {
        LED(i % MAX_IND, 0); //binary indication for slots_count > 4
    } else {
        LED(1 << i, 0); //simple indication for slots_count <=4
    }
}

void RunMod() {
    StandAloneMode();
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    Dbprintf("[=] >>  LF EM4100 simulator started  <<");

    int selected = 0; //selected slot after start
    slots_count = ARRAYLEN(low);
    bba = BigBuf_get_addr();
    for (;;) {
        WDT_HIT();
        if (data_available()) break;
        SpinDelay(100);
        SpinUp(100);
        LED_Slot(selected);
        ConstructEM410xEmulBuf(ReversQuads(low[selected]));
        SimulateTagLowFrequency(buflen, 0, true);
        selected = (selected + 1) % slots_count;
    }
}
