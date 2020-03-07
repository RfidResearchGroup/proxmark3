//-----------------------------------------------------------------------------
// Artyom Gnatyuk, 2020
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// LF emul V3 - This mode can simulate ID from selected slot, read ID to 
//              selected slot, write from selected slot to T5555 tag and store 
//              readed ID to flash (only RDV4). Also you can set predefined IDs
//              in any slot. 
//              To recall stored ID from flash execute:
//                  mem dump o offset l 5 p
//              where offset = 5 * selected slot
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

#ifdef WITH_FLASH
#include "flashmem.h"
#endif

#define MAX_IND 16 // 4 LEDs - 2^4 combinations
#define CLOCK 64 //for 125kHz

// low & high - array for storage IDs. Its length must be equal.
// Predefined IDs must be stored in low[]. 
// In high[] must be nulls
uint64_t low[] = {0x565AF781C7,0x540053E4E2,0x1234567890,0,0,0,0,0,0,0,0,0,0,0,0,0};
uint32_t high[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
uint8_t *bba,slots_count;
int buflen;

void ModInfo(void) {
    DbpString("  LF EM4100 simulate standalone V2");
}

uint64_t ReversQuads(uint64_t bits){
  uint64_t result = 0;
  for (int i = 0; i < 16; i++){
    result += ((bits >> (60 - 4 *i)) & 0xf) << (4 * i);
      }
  return result >> 24;
}

void FillBuff(uint8_t bit) {
    memset (bba + buflen, bit, CLOCK / 2);
	buflen += (CLOCK / 2);
	memset (bba + buflen, bit^1,CLOCK / 2);
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
	if (slots_count > 4) {
		LED(i % MAX_IND, 0); //binary indication, usefully for slots_count > 4
	} else {
		LED(1 << i,0); //simple indication for slots_count <=4
	}
}

void FlashLEDs(uint32_t speed, uint8_t times) {
    for (int i = 0; i < times * 2; i++) {
        LED_A_INV();
        LED_B_INV();
        LED_C_INV();
        LED_D_INV();
        SpinDelay(speed);
    }
}

#ifdef WITH_FLASH
void SaveIDtoFlash (int addr, uint64_t id) {
	uint8_t b, *ptr;
	for (int i = 0; i < 5; i++) {
		b = (uint8_t) (id >>  8 * i & 0xff);
		ptr = &b;
		Flash_WriteData(addr * 5 + 4 - i,ptr,1);
	}
}
#endif

void RunMod() {
    StandAloneMode();
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
	int selected = 0;
	//state 0 - select slot
	//      1 - read tag to selected slot, 
	//      2 - simulate tag from selected slot
	//      3 - write to T5555 tag
	uint8_t state = 0; 
	slots_count = sizeof(low)/sizeof(low[0]);
	bba = BigBuf_get_addr();
	LED_Slot(selected);
	for (;;) {		
		WDT_HIT();
        if (data_available()) break;
		int button_pressed = BUTTON_HELD(1000);
		SpinDelay(300);
		switch (state){
			case 0:
				// Select mode
				if (button_pressed == 1) {
					// Long press - switch to simulate mode
					SpinUp(100);
					SpinOff(100);
					LED_Slot(selected);
					state = 2;
				} else if (button_pressed < 0) {
					// Click - switch to next slot
					selected = (selected + 1) % slots_count;
					LEDsoff();
					LED_Slot(selected);
				} 
			break;
			case 1:
				// Read mode.
				if (button_pressed > 0) {
					// Long press - switch to read mode
					SpinUp(100);
					SpinOff(10);
					LED_Slot(selected);
					state = 3;
				} else if (button_pressed < 0) {
					// Click - exit to select mode
					CmdEM410xdemod(1, &high[selected], &low[selected], 0);
					FlashLEDs(100,5);
					#ifdef WITH_FLASH
					SaveIDtoFlash(selected, low[selected]);
					#endif
					state = 0;
				}
			break;
			case 2:
				// Simulate mode
				if (button_pressed > 0) {
					// Long press - switch to read mode
					SpinDown(100);
					SpinOff(10);
					LED_Slot(selected);
					state = 1;
				} else if (button_pressed < 0) {
					// Click - start simulating. Click again to exit from simelate mode
					LED_Slot(selected);
					ConstructEM410xEmulBuf(ReversQuads(low[selected]));
					FlashLEDs(100,5);
					SimulateTagLowFrequency(buflen, 0, 1);
					LED_Slot(selected);
					state = 0; // Switch to select mode
				}
			break;
			case 3:
				// Write tag mode
				if (button_pressed > 0) {
					// Long press - switch to select mode
					SpinDown(100);
					SpinOff(10);
					LED_Slot(selected);
					state = 0;
				} else if (button_pressed < 0) {
					// Click - write ID to tag
					WriteEM410x(0, (uint32_t) (low[selected] >> 32), (uint32_t) (low[selected] & 0xffffffff));
					LED_Slot(selected);
					state = 0; // Switch to select mode
				}
			break;
		}
	}
}
