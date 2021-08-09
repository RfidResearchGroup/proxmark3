//-----------------------------------------------------------------------------
// Ray Lee, 2021
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// main code for mifare classic simulator aka MFCSIM
//-----------------------------------------------------------------------------
#include <inttypes.h>
#include "ticks.h"
#include "proxmark3_arm.h"
#include "BigBuf.h"
#include "commonutil.h"
#include "fpgaloader.h"
#include "util.h"
#include "dbprint.h"
#include "spiffs.h"
#include "standalone.h" // standalone definitions
#include "appmain.h"
#include "string.h"
#include "iso14443a.h"
#include "mifarecmd.h"
#include "crc16.h"
#include "mifaresim.h"  // mifare1ksim
#include "mifareutil.h"

/*
 * `hf_mfcsim` simulates mifare classic 1k dumps uploaded to flash.
 * It requires RDV4 hardware (for flash and battery).
 *
 * On entering stand-alone mode, this module will start simulating.
 * Data is read from bin dump file uploaded to flash memory (hf_mfcsim_dump.bin).
 * Only support mifare classic 1k
 *
 * LEDs:
 * - LED A: initializing
 * - LED B: simulating
 * - LED C blinking: data transmiting
 *
 * To upload input file (eml format) to flash:
 * - mem spiffs upload -s <filename> -d hf_mfcsim_dump.bin
 * To delete the input file from flash:
 * - mem spiffs remove -f hf_mfcsim_dump.bin
 *
 */

#define HF_MFCSIM_INPUTFILE_SIM         "hf_mfcsim_dump.bin"
#define DUMP_SIZE                       1024

static uint8_t uid[10];

static bool ecfill_from_file(char *inputfile) {

    if (exists_in_spiffs(inputfile)) {
        uint32_t size = size_in_spiffs(inputfile);
        uint8_t *mem = BigBuf_malloc(size);
        if (!mem) {
            Dbprintf(_RED_("No memory！"));
            return false;
        }

        //read dumpfile
        Dbprintf(_YELLOW_("Found dump file %s"), inputfile);
        rdv40_spiffs_read_as_filetype(inputfile, mem, size, RDV40_SPIFFS_SAFETY_SAFE);

        //check dumpfile size
        Dbprintf(_YELLOW_("File size is %d"), size);
        if (size != DUMP_SIZE) {
            Dbprintf(_RED_("Only support Mifare Classic 1K! Please check the dumpfile"));
            BigBuf_free();
            return false;
        }

        //load the dump into emulator memory
        Dbprintf(_YELLOW_("Read card data from input file"));
        emlSetMem(mem, 0, MIFARE_1K_MAXBLOCK);
        Dbprintf(_YELLOW_("Uploaded to emulator memory"));
        BigBuf_free_keep_EM();
        return true;
    } else {
        Dbprintf(_RED_("no input file %s"), inputfile);
        return false;
    }
    return false;//Shouldn't be here
}

void ModInfo(void) {
    DbpString(_YELLOW_("  HF Mifare Classic simulation mode") " - a.k.a MFCSIM");
}

void RunMod(void) {
    StandAloneMode();
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    Dbprintf(_YELLOW_("Standalone mode MFCSIM started!"));

    LED_A_ON();
    emlClearMem();
    Dbprintf(_YELLOW_("Emulator memory initialized"));
    rdv40_spiffs_lazy_mount();
    if (!ecfill_from_file(HF_MFCSIM_INPUTFILE_SIM)) {
        Dbprintf(_RED_("Load data failed!"));
        return;
    }
    Dbprintf(_YELLOW_("Emulator memory filled, simulation ready to start."));
    Dbprintf(_YELLOW_("Press button to abort simulation at anytime."));

    SpinOff(1000);

    LED_B_ON();
    Dbprintf(_YELLOW_("Simulation start!"));
    uint16_t simflags = FLAG_UID_IN_EMUL | FLAG_MF_1K;
    Mifare1ksim(simflags, 0, uid, 0, 0);

    Dbprintf(_YELLOW_("Simulation end!"));
    LEDsoff();
}




