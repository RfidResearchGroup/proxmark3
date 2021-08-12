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
 * Data is read from bin dump file uploaded to flash memory (hf_mfcsim_dump_xx.bin).
 * Only support mifare classic 1k
 *
 * To upload input file (eml format) to flash:
 * - mem spiffs upload -s <filename> -d hf_mfcsim_dump_xx.bin (Notes: xx is form 01 to 15)
 * To delete the input file from flash:
 * - mem spiffs remove -f hf_mfcsim_dump_xx.bin (Notes: xx is form 01 to 15)
 * 
 */

#define HF_MFCSIM_DUMPFILE_SIM         "hf_mfcsim_dump_%02d.bin"
#define DUMP_SIZE                       1024

static char cur_dump_file[22] = {0};

static bool ecfill_from_file(char *dumpfile) {

    if (exists_in_spiffs(dumpfile)) {
        //check dumpfile size
        uint32_t size = size_in_spiffs(dumpfile);
        if (size != DUMP_SIZE) {
            Dbprintf(_RED_("File Size: %dB  The dump file size is incorrect! Only support Mifare Classic 1K! Please check it."));
            BigBuf_free();
            return false;
        }

        uint8_t *mem = BigBuf_malloc(size);
        if (!mem) {
            Dbprintf(_RED_("No memory!"));
            return false;
        }

        //read and load dump file
        if (DBGLEVEL >= DBG_INFO) Dbprintf(_YELLOW_("Found dump file %s. Uploading to emulator memory..."), dumpfile);
        rdv40_spiffs_read_as_filetype(dumpfile, mem, size, RDV40_SPIFFS_SAFETY_SAFE);
        emlClearMem();
        emlSetMem(mem, 0, MIFARE_1K_MAXBLOCK);
        BigBuf_free_keep_EM();
        return true;
    } else {
        Dbprintf(_RED_("Dump file %s not found!"), dumpfile);
        return false;
    }
    return false;//Shouldn't be here
}

void ModInfo(void) {
    DbpString(_YELLOW_("  HF Mifare Classic simulation mode") " - a.k.a MFCSIM");
}

void RunMod(void) {
    //initializing
    StandAloneMode();
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    rdv40_spiffs_lazy_mount();
    Dbprintf(_YELLOW_("Standalone mode MFCSIM started!"));

    bool flag_has_dumpfile = false;
    for (int i = 1;; i++) {
        if (i > 15) {
            if (flag_has_dumpfile) i = 1; //Next loop!
            else break;//No dump,Exit!
        }
        LED(i, 1000);
        emlClearMem();

        sprintf(cur_dump_file, HF_MFCSIM_DUMPFILE_SIM, i);
        Dbprintf(_YELLOW_("[Slot: %d] Try to load dump file: %s"), i, cur_dump_file);
        if (!ecfill_from_file(cur_dump_file)) {
            Dbprintf(_YELLOW_("[Slot: %d] Dump load Failed, Next one!"), i);
            continue;
        }
        flag_has_dumpfile = true;

        Dbprintf(_YELLOW_("[Slot: %d] Simulation start, Press button to change next card."), i);
        uint16_t simflags = FLAG_UID_IN_EMUL | FLAG_MF_1K;
        Mifare1ksim(simflags, 0, NULL, 0, 0);
        Dbprintf(_YELLOW_("[Slot: %d] Simulation end, Change to next card!"), i);
    }
    Dbprintf("No dump file found, Exit!");
    return;
}




