//-----------------------------------------------------------------------------
// Iceman, 2019
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency GALLAGHER tag commands
// NRZ, RF/32, 128 bits long (unknown cs)
//-----------------------------------------------------------------------------
#include "cmdlfgallagher.h"

#include <ctype.h>          //tolower

#include "commonutil.h"     // ARRAYLEN
#include "common.h"
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "lfdemod.h"    // preamble test
#include "protocols.h"  // t55xx defines
#include "cmdlft55xx.h" // clone..

static int CmdHelp(const char *Cmd);

static int usage_lf_gallagher_clone(void) {
    PrintAndLogEx(NORMAL, "clone a GALLAGHER tag to a T55x7 tag.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage: lf gallagher clone [h] [b <raw hex>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h               : this help");
    PrintAndLogEx(NORMAL, "  b <raw hex>     : raw hex data. 12 bytes max");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf gallagher clone b 0FFD5461A9DA1346B2D1AC32 ");
    return PM3_SUCCESS;
}

//see ASK/MAN Demod for what args are accepted
static int CmdGallagherDemod(const char *Cmd) {

    (void)Cmd;
    bool st = true;
    if (ASKDemod_ext("32 0 0 0", false, false, 1, &st) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - GALLAGHER: ASKDemod failed");
        return PM3_ESOFT;
    }

    size_t size = DemodBufferLen;
    int ans = detectGallagher(DemodBuffer, &size);
    if (ans < 0) {
        if (ans == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - GALLAGHER: too few bits found");
        else if (ans == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - GALLAGHER: preamble not found");
        else if (ans == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - GALLAGHER: Size not correct: %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - GALLAGHER: ans: %d", ans);

        return PM3_ESOFT;
    }
    setDemodBuff(DemodBuffer, 96, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));

    //got a good demod
    uint32_t raw1 = bytebits_to_byte(DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(DemodBuffer + 32, 32);
    uint32_t raw3 = bytebits_to_byte(DemodBuffer + 64, 32);

    // preamble                                                                                                                                       CS?

    PrintAndLogEx(SUCCESS, "GALLAGHER Tag Found -- Raw: %08X%08X%08X", raw1, raw2, raw3);
    PrintAndLogEx(INFO, "How the Raw ID is translated by the reader is unknown. Share your trace file on forum");
    return PM3_SUCCESS;
}

static int CmdGallagherRead(const char *Cmd) {
    lf_read(true, 4096 * 2 + 20);
    return CmdGallagherDemod(Cmd);
}

static int CmdGallagherClone(const char *Cmd) {

    uint32_t blocks[4];
    bool errors = false;
    uint8_t cmdp = 0;
    int datalen = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_gallagher_clone();
            case 'b': {
                // skip first block,  3*4 = 12 bytes left
                uint8_t rawhex[12] = {0};
                int res = param_gethex_to_eol(Cmd, cmdp + 1, rawhex, sizeof(rawhex), &datalen);
                if ( res != 0 )
                    errors = true;

                for(uint8_t i = 1; i < ARRAYLEN(blocks); i++) {
                    blocks[i] = bytes_to_num(rawhex + ( (i - 1) * 4 ), sizeof(uint32_t));
                }
                cmdp += 2;
                break;
            }
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors || cmdp == 0) return usage_lf_gallagher_clone();

    //Pac - compat mode, NRZ, data rate 40, 3 data blocks
    blocks[0] = T55x7_MODULATION_MANCHESTER | T55x7_BITRATE_RF_32 | 3 << T55x7_MAXBLOCK_SHIFT;

    PrintAndLogEx(INFO, "Preparing to clone Gallagher to T55x7 with raw hex");
    print_blocks(blocks,  ARRAYLEN(blocks));

    return clone_t55xx_tag(blocks, ARRAYLEN(blocks));
}

static int CmdGallagherSim(const char *Cmd) {

    // ASK/MAN sim.
    PrintAndLogEx(INFO, " To be implemented, feel free to contribute!");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",  CmdHelp,            AlwaysAvailable, "This help"},
    {"demod", CmdGallagherDemod,  AlwaysAvailable, "Demodulate an GALLAGHER tag from the GraphBuffer"},
    {"read",  CmdGallagherRead,   IfPm3Lf,         "Attempt to read and extract tag data from the antenna"},
    {"clone", CmdGallagherClone,  IfPm3Lf,         "clone GALLAGHER tag"},
    {"sim",   CmdGallagherSim,    IfPm3Lf,         "simulate GALLAGHER tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFGallagher(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// by marshmellow
// find PAC preamble in already demoded data
int detectGallagher(uint8_t *dest, size_t *size) {
    if (*size < 96) return -1; //make sure buffer has data
    size_t startIdx = 0;
    uint8_t preamble[] = {
          0, 0, 0, 0, 1, 1, 1, 1,
          1, 1, 1, 1, 1, 1, 0, 1,
          0, 1, 0, 1, 0, 1, 0, 0,
          0, 1, 1, 0, 0 ,0 ,0 ,1
    };
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx))
        return -2; //preamble not found
    if (*size != 96) return -3; //wrong demoded size
    //return start position
    return (int)startIdx;
}

int demodGallagher(void) {
    return CmdGallagherDemod("");
}

