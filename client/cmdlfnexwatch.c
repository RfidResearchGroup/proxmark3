//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Honeywell NexWatch tag commands
// PSK1 RF/16, RF/2, 128 bits long (known)
//-----------------------------------------------------------------------------

#include "cmdlfnexwatch.h"
#include <inttypes.h>       // PRIu
#include <ctype.h>          // tolower

#include "commonutil.h"     // ARRAYLEN
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "cmddata.h" // preamblesearch
#include "cmdlf.h"
#include "lfdemod.h"
#include "protocols.h"  // t55xx defines
#include "cmdlft55xx.h" // clone..

static int CmdHelp(const char *Cmd);

static int usage_lf_nexwatch_clone(void) {
    PrintAndLogEx(NORMAL, "clone a Nexwatch tag to a T55x7 tag.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage: lf nexwatch clone [h] [b <raw hex>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h               : this help");
    PrintAndLogEx(NORMAL, "  b <raw hex>     : raw hex data. 12 bytes max");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf nexwatch clone b 5600000000213C9F8F150C0000000000");
    return PM3_SUCCESS;
}

static int CmdNexWatchDemod(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far

    if (PSKDemod("", false) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch can't demod signal");
        return PM3_ESOFT;
    }
    bool invert = false;
    size_t size = DemodBufferLen;
    int idx = detectNexWatch(DemodBuffer, &size, &invert);
    if (idx <= 0) {
        if (idx == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch not enough samples");
        // else if (idx == -2)
        // PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch only noise found");
        // else if (idx == -3)
        // PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch problem during PSK demod");
        else if (idx == -4)
            PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch preamble not found");
        // else if (idx == -5)
        // PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch size not correct: %d", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch error %d", idx);

        return PM3_ESOFT;
    }

    setDemodBuff(DemodBuffer, size, idx + 4);
    setClockGrid(g_DemodClock, g_DemodStartIdx + ((idx + 4) * g_DemodClock));

//    idx = 8 + 32; // 8 = preamble, 32 = reserved bits (always 0)

    //get ID
    uint32_t ID = 0;
    for (uint8_t k = 0; k < 4; k++) {
        for (uint8_t m = 0; m < 8; m++) {
            ID = (ID << 1) | DemodBuffer[m + k + (m * 4)];
        }
    }
    //parity check (TBD)

    //checksum check (TBD)

    //output
    PrintAndLogEx(SUCCESS, "NexWatch ID: " _YELLOW_("%"PRIu32), ID);
    if (invert) {
        PrintAndLogEx(INFO, "Had to Invert - probably NexKey");
        for (size_t i = 0; i < size; i++)
            DemodBuffer[i] ^= 1;
    }

    CmdPrintDemodBuff("x");
    return PM3_SUCCESS;
}

//by marshmellow
//see ASKDemod for what args are accepted
static int CmdNexWatchRead(const char *Cmd) {
    lf_read(false, 10000);
    return CmdNexWatchDemod(Cmd);
}

static int CmdNexWatchClone(const char *Cmd) {

    // 56000000 00213C9F 8F150C00 00000000
    uint32_t blocks[5];
    bool errors = false;
    uint8_t cmdp = 0;
    int datalen = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_nexwatch_clone();
            case 'b': {
                // skip first block,  4*4 = 16 bytes left
                uint8_t rawhex[16] = {0};
                int res = param_gethex_to_eol(Cmd, cmdp + 1, rawhex, sizeof(rawhex), &datalen);
                if (res != 0)
                    errors = true;

                for (uint8_t i = 1; i < ARRAYLEN(blocks); i++) {
                    blocks[i] = bytes_to_num(rawhex + ((i - 1) * 4), sizeof(uint32_t));
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

    if (errors || cmdp == 0) return usage_lf_nexwatch_clone();

    //Nexwatch - compat mode, PSK, data rate 40, 3 data blocks
    blocks[0] = T55x7_MODULATION_PSK1 | T55x7_BITRATE_RF_32 | 4 << T55x7_MAXBLOCK_SHIFT;

    PrintAndLogEx(INFO, "Preparing to clone NexWatch to T55x7 with raw hex");
    print_blocks(blocks,  ARRAYLEN(blocks));

    return clone_t55xx_tag(blocks, ARRAYLEN(blocks));

}

static int CmdNexWatchSim(const char *Cmd) {
    PrintAndLogEx(INFO, " To be implemented, feel free to contribute!");
    return PM3_SUCCESS;
}


static command_t CommandTable[] = {
    {"help",  CmdHelp,           AlwaysAvailable, "This help"},
    {"demod", CmdNexWatchDemod,  AlwaysAvailable, "Demodulate a NexWatch tag (nexkey, quadrakey) from the GraphBuffer"},
    {"read",  CmdNexWatchRead,   IfPm3Lf,         "Attempt to Read and Extract tag data from the antenna"},
    {"clone", CmdNexWatchClone,  IfPm3Lf,         "clone NexWatch tag to T55x7"},
    {"sim",   CmdNexWatchSim,    IfPm3Lf,         "simulate NexWatch tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFNEXWATCH(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int detectNexWatch(uint8_t *dest, size_t *size, bool *invert) {

    uint8_t preamble[28]   = {0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    // sanity check.
    if (*size < sizeof(preamble) + 100) return -1;

    size_t startIdx = 0;

    if (!preambleSearch(DemodBuffer, preamble, sizeof(preamble), size, &startIdx)) {
        // if didn't find preamble try again inverting
        uint8_t preamble_i[28] = {1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
        if (!preambleSearch(DemodBuffer, preamble_i, sizeof(preamble_i), size, &startIdx)) return -4;
        *invert ^= 1;
    }

    // size tests?
    return (int) startIdx;
}

int demodNexWatch(void) {
    return CmdNexWatchDemod("");
}

