//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Paradox tag commands
// FSK2a, rf/50, 96 bits (completely known)
//-----------------------------------------------------------------------------
#include "cmdlfparadox.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "commonutil.h"     // ARRAYLEN
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "graph.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "lfdemod.h"
#include "protocols.h"  // t55xx defines
#include "cmdlft55xx.h" // clone..

static int CmdHelp(const char *Cmd);

static int usage_lf_paradox_clone(void) {
    PrintAndLogEx(NORMAL, "clone a Paradox tag to a T55x7 tag.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage: lf paradox clone [h] [b <raw hex>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h               : this help");
    PrintAndLogEx(NORMAL, "  b <raw hex>     : raw hex data. 12 bytes max");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf paradox clone 0f55555695596a6a9999a59a");
    return PM3_SUCCESS;
}

/*
static int usage_lf_paradox_sim(void) {
    PrintAndLogEx(NORMAL, "Enables simulation of Paradox card with specified card number.");
    PrintAndLogEx(NORMAL, "Simulation runs until the button is pressed or another USB command is issued.");
    PrintAndLogEx(NORMAL, "The facility-code is 8-bit and the card number is 16-bit.  Larger values are truncated.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf paradox sim [h] <Facility-Code> <Card-Number>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h               : this help");
    PrintAndLogEx(NORMAL, "  <Facility-Code> :  8-bit value facility code");
    PrintAndLogEx(NORMAL, "  <Card Number>   : 16-bit value card number");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf paradox sim 123 11223");
    return PM3_SUCCESS;
}
*/

//by marshmellow
//Paradox Prox demod - FSK2a RF/50 with preamble of 00001111 (then manchester encoded)
//print full Paradox Prox ID and some bit format details if found
static int CmdParadoxDemod(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    //raw fsk demod no manchester decoding no start bit finding just get binary from wave
    uint8_t bits[MAX_GRAPH_TRACE_LEN] = {0};
    size_t size = getFromGraphBuf(bits);
    if (size == 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Paradox not enough samples");
        return PM3_ESOFT;
    }

    uint32_t hi2 = 0, hi = 0, lo = 0;
    int waveIdx = 0;
    //get binary from fsk wave
    int idx = detectParadox(bits, &size, &hi2, &hi, &lo, &waveIdx);
    if (idx < 0) {

        if (idx == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Paradox not enough samples");
        else if (idx == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Paradox just noise detected");
        else if (idx == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Paradox problem during FSK demod");
        else if (idx == -4)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Paradox preamble not found");
        else if (idx == -5)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Paradox error in Manchester data, size %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - Paradox error demoding fsk %d", idx);

        return PM3_ESOFT;
    }

    setDemodBuff(bits, size, idx);
    setClockGrid(50, waveIdx + (idx * 50));

    if (hi2 == 0 && hi == 0 && lo == 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Paradox no value found");
        return PM3_ESOFT;
    }

    uint32_t fc = ((hi & 0x3) << 6) | (lo >> 26);
    uint32_t cardnum = (lo >> 10) & 0xFFFF;
    uint32_t rawLo = bytebits_to_byte(bits + idx + 64, 32);
    uint32_t rawHi = bytebits_to_byte(bits + idx + 32, 32);
    uint32_t rawHi2 = bytebits_to_byte(bits + idx, 32);

    PrintAndLogEx(NORMAL, "Paradox TAG ID: %x%08x - FC: %d - Card: %d - Checksum: %02x - RAW: %08x%08x%08x",
                  hi >> 10,
                  (hi & 0x3) << 26 | (lo >> 10),
                  fc, cardnum,
                  (lo >> 2) & 0xFF,
                  rawHi2,
                  rawHi,
                  rawLo
                 );

    PrintAndLogEx(DEBUG, "DEBUG: Paradox idx: %d, len: %zu, Printing Demod Buffer:", idx, size);
    if (g_debugMode)
        printDemodBuff();

    return PM3_SUCCESS;
}
//by marshmellow
//see ASKDemod for what args are accepted
static int CmdParadoxRead(const char *Cmd) {
    lf_read(false, 10000);
    return CmdParadoxDemod(Cmd);
}

static int CmdParadoxClone(const char *Cmd) {

    uint32_t blocks[4];
    bool errors = false;
    uint8_t cmdp = 0;
    int datalen = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_paradox_clone();
            case 'b': {
                // skip first block,  3*4 =12 bytes left
                uint8_t rawhex[12] = {0};
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

    if (errors || cmdp == 0) return usage_lf_paradox_clone();

    //Securakey - compat mode, ASK/Man, data rate 40, 3 data blocks
    blocks[0] = T55x7_MODULATION_FSK2a | T55x7_BITRATE_RF_50 | 3 << T55x7_MAXBLOCK_SHIFT;

    PrintAndLogEx(INFO, "Preparing to clone Paradox to T55x7 with raw hex");
    print_blocks(blocks,  ARRAYLEN(blocks));

    return clone_t55xx_tag(blocks, ARRAYLEN(blocks));
}

static int CmdParadoxSim(const char *Cmd) {
    PrintAndLogEx(INFO, " To be implemented, feel free to contribute!");
    return PM3_SUCCESS;
}
/*
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || cmdp == 'h') return usage_lf_paradox_sim();

    uint32_t facilitycode = 0, cardnumber = 0, fc = 0, cn = 0;

    uint8_t bs[96];
    memset(bs, 0x00, sizeof(bs));

    // Paradox uses:  fcHigh: 10, fcLow: 8, clk: 50, invert: 1  FSK2a
    uint8_t clk = 50, invert = 1, high = 10, low = 8;

    if (sscanf(Cmd, "%u %u", &fc, &cn) != 2) return usage_lf_paradox_sim();

    facilitycode = (fc & 0x000000FF);
    cardnumber = (cn & 0x0000FFFF);

    // if ( GetParadoxBits(facilitycode, cardnumber, bs) != PM3_SUCCESS) {
    // PrintAndLogEx(ERR, "Error with tag bitstream generation.");
    // return 1;
    // }

    PrintAndLogEx(NORMAL, "Simulating Paradox - Facility Code: %u, CardNumber: %u", facilitycode, cardnumber);

    lf_fsksim_t *payload = calloc(1, sizeof(lf_fsksim_t) + sizeof(bs));
    payload->fchigh = high;
    payload->fclow =  low;
    payload->separator = invert;
    payload->clock = clk;
    memcpy(payload->data, bs, sizeof(bs));

    clearCommandBuffer();
    SendCommandNG(CMD_LF_FSK_SIMULATE, (uint8_t *)payload,  sizeof(lf_fsksim_t) + sizeof(bs));
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_LF_FSK_SIMULATE, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;
    return PM3_SUCCESS;
}
*/
static command_t CommandTable[] = {
    {"help",  CmdHelp,          AlwaysAvailable, "This help"},
    {"demod", CmdParadoxDemod,  AlwaysAvailable, "Demodulate a Paradox FSK tag from the GraphBuffer"},
    {"read",  CmdParadoxRead,   IfPm3Lf,         "Attempt to read and Extract tag data from the antenna"},
    {"clone", CmdParadoxClone,  IfPm3Lf,         "clone paradox tag to T55x7"},
    {"sim",   CmdParadoxSim,    IfPm3Lf,         "simulate paradox tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFParadox(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// loop to get raw paradox waveform then FSK demodulate the TAG ID from it
int detectParadox(uint8_t *dest, size_t *size, uint32_t *hi2, uint32_t *hi, uint32_t *lo, int *waveStartIdx) {
    //make sure buffer has data
    if (*size < 96 * 50) return -1;

    if (getSignalProperties()->isnoise) return -2;

    // FSK demodulator
    *size = fskdemod(dest, *size, 50, 1, 10, 8, waveStartIdx); // paradox fsk2a

    //did we get a good demod?
    if (*size < 96) return -3;

    // 00001111 bit pattern represent start of frame, 01 pattern represents a 0 and 10 represents a 1
    size_t startIdx = 0;
    uint8_t preamble[] = {0, 0, 0, 0, 1, 1, 1, 1};
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx))
        return -4; //preamble not found

    size_t numStart = startIdx + sizeof(preamble);
    // final loop, go over previously decoded FSK data and manchester decode into usable tag ID
    for (size_t idx = numStart; (idx - numStart) < *size - sizeof(preamble); idx += 2) {
        if (dest[idx] == dest[idx + 1])
            return -5; //not manchester data

        *hi2 = (*hi2 << 1) | (*hi >> 31);
        *hi = (*hi << 1) | (*lo >> 31);
        //Then, shift in a 0 or one into low
        *lo <<= 1;
        if (dest[idx] && !dest[idx + 1]) // 1 0
            *lo |= 1;
        else // 0 1
            *lo |= 0;
    }
    return (int)startIdx;
}

int demodParadox(void) {
    return CmdParadoxDemod("");
}

