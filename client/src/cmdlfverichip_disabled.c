//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// Low frequency Verichip tag commands
//NRZ, RF/32, 128 bits long
//-----------------------------------------------------------------------------
#include "cmdlfverichip.h"

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

static int usage_lf_verichip_clone(void) {
    PrintAndLogEx(NORMAL, "clone a verichip tag to a T55x7 tag.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage: lf verichip clone [h] [b <raw hex>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h               : this help");
    PrintAndLogEx(NORMAL, "  b <raw hex>     : raw hex data. 12 bytes max");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("       lf verichip clone b FF2049906D8511C593155B56D5B2649F "));
    return PM3_SUCCESS;
}

//see NRZDemod for what args are accepted
int demodVerichip(bool verbose) {
    (void) verbose; // unused so far
    //NRZ
    if (NRZrawDemod(0, 0, 100, false) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - VERICHIP: NRZ Demod failed");
        return PM3_ESOFT;
    }
    size_t size = g_DemodBufferLen;
    int ans = detectVerichip(g_DemodBuffer, &size);
    if (ans < 0) {
        if (ans == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - VERICHIP: too few bits found");
        else if (ans == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - VERICHIP: preamble not found");
        else if (ans == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - VERICHIP: Size not correct: %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - VERICHIP: ans: %d", ans);

        return PM3_ESOFT;
    }
    setDemodBuff(g_DemodBuffer, 128, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));

    //got a good demod
    uint32_t raw1 = bytebits_to_byte(g_DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(g_DemodBuffer + 32, 32);
    uint32_t raw3 = bytebits_to_byte(g_DemodBuffer + 64, 32);
    uint32_t raw4 = bytebits_to_byte(g_DemodBuffer + 96, 32);

    // preamble     then appears to have marker bits of "10"                                                                                                                                       CS?
    // 11111111001000000 10 01001100 10 00001101 10 00001101 10 00001101 10 00001101 10 00001101 10 00001101 10 00001101 10 00001101 10 10001100 10 100000001
    // unknown checksum 9 bits at the end

    PrintAndLogEx(SUCCESS, "VERICHIP - Raw: %08X%08X%08X%08X", raw1, raw2, raw3, raw4);
    PrintAndLogEx(INFO, "How the Raw ID is translated by the reader is unknown. Share your trace file on forum");
    return PM3_SUCCESS;
}

static int CmdVerichipDemod(const char *Cmd) {
    (void)Cmd;
    return demodVerichip(true);
}

static int CmdVerichipRead(const char *Cmd) {
    (void)Cmd;
    lf_read(false, 4096 * 2 + 20);
    return demodVerichip(true);
}

static int CmdVerichipClone(const char *Cmd) {

    uint32_t blocks[5];
    bool errors = false;
    uint8_t cmdp = 0;
    int datalen = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_verichip_clone();
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

    if (errors || cmdp == 0) return usage_lf_verichip_clone();

    //Pac - compat mode, NRZ, data rate 40, 3 data blocks
    blocks[0] = T55x7_MODULATION_DIRECT | T55x7_BITRATE_RF_40 | 4 << T55x7_MAXBLOCK_SHIFT;

    PrintAndLogEx(INFO, "Preparing to clone Verichip to T55x7 with raw hex");
    print_blocks(blocks,  ARRAYLEN(blocks));

    int res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf verichip read`") " to verify");
    return res;
}

static int CmdVerichipSim(const char *Cmd) {

    // NRZ sim.
    PrintAndLogEx(INFO, " To be implemented, feel free to contribute!");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",  CmdHelp,           AlwaysAvailable, "This help"},
    {"demod", CmdVerichipDemod,  AlwaysAvailable, "demodulate an VERICHIP tag from the GraphBuffer"},
    {"read",  CmdVerichipRead,   IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone", CmdVerichipClone,  IfPm3Lf,         "clone VERICHIP tag"},
    {"sim",   CmdVerichipSim,    IfPm3Lf,         "simulate VERICHIP tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFVerichip(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// find VERICHIP preamble in already demoded data
int detectVerichip(uint8_t *dest, size_t *size) {
    if (*size < 128) return -1; //make sure buffer has data
    size_t startIdx = 0;
    uint8_t preamble[] = {1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0};
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx))
        return -2; //preamble not found
    if (*size < 128) return -3; //wrong demoded size
    //return start position
    return (int)startIdx;
}

