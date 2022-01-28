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
// Low frequency ZX8211 tag commands
//-----------------------------------------------------------------------------

#include "cmdlfzx8211.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>
#include "commonutil.h"    // ARRAYLEN
#include "common.h"
#include "cmdparser.h"     // command_t
#include "comms.h"
#include "ui.h"
#include "graph.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "protocols.h"     // for T55xx config register definitions
#include "lfdemod.h"       // parityTest
#include "cmdlft55xx.h"    // write verify
#include "cliparser.h"
#include "zx8211.h"

static int CmdHelp(const char *Cmd);

// see ASKDemod for what args are accepted
int demodzx(bool verbose) {
    (void) verbose; // unused so far
    save_restoreGB(GRAPH_SAVE);

    // CmdAskEdgeDetect("");

    // ASK / Manchester
    bool st = true;
    if (ASKDemod_ext(64, 0, 0, 0, false, false, false, 1, &st) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - ZX: ASK/Manchester Demod failed");
        save_restoreGB(GRAPH_RESTORE);
        return PM3_ESOFT;
    }
    size_t size = g_DemodBufferLen;
    int ans = detectzx(g_DemodBuffer, &size);
    if (ans < 0) {
        if (ans == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - ZX: too few bits found");
        else if (ans == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - ZX: preamble not found");
        else if (ans == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - ZX: Size not correct: %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - ZX: ans: %d", ans);

        save_restoreGB(GRAPH_RESTORE);
        return PM3_ESOFT;
    }
    setDemodBuff(g_DemodBuffer, 96, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));

    // got a good demod
    uint32_t raw1 = bytebits_to_byte(g_DemodBuffer, 32);

    // chksum

    // test checksums

    PrintAndLogEx(SUCCESS, "ZX8211 - Card " _GREEN_("%u"), raw1);
    return PM3_SUCCESS;
}

static int lf_Zx_read(void) {

    PacketResponseNG resp;
    clearCommandBuffer();

    SendCommandNG(CMD_LF_ZX_READ, NULL, 0);

    if (WaitForResponseTimeout(CMD_LF_ZX_READ, &resp, 1000) == false) {
        PrintAndLogEx(ERR, "Error occurred, device did not respond during read operation.");
        return PM3_ETIMEOUT;
    }

    return PM3_SUCCESS;
}

static int CmdZxDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf zx demod",
                  "Try to find zx8211 preamble, if found decode / descramble data",
                  "lf zx demod"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return demodzx(true);
}

static int CmdzxReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf zx reader",
                  "read a zx tag",
                  "lf zx reader -@   -> continuous reader mode"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("@", NULL, "optional - continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool cm = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    do {
        lf_Zx_read();
        demodzx(!cm);
    } while (cm && !kbd_enter_pressed());
    return PM3_SUCCESS;
}


static command_t CommandTable[] = {
    {"help",    CmdHelp,         AlwaysAvailable, "This help"},
    {"demod",   CmdZxDemod,      AlwaysAvailable, "demodulate an ZX 8211 tag from the GraphBuffer"},
    {"reader",  CmdzxReader,     IfPm3Lf,         "attempt to read and extract tag data"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFZx8211(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int detectzx(uint8_t *dest, size_t *size) {
    if (*size < 96) return -1; // make sure buffer has data
    size_t startIdx = 0;
    uint8_t preamble[] = {0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0};
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx))
        return -2; // preamble not found
    if (*size != 96) return -3; // wrong demoded size
    // return start position
    return (int)startIdx;
}


