//-----------------------------------------------------------------------------
// Iceman,
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Idteck tag commands
// PSK
//-----------------------------------------------------------------------------
#include "cmdlfidteck.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "common.h"
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "lfdemod.h"
#include "commonutil.h"     // num_to_bytes
#include "cliparser.h"
#include "cmdlfem4x05.h"  // EM defines

static int CmdHelp(const char *Cmd);

int demodIdteck(bool verbose) {
    (void) verbose; // unused so far
    if (PSKDemod(0, 0, 100, false) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Idteck PSKDemod failed");
        return PM3_ESOFT;
    }
    size_t size = DemodBufferLen;

    //get binary from PSK1 wave
    int idx = detectIdteck(DemodBuffer, &size);
    if (idx < 0) {

        if (idx == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Idteck: not enough samples");
        else if (idx == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Idteck: just noise");
        else if (idx == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Idteck: preamble not found");
        else if (idx == -4)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Idteck: size not correct: %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - Idteck: idx: %d", idx);

        // if didn't find preamble try again inverting
        if (PSKDemod(0, 1, 100, false) != PM3_SUCCESS) {
            PrintAndLogEx(DEBUG, "DEBUG: Error - Idteck PSKDemod failed");
            return PM3_ESOFT;
        }
        idx = detectIdteck(DemodBuffer, &size);
        if (idx < 0) {

            if (idx == -1)
                PrintAndLogEx(DEBUG, "DEBUG: Error - Idteck: not enough samples");
            else if (idx == -2)
                PrintAndLogEx(DEBUG, "DEBUG: Error - Idteck: just noise");
            else if (idx == -3)
                PrintAndLogEx(DEBUG, "DEBUG: Error - Idteck: preamble not found");
            else if (idx == -4)
                PrintAndLogEx(DEBUG, "DEBUG: Error - Idteck: size not correct: %zu", size);
            else
                PrintAndLogEx(DEBUG, "DEBUG: Error - Idteck: idx: %d", idx);

            return PM3_ESOFT;
        }
    }
    setDemodBuff(DemodBuffer, 64, idx);

    //got a good demod
    uint32_t id = 0;
    uint32_t raw1 = bytebits_to_byte(DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(DemodBuffer + 32, 32);

    //parity check (TBD)
    //checksum check (TBD)

    //output
    PrintAndLogEx(SUCCESS, "IDTECK Tag Found: Card ID %u ,  Raw: %08X%08X", id, raw1, raw2);
    return PM3_SUCCESS;
}

static int CmdIdteckDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf idteck demod",
                  "Try to find Idteck preamble, if found decode / descramble data",
                  "lf idteck demod"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return demodIdteck(true);
}

static int CmdIdteckReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf idteck reader",
                  "read a Idteck tag",
                  "lf idteck reader -@   -> continuous reader mode"
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
        lf_read(false, 5000);
        demodIdteck(!cm);
    } while (cm && !kbd_enter_pressed());

    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,         AlwaysAvailable, "This help"},
    {"demod",   CmdIdteckDemod,  AlwaysAvailable, "Demodulate an Idteck tag from the GraphBuffer"},
    {"reader",  CmdIdteckReader, IfPm3Lf,         "Attempt to read and Extract tag data from the antenna"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFIdteck(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// Find IDTEC PSK1, RF  Preamble == 0x4944544B, Demodsize 64bits
// by iceman
int detectIdteck(uint8_t *dest, size_t *size) {
    //make sure buffer has data
    if (*size < 64 * 2) return -1;

    if (getSignalProperties()->isnoise) return -2;

    size_t start_idx = 0;
    uint8_t preamble[] = {0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1};

    //preamble not found
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &start_idx))
        return -3;

    // wrong demoded size
    if (*size != 64) return -4;
    return (int)start_idx;
}
