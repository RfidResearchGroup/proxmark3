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
// Low frequency Idteck tag commands
// PSK1,  clk 32,  2 data blocks
//-----------------------------------------------------------------------------
#include "cmdlfidteck.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "common.h"
#include "cmdparser.h"   // command_t
#include "comms.h"
#include "ui.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "lfdemod.h"
#include "commonutil.h"  // num_to_bytes
#include "cliparser.h"
#include "cmdlfem4x05.h" // EM defines
#include "protocols.h"   // T55x7 defines
#include "cmdlft55xx.h"  // verifywrite

static int CmdHelp(const char *Cmd);

int demodIdteck(bool verbose) {
    (void) verbose; // unused so far
    if (PSKDemod(0, 0, 100, false) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Idteck PSKDemod failed");
        return PM3_ESOFT;
    }
    size_t size = g_DemodBufferLen;

    //get binary from PSK1 wave
    int idx = detectIdteck(g_DemodBuffer, &size);
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
        idx = detectIdteck(g_DemodBuffer, &size);
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
    setDemodBuff(g_DemodBuffer, 64, idx);

    //got a good demod
    uint32_t id = 0;
    uint32_t raw1 = bytebits_to_byte(g_DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(g_DemodBuffer + 32, 32);

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

static int CmdIdteckClone(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf idteck clone",
                  "clone a Idteck tag to T55x7 or Q5/T5555 tag\n"
                  "Tag must be on the antenna when issuing this command.",
                  "lf idteck clone --raw 4944544B351FBE4B"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str1("r", "raw", "<hex>", "raw bytes"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    uint8_t raw[8] = {0};
    CLIGetHexWithReturn(ctx, 1, raw, &raw_len);

    bool q5 = arg_get_lit(ctx, 2);
    bool em = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }

    uint32_t blocks[3] = {T55x7_MODULATION_PSK1 | T55x7_BITRATE_RF_32 | 2 << T55x7_MAXBLOCK_SHIFT, 0, 0};
    char cardtype[16] = {"T55x7"};

    // Q5
    if (q5) {
        blocks[0] = T5555_FIXED | T55x7_MODULATION_PSK1 |  T5555_SET_BITRATE(32) | 2 << T5555_MAXBLOCK_SHIFT;
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    }

    if (em) {
        blocks[0] = EM4305_IDTECK_CONFIG_BLOCK;
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
    }

    for (uint8_t i = 1; i < ARRAYLEN(blocks); i++) {
        blocks[i] = bytes_to_num(raw + ((i - 1) * 4), sizeof(uint32_t));
    }

    // config for Indala 64 format (RF/32;PSK1 with RF/2;Maxblock=2)
    PrintAndLogEx(INFO, "Preparing to clone Idteck to " _YELLOW_("%s") " raw " _GREEN_("%s")
                  , cardtype
                  , sprint_hex_inrow(raw, raw_len)
                 );
    print_blocks(blocks,  ARRAYLEN(blocks));

    int res;
    if (em) {
        res = em4x05_clone_tag(blocks, ARRAYLEN(blocks), 0, false);
    } else {
        res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    }
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf idteck reader`") " to verify");
    return res;
}

static int CmdIdteckSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf idteck sim",
                  "Enables simulation of Idteck card.\n"
                  "Simulation runs until the button is pressed or another USB command is issued.",
                  "lf idteck sim --raw 4944544B351FBE4B"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("r", "raw", "<hex>", "raw bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    uint8_t raw[8] = {0};
    CLIGetHexWithReturn(ctx, 1, raw, &raw_len);
    CLIParserFree(ctx);

    // convert to binarray
    uint8_t bs[64];
    memset(bs, 0x00, sizeof(bs));

    uint8_t counter = 0;
    for (int32_t i = 0; i < raw_len; i++) {
        uint8_t tmp = raw[i];
        bs[counter++] = (tmp >> 7) & 1;
        bs[counter++] = (tmp >> 6) & 1;
        bs[counter++] = (tmp >> 5) & 1;
        bs[counter++] = (tmp >> 4) & 1;
        bs[counter++] = (tmp >> 3) & 1;
        bs[counter++] = (tmp >> 2) & 1;
        bs[counter++] = (tmp >> 1) & 1;
        bs[counter++] = tmp & 1;
    }

    PrintAndLogEx(SUCCESS, "Simulating Idteck - raw " _YELLOW_("%s"), sprint_hex_inrow(raw, raw_len));
    PrintAndLogEx(SUCCESS, "Press pm3-button to abort simulation or run another command");
    PrintAndLogEx(NORMAL, "");

    lf_psksim_t *payload = calloc(1, sizeof(lf_psksim_t) + sizeof(bs));
    payload->carrier = 2;
    payload->invert = 0;
    payload->clock = 32;
    memcpy(payload->data, bs, sizeof(bs));

    clearCommandBuffer();
    SendCommandNG(CMD_LF_PSK_SIMULATE, (uint8_t *)payload,  sizeof(lf_psksim_t) + sizeof(bs));
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_LF_PSK_SIMULATE, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;
    return PM3_SUCCESS;
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
    {"demod",   CmdIdteckDemod,  AlwaysAvailable, "demodulate an Idteck tag from the GraphBuffer"},
    {"reader",  CmdIdteckReader, IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone",   CmdIdteckClone,  IfPm3Lf,         "clone Idteck tag to T55x7 or Q5/T5555"},
    {"sim",     CmdIdteckSim,    IfPm3Lf,         "simulate Idteck tag"},
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
int detectIdteck(uint8_t *dest, size_t *size) {
    //make sure buffer has data
    if (*size < 64 * 2) return -1;

    if (getSignalProperties()->isnoise) return -2;

    size_t start_idx = 0;
    //                    4           9           4           4           5           4           4           B
    uint8_t preamble[] = {0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1};

    //preamble not found
    if (preambleSearch(dest, preamble, sizeof(preamble), size, &start_idx) == false)
        return -3;

    // wrong demoded size
    if (*size != 64) {
        return -4;
    }
    return (int)start_idx;
}
