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
// Low frequency FDX-A FECAVA Destron tag commands
//-----------------------------------------------------------------------------
#include "cmdlfdestron.h"
#include <ctype.h>        // tolower
#include <string.h>       // memcpy
#include "commonutil.h"   // ARRAYLEN
#include "common.h"
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "lfdemod.h"      // preamble test
#include "protocols.h"    // t55xx defines
#include "cmdlft55xx.h"   // clone..
#include "cmdlf.h"        // cmdlfconfig
#include "parity.h"
#include "cliparser.h"    // cli parse input
#include "cmdlfem4x05.h"  // EM defines

#define DESTRON_FRAME_SIZE 96
#define DESTRON_PREAMBLE_SIZE 16

static int CmdHelp(const char *Cmd);

int demodDestron(bool verbose) {
    (void) verbose; // unused so far
    //PSK1
    if (FSKrawDemod(0, 0, 0, 0, false) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Destron: FSK Demod failed");
        return PM3_ESOFT;
    }

    size_t size = g_DemodBufferLen;
    int ans = detectDestron(g_DemodBuffer, &size);
    if (ans < 0) {
        if (ans == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Destron: too few bits found");
        else if (ans == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Destron: preamble not found");
        else if (ans == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Destron: Size not correct: %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - Destron: ans: %d", ans);

        return PM3_ESOFT;
    }

    setDemodBuff(g_DemodBuffer, DESTRON_FRAME_SIZE, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));

    uint8_t bits[DESTRON_FRAME_SIZE - DESTRON_PREAMBLE_SIZE] = {0};
    size_t bitlen = DESTRON_FRAME_SIZE - DESTRON_PREAMBLE_SIZE;
    memcpy(bits, g_DemodBuffer + DESTRON_PREAMBLE_SIZE, DESTRON_FRAME_SIZE - DESTRON_PREAMBLE_SIZE);

    uint8_t alignPos = 0;
    uint16_t errCnt = manrawdecode(bits, &bitlen, 0, &alignPos);
    if (errCnt > 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Destron: Manchester decoding errors: %d", ans);
        return PM3_ESOFT;
    }

    uint8_t data[5] = {0};
    uint8_t parity_err = 0;
    for (int i = 0; i < sizeof(data); i++) {
        data[i] = bytebits_to_byte(bits + i * 8, 8);
        parity_err += oddparity8(data[i]);
        data[i] &= 0x7F;
    }
    if (parity_err > 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Destron: parity errors: %d", parity_err);
        return PM3_ESOFT;
    }
    PrintAndLogEx(SUCCESS, "FDX-A FECAVA Destron: " _GREEN_("%s"), sprint_hex_inrow(data, 5));
    return PM3_SUCCESS;
}

static int CmdDestronDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf destron demod",
                  "Try to find Destron preamble, if found decode / descramble data",
                  "lf destron demod"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return demodDestron(true);
}

static int CmdDestronReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf destron reader",
                  "read a Destron tag",
                  "lf destron reader -@   -> continuous reader mode"
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
        lf_read(false, 16000);
        demodDestron(!cm);
    } while (cm && !kbd_enter_pressed());

    return PM3_SUCCESS;
}

static int CmdDestronClone(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf destron clone",
                  "clone a Destron tag to a T55x7, Q5/T5555 or EM4305/4469 tag.",
                  "lf destron clone --uid 1A2B3C4D5E\n"
                  "lf destron clone --q5  --uid 1A2B3C4D5E   -> encode for Q5/T5555 tag\n"
                  "lf destron clone --em  --uid 1A2B3C4D5E   -> encode for EM4305/4469"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("u", "uid", "<hex>", "5 bytes max"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_param_end
    };

    //TODO add selection of chip for Q5 or T55x7
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t data[8];
    int datalen = 0;
    CLIGetHexWithReturn(ctx, 1, data, &datalen);
    bool q5 = arg_get_lit(ctx, 2);
    bool em = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }

    if (datalen > 5) {
        PrintAndLogEx(FAILED, "Uid is max 5 bytes. (got %u)", datalen);
        return PM3_EINVARG;
    }

    uint32_t blocks[4] = {0};
    blocks[0] = T55x7_BITRATE_RF_50 | T55x7_MODULATION_FSK2 | 3 << T55x7_MAXBLOCK_SHIFT;
    char cardtype[16] = {"T55x7"};
    // Q5
    if (q5) {
        blocks[0] = T5555_FIXED | T5555_MODULATION_FSK2  | T5555_SET_BITRATE(50) | 3 << T5555_MAXBLOCK_SHIFT;
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    }

    // EM4305
    if (em) {
        PrintAndLogEx(WARNING, "Beware some EM4305 tags don't support FSK and datarate = RF/50, check your tag copy!");
        blocks[0] = EM4305_DESTRON_CONFIG_BLOCK;
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
    }

    uint8_t data_ex[12 + 24] = {0}; // ManchesterEncode need extra room
    for (int i = 0; i < datalen; i++) {
        data_ex[i + 1] = ~(data [i] | (oddparity8(data[i]) << 7));
    }

    // manchester encode it
    for (int i = 0; i < 3; i++) {
        blocks[i + 1] = manchesterEncode2Bytes((data_ex[i * 2] << 8) + data_ex[i * 2 + 1]);
    }
    // inject preamble
    blocks[1] = (blocks[1] & 0xFFFF) | 0xAAE20000;

    PrintAndLogEx(INFO, "Preparing to clone Destron tag to " _YELLOW_("%s") " with ID: " _YELLOW_("%s")
                  , cardtype
                  , sprint_hex_inrow(data, datalen)
                 );


    print_blocks(blocks, ARRAYLEN(blocks));
    int res;
    if (em) {
        res = em4x05_clone_tag(blocks, ARRAYLEN(blocks), 0, false);
    } else {
        res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    }
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf destron reader`") " to verify");
    return res;
}

static int CmdDestronSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf destron sim",
                  "Try to find Destron preamble, if found decode / descramble data",
                  "lf destron sim"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    PrintAndLogEx(INFO, " To be implemented, feel free to contribute!");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",   CmdHelp,          AlwaysAvailable, "This help"},
    {"demod",  CmdDestronDemod,  AlwaysAvailable, "demodulate an Destron tag from the GraphBuffer"},
    {"reader", CmdDestronReader, IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone",  CmdDestronClone,  IfPm3Lf,         "clone Destron tag to T55x7"},
    {"sim",    CmdDestronSim,    IfPm3Lf,         "simulate Destron tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFDestron(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// find Destron preamble in already demoded data
int detectDestron(uint8_t *dest, size_t *size) {

    //make sure buffer has data
    if (*size < 64)
        return -1;

    size_t found_size = *size;
    size_t start_idx = 0;

    uint8_t preamble[DESTRON_PREAMBLE_SIZE] =  {1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0};

    // preamble not found
    if (!preambleSearch(dest, preamble, sizeof(preamble), &found_size, &start_idx)) {
        return -2;
    }
    PrintAndLogEx(DEBUG, "DEBUG: detectDestron FSK found preamble");

    *size = found_size;
    // wrong demoded size
    if (*size != 96)
        return -3;

    return (int)start_idx;
}

int readDestronUid(void) {
    return (CmdDestronReader("") == PM3_SUCCESS);
}
