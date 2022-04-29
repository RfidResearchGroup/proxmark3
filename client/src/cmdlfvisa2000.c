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
// Low frequency visa 2000 tag commands
// by iceman
// ASK/Manchester, RF/64, STT, 96 bits (complete)
//-----------------------------------------------------------------------------

#include "cmdlfvisa2000.h"
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
#include "cmdlfem4x05.h"   //
#include "cliparser.h"

#ifndef VISA2k_BL0CK1
#define VISA2k_BL0CK1 0x56495332
#endif

static int CmdHelp(const char *Cmd);

static uint8_t visa_chksum(uint32_t id) {
    uint8_t sum = 0;
    for (uint8_t i = 0; i < 32; i += 4)
        sum ^= (id >> i) & 0xF;
    return sum & 0xF;
}

static uint8_t visa_parity(uint32_t id) {
    // 4bit parity LUT
    const uint8_t par_lut[] = {
        0, 1, 1, 0, 1, 0, 0, 1,
        1, 0, 0, 1, 0, 1, 1, 0
    };

    uint8_t par = 0;
    par |= par_lut[(id >> 28) & 0xF ] << 7;
    par |= par_lut[(id >> 24) & 0xF ] << 6;
    par |= par_lut[(id >> 20) & 0xF ] << 5;
    par |= par_lut[(id >> 16) & 0xF ] << 4;
    par |= par_lut[(id >> 12) & 0xF ] << 3;
    par |= par_lut[(id >>  8) & 0xF ] << 2;
    par |= par_lut[(id >>  4) & 0xF ] << 1;
    par |= par_lut[(id & 0xF) ];
    return par;
}

/**
*
* 56495332 00096ebd 00000077 —> tag id 618173
* aaaaaaaa iiiiiiii -----ppc
*
* a = fixed value  ascii 'VIS2'
* i = card id
* p = even parity bit for each nibble in card id.
* c = checksum  (xor of card id)
*
**/
//see ASKDemod for what args are accepted
int demodVisa2k(bool verbose) {
    (void) verbose; // unused so far
    save_restoreGB(GRAPH_SAVE);

    //CmdAskEdgeDetect("");

    //ASK / Manchester
    bool st = true;
    if (ASKDemod_ext(64, 0, 0, 0, false, false, false, 1, &st) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Visa2k: ASK/Manchester Demod failed");
        save_restoreGB(GRAPH_RESTORE);
        return PM3_ESOFT;
    }
    size_t size = g_DemodBufferLen;
    int ans = detectVisa2k(g_DemodBuffer, &size);
    if (ans < 0) {
        if (ans == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Visa2k: too few bits found");
        else if (ans == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Visa2k: preamble not found");
        else if (ans == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Visa2k: Size not correct: %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - Visa2k: ans: %d", ans);

        save_restoreGB(GRAPH_RESTORE);
        return PM3_ESOFT;
    }
    setDemodBuff(g_DemodBuffer, 96, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));

    //got a good demod
    uint32_t raw1 = bytebits_to_byte(g_DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(g_DemodBuffer + 32, 32);
    uint32_t raw3 = bytebits_to_byte(g_DemodBuffer + 64, 32);

    // chksum
    uint8_t calc = visa_chksum(raw2);
    uint8_t chk = raw3 & 0xF;

    // test checksums
    if (chk != calc) {
        PrintAndLogEx(DEBUG, "DEBUG: error: Visa2000 checksum (%s) %x - %x\n", _RED_("fail"), chk, calc);
        save_restoreGB(GRAPH_RESTORE);
        return PM3_ESOFT;
    }
    // parity
    uint8_t calc_par = visa_parity(raw2);
    uint8_t chk_par = (raw3 & 0xFF0) >> 4;
    if (calc_par != chk_par) {
        PrintAndLogEx(DEBUG, "DEBUG: error: Visa2000 parity (%s) %x - %x\n", _RED_("fail"), chk_par, calc_par);
        save_restoreGB(GRAPH_RESTORE);
        return PM3_ESOFT;
    }
    PrintAndLogEx(SUCCESS, "Visa2000 - Card " _GREEN_("%u") ", Raw: %08X%08X%08X", raw2,  raw1, raw2, raw3);
    return PM3_SUCCESS;
}

static int CmdVisa2kDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf visa2000 demod",
                  "Try to find visa2000 preamble, if found decode / descramble data",
                  "lf visa2000 demod"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return demodVisa2k(true);
}

// 64*96*2=12288 samples just in case we just missed the first preamble we can still catch 2 of them
static int CmdVisa2kReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf visa2000 reader",
                  "read a visa2000 tag",
                  "lf visa2000 reader -@   -> continuous reader mode"
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
        lf_read(false, 20000);
        demodVisa2k(!cm);
    } while (cm && !kbd_enter_pressed());
    return PM3_SUCCESS;
}

static int CmdVisa2kClone(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf visa2000 clone",
                  "clone a Visa2000 tag to a T55x7, Q5/T5555 or EM4305/4469 tag.",
                  "lf visa2000 clone --cn 112233           -> encode for T55x7 tag\n"
                  "lf visa2000 clone --cn 112233 --q5      -> encode for Q5/T5555 tag\n"
                  "lf visa2000 clone --cn 112233 --em      -> encode for EM4305/4469"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_1(NULL, "cn", "<dec>", "Visa2k card ID"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint32_t id = arg_get_u32_def(ctx, 1, 0);
    bool q5 = arg_get_lit(ctx, 2);
    bool em = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }

    uint32_t blocks[4] = {T55x7_MODULATION_MANCHESTER | T55x7_BITRATE_RF_64 | T55x7_ST_TERMINATOR | 3 << T55x7_MAXBLOCK_SHIFT, VISA2k_BL0CK1, 0};
    char cardtype[16] = {"T55x7"};
    // Q5
    if (q5) {
        blocks[0] = T5555_FIXED | T5555_MODULATION_MANCHESTER | T5555_SET_BITRATE(64) | T5555_ST_TERMINATOR | 3 << T5555_MAXBLOCK_SHIFT;
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    }

    // EM4305
    if (em) {
        blocks[0] = EM4305_VISA2000_CONFIG_BLOCK;
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
    }

    blocks[2] = id;
    blocks[3] = (visa_parity(id) << 4) | visa_chksum(id);

    PrintAndLogEx(INFO, "Preparing to clone Visa2000 to " _YELLOW_("%s") " with CardId: " _GREEN_("%"PRIu32), cardtype, id);
    print_blocks(blocks,  ARRAYLEN(blocks));

    int res;
    if (em) {
        res = em4x05_clone_tag(blocks, ARRAYLEN(blocks), 0, false);
    } else {
        res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    }
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf visa2000 reader`") " to verify");
    return res;
}

static int CmdVisa2kSim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf visa2000 sim",
                  "Enables simulation of visa2k card with specified card number.\n"
                  "Simulation runs until the button is pressed or another USB command is issued.\n",
                  "lf visa2000 sim --cn 1337"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_1(NULL, "cn", "<dec>", "Visa2k card ID"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    uint32_t id = arg_get_u32_def(ctx, 1, 0);
    CLIParserFree(ctx);

    PrintAndLogEx(SUCCESS, "Simulating Visa2000 - CardId:" _YELLOW_("%u"), id);

    uint32_t blocks[3] = { VISA2k_BL0CK1, id, (visa_parity(id) << 4) | visa_chksum(id) };

    uint8_t bs[96];
    for (int i = 0; i < 3; ++i)
        num_to_bytebits(blocks[i], 32, bs + i * 32);

    lf_asksim_t *payload = calloc(1, sizeof(lf_asksim_t) + sizeof(bs));
    payload->encoding =  1;
    payload->invert = 0;
    payload->separator = 1;
    payload->clock = 64;
    memcpy(payload->data, bs, sizeof(bs));

    clearCommandBuffer();
    SendCommandNG(CMD_LF_ASK_SIMULATE, (uint8_t *)payload,  sizeof(lf_asksim_t) + sizeof(bs));
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_LF_ASK_SIMULATE, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,         AlwaysAvailable, "This help"},
    {"demod",   CmdVisa2kDemod,  AlwaysAvailable, "demodulate an VISA2000 tag from the GraphBuffer"},
    {"reader",  CmdVisa2kReader, IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone",   CmdVisa2kClone,  IfPm3Lf,         "clone Visa2000 tag to T55x7 or Q5/T5555"},
    {"sim",     CmdVisa2kSim,    IfPm3Lf,         "simulate Visa2000 tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFVisa2k(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// by iceman
// find Visa2000 preamble in already demoded data
int detectVisa2k(uint8_t *dest, size_t *size) {
    if (*size < 96) return -1; //make sure buffer has data
    size_t startIdx = 0;
    uint8_t preamble[] = {0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0};
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx))
        return -2; //preamble not found
    if (*size != 96) return -3; //wrong demoded size
    //return start position
    return (int)startIdx;
}


