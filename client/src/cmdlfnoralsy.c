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
// Low frequency Noralsy tag commands
// ASK/Manchester, STT, RF/32, 96 bits long (some bits unknown)
//-----------------------------------------------------------------------------
#include "cmdlfnoralsy.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "commonutil.h"   // ARRAYLEN
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "protocols.h"    // for T55xx config register definitions
#include "lfdemod.h"      // parityTest
#include "cmdlft55xx.h"   // verifywrite
#include "cmdlfem4x05.h"  //
#include "cliparser.h"

static int CmdHelp(const char *Cmd);

static uint8_t noralsy_chksum(uint8_t *bits, uint8_t len) {
    uint8_t sum = 0;
    for (uint8_t i = 0; i < len; i += 4)
        sum ^= bytebits_to_byte(bits + i, 4);
    return sum & 0x0F ;
}

//see ASKDemod for what args are accepted
int demodNoralsy(bool verbose) {
    (void) verbose; // unused so far
    //ASK / Manchester
    bool st = true;
    if (ASKDemod_ext(32, 0, 0, 0, false, false, false, 1, &st) != PM3_SUCCESS) {
        if (g_debugMode) PrintAndLogEx(DEBUG, "DEBUG: Error - Noralsy: ASK/Manchester Demod failed");
        return PM3_ESOFT;
    }
    if (!st) {
        if (g_debugMode) PrintAndLogEx(DEBUG, "DEBUG: Error - Noralsy: sequence terminator not found");
        return PM3_ESOFT;
    }

    size_t size = g_DemodBufferLen;
    int ans = detectNoralsy(g_DemodBuffer, &size);
    if (ans < 0) {
        if (g_debugMode) {
            if (ans == -1)
                PrintAndLogEx(DEBUG, "DEBUG: Error - Noralsy: too few bits found");
            else if (ans == -2)
                PrintAndLogEx(DEBUG, "DEBUG: Error - Noralsy: preamble not found");
            else if (ans == -3)
                PrintAndLogEx(DEBUG, "DEBUG: Error - Noralsy: Size not correct: %zu", size);
            else
                PrintAndLogEx(DEBUG, "DEBUG: Error - Noralsy: ans: %d", ans);
        }
        return PM3_ESOFT;
    }
    setDemodBuff(g_DemodBuffer, 96, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));

    //got a good demod
    uint32_t raw1 = bytebits_to_byte(g_DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(g_DemodBuffer + 32, 32);
    uint32_t raw3 = bytebits_to_byte(g_DemodBuffer + 64, 32);

    uint32_t cardid = ((raw2 & 0xFFF00000) >> 20) << 16;
    cardid |= (raw2 & 0xFF) << 8;
    cardid |= ((raw3 & 0xFF000000) >> 24);
    cardid = BCD2DEC(cardid);

    uint16_t year = (raw2 & 0x000ff000) >> 12;
    year = BCD2DEC(year);
    year += (year > 60) ? 1900 : 2000;

    // calc checksums
    uint8_t calc1 = noralsy_chksum(g_DemodBuffer + 32, 40);
    uint8_t calc2 = noralsy_chksum(g_DemodBuffer, 76);
    uint8_t chk1 = 0, chk2 = 0;
    chk1 = bytebits_to_byte(g_DemodBuffer + 72, 4);
    chk2 = bytebits_to_byte(g_DemodBuffer + 76, 4);
    // test checksums
    if (chk1 != calc1) {
        if (g_debugMode) PrintAndLogEx(DEBUG, "DEBUG: Error - Noralsy: checksum 1 failed %x - %x\n", chk1, calc1);
        return PM3_ESOFT;
    }
    if (chk2 != calc2) {
        if (g_debugMode) PrintAndLogEx(DEBUG, "DEBUG: Error - Noralsy: checksum 2 failed %x - %x\n", chk2, calc2);
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Noralsy - Card: " _GREEN_("%u")", Year: " _GREEN_("%u") ", Raw: %08X%08X%08X", cardid, year, raw1, raw2, raw3);
    if (raw1 != 0xBB0214FF) {
        PrintAndLogEx(WARNING, "Unknown bits set in first block! Expected 0xBB0214FF, Found: 0x%08X", raw1);
        PrintAndLogEx(WARNING, "Please post this output in forum to further research on this format");
    }
    return PM3_SUCCESS;
}

static int CmdNoralsyDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf noralsy demod",
                  "Try to find Noralsy preamble, if found decode / descramble data",
                  "lf noralsy demod"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return demodNoralsy(true);
}

static int CmdNoralsyReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf noralsy reader",
                  "read a Noralsy tag",
                  "lf noralsy reader -@   -> continuous reader mode"
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
        lf_read(false, 8000);
        demodNoralsy(!cm);
    } while (cm && !kbd_enter_pressed());
    return PM3_SUCCESS;
}

static int CmdNoralsyClone(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf noralsy clone",
                  "clone a Noralsy tag to a T55x7, Q5/T5555 or EM4305/4469 tag.",
                  "lf noralsy clone --cn 112233           -> encode for T55x7 tag\n"
                  "lf noralsy clone --cn 112233 --q5      -> encode for Q5/T5555 tag\n"
                  "lf noralsy clone --cn 112233 --em      -> encode for EM4305/4469"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_1(NULL, "cn", "<dec>", "Noralsy card ID"),
        arg_u64_0("y", "year", "<dec>", "tag allocation year"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint32_t id = arg_get_u32_def(ctx, 1, 0);
    uint16_t year = arg_get_u32_def(ctx, 2, 2000);
    bool q5 = arg_get_lit(ctx, 3);
    bool em = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }

    uint32_t blocks[4] = {T55x7_MODULATION_MANCHESTER | T55x7_BITRATE_RF_32 | T55x7_ST_TERMINATOR | 3 << T55x7_MAXBLOCK_SHIFT, 0, 0};
    char cardtype[16] = {"T55x7"};
    //Q5
    if (q5) {
        blocks[0] = T5555_FIXED | T5555_MODULATION_MANCHESTER | T5555_SET_BITRATE(32) | T5555_ST_TERMINATOR | 3 << T5555_MAXBLOCK_SHIFT;
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    }

    // EM4305
    if (em) {
        blocks[0] = EM4305_NORALSY_CONFIG_BLOCK;
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
    }

    uint8_t *bits = calloc(96, sizeof(uint8_t));
    if (getnoralsyBits(id, year, bits) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Error with tag bitstream generation.");
        free(bits);
        return PM3_ESOFT;
    }

    blocks[1] = bytebits_to_byte(bits, 32);
    blocks[2] = bytebits_to_byte(bits + 32, 32);
    blocks[3] = bytebits_to_byte(bits + 64, 32);

    free(bits);

    PrintAndLogEx(INFO, "Preparing to clone Noralsy to " _YELLOW_("%s") " with Card id: " _GREEN_("%u"), cardtype, id);
    print_blocks(blocks,  ARRAYLEN(blocks));

    int res;
    if (em) {
        res = em4x05_clone_tag(blocks, ARRAYLEN(blocks), 0, false);
    } else {
        res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    }
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf noralsy reader`") " to verify");
    return res;
}

static int CmdNoralsySim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf noralsy sim",
                  "Enables simulation of Noralsy card with specified card number.\n"
                  "Simulation runs until the button is pressed or another USB command is issued.\n",
                  "lf noralsy sim --cn 1337\n"
                  "lf noralsy sim --cn 1337 --year 2010"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_1(NULL, "cn", "<dec>", "Noralsy card ID"),
        arg_u64_0("y", "year", "<dec>", "tag allocation year"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    uint32_t id = arg_get_u32_def(ctx, 1, 0);
    uint16_t year = arg_get_u32_def(ctx, 2, 2000);
    CLIParserFree(ctx);

    uint8_t bs[96];
    memset(bs, 0, sizeof(bs));

    if (getnoralsyBits(id, year, bs) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Error with tag bitstream generation.");
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Simulating Noralsy - CardId: " _YELLOW_("%u") " year " _YELLOW_("%u"), id, year);

    lf_asksim_t *payload = calloc(1, sizeof(lf_asksim_t) + sizeof(bs));
    payload->encoding = 1;
    payload->invert = 0;
    payload->separator = 1;
    payload->clock = 32;
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
    {"help",    CmdHelp,          AlwaysAvailable, "This help"},
    {"demod",   CmdNoralsyDemod,  AlwaysAvailable, "demodulate an Noralsy tag from the GraphBuffer"},
    {"reader",  CmdNoralsyReader, IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone",   CmdNoralsyClone,  IfPm3Lf,         "clone Noralsy tag to T55x7 or Q5/T5555"},
    {"sim",     CmdNoralsySim,    IfPm3Lf,         "simulate Noralsy tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFNoralsy(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int getnoralsyBits(uint32_t id, uint16_t year, uint8_t *bits) {
    //preamp
    num_to_bytebits(0xBB0214FF, 32, bits);  // --> Have seen 0xBB0214FF / 0xBB0314FF  UNKNOWN

    //convert ID into BCD-format
    id = DEC2BCD(id);
    year = DEC2BCD(year);
    year &= 0xFF;

    uint16_t sub1 = (id & 0xFFF0000) >> 16;
    uint8_t sub2 = (id & 0x000FF00) >> 8;
    uint8_t sub3 = (id & 0x00000FF);

    num_to_bytebits(sub1, 12, bits + 32);
    num_to_bytebits(year, 8, bits + 44);
    num_to_bytebits(0, 4, bits + 52); // --> UNKNOWN. Flag?

    num_to_bytebits(sub2, 8, bits + 56);
    num_to_bytebits(sub3, 8, bits + 64);

    //chksum byte
    uint8_t chksum = noralsy_chksum(bits + 32, 40);
    num_to_bytebits(chksum, 4, bits + 72);
    chksum = noralsy_chksum(bits, 76);
    num_to_bytebits(chksum, 4, bits + 76);
    return PM3_SUCCESS;
}

// find Noralsy preamble in already demoded data
int detectNoralsy(uint8_t *dest, size_t *size) {
    if (*size < 96) return -1; //make sure buffer has data
    size_t startIdx = 0;
    uint8_t preamble[] = {1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0};
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx))
        return -2; //preamble not found
    if (*size != 96) return -3; //wrong demoded size
    //return start position
    return (int)startIdx;
}
/*
*
* 2520116 | BB0214FF2529900116360000 | 10111011 00000011 00010100 11111111 00100101 00101001 10010000 00000001 00010110 00110110 00000000 00000000
*           aaa*aaaaiiiYY*iiiicc----                ****                   iiiiiiii iiiiYYYY YYYY**** iiiiiiii iiiiiiii cccccccc
*
* a = fixed value BB0*14FF
* i = printed id, BCD-format
* Y = year
* c = checksum
* * = unknown
*
**/
