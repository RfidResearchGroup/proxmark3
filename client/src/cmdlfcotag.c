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
// Low frequency COTAG commands
//-----------------------------------------------------------------------------
#include "cmdlfcotag.h"  // COTAG function declarations
#include <string.h>
#include <stdio.h>
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "lfdemod.h"
#include "cmddata.h"    // getSamples
#include "ui.h"         // PrintAndLog
#include "ctype.h"      // tolower
#include "cliparser.h"
#include "commonutil.h" // reflect32

static int CmdHelp(const char *Cmd);

// COTAG demod should be able to use g_GraphBuffer,
// when data load samples
int demodCOTAG(bool verbose) {
    (void) verbose; // unused so far

    uint8_t bits[COTAG_BITS] = {0};
    size_t bitlen = COTAG_BITS;
    memcpy(bits, g_DemodBuffer, COTAG_BITS);

    uint8_t inv_bits[COTAG_BITS] = {0};
    memcpy(inv_bits, g_DemodBuffer, COTAG_BITS);

    uint8_t alignPos = 0;
    uint16_t err = manrawdecode(bits, &bitlen, 1, &alignPos);
    if (err > 50) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - COTAG too many errors: %d", err);
        return PM3_ESOFT;
    }

    setDemodBuff(bits, bitlen, 0);

    //got a good demod
    uint16_t cn = bytebits_to_byteLSBF(bits + 1, 16);
    uint32_t fc = bytebits_to_byteLSBF(bits + 1 + 16, 8);

    uint32_t raw1 = bytebits_to_byteLSBF(bits, 32);
    uint32_t raw2 = bytebits_to_byteLSBF(bits + 32, 32);
    uint32_t raw3 = bytebits_to_byteLSBF(bits + 64, 32);
    uint32_t raw4 = bytebits_to_byteLSBF(bits + 96, 32);


    /*
    fc 161:   1010 0001 -> LSB 1000 0101
    cn 33593  1000 0011 0011 1001 -> LSB 1001 1100 1100 0001
        cccc cccc cccc cccc                     ffffffff
      0 1001 1100 1100 0001 1000 0101 0000 0000 100001010000000001111011100000011010000010000000000000000000000000000000000000000000000000000000100111001100000110000101000
        1001 1100 1100 0001                     10000101

    COTAG FC/272
    1    7    7    D    E    2    0    0    8    0    0    0    3    9    2    0    D    0    4    0000000000000
    0001 0111 0111 1101 1110 0010 0000 0000 1000 0000 0000 0000 0011 1001 0010 0000 1101 0000 0100 0000000000000000000000000000000000000000000000000000000
    0001 0111 0111 1101 1110 001                                0010 1001 0011      1000 0110 0100

    */
    PrintAndLogEx(SUCCESS, "COTAG Found: FC " _GREEN_("%u")", CN: " _GREEN_("%u")" Raw: %08X%08X%08X%08X", fc, cn, raw1, raw2, raw3, raw4);

    bitlen = COTAG_BITS;
    err = manrawdecode(inv_bits, &bitlen, 0, &alignPos);
    if (err < 50) {
        uint32_t cn_large = bytebits_to_byte(inv_bits + 1, 23);
        cn_large = reflect32(cn_large) >> 9;
        uint8_t a = bytebits_to_byte(inv_bits + 48, 4);
        uint8_t b = bytebits_to_byte(inv_bits + 52, 4);
        uint8_t c = bytebits_to_byte(inv_bits + 56, 4);
        uint16_t fc_large = NIBBLE_LOW(c) << 8 | NIBBLE_LOW(b) << 4 | NIBBLE_LOW(a);

        raw1 = bytebits_to_byte(inv_bits, 32);
        raw2 = bytebits_to_byte(inv_bits + 32, 32);
        raw3 = bytebits_to_byte(inv_bits + 64, 32);
        raw4 = bytebits_to_byte(inv_bits + 96, 32);
        PrintAndLogEx(SUCCESS, "             FC " _GREEN_("%u")", CN: " _GREEN_("%u")" Raw: %08X%08X%08X%08X", fc_large, cn_large, raw1, raw2, raw3, raw4);
    }
    return PM3_SUCCESS;
}

static int CmdCOTAGDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf cotag demod",
                  "Try to find COTAG preamble, if found decode / descramble data",
                  "lf cotag demod"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool verbose = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);
    return demodCOTAG(verbose);
}

// When reading a COTAG.
// 0 = HIGH/LOW signal - maxlength bigbuff
// 1 = translation for HI/LO into bytes with manchester 0,1 - length 300
// 2 = raw signal -  maxlength bigbuff
static int CmdCOTAGReader(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf cotag reader",
                  "read a COTAG tag,  the current support for COTAG is limited. ",
                  "lf cotag reader -2"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("1", NULL, "HIGH/LOW signal; maxlength bigbuff"),
        arg_lit0("2", NULL, "translation of HIGH/LOW into bytes with manchester 0,1"),
        arg_lit0("3", NULL, "raw signal; maxlength bigbuff"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, false);
    bool mode0 = arg_get_lit(ctx, 1);
    bool mode1 = arg_get_lit(ctx, 2);
    bool mode2 = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if ((mode0 + mode1 + mode2) > 1) {
        PrintAndLogEx(ERR, "You can only use one option at a time");
        return PM3_EINVARG;
    }
    uint8_t mode = 0xFF;
    if (mode0)
        mode = 0;
    if (mode1)
        mode = 1;
    if (mode2)
        mode = 2;

    struct p {
        uint8_t mode;
    } PACKED payload;
    payload.mode = mode;

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_LF_COTAG_READ, (uint8_t *)&payload, sizeof(payload));

    uint8_t timeout = 3;
    int res = PM3_SUCCESS;
    while (!WaitForResponseTimeout(CMD_LF_COTAG_READ, &resp, 1000)) {
        timeout--;
        if (timeout == 0) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(WARNING, "command execution time out");
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            res = PM3_ETIMEOUT;
        }
    }

    if (res != PM3_SUCCESS) {
        return res;
    }

    if (timeout != 3)
        PrintAndLogEx(NORMAL, "");

    switch (payload.mode) {
        case 0:
        case 2: {
            CmdPlot("");
            CmdGrid("-x 384");
            getSamples(0, false);
            break;
        }
        case 1: {
            memcpy(g_DemodBuffer, resp.data.asBytes, resp.length);
            g_DemodBufferLen = resp.length;
            return demodCOTAG(true);
        }
    }
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,         AlwaysAvailable, "This help"},
    {"demod",   CmdCOTAGDemod,   AlwaysAvailable, "demodulate an COTAG tag"},
    {"reader",  CmdCOTAGReader,  IfPm3Lf,         "attempt to read and extract tag data"},
    {NULL, NULL, NULL, NULL}
};
static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFCOTAG(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int readCOTAGUid(void) {
    return (CmdCOTAGReader("-2") == PM3_SUCCESS);
}
