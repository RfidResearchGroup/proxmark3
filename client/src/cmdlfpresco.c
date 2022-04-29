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
// Low frequency Presco tag commands
//-----------------------------------------------------------------------------

#include "cmdlfpresco.h"
#include <string.h>
#include <stdio.h>
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

// find presco preamble 0x10D in already demoded data
static int detectPresco(uint8_t *dest, size_t *size) {
    if (*size < 128 * 2) return -1; //make sure buffer has data
    size_t startIdx = 0;
    uint8_t preamble[] = {0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx))
        return -2; //preamble not found
    if (*size != 128) return -3; //wrong demoded size
    //return start position
    return (int)startIdx;
}

// convert base 12 ID to sitecode & usercode & 8 bit other unknown code
static int getWiegandFromPrintedPresco(void *arr,  uint32_t *fullcode) {
    char *s = (char *)arr;
    uint8_t val = 0;
    for (int i = 0; i < strlen(s); ++i) {
        // Get value from number string.
        if (s[i] == '*')
            val = 10;
        if (s[i] == '#')
            val = 11;
        if (s[i] >= 0x30 && s[i] <= 0x39)
            val = s[i] - 0x30;

        *fullcode += val;

        // last digit is only added, not multiplied.
        if (i < strlen(s) - 1)
            *fullcode *= 12;
    }
    return PM3_SUCCESS;
}

// calc not certain - intended to get bitstream for programming / sim
static int getPrescoBits(uint32_t fullcode, uint8_t *prescoBits) {
    num_to_bytebits(0x10D00000, 32, prescoBits);
    num_to_bytebits(0x00000000, 32, prescoBits + 32);
    num_to_bytebits(0x00000000, 32, prescoBits + 64);
    num_to_bytebits(fullcode, 32, prescoBits + 96);
    return PM3_SUCCESS;
}

//see ASKDemod for what args are accepted
int demodPresco(bool verbose) {
    (void) verbose; // unused so far
    bool st = true;
    if (ASKDemod_ext(32, 0, 0, 0, false, false, false, 1, &st) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error Presco ASKDemod failed");
        return PM3_ESOFT;
    }
    size_t size = g_DemodBufferLen;
    int ans = detectPresco(g_DemodBuffer, &size);
    if (ans < 0) {
        if (ans == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Presco: too few bits found");
        else if (ans == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Presco: preamble not found");
        else if (ans == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Presco: Size not correct: %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - Presco: ans: %d", ans);
        return PM3_ESOFT;
    }
    setDemodBuff(g_DemodBuffer, 128, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));

    //got a good demod
    uint32_t raw1 = bytebits_to_byte(g_DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(g_DemodBuffer + 32, 32);
    uint32_t raw3 = bytebits_to_byte(g_DemodBuffer + 64, 32);
    uint32_t raw4 = bytebits_to_byte(g_DemodBuffer + 96, 32);
    uint32_t fullcode = raw4;
    uint32_t usercode = fullcode & 0x0000FFFF;
    uint32_t sitecode = (fullcode >> 24) & 0x000000FF;

    PrintAndLogEx(SUCCESS, "Presco Site code: " _GREEN_("%u") " User code: " _GREEN_("%u") " Full code: " _GREEN_("%08X") " Raw: " _YELLOW_("%08X%08X%08X%08X")
                  , sitecode
                  , usercode
                  , fullcode
                  , raw1, raw2, raw3, raw4
                 );
    return PM3_SUCCESS;
}

static int CmdPrescoDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf presco demod",
                  "Try to find presco preamble, if found decode / descramble data",
                  "lf presco demod"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return demodPresco(true);
}

//see ASKDemod for what args are accepted
static int CmdPrescoReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf presco reader",
                  "read a presco tag",
                  "lf presco reader -@   -> continuous reader mode"
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
        lf_read(false, 12000);
        demodPresco(!cm);
    } while (cm && !kbd_enter_pressed());
    return PM3_SUCCESS;
}

// takes base 12 ID converts to hex
// Or takes 8 digit hex ID
static int CmdPrescoClone(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf presco clone",
                  "clone a presco tag to a T55x7, Q5/T5555 or EM4305/4469 tag.",
                  "lf presco clone -d 018363467           -> encode for T55x7 tag\n"
                  "lf presco clone -d 018363467 --q5      -> encode for Q5/T5555 tag\n"
                  "lf presco clone -d 018363467 --em      -> encode for EM4305/4469"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("c", NULL, "<hex>", "8 digit hex card number"),
        arg_str0("d", NULL, "<digits>", "9 digit presco card ID"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int hex_len = 0;
    uint8_t hex[4] = {0, 0, 0, 0};
    CLIGetHexWithReturn(ctx, 1, hex, &hex_len);

    uint8_t idstr[11];
    int slen = 9;
    memset(idstr, 0x00, sizeof(idstr));
    CLIGetStrWithReturn(ctx, 2, idstr, &slen);

    bool q5 = arg_get_lit(ctx, 3);
    bool em = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }

    uint32_t fullcode = 0;

    if (hex_len) {
        fullcode = bytes_to_num(hex, hex_len);
    } else {
        //param get string int param_getstr(const char *line, int paramnum, char * str)
        if (slen < 2)  {
            PrintAndLogEx(ERR, "Must contain atleast 2 digits");
            return PM3_EINVARG;
        }

        getWiegandFromPrintedPresco(idstr, &fullcode);
    }

    uint32_t usercode = fullcode & 0x0000FFFF; //% 65566
    uint32_t sitecode = (fullcode >> 24) & 0x000000FF;  // /= 16777216;

    uint32_t blocks[5] = {T55x7_MODULATION_MANCHESTER | T55x7_BITRATE_RF_32 | 4 << T55x7_MAXBLOCK_SHIFT | T55x7_ST_TERMINATOR, 0, 0, 0, 0};

    char cardtype[16] = {"T55x7"};
    // Q5
    if (q5) {
        blocks[0] = T5555_FIXED | T5555_MODULATION_MANCHESTER | T5555_SET_BITRATE(32) | 4 << T5555_MAXBLOCK_SHIFT | T5555_ST_TERMINATOR;
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    }

    // EM4305
    if (em) {
        blocks[0] = EM4305_PRESCO_CONFIG_BLOCK;
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
    }

    if ((sitecode & 0xFF) != sitecode) {
        sitecode &= 0xFF;
        PrintAndLogEx(INFO, "Site code truncated to 8-bits (Presco): %u", sitecode);
    }

    if ((usercode & 0xFFFF) != usercode) {
        usercode &= 0xFFFF;
        PrintAndLogEx(INFO, "User code truncated to 16-bits (Presco): %u", usercode);
    }

    blocks[1] = 0x10D00000; //preamble
    blocks[2] = 0x00000000;
    blocks[3] = 0x00000000;
    blocks[4] = fullcode;

    PrintAndLogEx(INFO, "Preparing to clone Presco to " _GREEN_("%s") " with Site code: " _GREEN_("%u") " User code: " _GREEN_("%u") " Full code: " _GREEN_("%08x")
                  , cardtype
                  , sitecode
                  , usercode
                  , fullcode
                 );
    print_blocks(blocks,  ARRAYLEN(blocks));

    int res;
    if (em) {
        res = em4x05_clone_tag(blocks, ARRAYLEN(blocks), 0, false);
    } else {
        res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    }
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf presco reader`") " to verify");
    return res;
}

// takes base 12 ID converts to hex
// Or takes 8 digit hex ID
static int CmdPrescoSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf presco sim",
                  "Enables simulation of presco card with specified card number.\n"
                  "Simulation runs until the button is pressed or another USB command is issued.\n"
                  "Per presco format, the card number is 9 digit number and can contain *# chars. Larger values are truncated.",
                  "lf presco sim -d 018363467"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("c", NULL, "<hex>", "8 digit hex card number"),
        arg_str0("d", NULL, "<digits>", "9 digit presco card ID"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int hex_len = 0;
    uint8_t hex[4] = {0, 0, 0, 0};
    CLIGetHexWithReturn(ctx, 1, hex, &hex_len);

    uint8_t idstr[11];
    int slen = 9;
    memset(idstr, 0x00, sizeof(idstr));
    CLIGetStrWithReturn(ctx, 2, idstr, &slen);
    CLIParserFree(ctx);

    uint32_t fullcode = 0;

    if (hex_len) {
        fullcode = bytes_to_num(hex, hex_len);
    } else {
        if (slen < 2)  {
            PrintAndLogEx(ERR, "Must contain atleast 2 digits");
            return PM3_EINVARG;
        }
        getWiegandFromPrintedPresco(idstr, &fullcode);
    }

    uint32_t usercode = fullcode & 0x0000FFFF;
    uint32_t sitecode = (fullcode >> 24) & 0x000000FF;

    if ((sitecode & 0xFF) != sitecode) {
        sitecode &= 0xFF;
        PrintAndLogEx(INFO, "Site code truncated to 8-bits (Presco): %u", sitecode);
    }

    if ((usercode & 0xFFFF) != usercode) {
        usercode &= 0xFFFF;
        PrintAndLogEx(INFO, "User code truncated to 16-bits (Presco): %u", usercode);
    }

    PrintAndLogEx(SUCCESS, "Simulating Presco - Site Code: " _GREEN_("%u") " User Code: " _GREEN_("%u") " Full Code: " _GREEN_("%08X")
                  , sitecode
                  , usercode
                  , fullcode)
    ;

    uint8_t bs[128];
    getPrescoBits(fullcode, bs);

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
    {"help",    CmdHelp,        AlwaysAvailable, "This help"},
    {"demod",   CmdPrescoDemod, AlwaysAvailable, "demodulate Presco tag from the GraphBuffer"},
    {"reader",  CmdPrescoReader, IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone",   CmdPrescoClone,  IfPm3Lf,         "clone presco tag to T55x7 or Q5/T5555"},
    {"sim",     CmdPrescoSim,    IfPm3Lf,         "simulate presco tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFPresco(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
