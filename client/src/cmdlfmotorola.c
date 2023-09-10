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
// Low frequency Motorola tag commands
// PSK1, RF/32, 64 bits long,  at 74 kHz
//-----------------------------------------------------------------------------
#include "cmdlfmotorola.h"
#include <ctype.h>        // tolower
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
#include "cliparser.h"    // cli parse input
#include "cmdlfem4x05.h"  // EM defines

static int CmdHelp(const char *Cmd);

int demodMotorola(bool verbose) {
    (void) verbose; // unused so far
    //PSK1
    if (PSKDemod(32, 1, 100, false) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Motorola: PSK Demod failed");
        return PM3_ESOFT;
    }

    size_t size = g_DemodBufferLen;
    int ans = detectMotorola(g_DemodBuffer, &size);
    if (ans < 0) {
        if (ans == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Motorola: too few bits found");
        else if (ans == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Motorola: preamble not found");
        else if (ans == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Motorola: Size not correct: %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - Motorola: ans: %d", ans);

        return PM3_ESOFT;
    }
    setDemodBuff(g_DemodBuffer, 64, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));

    //got a good demod
    uint32_t raw1 = bytebits_to_byte(g_DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(g_DemodBuffer + 32, 32);

// A0000000E308C0C1
// 10100000000000000000000000000000 1110 0011 0000 1000 1100 0000 1100 0001


//                1    1    2    2    2    3    3    4    4    4    5    5    6
// 0    4    8    2    6    0    4    8    2    6    0    4    8    2    6    0
// 1010 0000 0000 0000 0000 0000 0000 0000 1110 0011 0000 1000 1100 0000 0101 0010
//                                           9    .0      5  4 26    3 .  71
//                                           .    .0      5  4 26    3 .  71
//                                          6 9 A5   C0FD  E7    18 B 4  3  2

// hex(234)  0xEA    bin(234)    1110 1010
// hex(437)  0x1B5   bin(437)  1 1011 0101
// hex(229)  0xE5    bin(229)    1110 0101

    uint16_t fc = 0;

// FC seems to be guess work.  Need more samples
// guessing  printed FC is 4 digits.  1024? 10bit?
//    fc |= g_DemodBuffer[38] << 9; // b10
    fc |= g_DemodBuffer[34] << 8; // b9

    fc |= g_DemodBuffer[44] << 7; // b8
    fc |= g_DemodBuffer[47] << 6; // b7
    fc |= g_DemodBuffer[57] << 5; // b6
    fc |= g_DemodBuffer[49] << 4; // b5

// seems to match
    fc |= g_DemodBuffer[53] << 3; // b4
    fc |= g_DemodBuffer[48] << 2; // b3
    fc |= g_DemodBuffer[58] << 1; // b2
    fc |= g_DemodBuffer[39] << 0; // b1

// CSN was same as Indala CSN descramble.
    uint16_t csn = 0;
    csn |= g_DemodBuffer[42] << 15; // b16
    csn |= g_DemodBuffer[45] << 14; // b15
    csn |= g_DemodBuffer[43] << 13; // b14
    csn |= g_DemodBuffer[40] << 12; // b13
    csn |= g_DemodBuffer[52] << 11; // b12
    csn |= g_DemodBuffer[36] << 10; // b11
    csn |= g_DemodBuffer[35] << 9; // b10
    csn |= g_DemodBuffer[51] << 8; // b9
    csn |= g_DemodBuffer[46] << 7; // b8
    csn |= g_DemodBuffer[33] << 6; // b7
    csn |= g_DemodBuffer[37] << 5; // b6
    csn |= g_DemodBuffer[54] << 4; // b5
    csn |= g_DemodBuffer[56] << 3; // b4
    csn |= g_DemodBuffer[59] << 2; // b3
    csn |= g_DemodBuffer[50] << 1; // b2
    csn |= g_DemodBuffer[41] << 0; // b1

    uint8_t checksum = 0;
    checksum |= g_DemodBuffer[62] << 1; // b2
    checksum |= g_DemodBuffer[63] << 0; // b1


    PrintAndLogEx(SUCCESS, "Motorola - fmt: " _GREEN_("26") " FC: " _GREEN_("%u") " Card: " _GREEN_("%u") ", Raw: %08X%08X", fc, csn, raw1, raw2);
    PrintAndLogEx(DEBUG, "checksum: " _GREEN_("%1d%1d"), checksum >> 1 & 0x01, checksum & 0x01);
    return PM3_SUCCESS;
}

static int CmdMotorolaDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf motorola demod",
                  "Try to find Motorola Flexpass preamble, if found decode / descramble data",
                  "lf motorola demod"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return demodMotorola(true);
}

static int CmdMotorolaReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf motorola reader",
                  "read a Motorola Flexpass tag",
                  "lf motorola reader -@   -> continuous reader mode"
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

    // Motorola Flexpass seems to work at 74 kHz
    // and take about 4400 samples too before modulating
    sample_config sc = {
        .decimation = -1,
        .bits_per_sample = -1,
        .averaging = false,
        .divisor = LF_FREQ2DIV(74),
        .trigger_threshold = -1,
        .samples_to_skip = 4500,
        .verbose = false
    };
    lf_config(&sc);

    int res;
    do {
        // 64 * 32 * 2 * n-ish
        lf_read(false, 5000);
        res = demodMotorola(!cm);
    } while (cm && !kbd_enter_pressed());

    // reset back to 125 kHz
    sc.divisor = LF_DIVISOR_125;
    sc.samples_to_skip = 0;
    lf_config(&sc);

    return res;
}

static int CmdMotorolaClone(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf motorola clone",
                  "clone Motorola UID to a T55x7, Q5/T5555 or EM4305/4469 tag.\n"
                  "defaults to 64 bit format",
                  "lf motorola clone --raw a0000000a0002021       -> encode for T55x7 tag\n"
                  "lf motorola clone --raw a0000000a0002021 --q5  -> encode for Q5/T5555 tag\n"
                  "lf motorola clone --raw a0000000a0002021 --em  -> encode for EM4305/4469"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("r", "raw", "<hex>", "raw hex bytes. 8 bytes"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    uint8_t raw[8];
    CLIGetHexWithReturn(ctx, 1, raw, &raw_len);
    bool q5 = arg_get_lit(ctx, 2);
    bool em = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }

    //TODO add selection of chip for Q5 or T55x7
    uint32_t blocks[3] = {0};

    blocks[0] =  T55x7_BITRATE_RF_32 | T55x7_MODULATION_PSK1 | (2 << T55x7_MAXBLOCK_SHIFT);
    char cardtype[16] = {"T55x7"};
    // Q5
    if (q5) {
        blocks[0] = T5555_FIXED | T5555_SET_BITRATE(32) | T5555_MODULATION_PSK1 | 2 << T5555_MAXBLOCK_SHIFT;
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    }

    // EM4305
    if (em) {
        blocks[0] = EM4305_MOTOROLA_CONFIG_BLOCK;
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
    }

    blocks[1] = bytes_to_num(raw, 4);
    blocks[2] = bytes_to_num(raw + 4, 4);

    // config for Motorola 64 format (RF/32;PSK1 with RF/2; Maxblock=2)
    PrintAndLogEx(INFO, "Preparing to clone Motorola 64bit to " _YELLOW_("%s")  " with raw " _GREEN_("%s")
                  , cardtype
                  , sprint_hex_inrow(raw, sizeof(raw))
                 );
    print_blocks(blocks, ARRAYLEN(blocks));

    int res;
    if (em) {
        res = em4x05_clone_tag(blocks, ARRAYLEN(blocks), 0, false);
    } else {
        res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    }
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf motorola reader`") " to verify");
    return res;
}

static int CmdMotorolaSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf motorola sim",
                  "Enables simulation of Motorola card with specified card number.\n"
                  "Simulation runs until the button is pressed or another USB command is issued.",
                  "lf motorola sim"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    // PSK sim.
    PrintAndLogEx(INFO, " PSK1 at 66 kHz... Interesting.");
    PrintAndLogEx(INFO, " To be implemented, feel free to contribute!");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",   CmdHelp,           AlwaysAvailable, "This help"},
    {"demod",  CmdMotorolaDemod,  AlwaysAvailable, "demodulate an MOTOROLA tag from the GraphBuffer"},
    {"reader", CmdMotorolaReader, IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone",  CmdMotorolaClone,  IfPm3Lf,         "clone MOTOROLA tag to T55x7"},
    {"sim",    CmdMotorolaSim,    IfPm3Lf,         "simulate MOTOROLA tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFMotorola(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// find MOTOROLA preamble in already demoded data
int detectMotorola(uint8_t *dest, size_t *size) {

    //make sure buffer has data
    if (*size < 64)
        return -1;

    bool inverted = false;
    size_t found_size = *size;
    size_t start_idx = 0;

    // Seems Motorola is based on the following indala format.
    // standard 64 bit Motorola formats including 26 bit 40134 format
    uint8_t preamble[] =  {1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    uint8_t preamble_i[]  = {0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0};

    // preamble not found
    if (!preambleSearch(dest, preamble, sizeof(preamble), &found_size, &start_idx)) {
        found_size = *size;
        if (!preambleSearch(dest, preamble_i, sizeof(preamble_i), &found_size, &start_idx)) {
            return -2;
        }
        PrintAndLogEx(DEBUG, "DEBUG: detectMotorola PSK1 found inverted preamble");
        inverted = true;
    }

    *size = found_size;

    // wrong demoded size
    if (*size != 64)
        return -3;

    if (inverted && start_idx > 0) {
        for (size_t i = start_idx - 1 ; i < *size + start_idx + 2; i++) {
            dest[i] ^= 1;
        }
    }

    return (int)start_idx;
}

int readMotorolaUid(void) {
    return (CmdMotorolaReader("") == PM3_SUCCESS);
}
