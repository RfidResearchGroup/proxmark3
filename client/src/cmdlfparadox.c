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
// Low frequency Paradox tag commands
// FSK2a, rf/50, 96 bits (completely known)
//-----------------------------------------------------------------------------
#include "cmdlfparadox.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "commonutil.h"   // ARRAYLEN
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "graph.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "lfdemod.h"
#include "protocols.h"  // t55xx defines
#include "cmdlft55xx.h" // clone..
#include "crc.h"        // maxim
#include "cmdlfem4x05.h"   //
#include "cliparser.h"

static int CmdHelp(const char *Cmd);

static const uint8_t paradox_lut[] = {
    0xDB, 0xFC, 0x3F, 0xC5, 0x50, 0x14, 0x05, 0x47,
    0x9F, 0xED, 0x7D, 0x59, 0x22, 0x84, 0x21, 0x4E,
    0x39, 0x48, 0x12, 0x88, 0x53, 0xDE, 0xBB, 0xE4,
    0xB4, 0x2D, 0x4D, 0x55, 0xCA, 0xBE, 0xA3, 0xE2
};
// FC:108, Card01827
// 00000000  01101100       00000111     00100011
// hex(0xED xor 0x7D xor 0x22 xor 0x84 xor 0xDE xor 0xBB xor 0xE4 xor 0x4D xor 0xA3 xor 0xE2 xor 0x47) 0xFC

#define PARADOX_PREAMBLE_LEN 8

// by marshmellow
// Paradox Prox demod - FSK2a RF/50 with preamble of 00001111 (then manchester encoded)
// print full Paradox Prox ID and some bit format details if found

int demodParadox(bool verbose) {
    (void) verbose; // unused so far
    //raw fsk demod no manchester decoding no start bit finding just get binary from wave
    uint8_t bits[MAX_GRAPH_TRACE_LEN] = {0};
    size_t size = getFromGraphBuf(bits);
    if (size == 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Paradox not enough samples");
        return PM3_ESOFT;
    }

    int wave_idx = 0;
    //get binary from fsk wave
    int idx = detectParadox(bits, &size, &wave_idx);
    if (idx < 0) {
        if (idx == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Paradox not enough samples");
        else if (idx == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Paradox just noise detected");
        else if (idx == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Paradox problem during FSK demod");
        else if (idx == -4)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Paradox preamble not found");
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - Paradox error demoding fsk %d", idx);

        return PM3_ESOFT;
    }

    uint8_t *b = bits + idx;
    uint8_t rawhex[12] = {0};
    for (uint8_t i = 0, m = 0, p = 1; i < 96; i++) {

        // convert hex
        rawhex[m] <<= 1;
        rawhex[m] |= (*b & 1);
        b++;

        if (p == 8) {
            m++;
            p = 1;
        } else {
            p++;
        }
    }

    uint32_t hi2 = 0, hi = 0, lo = 0;
    uint8_t error = 0;

    // Remove manchester encoding from FSK bits, skip pre
    for (uint8_t i = idx + PARADOX_PREAMBLE_LEN; i < (idx + 96); i += 2) {

        // not manchester data
        if (bits[i] == bits[i + 1]) {
            PrintAndLogEx(WARNING, "Error Manchester at %u", i);
            error++;
        }

        hi2 = (hi2 << 1) | (hi >> 31);
        hi = (hi << 1) | (lo >> 31);
        lo <<= 1;

        if (bits[i] && !bits[i + 1])  {
            lo |= 1;  // 10
        }
    }

    setDemodBuff(bits, size, idx);
    setClockGrid(50, wave_idx + (idx * 50));

    if (hi2 == 0 && hi == 0 && lo == 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Paradox no value found");
        return PM3_ESOFT;
    }

    uint32_t fc = ((hi & 0x3) << 6) | (lo >> 26);
    uint32_t cardnum = (lo >> 10) & 0xFFFF;
    uint8_t chksum = (lo >> 2) & 0xFF;


    // Calc CRC & Checksum
    // 000088f0b - FC: 8 - Card: 36619 - Checksum: 05 - RAW: 0f55555559595aa559a5566a
    // checksum?
    uint8_t calc_chksum = 0x47;
    uint8_t pos = 0;
    for (uint8_t i = 0; i < 8; i++) {

        uint8_t ice = rawhex[i + 1];
        for (uint8_t j = 0x80; j > 0; j >>= 2) {

            if (ice & j) {
                calc_chksum ^= paradox_lut[pos];
            }
            pos++;
        }
    }

    uint32_t crc = CRC8Maxim(rawhex + 1, 8);
    PrintAndLogEx(DEBUG, " FSK/MAN raw : %s", sprint_hex(rawhex, sizeof(rawhex)));
    PrintAndLogEx(DEBUG, "         raw : %s = (maxim crc8) %02x == %02x", sprint_hex(rawhex + 1, 8), crc, calc_chksum);
//    PrintAndLogEx(DEBUG, " OTHER sample CRC-8/MAXIM : 55 55 69 A5 55 6A 59 5A  = FC");

    uint32_t rawLo = bytebits_to_byte(bits + idx + 64, 32);
    uint32_t rawHi = bytebits_to_byte(bits + idx + 32, 32);
    uint32_t rawHi2 = bytebits_to_byte(bits + idx, 32);

    PrintAndLogEx(INFO, "Paradox - ID: " _GREEN_("%x%08x") " FC: " _GREEN_("%d") " Card: " _GREEN_("%d") ", Checksum: %02x, Raw: %08x%08x%08x",
                  hi >> 10,
                  (hi & 0x3) << 26 | (lo >> 10),
                  fc,
                  cardnum,
                  chksum,
                  rawHi2,
                  rawHi,
                  rawLo
                 );

    PrintAndLogEx(DEBUG, "DEBUG: Paradox idx: %d, len: %zu, Printing DemodBuffer:", idx, size);
    if (g_debugMode) {
        printDemodBuff(0, false, false, false);
    }

    return PM3_SUCCESS;
}

static int CmdParadoxDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf paradox demod",
                  "Try to find Paradox preamble, if found decode / descramble data",
                  "lf paradox demod"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return demodParadox(true);
}

static int CmdParadoxReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf paradox reader",
                  "read a Paradox tag",
                  "lf Paradox reader -@   -> continuous reader mode"
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
        lf_read(false, 10000);
        demodParadox(!cm);
    } while (cm && !kbd_enter_pressed());

    return PM3_SUCCESS;
}

static int CmdParadoxClone(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf paradox clone",
                  "clone a paradox tag to a T55x7, Q5/T5555 or EM4305/4469 tag.",
                  "lf paradox clone --raw 0f55555695596a6a9999a59a\n"
                  "lf paradox clone -r 0f55555695596a6a9999a59a --q5      -> encode for Q5/T5555 tag\n"
                  "lf paradox clone -r 0f55555695596a6a9999a59a --em      -> encode for EM4305/4469"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("r", "raw", "<hex>", "raw hex data. 12 bytes max"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    // skip first block,  3*4 = 12 bytes left
    uint8_t raw[12] = {0};
    CLIGetHexWithReturn(ctx, 1, raw, &raw_len);

    bool q5 = arg_get_lit(ctx, 2);
    bool em = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }

    if (raw_len != 12) {
        PrintAndLogEx(ERR, "Data must be 12 bytes (24 HEX characters)  %d", raw_len);
        return PM3_EINVARG;
    }

    uint32_t blocks[4];
    for (uint8_t i = 1; i < ARRAYLEN(blocks); i++) {
        blocks[i] = bytes_to_num(raw + ((i - 1) * 4), sizeof(uint32_t));
    }

    // Paradox - FSK2a, data rate 50, 3 data blocks
    blocks[0] = T55x7_MODULATION_FSK2a | T55x7_BITRATE_RF_50 | 3 << T55x7_MAXBLOCK_SHIFT;
    char cardtype[16] = {"T55x7"};
    // Q5
    if (q5) {
        blocks[0] = T5555_FIXED | T5555_INVERT_OUTPUT | T5555_MODULATION_FSK2 | T5555_SET_BITRATE(50) | T5555_ST_TERMINATOR | 3 << T5555_MAXBLOCK_SHIFT;
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    }

    // EM4305
    if (em) {
        blocks[0] = EM4305_PARADOX_CONFIG_BLOCK;
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
    }

    PrintAndLogEx(INFO, "Preparing to clone Paradox to " _YELLOW_("%s") " with raw hex", cardtype);
    print_blocks(blocks,  ARRAYLEN(blocks));

    int res;
    if (em) {
        res = em4x05_clone_tag(blocks, ARRAYLEN(blocks), 0, false);
    } else {
        res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    }
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf paradox read`") " to verify");
    return res;
}

static int CmdParadoxSim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf paradox sim",
                  "Enables simulation of paradox card with specified card number.\n"
                  "Simulation runs until the button is pressed or another USB command is issued.",
                  "lf paradox sim --raw 0f55555695596a6a9999a59a"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("r", "raw", "<hex>", " raw hex data. 12 bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    // skip first block,  3*4 = 12 bytes left
    uint8_t raw[12] = {0};
    CLIGetHexWithReturn(ctx, 1, raw, &raw_len);
    CLIParserFree(ctx);

    if (raw_len != 12) {
        PrintAndLogEx(ERR, "Data must be 12 bytes (24 HEX characters)  %d", raw_len);
        return PM3_EINVARG;
    }

    PrintAndLogEx(SUCCESS, "Simulating Paradox -  raw " _YELLOW_("%s"), sprint_hex_inrow(raw, sizeof(raw)));

    uint8_t bs[sizeof(raw) * 8];
    bytes_to_bytebits(raw, sizeof(raw), bs);

    // Paradox uses:  fcHigh: 10, fcLow: 8, clk: 50, invert: 1  FSK2a
    uint8_t clk = 50, high = 10, low = 8;

    lf_fsksim_t *payload = calloc(1, sizeof(lf_fsksim_t) + sizeof(bs));
    payload->fchigh = high;
    payload->fclow =  low;
    payload->separator = 0;
    payload->clock = clk;
    memcpy(payload->data, bs, sizeof(bs));

    clearCommandBuffer();
    SendCommandNG(CMD_LF_FSK_SIMULATE, (uint8_t *)payload,  sizeof(lf_fsksim_t) + sizeof(bs));
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_LF_FSK_SIMULATE, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;

    return PM3_SUCCESS;
}
/*

    if (sscanf(Cmd, "%u %u", &fc, &cn) != 2) return usage_lf_paradox_sim();

    facilitycode = (fc & 0x000000FF);
    cardnumber = (cn & 0x0000FFFF);

    // if ( GetParadoxBits(facilitycode, cardnumber, bs) != PM3_SUCCESS) {
    // PrintAndLogEx(ERR, "Error with tag bitstream generation.");
    // return 1;
    // }

    PrintAndLogEx(NORMAL, "Simulating Paradox - Facility Code: %u, CardNumber: %u", facilitycode, cardnumber);

*/
static command_t CommandTable[] = {
    {"help",   CmdHelp,          AlwaysAvailable, "This help"},
    {"demod",  CmdParadoxDemod,  AlwaysAvailable, "demodulate a Paradox FSK tag from the GraphBuffer"},
    {"reader", CmdParadoxReader, IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone",  CmdParadoxClone,  IfPm3Lf,         "clone paradox tag"},
    {"sim",    CmdParadoxSim,    IfPm3Lf,         "simulate paradox tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFParadox(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// loop to get raw paradox waveform then FSK demodulate the TAG ID from it
int detectParadox(uint8_t *dest, size_t *size, int *wave_start_idx) {
    //make sure buffer has data
    if (*size < 96 * 50) return -1;

    if (getSignalProperties()->isnoise) return -2;

    // FSK demodulator
    *size = fskdemod(dest, *size, 50, 1, 10, 8, wave_start_idx); // paradox fsk2a

    //did we get a good demod?
    if (*size < 96) return -3;

    // 00001111 bit pattern represent start of frame, 01 pattern represents a 0 and 10 represents a 1
    size_t idx = 0;
    uint8_t preamble[] = {0, 0, 0, 0, 1, 1, 1, 1};
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &idx))
        return -4; //preamble not found

    return (int)idx;
}


