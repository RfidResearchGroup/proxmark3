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
// Low frequency Farpoint / Pyramid tag commands
// FSK2a, rf/50, 128 bits (complete)
//-----------------------------------------------------------------------------
#include "cmdlfpyramid.h"
#include "common.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include "commonutil.h"   // ARRAYLEN
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "graph.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "protocols.h"  // for T55xx config register definitions
#include "lfdemod.h"    // parityTest
#include "crc.h"
#include "cmdlft55xx.h" // verifywrite
#include "cliparser.h"
#include "cmdlfem4x05.h"  // EM Defines

static int CmdHelp(const char *Cmd);

//Pyramid Prox demod - FSK RF/50 with preamble of 0000000000000001  (always a 128 bit data stream)
//print full Farpointe Data/Pyramid Prox ID and some bit format details if found
int demodPyramid(bool verbose) {
    (void) verbose; // unused so far
    //raw fsk demod no manchester decoding no start bit finding just get binary from wave
    uint8_t bits[MAX_GRAPH_TRACE_LEN] = {0};
    size_t size = getFromGraphBuf(bits);
    if (size == 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Pyramid not enough samples");
        return PM3_ESOFT;
    }
    //get binary from fsk wave
    int waveIdx = 0;
    int idx = detectPyramid(bits, &size, &waveIdx);
    if (idx < 0) {
        if (idx == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Pyramid: not enough samples");
        else if (idx == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Pyramid: only noise found");
        else if (idx == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Pyramid: problem during FSK demod");
        else if (idx == -4)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Pyramid: preamble not found");
        else if (idx == -5)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Pyramid: size not correct: %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - Pyramid: error demoding fsk idx: %d", idx);
        return PM3_ESOFT;
    }
    setDemodBuff(bits, size, idx);
    setClockGrid(50, waveIdx + (idx * 50));

    // Index map
    // 0           10          20          30            40          50          60
    // |           |           |           |             |           |           |
    // 0123456 7 8901234 5 6789012 3 4567890 1 2345678 9 0123456 7 8901234 5 6789012 3
    // -----------------------------------------------------------------------------
    // 0000000 0 0000000 1 0000000 1 0000000 1 0000000 1 0000000 1 0000000 1 0000000 1
    // premable  xxxxxxx o xxxxxxx o xxxxxxx o xxxxxxx o xxxxxxx o xxxxxxx o xxxxxxx o

    // 64    70            80          90          100         110           120
    // |     |             |           |           |           |             |
    // 4567890 1 2345678 9 0123456 7 8901234 5 6789012 3 4567890 1 2345678 9 0123456 7
    // -----------------------------------------------------------------------------
    // 0000000 1 0000000 1 0000000 1 0110111 0 0011000 1 0000001 0 0001100 1 1001010 0
    // xxxxxxx o xxxxxxx o xxxxxxx o xswffff o ffffccc o ccccccc o ccccccw o ppppppp o
    //                                  |---115---||---------71---------|
    // s = format start bit, o = odd parity of last 7 bits
    // f = facility code, c = card number
    // w = wiegand parity, x = extra space for other formats
    // p = CRC8maxim checksum
    // (26 bit format shown)

    //get bytes for checksum calc
    uint8_t checksum = bytebits_to_byte(bits + idx + 120, 8);
    uint8_t csBuff[14] = {0x00};
    for (uint8_t i = 0; i < 13; i++) {
        csBuff[i] = bytebits_to_byte(bits + idx + 16 + (i * 8), 8);
    }
    //check checksum calc
    //checksum calc thanks to ICEMAN!!
    uint32_t checkCS =  CRC8Maxim(csBuff, 13);

    //get raw ID before removing parities
    uint32_t rawLo = bytebits_to_byte(bits + idx + 96, 32);
    uint32_t rawHi = bytebits_to_byte(bits + idx + 64, 32);
    uint32_t rawHi2 = bytebits_to_byte(bits + idx + 32, 32);
    uint32_t rawHi3 = bytebits_to_byte(bits + idx, 32);

    size = removeParity(bits, idx + 8, 8, 1, 120);
    if (size != 105) {
        if (size == 0)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Pyramid: parity check failed - IDX: %d, hi3: %08X", idx, rawHi3);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - Pyramid: at parity check - tag size does not match Pyramid format, SIZE: %zu, IDX: %d, hi3: %08X", size, idx, rawHi3);
        return PM3_ESOFT;
    }

    // ok valid card found!

    // Index map
    // 0         10        20        30        40        50        60        70
    // |         |         |         |         |         |         |         |
    // 01234567890123456789012345678901234567890123456789012345678901234567890
    // -----------------------------------------------------------------------
    // 00000000000000000000000000000000000000000000000000000000000000000000000
    // xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

    // 71         80         90          100
    // |          |          |           |
    // 1 2 34567890 1234567890123456 7 8901234
    // ---------------------------------------
    // 1 1 01110011 0000000001000110 0 1001010
    // s w ffffffff cccccccccccccccc w ppppppp
    //     |--115-| |------71------|
    // s = format start bit, o = odd parity of last 7 bits
    // f = facility code, c = card number
    // w = wiegand parity, x = extra space for other formats
    // p = CRC8-Maxim checksum
    // (26 bit format shown)

    //find start bit to get fmtLen
    int j;
    for (j = 0; j < size; ++j) {
        if (bits[j]) break;
    }

    uint8_t fmtLen = size - j - 8;

    if (fmtLen == 26) {
        uint32_t fc = bytebits_to_byte(bits + 73, 8);
        uint32_t cardnum = bytebits_to_byte(bits + 81, 16);
        uint32_t code1 = bytebits_to_byte(bits + 72, fmtLen);
        PrintAndLogEx(SUCCESS, "Pyramid - len: " _GREEN_("%d") ", FC: " _GREEN_("%d") " Card: " _GREEN_("%d") " - Wiegand: " _GREEN_("%x")", Raw: %08x%08x%08x%08x", fmtLen, fc, cardnum, code1, rawHi3, rawHi2, rawHi, rawLo);
    } else if (fmtLen == 45) {
        fmtLen = 42; //end = 10 bits not 7 like 26 bit fmt
        uint32_t fc = bytebits_to_byte(bits + 53, 10);
        uint32_t cardnum = bytebits_to_byte(bits + 63, 32);
        PrintAndLogEx(SUCCESS, "Pyramid - len: " _GREEN_("%d") ", FC: " _GREEN_("%d") " Card: " _GREEN_("%d") ", Raw: %08x%08x%08x%08x", fmtLen, fc, cardnum, rawHi3, rawHi2, rawHi, rawLo);
        /*
            } else if (fmtLen > 32) {
                uint32_t cardnum = bytebits_to_byte(bits + 81, 16);
                //uint32_t code1 = bytebits_to_byte(bits+(size-fmtLen),fmtLen-32);
                //code2 = bytebits_to_byte(bits+(size-32),32);
                PrintAndLogEx(SUCCESS, "Pyramid ID Found - BitLength: %d -unknown BitLength- (%d), Raw: %08x%08x%08x%08x", fmtLen, cardnum, rawHi3, rawHi2, rawHi, rawLo);
                */
    } else {
        uint32_t cardnum = bytebits_to_byte(bits + 81, 16);
        //uint32_t code1 = bytebits_to_byte(bits+(size-fmtLen),fmtLen);
        PrintAndLogEx(SUCCESS, "Pyramid - len: " _GREEN_("%d") " -unknown- Card: " _GREEN_("%d") ", Raw: %08x%08x%08x%08x", fmtLen, cardnum, rawHi3, rawHi2, rawHi, rawLo);
    }

    PrintAndLogEx(DEBUG, "DEBUG: Pyramid: checksum : 0x%02X - 0x%02X ( %s )"
                  , checksum
                  , checkCS
                  , (checksum == checkCS) ? _GREEN_("ok") : _RED_("fail")
                 );

    PrintAndLogEx(DEBUG, "DEBUG: Pyramid: idx: %d, Len: %d, Printing DemodBuffer:", idx, 128);
    if (g_debugMode) {
        printDemodBuff(0, false, false, false);
    }

    return PM3_SUCCESS;
}

static int CmdPyramidDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf pyramid demod",
                  "Try to find Farpoint/Pyramid preamble, if found decode / descramble data",
                  "lf pyramid demod"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return demodPyramid(true);
}

static int CmdPyramidReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf pyramid reader",
                  "read a Farpointe/Pyramid tag",
                  "lf pyramid reader -@   -> continuous reader mode"
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
        lf_read(false, 15000);
        demodPyramid(true);
    } while (cm && !kbd_enter_pressed());

    return PM3_SUCCESS;
}

static int CmdPyramidClone(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf pyramid clone",
                  "clone a Farpointe/Pyramid tag to a T55x7, Q5/T5555 or EM4305/4469 tag.\n"
                  "The facility-code is 8-bit and the card number is 16-bit. Larger values are truncated.\n"
                  "Currently only works on 26bit",
                  "lf pyramid clone --fc 123 --cn 11223       -> encode for T55x7 tag\n"
                  "lf pyramid clone --raw 0001010101010101010440013223921c -> idem, raw mode\n"
                  "lf pyramid clone --fc 123 --cn 11223 --q5  -> encode for Q5/T5555 tag\n"
                  "lf pyramid clone --fc 123 --cn 11223 --em  -> encode for EM4305/4469\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0(NULL, "fc", "<dec>", "8-bit value facility code"),
        arg_u64_0(NULL, "cn", "<dec>", "16-bit value card number"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_str0("r", "raw", "<hex>", "raw hex data. 16 bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint32_t fc = arg_get_u32_def(ctx, 1, -1);
    uint32_t cn = arg_get_u32_def(ctx, 2, -1);
    bool q5 = arg_get_lit(ctx, 3);
    bool em = arg_get_lit(ctx, 4);

    int raw_len = 0;
    // skip first block,  4*4 = 16 bytes left
    uint8_t raw[16] = {0};
    int res = CLIParamHexToBuf(arg_get_str(ctx, 5), raw, sizeof raw, &raw_len);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    CLIParserFree(ctx);

    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }

    bool use_raw = (raw_len > 0);

    if (fc == -1 && cn == -1) {
        if (use_raw == false) {
            PrintAndLogEx(FAILED, "Must specify either raw data to clone, or fc/cn");
            return PM3_EINVARG;
        }
    } else {
        // --raw and --fc/cn are mutually exclusive
        if (use_raw) {
            PrintAndLogEx(FAILED, "Can't specify both raw and fc/cn at the same time");
            return PM3_EINVARG;
        }
    }

    uint32_t blocks[5];
    if (use_raw) {
        for (uint8_t i = 1; i < ARRAYLEN(blocks); i++) {
            blocks[i] = bytes_to_num(raw + ((i - 1) * 4), sizeof(uint32_t));
        }
    } else {

        uint8_t *bs = calloc(128, sizeof(uint8_t));
        if (bs == NULL) {
            return PM3_EMALLOC;
        }

        uint32_t facilitycode = (fc & 0x000000FF);
        uint32_t cardnumber = (cn & 0x0000FFFF);

        if (getPyramidBits(facilitycode, cardnumber, bs) != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Error with tag bitstream generation.");
            return PM3_ESOFT;
        }

        blocks[1] = bytebits_to_byte(bs, 32);
        blocks[2] = bytebits_to_byte(bs + 32, 32);
        blocks[3] = bytebits_to_byte(bs + 64, 32);
        blocks[4] = bytebits_to_byte(bs + 96, 32);

        free(bs);
    }

    //Pyramid - compat mode, FSK2a, data rate 50, 4 data blocks
    blocks[0] = T55x7_MODULATION_FSK2a | T55x7_BITRATE_RF_50 | 4 << T55x7_MAXBLOCK_SHIFT;
    char cardtype[16] = {"T55x7"};

    // Q5
    if (q5) {
        blocks[0] = T5555_FIXED | T5555_MODULATION_FSK2 | T5555_INVERT_OUTPUT | T5555_SET_BITRATE(50) | 4 << T5555_MAXBLOCK_SHIFT;
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    }
    // EM4305
    if (em) {
        PrintAndLogEx(WARNING, "Beware some EM4305 tags don't support FSK and datarate = RF/50, check your tag copy!");
        blocks[0] = EM4305_PYRAMID_CONFIG_BLOCK;
        // invert FSK data
        for (uint8_t i = 1; i < ARRAYLEN(blocks) ; i++) {
            blocks[i] = blocks[i] ^ 0xFFFFFFFF;
        }
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
    }

    PrintAndLogEx(INFO, "Preparing to clone Farpointe/Pyramid to " _YELLOW_("%s") " from %s.",
                  cardtype,
                  use_raw ? "raw hex" : "specified data"
                 );
    print_blocks(blocks,  ARRAYLEN(blocks));

    if (em) {
        res = em4x05_clone_tag(blocks, ARRAYLEN(blocks), 0, false);
    } else {
        res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    }
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf pyramid reader`") " to verify");
    return res;
}

static int CmdPyramidSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf pyramid sim",
                  "Enables simulation of Farpointe/Pyramid card with specified card number.\n"
                  "Simulation runs until the button is pressed or another USB command is issued.\n"
                  "The facility-code is 8-bit and the card number is 16-bit. Larger values are truncated.\n"
                  "Currently work only on 26bit",
                  "lf pyramid sim --fc 123 --cn 1337\n"
                  "lf pyramid clone --raw 0001010101010101010440013223921c"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0(NULL, "fc", "<dec>", "8-bit value facility code"),
        arg_u64_0(NULL, "cn", "<dec>", "16-bit value card number"),
        arg_str0("r", "raw", "<hex>", "raw hex data. 16 bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    uint32_t fc = arg_get_u32_def(ctx, 1, -1);
    uint32_t cn = arg_get_u32_def(ctx, 2, -1);

    int raw_len = 0;
    // skip first block,  4*4 = 16 bytes left
    uint8_t raw[16] = {0};
    int res = CLIParamHexToBuf(arg_get_str(ctx, 5), raw, sizeof raw, &raw_len);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    CLIParserFree(ctx);

    bool use_raw = (raw_len > 0);

    if (fc == -1 && cn == -1) {
        if (use_raw == false) {
            PrintAndLogEx(FAILED, "Must specify either raw data to clone, or fc/cn");
            return PM3_EINVARG;
        }
    } else {
        // --raw and --fc/cn are mutually exclusive
        if (use_raw) {
            PrintAndLogEx(FAILED, "Can't specify both raw and fc/cn at the same time");
            return PM3_EINVARG;
        }
    }

    uint8_t bs[sizeof(raw) * 8];
    memset(bs, 0x00, sizeof(bs));

    if (use_raw == false) {
        uint32_t facilitycode = (fc & 0x000000FF);
        uint32_t cardnumber = (cn & 0x0000FFFF);

        if (getPyramidBits(facilitycode, cardnumber, bs) != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Error with tag bitstream generation.");
            return PM3_ESOFT;
        }
        PrintAndLogEx(SUCCESS, "Simulating Farpointe/Pyramid - Facility Code: " _YELLOW_("%u") ", CardNumber: " _YELLOW_("%u"), facilitycode, cardnumber);
    } else {
        PrintAndLogEx(SUCCESS, "Simulating Farpointe/Pyramid - raw " _YELLOW_("%s"), sprint_hex_inrow(raw, sizeof(raw)));
        bytes_to_bytebits(raw, sizeof(raw), bs);
    }

    // Pyramid uses:  fcHigh: 10, fcLow: 8, clk: 50, invert: 0
    lf_fsksim_t *payload = calloc(1, sizeof(lf_fsksim_t) + sizeof(bs));
    payload->fchigh = 10;
    payload->fclow =  8;
    payload->separator = 0;
    payload->clock = 50;
    memcpy(payload->data, bs, sizeof(bs));

    clearCommandBuffer();
    SendCommandNG(CMD_LF_FSK_SIMULATE, (uint8_t *)payload,  sizeof(lf_fsksim_t) + sizeof(bs));
    free(payload);

    return lfsim_wait_check(CMD_LF_FSK_SIMULATE);
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,          AlwaysAvailable, "this help"},
    {"demod",   CmdPyramidDemod,  AlwaysAvailable, "demodulate a Pyramid FSK tag from the GraphBuffer"},
    {"reader",  CmdPyramidReader, IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone",   CmdPyramidClone,  IfPm3Lf,         "clone pyramid tag to T55x7 or Q5/T5555"},
    {"sim",     CmdPyramidSim,    IfPm3Lf,         "simulate pyramid tag"},
    {NULL, NULL, NULL, NULL}
};

int CmdLFPyramid(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

// Works for 26bits.
int getPyramidBits(uint32_t fc, uint32_t cn, uint8_t *pyramidBits) {

    uint8_t pre[128];
    memset(pre, 0x00, sizeof(pre));

    // format start bit
    pre[79] = 1;

    // Get 26 wiegand from FacilityCode, CardNumber
    uint8_t wiegand[24];
    memset(wiegand, 0x00, sizeof(wiegand));
    num_to_bytebits(fc, 8, wiegand);
    num_to_bytebits(cn, 16, wiegand + 8);

    // add wiegand parity bits (dest, source, len)
    wiegand_add_parity(pre + 80, wiegand, 24);

    // add paritybits (bitsource, dest, sourcelen, paritylen, parityType (odd, even,)
    addParity(pre + 8, pyramidBits + 8, 102, 8, 1);

    // add checksum
    uint8_t csBuff[13];
    for (uint8_t i = 0; i < 13; i++)
        csBuff[i] = bytebits_to_byte(pyramidBits + 16 + (i * 8), 8);

    uint32_t crc = CRC8Maxim(csBuff, 13);
    num_to_bytebits(crc, 8, pyramidBits + 120);
    return PM3_SUCCESS;
}

// FSK Demod then try to locate a Farpointe Data (pyramid) ID
int detectPyramid(uint8_t *dest, size_t *size, int *waveStartIdx) {
    //make sure buffer has data
    if (*size < 128 * 50) return -1;

    //test samples are not just noise
    if (getSignalProperties()->isnoise) return -2;

    // FSK demodulator RF/50 FSK 10,8
    *size = fskdemod(dest, *size, 50, 1, 10, 8, waveStartIdx);  // pyramid fsk2

    //did we get a good demod?
    if (*size < 128) return -3;

    size_t startIdx = 0;
    uint8_t preamble[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1};
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx))
        return -4; //preamble not found

    // wrong size?  (between to preambles)
    if (*size < 128) return -5;

    return (int)startIdx;
}

