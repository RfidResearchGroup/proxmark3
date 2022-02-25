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
// Low frequency TI commands
//-----------------------------------------------------------------------------

#include "cmdlfti.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "cmdparser.h"    // command_t
#include "commonutil.h"
#include "comms.h"
#include "crc16.h"
#include "ui.h"
#include "proxgui.h"
#include "graph.h"
#include "cliparser.h"

static int CmdHelp(const char *Cmd);

int demodTI(bool verbose) {
    (void) verbose; // unused so far
    /* MATLAB as follows:
      f_s = 2000000;  % sampling frequency
      f_l = 123200;   % low FSK tone
      f_h = 134200;   % high FSK tone

      T_l = 119e-6;   % low bit duration
      T_h = 130e-6;   % high bit duration

      l = 2*pi*ones(1, floor(f_s*T_l))*(f_l/f_s);
      h = 2*pi*ones(1, floor(f_s*T_h))*(f_h/f_s);

      l = sign(sin(cumsum(l)));
      h = sign(sin(cumsum(h)));
    */

    // 2M*16/134.2k = 238
    static const int LowTone[] = {
        1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1, 1,    -1, -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1, 1,    -1, -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1, 1,    -1, -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1, 1,    -1, -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1, 1,    -1, -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1, 1,    -1, -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1, 1,    -1, -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1, 1,    -1, -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1, 1,    -1, -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1, 1,    -1, -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1, 1,    -1, -1
    };
    // 2M*16/123.2k = 260
    static const int HighTone[] = {
        1, 1, 1, 1, 1, 1, 1, 1,   -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1, 1,   -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1,      -1, -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1,      -1, -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1,      -1, -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1,      -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1, 1,   -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1, 1,   -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1,      -1, -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1,      -1, -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1,      -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1, 1,   -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1, 1,   -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1, 1,   -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1,      -1, -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1,      -1, -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1,      -1, -1, -1, -1, -1, -1, -1,
        1, 1, 1, 1, 1, 1, 1, 1
    };

    save_restoreGB(GRAPH_SAVE);

    int lowLen = ARRAYLEN(LowTone);
    int highLen = ARRAYLEN(HighTone);
    int convLen = (highLen > lowLen) ? highLen : lowLen;
    int i, j, TagType;
    int lowSum = 0, highSum = 0;
    int lowTot = 0, highTot = 0;
    int retval = PM3_ESOFT;

    if (g_GraphTraceLen < convLen) {
        return retval;
    }
    for (i = 0; i < g_GraphTraceLen - convLen; i++) {
        lowSum = 0;
        highSum = 0;

        for (j = 0; j < lowLen; j++) {
            lowSum += LowTone[j] * g_GraphBuffer[i + j];
        }
        for (j = 0; j < highLen; j++) {
            highSum += HighTone[j] * g_GraphBuffer[i + j];
        }
        lowSum = abs((100 * lowSum) / lowLen);
        highSum = abs((100 * highSum) / highLen);
        lowSum = (lowSum < 0) ? -lowSum : lowSum;
        highSum = (highSum < 0) ? -highSum : highSum;

        g_GraphBuffer[i] = (highSum << 16) | lowSum;
    }

    for (i = 0; i < g_GraphTraceLen - convLen - 16; i++) {
        lowTot = 0;
        highTot = 0;
        // 16 and 15 are f_s divided by f_l and f_h, rounded
        for (j = 0; j < 16; j++) {
            lowTot += (g_GraphBuffer[i + j] & 0xffff);
        }
        for (j = 0; j < 15; j++) {
            highTot += (g_GraphBuffer[i + j] >> 16);
        }
        g_GraphBuffer[i] = lowTot - highTot;
    }

    g_GraphTraceLen -= (convLen + 16);

    RepaintGraphWindow();

    // TI tag data format is 16 prebits, 8 start bits, 64 data bits,
    // 16 crc CCITT bits, 8 stop bits, 15 end bits

    // the 16 prebits are always low
    // the 8 start and stop bits of a tag must match
    // the start/stop prebits of a ro tag are 01111110
    // the start/stop prebits of a rw tag are 11111110
    // the 15 end bits of a ro tag are all low
    // the 15 end bits of a rw tag match bits 15-1 of the data bits

    // Okay, so now we have unsliced soft decisions;
    // find bit-sync, and then get some bits.
    // look for 17 low bits followed by 6 highs (common pattern for ro and rw tags)
    int max = 0, maxPos = 0;
    for (i = 0; i < 6000; i++) {
        int dec = 0;
        // searching 17 consecutive lows
        for (j = 0; j < 17 * lowLen; j++) {
            dec -= g_GraphBuffer[i + j];
        }
        // searching 7 consecutive highs
        for (; j < 17 * lowLen + 6 * highLen; j++) {
            dec += g_GraphBuffer[i + j];
        }
        if (dec > max) {
            max = dec;
            maxPos = i;
        }
    }

    // place a marker in the buffer to visually aid location
    // of the start of sync
    g_GraphBuffer[maxPos] = 800;
    g_GraphBuffer[maxPos + 1] = -800;

    // advance pointer to start of actual data stream (after 16 pre and 8 start bits)
    maxPos += 17 * lowLen;
    maxPos +=  6 * highLen;

    // place a marker in the buffer to visually aid location
    // of the end of sync
    g_GraphBuffer[maxPos] = 800;
    g_GraphBuffer[maxPos + 1] = -800;

    PrintAndLogEx(DEBUG, "actual data bits start at sample %d", maxPos);
    PrintAndLogEx(DEBUG, "length %d/%d", highLen, lowLen);

    uint8_t bits[1 + 64 + 16 + 8 + 16];
    bits[sizeof(bits) - 1] = '\0';

    uint32_t shift3 = 0x7e000000, shift2 = 0, shift1 = 0, shift0 = 0;

    for (i = 0; i < ARRAYLEN(bits) - 1; i++) {
        int high = 0, low = 0;
        for (j = 0; j < lowLen; j++) {
            low -= g_GraphBuffer[maxPos + j];
        }
        for (j = 0; j < highLen; j++) {
            high += g_GraphBuffer[maxPos + j];
        }

        if (high > low) {
            bits[i] = '1';
            maxPos += highLen;
            // bitstream arrives lsb first so shift right
            shift3 |= (1u << 31);
        } else {
            bits[i] = '.';
            maxPos += lowLen;
        }

        // 128 bit right shift register
        shift0 = (shift0 >> 1) | (shift1 << 31);
        shift1 = (shift1 >> 1) | (shift2 << 31);
        shift2 = (shift2 >> 1) | (shift3 << 31);
        shift3 >>= 1;

        // place a marker in the buffer between bits to visually aid location
        g_GraphBuffer[maxPos] = 800;
        g_GraphBuffer[maxPos + 1] = -800;
    }

    RepaintGraphWindow();

    PrintAndLogEx(DEBUG, "TI tag : raw tag bits | %s", bits);

    TagType = (shift3 >> 8) & 0xFF;
    if (TagType != ((shift0 >> 16) & 0xFF)) {
        PrintAndLogEx(DEBUG, "TI tag : Error: start and stop bits do not match!");
        goto out;
    } else if (TagType == 0x7E) {
        PrintAndLogEx(INFO, "Readonly TI tag detected.");
        retval = PM3_SUCCESS;
        goto out;
    } else if (TagType == 0xFE) {
        PrintAndLogEx(INFO, "Rewriteable TI tag detected.");

        // put 64 bit data into shift1 and shift0
        shift0 = (shift0 >> 24) | (shift1 << 8);
        shift1 = (shift1 >> 24) | (shift2 << 8);

        // align 16 bit crc into lower half of shift2
        shift2 = ((shift2 >> 24) | (shift3 << 8)) & 0x0FFFF;

        // align 16 bit "end bits" or "ident" into lower half of shift3
        shift3 >>= 16;

        // only 15 bits compare, last bit of ident is not valid
        if ((shift3 ^ shift0) & 0x7FFF) {
            PrintAndLogEx(WARNING, "Warning: Ident mismatch!");
        }
        // WARNING the order of the bytes in which we calc crc below needs checking
        // i'm 99% sure the crc algorithm is correct, but it may need to eat the
        // bytes in reverse or something
        // calculate CRC
        uint8_t raw[8] = {
            (shift0 >>  0) & 0xFF,
            (shift0 >>  8) & 0xFF,
            (shift0 >> 16) & 0xFF,
            (shift0 >> 24) & 0xFF,
            (shift1 >>  0) & 0xFF,
            (shift1 >>  8) & 0xFF,
            (shift1 >> 16) & 0xFF,
            (shift1 >> 24) & 0xFF
        };
        init_table(CRC_KERMIT);
        uint16_t calccrc = crc16_kermit(raw, sizeof(raw));
        const char *crc_str = (calccrc == (shift2 & 0xFFFF)) ? _GREEN_("ok") : _RED_("fail");
        PrintAndLogEx(INFO, "Tag data = %08X%08X  [%04X] ( %s )", shift1, shift0, calccrc, crc_str);

        if (calccrc != (shift2 & 0xFFFF))
            PrintAndLogEx(WARNING, "Warning: CRC mismatch, calculated %04X, got %04X", calccrc, shift2 & 0xFFFF);

        retval = PM3_SUCCESS;
        goto out;
    } else {
        PrintAndLogEx(WARNING, "Unknown tag type.");
    }

out:
    if (retval != PM3_SUCCESS)
        save_restoreGB(GRAPH_RESTORE);

    return retval;
}

static int CmdTIDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf ti demod",
                  "Try to find TI preamble, if found decode / descramble data",
                  "lf ti demod"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return demodTI(true);
}

// read a TI tag and return its ID
static int CmdTIReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf ti reader",
                  "read a TI tag",
                  "lf ti reader -@   -> continuous reader mode"
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
        clearCommandBuffer();
        SendCommandNG(CMD_LF_TI_READ, NULL, 0);
    } while (cm && !kbd_enter_pressed());

    return PM3_SUCCESS;
}

// write new data to a r/w TI tag
static int CmdTIWrite(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf ti write",
                  "write to a r/w TI tag.",
                  "lf ti write --raw 1122334455667788\n"
                  "lf ti write --raw 1122334455667788 --crc 1122\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("r", "raw", "<hex>", "raw hex data. 8 bytes max"),
        arg_str0(NULL, "crc", "<hex>", "optional - crc"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    uint8_t raw[8] = {0};
    CLIGetHexWithReturn(ctx, 1, raw, &raw_len);

    int crc_len = 0;
    uint8_t crc[2] = {0};
    CLIGetHexWithReturn(ctx, 2, crc, &crc_len);
    CLIParserFree(ctx);

    struct {
        uint32_t high;
        uint32_t low;
        uint16_t crc;
    } PACKED payload;

    payload.high = bytes_to_num(raw, 4);
    payload.low = bytes_to_num(raw + 4, 4);
    payload.crc = bytes_to_num(crc, crc_len);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_TI_WRITE, (uint8_t *)&payload, sizeof(payload));
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf ti reader`") " to verify");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,      AlwaysAvailable, "This help"},
    {"demod",   CmdTIDemod,   AlwaysAvailable, "Demodulate raw bits for TI LF tag from the GraphBuffer"},
    {"reader",  CmdTIReader,  IfPm3Lf,         "Read and decode a TI 134 kHz tag"},
    {"write",   CmdTIWrite,   IfPm3Lf,         "Write new data to a r/w TI 134 kHz tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFTI(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
