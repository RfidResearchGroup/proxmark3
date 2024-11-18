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
// Low frequency EM410x commands
//-----------------------------------------------------------------------------

#include "cmdlfem410x.h"
#include "cmdlfem4x50.h"
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdlib.h>
#include "fileutils.h"
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "commonutil.h"
#include "common.h"
#include "util_posix.h"
#include "protocols.h"
#include "ui.h"
#include "proxgui.h"
#include "graph.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "lfdemod.h"
#include "generator.h"
#include "cliparser.h"
#include "cmdhw.h"
#include "hitag.h"

static uint64_t gs_em410xid = 0;

static int CmdHelp(const char *Cmd);
/* Read the ID of an EM410x tag.
 * Format:
 *   1111 1111 1           <-- standard non-repeatable header
 *   XXXX [row parity bit] <-- 10 rows of 5 bits for our 40 bit tag ID
 *   ....
 *   CCCC                  <-- each bit here is parity for the 10 bits above in corresponding column
 *   0                     <-- stop bit, end of tag
 */

// Construct the graph for emulating an EM410X tag
static void em410x_construct_emul_graph(uint8_t *uid, uint8_t clock, uint8_t gap) {

    // clear our graph
    ClearGraph(true);

    // write 16 zero bit sledge
    for (uint8_t i = 0; i < gap; i++)
        AppendGraph(false, clock, 0);

    // write 9 start bits
    for (uint8_t i = 0; i < 9; i++)
        AppendGraph(false, clock, 1);

    uint8_t bs[8], parity[8];
    memset(parity, 0, sizeof(parity));

    for (uint8_t i = 0; i < 5; i++) {

        for (uint8_t j = 0; j < 8; j++) {
            bs[j] = (uid[i] >> (7 - j) & 1);
        }
        PrintAndLogEx(DEBUG, "EM ID[%d] 0x%02x (%s)", i, uid[i], sprint_bytebits_bin(bs, 4));

        for (uint8_t j = 0; j < 2; j++) {
            // append each bit
            AppendGraph(false, clock, bs[0 + (4 * j)]);
            AppendGraph(false, clock, bs[1 + (4 * j)]);
            AppendGraph(false, clock, bs[2 + (4 * j)]);
            AppendGraph(false, clock, bs[3 + (4 * j)]);

            // append parity bit
            AppendGraph(false, clock, bs[0 + (4 * j)] ^ bs[1 + (4 * j)] ^ bs[2 + (4 * j)] ^ bs[3 + (4 * j)]);

            // keep track of column parity
            parity[0] ^= bs[0 + (4 * j)];
            parity[1] ^= bs[1 + (4 * j)];
            parity[2] ^= bs[2 + (4 * j)];
            parity[3] ^= bs[3 + (4 * j)];
        }
    }

    // parity columns
    AppendGraph(false, clock, parity[0]);
    AppendGraph(false, clock, parity[1]);
    AppendGraph(false, clock, parity[2]);
    AppendGraph(false, clock, parity[3]);

    // stop bit
    AppendGraph(true, clock, 0);
}

// print 64 bit EM410x ID in multiple formats
void printEM410x(uint32_t hi, uint64_t id, bool verbose, int type) {

    if (verbose == false) {
        if (type & 0x1) { // Short ID
            PrintAndLogEx(SUCCESS, "EM 410x ID "_GREEN_("%010" PRIX64), id);
        }
        if (type & 0x2) { // Long ID
            PrintAndLogEx(SUCCESS, "EM 410x XL ID "_GREEN_("%06X%016" PRIX64), hi, id);
        }
        if (type & 0x4) { // Short Extended ID
            uint64_t data = (id << 20) >> 20;
            // Convert back to Short ID
            id = ((uint64_t)hi << 16) | (id >> 48);
            if ((data & 0xFFFFFFFF) == 0) {
                PrintAndLogEx(SUCCESS, "EM 410x ID "_GREEN_("%010" PRIX64)" Electra "_GREEN_("%03" PRIu64), id, data >> 32);
            } else {
                PrintAndLogEx(SUCCESS, "EM 410x ID "_GREEN_("%010" PRIX64)" on 128b frame with data "_GREEN_("%011" PRIX64), id, data);
            }
        }
        return;
    }

    if (type & 0x2) { // Long ID
        //output 88 bit em id
        PrintAndLogEx(SUCCESS, "EM 410x XL ID "_GREEN_("%06X%016" PRIX64)" ( RF/%d )", hi, id, g_DemodClock);
    }
    if (type & 0x4) { // Short Extended ID
        PrintAndLogEx(SUCCESS, "EM 410x Short ID found on a 128b frame");
        uint64_t data = (id << 20) >> 20;
        PrintAndLogEx(SUCCESS, "    Data after ID: "_GREEN_("%011" PRIX64), data);
        if ((data & 0xFFFFFFFF) == 0) {
            PrintAndLogEx(SUCCESS, "    Possibly an Electra (RO), 0x"_GREEN_("%03" PRIX64)" = "_GREEN_("%03" PRIu64), data >> 32, data >> 32);
        }
        PrintAndLogEx(SUCCESS, "    Short ID details:");
        // Convert back to Short ID
        id = ((uint64_t)hi << 16) | (id >> 48);
    }
    if (type & (0x4 | 0x1)) { // Short Extended or Short ID
        //output 40 bit em id
        uint64_t n = 1;
        uint64_t id2lo = 0;
        uint8_t m, i;
        for (m = 5; m > 0; m--) {
            for (i = 0; i < 8; i++) {
                id2lo = (id2lo << 1LL) | ((id & (n << (i + ((m - 1) * 8)))) >> (i + ((m - 1) * 8)));
            }
        }
        PrintAndLogEx(SUCCESS, "EM 410x ID "_GREEN_("%010" PRIX64), id);
        PrintAndLogEx(SUCCESS, "EM410x ( RF/%d )", g_DemodClock);
        PrintAndLogEx(INFO, "-------- " _CYAN_("Possible de-scramble patterns") " ---------");
        PrintAndLogEx(SUCCESS, "Unique TAG ID      : %010" PRIX64, id2lo);
        PrintAndLogEx(INFO, "HoneyWell IdentKey");
        PrintAndLogEx(SUCCESS, "    DEZ 8          : %08" PRIu64, id & 0xFFFFFF);
        PrintAndLogEx(SUCCESS, "    DEZ 10         : %010" PRIu64, id & 0xFFFFFFFF);
        PrintAndLogEx(SUCCESS, "    DEZ 5.5        : %05" PRIu64 ".%05" PRIu64, (id >> 16LL) & 0xFFFF, (id & 0xFFFF));
        PrintAndLogEx(SUCCESS, "    DEZ 3.5A       : %03" PRIu64 ".%05" PRIu64, (id >> 32ll), (id & 0xFFFF));
        PrintAndLogEx(SUCCESS, "    DEZ 3.5B       : %03" PRIu64 ".%05" PRIu64, (id & 0xFF000000) >> 24, (id & 0xFFFF));
        PrintAndLogEx(SUCCESS, "    DEZ 3.5C       : %03" PRIu64 ".%05" PRIu64, (id & 0xFF0000) >> 16, (id & 0xFFFF));
        PrintAndLogEx(SUCCESS, "    DEZ 14/IK2     : %014" PRIu64, id);
        PrintAndLogEx(SUCCESS, "    DEZ 15/IK3     : %015" PRIu64, id2lo);
        PrintAndLogEx(SUCCESS, "    DEZ 20/ZK      : %02" PRIu64 "%02" PRIu64 "%02" PRIu64 "%02" PRIu64 "%02" PRIu64 "%02" PRIu64 "%02" PRIu64 "%02" PRIu64 "%02" PRIu64 "%02" PRIu64,
                      (id2lo & 0xf000000000) >> 36,
                      (id2lo & 0x0f00000000) >> 32,
                      (id2lo & 0x00f0000000) >> 28,
                      (id2lo & 0x000f000000) >> 24,
                      (id2lo & 0x0000f00000) >> 20,
                      (id2lo & 0x00000f0000) >> 16,
                      (id2lo & 0x000000f000) >> 12,
                      (id2lo & 0x0000000f00) >> 8,
                      (id2lo & 0x00000000f0) >> 4,
                      (id2lo & 0x000000000f)
                     );
        PrintAndLogEx(INFO, "");

        uint64_t paxton = (((id >> 32) << 24) | (id & 0xffffff))  + 0x143e00;
        PrintAndLogEx(SUCCESS, "Other              : %05" PRIu64 "_%03" PRIu64 "_%08" PRIu64, (id & 0xFFFF), ((id >> 16LL) & 0xFF), (id & 0xFFFFFF));
        PrintAndLogEx(SUCCESS, "Pattern Paxton     : %" PRIu64 " [0x%" PRIX64 "]", paxton, paxton);

        uint32_t p1id = (id & 0xFFFFFF);
        uint8_t arr[32] = {0x00};
        int j = 23;
        for (int k = 0 ; k < 24; ++k, --j) {
            arr[k] = (p1id >> k) & 1;
        }

        uint32_t p1  = 0;

        p1 |= arr[23] << 21;
        p1 |= arr[22] << 23;
        p1 |= arr[21] << 20;
        p1 |= arr[20] << 22;

        p1 |= arr[19] << 18;
        p1 |= arr[18] << 16;
        p1 |= arr[17] << 19;
        p1 |= arr[16] << 17;

        p1 |= arr[15] << 13;
        p1 |= arr[14] << 15;
        p1 |= arr[13] << 12;
        p1 |= arr[12] << 14;

        p1 |= arr[11] << 6;
        p1 |= arr[10] << 2;
        p1 |= arr[9]  << 7;
        p1 |= arr[8]  << 1;

        p1 |= arr[7]  << 0;
        p1 |= arr[6]  << 8;
        p1 |= arr[5]  << 11;
        p1 |= arr[4]  << 3;

        p1 |= arr[3]  << 10;
        p1 |= arr[2]  << 4;
        p1 |= arr[1]  << 5;
        p1 |= arr[0]  << 9;
        PrintAndLogEx(SUCCESS, "Pattern 1          : %d [0x%X]", p1, p1);

        uint16_t sebury1 = id & 0xFFFF;
        uint8_t  sebury2 = (id >> 16) & 0x7F;
        uint32_t sebury3 = id & 0x7FFFFF;
        PrintAndLogEx(SUCCESS, "Pattern Sebury     : %d %d %d  [0x%X 0x%X 0x%X]", sebury1, sebury2, sebury3, sebury1, sebury2, sebury3);
        PrintAndLogEx(SUCCESS, "VD / ID            : %03" PRIu64 " / %010" PRIu64, (id >> 32LL) & 0xFFFF, (id & 0xFFFFFFFF));
        PrintAndLogEx(SUCCESS, "Pattern ELECTRA    : %" PRIu64 " %" PRIu64, (id >> 24) & 0xFFFF, id & 0xFFFFFF);

        PrintAndLogEx(INFO, "------------------------------------------------");
    }
}

// takes 1s and 0s and searches for EM410x format - output EM ID
static int ask_em410x_binary_decode(bool verbose, uint32_t *hi, uint64_t *lo, uint8_t *bits, size_t *size, size_t *idx) {

    int ans = Em410xDecode(bits, size, idx, hi, lo);
    if (ans < 0) {
        if (ans == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Em410x not enough samples after demod");
        else if (ans == -4)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Em410x preamble not found");
        else if (ans == -5)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Em410x Size not correct: %zu", size);
        else if (ans == -6)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Em410x parity failed");

        return PM3_ESOFT;
    }

    PrintAndLogEx(DEBUG, "DEBUG: Em410x idx: %zu, Len: %zu, Printing DemodBuffer:", *idx, *size);
    if (g_debugMode) {
        printDemodBuff(0, false, false, true);
    }

    printEM410x(*hi, *lo, verbose, ans);
    gs_em410xid = *lo;
    return PM3_SUCCESS;
}

/* Read the ID of an EM410x tag.
 * Format:
 *   1111 1111 1           <-- standard non-repeatable header
 *   XXXX [row parity bit] <-- 10 rows of 5 bits for our 40 bit tag ID
 *   ....
 *   CCCC                  <-- each bit here is parity for the 10 bits above in corresponding column
 *   0                     <-- stop bit, end of tag
 */
int AskEm410xDecode(bool verbose, uint32_t *hi, uint64_t *lo) {
    size_t idx = 0;
    uint8_t bits[512] = {0};
    size_t size = sizeof(bits);
    if (getDemodBuff(bits, &size) == false) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Em410x problem during copy from ASK demod");
        return PM3_ESOFT;
    }

    int ret = ask_em410x_binary_decode(verbose, hi, lo, bits, &size, &idx);

    if (ret == PM3_SUCCESS) {
        // set g_GraphBuffer for clone or sim command
        setDemodBuff(g_DemodBuffer, (size == 40) ? 64 : 128, idx + 1);
        setClockGrid(g_DemodClock, g_DemodStartIdx + ((idx + 1)*g_DemodClock));
    }
    return ret;
}

int AskEm410xDemod(int clk, int invert, int maxErr, size_t maxLen, bool amplify, uint32_t *hi, uint64_t *lo, bool verbose) {
    bool st = true;

    // em410x simulation etc uses 0/1 as signal data. This must be converted in order to demod it back again
    if (isGraphBitstream()) {
        convertGraphFromBitstream();
    }
    if (ASKDemod_ext(clk, invert, maxErr, maxLen, amplify, false, false, 1, &st) != PM3_SUCCESS) {
        return PM3_ESOFT;
    }
    return AskEm410xDecode(verbose, hi, lo);
}

// this read loops on device side.
// uses the demod in lfops.c
static int CmdEM410xWatch(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 410x watch",
                  "Enables Electro Marine (EM) compatible reader mode printing details of scanned tags.\n"
                  "Run until the button is pressed or another USB command is issued.",
                  "lf em 410x watch"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    PrintAndLogEx(SUCCESS, "Watching for EM410x cards - place tag on Proxmark3 antenna");
    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM410X_WATCH, NULL, 0);
    return lfsim_wait_check(CMD_LF_EM410X_WATCH);
}

// by marshmellow
//takes 3 arguments - clock, invert and maxErr as integers
//attempts to demodulate ask while decoding manchester
//prints binary found and saves in graphbuffer for further commands
int demodEM410x(bool verbose) {
    (void) verbose; // unused so far
    uint32_t hi = 0;
    uint64_t lo = 0;
    return AskEm410xDemod(0, 0, 100, 0, false, &hi, &lo, true);
}

static int CmdEM410xDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 410x demod",
                  "Try to find EM 410x preamble, if found decode / descramble data",
                  "lf em 410x demod                      -> demod an EM410x Tag ID from GraphBuffer\n"
                  "lf em 410x demod --clk 32             -> demod an EM410x Tag ID from GraphBuffer using a clock of RF/32\n"
                  "lf em 410x demod --clk 32 -i          -> demod an EM410x Tag ID from GraphBuffer using a clock of RF/32 and inverting data\n"
                  "lf em 410x demod -i                   -> demod an EM410x Tag ID from GraphBuffer while inverting data\n"
                  "lf em 410x demod --clk 64 -i --err 0  -> demod an EM410x Tag ID from GraphBuffer using a clock of RF/64 and inverting data and allowing 0 demod errors"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0(NULL, "clk", "<dec>", "clock (default autodetect)"),
        arg_u64_0(NULL, "err", "<dec>", "maximum allowed errors (default 100)"),
        arg_u64_0(NULL, "len", "<dec>", "maximum length"),
        arg_lit0("i", "invert", "invert output"),
        arg_lit0("a", "amp", "amplify signal"),
        arg_str0(NULL, "bin", "<bin>", "Binary string i.e 0001001001"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int clk = arg_get_u32_def(ctx, 1, 0);
    int max_err = arg_get_u32_def(ctx, 2, 100);
    size_t max_len = arg_get_u32_def(ctx, 3, 0);
    bool invert = arg_get_lit(ctx, 4);
    bool amplify = arg_get_lit(ctx, 5);
    uint8_t bin[512] = {0};
    int bin_len = sizeof(bin) - 1; // CLIGetStrWithReturn does not guarantee string to be null-terminated
    CLIGetStrWithReturn(ctx, 6, bin, &bin_len);
    CLIParserFree(ctx);

    uint32_t hi = 0;
    uint64_t lo = 0;

    if (bin_len) {
        // 111111111011110010010100001110010101001101110001100100000010010011111100001111
        size_t demodlen = bin_len;
        size_t start_idx = 0;
        uint8_t arr[258];
        binstr_2_binarray(arr, (char *)bin, bin_len);
        return ask_em410x_binary_decode(true, &hi, &lo, arr, &demodlen, &start_idx);
    }

    if (AskEm410xDemod(clk, invert, max_err, max_len, amplify, &hi, &lo, true) != PM3_SUCCESS) {
        return PM3_ESOFT;
    }

    return PM3_SUCCESS;
}

// this read is the "normal" read,  which download lf signal and tries to demod here.
static int CmdEM410xReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 410x reader",
                  "read EM 410x tag",
                  "lf em 410x reader\n"
                  "lf em 410x reader -@                   -> continuous reader mode\n"
                  "lf em 410x reader --clk 32             -> using a clock of RF/32\n"
                  "lf em 410x reader --clk 32 -i          -> using a clock of RF/32 and inverting data\n"
                  "lf em 410x reader -i                   -> inverting data\n"
                  "lf em 410x reader --clk 64 -i --err 0  -> using a clock of RF/64 and inverting data and allowing 0 demod errors"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0(NULL, "clk", "<dec>", "clock (default autodetect)"),
        arg_u64_0(NULL, "err", "<dec>", "maximum allowed errors (default 100)"),
        arg_u64_0(NULL, "len", "<dec>", "maximum length"),
        arg_lit0("i", "invert", "invert output"),
        arg_lit0("a", "amp", "amplify signal"),
        arg_lit0("b", NULL, "break on first found"),
        arg_lit0("@", NULL, "continuous reader mode"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int clk = arg_get_u32_def(ctx, 1, 0);
    int max_err = arg_get_u32_def(ctx, 2, 100);
    size_t max_len = arg_get_u32_def(ctx, 3, 0);
    bool invert = arg_get_lit(ctx, 4);
    bool amplify = arg_get_lit(ctx, 5);
    bool break_first = arg_get_lit(ctx, 6);
    bool cm = arg_get_lit(ctx, 7);
    bool verbose = arg_get_lit(ctx, 8);
    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    do {
        uint32_t hi = 0;
        uint64_t lo = 0;
        lf_read(false, 12288);
        AskEm410xDemod(clk, invert, max_err, max_len, amplify, &hi, &lo, verbose);

        if (break_first && gs_em410xid != 0) {
            break;
        }
    } while (cm && !kbd_enter_pressed());

    return PM3_SUCCESS;
}

// emulate an EM410X tag
static int CmdEM410xSim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 410x sim",
                  "Enables simulation of EM 410x card.\n"
                  "Simulation runs until the button is pressed or another USB command is issued.",
                  "lf em 410x sim --id 0F0368568B\n"
                  "lf em 410x sim --id 0F0368568B --clk 32\n"
                  "lf em 410x sim --id 0F0368568B --gap 0"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0(NULL, "clk", "<dec>", "<32|64> clock (default 64)"),
        arg_str1(NULL, "id", "<hex>", "EM Tag ID number (5 hex bytes)"),
        arg_u64_0(NULL, "gap", "<dec>", "gap (0's) between ID repeats (default 20)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    // clock is 64 in EM410x tags
    int clk = arg_get_u32_def(ctx, 1, 64);
    int uid_len = 0;
    int gap = arg_get_u32_def(ctx, 3, 20);
    uint8_t uid[5] = {0};
    CLIGetHexWithReturn(ctx, 2, uid, &uid_len);
    CLIParserFree(ctx);

    if (uid_len != 5) {
        PrintAndLogEx(FAILED, "EM ID must include 5 hex bytes (10 hex symbols), got " _YELLOW_("%u"), uid_len);
        return PM3_EINVARG;
    }

    PrintAndLogEx(SUCCESS, "Starting simulating EM Tag ID "_YELLOW_("%s")" clock: "_YELLOW_("%d"), sprint_hex_inrow(uid, sizeof(uid)), clk);
    em410x_construct_emul_graph(uid, clk, gap);
    CmdLFSim("");
    return PM3_SUCCESS;
}

static int CmdEM410xBrute(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 410x brute",
                  "bruteforcing by emulating EM 410x tag",
                  "lf em 410x brute -f ids.txt\n"
                  "lf em 410x brute -f ids.txt --clk 32\n"
                  "lf em 410x brute -f ids.txt --delay 3000\n"
                  "lf em 410x brute -f ids.txt --delay 3000 --clk 32\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0(NULL, "clk", "<dec>", "<32|64> clock (default 64)"),
        arg_u64_0(NULL, "delay", "<dec>", "pause delay in milliseconds between UIDs simulation (default 1000ms)"),
        arg_str1("f", "file", "<hex>", "file with EM Tag IDs, one id per line"),
        arg_u64_0(NULL, "gap", "<dec>", "gap (0's) between ID repeats (default 20)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    // clock default 64 in EM410x
    uint32_t clk = arg_get_u32_def(ctx, 1, 64);
    int gap = arg_get_u32_def(ctx, 4, 20);
    // default pause time: 1 second
    uint32_t delay = arg_get_u32_def(ctx, 2, 1000);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 3), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    if (fnlen == 0) {
        PrintAndLogEx(ERR, "Error: Please specify a filename");
        return PM3_EINVARG;
    }

    // get suffix.
    char suffix[10] = {0};
    char *ext = strrchr(filename, '.');
    if (ext != NULL) {
        strncpy(suffix, ext, sizeof(suffix) - 1);
    }

    // load keys
    uint8_t *uidblock = NULL;
    uint32_t uidcount = 0;
    int res = loadFileDICTIONARY_safe_ex(filename, suffix, (void **)&uidblock, 5, &uidcount, false);
    if (res != PM3_SUCCESS) {
        free(uidblock);
        return res;
    }

    if (uidcount == 0) {
        PrintAndLogEx(FAILED, "No EM Tag IDs found in file");
        free(uidblock);
        return PM3_EINVARG;
    }

    PrintAndLogEx(SUCCESS, "Loaded "_GREEN_("%d")" EM Tag IDs from `"_YELLOW_("%s")"`  pause delay:"_YELLOW_("%d")" ms", uidcount, filename, delay);

    // loop
    uint8_t testuid[5];
    for (uint32_t i = 0; i < uidcount; ++i) {

        if (kbd_enter_pressed()) {
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            PrintAndLogEx(WARNING, "aborted via keyboard!\n");
            free(uidblock);
            return PM3_EOPABORTED;
        }

        memset(testuid, 0, sizeof(testuid));
        memcpy(testuid, uidblock + (5 * i), sizeof(testuid));

        PrintAndLogEx(INFO, "Bruteforce %d / %u: simulating EM Tag ID " _YELLOW_("%s")
                      , i + 1
                      , uidcount
                      , sprint_hex_inrow(testuid, sizeof(testuid))
                     );

        em410x_construct_emul_graph(testuid, clk, gap);

        lfsim_upload_gb();

        struct p {
            uint16_t len;
            uint16_t gap;
        } PACKED payload;
        payload.len = g_GraphTraceLen;
        payload.gap = 0;

        clearCommandBuffer();
        SendCommandNG(CMD_LF_SIMULATE, (uint8_t *)&payload, sizeof(payload));
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_LF_SIMULATE, &resp, delay)) {
            if (resp.status == PM3_EOPABORTED) {
                PrintAndLogEx(INFO, "Button pressed, user aborted");
                break;
            }
        }
    }
    free(uidblock);
    return PM3_SUCCESS;
}

//currently only supports manchester modulations
static int CmdEM410xSpoof(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 410x spoof",
                  "Watch 'nd Spoof, activates reader\n"
                  "Waits until a EM 410x tag gets presented then Proxmark3 starts simulating the found EM Tag ID",
                  "lf em 410x spoof"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    // loops if the captured ID was in XL-format.
    gs_em410xid = 0;
    CmdEM410xReader("-b@");
    PrintAndLogEx(SUCCESS, "Replaying captured EM Tag ID "_YELLOW_("%010" PRIx64), gs_em410xid);
    CmdLFSim("");
    return PM3_SUCCESS;
}

static int CmdEM410xClone(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 410x clone",
                  "clone a EM410x ID to a T55x7, Q5/T5555, EM4305/4469 or Hitag S/8211/8268/8310 tag.",
                  "lf em 410x clone --id 0F0368568B        -> encode for T55x7 tag\n"
                  "lf em 410x clone --id 0F0368568B --q5   -> encode for Q5/T5555 tag\n"
                  "lf em 410x clone --id 0F0368568B --em   -> encode for EM4305/4469\n"
                  "lf em 410x clone --id 0F0368568B --hts  -> encode for Hitag S/8211/8268/8310"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0(NULL, "clk", "<dec>", "<16|32|40|64> clock (default 64)"),
        arg_str1(NULL, "id", "<hex>", "EM Tag ID number (5 hex bytes)"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_lit0(NULL, "hts", "optional - specify writing to Hitag S/8211/8268/8310 tag"),
        arg_lit0(NULL, "electra", "optional - add Electra blocks to tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    // clock default 64 in EM410x
    uint32_t clk = arg_get_u32_def(ctx, 1, 64);
    int uid_len = 0;
    uint8_t uid[5] = {0};
    CLIGetHexWithReturn(ctx, 2, uid, &uid_len);
    bool q5 = arg_get_lit(ctx, 3);
    bool em = arg_get_lit(ctx, 4);
    bool hts = arg_get_lit(ctx, 5);
    bool add_electra = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    if (q5 + em + hts > 1) {
        PrintAndLogEx(FAILED, "Only specify one tag Type");
        return PM3_EINVARG;
    }

    if (hts) {
        if (IfPm3Hitag() == false) {
            PrintAndLogEx(FAILED, "Device not compiled to support Hitag");
            return PM3_EINVARG;
        }
        if (clk == 40) {
            PrintAndLogEx(FAILED, "supported clock rates for Hitag are " _YELLOW_("16, 32, 64"));
            return PM3_EINVARG;
        }
    }

    // Allowed clock rates: 16, 32, 40 and 64
    if ((clk != 16) && (clk != 32) && (clk != 64) && (clk != 40)) {
        PrintAndLogEx(FAILED, "supported clock rates are " _YELLOW_("16, 32, 40, 64") "  got " _RED_("%d") "\n", clk);
        return PM3_EINVARG;
    }

    uint64_t id = bytes_to_num(uid, uid_len);
    PrintAndLogEx(SUCCESS, "Preparing to clone EM4102 to " _YELLOW_("%s") " tag with EM Tag ID " _GREEN_("%010" PRIX64) " (RF/%d)",
                  q5 ? "Q5/T5555" : (em ? "EM4305/4469" : (hts ? "Hitag S/82xx" : "T55x7")), id, clk);

    uint8_t data[HITAG_BLOCK_SIZE * 2] = {0xFF, 0x80}; // EM410X_HEADER 9 bits of one
    uint32_t databits = 9;
    uint8_t c_parity = 0;

    for (int i = 36; i >= 0; i -= 4) {
        uint8_t r_parity = 0;
        uint8_t nibble = id >> i & 0xF;

        databits = concatbits(data, databits, &nibble, 4, 4);
        for (size_t j = 0; j < 4; j++) {
            r_parity ^= nibble >> j & 1;
        }
        databits = concatbits(data, databits, &r_parity, 7, 1);
        c_parity ^= nibble;
    }
    data[7] |= c_parity << 1;

    PrintAndLogEx(INFO, "Encoded to %s", sprint_hex(data, sizeof(data)));

    clearCommandBuffer();
    PacketResponseNG resp;

    if (hts) {
        lf_hitag_data_t packet;
        memset(&packet, 0, sizeof(packet));

        for (size_t steps = 0; steps < 3; steps++) {
            switch (steps) {
                case 0:
                    packet.data[0] = 0xCA; //compatiable for 82xx, no impact on Hitag S
                    // clk -> TTFDR1 TTFDR0
                    // 32  -> 0x00      4 kBit/s
                    // 16  -> 0x10      8 kBit/s
                    // 64  -> 0x20      2 kBit/s
                    packet.data[1] = 0x04;
                    switch (clk) {
                        case 32:
                            break;
                        case 16:
                            packet.data[1] |= 0x10;
                            break;
                        case 64:
                            packet.data[1] |= 0x20;
                            break;
                    }
                    packet.data[2] = 0;
                    packet.data[3] = 0; //TODO: keep PWDH0?
                    packet.page = 1;
                    break;
                case 1:
                    memcpy(packet.data, &data[HITAG_BLOCK_SIZE * 0], HITAG_BLOCK_SIZE);
                    packet.page = 4;
                    break;
                case 2:
                    memcpy(packet.data, &data[HITAG_BLOCK_SIZE * 1], HITAG_BLOCK_SIZE);
                    packet.page = 5;
                    break;
            }

            packet.cmd = HTSF_82xx;
            memcpy(packet.pwd, "\xBB\xDD\x33\x99", HITAGS_PAGE_SIZE);
            SendCommandNG(CMD_LF_HITAGS_WRITE, (uint8_t *)&packet, sizeof(packet));
            if (WaitForResponseTimeout(CMD_LF_HITAGS_WRITE, &resp, 4000) == false) {
                PrintAndLogEx(WARNING, "timeout while waiting for reply.");
                return PM3_ETIMEOUT;
            }
            if (resp.status != PM3_SUCCESS) {
                PrintAndLogEx(WARNING, "Something went wrong");
                return resp.status;
            }
        }
    } else {
        struct {
            bool Q5;
            bool EM;
            bool add_electra;
            uint8_t clock;
            uint32_t high;
            uint32_t low;
        } PACKED payload;

        payload.Q5 = q5;
        payload.EM = em;
        payload.add_electra = add_electra;
        payload.clock = clk;
        payload.high = (uint32_t)(id >> 32);
        payload.low = (uint32_t)id;

        SendCommandNG(CMD_LF_EM410X_CLONE, (uint8_t *)&payload, sizeof(payload));
        if (WaitForResponseTimeout(CMD_LF_EM410X_CLONE, &resp, 2000) == false) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply.");
            return PM3_ETIMEOUT;
        }
    }

    switch (resp.status) {
        case PM3_SUCCESS: {
            PrintAndLogEx(SUCCESS, "Done!");
            PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf em 410x reader`") " to verify");
            break;
        }
        default: {
            PrintAndLogEx(WARNING, "Something went wrong");
            break;
        }
    }
    return resp.status;
}

static command_t CommandTable[] = {
    {"help",        CmdHelp,      AlwaysAvailable, "This help"},
    //{"demod",  CmdEMdemodASK,    IfPm3Lf,         "Extract ID from EM410x tag on antenna)"},
    {"demod",  CmdEM410xDemod,    AlwaysAvailable, "demodulate a EM410x tag from the GraphBuffer"},
    {"reader", CmdEM410xReader,   IfPm3Lf,         "attempt to read and extract tag data"},
    {"sim",    CmdEM410xSim,      IfPm3Lf,         "simulate EM410x tag"},
    {"brute",  CmdEM410xBrute,    IfPm3Lf,         "reader bruteforce attack by simulating EM410x tags"},
    {"watch",  CmdEM410xWatch,    IfPm3Lf,         "watches for EM410x 125/134 kHz tags"},
    {"spoof",  CmdEM410xSpoof,    IfPm3Lf,         "watches for EM410x 125/134 kHz tags, and replays them" },
    {"clone",  CmdEM410xClone,    IfPm3Lf,         "clone EM410x Tag ID to T55x7, Q5/T5555 or EM4305/4469"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFEM410X(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
