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
// Low frequency Trovan animal ID commands
//
// Trovan is not ISO 11784/11785
//
// Differential biphase phase shift keying on an Fc/2 subcarrier, 16 carrier cycles to the bit.
// A telegram is 64 bits:
//
//   8 bits   sync, 01111111.  Cannot occur anywhere in the body without
//            breaking row parity, which is what makes it a usable sync word.
//  13 rows   3 data bits and 1 odd row parity bit, 39 data bits in total
//   1 row    3 odd column parity bits and 1 odd row parity bit

//-----------------------------------------------------------------------------

#include "cmdlftrovan.h"

#include <string.h>
#include <inttypes.h>
#include <stdlib.h>

#include "commonutil.h"   // ARRAYLEN
#include "cmdparser.h"    // command_t
#include "cliparser.h"
#include "comms.h"
#include "ui.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "protocols.h"    // T55xx config register definitions
#include "lfdemod.h"      // psk1TOpsk2
#include "cmdlft55xx.h"   // clone_t55xx_tag
#include "cmdlfem4x05.h"  // em4x05_clone_tag

#define TROVAN_CLOCK        16
#define TROVAN_TELEGRAM     64
#define TROVAN_SYNC_LEN     8
#define TROVAN_ROWS         14
#define TROVAN_DATA_BITS    39

// samples for one telegram, times enough telegrams to survive a ragged start
#define TROVAN_READ_SAMPLES (TROVAN_TELEGRAM * TROVAN_CLOCK * 10)

static int CmdHelp(const char *Cmd);

static const uint8_t trovan_sync[TROVAN_SYNC_LEN] = { 0, 1, 1, 1, 1, 1, 1, 1 };

// Check one 64 bit telegram and pull the ID out of it.  `bits` holds one bit
// per byte.  Returns true and fills `id` when both parity planes hold.
static bool trovan_check(const uint8_t *bits, uint64_t *id) {

    const uint8_t *rows = bits + TROVAN_SYNC_LEN;

    // odd parity across each 4 bit row
    for (uint8_t r = 0; r < TROVAN_ROWS; r++) {

        uint8_t ones = 0;
        for (uint8_t c = 0; c < 4; c++) {
            ones += rows[(r * 4) + c];
        }

        if ((ones & 1) == 0) {
            return false;
        }
    }

    // odd parity down each of the three data columns, the fourth column is
    // the row parity itself and is not covered
    for (uint8_t c = 0; c < 3; c++) {

        uint8_t ones = 0;
        for (uint8_t r = 0; r < TROVAN_ROWS; r++) {
            ones += rows[(r * 4) + c];
        }

        if ((ones & 1) == 0) {
            return false;
        }
    }

    // 39 data bits, most significant first, the last row being parity only
    uint64_t v = 0;
    for (uint8_t r = 0; r < TROVAN_ROWS - 1; r++) {
        for (uint8_t c = 0; c < 3; c++) {
            v = (v << 1) | rows[(r * 4) + c];
        }
    }

    *id = v;
    return true;
}

// Hunt for a sync word and validate the telegram that follows it.
// Returns the bit offset the telegram started at, or -1.
static int trovan_find(const uint8_t *bits, size_t size, uint64_t *id) {

    if (size < TROVAN_TELEGRAM) {
        return -1;
    }

    for (size_t i = 0; i + TROVAN_TELEGRAM <= size; i++) {

        if (memcmp(bits + i, trovan_sync, TROVAN_SYNC_LEN) != 0) {
            continue;
        }

        if (trovan_check(bits + i, id)) {
            return (int)i;
        }
    }

    return -1;
}

// Conventional Trovan formatting is 10 hex digits in 2-4-4 groups.
static void trovan_print(uint64_t id) {

    PrintAndLogEx(SUCCESS, "Trovan animal ID " _GREEN_("%02X-%04X-%04X")
                  , (uint32_t)((id >> 32) & 0xFF)
                  , (uint32_t)((id >> 16) & 0xFFFF)
                  , (uint32_t)(id & 0xFFFF)
                 );
}

int demodTrovan(bool verbose) {

    if (PSKDemod(TROVAN_CLOCK, 0, 100, false) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Trovan: PSK demod failed");
        return PM3_ESOFT;
    }

    psk1TOpsk2(g_DemodBuffer, g_DemodBufferLen);

    if (g_DemodBufferLen < TROVAN_TELEGRAM) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Trovan: too few bits, %zu", g_DemodBufferLen);
        return PM3_ESOFT;
    }

    // The demodulator settles on a polarity of its own choosing, and the parity checks cannot tell the two apart.
    uint8_t *bits = calloc(g_DemodBufferLen, sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Trovan: out of memory");
        return PM3_EMALLOC;
    }

    uint64_t id = 0;
    int idx = -1;
    bool inverted = false;

    for (uint8_t pass = 0; pass < 2 && idx < 0; pass++) {

        for (size_t i = 0; i < g_DemodBufferLen; i++) {
            bits[i] = (pass == 0) ? (g_DemodBuffer[i] & 1) : (g_DemodBuffer[i] & 1) ^ 1;
        }

        idx = trovan_find(bits, g_DemodBufferLen, &id);
        inverted = (pass == 1);
    }

    if (idx < 0) {
        free(bits);
        PrintAndLogEx(DEBUG, "DEBUG: Error - Trovan: no valid telegram found");
        return PM3_ESOFT;
    }

    setDemodBuff(bits, TROVAN_TELEGRAM, (size_t)idx);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (idx * g_DemodClock));
    free(bits);

    trovan_print(id);

    if (verbose) {
        PrintAndLogEx(INFO, "  telegram at bit " _YELLOW_("%d") ", clock rf/%d, polarity %s"
                      , idx
                      , TROVAN_CLOCK
                      , inverted ? "inverted" : "normal"
                     );
        PrintAndLogEx(INFO, "  raw " _YELLOW_("%010" PRIX64), id);
    }

    return PM3_SUCCESS;
}

int readTrovanUid(void) {
    return (demodTrovan(false) == PM3_SUCCESS);
}

// Build the 64 bit telegram for an ID.
static void trovan_encode(uint64_t id, uint8_t *bits) {

    memcpy(bits, trovan_sync, TROVAN_SYNC_LEN);
    uint8_t *rows = bits + TROVAN_SYNC_LEN;

    // 13 rows of 3 data bits, most significant first, each closed with an odd row parity bit
    for (uint8_t r = 0; r < TROVAN_ROWS - 1; r++) {

        uint8_t ones = 0;

        for (uint8_t c = 0; c < 3; c++) {
            const uint8_t shift = (uint8_t)(TROVAN_DATA_BITS - 1 - ((r * 3) + c));
            const uint8_t b = (uint8_t)((id >> shift) & 1);
            rows[(r * 4) + c] = b;
            ones += b;
        }

        rows[(r * 4) + 3] = (ones & 1) ? 0 : 1;
    }

    // the last row carries the column parities, then its own row parity
    uint8_t last = 0;

    for (uint8_t c = 0; c < 3; c++) {

        uint8_t ones = 0;
        for (uint8_t r = 0; r < TROVAN_ROWS - 1; r++) {
            ones += rows[(r * 4) + c];
        }

        const uint8_t p = (ones & 1) ? 0 : 1;
        rows[((TROVAN_ROWS - 1) * 4) + c] = p;
        last += p;
    }

    rows[((TROVAN_ROWS - 1) * 4) + 3] = (last & 1) ? 0 : 1;
}

static int CmdTrovanDemod(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf trovan demod",
                  "Demodulate a Trovan animal ID tag from the GraphBuffer",
                  "lf trovan demod\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool verbose = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    const int res = demodTrovan(verbose);

    if (res != PM3_SUCCESS && verbose) {
        PrintAndLogEx(FAILED, "Trovan demod failed ( looked for a %d bit frame at rf/%d )"
                      , TROVAN_TELEGRAM
                      , TROVAN_CLOCK
                     );
    }

    return res;
}

static int CmdTrovanReader(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf trovan reader",
                  "read a Trovan animal ID tag",
                  "lf trovan reader -@   -> continuous reader mode"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("@", NULL, "optional - continuous reader mode"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool cm = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    int res = PM3_SUCCESS;

    do {
        lf_read(false, TROVAN_READ_SAMPLES);
        res = demodTrovan(verbose && (cm == false));
    } while (cm && (kbd_enter_pressed() == false));

    // continuous mode is expected to come up empty between tag presentations,
    // so only a one shot read is worth reporting a miss for
    if (res != PM3_SUCCESS && (cm == false) && verbose) {
        PrintAndLogEx(FAILED, "Trovan demod failed ( looked for a %d bit frame at rf/%d )"
                      , TROVAN_TELEGRAM
                      , TROVAN_CLOCK
                     );
    }

    return res;
}

static int CmdTrovanClone(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf trovan clone",
                  "clone a Trovan animal ID to a T55x7, Q5/T5555 or EM4305/4469 tag\n"
                  "The ID is the 10 hex digits printed on the tag, with or without dashes.",
                  "lf trovan clone --id 0007F9043A\n"
                  "lf trovan clone --id 00-07F9-043A\n"
                  "lf trovan clone --id 0007F9043A --q5"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "id", "<hex>", "Trovan animal ID, 10 hex digits"),
        arg_lit0(NULL, "q5", "specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "specify writing to EM4305/4469 tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t raw[24] = {0};
    int rawlen = sizeof(raw) - 1;
    CLIGetStrWithReturn(ctx, 1, raw, &rawlen);
    bool q5 = arg_get_lit(ctx, 2);
    bool em = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }

    // accept the dashed form the tags are printed in
    char digits[16] = {0};
    int n = 0;

    for (int i = 0; i < rawlen; i++) {

        if (raw[i] == '-' || raw[i] == ' ') {
            continue;
        }

        if (n >= (int)sizeof(digits) - 1) {
            n++;
            break;
        }

        digits[n++] = (char)raw[i];
    }

    if (n != 10) {
        PrintAndLogEx(FAILED, "ID must be 10 hex digits, got " _RED_("%d"), n);
        return PM3_EINVARG;
    }

    char *end = NULL;
    const uint64_t id = strtoull(digits, &end, 16);

    if (end == NULL || *end != '\0') {
        PrintAndLogEx(FAILED, "ID is not hex: " _RED_("%s"), digits);
        return PM3_EINVARG;
    }

    // 10 hex digits is 40 bits but only 39 of them are carried
    if (id > 0x7FFFFFFFFFULL) {
        PrintAndLogEx(FAILED, "ID does not fit in the 39 bits a telegram carries");
        return PM3_EINVARG;
    }

    uint8_t bits[TROVAN_TELEGRAM] = {0};
    trovan_encode(id, bits);

    uint32_t blocks[3] = {0};
    for (uint8_t i = 0; i < 64; i++) {
        const uint8_t b = bits[i] ^ 1;
        blocks[1 + (i / 32)] |= ((uint32_t)b) << (31 - (i % 32));
    }

    char cardtype[16] = {"T55x7"};

    blocks[0] = T55x7_TESTMODE_DISABLED | T55x7_MODULATION_PSK2 | T55x7_PSKCF_RF_2 | T55x7_BITRATE_RF_16 | 2 << T55x7_MAXBLOCK_SHIFT;

    if (q5) {
        blocks[0] = T5555_FIXED | T5555_MODULATION_PSK2 | T5555_SET_BITRATE(TROVAN_CLOCK) | T5555_PSK_RF_2 | 2 << T5555_MAXBLOCK_SHIFT;
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    }

    if (em) {
        PrintAndLogEx(FAILED, "EM4305/4469 does not support PSK, which Trovan needs");
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "Preparing to clone Trovan to " _YELLOW_("%s") " with animal ID " _GREEN_("%02X-%04X-%04X")
                  , cardtype
                  , (uint32_t)((id >> 32) & 0xFF)
                  , (uint32_t)((id >> 16) & 0xFFFF)
                  , (uint32_t)(id & 0xFFFF)
                 );

    print_blocks(blocks, ARRAYLEN(blocks));

    int res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));

    PrintAndLogEx(SUCCESS, "Done!");
    PrintAndLogEx(HINT, "Hint: Try " _YELLOW_("`lf trovan reader`") " to verify");
    return res;
}

static command_t CommandTable[] = {
    {"help",   CmdHelp,          AlwaysAvailable, "This help"},
    {"demod",  CmdTrovanDemod,   AlwaysAvailable, "demodulate a Trovan tag from the GraphBuffer"},
    {"reader", CmdTrovanReader,  IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone",  CmdTrovanClone,   IfPm3Lf,         "clone Trovan tag to T55x7 or Q5/T5555"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFTrovan(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
