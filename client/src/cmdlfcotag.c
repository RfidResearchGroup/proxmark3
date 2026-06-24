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
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <math.h>
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "lfdemod.h"
#include "cmddata.h"    // getSamples
#include "ui.h"         // PrintAndLog
#include "ctype.h"      // tolower
#include "cliparser.h"
#include "commonutil.h" // reflect32
#include "cmdlf.h"      // lf_getconfig, lf_setconfig, lf_read_cotag
#include "graph.h"      // g_GraphTraceLen

#define XSTR(x) #x
#define STR(x)  XSTR(x)

#define LF_COTAG_DIVISOR          90   // 132 kHz
#define LF_COTAG_CLOCK            768
#define LF_COTAG_DATA_LEN         128

#define LF_COTAG_DEF_SAMPLES_READ 500000

static int CmdHelp(const char *Cmd);

static int demod_cotag(int32_t *samples, int num_samples, int clock, int clock_start, int32_t threshold, bool verbose);
static int detect_edge(const int32_t *samples, int num_samples,
                       int index_start, int32_t threshold);
static void find_avg_high_low(const int32_t *samples, int num_samples,
                              int clock,
                              double *out_avg_high, double *out_avg_low);

#if 0
// TODO: With the new cotag implementation shall we remove this old version
// or is there anything we could use from it?
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
#endif

/**
 * Demodulate COTAG samples.
 *
 * @param clock        Number of samples per clock cycle.
 * @param clock_start  Sample index where the first clock cycle starts.
 *                     Use -1 for auto clock-start detection.
 * @param threshold    Amplitude threshold that defines a "high" sample. Use -1 for auto-threshold detection.
 */
static int demod_cotag(int32_t *samples, int num_samples, int clock, int clock_start, int32_t threshold, bool verbose) {
    int       clock_half = clock / 2;
    int32_t   min, max;
    double    avg;
    int       rv = PM3_EFAILED;
    uint8_t  *high_low_demod_01 = NULL;

    uint8_t  *manchester_demod = NULL;
    uint8_t  *manchester_demod_reversed = NULL;

    /* Calculate min, max, average */
    int64_t sum = 0;
    min = max = samples[0];
    for (int i = 0; i < num_samples; i++) {
        sum += samples[i];
        if (samples[i] < min) min = samples[i];
        if (samples[i] > max) max = samples[i];
    }
    avg = (double)sum / (double)num_samples;

    if (verbose) {
        PrintAndLogEx(INFO, "  Clock: %d", clock);
        if (threshold == -1)
            PrintAndLogEx(INFO, "  Threshold: auto");
        else
            PrintAndLogEx(INFO, "  Threshold: %d", threshold);
        PrintAndLogEx(INFO, "  Min : %" PRId32, min);
        PrintAndLogEx(INFO, "  Max : %" PRId32, max);
        PrintAndLogEx(INFO, "  Avg : %.2f\n", avg);
        printf("\n");
    }

    /* DC offset removal: subtract average from every sample */
    for (int i = 0; i < num_samples; i++) {
        double v = round((double)samples[i] - avg);
        samples[i] = (int32_t)v;
    }

    /* Auto threshold detection */
    if (threshold == -1) {
        double avg_high, avg_low;
        find_avg_high_low(samples, num_samples, clock, &avg_high, &avg_low);
        double thr = floor(0.9 * avg_high);
        threshold = (int32_t)thr;
        if (verbose)
            PrintAndLogEx(INFO, "  Auto threshold: avg_low=%.2f, avg_high=%.2f --> threshold=%d", avg_low, avg_high, (int)threshold);
    }

    /* Auto clock-start detection (first edge detection) */
    if (clock_start == -1) {
        clock_start = detect_edge(samples, num_samples, 0, threshold);
        if (verbose)
            PrintAndLogEx(INFO, "  Detected clock start candidate: sample #%d", clock_start);
    }

    /* High/low raw demodulation of clock-half cycles */
    int high_low_demod_01_len = (num_samples - clock_start) / clock_half + 16;
    high_low_demod_01 = calloc(high_low_demod_01_len, sizeof(uint8_t));
    if (!high_low_demod_01) {
        PrintAndLogEx(ERR, "Error: out of memory");
        rv = PM3_EMALLOC;
        goto end;
    }
    int high_low_demod_01_count = 0;

    for (int idx = clock_start; idx + clock <= num_samples; idx += clock) {
        /* Average absolute values of first half */
        int32_t clock_half1_val_avg = 0;
        for (int k = 0; k < clock_half; k++)
            clock_half1_val_avg += abs(samples[idx + k]);
        double h1v = round((double)clock_half1_val_avg / clock_half);
        clock_half1_val_avg = (int32_t)h1v;

        /* Average absolute values of second half */
        int32_t clock_half2_val_avg = 0;
        for (int k = 0; k < clock_half; k++)
            clock_half2_val_avg += abs(samples[idx + clock_half + k]);
        double h2v = round((double)clock_half2_val_avg / clock_half);
        clock_half2_val_avg = (int32_t)h2v;

        uint8_t half1 = (clock_half1_val_avg >= threshold) ? 1 : 0;
        uint8_t half2 = (clock_half2_val_avg >= threshold) ? 1 : 0;

        high_low_demod_01[high_low_demod_01_count]     = half1;
        high_low_demod_01[high_low_demod_01_count + 1] = half2;
        high_low_demod_01_count += 2;
    }

    /* Manchester demodulation buffer: */
    int manchester_demod_len = high_low_demod_01_count / 2;
    manchester_demod = calloc(manchester_demod_len, sizeof(uint8_t));
    if (!manchester_demod) {
        PrintAndLogEx(ERR, "Error: out of memory");
        rv = PM3_EMALLOC;
        goto end;
    }

    /* Manchester demodulation (Thomas) from raw high/low demod (high_low_demod_01) */
    const int MAX_MANDEMOD_ERRORS = 64;
    bool demod_success = true;
    int manchester_count = 0;
    int mandemod_err_count = 0;
    for (int i = 0; i + 1 < high_low_demod_01_count;) {
        uint8_t half1 = high_low_demod_01[i];
        uint8_t half2 = high_low_demod_01[i + 1];

        if (half1 == 0 && half2 == 1) {
            manchester_demod[manchester_count++] = 0;
            i += 2;
        } else if (half1 == 1 && half2 == 0) {
            manchester_demod[manchester_count++] = 1;
            i += 2;
        } else {
            if (verbose)
                PrintAndLogEx(INFO, "  Manchester demod error: index %d (sample #%" PRId32 "): half1=%u, half2=%u --> clock align by half cycle",
                              i, (int32_t)(clock_start + i * clock_half), (unsigned)half1, (unsigned)half2);
            i += 1; /* re-align by one half-clock forward */
            mandemod_err_count++;
            if (mandemod_err_count >= MAX_MANDEMOD_ERRORS) {
                PrintAndLogEx(ERR, "  Manchester demod: too many errors (%d), giving up", mandemod_err_count);
                demod_success = false;
                break;
            }
        }
    }

    if (demod_success) {
        if (verbose)
            PrintAndLogEx(INFO, "  Manchester demod: %d bits", manchester_count);
    } else
        goto end;
    printf("\n");

    /* Reverse order of bits */
    manchester_demod_reversed = calloc(manchester_demod_len, sizeof(uint8_t));
    if (!manchester_demod_reversed) {
        PrintAndLogEx(ERR, "Error: out of memory");
        rv = PM3_EMALLOC;
        goto end;
    }
    for (int i = 0; i < manchester_count; i++)
        manchester_demod_reversed[i] = manchester_demod[manchester_count - 1 - i];

    {
        char manchester_demod_reversed_str[manchester_count + 1];
        for (int i = 0; i < manchester_count; i++)
            manchester_demod_reversed_str[i] = '0' + manchester_demod_reversed[i];
        manchester_demod_reversed_str[manchester_count] = '\0';
        PrintAndLogEx(SUCCESS, "  Manchester demod reversed:");
        PrintAndLogEx(SUCCESS, "  %s", manchester_demod_reversed_str);
        printf("\n");
        printf("\n");
    }

    /*
     * Example cotag card dump (manchester demod reversed):
     *
     * 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0001 0000 0101 1000 0010 0100 1110 0000 0000 0000 0000 1000 0000 0010 0100 1010 1000 1000 1111
     *    0    0    0    0    0    0    0    0    0    0    0    0    0    1    0    5    8    2    4    E    0    0    0    0    8    0    2    4    A    8    8    F
     *
     * Card number: 0x24A88F
     */

    /* Find preamble. */
    static const uint8_t preamble_a[] = {
        /* type A: 62 zeros followed by 1,0,1,0,0,0 */
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
        1, 0, 0, 0
    };
    static const uint8_t preamble_p[] = {
        /* type P: 55 zeros followed by 1,0,0,0,0,0,1 */
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 0, 0, 1
    };
    static const uint8_t preamble_p0[] = {
        /* type P-0: 61 zeros followed by 1 */
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1
    };

    struct {
        const uint8_t *pat;
        int len;
        const char *name;
    } preamble_patterns[] = {
        { preamble_a, (int)(sizeof(preamble_a)   / sizeof(preamble_a[0])), "A"   },
        { preamble_p, (int)(sizeof(preamble_p)  / sizeof(preamble_p[0])),  "P"   },
        { preamble_p0, (int)(sizeof(preamble_p0) / sizeof(preamble_p0[0])), "P-0" },
        { NULL, 0, "" },
    };

    int preamble_index = -1;
    const char *preamble_type  = NULL;

    for (int i = 0; i < manchester_count && preamble_index < 0; i++) {
        for (int p = 0; preamble_patterns[p].pat != NULL; p++) {
            if (i + preamble_patterns[p].len <= manchester_count &&
                    memcmp(&manchester_demod_reversed[i], preamble_patterns[p].pat, preamble_patterns[p].len) == 0) {
                preamble_index = i;
                preamble_type  = preamble_patterns[p].name;
                break;
            }
        }
    }

    if (preamble_index < 0) {
        PrintAndLogEx(INFO, "  Preamble not found in manchester_demod_reversed");
        goto end;
    }

    PrintAndLogEx(SUCCESS, "  Preamble found (type %s) in manchester_demod_reversed at index %d",
                  preamble_type, preamble_index);

    /* data_bits: 128 bits starting at preamble */
    if (preamble_index + LF_COTAG_DATA_LEN > manchester_count) {
        PrintAndLogEx(INFO, "  Not enough bits after preamble for full 128-bit data block");
        rv = PM3_EPARTIAL;
        goto end;
    }

    const uint8_t *data_bits = &manchester_demod_reversed[preamble_index];

    /* Print raw 128 bits */
    {
        char str[LF_COTAG_DATA_LEN + 1];
        for (int i = 0; i < LF_COTAG_DATA_LEN; i++)
            str[i] = '0' + data_bits[i];
        str[LF_COTAG_DATA_LEN] = '\0';
        PrintAndLogEx(SUCCESS, "  data bits: %s", str);
    }
    /* Print bits grouped by 4, space-separated */
    {
        char str[LF_COTAG_DATA_LEN + LF_COTAG_DATA_LEN / 4];
        int p = 0;
        for (int i = 0; i < LF_COTAG_DATA_LEN; i += 4) {
            if (i > 0) str[p++] = ' ';
            for (int j = 0; j < 4; j++)
                str[p++] = '0' + data_bits[i + j];
        }
        str[p] = '\0';
        PrintAndLogEx(SUCCESS, "  data bits: %s", str);
    }
    /* Print bits as hex nibbles */
    {
        char str[LF_COTAG_DATA_LEN / 4 * 5 + 1];
        int p = 0;
        for (int i = 0; i < LF_COTAG_DATA_LEN; i += 4) {
            int nibble = (data_bits[i]     << 3)
                         | (data_bits[i + 1] << 2)
                         | (data_bits[i + 2] << 1)
                         |  data_bits[i + 3];
            str[p++] = ' ';
            str[p++] = ' ';
            str[p++] = ' ';
            str[p++] = ' ';
            str[p++] = "0123456789ABCDEF"[nibble];
        }
        str[p] = '\0';
        PrintAndLogEx(SUCCESS, "  data hex: %s", str);
    }

    /* Card number: last 24 bits of data_bits as an integer */
    uint32_t c_num = 0;
    for (int i = LF_COTAG_DATA_LEN - 24; i < LF_COTAG_DATA_LEN; i++)
        c_num = (c_num << 1) | data_bits[i];
    PrintAndLogEx(SUCCESS, "  card number: 0x%X == %u", c_num, c_num);

    /* Count how many subsequent 128-bit blocks equal data_bits */
    int repeat_count = 0;
    bool fully_repeats = true;
    int pos = preamble_index + LF_COTAG_DATA_LEN;
    while (pos + LF_COTAG_DATA_LEN <= manchester_count) {
        if (memcmp(&manchester_demod_reversed[pos], data_bits, LF_COTAG_DATA_LEN) == 0) {
            repeat_count++;
        } else {
            fully_repeats = false;
            break;
        }
        pos += LF_COTAG_DATA_LEN;
    }

    if (fully_repeats && repeat_count > 0)
        PrintAndLogEx(INFO, "  Sequence fully repeats until the end %d time(s)", repeat_count);
    else
        PrintAndLogEx(INFO, "  Sequence does NOT match at index %d (repeat count = %d)", pos, repeat_count);
    printf("\n");

    rv = PM3_SUCCESS;
end:
    free(manchester_demod_reversed);
    free(manchester_demod);
    free(high_low_demod_01);
    return rv;
}

int demodCOTAG(bool verbose, int clock, int threshold) {
    int clk = (clock > 0) ? clock : LF_COTAG_CLOCK;
    return demod_cotag(g_GraphBuffer, (int)g_GraphTraceLen, clk, -1, threshold, verbose);
}

static int CmdCOTAGDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf cotag demod",
                  "Demodulate COTAG samples from g_GraphBuffer. Try to find COTAG preamble, if found decode / descramble data.",
                  "lf cotag demod"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "verbose output"),
        arg_int0("c", "clk", "<dec>", "set clock manually (def " STR(LF_COTAG_CLOCK) ")"),
        arg_int0("t", "threshold", "<dec>", "set high value threshold manually (def: auto-detected)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool verbose = arg_get_lit(ctx, 1);
    int clock = arg_get_int_def(ctx, 2, -1);
    int thresh = arg_get_int_def(ctx, 3, -1);
    CLIParserFree(ctx);
    return demodCOTAG(verbose, clock, thresh);
}

static int CmdCOTAGReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf cotag reader",
                  "Read a COTAG tag.\n"
                  " - use " _YELLOW_("`lf config`") _CYAN_(" to set parameters except divisor "
                                                           "(which is assumed " STR(LF_COTAG_DIVISOR) " for cotag. Use --divisor to override).\n")
                  _CYAN_(" - use ") _YELLOW_("`data plot`") _CYAN_(" to look at it.\n")
                  _CYAN_(" - use ") _YELLOW_("`lf cotag demod`") _CYAN_(" to try to demodulate it.\n")
                  _CYAN_("If the number of samples is more than the device memory limit (40000 now), ")
                  _CYAN_("it will try to use the real-time sampling mode.\n\n")
                  _CYAN_("Note: Cotag has an extremely slow data rate - RF/" STR(LF_COTAG_CLOCK) " ")
                  _CYAN_("-- capturing a full " STR(LF_COTAG_DATA_LEN) " bit card read requires a minimum of ")
                  _CYAN_(STR(LF_COTAG_DATA_LEN) " x " STR(LF_COTAG_CLOCK) " samples, or a multiple thereof."),
                  "lf cotag reader -v -s 700000   --> collect 700000 samples\n"
                  "lf cotag reader -v --divisor 89 -s 700000   --> use divisor 89, collect 700000 samples\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("s", "samples", "<dec>", "number of samples to collect (def " STR(LF_COTAG_DEF_SAMPLES_READ) ")"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0("@", NULL, "continuous reading mode"),
        arg_int0(NULL, "divisor", "<19-255>", "Manually set freq divisor"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint64_t samples = arg_get_u64_def(ctx, 1, LF_COTAG_DEF_SAMPLES_READ);
    bool verbose = arg_get_lit(ctx, 2);
    bool cm = arg_get_lit(ctx, 3);
    int16_t divisor = arg_get_int_def(ctx, 4, -1);
    CLIParserFree(ctx);

    bool realtime = (samples > 40000);

    if (divisor > -1 && (divisor < 19 || divisor > 255)) {
        PrintAndLogEx(ERR, "divisor must be between 19 and 255");
        return PM3_EINVARG;
    }

    if (g_session.pm3_present == false)
        return PM3_ENOTTY;

    uint8_t effective_divisor = (divisor > -1) ? (uint8_t)divisor : LF_COTAG_DIVISOR;

    /* Set lf config divisor for cotag, restore lfconfig at the end. */
    sample_config orig_config;
    int res = lf_getconfig(&orig_config);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "could not read current LF config");
        return res;
    }

    sample_config tmp_config = orig_config;
    tmp_config.divisor = effective_divisor;
    tmp_config.verbose = verbose;
    res = lf_setconfig(&tmp_config);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "could not set LF config");
        return res;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "\nUsing divisor " _YELLOW_("%u") " (%.2f kHz)\n", effective_divisor, LF_DIV2FREQ(effective_divisor));
    }

    if (cm || realtime) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    int ret = PM3_SUCCESS;
    do {
        ret = lf_read_cotag(realtime, verbose, samples);
    } while (cm && (kbd_enter_pressed() == false));

    orig_config.verbose = false;
    lf_setconfig(&orig_config);

    if (verbose) {
        PrintAndLogEx(INFO, "\nRestored divisor " _YELLOW_("%u") " (%.2f kHz)\n", orig_config.divisor, LF_DIV2FREQ(orig_config.divisor));
    }

    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Got " _YELLOW_("%zu") " samples", g_GraphTraceLen);

        if (getSignalProperties()->isnoise) {
            PrintAndLogEx(INFO, "signal looks like noise");
        }
    }
    return ret;
}

#if 0 // TODO: Remove this implementation?
// When reading a COTAG.
// 0 = HIGH/LOW signal - maxlength bigbuff
// 1 = translation for HI/LO into bytes with manchester 0,1 - length 300
// 2 = raw signal -  maxlength bigbuff
int CmdCOTAGReader_old(const char *Cmd) {

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
    while (WaitForResponseTimeout(CMD_LF_COTAG_READ, &resp, 1000) == false) {
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
#endif

static command_t CommandTable[] = {
    {"help",    CmdHelp,         AlwaysAvailable, "This help"},
    {"demod",   CmdCOTAGDemod,   AlwaysAvailable, "demodulate a COTAG tag"},
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
    return (CmdCOTAGReader("") == PM3_SUCCESS && CmdCOTAGDemod("") == PM3_SUCCESS);
}

/**
 * Find average high and average low amplitude by sliding a 256-sample window
 * over the first 8*clock samples (DC-removed values).
 *
 * @param samples       DC-removed samples array.
 * @param num_samples   Total number of samples.
 * @param clock         Samples per clock cycle.
 * @param out_avg_high  the highest window average seen
 * @param out_avg_low   the lowest window average seen
 */
static void find_avg_high_low(const int32_t *samples, int num_samples,
                              int clock,
                              double *out_avg_high, double *out_avg_low) {
    const int WINDOW = 256;
    double avg_high = -127.0;
    double avg_low  = 127.0;

    int scan_end = 8 * clock;
    if (scan_end > num_samples)
        scan_end = num_samples;

    for (int i = 0; i + WINDOW <= scan_end; i++) {
        double window_avg = 0.0;
        for (int k = 0; k < WINDOW; k++)
            window_avg += abs(samples[i + k]);
        window_avg /= WINDOW;

        if (window_avg < avg_low)
            avg_low = window_avg;
        if (window_avg > avg_high)
            avg_high = window_avg;
    }

    *out_avg_high = avg_high;
    *out_avg_low  = avg_low;
}

/**
 * Find the first amplitude edge (threshold crossing) in samples[],
 * starting at index_start, with glitch rejection.
 *
 * @param samples      Array of (DC-removed) samples.
 * @param num_samples  Number of samples in the array.
 * @param index_start  Index to start scanning from.
 * @param threshold    Amplitude threshold defining "high".
 *
 * @return Index of the detected edge, or 0 if none found.
 */
static int detect_edge(const int32_t *samples, int num_samples,
                       int index_start, int32_t threshold) {
    const int GLITCH_WINDOW = 10;

    if (num_samples <= 0 || index_start < 0 || index_start >= num_samples)
        return 0;

    bool prev_high = abs(samples[index_start]) >= threshold;

    for (int i = index_start + 1; i < num_samples; i++) {
        bool curr_high = abs(samples[i]) >= threshold;

        if (curr_high != prev_high) {
            /* Need enough samples on both sides for glitch check */
            if ((int)i < GLITCH_WINDOW || i + GLITCH_WINDOW > num_samples) {
                prev_high = curr_high;
                continue;
            }

            /* Sum of GLITCH_WINDOW absolute values before the crossing */
            int64_t before_sum = 0;
            for (int k = 0; k < GLITCH_WINDOW; k++)
                before_sum += abs(samples[i - GLITCH_WINDOW + k]);

            /* Sum of GLITCH_WINDOW absolute values after the crossing */
            int64_t after_sum = 0;
            for (int k = 0; k < GLITCH_WINDOW; k++)
                after_sum += abs(samples[i + k]);

            bool before_high = before_sum >= (int64_t)threshold * GLITCH_WINDOW;
            bool after_high  = after_sum  >= (int64_t)threshold * GLITCH_WINDOW;

            if (before_high != after_high)
                return (int)i;
        }

        prev_high = curr_high;
    }

    return 0;
}
