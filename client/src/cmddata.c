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
// Data and Graph commands
//-----------------------------------------------------------------------------
#include "cmddata.h"
#include <stdio.h>
#include <string.h>
#include <limits.h>              // for CmdNorm INT_MIN && INT_MAX
#include <math.h>                // pow
#include <ctype.h>               // tolower
#include <locale.h>              // number formatter..
#include "commonutil.h"          // ARRAYLEN
#include "cmdparser.h"           // for command_t
#include "ui.h"                  // for show graph controls
#include "proxgui.h"
#include "graph.h"               // for graph data
#include "comms.h"
#include "lfdemod.h"             // for demod code
#include "loclass/cipherutils.h" // for decimating samples in getsamples
#include "cmdlfem410x.h"         // askem410xdecode
#include "fileutils.h"           // searchFile
#include "cliparser.h"
#include "cmdlft55xx.h"          // print...
#include "crypto/asn1utils.h"    // ASN1 decode / print
#include "cmdflashmemspiffs.h"   // SPIFFS flash memory download
#include "mbedtls/bignum.h"      // big num
#include "mbedtls/entropy.h"     //
#include "mbedtls/ctr_drbg.h"    // random generator
#include "atrs.h"                // ATR lookup
#include "crypto/libpcrypto.h"   // Cryptography


uint8_t g_DemodBuffer[MAX_DEMOD_BUF_LEN] = { 0x00 };
size_t g_DemodBufferLen = 0;
int32_t g_DemodStartIdx = 0;
int g_DemodClock = 0;

static int CmdHelp(const char *Cmd);


// https://www.eskimo.com/~scs/c-faq.com/stdio/commaprint.html
static char *commaprint(size_t n) {

    static int comma = '\0';
    static char retbuf[30];

    char *p = &retbuf[sizeof(retbuf) - 1];
    int i = 0;

    if (comma == '\0') {

        struct lconv *lcp = localeconv();
        if (lcp != NULL) {

            if (lcp->thousands_sep != NULL && *lcp->thousands_sep != '\0') {
                comma = *lcp->thousands_sep;
            } else {
                comma = ',';
            }
        }
    }

    *p = '\0';

    do {
        if (i % 3 == 0 && i != 0) {
            *--p = comma;
        }

        *--p = '0' + n % 10;

        n /= 10;

        i++;

    } while (n != 0);

    return p;
}

// set the g_DemodBuffer with given array ofq binary (one bit per byte)
void setDemodBuff(const uint8_t *buff, size_t size, size_t start_idx) {
    if (buff == NULL) return;

    if (size > MAX_DEMOD_BUF_LEN - start_idx)
        size = MAX_DEMOD_BUF_LEN - start_idx;

    for (size_t i = 0; i < size; i++)
        g_DemodBuffer[i] = buff[start_idx++];

    g_DemodBufferLen = size;
}

bool getDemodBuff(uint8_t *buff, size_t *size) {
    if (buff == NULL) return false;
    if (size == NULL) return false;
    if (*size == 0) return false;

    *size = (*size > g_DemodBufferLen) ? g_DemodBufferLen : *size;

    memcpy(buff, g_DemodBuffer, *size);
    return true;
}

// include <math.h>
// Root mean square
/*
static double rms(double *v, size_t n) {
    double sum = 0.0;
    for (size_t i = 0; i < n; i++)
        sum += v[i] * v[i];
    return sqrt(sum / n);
}

static int cmp_int(const void *a, const void *b) {
    if (*(const int *)a < * (const int *)b)
        return -1;
    else
        return *(const int *)a > *(const int *)b;
}
static int cmp_uint8(const void *a, const void *b) {
    if (*(const uint8_t *)a < * (const uint8_t *)b)
        return -1;
    else
        return *(const uint8_t *)a > *(const uint8_t *)b;
}
// Median of a array of values

static double median_int(int *src, size_t size) {
    qsort(src, size, sizeof(int), cmp_int);
    return 0.5 * (src[size / 2] + src[(size - 1) / 2]);
}
static double median_uint8(uint8_t *src, size_t size) {
    qsort(src, size, sizeof(uint8_t), cmp_uint8);
    return 0.5 * (src[size / 2] + src[(size - 1) / 2]);
}
*/
// function to compute mean for a series
static double compute_mean(const int *data, size_t n) {
    double mean = 0.0;
    for (size_t i = 0; i < n; i++)
        mean += data[i];
    mean /= n;
    return mean;
}

//  function to compute variance for a series
static double compute_variance(const int *data, size_t n) {
    double variance = 0.0;
    double mean = compute_mean(data, n);

    for (size_t i = 0; i < n; i++)
        variance += pow((data[i] - mean), 2.0);

    variance /= n;
    return variance;
}

// Function to compute autocorrelation for a series
//  Author: Kenneth J. Christensen
//  - Corrected divide by n to divide (n - lag) from Tobias Mueller
/*
static double compute_autoc(const int *data, size_t n, int lag) {
    double autocv = 0.0;    // Autocovariance value
    double ac_value;        // Computed autocorrelation value to be returned
    double variance;        // Computed variance
    double mean;

    mean = compute_mean(data, n);
    variance = compute_variance(data, n);

    for (size_t i=0; i < (n - lag); i++)
        autocv += (data[i] - mean) * (data[i+lag] - mean);

    autocv = (1.0 / (n - lag)) * autocv;

    // Autocorrelation is autocovariance divided by variance
    ac_value = autocv / variance;
    return ac_value;
}
*/

static int CmdSetDebugMode(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data setdebugmode",
                  "Set debugging level on client side",
                  "data setdebugmode"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("0", NULL, "no debug messages"),
        arg_lit0("1", NULL, "debug"),
        arg_lit0("2", NULL, "verbose debugging"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool dg_0 = arg_get_lit(ctx, 1);
    bool dg_1 = arg_get_lit(ctx, 2);
    bool dg_2 = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (dg_0 + dg_1 + dg_2 > 1) {
        PrintAndLogEx(INFO, "Select only one option");
        return PM3_EINVARG;
    }
    if (dg_0)
        g_debugMode = 0;

    if (dg_1)
        g_debugMode = 1;

    if (dg_2)
        g_debugMode = 2;

    switch (g_debugMode) {
        case 0:
            PrintAndLogEx(INFO, "client debug level... %u ( no debug messages )", g_debugMode);
            break;
        case 1:
            PrintAndLogEx(INFO, "client debug level... %u ( debug messages )", g_debugMode);
            break;
        case 2:
            PrintAndLogEx(INFO, "client debug level... %u ( verbose debug messages )", g_debugMode);
            break;
        default:
            break;
    }
    return PM3_SUCCESS;
}

// max output to MAX_DEMODULATION_BITS bits if we have more
// doesn't take inconsideration where the demod offset or bitlen found.
int printDemodBuff(uint8_t offset, bool strip_leading, bool invert, bool print_hex) {
    size_t len = g_DemodBufferLen;
    if (len == 0) {
        PrintAndLogEx(WARNING, "DemodBuffer is empty");
        return PM3_EINVARG;
    }

    uint8_t *buf = calloc(len, sizeof(uint8_t));
    if (buf == NULL) {
        PrintAndLogEx(WARNING, "fail, cannot allocate memory");
        return PM3_EMALLOC;
    }
    memcpy(buf, g_DemodBuffer, len);

    uint8_t *p = NULL;

    if (strip_leading) {
        p = (buf + offset);

        if (len > (g_DemodBufferLen - offset)) {
            len = (g_DemodBufferLen - offset);
        }

        size_t i;
        for (i = 0; i < len; i++) {
            if (p[i] == 1) {
                break;
            }
        }
        offset += i;
    }

    if (len > (g_DemodBufferLen - offset)) {
        len = (g_DemodBufferLen - offset);
    }

    if (len > MAX_DEMODULATION_BITS)  {
        len = MAX_DEMODULATION_BITS;
    }

    if (invert) {

        p = (buf + offset);

        for (size_t i = 0; i < len; i++) {
            if (p[i] == 1) {
                p[i] = 0;
            } else {
                if (p[i] == 0) {
                    p[i] = 1;
                }
            }
        }
    }

    if (print_hex) {
        p = (buf + offset);
        char hex[MAX_DEMODULATION_BITS + 1] = { 0x00 };
        int num_bits = binarray_2_hex(hex, sizeof(hex), (char *)p, len);

        if (num_bits == 0) {
            p = NULL;
            free(buf);
            return PM3_ESOFT;
        }

        PrintAndLogEx(SUCCESS, "DemodBuffer:\n%s", hex);
    } else {
        PrintAndLogEx(SUCCESS, "DemodBuffer:\n%s", sprint_bytebits_bin_break(buf + offset, len, 32));
    }

    p = NULL;
    free(buf);
    return PM3_SUCCESS;
}

int CmdPrintDemodBuff(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data print",
                  "Print the data in the DemodBuffer as hex or binary.\n"
                  "Defaults to binary output",
                  "data print"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("i", "inv", "invert DemodBuffer before printing"),
//        arg_int0("l","len", "<dec>", "length to print in # of bits or hex characters respectively"),
        arg_int0("o", "offset", "<dec>", "offset in # of bits"),
        arg_lit0("s", "strip", "strip leading zeroes, i.e. set offset to first bit equal to one"),
        arg_lit0("x", "hex", "output in hex (omit for binary output)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool invert = arg_get_lit(ctx, 1);
    int os = arg_get_int_def(ctx, 2, 0);
    bool lstrip = arg_get_lit(ctx, 3);
    bool print_hex = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    uint8_t offset = (os & 0xFF);

    return printDemodBuff(offset, lstrip, invert, print_hex);
}

// this function strictly converts >1 to 1 and <1 to 0 for each sample in the graphbuffer
int CmdGetBitStream(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data getbitstream",
                  "Convert GraphBuffer's value accordingly\n"
                  "   - larger or equal to ONE becomes ONE\n"
                  "   - less than ONE becomes ZERO",
                  "data getbitstream"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    CmdHpf("");
    for (uint32_t i = 0; i < g_GraphTraceLen; i++) {
        g_GraphBuffer[i] = (g_GraphBuffer[i] >= 1) ? 1 : 0;
    }
    RepaintGraphWindow();
    return PM3_SUCCESS;
}

static int CmdConvertBitStream(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data convertbitstream",
                  "Convert GraphBuffer's 0|1 values to 127|-127",
                  "data convertbitstream"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    if (isGraphBitstream()) {
        convertGraphFromBitstream();
    } else {
        // get high, low
        convertGraphFromBitstreamEx(-126, -127);
    }
    return PM3_SUCCESS;
}

// Cmd Args: Clock, invert, maxErr, maxLen as integers and amplify as char == 'a'
//   (amp may not be needed anymore)
// verbose will print results and demoding messages
// emSearch will auto search for EM410x format in bitstream
// askType switches decode: ask/raw = 0, ask/manchester = 1
int ASKDemod_ext(int clk, int invert, int maxErr, size_t maxlen, bool amplify, bool verbose, bool emSearch, uint8_t askType, bool *stCheck) {
    PrintAndLogEx(DEBUG, "DEBUG: (ASKDemod_ext) clk %i invert %i maxErr %i maxLen %zu amplify %i verbose %i emSearch %i askType %i "
                  , clk
                  , invert
                  , maxErr
                  , maxlen
                  , amplify
                  , verbose
                  , emSearch
                  , askType
                 );
    uint8_t askamp = 0;

    if (maxlen == 0)
        maxlen = g_pm3_capabilities.bigbuf_size;

    uint8_t *bits = calloc(MAX_GRAPH_TRACE_LEN, sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(INFO, "failed to allocate memory");
        return PM3_EMALLOC;
    }

    size_t bitlen = getFromGraphBuffer(bits);

    PrintAndLogEx(DEBUG, "DEBUG: (ASKDemod_ext) #samples from graphbuff: %zu", bitlen);

    if (bitlen < 255) {
        free(bits);
        return PM3_ESOFT;
    }

    if (maxlen < bitlen && maxlen != 0)
        bitlen = maxlen;

    int foundclk = 0;

    //amplify signal before ST check
    if (amplify) {
        askAmp(bits, bitlen);
    }

    size_t ststart = 0, stend = 0;
//    if (*stCheck)
    bool st = DetectST(bits, &bitlen, &foundclk, &ststart, &stend);

    if (clk == 0) {
        if (foundclk == 32 || foundclk == 64) {
            clk = foundclk;
        }
    }

    if (st) {
        *stCheck = st;
        g_MarkerC.pos = ststart;
        g_MarkerD.pos = stend;
        if (verbose)
            PrintAndLogEx(DEBUG, "Found Sequence Terminator - First one is shown by orange / blue graph markers");
    }

    int start_idx = 0;
    int errCnt = askdemod_ext(bits, &bitlen, &clk, &invert, maxErr, askamp, askType, &start_idx);
    if (start_idx >= clk / 2) {
        start_idx -= clk / 2;
    }
    if (askType == 0) {   // if not Manchester, clock width is halved
        clk /= 2;
    }
    if (errCnt < 0 || bitlen < 16) { //if fatal error (or -1)
        PrintAndLogEx(DEBUG, "DEBUG: (ASKDemod_ext) No data found errors:%d, %s bitlen:%zu, clock:%i"
                      , errCnt
                      , (invert) ? "inverted," : ""
                      , bitlen
                      , clk
                     );
        free(bits);
        return PM3_ESOFT;
    }

    if (errCnt > maxErr) {
        PrintAndLogEx(DEBUG, "DEBUG: (ASKDemod_ext) Too many errors found, errors:%d, bits:%zu, clock:%i"
                      , errCnt
                      , bitlen
                      , clk
                     );
        free(bits);
        return PM3_ESOFT;
    }

    if (verbose) {
        PrintAndLogEx(DEBUG, "DEBUG: (ASKDemod_ext) using clock:%i, %sbits found:%zu, start index %d"
                      , clk
                      , (invert) ? "inverted, " : ""
                      , bitlen
                      , start_idx
                     );
    }

    //output
    setDemodBuff(bits, bitlen, 0);
    setClockGrid(clk, start_idx);

    if (verbose) {
        if (errCnt > 0)
            PrintAndLogEx(DEBUG, "# Errors during demoding (shown as 7 in bit stream)... " _RED_("%d"), errCnt);

        if (askType) {
            PrintAndLogEx(SUCCESS, _YELLOW_("ASK/Manchester") " - clock " _YELLOW_("%i") " - decoded bitstream", clk);
            PrintAndLogEx(INFO, "-----------------------------------------------");
        } else {
            PrintAndLogEx(SUCCESS, _YELLOW_("ASK/Raw") " - clock " _YELLOW_("%i") " - decoded bitstream", clk);
            PrintAndLogEx(INFO, "----------------------------------------");
        }

        printDemodBuff(0, false, false, false);
    }
    uint64_t lo = 0;
    uint32_t hi = 0;
    if (emSearch)
        AskEm410xDecode(true, &hi, &lo);

    free(bits);
    return PM3_SUCCESS;
}

int ASKDemod(int clk, int invert, int maxErr, size_t maxlen, bool amplify, bool verbose, bool emSearch, uint8_t askType) {
    bool st = false;
    return ASKDemod_ext(clk, invert, maxErr, maxlen, amplify, verbose, emSearch, askType, &st);
}

// takes 5 arguments - clock, invert, maxErr, maxLen as integers and amplify as char == 'a'
// attempts to demodulate ask while decoding manchester
// prints binary found and saves in graphbuffer for further commands
static int Cmdaskmandemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data rawdemod --am",
                  "ASK/MANCHESTER demodulate the data in the GraphBuffer and output binary",
                  "data rawdemod --am                    --> demod a ask/manchester tag, using autodetect\n"
                  "data rawdemod --am -c 32              --> demod a ask/manchester tag, using a clock of RF/32\n"
                  "data rawdemod --am -i                 --> demod a ask/manchester tag, using autodetect, invert output\n"
                  "data rawdemod --am -c 32 -i           --> demod a ask/manchester tag, using a clock of RF/32, invert output\n"
                  "data rawdemod --am -c 64 -i --max 0   --> demod a ask/manchester tag, using a clock of RF/64, inverting and allowing 0 demod errors\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a", "amp", "try attempt demod with ask amplification (def no amp)"),
        arg_int0("c", "clk", "<dec>", "set clock manually (def autodetect)"),
        arg_lit0("i", "inv", "invert output"),
        arg_lit0("s", "st", "check for sequence terminator"),
        arg_int0(NULL, "max", "<dec>", "maximum allowed errors (def 100)"),
        arg_int0(NULL, "samples", "<dec>", "maximum samples to read (def 32768) [512 bits at RF/64]"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool amplify = arg_get_lit(ctx, 1);
    uint16_t clk = (uint16_t)arg_get_int_def(ctx, 2, 0);
    bool invert = arg_get_lit(ctx, 3);
    bool st = arg_get_lit(ctx, 4);
    uint8_t max_err = (uint8_t)arg_get_int_def(ctx, 5, 100) & 0xFF;
    size_t max_len = (size_t)arg_get_int_def(ctx, 6, 0) & 0xFF;
    CLIParserFree(ctx);

    return ASKDemod_ext(clk, invert, max_err, max_len, amplify, true, true, 1, &st);
}

// manchester decode
// strictly take 10 and 01 and convert to 0 and 1
static int Cmdmandecoderaw(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data manrawdecode",
                  "Manchester decode binary stream in DemodBuffer\n"
                  "Converts 10 and 01 and converts to 0 and 1 respectively\n"
                  " - must have binary sequence in DemodBuffer (run `data rawdemod --ar` before)",
                  "data manrawdecode"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("i", "inv", "invert output"),
        arg_int0(NULL, "err", "<dec>", "set max errors tolerated (def 20)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool invert = arg_get_lit(ctx, 1);
    int max_err = arg_get_int_def(ctx, 2, 20);
    CLIParserFree(ctx);

    if (g_DemodBufferLen == 0) {
        PrintAndLogEx(WARNING, "DemodBuffer empty, run " _YELLOW_("`data rawdemod --ar`"));
        return PM3_ESOFT;
    }

    uint8_t *bits = calloc(MAX_DEMOD_BUF_LEN, sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(FAILED, "failed to allocate memory");
        return PM3_EMALLOC;
    }

    // make sure its just binary data 0|1|7 in buffer
    int high = 0, low = 0;
    size_t i = 0;
    for (; i < g_DemodBufferLen; ++i) {
        if (g_DemodBuffer[i] > high)
            high = g_DemodBuffer[i];
        else if (g_DemodBuffer[i] < low)
            low = g_DemodBuffer[i];
        bits[i] = g_DemodBuffer[i];
    }

    if (high > 7 || low < 0) {
        PrintAndLogEx(ERR, "Error: please first raw demod then manchester raw decode");
        free(bits);
        return PM3_ESOFT;
    }

    size_t size = i;
    uint8_t offset = 0;
    uint16_t err_cnt = manrawdecode(bits, &size, invert, &offset);
    if (err_cnt > max_err) {
        PrintAndLogEx(ERR, "Too many errors attempting to decode " _RED_("%i"), err_cnt);
        free(bits);
        return PM3_ESOFT;
    }

    if (err_cnt > 0) {
        PrintAndLogEx(WARNING, "# %i errors found during demod (shown as " _YELLOW_(".")" in bit stream) ", err_cnt);
    }

    PrintAndLogEx(INFO, "Manchester decoded %s", (invert) ? "( inverted )" : "");
    PrintAndLogEx(INFO, "%s", sprint_bytebits_bin_break(bits, size, 32));

    // try decode EM410x
    if (err_cnt == 0) {
        uint64_t id = 0;
        uint32_t hi = 0;
        size_t idx = 0;
        size_t tmpsize = 0;
        int res = Em410xDecode(bits, &tmpsize, &idx, &hi, &id);
        if (res > 0) {
            //need to adjust to set bitstream back to manchester encoded data
            //setDemodBuff(bits, size, idx);
            printEM410x(hi, id, false, res);

            size = tmpsize;
        }
    }
    setDemodBuff(bits, size, 0);
    setClockGrid(g_DemodClock * 2, g_DemodStartIdx);
    free(bits);
    return PM3_SUCCESS;
}

/*
 *  @author marshmellow
 * biphase decode
 * decodes 01 or 10 -> ZERO
 *         11 or 00 -> ONE
 * param offset adjust start position
 * param invert invert output
 * param masxErr maximum tolerated errors
 */
static int CmdBiphaseDecodeRaw(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data biphaserawdecode",
                  "Biphase decode binary stream in DemodBuffer\n"
                  "Converts 10 or 01 -> 1 and 11 or 00 -> 0\n"
                  " - must have binary sequence in DemodBuffer (run `data rawdemod --ar` before)\n"
                  " - invert for Conditional Dephase Encoding (CDP) AKA Differential Manchester",
                  "data biphaserawdecode      --> decode biphase bitstream from the DemodBuffer\n"
                  "data biphaserawdecode -oi  --> decode biphase bitstream from the DemodBuffer, adjust offset, and invert output"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("o", "offset", "set to adjust decode start position"),
        arg_lit0("i", "inv", "invert output"),
        arg_int0(NULL, "err", "<dec>", "set max errors tolerated (def 20)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int offset = arg_get_lit(ctx, 1);
    bool invert = arg_get_lit(ctx, 2);
    int max_err = arg_get_int_def(ctx, 3, 20);
    CLIParserFree(ctx);

    if (g_DemodBufferLen == 0) {
        PrintAndLogEx(WARNING, "DemodBuffer empty, run " _YELLOW_("`data rawdemod --ar`"));
        return PM3_ESOFT;
    }

    uint8_t *bits = calloc(MAX_DEMOD_BUF_LEN, sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(FAILED, "failed to allocate memory");
        return PM3_EMALLOC;
    }

    size_t size = MAX_DEMOD_BUF_LEN;
    if (!getDemodBuff(bits, &size)) {
        free(bits);
        return PM3_ESOFT;
    }

    int err_cnt = BiphaseRawDecode(bits, &size, &offset, invert);
    if (err_cnt < 0) {
        PrintAndLogEx(ERR, "Error during decode " _RED_("%i"), err_cnt);
        free(bits);
        return PM3_ESOFT;
    }
    if (err_cnt > max_err) {
        PrintAndLogEx(ERR, "Too many errors attempting to decode " _RED_("%i"), err_cnt);
        free(bits);
        return PM3_ESOFT;
    }

    if (err_cnt > 0) {
        PrintAndLogEx(WARNING, "# %i errors found during demod (shown as " _YELLOW_(".")" in bit stream) ", err_cnt);
    }

    PrintAndLogEx(INFO, "Biphase decoded using offset %d%s", offset, (invert) ? "( inverted )" : "");
    PrintAndLogEx(INFO, "%s", sprint_bytebits_bin_break(bits, size, 32));

    setDemodBuff(bits, size, 0);
    setClockGrid(g_DemodClock * 2, g_DemodStartIdx + g_DemodClock * offset);
    free(bits);
    return PM3_SUCCESS;
}

// ASK Demod then Biphase decode g_GraphBuffer samples
int ASKbiphaseDemod(int offset, int clk, int invert, int maxErr, bool verbose) {
    //ask raw demod g_GraphBuffer first

    uint8_t *bs = calloc(MAX_DEMOD_BUF_LEN, sizeof(uint8_t));
    if (bs == NULL) {
        PrintAndLogEx(FAILED, "failed to allocate memory");
        return PM3_EMALLOC;
    }

    size_t size = getFromGraphBufferEx(bs, MAX_DEMOD_BUF_LEN);
    if (size == 0) {
        PrintAndLogEx(DEBUG, "DEBUG: no data in graphbuf");
        free(bs);
        return PM3_ESOFT;
    }
    int startIdx = 0;
    //invert here inverts the ask raw demoded bits which has no effect on the demod, but we need the pointer
    int errCnt = askdemod_ext(bs, &size, &clk, &invert, maxErr, 0, 0, &startIdx);
    if (errCnt < 0 || errCnt > maxErr) {
        PrintAndLogEx(DEBUG, "DEBUG: no data or error found %d, clock: %d", errCnt, clk);
        free(bs);
        return PM3_ESOFT;
    }

    //attempt to Biphase decode BitStream
    errCnt = BiphaseRawDecode(bs, &size, &offset, invert);
    if (errCnt < 0) {
        if (g_debugMode || verbose) PrintAndLogEx(DEBUG, "DEBUG: Error BiphaseRawDecode: %d", errCnt);
        free(bs);
        return PM3_ESOFT;
    }
    if (errCnt > maxErr) {
        if (g_debugMode || verbose) PrintAndLogEx(DEBUG, "DEBUG: Error BiphaseRawDecode too many errors: %d", errCnt);
        free(bs);
        return PM3_ESOFT;
    }

    if (offset >= 1) {
        offset -= 1;
    }
    //success set g_DemodBuffer and return
    setDemodBuff(bs, size, 0);
    setClockGrid(clk, startIdx + clk * offset / 2);
    if (g_debugMode || verbose) {
        PrintAndLogEx(DEBUG, "Biphase Decoded using offset %d | clock %d | #errors %d | start index %d\ndata\n", offset, clk, errCnt, (startIdx + clk * offset / 2));
        printDemodBuff(offset, false, false, false);
    }
    free(bs);
    return PM3_SUCCESS;
}

// see ASKbiphaseDemod
static int Cmdaskbiphdemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data rawdemod --ab",
                  "ASK/BIPHASE demodulate the data in the GraphBuffer and output binary\n"
                  "NOTE, `--invert` for Conditional Dephase Encoding (CDP) AKA Differential Manchester\n",
                  "data rawdemod --ab                    --> demod a ask/biphase tag, using autodetect\n"
                  "data rawdemod --ab -c 32              --> demod a ask/biphase tag, using a clock of RF/32\n"
                  "data rawdemod --ab -i                 --> demod a ask/biphase tag, using autodetect, invert output\n"
                  "data rawdemod --ab -c 32 -i           --> demod a ask/biphase tag, using a clock of RF/32, invert output\n"
                  "data rawdemod --ab -c 64 -i --max 0   --> demod a ask/biphase tag, using a clock of RF/64, inverting and allowing 0 demod errors\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int0("c", "clk", "<dec>", "set clock manually (def autodetect)"),
        arg_lit0("i", "inv", "invert output"),
        arg_int0("o", "offset", "<dec>", "offset to begin biphase (def 0)"),
        arg_int0(NULL, "max", "<dec>", "maximum allowed errors (def 50)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint16_t clk = (uint16_t)arg_get_int_def(ctx, 1, 0);
    bool invert = arg_get_lit(ctx, 2);
    int offset = arg_get_int_def(ctx, 3, 0);
    uint8_t max_err = (uint8_t)arg_get_int_def(ctx, 4, 50) & 0xFF;
    CLIParserFree(ctx);

    return ASKbiphaseDemod(offset, clk, invert, max_err, true);
}

// see ASKDemod
static int Cmdaskrawdemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data rawdemod --ar",
                  "ASK/RAW demodulate the data in the GraphBuffer and output binary",
                  "data rawdemod --ar -a                 --> demod a ask tag, using autodetect, amplified\n"
                  "data rawdemod --ar -c 32              --> demod a ask tag, using a clock of RF/32\n"
                  "data rawdemod --ar -i                 --> demod a ask tag, using autodetect, invert output\n"
                  "data rawdemod --ar -c 32 -i           --> demod a ask tag, using a clock of RF/32, invert output\n"
                  "data rawdemod --ar -c 64 -i --max 0   --> demod a ask tag, using a clock of RF/64, inverting and allowing 0 demod errors\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a", "amp", "try attempt demod with ask amplification (def no amp)"),
        arg_int0("c", "clk", "<dec>", "set clock manually (def autodetect)"),
        arg_lit0("i", "inv", "invert output"),
        arg_lit0("s", "st", "check for sequence terminator"),
        arg_int0(NULL, "max", "<dec>", "maximum allowed errors (def 100)"),
        arg_int0(NULL, "samples", "<dec>", "maximum samples to read (def 32768) [512 bits at RF/64]"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool amplify = arg_get_lit(ctx, 1);
    uint16_t clk = (uint16_t)arg_get_int_def(ctx, 2, 0);
    bool invert = arg_get_lit(ctx, 3);
    bool st = arg_get_lit(ctx, 4);
    uint8_t max_err = (uint8_t)arg_get_int_def(ctx, 5, 100) & 0xFF;
    size_t max_len = (size_t)arg_get_int_def(ctx, 6, 0) & 0xFF;
    CLIParserFree(ctx);

    return ASKDemod_ext(clk, invert, max_err, max_len, amplify, true, false, 0, &st);
}

int AutoCorrelate(const int *in, int *out, size_t len, size_t window, bool SaveGrph, bool verbose) {
    // sanity check
    if (window > len) {
        window = len;
    }

    //test
    double autocv = 0.0;    // Autocovariance value
    size_t correlation = 0;
    int lastmax = 0;

    // in, len, 4000
    double mean = compute_mean(in, len);
    // Computed variance
    double variance = compute_variance(in, len);

    int *correl_buf = calloc(MAX_GRAPH_TRACE_LEN, sizeof(int));

    uint8_t peak_cnt = 0;
    size_t peaks[10] = {0};

    for (size_t i = 0; i < len - window; ++i) {

        for (size_t j = 0; j < (len - i); j++) {
            autocv += (in[j] - mean) * (in[j + i] - mean);
        }
        autocv = (1.0 / (len - i)) * autocv;

        correl_buf[i] = autocv;

        // Computed autocorrelation value to be returned
        // Autocorrelation is autocovariance divided by variance
        double ac_value = autocv / variance;

        // keep track of which distance is repeating.
        // A value near 1.0 or more indicates a correlation in the signal
        if (ac_value > 0.95f) {
            correlation = i - lastmax;
            lastmax = i;

            if ((correlation > 1) && peak_cnt < ARRAYLEN(peaks)) {
                peaks[peak_cnt++] = correlation;
            }
        }
    }

    // Find shorts distance between peaks
    int distance = -1;
    for (size_t i = 0; i < ARRAYLEN(peaks); ++i) {

        PrintAndLogEx(DEBUG, "%zu | %zu", i, peaks[i]);
        if (peaks[i] < 128) {
            continue;
        }

        if (distance == -1) {
            distance = peaks[i];
            continue;
        }

        if (peaks[i] < distance) {
            distance = peaks[i];
        }
    }

    if (distance > -1) {
        if (verbose) {
            PrintAndLogEx(SUCCESS, "Possible correlation at "_YELLOW_("%4d") " samples", distance);
        }
    } else {
        PrintAndLogEx(HINT, "No repeating pattern found, try increasing window size");
        // return value -1, indication to increase window size
        return -1;
    }

    if (SaveGrph) {
        //g_GraphTraceLen = g_GraphTraceLen - window;
        memcpy(out, correl_buf, len * sizeof(int));
        setClockGrid(distance, 0);
        g_DemodBufferLen = 0;
        RepaintGraphWindow();
    }
    free(correl_buf);
    return distance;
}

static int CmdAutoCorr(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data autocorr",
                  "Autocorrelate over window is used to detect repeating sequences.\n"
                  "We use it as detection of how long in bits a message inside the signal is",
                  "data autocorr -w 4000\n"
                  "data autocorr -w 4000 -g"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("g", NULL, "save back to GraphBuffer (overwrite)"),
        arg_u64_0("w", "win", "<dec>", "window length for correlation. def 4000"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool updateGrph = arg_get_lit(ctx, 1);
    uint32_t window = arg_get_u32_def(ctx, 2, 4000);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "Using window size " _YELLOW_("%u"), window);

    if (g_GraphTraceLen == 0) {
        PrintAndLogEx(WARNING, "GraphBuffer is empty");
        PrintAndLogEx(HINT, "Try `" _YELLOW_("lf read") "` to collect samples");
        return PM3_ESOFT;
    }

    if (window >= g_GraphTraceLen) {
        PrintAndLogEx(WARNING, "window must be smaller than trace ( " _YELLOW_("%zu") " samples )", g_GraphTraceLen);
        return PM3_EINVARG;
    }

    AutoCorrelate(g_GraphBuffer, g_GraphBuffer, g_GraphTraceLen, window, updateGrph, true);
    return PM3_SUCCESS;
}

static int CmdBitsamples(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data bitsamples",
                  "Get raw samples from device as bitstring",
                  "data bitsamples"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    int cnt = 0;
    uint8_t got[12288];

    if (!GetFromDevice(BIG_BUF, got, sizeof(got), 0, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    for (size_t j = 0; j < ARRAYLEN(got); j++) {
        for (uint8_t k = 0; k < 8; k++) {
            if (got[j] & (1 << (7 - k)))
                g_GraphBuffer[cnt++] = 1;
            else
                g_GraphBuffer[cnt++] = 0;
        }
    }
    g_GraphTraceLen = cnt;
    RepaintGraphWindow();
    return PM3_SUCCESS;
}

static int CmdBuffClear(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data clear",
                  "This function clears the BigBuf on device side\n"
                  "and graph window ( graphbuffer )",
                  "data clear"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    clearCommandBuffer();
    SendCommandNG(CMD_BUFF_CLEAR, NULL, 0);
    ClearGraph(true);
    // iceman:  should clear all other new buffers getting introduced
    return PM3_SUCCESS;
}

static int CmdDecimate(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data decimate",
                  "Performs decimation, by reducing samples N times in the grapbuf. Good for PSK\n",
                  "data decimate\n"
                  "data decimate -n 4"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("n", NULL, "<dec>", "factor to reduce sample set (default 2)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int n = arg_get_int_def(ctx, 1, 2);
    CLIParserFree(ctx);

    for (size_t i = 0; i < (g_GraphTraceLen / n); ++i)
        g_GraphBuffer[i] = g_GraphBuffer[i * n];

    g_GraphTraceLen /= n;
    PrintAndLogEx(SUCCESS, "decimated by " _GREEN_("%u"), n);
    RepaintGraphWindow();
    return PM3_SUCCESS;
}
/**
 * Undecimate - I'd call it 'interpolate', but we'll save that
 * name until someone does an actual interpolation command, not just
 * blindly repeating samples
 * @param Cmd
 * @return
 */
static int CmdUndecimate(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data undecimate",
                  "Performs un-decimation, by repeating each sample N times in the graphbuf",
                  "data undecimate\n"
                  "data undecimate -n 4\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("n", NULL, "<dec>", "factor to repeat each sample (default 2)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int factor = arg_get_int_def(ctx, 1, 2);
    CLIParserFree(ctx);

    //We have memory, don't we?
    int *swap = calloc(MAX_GRAPH_TRACE_LEN, sizeof(int));
    if (swap == NULL) {
        PrintAndLogEx(FAILED, "failed to allocate memory");
        return PM3_EMALLOC;
    }
    uint32_t g_index = 0, s_index = 0;
    while (g_index < g_GraphTraceLen && s_index + factor < MAX_GRAPH_TRACE_LEN) {
        int count = 0;
        for (count = 0; count < factor && s_index + count < MAX_GRAPH_TRACE_LEN; count++) {
            swap[s_index + count] = (
                                        (double)(factor - count) / (factor - 1)) * g_GraphBuffer[g_index] +
                                    ((double)count / factor) * g_GraphBuffer[g_index + 1]
                                    ;
        }
        s_index += count;
        g_index++;
    }

    memcpy(g_GraphBuffer, swap, s_index * sizeof(int));
    g_GraphTraceLen = s_index;
    RepaintGraphWindow();
    free(swap);
    return PM3_SUCCESS;
}

// shift graph zero up or down based on input + or -
static int CmdGraphShiftZero(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data shiftgraphzero",
                  "Shift 0 for Graphed wave + or - shift value",
                  "data shiftgraphzero -n 10   --> shift 10 points\n"
                  "data shiftgraphzero -n -22  --> shift negative 22 points"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int1("n", NULL, "<dec>", "shift + or -"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int shift = arg_get_int_def(ctx, 1, 0);
    CLIParserFree(ctx);

    for (size_t i = 0; i < g_GraphTraceLen; i++) {
        int shiftedVal = g_GraphBuffer[i] + shift;

        if (shiftedVal > 127)
            shiftedVal = 127;
        else if (shiftedVal < -127)
            shiftedVal = -127;
        g_GraphBuffer[i] = shiftedVal;
    }
    CmdNorm("");
    return PM3_SUCCESS;
}

int AskEdgeDetect(const int *in, int *out, int len, int threshold) {
    int last = 0;
    for (int i = 1; i < len; i++) {
        if (in[i] - in[i - 1] >= threshold) //large jump up
            last = 127;
        else if (in[i] - in[i - 1] <= -1 * threshold) //large jump down
            last = -127;
        out[i - 1] = last;
    }
    return PM3_SUCCESS;
}

// use large jumps in read samples to identify edges of waves and then amplify that wave to max
// similar to dirtheshold, threshold commands
// takes a threshold length which is the measured length between two samples then determines an edge
static int CmdAskEdgeDetect(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data askedgedetect",
                  "Adjust Graph for manual ASK demod using the length of sample differences\n"
                  "to detect the edge of a wave",
                  "data askedgedetect -t 20"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int0("t", "thres", "<dec>", "threshold, use 20 - 45 (def 25)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int threshold = arg_get_int_def(ctx, 1, 25);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "using threshold " _YELLOW_("%i"), threshold);
    int res = AskEdgeDetect(g_GraphBuffer, g_GraphBuffer, g_GraphTraceLen, threshold);
    RepaintGraphWindow();
    return res;
}

// Print our clock rate
// uses data from graphbuffer
// adjusted to take char parameter for type of modulation to find the clock - by marshmellow.
static int CmdDetectClockRate(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data detectclock",
                  "Detect ASK, FSK, NRZ, PSK clock rate of wave in GraphBuffer",
                  "data detectclock --ask\n"
                  "data detectclock --nzr   --> detect clock of an nrz/direct wave in GraphBuffer\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "ask", "specify ASK modulation clock detection"),
        arg_lit0(NULL, "fsk", "specify FSK modulation clock detection"),
        arg_lit0(NULL, "nzr", "specify NZR/DIRECT modulation clock detection"),
        arg_lit0(NULL, "psk", "specify PSK modulation clock detection"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool a = arg_get_lit(ctx, 1);
    bool f = arg_get_lit(ctx, 2);
    bool n = arg_get_lit(ctx, 3);
    bool p = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    int tmp = (a + f + n + p);
    if (tmp > 1) {
        PrintAndLogEx(WARNING, "Only specify one modulation");
        return PM3_EINVARG;
    } else if (tmp == 0) {

        int clock = GetFskClock("", false);
        if (clock > 0) {
            PrintAndLogEx(SUCCESS, "FSK Clock... %d", clock);
        }
        clock = GetAskClock("", false);
        if (clock > 0) {
            PrintAndLogEx(SUCCESS, "ASK Clock... %d", clock);
        }
        clock = GetNrzClock("", false);
        if (clock > 0) {
            PrintAndLogEx(SUCCESS, "NRZ Clock... %d", clock);
        }
        clock = GetPskClock("", false);
        if (clock > 0) {
            PrintAndLogEx(SUCCESS, "PSK Clock... %d", clock);
        }
        return PM3_SUCCESS;
    }

    if (a)
        GetAskClock("", true);

    if (f)
        GetFskClock("", true);

    if (n)
        GetNrzClock("", true);

    if (p)
        GetPskClock("", true);

    RepaintGraphWindow();
    return PM3_SUCCESS;
}

static char *GetFSKType(uint8_t fchigh, uint8_t fclow, uint8_t invert) {
    static char fType[8];
    memset(fType, 0x00, 8);
    char *fskType = fType;

    if (fchigh == 10 && fclow == 8) {

        if (invert)
            memcpy(fskType, "FSK2a", 5);
        else
            memcpy(fskType, "FSK2", 4);

    } else if (fchigh == 8 && fclow == 5) {

        if (invert)
            memcpy(fskType, "FSK1", 4);
        else
            memcpy(fskType, "FSK1a", 5);

    } else {
        memcpy(fskType, "FSK??", 5);
    }
    return fskType;
}

// fsk raw demod and print binary
// takes 4 arguments - Clock, invert, fchigh, fclow
// defaults: clock = 50, invert=1, fchigh=10, fclow=8 (RF/10 RF/8 (fsk2a))
int FSKrawDemod(uint8_t rfLen, uint8_t invert, uint8_t fchigh, uint8_t fclow, bool verbose) {
    //raw fsk demod  no manchester decoding no start bit finding just get binary from wave
    if (getSignalProperties()->isnoise) {
        if (verbose) {
            PrintAndLogEx(INFO, "signal looks like noise");
        }
        return PM3_ESOFT;
    }

    uint8_t *bits = calloc(MAX_GRAPH_TRACE_LEN, sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(FAILED, "failed to allocate memory");
        return PM3_EMALLOC;
    }

    size_t bitlen = getFromGraphBuffer(bits);
    if (bitlen == 0) {
        PrintAndLogEx(DEBUG, "DEBUG: no data in graphbuf");
        free(bits);
        return PM3_ESOFT;
    }

    //get field clock lengths
    if (!fchigh || !fclow) {
        uint16_t fcs = countFC(bits, bitlen, true);
        if (!fcs) {
            fchigh = 10;
            fclow = 8;
        } else {
            fchigh = (fcs >> 8) & 0x00FF;
            fclow = fcs & 0x00FF;
        }
    }
    //get bit clock length
    if (!rfLen) {
        int firstClockEdge = 0; //todo - align grid on graph with this...
        rfLen = detectFSKClk(bits, bitlen, fchigh, fclow, &firstClockEdge);
        if (!rfLen) rfLen = 50;
    }

    int start_idx = 0;
    int size = fskdemod(bits, bitlen, rfLen, invert, fchigh, fclow, &start_idx);
    if (size > 0) {
        setDemodBuff(bits, size, 0);
        setClockGrid(rfLen, start_idx);

        // Now output the bitstream to the scrollback by line of 16 bits
        if (verbose || g_debugMode) {
            PrintAndLogEx(DEBUG, "DEBUG: (FSKrawDemod) using clock:%u, %sfc high:%u, fc low:%u"
                          , rfLen
                          , (invert) ? "inverted, " : ""
                          , fchigh
                          , fclow
                         );
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(SUCCESS, _YELLOW_("%s") " decoded bitstream", GetFSKType(fchigh, fclow, invert));
            PrintAndLogEx(INFO, "-----------------------");
            printDemodBuff(0, false, false, false);
        }
        goto out;
    } else {
        PrintAndLogEx(DEBUG, "no FSK data found");
    }

out:
    free(bits);
    return PM3_SUCCESS;
}

// fsk raw demod and print binary
// takes 4 arguments - Clock, invert, fchigh, fclow
// defaults: clock = 50, invert=1, fchigh=10, fclow=8 (RF/10 RF/8 (fsk2a))
static int CmdFSKrawdemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data rawdemod --fs",
                  "FSK demodulate the data in the GraphBuffer and output binary",
                  "data rawdemod --fs                         --> demod an fsk tag, using autodetect\n"
                  "data rawdemod --fs -c 32                   --> demod an fsk tag, using a clock of RF/32, autodetect fc\n"
                  "data rawdemod --fs -i                      --> demod an fsk tag, using autodetect, invert output\n"
                  "data rawdemod --fs -c 32 -i                --> demod an fsk tag, using a clock of RF/32, invert output, autodetect fc\n"
                  "data rawdemod --fs -c 64    --hi 8  --lo 5 --> demod an fsk1 RF/64 tag\n"
                  "data rawdemod --fs -c 50    --hi 10 --lo 8 --> demod an fsk2 RF/50 tag\n"
                  "data rawdemod --fs -c 50 -i --hi 10 --lo 8 --> demod an fsk2a RF/50 tag\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int0("c", "clk", "<dec>", "set clock manually (def: autodetect)"),
        arg_lit0("i", "inv", "invert output"),
        arg_int0(NULL, "hi", "<dec>", "larger field clock length (def: autodetect)"),
        arg_int0(NULL, "lo", "<dec>", "small field clock length (def: autodetect)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t clk = (uint8_t)arg_get_int_def(ctx, 1, 0) & 0xFF;
    bool invert = arg_get_lit(ctx, 2);
    uint8_t fchigh = (uint8_t)arg_get_int_def(ctx, 3, 0) & 0xFF;
    uint8_t fclow = (uint8_t)arg_get_int_def(ctx, 4, 0) & 0xFF;
    CLIParserFree(ctx);

    return FSKrawDemod(clk, invert, fchigh, fclow, true);
}

// attempt to psk1 demod graph buffer
int PSKDemod(int clk, int invert, int maxErr, bool verbose) {
    if (getSignalProperties()->isnoise) {
        if (verbose) {
            PrintAndLogEx(INFO, "signal looks like noise");
        }
        return PM3_ESOFT;
    }

    uint8_t *bits = calloc(MAX_GRAPH_TRACE_LEN, sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(FAILED, "failed to allocate memory");
        return PM3_EMALLOC;
    }
    size_t bitlen = getFromGraphBuffer(bits);
    if (bitlen == 0) {
        free(bits);
        return PM3_ESOFT;
    }

    int startIdx = 0;
    int errCnt = pskRawDemod_ext(bits, &bitlen, &clk, &invert, &startIdx);
    if (errCnt > maxErr) {
        if (g_debugMode || verbose) PrintAndLogEx(DEBUG, "DEBUG: (PSKdemod) Too many errors found, clk: %d, invert: %d, numbits: %zu, errCnt: %d", clk, invert, bitlen, errCnt);
        free(bits);
        return PM3_ESOFT;
    }
    if (errCnt < 0 || bitlen < 16) { //throw away static - allow 1 and -1 (in case of threshold command first)
        if (g_debugMode || verbose) PrintAndLogEx(DEBUG, "DEBUG: (PSKdemod) no data found, clk: %d, invert: %d, numbits: %zu, errCnt: %d", clk, invert, bitlen, errCnt);
        free(bits);
        return PM3_ESOFT;
    }
    if (verbose || g_debugMode) {
        PrintAndLogEx(DEBUG, "DEBUG: (PSKdemod) Using Clock:%d, invert:%d, Bits Found:%zu", clk, invert, bitlen);
        if (errCnt > 0) {
            PrintAndLogEx(DEBUG, "DEBUG: (PSKdemod) errors during Demoding (shown as 7 in bit stream): %d", errCnt);
        }
    }
    //prime g_DemodBuffer for output
    setDemodBuff(bits, bitlen, 0);
    setClockGrid(clk, startIdx);
    free(bits);
    return PM3_SUCCESS;
}

// takes 3 arguments - clock, invert, maxErr as integers
// attempts to demodulate nrz only
// prints binary found and saves in g_DemodBuffer for further commands
int NRZrawDemod(int clk, int invert, int maxErr, bool verbose) {

    int errCnt = 0, clkStartIdx = 0;

    if (getSignalProperties()->isnoise) {
        if (verbose) {
            PrintAndLogEx(INFO, "signal looks like noise");
        }
        return PM3_ESOFT;
    }

    uint8_t *bits = calloc(MAX_GRAPH_TRACE_LEN, sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(FAILED, "failed to allocate memory");
        return PM3_EMALLOC;
    }

    size_t bitlen = getFromGraphBuffer(bits);

    if (bitlen == 0) {
        free(bits);
        return PM3_ESOFT;
    }

    errCnt = nrzRawDemod(bits, &bitlen, &clk, &invert, &clkStartIdx);
    if (errCnt > maxErr) {
        PrintAndLogEx(DEBUG, "DEBUG: (NRZrawDemod) Too many errors found, clk: %d, invert: %d, numbits: %zu, errCnt: %d", clk, invert, bitlen, errCnt);
        free(bits);
        return PM3_ESOFT;
    }
    if (errCnt < 0 || bitlen < 16) { //throw away static - allow 1 and -1 (in case of threshold command first)
        PrintAndLogEx(DEBUG, "DEBUG: (NRZrawDemod) no data found, clk: %d, invert: %d, numbits: %zu, errCnt: %d", clk, invert, bitlen, errCnt);
        free(bits);
        return PM3_ESOFT;
    }

    if (verbose || g_debugMode) PrintAndLogEx(DEBUG, "DEBUG: (NRZrawDemod) Tried NRZ Demod using Clock: %d - invert: %d - Bits Found: %zu", clk, invert, bitlen);
    //prime g_DemodBuffer for output
    setDemodBuff(bits, bitlen, 0);
    setClockGrid(clk, clkStartIdx);


    if (errCnt > 0 && (verbose || g_debugMode)) PrintAndLogEx(DEBUG, "DEBUG: (NRZrawDemod) Errors during Demoding (shown as 7 in bit stream): %d", errCnt);
    if (verbose || g_debugMode) {
        PrintAndLogEx(SUCCESS, "NRZ demoded bitstream");
        PrintAndLogEx(INFO, "---------------------");
        // Now output the bitstream to the scrollback by line of 16 bits
        printDemodBuff(0, false, invert, false);
    }

    free(bits);
    return PM3_SUCCESS;
}

static int CmdNRZrawDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data rawdemod --nr",
                  "NRZ/DIRECT demodulate the data in the GraphBuffer and output binary",
                  "data rawdemod --nr                    --> demod a nrz/direct tag, using autodetect\n"
                  "data rawdemod --nr -c 32              --> demod a nrz/direct tag, using a clock of RF/32\n"
                  "data rawdemod --nr -i                 --> demod a nrz/direct tag, using autodetect, invert output\n"
                  "data rawdemod --nr -c 32 -i           --> demod a nrz/direct tag, using a clock of RF/32, invert output\n"
                  "data rawdemod --nr -c 64 -i --max 0   --> demod a nrz/direct tag, using a clock of RF/64, inverting and allowing 0 demod errors\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int0("c", "clk", "<dec>", "set clock manually (def autodetect)"),
        arg_lit0("i", "inv", "invert output"),
        arg_int0(NULL, "max", "<dec>", "maximum allowed errors (def 100)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint16_t clk = (uint16_t)arg_get_int_def(ctx, 1, 0);
    bool invert = arg_get_lit(ctx, 2);
    uint8_t max_err = (uint8_t)arg_get_int_def(ctx, 3, 100) & 0xFF;
    CLIParserFree(ctx);

    return NRZrawDemod(clk, invert, max_err, true);
}

// takes 3 arguments - clock, invert, max_err as integers
// attempts to demodulate psk only
// prints binary found and saves in g_DemodBuffer for further commands
int CmdPSK1rawDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data rawdemod --p1",
                  "PSK1 demodulate the data in the GraphBuffer and output binary",
                  "data rawdemod --p1                    --> demod a psk1 tag, using autodetect\n"
                  "data rawdemod --p1 -c 32              --> demod a psk1 tag, using a clock of RF/32\n"
                  "data rawdemod --p1 -i                 --> demod a psk1 tag, using autodetect, invert output\n"
                  "data rawdemod --p1 -c 32 -i           --> demod a psk1 tag, using a clock of RF/32, invert output\n"
                  "data rawdemod --p1 -c 64 -i --max 0   --> demod a psk1 tag, using a clock of RF/64, inverting and allowing 0 demod errors\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int0("c", "clk", "<dec>", "set clock manually (def autodetect)"),
        arg_lit0("i", "inv", "invert output"),
        arg_int0(NULL, "max", "<dec>", "maximum allowed errors (def 100)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint16_t clk = (uint16_t)arg_get_int_def(ctx, 1, 0);
    bool invert = arg_get_lit(ctx, 2);
    uint8_t max_err = (uint8_t)arg_get_int_def(ctx, 3, 100) & 0xFF;
    CLIParserFree(ctx);

    int ans = PSKDemod(clk, invert, max_err, true);
    //output
    if (ans != PM3_SUCCESS) {
        if (g_debugMode) PrintAndLogEx(ERR, "Error demoding: %d", ans);
        return PM3_ESOFT;
    }
    PrintAndLogEx(SUCCESS, _YELLOW_("PSK1") " demoded bitstream");
    PrintAndLogEx(INFO, "----------------------");
    // Now output the bitstream to the scrollback by line of 16 bits
    printDemodBuff(0, false, invert, false);
    return PM3_SUCCESS;
}

// takes same args as cmdpsk1rawdemod
static int CmdPSK2rawDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data rawdemod --p2",
                  "PSK2 demodulate the data in the GraphBuffer and output binary",
                  "data rawdemod --p2                    --> demod a psk2 tag, using autodetect\n"
                  "data rawdemod --p2 -c 32              --> demod a psk2 tag, using a clock of RF/32\n"
                  "data rawdemod --p2 -i                 --> demod a psk2 tag, using autodetect, invert output\n"
                  "data rawdemod --p2 -c 32 -i           --> demod a psk2 tag, using a clock of RF/32, invert output\n"
                  "data rawdemod --p2 -c 64 -i --max 0   --> demod a psk2 tag, using a clock of RF/64, inverting and allowing 0 demod errors\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int0("c", "clk", "<dec>", "set clock manually (def autodetect)"),
        arg_lit0("i", "inv", "invert output"),
        arg_int0(NULL, "max", "<dec>", "maximum allowed errors (def 100)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t clk = (uint8_t)arg_get_int_def(ctx, 1, 0) & 0xFF;
    bool invert = arg_get_lit(ctx, 2);
    uint8_t max_err = (uint8_t)arg_get_int_def(ctx, 3, 100) & 0xFF;
    CLIParserFree(ctx);

    int ans = PSKDemod(clk, invert, max_err, true);
    if (ans != PM3_SUCCESS) {
        if (g_debugMode) PrintAndLogEx(ERR, "Error demoding: %d", ans);
        return PM3_ESOFT;
    }
    psk1TOpsk2(g_DemodBuffer, g_DemodBufferLen);
    PrintAndLogEx(SUCCESS, _YELLOW_("PSK2") " demoded bitstream");
    PrintAndLogEx(INFO, "----------------------");
    // Now output the bitstream to the scrollback by line of 16 bits
    printDemodBuff(0, false, invert, false);
    return PM3_SUCCESS;
}

// combines all raw demod functions into one menu command
static int CmdRawDemod(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data rawdemod",
                  "Demodulate the data in the GraphBuffer and output binary",
                  "data rawdemod --fs    --> demod FSK - autodetect\n"
                  "data rawdemod --ab    --> demod ASK/BIPHASE - autodetect\n"
                  "data rawdemod --am    --> demod ASK/MANCHESTER - autodetect\n"
                  "data rawdemod --ar    --> demod ASK/RAW - autodetect\n"
                  "data rawdemod --nr    --> demod NRZ/DIRECT - autodetect\n"
                  "data rawdemod --p1    --> demod PSK1 - autodetect\n"
                  "data rawdemod --p2    --> demod PSK2 - autodetect\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "ab", "ASK/Biphase demodulation"),
        arg_lit0(NULL, "am", "ASK/Manchester demodulation"),
        arg_lit0(NULL, "ar", "ASK/Raw demodulation"),
        arg_lit0(NULL, "fs", "FSK demodulation"),
        arg_lit0(NULL, "nr", "NRZ/Direct demodulation"),
        arg_lit0(NULL, "p1", "PSK 1 demodulation"),
        arg_lit0(NULL, "p2", "PSK 2 demodulation"),
        arg_strn(NULL, NULL, "<params>", 0, 35, "params for sub command"),
        arg_param_end
    };

    //
    char tmp[5];
    size_t n = MIN(strlen(Cmd), sizeof(tmp) - 1);
    memset(tmp, 0, sizeof(tmp));
    strncpy(tmp, Cmd, sizeof(tmp) - 1);

    CLIExecWithReturn(ctx, tmp, argtable, false);
    bool ab = arg_get_lit(ctx, 1);
    bool am = arg_get_lit(ctx, 2);
    bool ar = arg_get_lit(ctx, 3);
    bool fs = arg_get_lit(ctx, 4);
    bool nr = arg_get_lit(ctx, 5);
    bool p1 = arg_get_lit(ctx, 6);
    bool p2 = arg_get_lit(ctx, 7);
    CLIParserFree(ctx);

    int foo = (ab + am + ar + fs + nr + p1 + p2);
    if (foo > 1) {
        PrintAndLogEx(WARNING, "please, select only one modulation");
        return PM3_EINVARG;
    }
    if (foo == 0) {
        PrintAndLogEx(WARNING, "please, select a modulation");
        return PM3_EINVARG;
    }

    int ans = 0;
    const char *s = Cmd + n;
    if (fs)
        ans = CmdFSKrawdemod(s);
    else if (ab)
        ans = Cmdaskbiphdemod(s);
    else if (am)
        ans = Cmdaskmandemod(s);
    else if (ar)
        ans = Cmdaskrawdemod(s);
    else if (nr)
        ans = CmdNRZrawDemod(s);
    else if (p1)
        ans = CmdPSK1rawDemod(s);
    else if (p2)
        ans = CmdPSK2rawDemod(s);

    return ans;
}

void setClockGrid(uint32_t clk, int offset) {
    g_DemodStartIdx = offset;
    g_DemodClock = clk;
    if (clk == 0 && offset == 0)
        PrintAndLogEx(DEBUG, "DEBUG: (setClockGrid) clear settings");
    else
        PrintAndLogEx(DEBUG, "DEBUG: (setClockGrid) demodoffset %d, clk %d", offset, clk);

    if (offset > clk) offset %= clk;
    if (offset < 0) offset += clk;

    if (offset > g_GraphTraceLen || offset < 0) return;
    if (clk < 8 || clk > g_GraphTraceLen) {
        g_GridLocked = false;
        g_GridOffset = 0;
        g_PlotGridX = 0;
        g_DefaultGridX = 0;
        RepaintGraphWindow();
    } else {
        g_GridLocked = true;
        g_GridOffset = offset;
        g_PlotGridX = clk;
        g_DefaultGridX = clk;
        RepaintGraphWindow();
    }
}

int CmdGrid(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data grid",
                  "This function overlay grid on graph plot window.\n"
                  "use zero value to turn off either",
                  "data grid               --> turn off\n"
                  "data grid -x 64 -y 50"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_dbl0("x", NULL, "<dec>", "plot grid X coord"),
        arg_dbl0("y", NULL, "<dec>", "plot grid Y coord"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    g_PlotGridX = arg_get_dbl_def(ctx, 1, 0);
    g_PlotGridY = arg_get_dbl_def(ctx, 2, 0);
    CLIParserFree(ctx);

    PrintAndLogEx(DEBUG, "Setting X %.0f  Y %.0f", g_PlotGridX, g_PlotGridY);
    g_DefaultGridX = g_PlotGridX;
    g_DefaultGridY = g_PlotGridY;
    RepaintGraphWindow();
    return PM3_SUCCESS;
}

static int CmdSetGraphMarkers(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data setgraphmarkers",
                  "Set the locations of the markers in the graph window",
                  "data setgraphmarkers               --> reset the markers\n"
                  "data setgraphmarkers -a 64         --> set A, reset the rest\n"
                  "data setgraphmarkers -d --keep     --> set D, keep the rest"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "keep", "keep the current values of the markers"),
        arg_u64_0("a", NULL, "<dec>", "yellow marker"),
        arg_u64_0("b", NULL, "<dec>", "purple marker"),
        arg_u64_0("c", NULL, "<dec>", "orange marker"),
        arg_u64_0("d", NULL, "<dec>", "blue marker"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool keep    = arg_get_lit(ctx, 1);
    g_MarkerA.pos = arg_get_u32_def(ctx, 2, (keep ? g_MarkerA.pos : 0));
    g_MarkerB.pos = arg_get_u32_def(ctx, 3, (keep ? g_MarkerB.pos : 0));
    g_MarkerC.pos = arg_get_u32_def(ctx, 4, (keep ? g_MarkerC.pos : 0));
    g_MarkerD.pos = arg_get_u32_def(ctx, 5, (keep ? g_MarkerD.pos : 0));
    CLIParserFree(ctx);
    PrintAndLogEx(INFO, "Setting markers " _BRIGHT_YELLOW_("A") "=%u, "_BRIGHT_MAGENTA_("B") "=%u, "_RED_("C") "=%u, "_BLUE_("D") "=%u",
                  g_MarkerA.pos,
                  g_MarkerB.pos,
                  g_MarkerC.pos,
                  g_MarkerD.pos
                 );
    RepaintGraphWindow();
    return PM3_SUCCESS;
}

static int CmdHexsamples(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data hexsamples",
                  "Dump big buffer as hex bytes",
                  "data hexsamples -n 128  -->  dumps 128 bytes from offset 0"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("b", "breaks", "<dec>", "row break, def 16"),
        arg_u64_0("n", NULL, "<dec>", "num of bytes to download"),
        arg_u64_0("o", "offset", "<hex>", "offset in big buffer"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    uint32_t breaks = arg_get_u32_def(ctx, 1, 16);
    uint32_t requested = arg_get_u32_def(ctx, 2, 8);
    uint32_t offset = arg_get_u32_def(ctx, 3, 0);
    CLIParserFree(ctx);

    // sanity checks
    if (requested > g_pm3_capabilities.bigbuf_size) {
        requested = g_pm3_capabilities.bigbuf_size;
        PrintAndLogEx(INFO, "n is larger than big buffer size, will use %u", requested);
    }

    uint8_t got[g_pm3_capabilities.bigbuf_size];
    if (offset + requested > sizeof(got)) {
        PrintAndLogEx(NORMAL, "Tried to read past end of buffer, <bytes %u> + <offset %u> > %d"
                      , requested
                      , offset
                      , g_pm3_capabilities.bigbuf_size
                     );
        return PM3_EINVARG;
    }

    if (!GetFromDevice(BIG_BUF, got, requested, offset, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ESOFT;
    }

    print_hex_break(got, requested, breaks);
    return PM3_SUCCESS;
}

static int CmdHide(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data hide",
                  "Show graph window",
                  "data hide"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    HideGraphWindow();
    return PM3_SUCCESS;
}

// zero mean g_GraphBuffer
int CmdHpf(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data hpf",
                  "Remove DC offset from trace. It should centralize around 0",
                  "data hpf"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    uint8_t *bits = calloc(g_GraphTraceLen, sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(FAILED, "failed to allocate memory");
        return PM3_EMALLOC;
    }
    size_t size = getFromGraphBuffer(bits);
    removeSignalOffset(bits, size);
    // push it back to graph
    setGraphBuffer(bits, size);
    // set signal properties low/high/mean/amplitude and is_noise detection
    computeSignalProperties(bits, size);

    RepaintGraphWindow();
    free(bits);
    return PM3_SUCCESS;
}

static bool _headBit(BitstreamOut_t *stream) {
    int bytepos = stream->position >> 3; // divide by 8
    int bitpos = (stream->position++) & 7; // mask out 00000111
    return (*(stream->buffer + bytepos) >> (7 - bitpos)) & 1;
}

static uint8_t getByte(uint8_t bits_per_sample, BitstreamOut_t *b) {
    uint8_t val = 0;
    for (int i = 0 ; i < bits_per_sample; i++)
        val |= (_headBit(b) << (7 - i));

    return val;
}

int getSamples(uint32_t n, bool verbose) {
    return getSamplesEx(0, n, verbose, false);
}

int getSamplesEx(uint32_t start, uint32_t end, bool verbose, bool ignore_lf_config) {

    if (end < start) {
        PrintAndLogEx(WARNING, "error, end (%u) is smaller than start (%u)", end, start);
        return PM3_EINVARG;
    }

    // If we get all but the last byte in bigbuf,
    // we don't have to worry about remaining trash
    // in the last byte in case the bits-per-sample
    // does not line up on byte boundaries
    uint8_t got[g_pm3_capabilities.bigbuf_size - 1];
    memset(got, 0x00, sizeof(got));

    uint32_t n = end - start;

    if (n == 0 || n > g_pm3_capabilities.bigbuf_size - 1) {
        n = g_pm3_capabilities.bigbuf_size - 1;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "Reading " _YELLOW_("%u") " bytes from device memory", n);
    }

    PacketResponseNG resp;
    if (GetFromDevice(BIG_BUF, got, n, start, NULL, 0, &resp, 10000, true) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (verbose) {
        PrintAndLogEx(SUCCESS, "Data fetched");
    }

    uint8_t bits_per_sample = 8;

    // Old devices without this feature would send 0 at arg[0]
    if (resp.oldarg[0] > 0 && (ignore_lf_config == false)) {
        sample_config *sc = (sample_config *) resp.data.asBytes;
        if (verbose) {
            PrintAndLogEx(INFO, "Samples @ " _YELLOW_("%d") " bits/smpl, decimation 1:%d ", sc->bits_per_sample, sc->decimation);
        }
        bits_per_sample = sc->bits_per_sample;
    }

    return getSamplesFromBufEx(got, n, bits_per_sample, verbose);;
}

int getSamplesFromBufEx(uint8_t *data, size_t sample_num, uint8_t bits_per_sample, bool verbose) {

    size_t max_num = MIN(sample_num, MAX_GRAPH_TRACE_LEN);

    if (bits_per_sample < 8) {

        if (verbose) PrintAndLogEx(INFO, "Unpacking...");

        BitstreamOut_t bout = {data, bits_per_sample * sample_num,  0};
        size_t j = 0;
        for (j = 0; j < max_num; j++) {
            uint8_t sample = getByte(bits_per_sample, &bout);
            g_GraphBuffer[j] = ((int) sample) - 127;
        }
        g_GraphTraceLen = j;

        if (verbose) PrintAndLogEx(INFO, "Unpacked %zu samples", j);

    } else {
        for (size_t j = 0; j < max_num; j++) {
            g_GraphBuffer[j] = ((int)data[j]) - 127;
        }
        g_GraphTraceLen = max_num;
    }

    uint8_t *bits = calloc(g_GraphTraceLen, sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(FAILED, "failed to allocate memory");
        return PM3_EMALLOC;
    }
    size_t size = getFromGraphBuffer(bits);
    // set signal properties low/high/mean/amplitude and is_noise detection
    computeSignalProperties(bits, size);
    free(bits);

    setClockGrid(0, 0);
    g_DemodBufferLen = 0;
    RepaintGraphWindow();

    return PM3_SUCCESS;
}

static int CmdSamples(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data samples",
                  "Get raw samples for graph window (GraphBuffer) from device.\n"
                  "If 0, then get whole big buffer from device.",
                  "data samples\n"
                  "data samples -n 10000"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int0("n", NULL, "<dec>", "num of samples (512 - 40000)"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int n = arg_get_int_def(ctx, 1, 0);
    bool verbose = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);
    return getSamples(n, verbose);
}


static int CmdLoad(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data load",
                  "This command loads the contents of a pm3 file into graph window\n",
                  "data load -f myfilename"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "file to load"),
        arg_lit0("b", "bin", "binary file"),
        arg_lit0("n",  "no-fix",  "Load data from file without any transformations"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    bool is_bin = arg_get_lit(ctx, 2);
    bool nofix = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    char *path = NULL;
    if (searchFile(&path, TRACES_SUBDIR, filename, ".pm3", true) != PM3_SUCCESS) {
        if (searchFile(&path, TRACES_SUBDIR, filename, "", false) != PM3_SUCCESS) {
            return PM3_EFILE;
        }
    }

    FILE *f;
    if (is_bin)
        f = fopen(path, "rb");
    else
        f = fopen(path, "r");

    if (f == NULL) {
        PrintAndLogEx(WARNING, "couldn't open '%s'", path);
        free(path);
        return PM3_EFILE;
    }
    free(path);

    g_GraphTraceLen = 0;

    if (is_bin) {
        uint8_t val[2];
        while (fread(val, 1, 1, f)) {
            g_GraphBuffer[g_GraphTraceLen] = val[0] - 127;
            g_GraphTraceLen++;

            if (g_GraphTraceLen >= MAX_GRAPH_TRACE_LEN)
                break;
        }
    } else {
        char line[80];
        while (fgets(line, sizeof(line), f)) {
            g_GraphBuffer[g_GraphTraceLen] = atoi(line);
            g_GraphTraceLen++;

            if (g_GraphTraceLen >= MAX_GRAPH_TRACE_LEN)
                break;
        }
    }
    fclose(f);

    PrintAndLogEx(SUCCESS, "loaded " _YELLOW_("%s") " samples", commaprint(g_GraphTraceLen));

    if (nofix == false) {
        uint8_t *bits = calloc(g_GraphTraceLen, sizeof(uint8_t));
        if (bits == NULL) {
            PrintAndLogEx(FAILED, "failed to allocate memory");
            return PM3_EMALLOC;
        }
        size_t size = getFromGraphBuffer(bits);

        removeSignalOffset(bits, size);
        setGraphBuffer(bits, size);
        computeSignalProperties(bits, size);
        free(bits);
    }

    setClockGrid(0, 0);
    g_DemodBufferLen = 0;
    RepaintGraphWindow();
    return PM3_SUCCESS;
}

// trim graph from the end
int CmdLtrim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data ltrim",
                  "Trim samples from left of trace",
                  "data ltrim -i 300   --> remove from start 0 to index 300"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_u64_1("i", "idx", "<dec>", "index in graph buffer"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    uint32_t ds = arg_get_u32(ctx, 1);
    CLIParserFree(ctx);

    // sanitycheck
    if (g_GraphTraceLen <= ds) {
        PrintAndLogEx(WARNING, "index out of bounds");
        return PM3_EINVARG;
    }

    for (size_t i = ds; i < g_GraphTraceLen; ++i) {
        g_GraphBuffer[i - ds] = g_GraphBuffer[i];
    }
    g_GraphTraceLen -= ds;
    g_DemodStartIdx -= ds;
    RepaintGraphWindow();
    return PM3_SUCCESS;
}

// trim graph from the beginning
static int CmdRtrim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data rtrim",
                  "Trim samples from right of trace",
                  "data rtrim -i 4000    --> remove from index 4000 to end of graph buffer"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_u64_1("i", "idx", "<dec>", "index in graph buffer"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    uint32_t ds = arg_get_u32(ctx, 1);
    CLIParserFree(ctx);

    // sanitycheck
    if (g_GraphTraceLen <= ds) {
        PrintAndLogEx(WARNING, "index out of bounds");
        return PM3_EINVARG;
    }

    g_GraphTraceLen = ds;
    RepaintGraphWindow();
    return PM3_SUCCESS;
}

// trim graph (middle) piece
static int CmdMtrim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data mtrim",
                  "Trim out samples from\n"
                  "  start 0 to `-s index`\n"
                  "AND\n"
                  "  from `-e index` to end of graph buffer",
                  "data mtrim -s 1000 -e 2000  -->  keep all between index 1000 and 2000"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_u64_1("s", "start", "<dec>", "start point"),
        arg_u64_1("e", "end", "<dec>", "end point"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    uint32_t start = arg_get_u32(ctx, 1);
    uint32_t stop = arg_get_u32(ctx, 2);
    CLIParserFree(ctx);

    if (start > g_GraphTraceLen || stop > g_GraphTraceLen || start >= stop) {
        PrintAndLogEx(WARNING, "start and end points doesn't align");
        return PM3_EINVARG;
    }

    // leave start position sample
    start++;

    g_GraphTraceLen = stop - start;
    for (uint32_t i = 0; i < g_GraphTraceLen; i++) {
        g_GraphBuffer[i] = g_GraphBuffer[start + i];
    }

    g_DemodStartIdx = 0;
    RepaintGraphWindow();
    return PM3_SUCCESS;
}

int CmdNorm(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data norm",
                  "Normalize max/min to +/-128",
                  "data norm"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    int max = INT_MIN, min = INT_MAX;

    // Find local min, max
    for (uint32_t i = 10; i < g_GraphTraceLen; ++i) {
        if (g_GraphBuffer[i] > max) max = g_GraphBuffer[i];
        if (g_GraphBuffer[i] < min) min = g_GraphBuffer[i];
    }

    if ((g_GraphTraceLen > 10) && (max != min)) {
        for (uint32_t i = 0; i < g_GraphTraceLen; ++i) {
            g_GraphBuffer[i] = ((long)(g_GraphBuffer[i] - ((max + min) / 2)) * 256) / (max - min);
            //marshmelow: adjusted *1000 to *256 to make +/- 128 so demod commands still work
        }
    }

    uint8_t *bits = calloc(g_GraphTraceLen, sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(FAILED, "failed to allocate memory");
        return PM3_EMALLOC;
    }
    size_t size = getFromGraphBuffer(bits);
    // set signal properties low/high/mean/amplitude and is_noise detection
    computeSignalProperties(bits, size);

    RepaintGraphWindow();
    free(bits);
    return PM3_SUCCESS;
}

int CmdPlot(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data plot",
                  "Show graph window \n"
                  "hit 'h' in window for detail keystroke help available",
                  "data plot"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    ShowGraphWindow();
    return PM3_SUCCESS;
}

int CmdSave(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data save",
                  "Save signal trace from graph window , i.e. the GraphBuffer\n"
                  "This is a text file with number -127 to 127.  With the option `w` you can save it as wave file\n"
                  "Filename should be without file extension",
                  "data save -f myfilename         -> save graph buffer to file\n"
                  "data save --wave -f myfilename  -> save graph buffer to wave file"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("w", "wave", "save as wave format (.wav)"),
        arg_str1("f", "file", "<fn w/o ext>", "save file name"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool as_wave = arg_get_lit(ctx, 1);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    // CLIGetStrWithReturn(ctx, 2, (uint8_t *)filename, &fnlen);
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    if (g_GraphTraceLen == 0) {
        PrintAndLogEx(WARNING, "Graphbuffer is empty, nothing to save");
        return PM3_SUCCESS;
    }

    if (as_wave)
        return saveFileWAVE(filename, g_GraphBuffer, g_GraphTraceLen);
    else
        return saveFilePM3(filename, g_GraphBuffer, g_GraphTraceLen);
}

static int CmdTimeScale(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data timescale",
                  "Set cursor display timescale.\n"
                  "Setting the timescale makes the differential `dt` reading between the yellow and purple markers meaningful.\n"
                  "once the timescale is set, the differential reading between brackets can become a time duration.",
                  "data timescale --sr 125   -u ms  -> for LF sampled at 125 kHz. Reading will be in milliseconds\n"
                  "data timescale --sr 1.695 -u us  -> for HF sampled at 16 * fc/128. Reading will be in microseconds\n"
                  "data timescale --sr 16    -u ETU -> for HF with 16 samples per ETU (fc/128). Reading will be in ETUs"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_dbl1(NULL,  "sr", "<float>", "sets timescale factor according to sampling rate"),
        arg_str0("u", "unit", "<string>", "time unit to display (max 10 chars)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    g_CursorScaleFactor = arg_get_dbl_def(ctx, 1, 1);
    if (g_CursorScaleFactor <= 0) {
        PrintAndLogEx(FAILED, "bad, can't have negative or zero timescale factor");
        g_CursorScaleFactor = 1;
    }
    int len = 0;
    g_CursorScaleFactorUnit[0] = '\x00';
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)g_CursorScaleFactorUnit, sizeof(g_CursorScaleFactorUnit), &len);
    CLIParserFree(ctx);
    RepaintGraphWindow();
    return PM3_SUCCESS;
}

int directionalThreshold(const int *in, int *out, size_t len, int8_t up, int8_t down) {

    int lastValue = in[0];

    // Will be changed at the end, but init 0 as we adjust to last samples
    // value if no threshold kicks in.
    out[0] = 0;

    for (size_t i = 1; i < len; ++i) {
        // Apply first threshold to samples heading up
        if (in[i] >= up && in[i] > lastValue) {
            lastValue = out[i]; // Buffer last value as we overwrite it.
            out[i] = 1;
        }
        // Apply second threshold to samples heading down
        else if (in[i] <= down && in[i] < lastValue) {
            lastValue = out[i]; // Buffer last value as we overwrite it.
            out[i] = -1;
        } else {
            lastValue = out[i]; // Buffer last value as we overwrite it.
            out[i] = out[i - 1];
        }
    }

    // Align with first edited sample.
    out[0] = out[1];
    return PM3_SUCCESS;
}

static int CmdDirectionalThreshold(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data dirthreshold",
                  "Max rising higher up-thres/ Min falling lower down-thres, keep rest as prev.",
                  "data dirthreshold -u 10 -d -10"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int1("d", "down", "<dec>", "threshold down"),
        arg_int1("u", "up", "<dec>", "threshold up"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int8_t down = arg_get_int(ctx, 1);
    int8_t up = arg_get_int(ctx, 2);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "Applying up threshold: " _YELLOW_("%i") ", down threshold: " _YELLOW_("%i") "\n", up, down);

    directionalThreshold(g_GraphBuffer, g_GraphBuffer, g_GraphTraceLen, up, down);

    // set signal properties low/high/mean/amplitude and isnoice detection
    uint8_t *bits = calloc(g_GraphTraceLen, sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(FAILED, "failed to allocate memory");
        return PM3_EMALLOC;
    }
    size_t size = getFromGraphBuffer(bits);
    // set signal properties low/high/mean/amplitude and is_noice detection
    computeSignalProperties(bits, size);

    RepaintGraphWindow();
    free(bits);
    return PM3_SUCCESS;
}

static int CmdZerocrossings(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data zerocrossings",
                  "Count time between zero-crossings",
                  "data zerocrossings"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    // Zero-crossings aren't meaningful unless the signal is zero-mean.
    CmdHpf("");

    int sign = 1, zc = 0, lastZc = 0;

    for (uint32_t i = 0; i < g_GraphTraceLen; ++i) {
        if (g_GraphBuffer[i] * sign >= 0) {
            // No change in sign, reproduce the previous sample count.
            zc++;
            g_GraphBuffer[i] = lastZc;
        } else {
            // Change in sign, reset the sample count.
            sign = -sign;
            g_GraphBuffer[i] = lastZc;
            if (sign > 0) {
                lastZc = zc;
                zc = 0;
            }
        }
    }

    uint8_t *bits = calloc(g_GraphTraceLen, sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(FAILED, "failed to allocate memory");
        return PM3_EMALLOC;
    }
    size_t size = getFromGraphBuffer(bits);
    // set signal properties low/high/mean/amplitude and is_noise detection
    computeSignalProperties(bits, size);
    RepaintGraphWindow();
    free(bits);
    return PM3_SUCCESS;
}

static bool data_verify_hex(uint8_t *d, size_t n) {
    if (d == NULL)
        return false;

    for (size_t i = 0; i < n; i++) {
        if (isxdigit(d[i]) == false) {
            PrintAndLogEx(ERR, "Non hex digit found");
            return false;
        }
    }
    return true;
}

/* // example of FSK2 RF/50 Tones
static const int LowTone[]  = {
1,  1,  1,  1,  1, -1, -1, -1, -1, -1,
1,  1,  1,  1,  1, -1, -1, -1, -1, -1,
1,  1,  1,  1,  1, -1, -1, -1, -1, -1,
1,  1,  1,  1,  1, -1, -1, -1, -1, -1,
1,  1,  1,  1,  1, -1, -1, -1, -1, -1
};
static const int HighTone[] = {
1,  1,  1,  1,  1,     -1, -1, -1, -1, // note one extra 1 to padd due to 50/8 remainder (1/2 the remainder)
1,  1,  1,  1,         -1, -1, -1, -1,
1,  1,  1,  1,         -1, -1, -1, -1,
1,  1,  1,  1,         -1, -1, -1, -1,
1,  1,  1,  1,         -1, -1, -1, -1,
1,  1,  1,  1,     -1, -1, -1, -1, -1, // note one extra -1 to padd due to 50/8 remainder
};
*/
static void GetHiLoTone(int *LowTone, int *HighTone, int clk, int LowToneFC, int HighToneFC) {
    int i, j = 0;
    int Left_Modifier = ((clk % LowToneFC) % 2) + ((clk % LowToneFC) / 2);
    int Right_Modifier = (clk % LowToneFC) / 2;
    //int HighToneMod = clk mod HighToneFC;
    int LeftHalfFCCnt = (LowToneFC % 2) + (LowToneFC / 2); //truncate
    int FCs_per_clk = clk / LowToneFC;

    // need to correctly split up the clock to field clocks.
    // First attempt uses modifiers on each end to make up for when FCs don't evenly divide into Clk

    // start with LowTone
    // set extra 1 modifiers to make up for when FC doesn't divide evenly into Clk
    for (i = 0; i < Left_Modifier; i++) {
        LowTone[i] = 1;
    }

    // loop # of field clocks inside the main clock
    for (i = 0; i < (FCs_per_clk); i++) {
        // loop # of samples per field clock
        for (j = 0; j < LowToneFC; j++) {
            LowTone[(i * LowToneFC) + Left_Modifier + j] = (j < LeftHalfFCCnt) ? 1 : -1;
        }
    }

    int k;
    // add last -1 modifiers
    for (k = 0; k < Right_Modifier; k++) {
        LowTone[((i - 1) * LowToneFC) + Left_Modifier + j + k] = -1;
    }

    // now do hightone
    Left_Modifier = ((clk % HighToneFC) % 2) + ((clk % HighToneFC) / 2);
    Right_Modifier = (clk % HighToneFC) / 2;
    LeftHalfFCCnt = (HighToneFC % 2) + (HighToneFC / 2); //truncate
    FCs_per_clk = clk / HighToneFC;

    for (i = 0; i < Left_Modifier; i++) {
        HighTone[i] = 1;
    }

    // loop # of field clocks inside the main clock
    for (i = 0; i < (FCs_per_clk); i++) {
        // loop # of samples per field clock
        for (j = 0; j < HighToneFC; j++) {
            HighTone[(i * HighToneFC) + Left_Modifier + j] = (j < LeftHalfFCCnt) ? 1 : -1;
        }
    }

    // add last -1 modifiers
    for (k = 0; k < Right_Modifier; k++) {
        PrintAndLogEx(NORMAL, "(i-1)*HighToneFC+lm+j+k %i", ((i - 1) * HighToneFC) + Left_Modifier + j + k);
        HighTone[((i - 1) * HighToneFC) + Left_Modifier + j + k] = -1;
    }
    if (g_debugMode == 2) {
        for (i = 0; i < clk; i++) {
            PrintAndLogEx(NORMAL, "Low: %i,  High: %i", LowTone[i], HighTone[i]);
        }
    }
}

//old CmdFSKdemod adapted by marshmellow
//converts FSK to clear NRZ style wave.  (or demodulates)
static int FSKToNRZ(int *data, size_t *dataLen, uint8_t clk, uint8_t LowToneFC, uint8_t HighToneFC) {
    uint8_t ans = 0;
    if (clk == 0 || LowToneFC == 0 || HighToneFC == 0) {
        int firstClockEdge = 0;
        ans = fskClocks((uint8_t *) &LowToneFC, (uint8_t *) &HighToneFC, (uint8_t *) &clk, &firstClockEdge);
        if (g_debugMode > 1) {
            PrintAndLogEx(NORMAL, "DEBUG FSKtoNRZ: detected clocks: fc_low %i, fc_high %i, clk %i, firstClockEdge %i, ans %u", LowToneFC, HighToneFC, clk, firstClockEdge, ans);
        }
    }
    // currently only know fsk modulations with field clocks < 10 samples and > 4 samples. filter out to remove false positives (and possibly destroying ask/psk modulated waves...)
    if (ans == 0 || clk == 0 || LowToneFC == 0 || HighToneFC == 0 || LowToneFC > 10 || HighToneFC < 4) {
        if (g_debugMode > 1) {
            PrintAndLogEx(NORMAL, "DEBUG FSKtoNRZ: no fsk clocks found");
        }
        return PM3_ESOFT;
    }

    int LowTone[clk];
    int HighTone[clk];
    GetHiLoTone(LowTone, HighTone, clk, LowToneFC, HighToneFC);

    // loop through ([all samples] - clk)
    for (size_t i = 0; i < *dataLen - clk; ++i) {
        int lowSum = 0, highSum = 0;

        // sum all samples together starting from this sample for [clk] samples for each tone (multiply tone value with sample data)
        for (size_t j = 0; j < clk; ++j) {
            lowSum += LowTone[j] * data[i + j];
            highSum += HighTone[j] * data[i + j];
        }
        // get abs( [average sample value per clk] * 100 )  (or a rolling average of sorts)
        lowSum = abs(100 * lowSum / clk);
        highSum = abs(100 * highSum / clk);
        // save these back to buffer for later use
        data[i] = (highSum << 16) | lowSum;
    }

    // now we have the abs( [average sample value per clk] * 100 ) for each tone
    //   loop through again [all samples] - clk - 16
    //                  note why 16???  is 16 the largest FC? changed to LowToneFC as that should be the > fc
    for (size_t i = 0; i < *dataLen - clk - LowToneFC; ++i) {
        int lowTot = 0, highTot = 0;

        // sum a field clock width of abs( [average sample values per clk] * 100) for each tone
        for (size_t j = 0; j < LowToneFC; ++j) {  //10 for fsk2
            lowTot += (data[i + j] & 0xffff);
        }
        for (size_t j = 0; j < HighToneFC; j++) {  //8 for fsk2
            highTot += (data[i + j] >> 16);
        }

        // subtract the sum of lowTone averages by the sum of highTone averages as it
        //   and write back the new graph value
        data[i] = lowTot - highTot;
    }
    // update dataLen to what we put back to the data sample buffer
    *dataLen -= (clk + LowToneFC);
    return PM3_SUCCESS;
}

static int CmdFSKToNRZ(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data fsktonrz",
                  "Convert fsk2 to nrz wave for alternate fsk demodulating (for weak fsk)\n"
                  "Omitted values are autodetect instead",
                  "data fsktonrz\n"
                  "data fsktonrz -c 32 --low 8 --hi 10");

    void *argtable[] = {
        arg_param_begin,
        arg_int0("c", "clk", "<dec>", "clock"),
        arg_int0(NULL, "low", "<dec>", "low field clock"),
        arg_int0(NULL, "hi", "<dec>", "high field clock"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int clk = arg_get_int_def(ctx, 1, 0);
    int fc_low = arg_get_int_def(ctx, 2, 0);
    int fc_high = arg_get_int_def(ctx, 3, 0);
    CLIParserFree(ctx);

    setClockGrid(0, 0);
    g_DemodBufferLen = 0;
    int ans = FSKToNRZ(g_GraphBuffer, &g_GraphTraceLen, clk, fc_low, fc_high);
    CmdNorm("");
    RepaintGraphWindow();
    return ans;
}

static int CmdDataIIR(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data iir",
                  "Apply IIR buttersworth filter on plot data",
                  "data iir -n 2"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_u64_1("n", NULL, "<dec>", "factor n"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    uint8_t k = (arg_get_u32_def(ctx, 1, 0) & 0xFF);
    CLIParserFree(ctx);

    iceSimple_Filter(g_GraphBuffer, g_GraphTraceLen, k);

    uint8_t *bits = calloc(g_GraphTraceLen, sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(FAILED, "failed to allocate memory");
        return PM3_EMALLOC;
    }
    size_t size = getFromGraphBuffer(bits);
    // set signal properties low/high/mean/amplitude and is_noise detection
    computeSignalProperties(bits, size);
    RepaintGraphWindow();
    free(bits);
    return PM3_SUCCESS;
}

typedef struct {
    t55xx_modulation modulation;
    int bitrate;
    int carrier;
    uint8_t fc1;
    uint8_t fc2;
} lf_modulation_t;

static int print_modulation(lf_modulation_t b) {
    PrintAndLogEx(INFO, " Modulation........ " _GREEN_("%s"), GetSelectedModulationStr(b.modulation));
    PrintAndLogEx(INFO, " Bit clock......... " _GREEN_("RF/%d"), b.bitrate);
    PrintAndLogEx(INFO, " Approx baudrate... " _GREEN_("%.f") " baud", (125000 / (float)b.bitrate));
    switch (b.modulation) {
        case DEMOD_PSK1:
        case DEMOD_PSK2:
        case DEMOD_PSK3:
            PrintAndLogEx(SUCCESS, " Carrier rate...... %d", b.carrier);
            break;
        case DEMOD_FSK:
        case DEMOD_FSK1:
        case DEMOD_FSK1a:
        case DEMOD_FSK2:
        case DEMOD_FSK2a:
            PrintAndLogEx(SUCCESS, " Field Clocks...... FC/%u, FC/%u", b.fc1, b.fc2);
            break;
        case DEMOD_NRZ:
        case DEMOD_ASK:
        case DEMOD_BI:
        case DEMOD_BIa:
        default:
            break;
    }
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int try_detect_modulation(void) {

#define LF_NUM_OF_TESTS     6

    lf_modulation_t tests[LF_NUM_OF_TESTS];
    for (int i = 0; i < ARRAYLEN(tests); i++) {
        memset(&tests[i], 0, sizeof(lf_modulation_t));
    }

    int clk = 0, firstClockEdge = 0;
    uint8_t hits = 0, fc1 = 0, fc2 = 0;
    bool st = false;


    uint8_t ans = fskClocks(&fc1, &fc2, (uint8_t *)&clk, &firstClockEdge);

    if (ans && ((fc1 == 10 && fc2 == 8) || (fc1 == 8 && fc2 == 5))) {

        if ((FSKrawDemod(0, 0, 0, 0, false) == PM3_SUCCESS)) {
            tests[hits].modulation = DEMOD_FSK;
            if (fc1 == 8 && fc2 == 5) {
                tests[hits].modulation = DEMOD_FSK1a;
            } else if (fc1 == 10 && fc2 == 8) {
                tests[hits].modulation = DEMOD_FSK2;
            }

            tests[hits].bitrate = clk;
            tests[hits].fc1 = fc1;
            tests[hits].fc2 = fc2;
            ++hits;
        }

    } else {
        clk = GetAskClock("", false);
        if (clk > 0) {
            // 0 = auto clock
            // 0 = no invert
            // 1 = maxError 1
            // 0 = max len
            // false = no amplify
            // false = no verbose
            // false = no emSearch
            // 1 = Ask/Man
            // st = true
            if ((ASKDemod_ext(0, 0, 1, 0, false, false, false, 1, &st) == PM3_SUCCESS)) {
                tests[hits].modulation = DEMOD_ASK;
                tests[hits].bitrate = clk;
                ++hits;
            }
            // "0 0 1 " == clock auto, invert true, maxError 1.
            // false = no verbose
            // false = no emSearch
            // 1 = Ask/Man
            // st = true

            // ASK / biphase
            if ((ASKbiphaseDemod(0, 0, 0, 2, false) == PM3_SUCCESS)) {
                tests[hits].modulation = DEMOD_BI;
                tests[hits].bitrate = clk;
                ++hits;
            }
            // ASK / Diphase
            if ((ASKbiphaseDemod(0, 0, 1, 2, false) == PM3_SUCCESS)) {
                tests[hits].modulation = DEMOD_BIa;
                tests[hits].bitrate = clk;
                ++hits;
            }
        }
        clk = GetNrzClock("", false);
        if ((NRZrawDemod(0, 0, 1, false) == PM3_SUCCESS)) {
            tests[hits].modulation = DEMOD_NRZ;
            tests[hits].bitrate = clk;
            ++hits;
        }

        clk = GetPskClock("", false);
        if (clk > 0) {
            // allow undo
            buffer_savestate_t saveState = save_bufferS32(g_GraphBuffer, g_GraphTraceLen);
            saveState.offset = g_GridOffset;
            // skip first 160 samples to allow antenna to settle in (psk gets inverted occasionally otherwise)
            CmdLtrim("-i 160");
            if ((PSKDemod(0, 0, 6, false) == PM3_SUCCESS)) {
                tests[hits].modulation = DEMOD_PSK1;
                tests[hits].bitrate = clk;
                ++hits;

                // get psk carrier
                tests[hits].carrier = GetPskCarrier(false);
            }
            //undo trim samples
            restore_bufferS32(saveState, g_GraphBuffer);
            g_GridOffset = saveState.offset;
        }
    }

    if (hits) {
        PrintAndLogEx(SUCCESS, "Found [%d] possible matches for modulation.", hits);
        for (int i = 0; i < hits; ++i) {
            PrintAndLogEx(INFO, "--[%d]---------------", i + 1);
            print_modulation(tests[i]);
        }
        return PM3_SUCCESS;
    } else {
        PrintAndLogEx(INFO, "Signal doesn't match");
        return PM3_ESOFT;
    }
}

static int CmdDataModulationSearch(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data modulation",
                  "search LF signal after clock and modulation\n",
                  "data modulation"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return try_detect_modulation();
}

static int CmdAsn1Decoder(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data asn1",
                  "Decode ASN1 bytearray\n"
                  "",
                  "data asn1 -d 303381050186922305a5020500a6088101010403030008a7188516eeee4facacf4fbde5e5c49d95e55bfbca74267b02407a9020500\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("d", NULL, "<hex>", "ASN1 encoded byte array"),
        arg_lit0("t", "test", "perform self test"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int dlen = 2048;
    uint8_t data[2048];
    CLIGetHexWithReturn(ctx, 1, data, &dlen);
    bool selftest = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);
    if (selftest) {
        return asn1_selftest();
    }

    // print ASN1 decoded array in TLV view
    PrintAndLogEx(INFO, "---------------- " _CYAN_("ASN1 TLV") " -----------------");
    asn1_print(data, dlen, "  ");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdDiff(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data diff",
                  "Diff takes a multitude of input data and makes a binary compare.\n"
                  "It accepts filenames (filesystem or RDV4 flashmem SPIFFS), emulator memory, magic gen1",
                  "data diff -w 4 -a hf-mfu-01020304.bin -b hf-mfu-04030201.bin\n"
                  "data diff -a fileA -b fileB\n"
                  "data diff -a fileA --eb\n"
                  "data diff --fa fileA -b fileB\n"
                  "data diff --fa fileA --fb fileB\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("a",  NULL, "<fn>", "input file name A"),
        arg_str0("b",  NULL, "<fn>", "input file name B"),
        arg_lit0(NULL, "eb", "emulator memory <hf mf esave>"),
        arg_str0(NULL, "fa", "<fn>", "input spiffs file A"),
        arg_str0(NULL, "fb", "<fn>", "input spiffs file B"),
        arg_int0("w",  NULL, "<4|8|16>", "Width of data output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlenA = 0;
    char filenameA[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filenameA, FILE_PATH_SIZE, &fnlenA);

    int fnlenB = 0;
    char filenameB[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)filenameB, FILE_PATH_SIZE, &fnlenB);

    bool use_e = arg_get_lit(ctx, 3);

    // SPIFFS filename A
    int splenA = 0;
    char spnameA[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 4), (uint8_t *)spnameA, FILE_PATH_SIZE, &splenA);

    // SPIFFS filename B
    int splenB = 0;
    char spnameB[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 5), (uint8_t *)spnameB, FILE_PATH_SIZE, &splenB);

    int width = arg_get_int_def(ctx, 6, 16);
    CLIParserFree(ctx);

    // sanity check
    if (IfPm3Rdv4Fw() == false && (splenA > 0 || splenB > 0)) {
        PrintAndLogEx(WARNING, "No RDV4 Flashmemory available");
        return PM3_EINVARG;
    }

    if (splenA > 32) {
        PrintAndLogEx(WARNING, "SPIFFS filname A length is large than 32 bytes, got %d", splenA);
        return PM3_EINVARG;
    }
    if (splenB > 32) {
        PrintAndLogEx(WARNING, "SPIFFS filname B length is large than 32 bytes, got %d", splenB);
        return PM3_EINVARG;
    }

    //
    if (width > 16 || width < 1) {
        PrintAndLogEx(INFO, "Width out of range, using default 16 bytes width");
        width = 16;
    }

    // if user supplied dump file,  time to load it
    int res = PM3_SUCCESS;
    uint8_t *inA = NULL, *inB = NULL;
    size_t datalenA = 0, datalenB = 0;



    // read file A
    if (fnlenA) {
        // read dump file
        res = pm3_load_dump(filenameA, (void **)&inA, &datalenA, MIFARE_4K_MAX_BYTES);
        if (res != PM3_SUCCESS) {
            return res;
        }
    }

    // read file B
    if (fnlenB) {
        // read dump file
        res = pm3_load_dump(filenameB, (void **)&inB, &datalenB, MIFARE_4K_MAX_BYTES);
        if (res != PM3_SUCCESS) {
            return res;
        }
    }

    // read spiffs file A
    if (splenA) {
        res = flashmem_spiffs_download(spnameA, splenA, (void **)&inA, &datalenA);
        if (res != PM3_SUCCESS) {
            return res;
        }
    }

    // read spiffs file B
    if (splenB) {
        res = flashmem_spiffs_download(spnameB, splenB, (void **)&inB, &datalenB);
        if (res != PM3_SUCCESS) {
            return res;
        }
    }

    // download emulator memory
    if (use_e) {

        uint8_t *d = calloc(MIFARE_4K_MAX_BYTES, sizeof(uint8_t));
        if (d == NULL) {
            PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
            return PM3_EMALLOC;
        }

        PrintAndLogEx(INFO, "downloading from emulator memory");
        if (GetFromDevice(BIG_BUF_EML, d, MIFARE_4K_MAX_BYTES, 0, NULL, 0, NULL, 2500, false) == false) {
            PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
            free(inA);
            free(inB);
            free(d);
            return PM3_ETIMEOUT;
        }

        if (fnlenA) {
            datalenB = MIFARE_4K_MAX_BYTES;
            inB = d;
        } else {
            datalenA = MIFARE_4K_MAX_BYTES;
            inA = d;
        }
    }

    size_t biggest = (datalenA > datalenB) ? datalenA : datalenB;
    PrintAndLogEx(DEBUG, "data len:  %zu   A %zu  B %zu", biggest, datalenA, datalenB);

    if (inA == NULL) {
        PrintAndLogEx(INFO, "inA null");
    }

    if (inB == NULL) {
        PrintAndLogEx(INFO, "inB null");
    }

    char hdr0[400] = {0};

    int hdr_sln = (width * 4) + 2;
    int max_fn_space = (width * 4);

    if (max_fn_space < fnlenA) {
        truncate_filename(filenameA, max_fn_space);
        fnlenA = strlen(filenameA);
    }

    if (max_fn_space < fnlenB) {
        truncate_filename(filenameB, max_fn_space);
        fnlenB = strlen(filenameB);
    }

    if (fnlenA && fnlenB) {

        snprintf(hdr0, sizeof(hdr0) - 1, " #  | " _CYAN_("%.*s"), max_fn_space, filenameA);

        // add space if needed
        int padding_len = (hdr_sln - fnlenA - 1);
        if (padding_len > 0) {
            memset(hdr0 + strlen(hdr0), ' ', padding_len);
        }
        snprintf(hdr0 + strlen(hdr0), sizeof(hdr0) - 1 - strlen(hdr0), "| " _CYAN_("%.*s"), max_fn_space, filenameB);

    } else {
        strcat(hdr0, " #  | " _CYAN_("a"));
        memset(hdr0 + strlen(hdr0), ' ', hdr_sln - 2);
        strcat(hdr0 + strlen(hdr0), "| " _CYAN_("b"));
    }

    char hdr1[200] = "----+";
    memset(hdr1 + strlen(hdr1), '-', hdr_sln);
    memset(hdr1 + strlen(hdr1), '+', 1);
    memset(hdr1 + strlen(hdr1), '-', hdr_sln);

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, hdr1);
    PrintAndLogEx(INFO, hdr0);
    PrintAndLogEx(INFO, hdr1);

    char line[880] = {0};

    // print data diff loop
    for (int i = 0 ; i < biggest ; i += width) {
        char dlnA[240] = {0};
        char dlnB[240] = {0};
        char dlnAii[180] = {0};
        char dlnBii[180] = {0};

        memset(dlnA, 0, sizeof(dlnA));
        memset(dlnB, 0, sizeof(dlnB));
        memset(dlnAii, 0, sizeof(dlnAii));
        memset(dlnBii, 0, sizeof(dlnBii));

        for (int j = i; j < i + width; j++) {
            int dlnALen = strlen(dlnA);
            int dlnBLen = strlen(dlnB);
            int dlnAiiLen = strlen(dlnAii);
            int dlnBiiLen = strlen(dlnBii);

            //both files ended
            if (j >= datalenA && j >= datalenB) {
                snprintf(dlnA + dlnALen, sizeof(dlnA) - dlnALen, "-- ");
                snprintf(dlnAii + dlnAiiLen, sizeof(dlnAii) - dlnAiiLen, ".") ;
                snprintf(dlnB + dlnBLen, sizeof(dlnB) - dlnBLen, "-- ");
                snprintf(dlnBii + dlnBiiLen, sizeof(dlnBii) - dlnBiiLen, ".") ;
                continue ;
            }

            char ca, cb;

            if (j >= datalenA) {
                // file A ended. print B without colors
                cb = inB[j];
                snprintf(dlnA + dlnALen, sizeof(dlnA) - dlnALen, "-- ");
                snprintf(dlnAii + dlnAiiLen, sizeof(dlnAii) - dlnAiiLen, ".") ;
                snprintf(dlnB + dlnBLen, sizeof(dlnB) - dlnBLen, "%02X ", inB[j]);
                snprintf(dlnBii + dlnBiiLen, sizeof(dlnBii) - dlnBiiLen, "%c", ((cb < 32) || (cb == 127)) ? '.' : cb);
                continue ;
            }
            ca = inA[j];
            if (j >= datalenB) {
                // file B ended. print A without colors
                snprintf(dlnA + dlnALen, sizeof(dlnA) - dlnALen, "%02X ", inA[j]);
                snprintf(dlnAii + dlnAiiLen, sizeof(dlnAii) - dlnAiiLen, "%c", ((ca < 32) || (ca == 127)) ? '.' : ca);
                snprintf(dlnB + dlnBLen, sizeof(dlnB) - dlnBLen, "-- ");
                snprintf(dlnBii + dlnBiiLen, sizeof(dlnBii) - dlnBiiLen, ".") ;
                continue ;
            }
            cb = inB[j];
            if (inA[j] != inB[j]) {
                // diff / add colors
                snprintf(dlnA + dlnALen, sizeof(dlnA) - dlnALen, _GREEN_("%02X "), inA[j]);
                snprintf(dlnB + dlnBLen, sizeof(dlnB) - dlnBLen, _RED_("%02X "), inB[j]);
                snprintf(dlnAii + dlnAiiLen, sizeof(dlnAii) - dlnAiiLen, _GREEN_("%c"), ((ca < 32) || (ca == 127)) ? '.' : ca);
                snprintf(dlnBii + dlnBiiLen, sizeof(dlnBii) - dlnBiiLen, _RED_("%c"), ((cb < 32) || (cb == 127)) ? '.' : cb);
            } else {
                // normal
                snprintf(dlnA + dlnALen, sizeof(dlnA) - dlnALen, "%02X ", inA[j]);
                snprintf(dlnB + dlnBLen, sizeof(dlnB) - dlnBLen, "%02X ", inB[j]);
                snprintf(dlnAii + dlnAiiLen, sizeof(dlnAii) - dlnAiiLen, "%c", ((ca < 32) || (ca == 127)) ? '.' : ca);
                snprintf(dlnBii + dlnBiiLen, sizeof(dlnBii) - dlnBiiLen, "%c", ((cb < 32) || (cb == 127)) ? '.' : cb);
            }
        }
        snprintf(line, sizeof(line), "%s%s | %s%s", dlnA, dlnAii, dlnB, dlnBii);

        PrintAndLogEx(INFO, "%03X | %s", i, line);
    }

    // footer
    PrintAndLogEx(INFO, hdr1);
    PrintAndLogEx(NORMAL, "");

    free(inB);
    free(inA);
    return PM3_SUCCESS;
}

/**
 * @brief Utility for number conversion via cmdline.
 * @param Cmd
 * @return
 */
static int CmdNumCon(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data num",
                  "Function takes a decimal or hexdecimal number and print it in decimal/hex/binary\n"
                  "Will print message if number is a prime number\n",
                  "data num --dec 2023\n"
                  "data num --hex 0x1000\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL,  "dec", "<dec>", "decimal value"),
        arg_str0(NULL,  "hex", "<hex>", "hexadecimal value"),
        arg_str0(NULL,  "bin", "<bin>", "binary value"),
        arg_lit0("i",  NULL,  "print inverted value"),
        arg_lit0("r",  NULL,  "print reversed value"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int dlen = 256;
    char dec[256];
    memset(dec, 0, sizeof(dec));
    int res = CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)dec, sizeof(dec), &dlen);

    int hlen = 256;
    char hex[256];
    memset(hex, 0, sizeof(hex));
    res |= CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)hex, sizeof(hex), &hlen);

    int blen = 256;
    char bin[256];
    memset(bin, 0, sizeof(bin));
    res |= CLIParamStrToBuf(arg_get_str(ctx, 3), (uint8_t *)bin, sizeof(bin), &blen);

    bool shall_invert = arg_get_lit(ctx, 4);
    bool shall_reverse = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    // sanity checks
    if (res) {
        PrintAndLogEx(FAILED, "Error parsing bytes");
        return PM3_EINVARG;
    }

    // results for MPI actions
    bool ret = false;
    (void) ret;

    // container of big number
    mbedtls_mpi N;
    mbedtls_mpi_init(&N);

    // hex
    if (hlen > 0) {
        if (data_verify_hex((uint8_t *)hex, hlen) == false) {
            return PM3_EINVARG;
        }
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&N, 16, hex));
        PrintAndLogEx(INFO, "#....... %d", hlen);
    }

    // decimal
    if (dlen > 0) {
        // should have decimal string check here too
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&N, 10, dec));
    }

    // binary
    if (blen > 0) {
        // should have bianry string check here too
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&N, 2, bin));
        PrintAndLogEx(INFO, "#bits... %d", blen);
    }

    mbedtls_mpi base;
    mbedtls_mpi_init(&base);
    mbedtls_mpi_add_int(&base, &base, 10);

    // printing
    typedef struct {
        const char *desc;
        uint8_t radix;
    } radix_t;

    radix_t radix[] = {
        {"dec..... ", 10},
        {"hex..... ", 16},
        {"bin..... ", 2}
    };

    char s[600] = {0};
    size_t slen = 0;

    for (uint8_t i = 0; i < ARRAYLEN(radix); i++) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_write_string(&N, radix[i].radix, s, sizeof(s), &slen));
        if (slen) {
            PrintAndLogEx(SUCCESS, "%s%s", radix[i].desc, s);
        }
    }

    // ascii
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_string(&N, 16, s, sizeof(s), &slen));
    if (slen) {
        size_t n = (slen >> 1);
        uint8_t *d = calloc(n, sizeof(uint8_t));
        if (d != NULL) {
            hexstr_to_byte_array(s, d, &n);
            PrintAndLogEx(SUCCESS, "ascii... " _YELLOW_("%s"), sprint_ascii((const uint8_t *)d, n));
            free(d);
        }
    }

    // reverse
    if (shall_reverse) {
        PrintAndLogEx(SUCCESS, _CYAN_("Reversed"));
        for (uint8_t i = 0; i < ARRAYLEN(radix); i++) {
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_string(&N, radix[i].radix, s, sizeof(s), &slen));

            str_reverse(s, strlen(s));

            if (slen) {
                PrintAndLogEx(SUCCESS, "%s%s", radix[i].desc, s);
            }
        }

        // ascii
        MBEDTLS_MPI_CHK(mbedtls_mpi_write_string(&N, 16, s, sizeof(s), &slen));
        if (slen) {
            str_reverse(s, strlen(s));
            size_t n = (slen >> 1);
            uint8_t *d = calloc(n, sizeof(uint8_t));
            if (d != NULL) {
                hexstr_to_byte_array(s, d, &n);
                PrintAndLogEx(SUCCESS, "ascii... " _YELLOW_("%s"), sprint_ascii((const uint8_t *)d, n));
                free(d);
            }
        }
    }

    // invert
    if (shall_invert) {
        PrintAndLogEx(SUCCESS, _CYAN_("Inverted"));
        for (uint8_t i = 0; i < ARRAYLEN(radix); i++) {
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_string(&N, radix[i].radix, s, sizeof(s), &slen));
            if (slen == 0) {
                continue;
            }

            switch (i) {
                case 0:
//                    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&N, &N, &base));
                    break;
                case 1:
                    str_inverse_hex(s, strlen(s));
                    PrintAndLogEx(SUCCESS, "%s%s", radix[i].desc, s);
                    break;
                case 2:
                    str_inverse_bin(s, strlen(s));
                    PrintAndLogEx(SUCCESS, "%s%s", radix[i].desc, s);
                    break;
                default:
                    break;
            }
        }
        // ascii
        MBEDTLS_MPI_CHK(mbedtls_mpi_write_string(&N, 16, s, sizeof(s), &slen));
        if (slen) {
            str_inverse_hex(s, strlen(s));
            size_t n = (slen >> 1);
            uint8_t *d = calloc(n, sizeof(uint8_t));
            if (d != NULL) {
                hexstr_to_byte_array(s, d, &n);
                PrintAndLogEx(SUCCESS, "ascii... " _YELLOW_("%s"), sprint_ascii((const uint8_t *)d, n));
                free(d);
            }
        }
    }


    // check if number is a prime
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    MBEDTLS_MPI_CHK(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0));

    res = mbedtls_mpi_is_prime_ext(&N, 50, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (res == 0) {
        PrintAndLogEx(INFO, "prime... " _YELLOW_("yes"));
    }

cleanup:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&base);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    return PM3_SUCCESS;
}

int centerThreshold(const int *in, int *out, size_t len, int8_t up, int8_t down) {
    if (len < 5) {
        return PM3_EINVARG;
    }

    for (size_t i = 0; i < len; ++i) {
        if ((in[i] <= up) && (in[i] >= down)) {
            out[i] = 0;
        }
    }

    // clean out spikes.
    for (size_t i = 2; i < len - 2; ++i) {

        int a = out[i - 2] + out[i - 1];
        int b = out[i + 2] + out[i + 1];
        if (a == 0 && b == 0) {
            out[i] = 0;
        }
    }
    return PM3_SUCCESS;
}

static int CmdCenterThreshold(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data cthreshold",
                  "Inverse of dirty threshold command,  all values between up and down will be average out",
                  "data cthreshold -u 10 -d -10"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int1("d", "down", "<dec>", "threshold down"),
        arg_int1("u", "up", "<dec>", "threshold up"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int8_t down = arg_get_int(ctx, 1);
    int8_t up = arg_get_int(ctx, 2);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "Applying up threshold: " _YELLOW_("%i") ", down threshold: " _YELLOW_("%i") "\n", up, down);

    centerThreshold(g_GraphBuffer, g_GraphBuffer, g_GraphTraceLen, up, down);

    // set signal properties low/high/mean/amplitude and isnoice detection
    uint8_t *bits = calloc(g_GraphTraceLen, sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(FAILED, "failed to allocate memory");
        return PM3_EMALLOC;
    }
    size_t size = getFromGraphBuffer(bits);
    // set signal properties low/high/mean/amplitude and is_noice detection
    computeSignalProperties(bits, size);
    RepaintGraphWindow();
    free(bits);
    return PM3_SUCCESS;
}

static int envelope_square(const int *in, int *out, size_t len) {
    if (len < 10) {
        return PM3_EINVARG;
    }


    size_t i = 0;
    while (i < len - 8) {

        if (in[i] == 0 && in[i + 1] == 0 && in[i + 2] == 0 && in[i + 3] == 0 &&
                in[i + 4] == 0 && in[i + 5] == 0 && in[i + 6] == 0 && in[i + 7] == 0) {

            i += 8;
            continue;
        }

        out[i] = 255;
        i++;
    }
    return PM3_SUCCESS;
}

static int CmdEnvelope(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data envelop",
                  "Create an square envelop of the samples",
                  "data envelop"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    envelope_square(g_GraphBuffer, g_GraphBuffer, g_GraphTraceLen);

    uint8_t *bits = calloc(g_GraphTraceLen, sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(FAILED, "failed to allocate memory");
        return PM3_EMALLOC;
    }
    size_t size = getFromGraphBuffer(bits);
    // set signal properties low/high/mean/amplitude and is_noice detection
    computeSignalProperties(bits, size);
    RepaintGraphWindow();
    free(bits);
    return PM3_SUCCESS;
}

static int CmdAtrLookup(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data atr",
                  "look up ATR record from bytearray\n"
                  "",
                  "data atr -d 3B6B00000031C064BE1B0100079000\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("d", NULL, "<hex>", "ASN1 encoded byte array"),
//        arg_lit0("t", "test", "perform self test"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int dlen = 128;
    uint8_t data[128 + 1];
    CLIGetStrWithReturn(ctx, 1, data, &dlen);

//    bool selftest = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);
//    if (selftest) {
//        return atr_selftest();
//    }
    PrintAndLogEx(INFO, "ISO7816-3 ATR... " _YELLOW_("%s"), data);
    PrintAndLogEx(INFO, "Fingerprint...");

    char *copy = str_dup(getAtrInfo((char *)data));

    char *token = strtok(copy, "\n");
    while (token != NULL) {
        PrintAndLogEx(INFO, "    %s", token);
        token = strtok(NULL, "\n");
    }
    free(copy);
    return PM3_SUCCESS;
}

static int CmdCryptography(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data crypto",
                  "Encrypt data, right here, right now. Or decrypt.",
                  "Supply data, key, IV (needed for des MAC or aes), and cryptography action.\n"
                  "To calculate a MAC for FMCOS, supply challenge as IV, data as data, and session/line protection key as key.\n"
                  "To calculate a MAC for FeliCa, supply first RC as IV, BLE+data as data and session key as key.\n"
                  "data crypto -d 04D6850E06AABB80 -k FFFFFFFFFFFFFFFF --iv 9EA0401A00000000 --des  -> Calculate a MAC for FMCOS chip. The result should be ED3A0133\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "data", "<hex>", "Data to process"),
        arg_str1("k", "key", "<hex>", "Key to use"),
        arg_lit0("r", "rev", "Decrypt, not encrypt"),
        arg_lit0(NULL, "des", "Cipher with DES, not AES"),
        arg_lit0(NULL, "mac", "Calculate AES CMAC/FeliCa Lite MAC"),
        arg_str0(NULL, "iv", "<hex>", "IV value if needed"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    uint8_t dati[250] = {0};
    uint8_t dato[250] = {0};
    int datilen = 0;
    CLIGetHexWithReturn(ctx, 1, dati, &datilen);
    uint8_t key[25] = {0};
    int keylen = 0;
    CLIGetHexWithReturn(ctx, 2, key, &keylen);
    int type = 0;
    if (arg_get_lit(ctx, 3)) type ^= 8;
    if (arg_get_lit(ctx, 4)) type ^= 4;
    if (arg_get_lit(ctx, 5)) type ^= 2;
    uint8_t iv[250] = {0};
    int ivlen = 0;
    CLIGetHexWithReturn(ctx, 6, iv, &ivlen);
    CLIParserFree(ctx);

    // Do data length check
    if ((type & 0x4) >> 2) { // Use AES(0) or DES(1)?

        if (datilen % 8 != 0) {
            PrintAndLogEx(ERR, "<data> length must be a multiple of 8. Got %d", datilen);
            return PM3_EINVARG;
        }

        if (keylen != 8 && keylen != 16 && keylen != 24) {
            PrintAndLogEx(ERR, "<key> must be 8, 16 or 24 bytes. Got %d", keylen);
            return PM3_EINVARG;
        }

    } else {

        if (datilen % 16 != 0 && ((type & 0x2) >> 1 == 0)) {
            PrintAndLogEx(ERR, "<data> length must be a multiple of 16. Got %d", datilen);
            return PM3_EINVARG;
        }

        if (keylen != 16) {
            PrintAndLogEx(ERR, "<key> must be 16 bytes. Got %d", keylen);
            return PM3_EINVARG;
        }
    }

    // Encrypt(0) or decrypt(1)?
    if ((type & 0x8) >> 3) {

        if ((type & 0x4) >> 2) { // AES or DES?

            if (keylen > 8) {

                PrintAndLogEx(INFO, "Called 3DES decrypt");
                des3_decrypt(dato, dati, key, keylen / 8);

            } else {

                PrintAndLogEx(INFO, "Called DES decrypt");
                if (ivlen == 0) {
                    // If there's an IV, use CBC
                    des_decrypt_ecb(dato, dati, datilen, key);
                } else {
                    des_decrypt_cbc(dato, dati, datilen, key, iv);
                }
            }
        } else {
            PrintAndLogEx(INFO, "Called AES decrypt");
            aes_decode(iv, key, dati, dato, datilen);
        }

    } else {
        if (type & 0x4) { // AES or DES?
            if (type & 0x02) { // If we will calculate a MAC
                /*PrintAndLogEx(INFO, "Called FeliCa MAC");
                    // For DES all I know useful is the felica and fudan MAC algorithm.This is just des-cbc, but felica needs it in its way.
                    for (int i = 0; i < datilen; i+=8){ // For all 8 byte sequences
                        reverser(dati, &dati[i], 8, i);
                        if (i){ // If IV is processed
                            for (int n = 0; n < 8; ++n){
                                dato[n] ^= dati[i+n]; // XOR with Dx
                            }
                            des_encrypt_ecb(dato, dato, 8, key); // Cipher itself
                        } else { // If we didn't start with IV
                            for (int n = 0; n < 8; ++n){
                                dato[n] = iv[n]; // Feed data into output
                                dato[n] ^= dati[i+n]; // XOR with D1
                            }
                            des_encrypt_ecb(dato, dato, 8, key); // Cipher itself
                        }
                    }
                    PrintAndLogEx(SUCCESS, "MAC: %s", sprint_hex_inrow(dato, 8));*/
                PrintAndLogEx(INFO, "Not implemented yet - feel free to contribute!");
                return PM3_SUCCESS;
            } else {

                if (keylen > 8) {
                    PrintAndLogEx(INFO, "Called 3DES encrypt keysize: %i", keylen / 8);
                    des3_encrypt(dato, dati, key, keylen / 8);
                } else {

                    PrintAndLogEx(INFO, "Called DES encrypt");

                    if (ivlen == 0) {
                        // If there's an IV, use ECB
                        des_encrypt_ecb(dato, dati, datilen, key);
                    } else {
                        des_encrypt_cbc(dato, dati, datilen, key, iv);
                        char pad[250];
                        memset(pad, ' ', 4 + 8 + (datilen - 8) * 3);
                        pad[8 + (datilen - 8) * 3] = 0; // Make a padding to insert FMCOS macing algorithm guide
                        PrintAndLogEx(INFO, "%sVV VV VV VV FMCOS MAC", pad);
                    }
                }
            }
        } else {

            if (type & 0x02) {
                PrintAndLogEx(INFO, "Called AES CMAC");
                // If we will calculate a MAC
                aes_cmac8(iv, key, dati, dato, datilen);
            } else {
                PrintAndLogEx(INFO, "Called AES encrypt");
                aes_encode(iv, key, dati, dato, datilen);
            }
        }
    }
    PrintAndLogEx(SUCCESS, "Result: %s", sprint_hex(dato, datilen));
    return PM3_SUCCESS;
}

static int CmdBinaryMap(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data bmap",
                  "Breaks down a hex value to binary according a template\n"
                  "   data bmap -d 16 -m 4,4\n"
                  "This will give two rows each with four bits",
                  "data bmap -d 3B\n"
                  "data bmap -d 3B -m 2,5,1\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("d", NULL, "<hex>", "hex string"),
        arg_str0("m", NULL, "<str>", "binary template"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int hlen = 5;
    uint8_t hex[5 + 1];
    CLIGetStrWithReturn(ctx, 1, hex, &hlen);

    int tlen = 40;
    uint8_t template[40 + 1];
    CLIGetStrWithReturn(ctx, 2, template, &tlen);
    CLIParserFree(ctx);

    char bits[(8 * 4) + 1] = {0};
    hextobinstring_n(bits, (char *)hex, hlen);

    if (tlen == 0) {
        template[0] = '8';
        template[1] = 0;
    }

    char *token = strtok((char *)template, ",");

    // header
    PrintAndLogEx(INFO, "---+-------------------------");
    PrintAndLogEx(INFO, "   | b0 b1 b2 b3 b4 b5 b6 b7");
    PrintAndLogEx(INFO, "---+-------------------------");

    uint8_t i = 0;
    uint8_t cnt = 1;
    int x = 0;
    while (token != NULL) {
        sscanf(token, "%d", &x);

        PrintAndLogEx(INFO, " %d | %.*s" NOLF, cnt, i * 3, "                         ");

        // incease with previous offset
        x += i;

        for (; i < (uint8_t)x; i++) {
            PrintAndLogEx(NORMAL, "%c  " NOLF, bits[7 - i]);
        }

        PrintAndLogEx(NORMAL, "");
        token = strtok(NULL, ",");
        cnt++;
    }

    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdXor(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data xor",
                  "takes input string and xor string. Perform xor on it.\n"
                  "If no xor string, try the most reoccuring value to xor against",
                  "data xor -d 99aabbcc8888888888\n"
                  "data xor -d 99aabbcc --xor 88888888\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "data", "<hex>", "input hex string"),
        arg_str0("x", "xor", "<str>", "input xor string"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int hlen = 128;
    uint8_t hex[128 + 1];
    CLIGetHexWithReturn(ctx, 1, hex, &hlen);

    int xlen = 128;
    uint8_t xor[128 + 1];
    CLIGetHexWithReturn(ctx, 2, xor, &xlen);
    CLIParserFree(ctx);

    // find xor value
    if (xlen == 0) {
        uint8_t x = get_highest_frequency(hex, hlen);
        xlen = hlen;
        memset(xor, x, xlen);
    }

    if (hlen != xlen) {
        PrintAndLogEx(FAILED, "Length mismatch, got %i != %i", hlen, xlen);
        return PM3_EINVARG;
    }

    PrintAndLogEx(SUCCESS, "input... %s", sprint_hex_inrow(hex, hlen));
    PrintAndLogEx(SUCCESS, "xor..... %s", sprint_hex_inrow(xor, xlen));
    hex_xor(hex, xor, hlen);
    PrintAndLogEx(SUCCESS, "plain... " _YELLOW_("%s"), sprint_hex_inrow(hex, hlen));
    return PM3_SUCCESS;
}

static int CmdTestSaveState8(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data test_ss8",
                  "Tests the implementation of Buffer Save States (8-bit buffer)",
                  "data test_ss8");
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    srand(time(NULL));

    size_t length = 64;
    uint8_t *srcBuffer = (uint8_t *)calloc(length, sizeof(uint8_t));

    //Set up the source buffer with random data
    for (int i = 0; i < length; i++) {
        srcBuffer[i] = (rand() % 256);
    }

    buffer_savestate_t test8 = save_buffer8(srcBuffer, length);
    PrintAndLogEx(DEBUG, "Save State created, length=%llu, type=%i", test8.bufferSize, test8.type);

    test8.clock = rand();
    test8.offset = rand();
    PrintAndLogEx(DEBUG, "Save State clock=%u, offset=%u", test8.clock, test8.offset);

    uint8_t *destBuffer = (uint8_t *)calloc(length, sizeof(uint8_t));
    size_t returnedLength = restore_buffer8(test8, destBuffer);

    if (returnedLength != length) {
        PrintAndLogEx(FAILED, "Return Length != Buffer Length! Expected '%llu', got '%llu", g_DemodBufferLen, returnedLength);
        free(srcBuffer);
        free(destBuffer);
        return PM3_EFAILED;
    }
    PrintAndLogEx(DEBUG, _GREEN_("Lengths match!") "\n");

    for (size_t i = 0; i < length; i++) {
        if (srcBuffer[i] != destBuffer[i]) {
            PrintAndLogEx(FAILED, "Buffers don't match at index %lu!, Expected %i, got %i", i, srcBuffer[i], destBuffer[i]);
            free(srcBuffer);
            free(destBuffer);
            return PM3_EFAILED;
        }
        PrintAndLogEx(DEBUG, "Index %lu matches: %u", i, destBuffer[i]);
    }
    PrintAndLogEx(SUCCESS, _GREEN_("Save State (8-bit) test success!") "\n");

    free(srcBuffer);
    free(destBuffer);
    return PM3_SUCCESS;
}

static int CmdTestSaveState32(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data test_ss32",
                  "Tests the implementation of Buffer Save States (32-bit buffer)",
                  "data test_ss32");
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    srand(time(NULL));

    size_t length = 64;
    uint32_t *srcBuffer = (uint32_t *)calloc(length, sizeof(uint32_t));

    //Set up the source buffer with random data
    for (size_t i = 0; i < length; i++) {
        srcBuffer[i] = (rand());
    }

    buffer_savestate_t test32 = save_buffer32(srcBuffer, length);
    PrintAndLogEx(DEBUG, "Save State created, length=%llu, type=%i", test32.bufferSize, test32.type);

    test32.clock = rand();
    test32.offset = rand();
    PrintAndLogEx(DEBUG, "Save State clock=%u, offset=%u", test32.clock, test32.offset);

    uint32_t *destBuffer = (uint32_t *)calloc(length, sizeof(uint32_t));
    size_t returnedLength = restore_buffer32(test32, destBuffer);

    if (returnedLength != length) {
        PrintAndLogEx(FAILED, "Return Length != Buffer Length! Expected '%llu', got '%llu", g_DemodBufferLen, returnedLength);
        free(srcBuffer);
        free(destBuffer);
        return PM3_EFAILED;
    }
    PrintAndLogEx(DEBUG, _GREEN_("Lengths match!") "\n");

    for (size_t i = 0; i < length; i++) {
        if (srcBuffer[i] != destBuffer[i]) {
            PrintAndLogEx(FAILED, "Buffers don't match at index %lu!, Expected %i, got %i", i, srcBuffer[i], destBuffer[i]);
            free(srcBuffer);
            free(destBuffer);
            return PM3_EFAILED;
        }
        PrintAndLogEx(DEBUG, "Index %lu matches: %i", i, destBuffer[i]);
    }
    PrintAndLogEx(SUCCESS, _GREEN_("Save State (32-bit) test success!") "\n");

    free(srcBuffer);
    free(destBuffer);
    return PM3_SUCCESS;
}

static int CmdTestSaveState32S(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data test_ss32s",
                  "Tests the implementation of Buffer Save States (32-bit signed buffer)",
                  "data test_ss32s");
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    srand(time(NULL));

    size_t length = 64;
    int32_t *srcBuffer = (int32_t *)calloc(length, sizeof(int32_t));

    //Set up the source buffer with random data
    for (int i = 0; i < length; i++) {
        srcBuffer[i] = (rand() - 4294967296);
    }

    buffer_savestate_t test32 = save_bufferS32(srcBuffer, length);
    PrintAndLogEx(DEBUG, "Save State created, length=%llu, type=%i", test32.bufferSize, test32.type);

    test32.clock = rand();
    test32.offset = rand();
    PrintAndLogEx(DEBUG, "Save State clock=%u, offset=%u", test32.clock, test32.offset);

    int32_t *destBuffer = (int32_t *)calloc(length, sizeof(int32_t));
    size_t returnedLength = restore_bufferS32(test32, destBuffer);

    if (returnedLength != length) {
        PrintAndLogEx(FAILED, "Return Length != Buffer Length! Expected '%llu', got '%llu", g_DemodBufferLen, returnedLength);
        free(srcBuffer);
        free(destBuffer);
        return PM3_EFAILED;
    }
    PrintAndLogEx(DEBUG, _GREEN_("Lengths match!") "\n");

    for (int i = 0; i < length; i++) {
        if (srcBuffer[i] != destBuffer[i]) {
            PrintAndLogEx(FAILED, "Buffers don't match at index %i!, Expected %i, got %i", i, srcBuffer[i], destBuffer[i]);
            free(srcBuffer);
            free(destBuffer);
            return PM3_EFAILED;
        }
        PrintAndLogEx(DEBUG, "Index %i matches: %i", i, destBuffer[i]);
    }
    PrintAndLogEx(SUCCESS, _GREEN_("Save State (signed 32-bit) test success!") "\n");

    free(srcBuffer);
    free(destBuffer);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",             CmdHelp,                 AlwaysAvailable,  "This help"},
    {"-----------",      CmdHelp,                 AlwaysAvailable, "------------------------- " _CYAN_("General") "-------------------------"},
    {"clear",            CmdBuffClear,            AlwaysAvailable,  "Clears various buffers used by the graph window"},
    {"hide",             CmdHide,                 AlwaysAvailable,  "Hide the graph window"},
    {"load",             CmdLoad,                 AlwaysAvailable,  "Load contents of file into graph window"},
    {"num",              CmdNumCon,               AlwaysAvailable,  "Converts dec/hex/bin"},
    {"plot",             CmdPlot,                 AlwaysAvailable,  "Show the graph window"},
    {"print",            CmdPrintDemodBuff,       AlwaysAvailable,  "Print the data in the DemodBuffer"},
    {"save",             CmdSave,                 AlwaysAvailable,  "Save signal trace data"},
    {"setdebugmode",     CmdSetDebugMode,         AlwaysAvailable,  "Set Debugging Level on client side"},
    {"xor",              CmdXor,                  AlwaysAvailable,  "Xor a input string"},

    {"-----------",      CmdHelp,                 AlwaysAvailable, "------------------------- " _CYAN_("Modulation") "-------------------------"},
    {"biphaserawdecode", CmdBiphaseDecodeRaw,     AlwaysAvailable,  "Biphase decode bin stream in DemodBuffer"},
    {"detectclock",      CmdDetectClockRate,      AlwaysAvailable,  "Detect ASK, FSK, NRZ, PSK clock rate of wave in GraphBuffer"},
    {"fsktonrz",         CmdFSKToNRZ,             AlwaysAvailable,  "Convert fsk2 to nrz wave for alternate fsk demodulating (for weak fsk)"},
    {"manrawdecode",     Cmdmandecoderaw,         AlwaysAvailable,  "Manchester decode binary stream in DemodBuffer"},
    {"modulation",       CmdDataModulationSearch, AlwaysAvailable,  "Identify LF signal for clock and modulation"},
    {"rawdemod",         CmdRawDemod,             AlwaysAvailable,  "Demodulate the data in the GraphBuffer and output binary"},

    {"-----------",      CmdHelp,                 AlwaysAvailable, "------------------------- " _CYAN_("Graph") "-------------------------"},
    {"askedgedetect",    CmdAskEdgeDetect,        AlwaysAvailable,  "Adjust Graph for manual ASK demod"},
    {"autocorr",         CmdAutoCorr,             AlwaysAvailable,  "Autocorrelation over window"},
    {"convertbitstream", CmdConvertBitStream,     AlwaysAvailable,  "Convert GraphBuffer's 0/1 values to 127 / -127"},
    {"cthreshold",       CmdCenterThreshold,      AlwaysAvailable,  "Average out all values between"},
    {"dirthreshold",     CmdDirectionalThreshold, AlwaysAvailable,  "Max rising higher up-thres/ Min falling lower down-thres"},
    {"decimate",         CmdDecimate,             AlwaysAvailable,  "Decimate samples"},
    {"envelope",         CmdEnvelope,             AlwaysAvailable,  "Generate square envelope of samples"},
    {"grid",             CmdGrid,                 AlwaysAvailable,  "overlay grid on graph window"},
    {"getbitstream",     CmdGetBitStream,         AlwaysAvailable,  "Convert GraphBuffer's >=1 values to 1 and <1 to 0"},
    {"hpf",              CmdHpf,                  AlwaysAvailable,  "Remove DC offset from trace"},
    {"iir",              CmdDataIIR,              AlwaysAvailable,  "Apply IIR buttersworth filter on plot data"},
    {"ltrim",            CmdLtrim,                AlwaysAvailable,  "Trim samples from left of trace"},
    {"mtrim",            CmdMtrim,                AlwaysAvailable,  "Trim out samples from the specified start to the specified stop"},
    {"norm",             CmdNorm,                 AlwaysAvailable,  "Normalize max/min to +/-128"},
    {"rtrim",            CmdRtrim,                AlwaysAvailable,  "Trim samples from right of trace"},
    {"setgraphmarkers",  CmdSetGraphMarkers,      AlwaysAvailable,  "Set the markers in the graph window"},
    {"shiftgraphzero",   CmdGraphShiftZero,       AlwaysAvailable,  "Shift 0 for Graphed wave + or - shift value"},
    {"timescale",        CmdTimeScale,            AlwaysAvailable,  "Set cursor display timescale"},
    {"undecimate",       CmdUndecimate,           AlwaysAvailable,  "Un-decimate samples"},
    {"zerocrossings",    CmdZerocrossings,        AlwaysAvailable,  "Count time between zero-crossings"},

    {"-----------",      CmdHelp,                 AlwaysAvailable, "------------------------- " _CYAN_("Operations") "-------------------------"},
    {"asn1",             CmdAsn1Decoder,          AlwaysAvailable,  "ASN1 decoder"},
    {"atr",              CmdAtrLookup,            AlwaysAvailable,  "ATR lookup"},
    {"bitsamples",       CmdBitsamples,           IfPm3Present,     "Get raw samples as bitstring"},
    {"bmap",             CmdBinaryMap,            AlwaysAvailable,  "Convert hex value according a binary template"},
    {"crypto",           CmdCryptography,         AlwaysAvailable,  "Encrypt and decrypt data"},
    {"diff",             CmdDiff,                 AlwaysAvailable,  "Diff of input files"},
    {"hexsamples",       CmdHexsamples,           IfPm3Present,     "Dump big buffer as hex bytes"},
    {"samples",          CmdSamples,              IfPm3Present,     "Get raw samples for graph window ( GraphBuffer )"},

    {"-----------",      CmdHelp,                 IfClientDebugEnabled, "------------------------- " _CYAN_("Debug") "-------------------------"},
    {"test_ss8",         CmdTestSaveState8,       IfClientDebugEnabled, "Test the implementation of Buffer Save States (8-bit buffer)"},
    {"test_ss32",        CmdTestSaveState32,      IfClientDebugEnabled, "Test the implementation of Buffer Save States (32-bit buffer)"},
    {"test_ss32s",       CmdTestSaveState32S,     IfClientDebugEnabled, "Test the implementation of Buffer Save States (32-bit signed buffer)"},

    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdData(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
