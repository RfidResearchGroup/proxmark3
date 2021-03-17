//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// iceman 2019
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Data and Graph commands
//-----------------------------------------------------------------------------
#include "cmddata.h"
#include <stdio.h>
#include <string.h>
#include <limits.h>   // for CmdNorm INT_MIN && INT_MAX
#include <math.h>     // pow
#include <ctype.h>    // tolower
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
#include "mifare/ndef.h"
#include "cliparser.h"
#include "cmdlft55xx.h"          // print...

uint8_t DemodBuffer[MAX_DEMOD_BUF_LEN];
size_t DemodBufferLen = 0;
int32_t g_DemodStartIdx = 0;
int g_DemodClock = 0;

static int CmdHelp(const char *Cmd);

static int usage_data_printdemodbuf(void) {
    PrintAndLogEx(NORMAL, "Usage: data print x o <offset> l <length>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h          this help");
    PrintAndLogEx(NORMAL, "       i          invert Demodbuffer before printing");
    PrintAndLogEx(NORMAL, "       x          output in hex (omit for binary output)");
    PrintAndLogEx(NORMAL, "       o <offset> enter offset in # of bits");
    PrintAndLogEx(NORMAL, "       l <length> enter length to print in # of bits or hex characters respectively");
    PrintAndLogEx(NORMAL, "       s          strip leading zeroes, i.e. set offset to first bit equal to one");
    return PM3_SUCCESS;
}
static int usage_data_manrawdecode(void) {
    PrintAndLogEx(NORMAL, "Usage:  data manrawdecode [invert] [maxErr]");
    PrintAndLogEx(NORMAL, "     Takes 10 and 01 and converts to 0 and 1 respectively");
    PrintAndLogEx(NORMAL, "     --must have binary sequence in demodbuffer (run data askrawdemod first)");
    PrintAndLogEx(NORMAL, "  [invert]  invert output");
    PrintAndLogEx(NORMAL, "  [maxErr]  set number of errors allowed (default = 20)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "   Example: data manrawdecode   = decode manchester bitstream from the demodbuffer");
    return PM3_SUCCESS;
}
static int usage_data_biphaserawdecode(void) {
    PrintAndLogEx(NORMAL, "Usage:  data biphaserawdecode [offset] [invert] [maxErr]");
    PrintAndLogEx(NORMAL, "     Converts 10 or 01 to 1 and 11 or 00 to 0");
    PrintAndLogEx(NORMAL, "     --must have binary sequence in demodbuffer (run data askrawdemod first)");
    PrintAndLogEx(NORMAL, "     --invert for Conditional Dephase Encoding (CDP) AKA Differential Manchester");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "     [offset <0|1>], set to 0 not to adjust start position or to 1 to adjust decode start position");
    PrintAndLogEx(NORMAL, "     [invert <0|1>], set to 1 to invert output");
    PrintAndLogEx(NORMAL, "     [maxErr int],   set max errors tolerated - default=20");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "   Example: data biphaserawdecode     = decode biphase bitstream from the demodbuffer");
    PrintAndLogEx(NORMAL, "   Example: data biphaserawdecode 1 1 = decode biphase bitstream from the demodbuffer, set offset, and invert output");
    return PM3_SUCCESS;
}
static int usage_data_rawdemod(void) {
    PrintAndLogEx(NORMAL, "Usage:  data rawdemod [modulation] <help>|<options>");
    PrintAndLogEx(NORMAL, "   [modulation] as 2 char,");
    PrintAndLogEx(NORMAL, "       "_YELLOW_("ab")" - ask/biphase");
    PrintAndLogEx(NORMAL, "       "_YELLOW_("am")" - ask/manchester");
    PrintAndLogEx(NORMAL, "       "_YELLOW_("ar")" - ask/raw");
    PrintAndLogEx(NORMAL, "       "_YELLOW_("fs")" - fsk");
    PrintAndLogEx(NORMAL, "       "_YELLOW_("nr")" - nrz/direct");
    PrintAndLogEx(NORMAL, "       "_YELLOW_("p1")" - psk1");
    PrintAndLogEx(NORMAL, "       "_YELLOW_("p2")" - psk2");
    PrintAndLogEx(NORMAL, "   <help> as 'h', prints the help for the specific modulation");
    PrintAndLogEx(NORMAL, "   <options> see specific modulation help for optional parameters");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Example:");
    PrintAndLogEx(NORMAL, "       data rawdemod fs h         = print help specific to fsk demod");
    PrintAndLogEx(NORMAL, "       data rawdemod fs           = demod GraphBuffer using: fsk - autodetect");
    PrintAndLogEx(NORMAL, "       data rawdemod ab           = demod GraphBuffer using: ask/biphase - autodetect");
    PrintAndLogEx(NORMAL, "       data rawdemod am           = demod GraphBuffer using: ask/manchester - autodetect");
    PrintAndLogEx(NORMAL, "       data rawdemod ar           = demod GraphBuffer using: ask/raw - autodetect");
    PrintAndLogEx(NORMAL, "       data rawdemod nr           = demod GraphBuffer using: nrz/direct - autodetect");
    PrintAndLogEx(NORMAL, "       data rawdemod p1           = demod GraphBuffer using: psk1 - autodetect");
    PrintAndLogEx(NORMAL, "       data rawdemod p2           = demod GraphBuffer using: psk2 - autodetect");
    return PM3_SUCCESS;
}
static int usage_data_rawdemod_am(void) {
    PrintAndLogEx(NORMAL, "Usage:  data rawdemod am <s> [clock] <invert> [maxError] [maxLen] [amplify]");
    PrintAndLogEx(NORMAL, "     ['s'] optional, check for Sequence Terminator");
    PrintAndLogEx(NORMAL, "     [set clock as integer] optional, if not set, autodetect");
    PrintAndLogEx(NORMAL, "     <invert>, 1 to invert output");
    PrintAndLogEx(NORMAL, "     [set maximum allowed errors], default = 100");
    PrintAndLogEx(NORMAL, "     [set maximum Samples to read], default = 32768 (512 bits at rf/64)");
    PrintAndLogEx(NORMAL, "     <amplify>, 'a' to attempt demod with ask amplification, default = no amp");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Example:");
    PrintAndLogEx(NORMAL, "       data rawdemod am        = demod an ask/manchester tag from GraphBuffer");
    PrintAndLogEx(NORMAL, "       data rawdemod am 32     = demod an ask/manchester tag from GraphBuffer using a clock of RF/32");
    PrintAndLogEx(NORMAL, "       data rawdemod am 32 1   = demod an ask/manchester tag from GraphBuffer using a clock of RF/32 and inverting data");
    PrintAndLogEx(NORMAL, "       data rawdemod am 1      = demod an ask/manchester tag from GraphBuffer while inverting data");
    PrintAndLogEx(NORMAL, "       data rawdemod am 64 1 0 = demod an ask/manchester tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors");
    return PM3_SUCCESS;
}
static int usage_data_rawdemod_ab(void) {
    PrintAndLogEx(NORMAL, "Usage:  data rawdemod ab [offset] [clock] <invert> [maxError] [maxLen] <amplify>");
    PrintAndLogEx(NORMAL, "     [offset], offset to begin biphase, default=0");
    PrintAndLogEx(NORMAL, "     [set clock as integer] optional, if not set, autodetect");
    PrintAndLogEx(NORMAL, "     <invert>, 1 to invert output");
    PrintAndLogEx(NORMAL, "     [set maximum allowed errors], default = 100");
    PrintAndLogEx(NORMAL, "     [set maximum Samples to read], default = 32768 (512 bits at rf/64)");
    PrintAndLogEx(NORMAL, "     <amplify>, 'a' to attempt demod with ask amplification, default = no amp");
    PrintAndLogEx(NORMAL, "     NOTE: <invert>  can be entered as second or third argument");
    PrintAndLogEx(NORMAL, "     NOTE: <amplify> can be entered as first, second or last argument");
    PrintAndLogEx(NORMAL, "     NOTE: any other arg must have previous args set to work");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "     NOTE: --invert for Conditional Dephase Encoding (CDP) AKA Differential Manchester");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Example:");
    PrintAndLogEx(NORMAL, "       data rawdemod ab              = demod an ask/biph tag from GraphBuffer");
    PrintAndLogEx(NORMAL, "       data rawdemod ab 0 a          = demod an ask/biph tag from GraphBuffer, amplified");
    PrintAndLogEx(NORMAL, "       data rawdemod ab 1 32         = demod an ask/biph tag from GraphBuffer using an offset of 1 and a clock of RF/32");
    PrintAndLogEx(NORMAL, "       data rawdemod ab 0 32 1       = demod an ask/biph tag from GraphBuffer using a clock of RF/32 and inverting data");
    PrintAndLogEx(NORMAL, "       data rawdemod ab 0 1          = demod an ask/biph tag from GraphBuffer while inverting data");
    PrintAndLogEx(NORMAL, "       data rawdemod ab 0 64 1 0     = demod an ask/biph tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors");
    PrintAndLogEx(NORMAL, "       data rawdemod ab 0 64 1 0 0 a = demod an ask/biph tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors, and amp");
    return PM3_SUCCESS;
}
static int usage_data_rawdemod_ar(void) {
    PrintAndLogEx(NORMAL, "Usage:  data rawdemod ar [clock] <invert> [maxError] [maxLen] [amplify]");
    PrintAndLogEx(NORMAL, "     [set clock as integer] optional, if not set, autodetect");
    PrintAndLogEx(NORMAL, "     <invert>, 1 to invert output");
    PrintAndLogEx(NORMAL, "     [set maximum allowed errors], default = 100");
    PrintAndLogEx(NORMAL, "     [set maximum Samples to read], default = 32768 (1024 bits at rf/64)");
    PrintAndLogEx(NORMAL, "     <amplify>, 'a' to attempt demod with ask amplification, default = no amp");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Example:");
    PrintAndLogEx(NORMAL, "       data rawdemod ar            = demod an ask tag from GraphBuffer");
    PrintAndLogEx(NORMAL, "       data rawdemod ar a          = demod an ask tag from GraphBuffer, amplified");
    PrintAndLogEx(NORMAL, "       data rawdemod ar 32         = demod an ask tag from GraphBuffer using a clock of RF/32");
    PrintAndLogEx(NORMAL, "       data rawdemod ar 32 1       = demod an ask tag from GraphBuffer using a clock of RF/32 and inverting data");
    PrintAndLogEx(NORMAL, "       data rawdemod ar 1          = demod an ask tag from GraphBuffer while inverting data");
    PrintAndLogEx(NORMAL, "       data rawdemod ar 64 1 0     = demod an ask tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors");
    PrintAndLogEx(NORMAL, "       data rawdemod ar 64 1 0 0 a = demod an ask tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors, and amp");
    return PM3_SUCCESS;
}
static int usage_data_rawdemod_fs(void) {
    PrintAndLogEx(NORMAL, "Usage:  data rawdemod fs [clock] <invert> [fchigh] [fclow]");
    PrintAndLogEx(NORMAL, "     [set clock as integer] optional, omit for autodetect.");
    PrintAndLogEx(NORMAL, "     <invert>, 1 for invert output, can be used even if the clock is omitted");
    PrintAndLogEx(NORMAL, "     [fchigh], larger field clock length, omit for autodetect");
    PrintAndLogEx(NORMAL, "     [fclow], small field clock length, omit for autodetect");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Example:");
    PrintAndLogEx(NORMAL, "       data rawdemod fs           = demod an fsk tag from GraphBuffer using autodetect");
    PrintAndLogEx(NORMAL, "       data rawdemod fs 32        = demod an fsk tag from GraphBuffer using a clock of RF/32, autodetect fc");
    PrintAndLogEx(NORMAL, "       data rawdemod fs 1         = demod an fsk tag from GraphBuffer using autodetect, invert output");
    PrintAndLogEx(NORMAL, "       data rawdemod fs 32 1      = demod an fsk tag from GraphBuffer using a clock of RF/32, invert output, autodetect fc");
    PrintAndLogEx(NORMAL, "       data rawdemod fs 64 0 8 5  = demod an fsk1 RF/64 tag from GraphBuffer");
    PrintAndLogEx(NORMAL, "       data rawdemod fs 50 0 10 8 = demod an fsk2 RF/50 tag from GraphBuffer");
    PrintAndLogEx(NORMAL, "       data rawdemod fs 50 1 10 8 = demod an fsk2a RF/50 tag from GraphBuffer");
    return PM3_SUCCESS;
}
static int usage_data_rawdemod_nr(void) {
    PrintAndLogEx(NORMAL, "Usage:  data rawdemod nr [clock] <0|1> [maxError]");
    PrintAndLogEx(NORMAL, "     [set clock as integer] optional, if not set, autodetect.");
    PrintAndLogEx(NORMAL, "     <invert>, 1 for invert output");
    PrintAndLogEx(NORMAL, "     [set maximum allowed errors], default = 100.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Example:");
    PrintAndLogEx(NORMAL, "       data rawdemod nr        = demod a nrz/direct tag from GraphBuffer");
    PrintAndLogEx(NORMAL, "       data rawdemod nr 32     = demod a nrz/direct tag from GraphBuffer using a clock of RF/32");
    PrintAndLogEx(NORMAL, "       data rawdemod nr 32 1   = demod a nrz/direct tag from GraphBuffer using a clock of RF/32 and inverting data");
    PrintAndLogEx(NORMAL, "       data rawdemod nr 1      = demod a nrz/direct tag from GraphBuffer while inverting data");
    PrintAndLogEx(NORMAL, "       data rawdemod nr 64 1 0 = demod a nrz/direct tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors");
    return PM3_SUCCESS;
}
static int usage_data_rawdemod_p1(void) {
    PrintAndLogEx(NORMAL, "Usage:  data rawdemod p1 [clock] <0|1> [maxError]");
    PrintAndLogEx(NORMAL, "     [set clock as integer] optional, if not set, autodetect.");
    PrintAndLogEx(NORMAL, "     <invert>, 1 for invert output");
    PrintAndLogEx(NORMAL, "     [set maximum allowed errors], default = 100.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Example:");
    PrintAndLogEx(NORMAL, "       data rawdemod p1        = demod a psk1 tag from GraphBuffer");
    PrintAndLogEx(NORMAL, "       data rawdemod p1 32     = demod a psk1 tag from GraphBuffer using a clock of RF/32");
    PrintAndLogEx(NORMAL, "       data rawdemod p1 32 1   = demod a psk1 tag from GraphBuffer using a clock of RF/32 and inverting data");
    PrintAndLogEx(NORMAL, "       data rawdemod p1 1      = demod a psk1 tag from GraphBuffer while inverting data");
    PrintAndLogEx(NORMAL, "       data rawdemod p1 64 1 0 = demod a psk1 tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors");
    return PM3_SUCCESS;
}
static int usage_data_rawdemod_p2(void) {
    PrintAndLogEx(NORMAL, "Usage:  data rawdemod p2 [clock] <0|1> [maxError]");
    PrintAndLogEx(NORMAL, "     [set clock as integer] optional, if not set, autodetect.");
    PrintAndLogEx(NORMAL, "     <invert>, 1 for invert output");
    PrintAndLogEx(NORMAL, "     [set maximum allowed errors], default = 100.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Example:");
    PrintAndLogEx(NORMAL, "       data rawdemod p2         = demod a psk2 tag from GraphBuffer, autodetect clock");
    PrintAndLogEx(NORMAL, "       data rawdemod p2 32      = demod a psk2 tag from GraphBuffer using a clock of RF/32");
    PrintAndLogEx(NORMAL, "       data rawdemod p2 32 1    = demod a psk2 tag from GraphBuffer using a clock of RF/32 and inverting output");
    PrintAndLogEx(NORMAL, "       data rawdemod p2 1       = demod a psk2 tag from GraphBuffer, autodetect clock and invert output");
    PrintAndLogEx(NORMAL, "       data rawdemod p2 64 1 0  = demod a psk2 tag from GraphBuffer using a clock of RF/64, inverting output and allowing 0 demod errors");
    return PM3_SUCCESS;
}
static int usage_data_autocorr(void) {
    PrintAndLogEx(NORMAL, "Autocorrelate is used to detect repeating sequences. We use it as detection of length in bits a message inside the signal is");
    PrintAndLogEx(NORMAL, "Usage: data autocorr w <window> [g]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h              This help");
    PrintAndLogEx(NORMAL, "       w <window>     window length for correlation - default = 4000");
    PrintAndLogEx(NORMAL, "       g              save back to GraphBuffer (overwrite)");
    return PM3_SUCCESS;
}
static int usage_data_detectclock(void) {
    PrintAndLogEx(NORMAL, "Usage:  data detectclock [modulation] <clock>");
    PrintAndLogEx(NORMAL, "     [modulation as char], specify the modulation type you want to detect the clock of");
    PrintAndLogEx(NORMAL, "     <clock>             , specify the clock (optional - to get best start position only)");
    PrintAndLogEx(NORMAL, "       'a' = ask, 'f' = fsk, 'n' = nrz/direct, 'p' = psk");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "   Example: data detectclock a    = detect the clock of an ask modulated wave in the GraphBuffer");
    PrintAndLogEx(NORMAL, "            data detectclock f    = detect the clock of an fsk modulated wave in the GraphBuffer");
    PrintAndLogEx(NORMAL, "            data detectclock p    = detect the clock of an psk modulated wave in the GraphBuffer");
    PrintAndLogEx(NORMAL, "            data detectclock n    = detect the clock of an nrz/direct modulated wave in the GraphBuffer");
    return PM3_SUCCESS;
}
static int usage_data_hex2bin(void) {
    PrintAndLogEx(NORMAL, "Usage: data hex2bin <hex_digits>");
    PrintAndLogEx(NORMAL, "       This function will ignore all non-hexadecimal characters (but stop reading on whitespace)");
    return PM3_SUCCESS;
}
static int usage_data_bin2hex(void) {
    PrintAndLogEx(NORMAL, "Usage: data bin2hex <binary_digits>");
    PrintAndLogEx(NORMAL, "       This function will ignore all characters not 1 or 0 (but stop reading on whitespace)");
    return PM3_SUCCESS;
}
static int usage_data_buffclear(void) {
    PrintAndLogEx(NORMAL, "This function clears the bigbuff on deviceside");
    PrintAndLogEx(NORMAL, "Usage: data clear [h]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h              This help");
    return PM3_SUCCESS;
}
static int usage_data_fsktonrz(void) {
    PrintAndLogEx(NORMAL, "Usage: data fsktonrz c <clock> l <fc_low> f <fc_high>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h            This help");
    PrintAndLogEx(NORMAL, "       c <clock>    enter the a clock (omit to autodetect)");
    PrintAndLogEx(NORMAL, "       l <fc_low>   enter a field clock (omit to autodetect)");
    PrintAndLogEx(NORMAL, "       f <fc_high>  enter a field clock (omit to autodetect)");
    return PM3_SUCCESS;
}

//set the demod buffer with given array of binary (one bit per byte)
//by marshmellow
void setDemodBuff(uint8_t *buff, size_t size, size_t start_idx) {
    if (buff == NULL) return;

    if (size > MAX_DEMOD_BUF_LEN - start_idx)
        size = MAX_DEMOD_BUF_LEN - start_idx;

    for (size_t i = 0; i < size; i++)
        DemodBuffer[i] = buff[start_idx++];

    DemodBufferLen = size;
}

bool getDemodBuff(uint8_t *buff, size_t *size) {
    if (buff == NULL) return false;
    if (size == NULL) return false;
    if (*size == 0) return false;

    *size = (*size > DemodBufferLen) ? DemodBufferLen : *size;

    memcpy(buff, DemodBuffer, *size);
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

// option '1' to save DemodBuffer any other to restore
void save_restoreDB(uint8_t saveOpt) {
    static uint8_t SavedDB[MAX_DEMOD_BUF_LEN];
    static size_t SavedDBlen;
    static bool DB_Saved = false;
    static size_t savedDemodStartIdx = 0;
    static int savedDemodClock = 0;

    if (saveOpt == GRAPH_SAVE) { //save

        memcpy(SavedDB, DemodBuffer, sizeof(DemodBuffer));
        SavedDBlen = DemodBufferLen;
        DB_Saved = true;
        savedDemodStartIdx = g_DemodStartIdx;
        savedDemodClock = g_DemodClock;
    } else if (DB_Saved) { //restore

        memcpy(DemodBuffer, SavedDB, sizeof(DemodBuffer));
        DemodBufferLen = SavedDBlen;
        g_DemodClock = savedDemodClock;
        g_DemodStartIdx = savedDemodStartIdx;
    }
}

static int CmdSetDebugMode(const char *Cmd) {
    int demod = 0;
    sscanf(Cmd, "%i", &demod);
    g_debugMode = (uint8_t)demod;
    return PM3_SUCCESS;
}

//by marshmellow
// max output to 512 bits if we have more
// doesn't take inconsideration where the demod offset or bitlen found.
int printDemodBuff(uint8_t offset, bool strip_leading, bool invert, bool print_hex) {
    size_t len = DemodBufferLen;
    if (len == 0) {
        PrintAndLogEx(WARNING, "Demodbuffer is empty");
        return PM3_EINVARG;
    }

    uint8_t *buf = NULL;

    if (strip_leading) {
        buf = (DemodBuffer + offset);

        if (len > (DemodBufferLen - offset))
            len = (DemodBufferLen - offset);

        size_t i;
        for (i = 0; i < len; i++) {
            if (buf[i] == 1) break;
        }
        offset += i;
    }

    if (len > (DemodBufferLen - offset)) {
        len = (DemodBufferLen - offset);
    }

    if (len > 512)  {
        len = 512;
    }

    if (invert) {
        buf = (DemodBuffer + offset);
        for (size_t i = 0; i < len; i++) {
            if (buf[i] == 1)
                buf[i] = 0;
            else {
                if (buf[i] == 0)
                    buf[i] = 1;
            }
        }
    }

    if (print_hex) {
        buf = (DemodBuffer + offset);
        char hex[512] = {0x00};
        int num_bits = binarraytohex(hex, sizeof(hex), (char *)buf, len);
        if (num_bits == 0) {
            return PM3_ESOFT;
        }
        PrintAndLogEx(SUCCESS, "DemodBuffer: %s", hex);
    } else {
        PrintAndLogEx(SUCCESS, "DemodBuffer:\n%s", sprint_bin_break(DemodBuffer + offset, len, 32));
    }
    return PM3_SUCCESS;
}

int CmdPrintDemodBuff(const char *Cmd) {
    bool print_hex = false;
    bool errors = false;
    bool lstrip = false;
    bool invert = false;
    uint32_t offset = 0;
    uint32_t length = 512;
    char cmdp = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_data_printdemodbuf();
            case 'x':
                print_hex = true;
                cmdp++;
                break;
            case 'o':
                offset = param_get32ex(Cmd, cmdp + 1, 0, 10);
                if (!offset) errors = true;
                cmdp += 2;
                break;
            case 'l':
                length = param_get32ex(Cmd, cmdp + 1, 512, 10);
                if (!length) errors = true;
                cmdp += 2;
                break;
            case 's':
                lstrip = true;
                cmdp++;
                break;
            case 'i':
                invert = true;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    //Validations
    if (errors) return usage_data_printdemodbuf();

    return printDemodBuff(offset, lstrip, invert, print_hex);
}

//by marshmellow
//this function strictly converts >1 to 1 and <1 to 0 for each sample in the graphbuffer
int CmdGetBitStream(const char *Cmd) {
    CmdHpf(Cmd);
    for (uint32_t i = 0; i < GraphTraceLen; i++)
        GraphBuffer[i] = (GraphBuffer[i] >= 1) ? 1 : 0;

    RepaintGraphWindow();
    return PM3_SUCCESS;
}
static int CmdConvertBitStream(const char *Cmd) {

    if (isGraphBitstream()) {
        convertGraphFromBitstream();
    } else {
        // get high, low
        convertGraphFromBitstreamEx(-126, -127);
    }
    return PM3_SUCCESS;
}

//by marshmellow
//Cmd Args: Clock, invert, maxErr, maxLen as integers and amplify as char == 'a'
//   (amp may not be needed anymore)
//verbose will print results and demoding messages
//emSearch will auto search for EM410x format in bitstream
//askType switches decode: ask/raw = 0, ask/manchester = 1
int ASKDemod_ext(int clk, int invert, int maxErr, size_t maxLen, bool amplify, bool verbose, bool emSearch, uint8_t askType, bool *stCheck) {
    PrintAndLogEx(DEBUG, "DEBUG: (ASKDemod_ext) clk %i invert %i maxErr %i maxLen %zu amplify %i verbose %i emSearch %i askType %i ", clk, invert, maxErr, maxLen, amplify, verbose, emSearch, askType);
    uint8_t askamp = 0;

    if (!maxLen) maxLen = pm3_capabilities.bigbuf_size;

    uint8_t *bits = calloc(MAX_GRAPH_TRACE_LEN, sizeof(uint8_t));
    if (bits == NULL) {
        return PM3_EMALLOC;
    }

    size_t BitLen = getFromGraphBuf(bits);

    PrintAndLogEx(DEBUG, "DEBUG: (ASKDemod_ext) #samples from graphbuff: %zu", BitLen);

    if (BitLen < 255) {
        free(bits);
        return PM3_ESOFT;
    }

    if (maxLen < BitLen && maxLen != 0) BitLen = maxLen;

    int foundclk = 0;

    //amplify signal before ST check
    if (amplify) {
        askAmp(bits, BitLen);
    }

    size_t ststart = 0, stend = 0;
//    if (*stCheck)
    bool st = DetectST(bits, &BitLen, &foundclk, &ststart, &stend);

    if (clk == 0) {
        if (foundclk == 32 || foundclk == 64) {
            clk = foundclk;
        }
    }

    if (st) {
        *stCheck = st;
        CursorCPos = ststart;
        CursorDPos = stend;
        if (verbose)
            PrintAndLogEx(DEBUG, "Found Sequence Terminator - First one is shown by orange / blue graph markers");
    }

    int startIdx = 0;
    int errCnt = askdemod_ext(bits, &BitLen, &clk, &invert, maxErr, askamp, askType, &startIdx);

    if (errCnt < 0 || BitLen < 16) { //if fatal error (or -1)
        PrintAndLogEx(DEBUG, "DEBUG: (ASKDemod_ext) No data found errors:%d, invert:%c, bitlen:%zu, clock:%d", errCnt, (invert) ? 'Y' : 'N', BitLen, clk);
        free(bits);
        return PM3_ESOFT;
    }

    if (errCnt > maxErr) {
        PrintAndLogEx(DEBUG, "DEBUG: (ASKDemod_ext) Too many errors found, errors:%d, bits:%zu, clock:%d", errCnt, BitLen, clk);
        free(bits);
        return PM3_ESOFT;
    }

    if (verbose) PrintAndLogEx(DEBUG, "DEBUG: (ASKDemod_ext) Using clock:%d, invert:%d, bits found:%zu, start index %d", clk, invert, BitLen, startIdx);

    //output
    setDemodBuff(bits, BitLen, 0);
    setClockGrid(clk, startIdx);

    if (verbose) {
        if (errCnt > 0)
            PrintAndLogEx(DEBUG, "# Errors during Demoding (shown as 7 in bit stream): %d", errCnt);
        if (askType)
            PrintAndLogEx(DEBUG, "ASK/Manchester - Clock: %d - Decoded bitstream:", clk);
        else
            PrintAndLogEx(DEBUG, "ASK/Raw - Clock: %d - Decoded bitstream:", clk);

        printDemodBuff(0, false, false, false);
    }
    uint64_t lo = 0;
    uint32_t hi = 0;
    if (emSearch)
        AskEm410xDecode(true, &hi, &lo);

    free(bits);
    return PM3_SUCCESS;
}
int ASKDemod(int clk, int invert, int maxErr, size_t maxLen, bool amplify, bool verbose, bool emSearch, uint8_t askType) {
    bool st = false;
    return ASKDemod_ext(clk, invert, maxErr, maxLen, amplify, verbose, emSearch, askType, &st);
}

//by marshmellow
//takes 5 arguments - clock, invert, maxErr, maxLen as integers and amplify as char == 'a'
//attempts to demodulate ask while decoding manchester
//prints binary found and saves in graphbuffer for further commands
static int Cmdaskmandemod(const char *Cmd) {

    size_t slen = strlen(Cmd);

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (slen > 45 || cmdp == 'h') return usage_data_rawdemod_am();

    bool st = false, amplify = false;
    int clk = 0, invert = 0, maxErr = 100;
    size_t maxLen = 0;

    if (slen) {

        if (Cmd[0] == 's') {
            st = true;
            Cmd++;
        } else if (slen > 1 && Cmd[1] == 's') {
            st = true;
            Cmd += 2;
        }

        char amp = tolower(param_getchar(Cmd, 0));
        sscanf(Cmd, "%i %i %i %zu %c", &clk, &invert, &maxErr, &maxLen, &amp);

        amplify = (amp == 'a');
    }

    if (clk == 1) {
        invert = 1;
        clk = 0;
    }

    if (invert != 0 && invert != 1) {
        PrintAndLogEx(WARNING, "Invalid value for invert: %i", invert);
        return PM3_EINVARG;
    }
    return ASKDemod_ext(clk, invert, maxErr, maxLen, amplify, true, true, 1, &st);
}

//by marshmellow
//manchester decode
//strictly take 10 and 01 and convert to 0 and 1
static int Cmdmandecoderaw(const char *Cmd) {
    size_t size = 0;
    int high = 0, low = 0;
    size_t i = 0;
    uint16_t errCnt = 0;
    int invert = 0, maxErr = 20;
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) > 5 || cmdp == 'h') return usage_data_manrawdecode();

    if (DemodBufferLen == 0) return PM3_ESOFT;

    uint8_t bits[MAX_DEMOD_BUF_LEN] = {0};

    for (; i < DemodBufferLen; ++i) {
        if (DemodBuffer[i] > high)
            high = DemodBuffer[i];
        else if (DemodBuffer[i] < low)
            low = DemodBuffer[i];
        bits[i] = DemodBuffer[i];
    }

    if (high > 7 || low < 0) {
        PrintAndLogEx(ERR, "Error: please raw demod the wave first then manchester raw decode");
        return PM3_ESOFT;
    }

    sscanf(Cmd, "%i %i", &invert, &maxErr);
    size = i;
    uint8_t alignPos = 0;
    errCnt = manrawdecode(bits, &size, invert, &alignPos);
    if (errCnt >= maxErr) {
        PrintAndLogEx(ERR, "Too many errors: %u", errCnt);
        return PM3_ESOFT;
    }

    PrintAndLogEx(NORMAL, "Manchester Decoded - # errors:%d - data:", errCnt);
    PrintAndLogEx(NORMAL, "%s", sprint_bin_break(bits, size, 32));

    if (errCnt == 0) {
        uint64_t id = 0;
        uint32_t hi = 0;
        size_t idx = 0;
        if (Em410xDecode(bits, &size, &idx, &hi, &id) == 1) {
            //need to adjust to set bitstream back to manchester encoded data
            //setDemodBuff(bits, size, idx);
            printEM410x(hi, id, false);
        }
    }
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
    size_t size = 0;
    int offset = 0, invert = 0, maxErr = 20, errCnt = 0;
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) > 5 || cmdp == 'h') return usage_data_biphaserawdecode();

    sscanf(Cmd, "%i %i %i", &offset, &invert, &maxErr);
    if (DemodBufferLen == 0) {
        PrintAndLogEx(WARNING, "DemodBuffer Empty - run " _YELLOW_("'data rawdemod ar'")" first");
        return PM3_ESOFT;
    }

    uint8_t bits[MAX_DEMOD_BUF_LEN] = {0};
    size = sizeof(bits);
    if (!getDemodBuff(bits, &size)) return PM3_ESOFT;

    errCnt = BiphaseRawDecode(bits, &size, &offset, invert);
    if (errCnt < 0) {
        PrintAndLogEx(ERR, "Error during decode:%d", errCnt);
        return PM3_ESOFT;
    }
    if (errCnt > maxErr) {
        PrintAndLogEx(ERR, "Too many errors attempting to decode: %d", errCnt);
        return PM3_ESOFT;
    }

    if (errCnt > 0)
        PrintAndLogEx(WARNING, "# Errors found during Demod (shown as " _YELLOW_("7")" in bit stream): %d", errCnt);

    PrintAndLogEx(NORMAL, "Biphase Decoded using offset: %d - # invert:%d - data:", offset, invert);
    PrintAndLogEx(NORMAL, "%s", sprint_bin_break(bits, size, 32));

    //remove first bit from raw demod
    if (offset)
        setDemodBuff(DemodBuffer, DemodBufferLen - offset, offset);

    setClockGrid(g_DemodClock, g_DemodStartIdx + g_DemodClock * offset / 2);
    return PM3_SUCCESS;
}

//by marshmellow
// - ASK Demod then Biphase decode GraphBuffer samples
int ASKbiphaseDemod(int offset, int clk, int invert, int maxErr, bool verbose) {
    //ask raw demod GraphBuffer first

    uint8_t bs[MAX_DEMOD_BUF_LEN];
    size_t size = getFromGraphBuf(bs);
    if (size == 0) {
        PrintAndLogEx(DEBUG, "DEBUG: no data in graphbuf");
        return PM3_ESOFT;
    }
    int startIdx = 0;
    //invert here inverts the ask raw demoded bits which has no effect on the demod, but we need the pointer
    int errCnt = askdemod_ext(bs, &size, &clk, &invert, maxErr, 0, 0, &startIdx);
    if (errCnt < 0 || errCnt > maxErr) {
        PrintAndLogEx(DEBUG, "DEBUG: no data or error found %d, clock: %d", errCnt, clk);
        return PM3_ESOFT;
    }

    //attempt to Biphase decode BitStream
    errCnt = BiphaseRawDecode(bs, &size, &offset, invert);
    if (errCnt < 0) {
        if (g_debugMode || verbose) PrintAndLogEx(DEBUG, "DEBUG: Error BiphaseRawDecode: %d", errCnt);
        return PM3_ESOFT;
    }
    if (errCnt > maxErr) {
        if (g_debugMode || verbose) PrintAndLogEx(DEBUG, "DEBUG: Error BiphaseRawDecode too many errors: %d", errCnt);
        return PM3_ESOFT;
    }

    //success set DemodBuffer and return
    setDemodBuff(bs, size, 0);
    setClockGrid(clk, startIdx + clk * offset / 2);
    if (g_debugMode || verbose) {
        PrintAndLogEx(DEBUG, "Biphase Decoded using offset %d | clock %d | #errors %d | start index %d\ndata\n", offset, clk, errCnt, (startIdx + clk * offset / 2));
        printDemodBuff(offset, false, false, false);
    }
    return PM3_SUCCESS;
}
//by marshmellow - see ASKbiphaseDemod
static int Cmdaskbiphdemod(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) > 25 || cmdp == 'h') return usage_data_rawdemod_ab();
    int offset = 0, clk = 0, invert = 0, maxErr = 50;
    sscanf(Cmd, "%i %i %i %i", &offset, &clk, &invert, &maxErr);
    return ASKbiphaseDemod(offset, clk, invert, maxErr, true);
}

//by marshmellow - see ASKDemod
static int Cmdaskrawdemod(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) > 25 || cmdp == 'h') return usage_data_rawdemod_ar();
    bool st = false;
    int clk = 0;
    int invert = 0;
    int maxErr = 100;
    size_t maxLen = 0;
    bool amplify = false;
    char amp = tolower(param_getchar(Cmd, 0));
    sscanf(Cmd, "%i %i %i %zu %c", &clk, &invert, &maxErr, &maxLen, &amp);
    amplify = amp == 'a';
    if (clk == 1) {
        invert = 1;
        clk = 0;
    }
    if (invert != 0 && invert != 1) {
        PrintAndLogEx(WARNING, "Invalid value for invert: %i", invert);
        return PM3_EINVARG;
    }
    return ASKDemod_ext(clk, invert, maxErr, maxLen, amplify, true, false, 0, &st);
}

int AutoCorrelate(const int *in, int *out, size_t len, size_t window, bool SaveGrph, bool verbose) {
    // sanity check
    if (window > len) window = len;

    if (verbose) PrintAndLogEx(INFO, "performing " _YELLOW_("%zu") " correlations", GraphTraceLen - window);

    //test
    double autocv = 0.0;    // Autocovariance value
    size_t correlation = 0;
    int lastmax = 0;

    // in, len, 4000
    double mean = compute_mean(in, len);
    // Computed variance
    double variance = compute_variance(in, len);

    int *correl_buf = calloc(MAX_GRAPH_TRACE_LEN, sizeof(int));

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
        if (ac_value > 1) {
            correlation = i - lastmax;
            lastmax = i;
        }
    }

    //
    int hi = 0, idx = 0;
    int distance = 0, hi_1 = 0, idx_1 = 0;
    for (size_t i = 0; i <= len; ++i) {
        if (correl_buf[i] > hi) {
            hi = correl_buf[i];
            idx = i;
        }
    }

    for (size_t i = idx + 1; i <= window; ++i) {
        if (correl_buf[i] > hi_1) {
            hi_1 = correl_buf[i];
            idx_1 = i;
        }
    }

    int foo = ABS(hi - hi_1);
    int bar = (int)((int)((hi + hi_1) / 2) * 0.04);

    if (verbose && foo < bar) {
        distance = idx_1 - idx;
        PrintAndLogEx(SUCCESS, "possible visible correlation "_YELLOW_("%4d") " samples", distance);
    } else if (verbose && (correlation > 1)) {
        PrintAndLogEx(SUCCESS, "possible correlation " _YELLOW_("%4zu") " samples", correlation);
    } else {
        PrintAndLogEx(FAILED, "no repeating pattern found, try increasing window size");
    }

    int retval = correlation;
    if (SaveGrph) {
        //GraphTraceLen = GraphTraceLen - window;
        memcpy(out, correl_buf, len * sizeof(int));
        if (distance > 0) {
            setClockGrid(distance, idx);
            retval = distance;
        } else
            setClockGrid(correlation, idx);

        CursorCPos = idx_1;
        CursorDPos = idx_1 + retval;
        DemodBufferLen = 0;
        RepaintGraphWindow();
    }
    free(correl_buf);
    return retval;
}

static int CmdAutoCorr(const char *Cmd) {

    uint32_t window = 4000;
    uint8_t cmdp = 0;
    bool updateGrph = false;
    bool errors = false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_data_autocorr();
            case 'g':
                updateGrph = true;
                cmdp++;
                break;
            case 'w':
                window = param_get32ex(Cmd, cmdp + 1, 4000, 10);
                if (window >= GraphTraceLen) {
                    PrintAndLogEx(WARNING, "window must be smaller than trace (%zu samples)", GraphTraceLen);
                    errors = true;
                }
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    //Validations
    if (errors || cmdp == 0) return usage_data_autocorr();

    AutoCorrelate(GraphBuffer, GraphBuffer, GraphTraceLen, window, updateGrph, true);

    return PM3_SUCCESS;
}

static int CmdBitsamples(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    int cnt = 0;
    uint8_t got[12288];

    if (!GetFromDevice(BIG_BUF, got, sizeof(got), 0, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    for (size_t j = 0; j < ARRAYLEN(got); j++) {
        for (uint8_t k = 0; k < 8; k++) {
            if (got[j] & (1 << (7 - k)))
                GraphBuffer[cnt++] = 1;
            else
                GraphBuffer[cnt++] = 0;
        }
    }
    GraphTraceLen = cnt;
    RepaintGraphWindow();
    return PM3_SUCCESS;
}

static int CmdBuffClear(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_data_buffclear();

    clearCommandBuffer();
    SendCommandNG(CMD_BUFF_CLEAR, NULL, 0);
    ClearGraph(true);
    return PM3_SUCCESS;
}

static int CmdDecimate(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data decimate",
                  "Performs decimation, by reducing samples N times in the grapbuf. Good for PSK\n",
                  "data decimate\n"
                  "data decimate 4"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0(NULL, NULL, "<dec>", "factor to reduce sample set (default 2)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int n = arg_get_int_def(ctx, 1, 2);
    CLIParserFree(ctx);

    for (size_t i = 0; i < (GraphTraceLen / n); ++i)
        GraphBuffer[i] = GraphBuffer[i * n];

    GraphTraceLen /= n;
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
                  "data undecimate 4\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0(NULL, NULL, "<dec>", "factor to repeat each sample (default 2)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int factor = arg_get_int_def(ctx, 1, 2);
    CLIParserFree(ctx);

    //We have memory, don't we?
    int swap[MAX_GRAPH_TRACE_LEN] = {0};
    uint32_t g_index = 0, s_index = 0;
    while (g_index < GraphTraceLen && s_index + factor < MAX_GRAPH_TRACE_LEN) {
        int count = 0;
        for (count = 0; count < factor && s_index + count < MAX_GRAPH_TRACE_LEN; count++) {
            swap[s_index + count] = (
                                        (double)(factor - count) / (factor - 1)) * GraphBuffer[g_index] +
                                    ((double)count / factor) * GraphBuffer[g_index + 1]
                                    ;
        }
        s_index += count;
        g_index++;
    }

    memcpy(GraphBuffer, swap, s_index * sizeof(int));
    GraphTraceLen = s_index;
    RepaintGraphWindow();
    return PM3_SUCCESS;
}

//by marshmellow
//shift graph zero up or down based on input + or -
static int CmdGraphShiftZero(const char *Cmd) {
    int shift = 0;
    //set options from parameters entered with the command
    sscanf(Cmd, "%i", &shift);

    for (size_t i = 0; i < GraphTraceLen; i++) {
        int shiftedVal = GraphBuffer[i] + shift;

        if (shiftedVal > 127)
            shiftedVal = 127;
        else if (shiftedVal < -127)
            shiftedVal = -127;
        GraphBuffer[i] = shiftedVal;
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

//by marshmellow
//use large jumps in read samples to identify edges of waves and then amplify that wave to max
//similar to dirtheshold, threshold commands
//takes a threshold length which is the measured length between two samples then determines an edge
static int CmdAskEdgeDetect(const char *Cmd) {
    int thresLen = 25;
    int ans = 0;
    sscanf(Cmd, "%i", &thresLen);

    ans = AskEdgeDetect(GraphBuffer, GraphBuffer, GraphTraceLen, thresLen);
    RepaintGraphWindow();
    return ans;
}

/* Print our clock rate */
// uses data from graphbuffer
// adjusted to take char parameter for type of modulation to find the clock - by marshmellow.
static int CmdDetectClockRate(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) > 6 || strlen(Cmd) == 0 || cmdp == 'h')
        return usage_data_detectclock();

    int clock1 = 0;
    switch (cmdp) {
        case 'a' :
            clock1 = GetAskClock(Cmd + 1, true);
            break;
        case 'f' :
            clock1 = GetFskClock("", true);
            break;
        case 'n' :
            clock1 = GetNrzClock("", true);
            break;
        case 'p' :
            clock1 = GetPskClock("", true);
            break;
        default :
            PrintAndLogEx(NORMAL, "Please specify a valid modulation to detect the clock of - see option h for help");
            break;
    }
    RepaintGraphWindow();
    return clock1;
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

//by marshmellow
//fsk raw demod and print binary
//takes 4 arguments - Clock, invert, fchigh, fclow
//defaults: clock = 50, invert=1, fchigh=10, fclow=8 (RF/10 RF/8 (fsk2a))
int FSKrawDemod(uint8_t rfLen, uint8_t invert, uint8_t fchigh, uint8_t fclow, bool verbose) {
    //raw fsk demod  no manchester decoding no start bit finding just get binary from wave
    if (getSignalProperties()->isnoise)
        return PM3_ESOFT;

    uint8_t *bits = calloc(MAX_GRAPH_TRACE_LEN, sizeof(uint8_t));
    if (bits == NULL) {
        return PM3_EMALLOC;
    }

    size_t BitLen = getFromGraphBuf(bits);
    if (BitLen == 0) {
        free(bits);
        return PM3_ESOFT;
    }

    //get field clock lengths
    if (!fchigh || !fclow) {
        uint16_t fcs = countFC(bits, BitLen, true);
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
        rfLen = detectFSKClk(bits, BitLen, fchigh, fclow, &firstClockEdge);
        if (!rfLen) rfLen = 50;
    }
    int startIdx = 0;
    int size = fskdemod(bits, BitLen, rfLen, invert, fchigh, fclow, &startIdx);
    if (size > 0) {
        setDemodBuff(bits, size, 0);
        setClockGrid(rfLen, startIdx);

        // Now output the bitstream to the scrollback by line of 16 bits
        if (verbose || g_debugMode) {
            PrintAndLogEx(DEBUG, "DEBUG: (FSKrawDemod) Using Clock:%u, invert:%u, fchigh:%u, fclow:%u", rfLen, invert, fchigh, fclow);
            PrintAndLogEx(NORMAL, "%s decoded bitstream:", GetFSKType(fchigh, fclow, invert));
            printDemodBuff(0, false, invert, false);
        }
        goto out;
    } else {
        PrintAndLogEx(DEBUG, "no FSK data found");
    }

out:
    free(bits);
    return PM3_SUCCESS;
}

//by marshmellow
//fsk raw demod and print binary
//takes 4 arguments - Clock, invert, fchigh, fclow
//defaults: clock = 50, invert=1, fchigh=10, fclow=8 (RF/10 RF/8 (fsk2a))
static int CmdFSKrawdemod(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) > 20 || cmdp == 'h') return usage_data_rawdemod_fs();
    uint8_t rfLen, invert, fchigh, fclow;

    //set defaults
    //set options from parameters entered with the command
    rfLen = param_get8(Cmd, 0);
    invert = param_get8(Cmd, 1);
    fchigh = param_get8(Cmd, 2);
    fclow = param_get8(Cmd, 3);

    if (strlen(Cmd) > 0 && strlen(Cmd) <= 2) {
        if (rfLen == 1) {
            invert = 1;   //if invert option only is used
            rfLen = 0;
        }
    }
    return FSKrawDemod(rfLen, invert, fchigh, fclow, true);
}

//by marshmellow
//attempt to psk1 demod graph buffer
int PSKDemod(int clk, int invert, int maxErr, bool verbose) {
    if (getSignalProperties()->isnoise)
        return PM3_ESOFT;

    uint8_t *bits = calloc(MAX_GRAPH_TRACE_LEN, sizeof(uint8_t));
    if (bits == NULL) {
        return PM3_EMALLOC;
    }
    size_t bitlen = getFromGraphBuf(bits);
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
    //prime demod buffer for output
    setDemodBuff(bits, bitlen, 0);
    setClockGrid(clk, startIdx);
    free(bits);
    return PM3_SUCCESS;
}

// by marshmellow
// takes 3 arguments - clock, invert, maxErr as integers
// attempts to demodulate nrz only
// prints binary found and saves in demodbuffer for further commands
int NRZrawDemod(int clk, int invert, int maxErr, bool verbose) {

    int errCnt = 0, clkStartIdx = 0;

    if (getSignalProperties()->isnoise)
        return PM3_ESOFT;

    uint8_t *bits = calloc(MAX_GRAPH_TRACE_LEN, sizeof(uint8_t));
    if (bits == NULL) {
        return PM3_EMALLOC;
    }

    size_t BitLen = getFromGraphBuf(bits);

    if (BitLen == 0) {
        free(bits);
        return PM3_ESOFT;
    }

    errCnt = nrzRawDemod(bits, &BitLen, &clk, &invert, &clkStartIdx);
    if (errCnt > maxErr) {
        PrintAndLogEx(DEBUG, "DEBUG: (NRZrawDemod) Too many errors found, clk: %d, invert: %d, numbits: %zu, errCnt: %d", clk, invert, BitLen, errCnt);
        free(bits);
        return PM3_ESOFT;
    }
    if (errCnt < 0 || BitLen < 16) { //throw away static - allow 1 and -1 (in case of threshold command first)
        PrintAndLogEx(DEBUG, "DEBUG: (NRZrawDemod) no data found, clk: %d, invert: %d, numbits: %zu, errCnt: %d", clk, invert, BitLen, errCnt);
        free(bits);
        return PM3_ESOFT;
    }

    if (verbose || g_debugMode) PrintAndLogEx(DEBUG, "DEBUG: (NRZrawDemod) Tried NRZ Demod using Clock: %d - invert: %d - Bits Found: %zu", clk, invert, BitLen);
    //prime demod buffer for output
    setDemodBuff(bits, BitLen, 0);
    setClockGrid(clk, clkStartIdx);


    if (errCnt > 0 && (verbose || g_debugMode)) PrintAndLogEx(DEBUG, "DEBUG: (NRZrawDemod) Errors during Demoding (shown as 7 in bit stream): %d", errCnt);
    if (verbose || g_debugMode) {
        PrintAndLogEx(NORMAL, "NRZ demoded bitstream:");
        // Now output the bitstream to the scrollback by line of 16 bits
        printDemodBuff(0, false, invert, false);
    }

    free(bits);
    return PM3_SUCCESS;
}

static int CmdNRZrawDemod(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) > 16 || cmdp == 'h') return usage_data_rawdemod_nr();
    int invert = 0, clk = 0, maxErr = 100;
    sscanf(Cmd, "%i %i %i", &clk, &invert, &maxErr);
    if (clk == 1) {
        invert = 1;
        clk = 0;
    }

    if (invert != 0 && invert != 1) {
        PrintAndLogEx(WARNING, "(NRZrawDemod) Invalid argument: %s", Cmd);
        return PM3_EINVARG;
    }
    return NRZrawDemod(clk, invert, maxErr, true);
}

// by marshmellow
// takes 3 arguments - clock, invert, max_err as integers
// attempts to demodulate psk only
// prints binary found and saves in demodbuffer for further commands
int CmdPSK1rawDemod(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) > 16 || cmdp == 'h') return usage_data_rawdemod_p1();
    int clk = 0, invert = 0, max_err = 100;
    sscanf(Cmd, "%i %i %i", &clk, &invert, &max_err);
    if (clk == 1) {
        invert = 1;
        clk = 0;
    }
    if (invert != 0 && invert != 1) {
        PrintAndLogEx(WARNING, "Invalid value for invert: %i", invert);
        return PM3_EINVARG;
    }
    int ans = PSKDemod(clk, invert, max_err, true);
    //output
    if (ans != PM3_SUCCESS) {
        if (g_debugMode) PrintAndLogEx(ERR, "Error demoding: %d", ans);
        return PM3_ESOFT;
    }
    PrintAndLogEx(NORMAL, "PSK1 demoded bitstream:");
    // Now output the bitstream to the scrollback by line of 16 bits
    printDemodBuff(0, false, invert, false);
    return PM3_SUCCESS;
}

// by marshmellow
// takes same args as cmdpsk1rawdemod
static int CmdPSK2rawDemod(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) > 16 || cmdp == 'h') return usage_data_rawdemod_p2();
    int clk = 0, invert = 0, max_err = 100;
    sscanf(Cmd, "%i %i %i", &clk, &invert, &max_err);
    if (clk == 1) {
        invert = 1;
        clk = 0;
    }
    if (invert != 0 && invert != 1) {
        PrintAndLogEx(WARNING, "Invalid value for invert: %i", invert);
        return PM3_EINVARG;
    }
    int ans = PSKDemod(clk, invert, max_err, true);
    if (ans != PM3_SUCCESS) {
        if (g_debugMode) PrintAndLogEx(ERR, "Error demoding: %d", ans);
        return PM3_ESOFT;
    }
    psk1TOpsk2(DemodBuffer, DemodBufferLen);
    PrintAndLogEx(NORMAL, "PSK2 demoded bitstream:");
    // Now output the bitstream to the scrollback by line of 16 bits
    printDemodBuff(0, false, invert, false);
    return PM3_SUCCESS;
}

// by marshmellow - combines all raw demod functions into one menu command
static int CmdRawDemod(const char *Cmd) {
    int ans = 0;

    if (strlen(Cmd) > 35 || strlen(Cmd) < 2)
        return usage_data_rawdemod();

    str_lower((char *)Cmd);

    if (str_startswith(Cmd, "fs") || Cmd[0] == 'f') ans = CmdFSKrawdemod(Cmd + 2);
    else if (str_startswith(Cmd, "ab")) ans = Cmdaskbiphdemod(Cmd + 2);
    else if (str_startswith(Cmd, "am")) ans = Cmdaskmandemod(Cmd + 2);
    else if (str_startswith(Cmd, "ar")) ans = Cmdaskrawdemod(Cmd + 2);
    else if (str_startswith(Cmd, "nr") || Cmd[0] == 'n') ans = CmdNRZrawDemod(Cmd + 2);
    else if (str_startswith(Cmd, "p1")) ans = CmdPSK1rawDemod(Cmd + 2);
    else if (str_startswith(Cmd, "p2")) ans = CmdPSK2rawDemod(Cmd + 2);
    else PrintAndLogEx(WARNING, "Unknown modulation entered - see help ('h') for parameter structure");

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

    if (offset > GraphTraceLen || offset < 0) return;
    if (clk < 8 || clk > GraphTraceLen) {
        GridLocked = false;
        GridOffset = 0;
        PlotGridX = 0;
        PlotGridXdefault = 0;
        RepaintGraphWindow();
    } else {
        GridLocked = true;
        GridOffset = offset;
        PlotGridX = clk;
        PlotGridXdefault = clk;
        RepaintGraphWindow();
    }
}

int CmdGrid(const char *Cmd) {
    sscanf(Cmd, "%lf %lf", &PlotGridX, &PlotGridY);
    PlotGridXdefault = PlotGridX;
    PlotGridYdefault = PlotGridY;
    RepaintGraphWindow();
    return PM3_SUCCESS;
}

static int CmdSetGraphMarkers(const char *Cmd) {
    sscanf(Cmd, "%i %i", &CursorCPos, &CursorDPos);
    RepaintGraphWindow();
    return PM3_SUCCESS;
}

static int CmdHexsamples(const char *Cmd) {
    uint32_t requested = 0;
    uint32_t offset = 0;
    char string_buf[25];
    char *string_ptr = string_buf;
    uint8_t got[pm3_capabilities.bigbuf_size];

    sscanf(Cmd, "%u %u", &requested, &offset);

    /* if no args send something */
    if (requested == 0)
        requested = 8;
    if (requested > pm3_capabilities.bigbuf_size)
        requested = pm3_capabilities.bigbuf_size;

    if (offset + requested > sizeof(got)) {
        PrintAndLogEx(NORMAL, "Tried to read past end of buffer, <bytes> + <offset> > %d", pm3_capabilities.bigbuf_size);
        return PM3_EINVARG;
    }

    if (!GetFromDevice(BIG_BUF, got, requested, offset, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ESOFT;
    }

    uint8_t i = 0;
    for (uint32_t j = 0; j < requested; j++) {
        i++;
        string_ptr += sprintf(string_ptr, "%02x ", got[j]);
        if (i == 8) {
            *(string_ptr - 1) = '\0';    // remove the trailing space
            PrintAndLogEx(NORMAL, "%s", string_buf);
            string_buf[0] = '\0';
            string_ptr = string_buf;
            i = 0;
        }
        if (j == requested - 1 && string_buf[0] != '\0') { // print any remaining bytes
            *(string_ptr - 1) = '\0';
            PrintAndLogEx(NORMAL, "%s", string_buf);
            string_buf[0] = '\0';
        }
    }
    return PM3_SUCCESS;
}

static int CmdHide(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    HideGraphWindow();
    return PM3_SUCCESS;
}

//zero mean GraphBuffer
int CmdHpf(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    uint8_t bits[GraphTraceLen];
    size_t size = getFromGraphBuf(bits);
    removeSignalOffset(bits, size);
    // push it back to graph
    setGraphBuf(bits, size);
    // set signal properties low/high/mean/amplitude and is_noise detection
    computeSignalProperties(bits, size);

    RepaintGraphWindow();
    return PM3_SUCCESS;
}

static bool _headBit(BitstreamOut *stream) {
    int bytepos = stream->position >> 3; // divide by 8
    int bitpos = (stream->position++) & 7; // mask out 00000111
    return (*(stream->buffer + bytepos) >> (7 - bitpos)) & 1;
}

static uint8_t getByte(uint8_t bits_per_sample, BitstreamOut *b) {
    uint8_t val = 0;
    for (int i = 0 ; i < bits_per_sample; i++)
        val |= (_headBit(b) << (7 - i));

    return val;
}

int getSamples(uint32_t n, bool verbose) {
    return getSamplesEx(0, n, verbose);
}

int getSamplesEx(uint32_t start, uint32_t end, bool verbose) {

    if (end < start) {
        PrintAndLogEx(WARNING, "error, end (%u) is smaller than start (%u)", end, start);
        return PM3_EINVARG;
    }

    //If we get all but the last byte in bigbuf,
    // we don't have to worry about remaining trash
    // in the last byte in case the bits-per-sample
    // does not line up on byte boundaries
    uint8_t got[pm3_capabilities.bigbuf_size - 1];
    memset(got, 0x00, sizeof(got));

    uint32_t n = end - start;

    if (n == 0 || n > pm3_capabilities.bigbuf_size - 1)
        n = pm3_capabilities.bigbuf_size - 1;

    if (verbose)
        PrintAndLogEx(INFO, "Reading " _YELLOW_("%u") " bytes from device memory", n);

    PacketResponseNG response;
    if (!GetFromDevice(BIG_BUF, got, n, start, NULL, 0, &response, 10000, true)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (verbose) PrintAndLogEx(SUCCESS, "Data fetched");

    uint8_t bits_per_sample = 8;

    //Old devices without this feature would send 0 at arg[0]
    if (response.oldarg[0] > 0) {
        sample_config *sc = (sample_config *) response.data.asBytes;
        if (verbose) PrintAndLogEx(INFO, "Samples @ " _YELLOW_("%d") " bits/smpl, decimation 1:%d ", sc->bits_per_sample, sc->decimation);
        bits_per_sample = sc->bits_per_sample;
    }

    if (bits_per_sample < 8) {

        if (verbose) PrintAndLogEx(INFO, "Unpacking...");

        BitstreamOut bout = { got, bits_per_sample * n,  0};
        uint32_t j = 0;
        for (j = 0; j * bits_per_sample < n * 8 && j < n; j++) {
            uint8_t sample = getByte(bits_per_sample, &bout);
            GraphBuffer[j] = ((int) sample) - 127;
        }
        GraphTraceLen = j;

        if (verbose) PrintAndLogEx(INFO, "Unpacked %d samples", j);

    } else {
        for (uint32_t j = 0; j < n; j++) {
            GraphBuffer[j] = ((int)got[j]) - 127;
        }
        GraphTraceLen = n;
    }

    uint8_t bits[GraphTraceLen];
    size_t size = getFromGraphBuf(bits);
    // set signal properties low/high/mean/amplitude and is_noise detection
    computeSignalProperties(bits, size);

    setClockGrid(0, 0);
    DemodBufferLen = 0;
    RepaintGraphWindow();
    return PM3_SUCCESS;
}

static int CmdSamples(const char *Cmd) {
    int n = strtol(Cmd, NULL, 0);
    return getSamples(n, false);
}

int CmdTuneSamples(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
#define NON_VOLTAGE     1000
#define LF_UNUSABLE_V   2000
#define LF_MARGINAL_V   10000
#define HF_UNUSABLE_V   3000
#define HF_MARGINAL_V   5000
#define ANTENNA_ERROR   1.00 // current algo has 3% error margin.

    // hide demod plot line
    DemodBufferLen = 0;
    setClockGrid(0, 0);
    RepaintGraphWindow();

    int timeout = 0;
    int timeout_max = 20;
    PrintAndLogEx(INFO, "REMINDER: " _YELLOW_("'hw tune' doesn't actively tune your antennas") ", it's only informative");
    PrintAndLogEx(INFO, "Measuring antenna characteristics, please wait...");

    clearCommandBuffer();
    SendCommandNG(CMD_MEASURE_ANTENNA_TUNING, NULL, 0);
    PacketResponseNG resp;
    PrintAndLogEx(INPLACE, "% 3i", timeout_max - timeout);
    while (!WaitForResponseTimeout(CMD_MEASURE_ANTENNA_TUNING, &resp, 500)) {
        fflush(stdout);
        if (timeout >= timeout_max) {
            PrintAndLogEx(WARNING, "\nNo response from Proxmark3. Aborting...");
            return PM3_ETIMEOUT;
        }
        timeout++;
        PrintAndLogEx(INPLACE, "% 3i", timeout_max - timeout);
    }

    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Antenna tuning failed");
        return PM3_ESOFT;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "---------- " _CYAN_("LF Antenna") " ----------");
    // in mVolt
    struct p {
        uint32_t v_lf134;
        uint32_t v_lf125;
        uint32_t v_lfconf;
        uint32_t v_hf;
        uint32_t peak_v;
        uint32_t peak_f;
        int divisor;
        uint8_t results[256];
    } PACKED;

    struct p *package = (struct p *)resp.data.asBytes;

    if (package->v_lf125 > NON_VOLTAGE)
        PrintAndLogEx(SUCCESS, "LF antenna: %5.2f V - %.2f kHz", (package->v_lf125 * ANTENNA_ERROR) / 1000.0, LF_DIV2FREQ(LF_DIVISOR_125));

    if (package->v_lf134 > NON_VOLTAGE)
        PrintAndLogEx(SUCCESS, "LF antenna: %5.2f V - %.2f kHz", (package->v_lf134 * ANTENNA_ERROR) / 1000.0, LF_DIV2FREQ(LF_DIVISOR_134));

    if (package->v_lfconf > NON_VOLTAGE && package->divisor > 0 && package->divisor != LF_DIVISOR_125 && package->divisor != LF_DIVISOR_134)
        PrintAndLogEx(SUCCESS, "LF antenna: %5.2f V - %.2f kHz", (package->v_lfconf * ANTENNA_ERROR) / 1000.0, LF_DIV2FREQ(package->divisor));

    if (package->peak_v > NON_VOLTAGE && package->peak_f > 0)
        PrintAndLogEx(SUCCESS, "LF optimal: %5.2f V - %6.2f kHz", (package->peak_v * ANTENNA_ERROR) / 1000.0, LF_DIV2FREQ(package->peak_f));

    // Empirical measures in mV
    const double vdd_rdv4 = 9000;
    const double vdd_other = 5400;
    double vdd = IfPm3Rdv4Fw() ? vdd_rdv4 : vdd_other;

    if (package->peak_v > NON_VOLTAGE && package->peak_f > 0) {

        // Q measure with Q=f/delta_f
        double v_3db_scaled = (double)(package->peak_v * 0.707) / 512; // /512 == >>9
        uint32_t s2 = 0, s4 = 0;
        for (int i = 1; i < 256; i++) {
            if ((s2 == 0) && (package->results[i] > v_3db_scaled)) {
                s2 = i;
            }
            if ((s2 != 0) && (package->results[i] < v_3db_scaled)) {
                s4 = i;
                break;
            }
        }
        double lfq1 = 0;
        if (s4 != 0) { // we got all our points of interest
            double a = package->results[s2 - 1];
            double b = package->results[s2];
            double f1 = LF_DIV2FREQ(s2 - 1 + (v_3db_scaled - a) / (b - a));
            double c = package->results[s4 - 1];
            double d = package->results[s4];
            double f2 = LF_DIV2FREQ(s4 - 1 + (c - v_3db_scaled) / (c - d));
            lfq1 = LF_DIV2FREQ(package->peak_f) / (f1 - f2);
            PrintAndLogEx(SUCCESS, "Approx. Q factor (*): %.1lf by frequency bandwidth measurement", lfq1);
        }

        // Q measure with Vlr=Q*(2*Vdd/pi)
        double lfq2 = (double)package->peak_v * 3.14 / 2 / vdd;
        PrintAndLogEx(SUCCESS, "Approx. Q factor (*): %.1lf by peak voltage measurement", lfq2);
        // cross-check results
        if (lfq1 > 3) {
            double approx_vdd = (double)package->peak_v * 3.14 / 2 / lfq1;
            // Got 8858 on a RDV4 with large antenna 134/14
            // Got 8761 on a non-RDV4
            const double approx_vdd_other_max = 8840;

            // 1% over threshold and supposedly non-RDV4
            if ((approx_vdd > approx_vdd_other_max * 1.01) && (! IfPm3Rdv4Fw()))
                PrintAndLogEx(WARNING, "Contradicting measures seem to indicate you're running a " _YELLOW_("PM3_OTHER firmware on a RDV4") ", please check your setup");
            // 1% below threshold and supposedly RDV4
            if ((approx_vdd < approx_vdd_other_max * 0.99) && (IfPm3Rdv4Fw()))
                PrintAndLogEx(WARNING, "Contradicting measures seem to indicate you're running a " _YELLOW_("PM3_RDV4 firmware on a non-RDV4") ", please check your setup");
        }
    }

    char judgement[20];
    memset(judgement, 0, sizeof(judgement));
    // LF evaluation
    if (package->peak_v < LF_UNUSABLE_V)
        sprintf(judgement, _RED_("UNUSABLE"));
    else if (package->peak_v < LF_MARGINAL_V)
        sprintf(judgement, _YELLOW_("MARGINAL"));
    else
        sprintf(judgement, _GREEN_("OK"));

    PrintAndLogEx((package->peak_v < LF_UNUSABLE_V) ? WARNING : SUCCESS, "LF antenna is %s", judgement);

    PrintAndLogEx(INFO, "---------- " _CYAN_("HF Antenna") " ----------");
    // HF evaluation
    if (package->v_hf > NON_VOLTAGE)
        PrintAndLogEx(SUCCESS, "HF antenna: %5.2f V - 13.56 MHz", (package->v_hf * ANTENNA_ERROR) / 1000.0);

    memset(judgement, 0, sizeof(judgement));

    if (package->v_hf >= HF_UNUSABLE_V) {
        // Q measure with Vlr=Q*(2*Vdd/pi)
        double hfq = (double)package->v_hf * 3.14 / 2 / vdd;
        PrintAndLogEx(SUCCESS, "Approx. Q factor (*): %.1lf by peak voltage measurement", hfq);
    }
    if (package->v_hf < HF_UNUSABLE_V)
        sprintf(judgement, _RED_("UNUSABLE"));
    else if (package->v_hf < HF_MARGINAL_V)
        sprintf(judgement, _YELLOW_("MARGINAL"));
    else
        sprintf(judgement, _GREEN_("OK"));

    PrintAndLogEx((package->v_hf < HF_UNUSABLE_V) ? WARNING : SUCCESS, "HF antenna is %s", judgement);
    PrintAndLogEx(NORMAL, "\n(*) Q factor must be measured without tag on the antenna");

    // graph LF measurements
    // even here, these values has 3% error.
    uint16_t test1 = 0;
    for (int i = 0; i < 256; i++) {
        GraphBuffer[i] = package->results[i] - 128;
        test1 += package->results[i];
    }

    if (test1 > 0) {
        PrintAndLogEx(SUCCESS, "\nDisplaying LF tuning graph. Divisor %d (blue) is %.2f kHz, %d (red) is %.2f kHz.\n\n",
                      LF_DIVISOR_134, LF_DIV2FREQ(LF_DIVISOR_134), LF_DIVISOR_125, LF_DIV2FREQ(LF_DIVISOR_125));
        GraphTraceLen = 256;
        CursorCPos = LF_DIVISOR_125;
        CursorDPos = LF_DIVISOR_134;
        ShowGraphWindow();
        RepaintGraphWindow();
    } else {

        PrintAndLogEx(FAILED, "\nNot showing LF tuning graph since all values is zero.\n\n");
    }

    return PM3_SUCCESS;
}

static int CmdLoad(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data load",
                  "This command loads the contents of a pm3 file into graph window\n",
                  "data load -f myfilename"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_strx0("f", "file", "<filename>", "file to load"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    char *path = NULL;
    if (searchFile(&path, TRACES_SUBDIR, filename, ".pm3", true) != PM3_SUCCESS) {
        if (searchFile(&path, TRACES_SUBDIR, filename, "", false) != PM3_SUCCESS) {
            return PM3_EFILE;
        }
    }

    FILE *f = fopen(path, "r");
    if (!f) {
        PrintAndLogEx(WARNING, "couldn't open '%s'", path);
        free(path);
        return PM3_EFILE;
    }
    free(path);

    GraphTraceLen = 0;
    char line[80];
    while (fgets(line, sizeof(line), f)) {
        GraphBuffer[GraphTraceLen] = atoi(line);
        GraphTraceLen++;

        if (GraphTraceLen >= MAX_GRAPH_TRACE_LEN)
            break;
    }
    fclose(f);

    PrintAndLogEx(SUCCESS, "loaded " _YELLOW_("%zu") " samples", GraphTraceLen);

    uint8_t bits[GraphTraceLen];
    size_t size = getFromGraphBuf(bits);

    removeSignalOffset(bits, size);
    setGraphBuf(bits, size);
    computeSignalProperties(bits, size);

    setClockGrid(0, 0);
    DemodBufferLen = 0;
    RepaintGraphWindow();
    return PM3_SUCCESS;
}

// trim graph from the end
int CmdLtrim(const char *Cmd) {

    uint32_t ds = strtoul(Cmd, NULL, 10);

    // sanitycheck
    if (GraphTraceLen <= ds) return PM3_ESOFT;

    for (uint32_t i = ds; i < GraphTraceLen; ++i)
        GraphBuffer[i - ds] = GraphBuffer[i];

    GraphTraceLen -= ds;
    g_DemodStartIdx -= ds;
    RepaintGraphWindow();
    return PM3_SUCCESS;
}

// trim graph from the beginning
static int CmdRtrim(const char *Cmd) {

    uint32_t ds = strtoul(Cmd, NULL, 10);

    // sanitycheck
    if (GraphTraceLen <= ds) return PM3_ESOFT;

    GraphTraceLen = ds;
    RepaintGraphWindow();
    return PM3_SUCCESS;
}

// trim graph (middle) piece
static int CmdMtrim(const char *Cmd) {
    uint32_t start = 0, stop = 0;
    sscanf(Cmd, "%u %u", &start, &stop);

    if (start > GraphTraceLen || stop > GraphTraceLen || start >= stop)
        return PM3_ESOFT;

    // leave start position sample
    start++;

    GraphTraceLen = stop - start;
    for (uint32_t i = 0; i < GraphTraceLen; i++)
        GraphBuffer[i] = GraphBuffer[start + i];

    return PM3_SUCCESS;
}

int CmdNorm(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    int max = INT_MIN, min = INT_MAX;

    // Find local min, max
    for (uint32_t i = 10; i < GraphTraceLen; ++i) {
        if (GraphBuffer[i] > max) max = GraphBuffer[i];
        if (GraphBuffer[i] < min) min = GraphBuffer[i];
    }

    if (max != min) {
        for (uint32_t i = 0; i < GraphTraceLen; ++i) {
            GraphBuffer[i] = ((long)(GraphBuffer[i] - ((max + min) / 2)) * 256) / (max - min);
            //marshmelow: adjusted *1000 to *256 to make +/- 128 so demod commands still work
        }
    }

    uint8_t bits[GraphTraceLen];
    size_t size = getFromGraphBuf(bits);
    // set signal properties low/high/mean/amplitude and is_noise detection
    computeSignalProperties(bits, size);

    RepaintGraphWindow();
    return PM3_SUCCESS;
}

int CmdPlot(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    ShowGraphWindow();
    return PM3_SUCCESS;
}

int CmdSave(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data save",
                  "Save trace from graph window , i.e. the GraphBuffer\n"
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

    if (as_wave)
        return saveFileWAVE(filename, GraphBuffer, GraphTraceLen);
    else
        return saveFilePM3(filename, GraphBuffer, GraphTraceLen);
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
    CursorScaleFactor = arg_get_dbl_def(ctx, 1, 1);
    if (CursorScaleFactor <= 0) {
        PrintAndLogEx(FAILED, "bad, can't have negative or zero timescale factor");
        CursorScaleFactor = 1;
    }
    int len = 0;
    CursorScaleFactorUnit[0] = '\x00';
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)CursorScaleFactorUnit, sizeof(CursorScaleFactorUnit), &len);
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
    int8_t up = param_get8(Cmd, 0);
    int8_t down = param_get8(Cmd, 1);

    PrintAndLogEx(INFO, "Applying Up Threshold: %d, Down Threshold: %d\n", up, down);

    directionalThreshold(GraphBuffer, GraphBuffer, GraphTraceLen, up, down);

    // set signal properties low/high/mean/amplitude and isnoice detection
    uint8_t bits[GraphTraceLen];
    size_t size = getFromGraphBuf(bits);
    // set signal properties low/high/mean/amplitude and is_noice detection
    computeSignalProperties(bits, size);

    RepaintGraphWindow();
    return PM3_SUCCESS;
}

static int CmdZerocrossings(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    // Zero-crossings aren't meaningful unless the signal is zero-mean.
    CmdHpf("");

    int sign = 1, zc = 0, lastZc = 0;

    for (uint32_t i = 0; i < GraphTraceLen; ++i) {
        if (GraphBuffer[i] * sign >= 0) {
            // No change in sign, reproduce the previous sample count.
            zc++;
            GraphBuffer[i] = lastZc;
        } else {
            // Change in sign, reset the sample count.
            sign = -sign;
            GraphBuffer[i] = lastZc;
            if (sign > 0) {
                lastZc = zc;
                zc = 0;
            }
        }
    }

    uint8_t bits[GraphTraceLen];
    size_t size = getFromGraphBuf(bits);
    // set signal properties low/high/mean/amplitude and is_noise detection
    computeSignalProperties(bits, size);

    RepaintGraphWindow();
    return PM3_SUCCESS;
}

/**
 * @brief Utility for conversion via cmdline.
 * @param Cmd
 * @return
 */
static int Cmdbin2hex(const char *Cmd) {
    int bg = 0, en = 0;
    if (param_getptr(Cmd, &bg, &en, 0))
        return usage_data_bin2hex();

    //Number of digits supplied as argument
    size_t length = en - bg + 1;
    size_t bytelen = (length + 7) / 8;
    uint8_t *arr = (uint8_t *) calloc(bytelen, sizeof(uint8_t));
    memset(arr, 0, bytelen);
    BitstreamOut bout = { arr, 0, 0 };

    for (; bg <= en; bg++) {
        char c = Cmd[bg];
        if (c == '1')
            pushBit(&bout, 1);
        else if (c == '0')
            pushBit(&bout, 0);
        else
            PrintAndLogEx(NORMAL, "Ignoring '%c'", c);
    }

    if (bout.numbits % 8 != 0)
        PrintAndLogEx(NORMAL, "[padded with %d zeroes]", 8 - (bout.numbits % 8));

    PrintAndLogEx(NORMAL, "%s", sprint_hex(arr, bytelen));
    free(arr);
    return PM3_SUCCESS;
}

static int Cmdhex2bin(const char *Cmd) {
    int bg = 0, en = 0;
    if (param_getptr(Cmd, &bg, &en, 0)) return usage_data_hex2bin();

    while (bg <= en) {
        char x = Cmd[bg++];
        // capitalize
        if (x >= 'a' && x <= 'f')
            x -= 32;
        // convert to numeric value
        if (x >= '0' && x <= '9')
            x -= '0';
        else if (x >= 'A' && x <= 'F')
            x -= 'A' - 10;
        else
            continue;

        for (int i = 0 ; i < 4 ; ++i)
            PrintAndLogEx(NORMAL, "%d" NOLF, (x >> (3 - i)) & 1);
    }
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
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
    // take clk, fc_low, fc_high
    //   blank = auto;
    bool errors = false;
    char cmdp = 0;
    int  clk = 0, fc_low = 10, fc_high = 8;
    while (param_getchar(Cmd, cmdp) != 0x00) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_data_fsktonrz();
            case 'c':
                clk = param_get32ex(Cmd, cmdp + 1, 0, 10);
                cmdp += 2;
                break;
            case 'f':
                fc_high = param_get32ex(Cmd, cmdp + 1, 0, 10);
                cmdp += 2;
                break;
            case 'l':
                fc_low = param_get32ex(Cmd, cmdp + 1, 0, 10);
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
        if (errors) break;
    }
    //Validations
    if (errors) return usage_data_fsktonrz();

    setClockGrid(0, 0);
    DemodBufferLen = 0;
    int ans = FSKToNRZ(GraphBuffer, &GraphTraceLen, clk, fc_low, fc_high);
    CmdNorm("");
    RepaintGraphWindow();
    return ans;
}

static int CmdDataIIR(const char *Cmd) {
    uint8_t k = param_get8(Cmd, 0);
    //iceIIR_Butterworth(GraphBuffer, GraphTraceLen);
    iceSimple_Filter(GraphBuffer, GraphTraceLen, k);

    uint8_t bits[GraphTraceLen];
    size_t size = getFromGraphBuf(bits);
    // set signal properties low/high/mean/amplitude and is_noise detection
    computeSignalProperties(bits, size);
    RepaintGraphWindow();
    return PM3_SUCCESS;
}

static int CmdDataNDEF(const char *Cmd) {

#ifndef MAX_NDEF_LEN
#define MAX_NDEF_LEN  2048
#endif

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "data ndef",
                  "Decode and print NFC Data Exchange Format (NDEF)",
                  "data ndef -d 9101085402656e48656c6c6f5101085402656e576f726c64\n"
                  "data ndef -d 0103d020240203e02c040300fe\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_strx0("d",  "data", "<hex>", "NDEF data to decode"),
        arg_lit0("v",  "verbose", "verbose mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int datalen = 0;
    uint8_t data[MAX_NDEF_LEN] = {0};
    CLIGetHexWithReturn(ctx, 1, data, &datalen);
    bool verbose = arg_get_lit(ctx, 2);

    CLIParserFree(ctx);
    if (datalen == 0)
        return PM3_EINVARG;

    int res = NDEFDecodeAndPrint(data, datalen, verbose);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(INFO, "Trying to parse NDEF records w/o NDEF header");
        res = NDEFRecordsDecodeAndPrint(data, datalen);
    }
    return res;
}

typedef struct {
    t55xx_modulation modulation;
    int bitrate;
    int carrier;
    uint8_t fc1;
    uint8_t fc2;
} lf_modulation_t;

static int print_modulation(lf_modulation_t b) {
    PrintAndLogEx(INFO, " Modulation.... " _GREEN_("%s"), GetSelectedModulationStr(b.modulation));
    PrintAndLogEx(INFO, " Bit clock..... " _GREEN_("RF/%d"), b.bitrate);
    switch (b.modulation) {
        case DEMOD_PSK1:
        case DEMOD_PSK2:
        case DEMOD_PSK3:
            PrintAndLogEx(SUCCESS, " Carrier rate.. %d", b.carrier);
            break;
        case DEMOD_FSK:
        case DEMOD_FSK1:
        case DEMOD_FSK1a:
        case DEMOD_FSK2:
        case DEMOD_FSK2a:
            PrintAndLogEx(SUCCESS, " Field Clocks.. FC/%u, FC/%u", b.fc1, b.fc2);
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

    lf_modulation_t tests[6];
    int clk = 0, firstClockEdge = 0;
    uint8_t hits = 0, ans = 0;
    uint8_t fc1 = 0, fc2 = 0;
    bool st = false;

    ans = fskClocks(&fc1, &fc2, (uint8_t *)&clk, &firstClockEdge);

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
            save_restoreGB(GRAPH_SAVE);
            // skip first 160 samples to allow antenna to settle in (psk gets inverted occasionally otherwise)
            CmdLtrim("160");
            if ((PSKDemod(0, 0, 6, false) == PM3_SUCCESS)) {
                tests[hits].modulation = DEMOD_PSK1;
                tests[hits].bitrate = clk;
                ++hits;

                // get psk carrier
                tests[hits].carrier = GetPskCarrier(false);
            }
            //undo trim samples
            save_restoreGB(GRAPH_RESTORE);
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

static command_t CommandTable[] = {
    {"help",            CmdHelp,                 AlwaysAvailable,  "This help"},

    {"-----------",     CmdHelp,                 AlwaysAvailable, "------------------------- " _CYAN_("Modulation") "-------------------------"},
    {"biphaserawdecode", CmdBiphaseDecodeRaw,    AlwaysAvailable,  "Biphase decode bin stream in DemodBuffer"},
    {"detectclock",     CmdDetectClockRate,      AlwaysAvailable,  "Detect ASK, FSK, NRZ, PSK clock rate of wave in GraphBuffer"},
    {"fsktonrz",        CmdFSKToNRZ,             AlwaysAvailable,  "Convert fsk2 to nrz wave for alternate fsk demodulating (for weak fsk)"},
    {"manrawdecode",    Cmdmandecoderaw,         AlwaysAvailable,  "Manchester decode binary stream in DemodBuffer"},
    {"modulation",      CmdDataModulationSearch, AlwaysAvailable,  "Identify LF signal for clock and modulation"},
    {"rawdemod",        CmdRawDemod,             AlwaysAvailable,  "Demodulate the data in the GraphBuffer and output binary"},

    {"-----------",     CmdHelp,                 AlwaysAvailable, "------------------------- " _CYAN_("Graph") "-------------------------"},
    {"askedgedetect",   CmdAskEdgeDetect,        AlwaysAvailable,  "[threshold] Adjust Graph for manual ASK demod using the length of sample differences to detect the edge of a wave (use 20-45, def:25)"},
    {"autocorr",        CmdAutoCorr,             AlwaysAvailable,  "Autocorrelation over window"},
    {"dirthreshold",    CmdDirectionalThreshold, AlwaysAvailable,  "<thres up> <thres down> -- Max rising higher up-thres/ Min falling lower down-thres, keep rest as prev."},
    {"decimate",        CmdDecimate,             AlwaysAvailable,  "Decimate samples"},
    {"undecimate",      CmdUndecimate,           AlwaysAvailable,  "Un-decimate samples"},
    {"hide",            CmdHide,                 AlwaysAvailable,  "Hide graph window"},
    {"hpf",             CmdHpf,                  AlwaysAvailable,  "Remove DC offset from trace"},
    {"iir",             CmdDataIIR,              AlwaysAvailable,  "apply IIR buttersworth filter on plotdata"},
    {"grid",            CmdGrid,                 AlwaysAvailable,  "<x> <y> -- overlay grid on graph window, use zero value to turn off either"},
    {"ltrim",           CmdLtrim,                AlwaysAvailable,  "<samples> -- Trim samples from left of trace"},
    {"mtrim",           CmdMtrim,                AlwaysAvailable,  "<start> <stop> -- Trim out samples from the specified start to the specified stop"},
    {"norm",            CmdNorm,                 AlwaysAvailable,  "Normalize max/min to +/-128"},
    {"plot",            CmdPlot,                 AlwaysAvailable,  "Show graph window (hit 'h' in window for keystroke help)"},
    {"rtrim",           CmdRtrim,                AlwaysAvailable,  "<location to end trace> -- Trim samples from right of trace"},
    {"setgraphmarkers", CmdSetGraphMarkers,      AlwaysAvailable,  "[orange_marker] [blue_marker] (in graph window)"},
    {"shiftgraphzero",  CmdGraphShiftZero,       AlwaysAvailable,  "<shift> -- Shift 0 for Graphed wave + or - shift value"},
    {"timescale",       CmdTimeScale,            AlwaysAvailable,  "Set a timescale to get a differential reading between the yellow and purple markers as time duration\n"},
    {"zerocrossings",   CmdZerocrossings,        AlwaysAvailable,  "Count time between zero-crossings"},

    {"convertbitstream", CmdConvertBitStream,    AlwaysAvailable,  "Convert GraphBuffer's 0/1 values to 127 / -127"},
    {"getbitstream",    CmdGetBitStream,         AlwaysAvailable,  "Convert GraphBuffer's >=1 values to 1 and <1 to 0"},


    {"-----------",     CmdHelp,                 AlwaysAvailable, "------------------------- " _CYAN_("General") "-------------------------"},
    {"bin2hex",         Cmdbin2hex,              AlwaysAvailable,  "Converts binary to hexadecimal"},
    {"bitsamples",      CmdBitsamples,           IfPm3Present,     "Get raw samples as bitstring"},
    {"clear",           CmdBuffClear,            AlwaysAvailable,  "Clears bigbuf on deviceside and graph window"},
    {"hexsamples",      CmdHexsamples,           IfPm3Present,     "<bytes> [<offset>] -- Dump big buffer as hex bytes"},
    {"hex2bin",         Cmdhex2bin,              AlwaysAvailable,  "Converts hexadecimal to binary"},
    {"load",            CmdLoad,                 AlwaysAvailable,  "Load contents of file into graph window"},
    {"ndef",            CmdDataNDEF,             AlwaysAvailable,  "Decode NDEF records"},
    {"print",           CmdPrintDemodBuff,       AlwaysAvailable,  "print the data in the DemodBuffer"},
    {"samples",         CmdSamples,              IfPm3Present,     "[512 - 40000] -- Get raw samples for graph window (GraphBuffer)"},
    {"save",            CmdSave,                 AlwaysAvailable,  "Save signal trace data  (from graph window)"},
    {"setdebugmode",    CmdSetDebugMode,         AlwaysAvailable,  "<0|1|2> -- Set Debugging Level on client side"},
    {"tune",            CmdTuneSamples,          IfPm3Present,     "Measure tuning of device antenna. Results shown in graph window"},
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

