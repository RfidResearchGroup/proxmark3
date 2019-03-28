//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Data and Graph commands
//-----------------------------------------------------------------------------
#include "cmddata.h"

uint8_t DemodBuffer[MAX_DEMOD_BUF_LEN];
//uint8_t g_debugMode = 0;
size_t DemodBufferLen = 0;
size_t g_DemodStartIdx = 0;
int g_DemodClock = 0;

static int CmdHelp(const char *Cmd);

int usage_data_printdemodbuf(void) {
    PrintAndLogEx(NORMAL, "Usage: data printdemodbuffer x o <offset> l <length>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h          This help");
    PrintAndLogEx(NORMAL, "       x          output in hex (omit for binary output)");
    PrintAndLogEx(NORMAL, "       o <offset> enter offset in # of bits");
    PrintAndLogEx(NORMAL, "       l <length> enter length to print in # of bits or hex characters respectively");
    return 0;
}
int usage_data_manrawdecode(void) {
    PrintAndLogEx(NORMAL, "Usage:  data manrawdecode [invert] [maxErr]");
    PrintAndLogEx(NORMAL, "     Takes 10 and 01 and converts to 0 and 1 respectively");
    PrintAndLogEx(NORMAL, "     --must have binary sequence in demodbuffer (run data askrawdemod first)");
    PrintAndLogEx(NORMAL, "  [invert]  invert output");
    PrintAndLogEx(NORMAL, "  [maxErr]  set number of errors allowed (default = 20)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "   Example: data manrawdecode   = decode manchester bitstream from the demodbuffer");
    return 0;
}
int usage_data_biphaserawdecode(void) {
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
    return 0;
}
int usage_data_rawdemod(void) {
    PrintAndLogEx(NORMAL, "Usage:  data rawdemod [modulation] <help>|<options>");
    PrintAndLogEx(NORMAL, "   [modulation] as 2 char, 'ab' for ask/biphase, 'am' for ask/manchester, 'ar' for ask/raw, 'fs' for fsk, ...");
    PrintAndLogEx(NORMAL, "         'nr' for nrz/direct, 'p1' for psk1, 'p2' for psk2");
    PrintAndLogEx(NORMAL, "   <help> as 'h', prints the help for the specific modulation");
    PrintAndLogEx(NORMAL, "   <options> see specific modulation help for optional parameters");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "   Example: data rawdemod fs h         = print help specific to fsk demod");
    PrintAndLogEx(NORMAL, "          : data rawdemod fs           = demod GraphBuffer using: fsk - autodetect");
    PrintAndLogEx(NORMAL, "          : data rawdemod ab           = demod GraphBuffer using: ask/biphase - autodetect");
    PrintAndLogEx(NORMAL, "          : data rawdemod am           = demod GraphBuffer using: ask/manchester - autodetect");
    PrintAndLogEx(NORMAL, "          : data rawdemod ar           = demod GraphBuffer using: ask/raw - autodetect");
    PrintAndLogEx(NORMAL, "          : data rawdemod nr           = demod GraphBuffer using: nrz/direct - autodetect");
    PrintAndLogEx(NORMAL, "          : data rawdemod p1           = demod GraphBuffer using: psk1 - autodetect");
    PrintAndLogEx(NORMAL, "          : data rawdemod p2           = demod GraphBuffer using: psk2 - autodetect");
    return 0;
}
int usage_data_rawdemod_am(void) {
    PrintAndLogEx(NORMAL, "Usage:  data rawdemod am <s> [clock] <invert> [maxError] [maxLen] [amplify]");
    PrintAndLogEx(NORMAL, "     ['s'] optional, check for Sequence Terminator");
    PrintAndLogEx(NORMAL, "     [set clock as integer] optional, if not set, autodetect");
    PrintAndLogEx(NORMAL, "     <invert>, 1 to invert output");
    PrintAndLogEx(NORMAL, "     [set maximum allowed errors], default = 100");
    PrintAndLogEx(NORMAL, "     [set maximum Samples to read], default = 32768 (512 bits at rf/64)");
    PrintAndLogEx(NORMAL, "     <amplify>, 'a' to attempt demod with ask amplification, default = no amp");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "   Example: data rawdemod am        = demod an ask/manchester tag from GraphBuffer");
    PrintAndLogEx(NORMAL, "          : data rawdemod am 32     = demod an ask/manchester tag from GraphBuffer using a clock of RF/32");
    PrintAndLogEx(NORMAL, "          : data rawdemod am 32 1   = demod an ask/manchester tag from GraphBuffer using a clock of RF/32 and inverting data");
    PrintAndLogEx(NORMAL, "          : data rawdemod am 1      = demod an ask/manchester tag from GraphBuffer while inverting data");
    PrintAndLogEx(NORMAL, "          : data rawdemod am 64 1 0 = demod an ask/manchester tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors");
    return 0;
}
int usage_data_rawdemod_ab(void) {
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
    PrintAndLogEx(NORMAL, "   Example: data rawdemod ab              = demod an ask/biph tag from GraphBuffer");
    PrintAndLogEx(NORMAL, "          : data rawdemod ab 0 a          = demod an ask/biph tag from GraphBuffer, amplified");
    PrintAndLogEx(NORMAL, "          : data rawdemod ab 1 32         = demod an ask/biph tag from GraphBuffer using an offset of 1 and a clock of RF/32");
    PrintAndLogEx(NORMAL, "          : data rawdemod ab 0 32 1       = demod an ask/biph tag from GraphBuffer using a clock of RF/32 and inverting data");
    PrintAndLogEx(NORMAL, "          : data rawdemod ab 0 1          = demod an ask/biph tag from GraphBuffer while inverting data");
    PrintAndLogEx(NORMAL, "          : data rawdemod ab 0 64 1 0     = demod an ask/biph tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors");
    PrintAndLogEx(NORMAL, "          : data rawdemod ab 0 64 1 0 0 a = demod an ask/biph tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors, and amp");
    return 0;
}
int usage_data_rawdemod_ar(void) {
    PrintAndLogEx(NORMAL, "Usage:  data rawdemod ar [clock] <invert> [maxError] [maxLen] [amplify]");
    PrintAndLogEx(NORMAL, "     [set clock as integer] optional, if not set, autodetect");
    PrintAndLogEx(NORMAL, "     <invert>, 1 to invert output");
    PrintAndLogEx(NORMAL, "     [set maximum allowed errors], default = 100");
    PrintAndLogEx(NORMAL, "     [set maximum Samples to read], default = 32768 (1024 bits at rf/64)");
    PrintAndLogEx(NORMAL, "     <amplify>, 'a' to attempt demod with ask amplification, default = no amp");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "   Example: data rawdemod ar            = demod an ask tag from GraphBuffer");
    PrintAndLogEx(NORMAL, "          : data rawdemod ar a          = demod an ask tag from GraphBuffer, amplified");
    PrintAndLogEx(NORMAL, "          : data rawdemod ar 32         = demod an ask tag from GraphBuffer using a clock of RF/32");
    PrintAndLogEx(NORMAL, "          : data rawdemod ar 32 1       = demod an ask tag from GraphBuffer using a clock of RF/32 and inverting data");
    PrintAndLogEx(NORMAL, "          : data rawdemod ar 1          = demod an ask tag from GraphBuffer while inverting data");
    PrintAndLogEx(NORMAL, "          : data rawdemod ar 64 1 0     = demod an ask tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors");
    PrintAndLogEx(NORMAL, "          : data rawdemod ar 64 1 0 0 a = demod an ask tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors, and amp");
    return 0;
}
int usage_data_rawdemod_fs(void) {
    PrintAndLogEx(NORMAL, "Usage:  data rawdemod fs [clock] <invert> [fchigh] [fclow]");
    PrintAndLogEx(NORMAL, "     [set clock as integer] optional, omit for autodetect.");
    PrintAndLogEx(NORMAL, "     <invert>, 1 for invert output, can be used even if the clock is omitted");
    PrintAndLogEx(NORMAL, "     [fchigh], larger field clock length, omit for autodetect");
    PrintAndLogEx(NORMAL, "     [fclow], small field clock length, omit for autodetect");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "   Example: data rawdemod fs           = demod an fsk tag from GraphBuffer using autodetect");
    PrintAndLogEx(NORMAL, "          : data rawdemod fs 32        = demod an fsk tag from GraphBuffer using a clock of RF/32, autodetect fc");
    PrintAndLogEx(NORMAL, "          : data rawdemod fs 1         = demod an fsk tag from GraphBuffer using autodetect, invert output");
    PrintAndLogEx(NORMAL, "          : data rawdemod fs 32 1      = demod an fsk tag from GraphBuffer using a clock of RF/32, invert output, autodetect fc");
    PrintAndLogEx(NORMAL, "          : data rawdemod fs 64 0 8 5  = demod an fsk1 RF/64 tag from GraphBuffer");
    PrintAndLogEx(NORMAL, "          : data rawdemod fs 50 0 10 8 = demod an fsk2 RF/50 tag from GraphBuffer");
    PrintAndLogEx(NORMAL, "          : data rawdemod fs 50 1 10 8 = demod an fsk2a RF/50 tag from GraphBuffer");
    return 0;
}
int usage_data_rawdemod_nr(void) {
    PrintAndLogEx(NORMAL, "Usage:  data rawdemod nr [clock] <0|1> [maxError]");
    PrintAndLogEx(NORMAL, "     [set clock as integer] optional, if not set, autodetect.");
    PrintAndLogEx(NORMAL, "     <invert>, 1 for invert output");
    PrintAndLogEx(NORMAL, "     [set maximum allowed errors], default = 100.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "   Example: data rawdemod nr        = demod a nrz/direct tag from GraphBuffer");
    PrintAndLogEx(NORMAL, "          : data rawdemod nr 32     = demod a nrz/direct tag from GraphBuffer using a clock of RF/32");
    PrintAndLogEx(NORMAL, "          : data rawdemod nr 32 1   = demod a nrz/direct tag from GraphBuffer using a clock of RF/32 and inverting data");
    PrintAndLogEx(NORMAL, "          : data rawdemod nr 1      = demod a nrz/direct tag from GraphBuffer while inverting data");
    PrintAndLogEx(NORMAL, "          : data rawdemod nr 64 1 0 = demod a nrz/direct tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors");
    return 0;
}
int usage_data_rawdemod_p1(void) {
    PrintAndLogEx(NORMAL, "Usage:  data rawdemod p1 [clock] <0|1> [maxError]");
    PrintAndLogEx(NORMAL, "     [set clock as integer] optional, if not set, autodetect.");
    PrintAndLogEx(NORMAL, "     <invert>, 1 for invert output");
    PrintAndLogEx(NORMAL, "     [set maximum allowed errors], default = 100.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "   Example: data rawdemod p1        = demod a psk1 tag from GraphBuffer");
    PrintAndLogEx(NORMAL, "          : data rawdemod p1 32     = demod a psk1 tag from GraphBuffer using a clock of RF/32");
    PrintAndLogEx(NORMAL, "          : data rawdemod p1 32 1   = demod a psk1 tag from GraphBuffer using a clock of RF/32 and inverting data");
    PrintAndLogEx(NORMAL, "          : data rawdemod p1 1      = demod a psk1 tag from GraphBuffer while inverting data");
    PrintAndLogEx(NORMAL, "          : data rawdemod p1 64 1 0 = demod a psk1 tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors");
    return 0;
}
int usage_data_rawdemod_p2(void) {
    PrintAndLogEx(NORMAL, "Usage:  data rawdemod p2 [clock] <0|1> [maxError]");
    PrintAndLogEx(NORMAL, "     [set clock as integer] optional, if not set, autodetect.");
    PrintAndLogEx(NORMAL, "     <invert>, 1 for invert output");
    PrintAndLogEx(NORMAL, "     [set maximum allowed errors], default = 100.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "   Example: data rawdemod p2         = demod a psk2 tag from GraphBuffer, autodetect clock");
    PrintAndLogEx(NORMAL, "          : data rawdemod p2 32      = demod a psk2 tag from GraphBuffer using a clock of RF/32");
    PrintAndLogEx(NORMAL, "          : data rawdemod p2 32 1    = demod a psk2 tag from GraphBuffer using a clock of RF/32 and inverting output");
    PrintAndLogEx(NORMAL, "          : data rawdemod p2 1       = demod a psk2 tag from GraphBuffer, autodetect clock and invert output");
    PrintAndLogEx(NORMAL, "          : data rawdemod p2 64 1 0  = demod a psk2 tag from GraphBuffer using a clock of RF/64, inverting output and allowing 0 demod errors");
    return 0;
}
int usage_data_autocorr(void) {
    PrintAndLogEx(NORMAL, "Autocorrelate is used to detect repeating sequences. We use it as detection of length in bits a message inside the signal is");
    PrintAndLogEx(NORMAL, "Usage: data autocorr w <window> [g]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h              This help");
    PrintAndLogEx(NORMAL, "       w <window>     window length for correlation - default = 4000");
    PrintAndLogEx(NORMAL, "       g              save back to GraphBuffer (overwrite)");
    return 0;
}
int usage_data_undecimate(void) {
    PrintAndLogEx(NORMAL, "Usage: data undec [factor]");
    PrintAndLogEx(NORMAL, "This function performs un-decimation, by repeating each sample N times");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h            This help");
    PrintAndLogEx(NORMAL, "       factor       The number of times to repeat each sample.[default:2]");
    PrintAndLogEx(NORMAL, "Example: 'data undec 3'");
    return 0;
}
int usage_data_detectclock(void) {
    PrintAndLogEx(NORMAL, "Usage:  data detectclock [modulation] <clock>");
    PrintAndLogEx(NORMAL, "     [modulation as char], specify the modulation type you want to detect the clock of");
    PrintAndLogEx(NORMAL, "     <clock>             , specify the clock (optional - to get best start position only)");
    PrintAndLogEx(NORMAL, "       'a' = ask, 'f' = fsk, 'n' = nrz/direct, 'p' = psk");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "   Example: data detectclock a    = detect the clock of an ask modulated wave in the GraphBuffer");
    PrintAndLogEx(NORMAL, "            data detectclock f    = detect the clock of an fsk modulated wave in the GraphBuffer");
    PrintAndLogEx(NORMAL, "            data detectclock p    = detect the clock of an psk modulated wave in the GraphBuffer");
    PrintAndLogEx(NORMAL, "            data detectclock n    = detect the clock of an nrz/direct modulated wave in the GraphBuffer");
    return 0;
}
int usage_data_hex2bin(void) {
    PrintAndLogEx(NORMAL, "Usage: data hex2bin <hex_digits>");
    PrintAndLogEx(NORMAL, "       This function will ignore all non-hexadecimal characters (but stop reading on whitespace)");
    return 0;
}
int usage_data_bin2hex(void) {
    PrintAndLogEx(NORMAL, "Usage: data bin2hex <binary_digits>");
    PrintAndLogEx(NORMAL, "       This function will ignore all characters not 1 or 0 (but stop reading on whitespace)");
    return 0;
}
int usage_data_buffclear(void) {
    PrintAndLogEx(NORMAL, "This function clears the bigbuff on deviceside");
    PrintAndLogEx(NORMAL, "Usage: data buffclear [h]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h              This help");
    return 0;
}
int usage_data_fsktonrz() {
    PrintAndLogEx(NORMAL, "Usage: data fsktonrz c <clock> l <fc_low> f <fc_high>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h            This help");
    PrintAndLogEx(NORMAL, "       c <clock>    enter the a clock (omit to autodetect)");
    PrintAndLogEx(NORMAL, "       l <fc_low>   enter a field clock (omit to autodetect)");
    PrintAndLogEx(NORMAL, "       f <fc_high>  enter a field clock (omit to autodetect)");
    return 0;
}

//set the demod buffer with given array of binary (one bit per byte)
//by marshmellow
void setDemodBuf(uint8_t *buf, size_t size, size_t start_idx) {
    if (buf == NULL) return;

    if (size > MAX_DEMOD_BUF_LEN - start_idx)
        size = MAX_DEMOD_BUF_LEN - start_idx;

    for (size_t i = 0; i < size; i++)
        DemodBuffer[i] = buf[start_idx++];

    DemodBufferLen = size;
}

bool getDemodBuf(uint8_t *buf, size_t *size) {
    if (buf == NULL) return false;
    if (size == NULL) return false;
    if (*size == 0) return false;

    *size = (*size > DemodBufferLen) ? DemodBufferLen : *size;

    memcpy(buf, DemodBuffer, *size);
    return true;
}

// include <math.h>
// Root mean square
double rms(double *v, size_t n) {
    double sum = 0.0;
    for (size_t i = 0; i < n; i++)
        sum += v[i] * v[i];
    return sqrt(sum / n);
}
int cmp_int(const void *a, const void *b) {
    if (*(const int *)a < * (const int *)b)
        return -1;
    else
        return *(const int *)a > *(const int *)b;
}
int cmp_uint8(const void *a, const void *b) {
    if (*(const uint8_t *)a < * (const uint8_t *)b)
        return -1;
    else
        return *(const uint8_t *)a > *(const uint8_t *)b;
}
// Median of a array of values
double median_int(int *src, size_t size) {
    qsort(src, size, sizeof(int), cmp_int);
    return 0.5 * (src[size / 2] + src[(size - 1) / 2]);
}
double median_uint8(uint8_t *src, size_t size) {
    qsort(src, size, sizeof(uint8_t), cmp_uint8);
    return 0.5 * (src[size / 2] + src[(size - 1) / 2]);
}
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

int CmdSetDebugMode(const char *Cmd) {
    int demod = 0;
    sscanf(Cmd, "%i", &demod);
    g_debugMode = (uint8_t)demod;
    return 1;
}

//by marshmellow
// max output to 512 bits if we have more
// doesn't take inconsideration where the demod offset or bitlen found.
void printDemodBuff(void) {
    int len = DemodBufferLen;
    if (len < 1) {
        PrintAndLogEx(NORMAL, "(printDemodBuff) no bits found in demod buffer");
        return;
    }
    if (len > 512) len = 512;

    PrintAndLogEx(NORMAL, "%s", sprint_bin_break(DemodBuffer, len, 32));
}

int CmdPrintDemodBuff(const char *Cmd) {
    char hex[512] = {0x00};
    bool hexMode = false;
    bool errors = false;
    uint32_t offset = 0;
    uint32_t length = 512;
    char cmdp = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_data_printdemodbuf();
            case 'x':
                hexMode = true;
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
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    //Validations
    if (errors) return usage_data_printdemodbuf();

    if (DemodBufferLen == 0) {
        PrintAndLogEx(NORMAL, "Demodbuffer is empty");
        return 0;
    }
    length = (length > (DemodBufferLen - offset)) ? DemodBufferLen - offset : length;

    if (hexMode) {
        char *buf = (char *)(DemodBuffer + offset);
        int numBits = binarraytohex(hex, sizeof(hex), buf, length);
        if (numBits == 0) {
            return 0;
        }
        PrintAndLogEx(NORMAL, "DemodBuffer: %s", hex);
    } else {
        PrintAndLogEx(NORMAL, "DemodBuffer:\n%s", sprint_bin_break(DemodBuffer + offset, length, 32));
    }
    return 1;
}

//by marshmellow
//this function strictly converts >1 to 1 and <1 to 0 for each sample in the graphbuffer
int CmdGetBitStream(const char *Cmd) {
    CmdHpf(Cmd);
    for (uint32_t i = 0; i < GraphTraceLen; i++)
        GraphBuffer[i] = (GraphBuffer[i] >= 1) ? 1 : 0;

    RepaintGraphWindow();
    return 0;
}

//by marshmellow
//Cmd Args: Clock, invert, maxErr, maxLen as integers and amplify as char == 'a'
//   (amp may not be needed anymore)
//verbose will print results and demoding messages
//emSearch will auto search for EM410x format in bitstream
//askType switches decode: ask/raw = 0, ask/manchester = 1
int ASKDemod_ext(const char *Cmd, bool verbose, bool emSearch, uint8_t askType, bool *stCheck) {
    int invert = 0;
    int clk = 0;
    int maxErr = 100;
    int maxLen = 0;
    uint8_t askamp = 0;
    char amp = tolower(param_getchar(Cmd, 0));
    uint8_t bits[MAX_GRAPH_TRACE_LEN] = {0};

    sscanf(Cmd, "%i %i %i %i %c", &clk, &invert, &maxErr, &maxLen, &amp);

    if (!maxLen) maxLen = BIGBUF_SIZE;

    if (invert != 0 && invert != 1) {
        PrintAndLogEx(WARNING, "Invalid argument: %s", Cmd);
        return 0;
    }

    if (clk == 1) {
        invert = 1;
        clk = 0;
    }

    size_t BitLen = getFromGraphBuf(bits);

    PrintAndLogEx(DEBUG, "DEBUG: (ASKDemod_ext) #samples from graphbuff: %d", BitLen);

    if (BitLen < 255) return 0;

    if (maxLen < BitLen && maxLen != 0) BitLen = maxLen;

    int foundclk = 0;

    //amplify signal before ST check
    if (amp == 'a') {
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
        PrintAndLogEx(DEBUG, "DEBUG: (ASKDemod_ext) No data found errors:%d, invert:%c, bitlen:%d, clock:%d", errCnt, (invert) ? 'Y' : 'N', BitLen, clk);
        return 0;
    }

    if (errCnt > maxErr) {
        PrintAndLogEx(DEBUG, "DEBUG: (ASKDemod_ext) Too many errors found, errors:%d, bits:%d, clock:%d", errCnt, BitLen, clk);
        return 0;
    }

    if (verbose) PrintAndLogEx(DEBUG, "DEBUG: (ASKDemod_ext) Using clock:%d, invert:%d, bits found:%d", clk, invert, BitLen);

    //output
    setDemodBuf(bits, BitLen, 0);
    setClockGrid(clk, startIdx);

    if (verbose) {
        if (errCnt > 0)
            PrintAndLogEx(DEBUG, "# Errors during Demoding (shown as 7 in bit stream): %d", errCnt);
        if (askType)
            PrintAndLogEx(DEBUG, "ASK/Manchester - Clock: %d - Decoded bitstream:", clk);
        else
            PrintAndLogEx(DEBUG, "ASK/Raw - Clock: %d - Decoded bitstream:", clk);

        printDemodBuff();
    }
    uint64_t lo = 0;
    uint32_t hi = 0;
    if (emSearch)
        AskEm410xDecode(true, &hi, &lo);

    return 1;
}
int ASKDemod(const char *Cmd, bool verbose, bool emSearch, uint8_t askType) {
    bool st = false;
    return ASKDemod_ext(Cmd, verbose, emSearch, askType, &st);
}

//by marshmellow
//takes 5 arguments - clock, invert, maxErr, maxLen as integers and amplify as char == 'a'
//attempts to demodulate ask while decoding manchester
//prints binary found and saves in graphbuffer for further commands
int Cmdaskmandemod(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) > 45 || cmdp == 'h') return usage_data_rawdemod_am();

    bool st = true;
    if (Cmd[0] == 's')
        return ASKDemod_ext(Cmd++, true, true, 1, &st);
    else if (Cmd[1] == 's')
        return ASKDemod_ext(Cmd += 2, true, true, 1, &st);

    return ASKDemod(Cmd, true, true, 1);
}

//by marshmellow
//manchester decode
//stricktly take 10 and 01 and convert to 0 and 1
int Cmdmandecoderaw(const char *Cmd) {
    size_t size = 0;
    int high = 0, low = 0;
    int i = 0, errCnt = 0, invert = 0, maxErr = 20;
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) > 5 || cmdp == 'h') return usage_data_manrawdecode();

    if (DemodBufferLen == 0) return 0;

    uint8_t bits[MAX_DEMOD_BUF_LEN] = {0};

    for (; i < DemodBufferLen; ++i) {
        if (DemodBuffer[i] > high)
            high = DemodBuffer[i];
        else if (DemodBuffer[i] < low)
            low = DemodBuffer[i];
        bits[i] = DemodBuffer[i];
    }

    if (high > 7 || low < 0) {
        PrintAndLogEx(WARNING, "Error: please raw demod the wave first then manchester raw decode");
        return 0;
    }

    sscanf(Cmd, "%i %i", &invert, &maxErr);
    size = i;
    uint8_t alignPos = 0;
    errCnt = manrawdecode(bits, &size, invert, &alignPos);
    if (errCnt >= maxErr) {
        PrintAndLogEx(WARNING, "Too many errors: %d", errCnt);
        return 0;
    }

    PrintAndLogEx(NORMAL, "Manchester Decoded - # errors:%d - data:", errCnt);
    PrintAndLogEx(NORMAL, "%s", sprint_bin_break(bits, size, 32));

    if (errCnt == 0) {
        uint64_t id = 0;
        uint32_t hi = 0;
        size_t idx = 0;
        if (Em410xDecode(bits, &size, &idx, &hi, &id) == 1) {
            //need to adjust to set bitstream back to manchester encoded data
            //setDemodBuf(bits, size, idx);
            printEM410x(hi, id);
        }
    }
    return 1;
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
int CmdBiphaseDecodeRaw(const char *Cmd) {
    size_t size = 0;
    int offset = 0, invert = 0, maxErr = 20, errCnt = 0;
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) > 5 || cmdp == 'h') return usage_data_biphaserawdecode();

    sscanf(Cmd, "%i %i %i", &offset, &invert, &maxErr);
    if (DemodBufferLen == 0) {
        PrintAndLogEx(WARNING, "DemodBuffer Empty - run " _YELLOW_("'data rawdemod ar'")" first");
        return 0;
    }

    uint8_t bits[MAX_DEMOD_BUF_LEN] = {0};
    size = sizeof(bits);
    if (!getDemodBuf(bits, &size)) return 0;

    errCnt = BiphaseRawDecode(bits, &size, &offset, invert);
    if (errCnt < 0) {
        PrintAndLogEx(WARNING, "Error during decode:%d", errCnt);
        return 0;
    }
    if (errCnt > maxErr) {
        PrintAndLogEx(WARNING, "Too many errors attempting to decode: %d", errCnt);
        return 0;
    }

    if (errCnt > 0)
        PrintAndLogEx(WARNING, "# Errors found during Demod (shown as " _YELLOW_("7")" in bit stream): %d", errCnt);

    PrintAndLogEx(NORMAL, "Biphase Decoded using offset: %d - # invert:%d - data:", offset, invert);
    PrintAndLogEx(NORMAL, "%s", sprint_bin_break(bits, size, 32));

    //remove first bit from raw demod
    if (offset)
        setDemodBuf(DemodBuffer, DemodBufferLen - offset, offset);

    setClockGrid(g_DemodClock, g_DemodStartIdx + g_DemodClock * offset / 2);
    return 1;
}

//by marshmellow
// - ASK Demod then Biphase decode GraphBuffer samples
int ASKbiphaseDemod(const char *Cmd, bool verbose) {
    //ask raw demod GraphBuffer first
    int offset = 0, clk = 0, invert = 0, maxErr = 100;
    sscanf(Cmd, "%i %i %i %i", &offset, &clk, &invert, &maxErr);

    uint8_t BitStream[MAX_DEMOD_BUF_LEN];
    size_t size = getFromGraphBuf(BitStream);
    if (size == 0) {
        PrintAndLogEx(DEBUG, "DEBUG: no data in graphbuf");
        return 0;
    }
    int startIdx = 0;
    //invert here inverts the ask raw demoded bits which has no effect on the demod, but we need the pointer
    int errCnt = askdemod_ext(BitStream, &size, &clk, &invert, maxErr, 0, 0, &startIdx);
    if (errCnt < 0 || errCnt > maxErr) {
        PrintAndLogEx(DEBUG, "DEBUG: no data or error found %d, clock: %d", errCnt, clk);
        return 0;
    }

    //attempt to Biphase decode BitStream
    errCnt = BiphaseRawDecode(BitStream, &size, &offset, invert);
    if (errCnt < 0) {
        if (g_debugMode || verbose) PrintAndLogEx(DEBUG, "DEBUG: Error BiphaseRawDecode: %d", errCnt);
        return 0;
    }
    if (errCnt > maxErr) {
        if (g_debugMode || verbose) PrintAndLogEx(DEBUG, "DEBUG: Error BiphaseRawDecode too many errors: %d", errCnt);
        return 0;
    }
    //success set DemodBuffer and return
    setDemodBuf(BitStream, size, 0);
    setClockGrid(clk, startIdx + clk * offset / 2);
    if (g_debugMode || verbose) {
        PrintAndLogEx(NORMAL, "Biphase Decoded using offset: %d - clock: %d - # errors:%d - data:", offset, clk, errCnt);
        printDemodBuff();
    }
    return 1;
}
//by marshmellow - see ASKbiphaseDemod
int Cmdaskbiphdemod(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) > 25 || cmdp == 'h') return usage_data_rawdemod_ab();

    return ASKbiphaseDemod(Cmd, true);
}

//by marshmellow - see ASKDemod
int Cmdaskrawdemod(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) > 25 || cmdp == 'h') return usage_data_rawdemod_ar();

    return ASKDemod(Cmd, true, false, 0);
}

int AutoCorrelate(const int *in, int *out, size_t len, int window, bool SaveGrph, bool verbose) {
    // sanity check
    if (window > len) window = len;

    if (verbose) PrintAndLogEx(INFO, "performing " _YELLOW_("%d")" correlations", GraphTraceLen - window);

    //test
    double autocv = 0.0;    // Autocovariance value
    double ac_value;        // Computed autocorrelation value to be returned
    double variance;        // Computed variance
    double mean;
    size_t correlation = 0;
    int lastmax = 0;

    // in, len, 4000
    mean = compute_mean(in, len);
    variance = compute_variance(in, len);

    static int CorrelBuffer[MAX_GRAPH_TRACE_LEN];

    for (int i = 0; i < len - window; ++i) {

        for (size_t j = 0; j < (len - i); j++) {
            autocv += (in[j] - mean) * (in[j + i] - mean);
        }
        autocv = (1.0 / (len - i)) * autocv;

        CorrelBuffer[i] = autocv;

        // Autocorrelation is autocovariance divided by variance
        ac_value = autocv / variance;

        // keep track of which distance is repeating.
        if (ac_value > 1) {
            correlation = i - lastmax;
            lastmax = i;
        }
    }

    //
    int hi = 0, idx = 0;
    int distance = 0, hi_1 = 0, idx_1 = 0;
    for (int i = 0; i <= len; ++i) {
        if (CorrelBuffer[i] > hi) {
            hi = CorrelBuffer[i];
            idx = i;
        }
    }

    for (int i = idx + 1; i <= window; ++i) {
        if (CorrelBuffer[i] > hi_1) {
            hi_1 = CorrelBuffer[i];
            idx_1 = i;
        }
    }

    int foo = ABS(hi - hi_1);
    int bar = (int)((int)((hi + hi_1) / 2) * 0.04);

    if (verbose && foo < bar) {
        distance = idx_1 - idx;
        PrintAndLogEx(SUCCESS, "possible 4% visible correlation %4d samples", distance);
    } else if (verbose && (correlation > 1)) {
        PrintAndLogEx(SUCCESS, "possible correlation %4d samples", correlation);
    } else {
        PrintAndLogEx(FAILED, "no repeating pattern found, try increasing window size");
    }

    int retval = correlation;
    if (SaveGrph) {
        //GraphTraceLen = GraphTraceLen - window;
        memcpy(out, CorrelBuffer, len * sizeof(int));
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

    return retval;
}

int CmdAutoCorr(const char *Cmd) {

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
                    PrintAndLogEx(WARNING, "window must be smaller than trace (%d samples)", GraphTraceLen);
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

    return AutoCorrelate(GraphBuffer, GraphBuffer, GraphTraceLen, window, updateGrph, true);
}

int CmdBitsamples(const char *Cmd) {
    int cnt = 0;
    uint8_t got[12288];

    if (!GetFromDevice(BIG_BUF, got, sizeof(got), 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return false;
    }

    for (int j = 0; j < sizeof(got); j++) {
        for (int k = 0; k < 8; k++) {
            if (got[j] & (1 << (7 - k)))
                GraphBuffer[cnt++] = 1;
            else
                GraphBuffer[cnt++] = 0;
        }
    }
    GraphTraceLen = cnt;
    RepaintGraphWindow();
    return 0;
}

int CmdBuffClear(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_data_buffclear();

    UsbCommand c = {CMD_BUFF_CLEAR, {0, 0, 0}};
    clearCommandBuffer();
    SendCommand(&c);
    ClearGraph(true);
    return 0;
}

int CmdDec(const char *Cmd) {
    for (int i = 0; i < (GraphTraceLen / 2); ++i)
        GraphBuffer[i] = GraphBuffer[i * 2];
    GraphTraceLen /= 2;
    PrintAndLogEx(NORMAL, "decimated by 2");
    RepaintGraphWindow();
    return 0;
}
/**
 * Undecimate - I'd call it 'interpolate', but we'll save that
 * name until someone does an actual interpolation command, not just
 * blindly repeating samples
 * @param Cmd
 * @return
 */
int CmdUndec(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_data_undecimate();

    uint8_t factor = param_get8ex(Cmd, 0, 2, 10);

    //We have memory, don't we?
    int swap[MAX_GRAPH_TRACE_LEN] = {0};
    uint32_t g_index = 0, s_index = 0;
    while (g_index < GraphTraceLen && s_index + factor < MAX_GRAPH_TRACE_LEN) {
        int count = 0;
        for (count = 0; count < factor && s_index + count < MAX_GRAPH_TRACE_LEN; count++)
            swap[s_index + count] = GraphBuffer[g_index];
        s_index += count;
        g_index++;
    }

    memcpy(GraphBuffer, swap, s_index * sizeof(int));
    GraphTraceLen = s_index;
    RepaintGraphWindow();
    return 0;
}

//by marshmellow
//shift graph zero up or down based on input + or -
int CmdGraphShiftZero(const char *Cmd) {
    int shift = 0, shiftedVal = 0;
    //set options from parameters entered with the command
    sscanf(Cmd, "%i", &shift);

    for (int i = 0; i < GraphTraceLen; i++) {
        if (i + shift >= GraphTraceLen)
            shiftedVal = GraphBuffer[i];
        else
            shiftedVal = GraphBuffer[i] + shift;

        if (shiftedVal > 127)
            shiftedVal = 127;
        else if (shiftedVal < -127)
            shiftedVal = -127;
        GraphBuffer[i] = shiftedVal;
    }
    CmdNorm("");
    return 0;
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
    return 0;
}

//by marshmellow
//use large jumps in read samples to identify edges of waves and then amplify that wave to max
//similar to dirtheshold, threshold commands
//takes a threshold length which is the measured length between two samples then determines an edge
int CmdAskEdgeDetect(const char *Cmd) {
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
int CmdDetectClockRate(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) > 6 || strlen(Cmd) == 0 || cmdp == 'h')
        return usage_data_detectclock();

    int clock = 0;
    switch (cmdp) {
        case 'a' :
            clock = GetAskClock(Cmd + 1, true);
            break;
        case 'f' :
            clock = GetFskClock("", true);
            break;
        case 'n' :
            clock = GetNrzClock("", true);
            break;
        case 'p' :
            clock = GetPskClock("", true);
            break;
        default :
            PrintAndLogEx(NORMAL, "Please specify a valid modulation to detect the clock of - see option h for help");
            break;
    }
    RepaintGraphWindow();
    return clock;
}

char *GetFSKType(uint8_t fchigh, uint8_t fclow, uint8_t invert) {
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
int FSKrawDemod(const char *Cmd, bool verbose) {
    //raw fsk demod  no manchester decoding no start bit finding just get binary from wave
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

    if (getSignalProperties()->isnoise)
        return 0;

    uint8_t bits[MAX_GRAPH_TRACE_LEN] = {0};
    size_t BitLen = getFromGraphBuf(bits);
    if (BitLen == 0) return 0;

    //get field clock lengths
    uint16_t fcs = 0;
    if (!fchigh || !fclow) {
        fcs = countFC(bits, BitLen, true);
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
        setDemodBuf(bits, size, 0);
        setClockGrid(rfLen, startIdx);

        // Now output the bitstream to the scrollback by line of 16 bits
        if (verbose || g_debugMode) {
            PrintAndLogEx(DEBUG, "DEBUG: (FSKrawDemod) Using Clock:%u, invert:%u, fchigh:%u, fclow:%u", rfLen, invert, fchigh, fclow);
            PrintAndLogEx(NORMAL, "%s decoded bitstream:", GetFSKType(fchigh, fclow, invert));
            printDemodBuff();
        }
        return 1;
    } else {
        PrintAndLogEx(DEBUG, "no FSK data found");
    }
    return 0;
}

//by marshmellow
//fsk raw demod and print binary
//takes 4 arguments - Clock, invert, fchigh, fclow
//defaults: clock = 50, invert=1, fchigh=10, fclow=8 (RF/10 RF/8 (fsk2a))
int CmdFSKrawdemod(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) > 20 || cmdp == 'h') return usage_data_rawdemod_fs();

    return FSKrawDemod(Cmd, true);
}

//by marshmellow
//attempt to psk1 demod graph buffer
int PSKDemod(const char *Cmd, bool verbose) {
    int invert = 0, clk = 0, maxErr = 100;

    sscanf(Cmd, "%i %i %i", &clk, &invert, &maxErr);

    if (clk == 1) {
        invert = 1;
        clk = 0;
    }
    if (invert != 0 && invert != 1) {
        if (g_debugMode || verbose) PrintAndLogEx(WARNING, "Invalid argument: %s", Cmd);
        return 0;
    }

    if (getSignalProperties()->isnoise)
        return 0;

    uint8_t bits[MAX_GRAPH_TRACE_LEN] = {0};
    size_t bitlen = getFromGraphBuf(bits);
    if (bitlen == 0)
        return 0;

    int startIdx = 0;
    int errCnt = pskRawDemod_ext(bits, &bitlen, &clk, &invert, &startIdx);
    if (errCnt > maxErr) {
        if (g_debugMode || verbose) PrintAndLogEx(DEBUG, "DEBUG: (PSKdemod) Too many errors found, clk: %d, invert: %d, numbits: %d, errCnt: %d", clk, invert, bitlen, errCnt);
        return 0;
    }
    if (errCnt < 0 || bitlen < 16) { //throw away static - allow 1 and -1 (in case of threshold command first)
        if (g_debugMode || verbose) PrintAndLogEx(DEBUG, "DEBUG: (PSKdemod) no data found, clk: %d, invert: %d, numbits: %d, errCnt: %d", clk, invert, bitlen, errCnt);
        return 0;
    }
    if (verbose || g_debugMode) {
        PrintAndLogEx(DEBUG, "DEBUG: (PSKdemod) Using Clock:%d, invert:%d, Bits Found:%d", clk, invert, bitlen);
        if (errCnt > 0) {
            PrintAndLogEx(DEBUG, "DEBUG: (PSKdemod) errors during Demoding (shown as 7 in bit stream): %d", errCnt);
        }
    }
    //prime demod buffer for output
    setDemodBuf(bits, bitlen, 0);
    setClockGrid(clk, startIdx);
    return 1;
}

int CmdIdteckDemod(const char *Cmd) {

    if (!PSKDemod("", false)) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Idteck PSKDemod failed");
        return 0;
    }
    size_t size = DemodBufferLen;

    //get binary from PSK1 wave
    int idx = detectIdteck(DemodBuffer, &size);
    if (idx < 0) {

        if (idx == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Idteck: not enough samples");
        else if (idx == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Idteck: just noise");
        else if (idx == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Idteck: preamble not found");
        else if (idx == -4)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Idteck: size not correct: %d", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - Idteck: idx: %d", idx);

        // if didn't find preamble try again inverting
        if (!PSKDemod("1", false)) {
            PrintAndLogEx(DEBUG, "DEBUG: Error - Idteck PSKDemod failed");
            return 0;
        }
        idx = detectIdteck(DemodBuffer, &size);
        if (idx < 0) {

            if (idx == -1)
                PrintAndLogEx(DEBUG, "DEBUG: Error - Idteck: not enough samples");
            else if (idx == -2)
                PrintAndLogEx(DEBUG, "DEBUG: Error - Idteck: just noise");
            else if (idx == -3)
                PrintAndLogEx(DEBUG, "DEBUG: Error - Idteck: preamble not found");
            else if (idx == -4)
                PrintAndLogEx(DEBUG, "DEBUG: Error - Idteck: size not correct: %d", size);
            else
                PrintAndLogEx(DEBUG, "DEBUG: Error - Idteck: idx: %d", idx);

            return 0;
        }
    }
    setDemodBuf(DemodBuffer, 64, idx);

    //got a good demod
    uint32_t id = 0;
    uint32_t raw1 = bytebits_to_byte(DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(DemodBuffer + 32, 32);

    //parity check (TBD)
    //checksum check (TBD)

    //output
    PrintAndLogEx(SUCCESS, "IDTECK Tag Found: Card ID %u ,  Raw: %08X%08X", id, raw1, raw2);
    return 1;
}

// by marshmellow
// takes 3 arguments - clock, invert, maxErr as integers
// attempts to demodulate nrz only
// prints binary found and saves in demodbuffer for further commands
int NRZrawDemod(const char *Cmd, bool verbose) {

    int errCnt = 0, clkStartIdx = 0;
    int invert = 0, clk = 0, maxErr = 100;
    sscanf(Cmd, "%i %i %i", &clk, &invert, &maxErr);
    if (clk == 1) {
        invert = 1;
        clk = 0;
    }

    if (invert != 0 && invert != 1) {
        PrintAndLogEx(WARNING, "(NRZrawDemod) Invalid argument: %s", Cmd);
        return 0;
    }

    if (getSignalProperties()->isnoise)
        return 0;

    uint8_t bits[MAX_GRAPH_TRACE_LEN] = {0};
    size_t BitLen = getFromGraphBuf(bits);

    if (BitLen == 0) return 0;

    errCnt = nrzRawDemod(bits, &BitLen, &clk, &invert, &clkStartIdx);
    if (errCnt > maxErr) {
        PrintAndLogEx(DEBUG, "DEBUG: (NRZrawDemod) Too many errors found, clk: %d, invert: %d, numbits: %d, errCnt: %d", clk, invert, BitLen, errCnt);
        return 0;
    }
    if (errCnt < 0 || BitLen < 16) { //throw away static - allow 1 and -1 (in case of threshold command first)
        PrintAndLogEx(DEBUG, "DEBUG: (NRZrawDemod) no data found, clk: %d, invert: %d, numbits: %d, errCnt: %d", clk, invert, BitLen, errCnt);
        return 0;
    }
    if (verbose || g_debugMode) PrintAndLogEx(DEBUG, "DEBUG: (NRZrawDemod) Tried NRZ Demod using Clock: %d - invert: %d - Bits Found: %d", clk, invert, BitLen);
    //prime demod buffer for output
    setDemodBuf(bits, BitLen, 0);
    setClockGrid(clk, clkStartIdx);


    if (errCnt > 0 && (verbose || g_debugMode)) PrintAndLogEx(DEBUG, "DEBUG: (NRZrawDemod) Errors during Demoding (shown as 7 in bit stream): %d", errCnt);
    if (verbose || g_debugMode) {
        PrintAndLogEx(NORMAL, "NRZ demoded bitstream:");
        // Now output the bitstream to the scrollback by line of 16 bits
        printDemodBuff();
    }
    return 1;
}

int CmdNRZrawDemod(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) > 16 || cmdp == 'h') return usage_data_rawdemod_nr();

    return NRZrawDemod(Cmd, true);
}

// by marshmellow
// takes 3 arguments - clock, invert, maxErr as integers
// attempts to demodulate psk only
// prints binary found and saves in demodbuffer for further commands
int CmdPSK1rawDemod(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) > 16 || cmdp == 'h') return usage_data_rawdemod_p1();

    int ans = PSKDemod(Cmd, true);
    //output
    if (!ans) {
        if (g_debugMode) PrintAndLogEx(WARNING, "Error demoding: %d", ans);
        return 0;
    }
    PrintAndLogEx(NORMAL, "PSK1 demoded bitstream:");
    // Now output the bitstream to the scrollback by line of 16 bits
    printDemodBuff();
    return 1;
}

// by marshmellow
// takes same args as cmdpsk1rawdemod
int CmdPSK2rawDemod(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) > 16 || cmdp == 'h') return usage_data_rawdemod_p2();

    int ans = PSKDemod(Cmd, true);
    if (!ans) {
        if (g_debugMode) PrintAndLogEx(WARNING, "Error demoding: %d", ans);
        return 0;
    }
    psk1TOpsk2(DemodBuffer, DemodBufferLen);
    PrintAndLogEx(NORMAL, "PSK2 demoded bitstream:");
    // Now output the bitstream to the scrollback by line of 16 bits
    printDemodBuff();
    return 1;
}

// by marshmellow - combines all raw demod functions into one menu command
int CmdRawDemod(const char *Cmd) {
    int ans = 0;

    if (strlen(Cmd) > 35 || strlen(Cmd) < 2)
        return usage_data_rawdemod();

    str_lower((char *)Cmd);

    if (str_startswith(Cmd, "fs"))     ans = CmdFSKrawdemod(Cmd + 2);
    else if (str_startswith(Cmd, "ab")) ans = Cmdaskbiphdemod(Cmd + 2);
    else if (str_startswith(Cmd, "am")) ans = Cmdaskmandemod(Cmd + 2);
    else if (str_startswith(Cmd, "ar")) ans = Cmdaskrawdemod(Cmd + 2);
    else if (str_startswith(Cmd, "nr")) ans = CmdNRZrawDemod(Cmd + 2);
    else if (str_startswith(Cmd, "p1")) ans = CmdPSK1rawDemod(Cmd + 2);
    else if (str_startswith(Cmd, "p2")) ans = CmdPSK2rawDemod(Cmd + 2);
    else PrintAndLogEx(WARNING, "Unknown modulation entered - see help ('h') for parameter structure");

    return ans;
}

void setClockGrid(int clk, int offset) {
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
    sscanf(Cmd, "%i %i", &PlotGridX, &PlotGridY);
    PlotGridXdefault = PlotGridX;
    PlotGridYdefault = PlotGridY;
    RepaintGraphWindow();
    return 0;
}

int CmdSetGraphMarkers(const char *Cmd) {
    sscanf(Cmd, "%i %i", &CursorCPos, &CursorDPos);
    RepaintGraphWindow();
    return 0;
}

int CmdHexsamples(const char *Cmd) {
    int i, j, requested = 0, offset = 0;
    char string_buf[25];
    char *string_ptr = string_buf;
    uint8_t got[BIGBUF_SIZE];

    sscanf(Cmd, "%i %i", &requested, &offset);

    /* if no args send something */
    if (requested == 0)
        requested = 8;

    if (offset + requested > sizeof(got)) {
        PrintAndLogEx(NORMAL, "Tried to read past end of buffer, <bytes> + <offset> > %d", BIGBUF_SIZE);
        return 0;
    }

    if (!GetFromDevice(BIG_BUF, got, requested, offset, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return false;
    }

    i = 0;
    for (j = 0; j < requested; j++) {
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
    return 0;
}

int CmdHide(const char *Cmd) {
    HideGraphWindow();
    return 0;
}

//zero mean GraphBuffer
int CmdHpf(const char *Cmd) {
    uint8_t bits[GraphTraceLen];
    size_t size = getFromGraphBuf(bits);
    removeSignalOffset(bits, size);
    // push it back to graph
    setGraphBuf(bits, size);
    // set signal properties low/high/mean/amplitude and is_noise detection
    computeSignalProperties(bits, size);

    RepaintGraphWindow();
    return 0;
}

bool _headBit(BitstreamOut *stream) {
    int bytepos = stream->position >> 3; // divide by 8
    int bitpos = (stream->position++) & 7; // mask out 00000111
    return (*(stream->buffer + bytepos) >> (7 - bitpos)) & 1;
}

uint8_t getByte(uint8_t bits_per_sample, BitstreamOut *b) {
    uint8_t val = 0;
    for (int i = 0 ; i < bits_per_sample; i++)
        val |= (_headBit(b) << (7 - i));

    return val;
}

int getSamples(int n, bool silent) {
    //If we get all but the last byte in bigbuf,
    // we don't have to worry about remaining trash
    // in the last byte in case the bits-per-sample
    // does not line up on byte boundaries
    uint8_t got[BIGBUF_SIZE - 1] = { 0 };

    if (n == 0 || n > sizeof(got))
        n = sizeof(got);

    if (!silent) PrintAndLogEx(NORMAL, "Reading %d bytes from device memory\n", n);

    UsbCommand response;
    if (!GetFromDevice(BIG_BUF, got, n, 0, &response, 10000, true)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return 1;
    }

    if (!silent) PrintAndLogEx(NORMAL, "Data fetched");

    uint8_t bits_per_sample = 8;

    //Old devices without this feature would send 0 at arg[0]
    if (response.arg[0] > 0) {
        sample_config *sc = (sample_config *) response.d.asBytes;
        if (!silent) PrintAndLogEx(NORMAL, "Samples @ %d bits/smpl, decimation 1:%d ", sc->bits_per_sample, sc->decimation);
        bits_per_sample = sc->bits_per_sample;
    }

    if (bits_per_sample < 8) {

        if (!silent) PrintAndLogEx(NORMAL, "Unpacking...");

        BitstreamOut bout = { got, bits_per_sample * n,  0};
        int j = 0;
        for (j = 0; j * bits_per_sample < n * 8 && j < n; j++) {
            uint8_t sample = getByte(bits_per_sample, &bout);
            GraphBuffer[j] = ((int) sample) - 128;
        }
        GraphTraceLen = j;

        if (!silent) PrintAndLogEx(NORMAL, "Unpacked %d samples", j);

    } else {
        for (int j = 0; j < n; j++) {
            GraphBuffer[j] = ((int)got[j]) - 128;
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
    return 0;
}

int CmdSamples(const char *Cmd) {
    int n = strtol(Cmd, NULL, 0);
    return getSamples(n, false);
}

int CmdTuneSamples(const char *Cmd) {
#define NON_VOLTAGE     1000
#define LF_UNUSABLE_V   2000
#define LF_MARGINAL_V   10000
#define HF_UNUSABLE_V   3000
#define HF_MARGINAL_V   5000
#define ANTENNA_ERROR   1.03 // current algo has 3% error margin.

    // hide demod plot line
    DemodBufferLen = 0;
    setClockGrid(0, 0);
    RepaintGraphWindow();


    int timeout = 0;
    PrintAndLogEx(INFO, "\nmeasuring antenna characteristics, please wait...");

    UsbCommand c = {CMD_MEASURE_ANTENNA_TUNING, {0, 0, 0}};
    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;
    while (!WaitForResponseTimeout(CMD_MEASURED_ANTENNA_TUNING, &resp, 2000)) {
        timeout++;
        printf(".");
        fflush(stdout);
        if (timeout > 7) {
            PrintAndLogEx(WARNING, "\nno response from Proxmark. Aborting...");
            return 1;
        }
    }
    PrintAndLogEx(NORMAL, "\n");

    uint32_t v_lf125 = resp.arg[0];
    uint32_t v_lf134 = resp.arg[0] >> 32;

    uint32_t v_hf = resp.arg[1];
    uint32_t peakf = resp.arg[2];
    uint32_t peakv = resp.arg[2] >> 32;

    if (v_lf125 > NON_VOLTAGE)
        PrintAndLogEx(SUCCESS, "LF antenna: %5.2f V - 125.00 kHz", (v_lf125 * ANTENNA_ERROR) / 1000.0);
    if (v_lf134 > NON_VOLTAGE)
        PrintAndLogEx(SUCCESS, "LF antenna: %5.2f V - 134.00 kHz", (v_lf134 * ANTENNA_ERROR) / 1000.0);
    if (peakv > NON_VOLTAGE && peakf > 0)
        PrintAndLogEx(SUCCESS, "LF optimal: %5.2f V - %6.2f kHz", (peakv * ANTENNA_ERROR) / 1000.0, 12000.0 / (peakf + 1));

    char judgement[20];
    memset(judgement, 0, sizeof(judgement));
    // LF evaluation
    if (peakv < LF_UNUSABLE_V)
        sprintf(judgement, _RED_("UNUSABLE"));
    else if (peakv < LF_MARGINAL_V)
        sprintf(judgement, _YELLOW_("MARGINAL"));
    else
        sprintf(judgement, _GREEN_("OK"));

    PrintAndLogEx(NORMAL, "%sLF antenna is %s \n"
                  , (peakv < LF_UNUSABLE_V) ? _CYAN_("[!]") : _GREEN_("[+]")
                  , judgement
                 );

    // HF evaluation
    if (v_hf > NON_VOLTAGE)
        PrintAndLogEx(SUCCESS, "HF antenna: %5.2f V - 13.56 MHz", (v_hf * ANTENNA_ERROR) / 1000.0);

    memset(judgement, 0, sizeof(judgement));

    if (v_hf < HF_UNUSABLE_V)
        sprintf(judgement, _RED_("UNUSABLE"));
    else if (v_hf < HF_MARGINAL_V)
        sprintf(judgement, _YELLOW_("MARGINAL"));
    else
        sprintf(judgement, _GREEN_("OK"));

    PrintAndLogEx(NORMAL, "%sHF antenna is %s"
                  , (v_hf < HF_UNUSABLE_V) ? _CYAN_("[!]") : _GREEN_("[+]")
                  , judgement
                 );

    // graph LF measurements
    // even here, these values has 3% error.
    uint16_t test = 0;
    for (int i = 0; i < 256; i++) {
        GraphBuffer[i] = resp.d.asBytes[i] - 128;
        test += resp.d.asBytes[i];
    }
    if (test > 0) {
        PrintAndLogEx(SUCCESS, "\nDisplaying LF tuning graph. Divisor 89 is 134khz, 95 is 125khz.\n\n");
        GraphTraceLen = 256;
        ShowGraphWindow();
        RepaintGraphWindow();
    } else {

        PrintAndLogEx(FAILED, "\nNot showing LF tuning graph since all values is zero.\n\n");
    }

    return 0;
}

int CmdLoad(const char *Cmd) {
    char filename[FILE_PATH_SIZE] = {0x00};
    int len = 0;

    len = strlen(Cmd);
    if (len > FILE_PATH_SIZE) len = FILE_PATH_SIZE;
    memcpy(filename, Cmd, len);

    FILE *f = fopen(filename, "r");
    if (!f) {
        PrintAndLogEx(WARNING, "couldn't open '%s'", filename);
        return 0;
    }

    GraphTraceLen = 0;
    char line[80];
    while (fgets(line, sizeof(line), f)) {
        GraphBuffer[GraphTraceLen] = atoi(line);
        GraphTraceLen++;

        if (GraphTraceLen >= MAX_GRAPH_TRACE_LEN)
            break;
    }

    fclose(f);

    PrintAndLogEx(SUCCESS, "loaded %d samples", GraphTraceLen);

    uint8_t bits[GraphTraceLen];
    size_t size = getFromGraphBuf(bits);

    removeSignalOffset(bits, size);
    setGraphBuf(bits, size);
    computeSignalProperties(bits, size);

    setClockGrid(0, 0);
    DemodBufferLen = 0;
    RepaintGraphWindow();
    return 0;
}

// trim graph from the end
int CmdLtrim(const char *Cmd) {
    // sanitycheck
    if (GraphTraceLen <= 0) return 1;

    int ds = atoi(Cmd);
    for (int i = ds; i < GraphTraceLen; ++i)
        GraphBuffer[i - ds] = GraphBuffer[i];

    GraphTraceLen -= ds;
    RepaintGraphWindow();
    return 0;
}

// trim graph from the beginning
int CmdRtrim(const char *Cmd) {

    int ds = atoi(Cmd);

    // sanitycheck
    if (GraphTraceLen <= ds) return 1;

    GraphTraceLen = ds;
    RepaintGraphWindow();
    return 0;
}

// trim graph (middle) piece
int CmdMtrim(const char *Cmd) {
    int start = 0, stop = 0;
    sscanf(Cmd, "%i %i", &start, &stop);

    if (start > GraphTraceLen || stop > GraphTraceLen || start > stop) return 1;

    // leave start position sample
    start++;

    GraphTraceLen = stop - start;
    for (int i = 0; i < GraphTraceLen; i++)
        GraphBuffer[i] = GraphBuffer[start + i];

    return 0;
}

int CmdNorm(const char *Cmd) {
    int i;
    int max = INT_MIN, min = INT_MAX;

    // Find local min, max
    for (i = 10; i < GraphTraceLen; ++i) {
        if (GraphBuffer[i] > max) max = GraphBuffer[i];
        if (GraphBuffer[i] < min) min = GraphBuffer[i];
    }

    if (max != min) {
        for (i = 0; i < GraphTraceLen; ++i) {
            GraphBuffer[i] = ((long)(GraphBuffer[i] - ((max + min) / 2)) * 256) / (max - min);
            //marshmelow: adjusted *1000 to *256 to make +/- 128 so demod commands still work
        }
    }

    uint8_t bits[GraphTraceLen];
    size_t size = getFromGraphBuf(bits);
    // set signal properties low/high/mean/amplitude and is_noise detection
    computeSignalProperties(bits, size);

    RepaintGraphWindow();
    return 0;
}

int CmdPlot(const char *Cmd) {
    ShowGraphWindow();
    return 0;
}

int CmdSave(const char *Cmd) {

    int len = 0;
    char filename[FILE_PATH_SIZE] = {0x00};

    len = strlen(Cmd);
    if (len > FILE_PATH_SIZE) len = FILE_PATH_SIZE;
    memcpy(filename, Cmd, len);

    FILE *f = fopen(filename, "w");
    if (!f) {
        PrintAndLogEx(WARNING, "couldn't open '%s'", filename);
        return 0;
    }

    for (int i = 0; i < GraphTraceLen; i++)
        fprintf(f, "%d\n", GraphBuffer[i]);

    if (f)
        fclose(f);

    PrintAndLogEx(SUCCESS, "saved to '%s'", Cmd);
    return 0;
}

int CmdScale(const char *Cmd) {
    CursorScaleFactor = atoi(Cmd);
    if (CursorScaleFactor == 0) {
        PrintAndLogEx(FAILED, "bad, can't have zero scale");
        CursorScaleFactor = 1;
    }
    RepaintGraphWindow();
    return 0;
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
    return 0;
}

int CmdDirectionalThreshold(const char *Cmd) {
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
    return 0;
}

int CmdZerocrossings(const char *Cmd) {
    // Zero-crossings aren't meaningful unless the signal is zero-mean.
    CmdHpf("");

    int sign = 1, zc = 0, lastZc = 0;

    for (int i = 0; i < GraphTraceLen; ++i) {
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
    return 0;
}

/**
 * @brief Utility for conversion via cmdline.
 * @param Cmd
 * @return
 */
int Cmdbin2hex(const char *Cmd) {
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
    return 0;
}

int Cmdhex2bin(const char *Cmd) {
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

        //Uses printf instead of PrintAndLog since the latter adds linebreaks to each printout
        for (int i = 0 ; i < 4 ; ++i)
            printf("%d", (x >> (3 - i)) & 1);
    }
    PrintAndLogEx(NORMAL, "\n");
    return 0;
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
void GetHiLoTone(int *LowTone, int *HighTone, int clk, int LowToneFC, int HighToneFC) {
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
int FSKToNRZ(int *data, int *dataLen, int clk, int LowToneFC, int HighToneFC) {
    uint8_t ans = 0;
    if (clk == 0 || LowToneFC == 0 || HighToneFC == 0) {
        int firstClockEdge = 0;
        ans = fskClocks((uint8_t *) &LowToneFC, (uint8_t *) &HighToneFC, (uint8_t *) &clk, &firstClockEdge);
        if (g_debugMode > 1) {
            PrintAndLog("DEBUG FSKtoNRZ: detected clocks: fc_low %i, fc_high %i, clk %i, firstClockEdge %i, ans %u", LowToneFC, HighToneFC, clk, firstClockEdge, ans);
        }
    }
    // currently only know fsk modulations with field clocks < 10 samples and > 4 samples. filter out to remove false positives (and possibly destroying ask/psk modulated waves...)
    if (ans == 0 || clk == 0 || LowToneFC == 0 || HighToneFC == 0 || LowToneFC > 10 || HighToneFC < 4) {
        if (g_debugMode > 1) {
            PrintAndLog("DEBUG FSKtoNRZ: no fsk clocks found");
        }
        return 0;
    }

    int i, j;
    int LowTone[clk];
    int HighTone[clk];
    GetHiLoTone(LowTone, HighTone, clk, LowToneFC, HighToneFC);

    // loop through ([all samples] - clk)
    for (i = 0; i < *dataLen - clk; ++i) {
        int lowSum = 0, highSum = 0;

        // sum all samples together starting from this sample for [clk] samples for each tone (multiply tone value with sample data)
        for (j = 0; j < clk; ++j) {
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
    for (i = 0; i < *dataLen - clk - LowToneFC; ++i) {
        int lowTot = 0, highTot = 0;

        // sum a field clock width of abs( [average sample values per clk] * 100) for each tone
        for (j = 0; j < LowToneFC; ++j) {  //10 for fsk2
            lowTot += (data[i + j] & 0xffff);
        }
        for (j = 0; j < HighToneFC; j++) {  //8 for fsk2
            highTot += (data[i + j] >> 16);
        }

        // subtract the sum of lowTone averages by the sum of highTone averages as it
        //   and write back the new graph value
        data[i] = lowTot - highTot;
    }
    // update dataLen to what we put back to the data sample buffer
    *dataLen -= (clk + LowToneFC);
    return 0;
}

int CmdFSKToNRZ(const char *Cmd) {
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

int CmdDataIIR(const char *Cmd) {
    uint8_t k = param_get8(Cmd, 0);
    //iceIIR_Butterworth(GraphBuffer, GraphTraceLen);
    iceSimple_Filter(GraphBuffer, GraphTraceLen, k);

    uint8_t bits[GraphTraceLen];
    size_t size = getFromGraphBuf(bits);
    // set signal properties low/high/mean/amplitude and is_noise detection
    computeSignalProperties(bits, size);
    RepaintGraphWindow();
    return 0;
}

static command_t CommandTable[] = {
    {"help",            CmdHelp,            1, "This help"},
    {"askedgedetect",   CmdAskEdgeDetect,   1, "[threshold] Adjust Graph for manual ASK demod using the length of sample differences to detect the edge of a wave (use 20-45, def:25)"},
    {"autocorr",        CmdAutoCorr,        1, "[window length] [g] -- Autocorrelation over window - g to save back to GraphBuffer (overwrite)"},
    {"biphaserawdecode", CmdBiphaseDecodeRaw, 1, "[offset] [invert<0|1>] [maxErr] -- Biphase decode bin stream in DemodBuffer (offset = 0|1 bits to shift the decode start)"},
    {"bin2hex",         Cmdbin2hex,         1, "<digits> -- Converts binary to hexadecimal"},
    {"bitsamples",      CmdBitsamples,      0, "Get raw samples as bitstring"},
    {"buffclear",       CmdBuffClear,       1, "Clears bigbuff on deviceside and graph window"},
    {"dec",             CmdDec,             1, "Decimate samples"},
    {"detectclock",     CmdDetectClockRate, 1, "[<a|f|n|p>] Detect ASK, FSK, NRZ, PSK clock rate of wave in GraphBuffer"},
    {"fsktonrz",        CmdFSKToNRZ,        1, "Convert fsk2 to nrz wave for alternate fsk demodulating (for weak fsk)"},

    {"getbitstream",    CmdGetBitStream,    1, "Convert GraphBuffer's >=1 values to 1 and <1 to 0"},
    {"grid",            CmdGrid,            1, "<x> <y> -- overlay grid on graph window, use zero value to turn off either"},
    {"hexsamples",      CmdHexsamples,      0, "<bytes> [<offset>] -- Dump big buffer as hex bytes"},
    {"hex2bin",         Cmdhex2bin,         1, "<hexadecimal> -- Converts hexadecimal to binary"},
    {"hide",            CmdHide,            1, "Hide graph window"},
    {"hpf",             CmdHpf,             1, "Remove DC offset from trace"},
    {"load",            CmdLoad,            1, "<filename> -- Load trace (to graph window"},
    {"ltrim",           CmdLtrim,           1, "<samples> -- Trim samples from left of trace"},
    {"rtrim",           CmdRtrim,           1, "<location to end trace> -- Trim samples from right of trace"},
    {"mtrim",           CmdMtrim,           1, "<start> <stop> -- Trim out samples from the specified start to the specified stop"},
    {"manrawdecode",    Cmdmandecoderaw,    1, "[invert] [maxErr] -- Manchester decode binary stream in DemodBuffer"},
    {"norm",            CmdNorm,            1, "Normalize max/min to +/-128"},
    {"plot",            CmdPlot,            1, "Show graph window (hit 'h' in window for keystroke help)"},
    {"printdemodbuffer", CmdPrintDemodBuff,  1, "[x] [o] <offset> [l] <length> -- print the data in the DemodBuffer - 'x' for hex output"},
    {"rawdemod",        CmdRawDemod,        1, "[modulation] ... <options> -see help (h option) -- Demodulate the data in the GraphBuffer and output binary"},
    {"samples",         CmdSamples,         0, "[512 - 40000] -- Get raw samples for graph window (GraphBuffer)"},
    {"save",            CmdSave,            1, "<filename> -- Save trace (from graph window)"},
    {"setgraphmarkers", CmdSetGraphMarkers, 1, "[orange_marker] [blue_marker] (in graph window)"},
    {"scale",           CmdScale,           1, "<int> -- Set cursor display scale"},
    {"setdebugmode",    CmdSetDebugMode,    1, "<0|1|2> -- Turn on or off Debugging Level for lf demods"},
    {"shiftgraphzero",  CmdGraphShiftZero,  1, "<shift> -- Shift 0 for Graphed wave + or - shift value"},
    {"dirthreshold",    CmdDirectionalThreshold,   1, "<thres up> <thres down> -- Max rising higher up-thres/ Min falling lower down-thres, keep rest as prev."},
    {"tune",            CmdTuneSamples,     0, "Get hw tune samples for graph window"},
    {"undec",           CmdUndec,           1, "Un-decimate samples by 2"},
    {"zerocrossings",   CmdZerocrossings,   1, "Count time between zero-crossings"},
    {"iir",             CmdDataIIR,         0, "apply IIR buttersworth filter on plotdata"},
    {NULL, NULL, 0, NULL}
};

int CmdData(const char *Cmd) {
    clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}
