//-----------------------------------------------------------------------------
// Copyright (C) 2009 Michael Gernoth <michael at gernoth.net>
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// UI utilities
//-----------------------------------------------------------------------------

/* Ensure strtok_r is available even with -std=c99; must be included before
 */
#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200112L
#endif

#include "ui.h"
session_arg_t session;

double CursorScaleFactor = 1;
int PlotGridX = 0, PlotGridY = 0, PlotGridXdefault = 64, PlotGridYdefault = 64;
uint32_t CursorCPos = 0, CursorDPos = 0;
bool flushAfterWrite = 0;
int GridOffset = 0;
bool GridLocked = false;
bool showDemod = true;

pthread_mutex_t print_lock = PTHREAD_MUTEX_INITIALIZER;
static const char *logfilename = "proxmark3.log";
static void fPrintAndLog(FILE *stream, const char *fmt, ...);

void PrintAndLogOptions(const char *str[][2], size_t size, size_t space) {
    char buff[2000] = "Options:\n";
    char format[2000] = "";
    size_t counts[2] = {0, 0};
    for (size_t i = 0; i < size; i++)
        for (size_t j = 0 ; j < 2 ; j++)
            if (counts[j] < strlen(str[i][j])) {
                counts[j] = strlen(str[i][j]);
            }
    for (size_t i = 0; i < size; i++) {
        for (size_t j = 0; j < 2; j++) {
            if (j == 0)
                snprintf(format, sizeof(format), "%%%zus%%%zus", space, counts[j]);
            else
                snprintf(format, sizeof(format), "%%%zus%%-%zus", space, counts[j]);
            snprintf(buff + strlen(buff), sizeof(buff) - strlen(buff), format, " ", str[i][j]);
        }
        if (i < size - 1)
            strncat(buff, "\n", sizeof(buff) - strlen(buff) - 1);
    }
    PrintAndLogEx(NORMAL, "%s", buff);
}

uint8_t PrintAndLogEx_spinidx = 0;

void PrintAndLogEx(logLevel_t level, const char *fmt, ...) {

    // skip debug messages if client debugging is turned off i.e. 'DATA SETDEBUG 0'
    if (g_debugMode == 0 && level == DEBUG)
        return;

    char prefix[20] = {0};
    char buffer[MAX_PRINT_BUFFER] = {0};
    char buffer2[MAX_PRINT_BUFFER + 20] = {0};
    char *token = NULL;
    char *tmp_ptr = NULL;
    FILE *stream = stdout;
    char *spinner[] = {_YELLOW_("[\\]"), _YELLOW_("[|]"), _YELLOW_("[/]"), _YELLOW_("[-]")};
    switch (level) {
        case ERR:
            strncpy(prefix, _RED_("[!!]"), sizeof(prefix) - 1);
            stream = stderr;
            break;
        case FAILED:
            strncpy(prefix, _RED_("[-]"), sizeof(prefix) - 1);
            break;
        case DEBUG:
            strncpy(prefix, _BLUE_("[#]"), sizeof(prefix) - 1);
            break;
        case SUCCESS:
            strncpy(prefix, _GREEN_("[+]"), sizeof(prefix) - 1);
            break;
        case WARNING:
            strncpy(prefix, _CYAN_("[!]"), sizeof(prefix) - 1);
            break;
        case INFO:
            strncpy(prefix, _YELLOW_("[=]"), sizeof(prefix) - 1);
            break;
        case INPLACE:
            strncpy(prefix, spinner[PrintAndLogEx_spinidx], sizeof(prefix) - 1);
            PrintAndLogEx_spinidx++;
            if (PrintAndLogEx_spinidx == ARRAYLEN(spinner))
                PrintAndLogEx_spinidx = 0;
            break;
        case NORMAL:
            // no prefixes for normal
            break;
    }

    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    // no prefixes for normal & inplace
    if (level == NORMAL) {
        fPrintAndLog(stream, "%s", buffer);
        return;
    }

    if (strchr(buffer, '\n')) {

        const char delim[2] = "\n";

        // line starts with newline
        if (buffer[0] == '\n')
            fPrintAndLog(stream, "");

        token = strtok_r(buffer, delim, &tmp_ptr);

        while (token != NULL) {

            size_t size = strlen(buffer2);

            if (strlen(token))
                snprintf(buffer2 + size, sizeof(buffer2) - size, "%s%s\n", prefix, token);
            else
                snprintf(buffer2 + size, sizeof(buffer2) - size, "\n");

            token = strtok_r(NULL, delim, &tmp_ptr);
        }
        fPrintAndLog(stream, "%s", buffer2);
    } else {
        snprintf(buffer2, sizeof(buffer2), "%s%s", prefix, buffer);
        if (level == INPLACE) {
            char buffer3[MAX_PRINT_BUFFER + 20] = {0};
            memcpy_filter_ansi(buffer3, buffer2, sizeof(buffer2), !session.supports_colors);
            fprintf(stream, "\r%s", buffer3);
            fflush(stream);
        } else {
            fPrintAndLog(stream, "%s", buffer2);
        }
    }
}

static void fPrintAndLog(FILE *stream, const char *fmt, ...) {
    char *saved_line;
    int saved_point;
    va_list argptr;
    static FILE *logfile = NULL;
    static int logging = 1;
    char buffer[MAX_PRINT_BUFFER] = {0};
    char buffer2[MAX_PRINT_BUFFER] = {0};
    // lock this section to avoid interlacing prints from different threads
    pthread_mutex_lock(&print_lock);

    if (logging && !logfile) {
        logfile = fopen(logfilename, "a");
        if (!logfile) {
            fprintf(stderr, "Can't open logfile, logging disabled!\n");
            logging = 0;
        }
    }


// If there is an incoming message from the hardware (eg: lf hid read) in
// the background (while the prompt is displayed and accepting user input),
// stash the prompt and bring it back later.
#ifdef RL_STATE_READCMD
    // We are using GNU readline. libedit (OSX) doesn't support this flag.
    int need_hack = (rl_readline_state & RL_STATE_READCMD) > 0;

    if (need_hack) {
        saved_point = rl_point;
        saved_line = rl_copy_text(0, rl_end);
        rl_save_prompt();
        rl_replace_line("", 0);
        rl_redisplay();
    }
#endif

    va_start(argptr, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, argptr);
    va_end(argptr);

    bool filter_ansi = !session.supports_colors;
    memcpy_filter_ansi(buffer2, buffer, sizeof(buffer), filter_ansi);
    fprintf(stream, "%s", buffer2);
    fprintf(stream, "          "); // cleaning prompt
    fprintf(stream, "\n");

#ifdef RL_STATE_READCMD
    // We are using GNU readline. libedit (OSX) doesn't support this flag.
    if (need_hack) {
        rl_restore_prompt();
        rl_replace_line(saved_line, 0);
        rl_point = saved_point;
        rl_redisplay();
        free(saved_line);
    }
#endif

    if (logging && logfile) {
        if (filter_ansi) { // already done
            fprintf(logfile, "%s\n", buffer2);
        } else {
            memcpy_filter_ansi(buffer, buffer2, sizeof(buffer2), true);
            fprintf(logfile, "%s\n", buffer);
        }
        fflush(logfile);
    }

    if (flushAfterWrite)
        fflush(stdout);

    //release lock
    pthread_mutex_unlock(&print_lock);
}

void SetLogFilename(char *fn) {
    logfilename = fn;
}

void SetFlushAfterWrite(bool value) {
    flushAfterWrite = value;
}

void memcpy_filter_ansi(void *dest, const void *src, size_t n, bool filter) {
    if (filter) {
        // Filter out ANSI sequences on these OS
        uint8_t *rdest = (uint8_t *)dest;
        uint8_t *rsrc = (uint8_t *)src;
        uint16_t si = 0;
        for (uint16_t i = 0; i < n; i++) {
            if ((i < n - 1)
                    && (rsrc[i] == '\x1b')
                    && (rsrc[i + 1] >= 0x40)
                    && (rsrc[i + 1] <= 0x5F)) {  // entering ANSI sequence

                i++;
                if ((i < n - 1) && (rsrc[i] == '[')) { // entering CSI sequence
                    i++;

                    while ((i < n - 1) && (rsrc[i] >= 0x30) && (rsrc[i] <= 0x3F)) { // parameter bytes
                        i++;
                    }

                    while ((i < n - 1) && (rsrc[i] >= 0x20) && (rsrc[i] <= 0x2F)) { // intermediate bytes
                        i++;
                    }

                    if ((rsrc[i] >= 0x40) && (rsrc[i] <= 0x7F)) { // final byte
                        continue;
                    }
                } else {
                    continue;
                }
            }
            rdest[si++] = rsrc[i];
        }
    } else {
        memcpy(dest, src, n);
    }
}

void iceIIR_Butterworth(int *data, const size_t len) {

    int *output = (int *) calloc(sizeof(int) * len, sizeof(uint8_t));
    if (!output) return;

    // clear mem
    memset(output, 0x00, len);

    size_t adjustedLen = len;
    float fc = 0.1125f;          // center frequency

    // create very simple low-pass filter to remove images (2nd-order Butterworth)
    float complex iir_buf[3] = {0, 0, 0};
    float b[3] = {0.003621681514929,  0.007243363029857, 0.003621681514929};
    float a[3] = {1.000000000000000, -1.822694925196308, 0.837181651256023};

    for (size_t i = 0; i < adjustedLen; ++i) {

        float sample = data[i];          // input sample read from array
        float complex x_prime  = 1.0f;   // save sample for estimating frequency
        float complex x;

        // remove DC offset and mix to complex baseband
        x = (sample - 127.5f) * cexpf(_Complex_I * 2 * M_PI * fc * i);

        // apply low-pass filter, removing spectral image (IIR using direct-form II)
        iir_buf[2] = iir_buf[1];
        iir_buf[1] = iir_buf[0];
        iir_buf[0] = x - a[1] * iir_buf[1] - a[2] * iir_buf[2];
        x          = b[0] * iir_buf[0] +
                     b[1] * iir_buf[1] +
                     b[2] * iir_buf[2];

        // compute instantaneous frequency by looking at phase difference
        // between adjacent samples
        float freq = cargf(x * conjf(x_prime));
        x_prime = x;    // retain this sample for next iteration

        output[i] = (freq > 0) ? 127 : -127;
    }

    // show data
    //memcpy(data, output, adjustedLen);
    for (size_t j = 0; j < adjustedLen; ++j)
        data[j] = output[j];

    free(output);
}

void iceSimple_Filter(int *data, const size_t len, uint8_t k) {
// ref: http://www.edn.com/design/systems-design/4320010/A-simple-software-lowpass-filter-suits-embedded-system-applications
// parameter K
#define FILTER_SHIFT 4

    int32_t filter_reg = 0;
    int8_t shift = (k <= 8) ? k : FILTER_SHIFT;

    for (size_t i = 0; i < len; ++i) {
        // Update filter with current sample
        filter_reg = filter_reg - (filter_reg >> shift) + data[i];

        // Scale output for unity gain
        data[i] = filter_reg >> shift;
    }
}


