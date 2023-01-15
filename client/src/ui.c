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
// UI utilities
//-----------------------------------------------------------------------------

/* Ensure strtok_r is available even with -std=c99; must be included before
 */
#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200112L
#endif
#include "ui.h"
#include "commonutil.h"  // ARRAYLEN
#include <stdio.h> // for Mingw readline
#include <stdarg.h>
#include <stdlib.h>

#if defined(HAVE_READLINE)
//Load readline after stdio.h
#include <readline/readline.h>
#endif

#include <complex.h>
#include "util.h"
#include "proxmark3.h"  // PROXLOG
#include "fileutils.h"
#include "pm3_cmd.h"

#ifdef _WIN32
# include <direct.h>    // _mkdir
#endif

#include <time.h>
#include "emojis.h"
#include "emojis_alt.h"
session_arg_t g_session;

double g_CursorScaleFactor = 1;
char g_CursorScaleFactorUnit[11] = {0};
double g_PlotGridX = 0, g_PlotGridY = 0, g_PlotGridXdefault = 64, g_PlotGridYdefault = 64;
uint32_t g_CursorCPos = 0, g_CursorDPos = 0, g_GraphStop = 0;
uint32_t g_GraphStart = 0; // Starting point/offset for the left side of the graph
double g_GraphPixelsPerPoint = 1.f; // How many visual pixels are between each sample point (x axis)
static bool flushAfterWrite = false;
double g_GridOffset = 0;
bool g_GridLocked = false;

pthread_mutex_t g_print_lock = PTHREAD_MUTEX_INITIALIZER;

static void fPrintAndLog(FILE *stream, const char *fmt, ...);

#ifdef _WIN32
#define MKDIR_CHK _mkdir(path)
#else
#define MKDIR_CHK mkdir(path, 0700)
#endif


// needed by flasher, so let's put it here instead of fileutils.c
int searchHomeFilePath(char **foundpath, const char *subdir, const char *filename, bool create_home) {
    if (foundpath == NULL) {
        return PM3_EINVARG;
    }

    const char *user_path = get_my_user_directory();
    if (user_path == NULL) {
        fprintf(stderr, "Could not retrieve $HOME from the environment\n");
        return PM3_EFILE;
    }

    size_t pathlen = strlen(user_path) + strlen(PM3_USER_DIRECTORY) + 1;
    char *path = calloc(pathlen, sizeof(char));
    if (path == NULL) {
        return PM3_EMALLOC;
    }

    strcpy(path, user_path);
    strcat(path, PM3_USER_DIRECTORY);
    int result;

#ifdef _WIN32
    struct _stat st;
    // Mingw _stat fails if path ends with /, so let's use a stripped path
    if (str_endswith(path, PATHSEP)) {
        memset(path + (strlen(path) - strlen(PATHSEP)), 0x00, strlen(PATHSEP));
        result = _stat(path, &st);
        strcat(path, PATHSEP);
    } else {
        result = _stat(path, &st);
    }
#else
    struct stat st;
    result = stat(path, &st);
#endif

    if ((result != 0) && create_home) {

        if (MKDIR_CHK) {
            fprintf(stderr, "Could not create user directory %s\n", path);
            free(path);
            return PM3_EFILE;
        }
    }

    if (subdir != NULL) {
        pathlen += strlen(subdir);
        char *tmp = realloc(path, pathlen * sizeof(char));
        if (tmp == NULL) {
            //free(path);
            return PM3_EMALLOC;
        }
        path = tmp;
        strcat(path, subdir);

#ifdef _WIN32
        // Mingw _stat fails if path ends with /, so let's use a stripped path
        if (str_endswith(path, PATHSEP)) {
            memset(path + (strlen(path) - strlen(PATHSEP)), 0x00, strlen(PATHSEP));
            result = _stat(path, &st);
            strcat(path, PATHSEP);
        } else {
            result = _stat(path, &st);
        }
#else
        result = stat(path, &st);
#endif

        if ((result != 0) && create_home) {

            if (MKDIR_CHK) {
                fprintf(stderr, "Could not create user directory %s\n", path);
                free(path);
                return PM3_EFILE;
            }
        }
    }

    if (filename == NULL) {
        *foundpath = path;
        return PM3_SUCCESS;
    }

    pathlen += strlen(filename);
    char *tmp = realloc(path, pathlen * sizeof(char));
    if (tmp == NULL) {
        //free(path);
        return PM3_EMALLOC;
    }

    path = tmp;
    strcat(path, filename);
    *foundpath = path;

    return PM3_SUCCESS;
}

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

static uint8_t PrintAndLogEx_spinidx = 0;

void PrintAndLogEx(logLevel_t level, const char *fmt, ...) {

    // skip debug messages if client debugging is turned off i.e. 'DATA SETDEBUG -0'
    if (g_debugMode == 0 && level == DEBUG)
        return;

    // skip HINT messages if client has hints turned off i.e. 'HINT 0'
    if (g_session.show_hints == false && level == HINT)
        return;

    char prefix[40] = {0};
    char buffer[MAX_PRINT_BUFFER] = {0};
    char buffer2[MAX_PRINT_BUFFER + sizeof(prefix)] = {0};
    char *token = NULL;
    char *tmp_ptr = NULL;
    FILE *stream = stdout;
    const char *spinner[] = {_YELLOW_("[\\]"), _YELLOW_("[|]"), _YELLOW_("[/]"), _YELLOW_("[-]")};
    const char *spinner_emoji[] = {" :clock1: ", " :clock2: ", " :clock3: ", " :clock4: ", " :clock5: ", " :clock6: ",
                                   " :clock7: ", " :clock8: ", " :clock9: ", " :clock10: ", " :clock11: ", " :clock12: "
                                  };
    switch (level) {
        case ERR:
            if (g_session.emoji_mode == EMO_EMOJI)
                strncpy(prefix,  "[" _RED_("!!") "] :rotating_light: ", sizeof(prefix) - 1);
            else
                strncpy(prefix, "[" _RED_("!!") "] ", sizeof(prefix) - 1);
            stream = stderr;
            break;
        case FAILED:
            if (g_session.emoji_mode == EMO_EMOJI)
                strncpy(prefix, "[" _RED_("-") "] :no_entry: ", sizeof(prefix) - 1);
            else
                strncpy(prefix, "[" _RED_("-") "] ", sizeof(prefix) - 1);
            break;
        case DEBUG:
            strncpy(prefix, "[" _BLUE_("#") "] ", sizeof(prefix) - 1);
            break;
        case HINT:
            strncpy(prefix, "[" _YELLOW_("?") "] ", sizeof(prefix) - 1);
            break;
        case SUCCESS:
            strncpy(prefix, "[" _GREEN_("+") "] ", sizeof(prefix) - 1);
            break;
        case WARNING:
            if (g_session.emoji_mode == EMO_EMOJI)
                strncpy(prefix, "[" _CYAN_("!") "] :warning:  ", sizeof(prefix) - 1);
            else
                strncpy(prefix, "[" _CYAN_("!") "] ", sizeof(prefix) - 1);
            break;
        case INFO:
            strncpy(prefix, "[" _YELLOW_("=") "] ", sizeof(prefix) - 1);
            break;
        case INPLACE:
            if (g_session.emoji_mode == EMO_EMOJI) {
                strncpy(prefix, spinner_emoji[PrintAndLogEx_spinidx], sizeof(prefix) - 1);
                PrintAndLogEx_spinidx++;
                if (PrintAndLogEx_spinidx >= ARRAYLEN(spinner_emoji))
                    PrintAndLogEx_spinidx = 0;
            } else {
                strncpy(prefix, spinner[PrintAndLogEx_spinidx], sizeof(prefix) - 1);
                PrintAndLogEx_spinidx++;
                if (PrintAndLogEx_spinidx >= ARRAYLEN(spinner))
                    PrintAndLogEx_spinidx = 0;
            }
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
            char buffer3[sizeof(buffer2)] = {0};
            char buffer4[sizeof(buffer2)] = {0};
            memcpy_filter_ansi(buffer3, buffer2, sizeof(buffer2), !g_session.supports_colors);
            memcpy_filter_emoji(buffer4, buffer3, sizeof(buffer3), g_session.emoji_mode);
            fprintf(stream, "\r%s", buffer4);
            fflush(stream);
        } else {
            fPrintAndLog(stream, "%s", buffer2);
        }
    }
}

static void fPrintAndLog(FILE *stream, const char *fmt, ...) {
    va_list argptr;
    static FILE *logfile = NULL;
    static int logging = 1;
    char buffer[MAX_PRINT_BUFFER] = {0};
    char buffer2[MAX_PRINT_BUFFER] = {0};
    char buffer3[MAX_PRINT_BUFFER] = {0};
    // lock this section to avoid interlacing prints from different threads
    pthread_mutex_lock(&g_print_lock);
    bool linefeed = true;

    if (logging && g_session.incognito) {
        logging = 0;
    }
    if ((g_printAndLog & PRINTANDLOG_LOG) && logging && !logfile) {
        char *my_logfile_path = NULL;
        char filename[40];
        struct tm *timenow;
        time_t now = time(NULL);
        timenow = gmtime(&now);
        strftime(filename, sizeof(filename), PROXLOG, timenow);
        if (searchHomeFilePath(&my_logfile_path, LOGS_SUBDIR, filename, true) != PM3_SUCCESS) {
            printf(_YELLOW_("[-]") " Logging disabled!\n");
            my_logfile_path = NULL;
            logging = 0;
        } else {
            logfile = fopen(my_logfile_path, "a");
            if (logfile == NULL) {
                printf(_YELLOW_("[-]") " Can't open logfile %s, logging disabled!\n", my_logfile_path);
                logging = 0;
            } else {

                if (g_session.supports_colors) {
                    printf("["_YELLOW_("=")"] Session log " _YELLOW_("%s") "\n", my_logfile_path);
                } else {
                    printf("[=] Session log %s\n", my_logfile_path);
                }

            }
            free(my_logfile_path);
        }
    }


// If there is an incoming message from the hardware (eg: lf hid read) in
// the background (while the prompt is displayed and accepting user input),
// stash the prompt and bring it back later.
#ifdef RL_STATE_READCMD
    // We are using GNU readline. libedit (OSX) doesn't support this flag.
    int need_hack = (rl_readline_state & RL_STATE_READCMD) > 0;
    char *saved_line;
    int saved_point;

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
    if (strlen(buffer) > 0 && buffer[strlen(buffer) - 1] == NOLF[0]) {
        linefeed = false;
        buffer[strlen(buffer) - 1] = 0;
    }
    bool filter_ansi = !g_session.supports_colors;
    memcpy_filter_ansi(buffer2, buffer, sizeof(buffer), filter_ansi);
    if (g_printAndLog & PRINTANDLOG_PRINT) {
        memcpy_filter_emoji(buffer3, buffer2, sizeof(buffer2), g_session.emoji_mode);
        fprintf(stream, "%s", buffer3);
        if (linefeed)
            fprintf(stream, "\n");
    }

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

    if ((g_printAndLog & PRINTANDLOG_LOG) && logging && logfile) {
        memcpy_filter_emoji(buffer3, buffer2, sizeof(buffer2), EMO_ALTTEXT);
        if (filter_ansi) { // already done
            fprintf(logfile, "%s", buffer3);
        } else {
            memcpy_filter_ansi(buffer, buffer3, sizeof(buffer3), true);
            fprintf(logfile, "%s", buffer);
        }
        if (linefeed)
            fprintf(logfile, "\n");
        fflush(logfile);
    }

    if (flushAfterWrite)
        fflush(stdout);

    //release lock
    pthread_mutex_unlock(&g_print_lock);
}

void SetFlushAfterWrite(bool value) {
    flushAfterWrite = value;
}

bool GetFlushAfterWrite(void) {
    return flushAfterWrite;
}

void memcpy_filter_rlmarkers(void *dest, const void *src, size_t n) {
    uint8_t *rdest = (uint8_t *)dest;
    uint8_t *rsrc = (uint8_t *)src;
    uint16_t si = 0;
    for (size_t i = 0; i < n; i++) {
        if ((rsrc[i] == '\001') || (rsrc[i] == '\002'))
            // skip readline special markers
            continue;
        rdest[si++] = rsrc[i];
    }
}

void memcpy_filter_ansi(void *dest, const void *src, size_t n, bool filter) {
    if (filter) {
        // Filter out ANSI sequences on these OS
        uint8_t *rdest = (uint8_t *)dest;
        uint8_t *rsrc = (uint8_t *)src;
        uint16_t si = 0;
        for (size_t i = 0; i < n; i++) {
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

static bool emojify_token(const char *token, uint8_t token_length, const char **emojified_token, uint8_t *emojified_token_length, emojiMode_t mode) {
    int i = 0;
    while (EmojiTable[i].alias && EmojiTable[i].emoji) {
        if ((strlen(EmojiTable[i].alias) == token_length) && (0 == memcmp(EmojiTable[i].alias, token, token_length))) {
            switch (mode) {
                case EMO_EMOJI: {
                    *emojified_token = EmojiTable[i].emoji;
                    *emojified_token_length = strlen(EmojiTable[i].emoji);
                    break;
                }
                case EMO_ALTTEXT: {
                    int j = 0;
                    *emojified_token_length = 0;
                    while (EmojiAltTable[j].alias && EmojiAltTable[j].alttext) {
                        if ((strlen(EmojiAltTable[j].alias) == token_length) && (0 == memcmp(EmojiAltTable[j].alias, token, token_length))) {
                            *emojified_token = EmojiAltTable[j].alttext;
                            *emojified_token_length = strlen(EmojiAltTable[j].alttext);
                            break;
                        }
                        ++j;
                    }
                    break;
                }
                case EMO_NONE: {
                    *emojified_token_length = 0;
                    break;
                }
                case EMO_ALIAS: { // should never happen
                    return false;
                }
            }
            return true;
        }
        ++i;
    }
    return false;
}

static bool token_charset(uint8_t c) {
    if ((c >= '0') && (c <= '9')) return true;
    if ((c >= 'a') && (c <= 'z')) return true;
    if ((c >= 'A') && (c <= 'Z')) return true;
    if ((c == '_') || (c == '+') || (c == '-')) return true;
    return false;
}

void memcpy_filter_emoji(void *dest, const void *src, size_t n, emojiMode_t mode) {
    if (mode == EMO_ALIAS) {
        memcpy(dest, src, n);
    } else {
        // tokenize emoji
        const char *emojified_token = NULL;
        uint8_t emojified_token_length = 0;
        char *current_token = NULL;
        uint8_t current_token_length = 0;
        char *rdest = (char *)dest;
        char *rsrc = (char *)src;
        uint16_t si = 0;
        for (size_t i = 0; i < n; i++) {
            char current_char = rsrc[i];

            if (current_token_length == 0) {
                // starting a new token.
                if (current_char == ':') {
                    current_token = rsrc + i;
                    current_token_length = 1;
                } else { // not starting a new token.
                    rdest[si++] = current_char;
                }
            } else {
                // finishing the current token.
                if (current_char == ':') {
                    // nothing changed? we still need the ending ':' as it might serve for an upcoming emoji
                    if (! emojify_token(current_token, current_token_length + 1, &emojified_token, &emojified_token_length, mode)) {
                        memcpy(rdest + si, current_token, current_token_length);
                        si += current_token_length;
                        current_token = rsrc + i;
                        current_token_length = 1;
                    } else {
                        memcpy(rdest + si, emojified_token, emojified_token_length);
                        si += emojified_token_length;
                        current_token_length = 0;
                    }
                } else if (token_charset(current_char)) { // continuing the current token.
                    current_token_length++;
                } else { // dropping the current token.
                    current_token_length++;
                    memcpy(rdest + si, current_token, current_token_length);
                    si += current_token_length;
                    current_token_length = 0;
                }
            }
        }
        if (current_token_length > 0) {
            memcpy(rdest + si, current_token, current_token_length);
        }
    }
}

/*
// If reactivated, beware it doesn't compile on Android (DXL)
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
*/

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

void print_progress(size_t count, uint64_t max, barMode_t style) {
    int cols = 100 + 35;
#if defined(HAVE_READLINE)
    static int prev_cols = 0;
    int rows;
    rl_reset_screen_size(); // refresh Readline idea of the actual screen width
    rl_get_screen_size(&rows, &cols);

    if (cols < 36)
        return;

    (void) rows;
    if (prev_cols > cols) {
        PrintAndLogEx(NORMAL, _CLEAR_ _TOP_ "");
    }
    prev_cols = cols;
#endif
    int width = cols - 35;

#define PERCENTAGE(V, T)   ((V * width) / T)
    // x/8 fractional part of the percentage
#define PERCENTAGEFRAC(V, T)   ((uint8_t)(((((float)V * width) / T) - ((V * width) / T)) * 8))

    const char *smoothtable[] = {
        "\xe2\x80\x80",
        "\xe2\x96\x8F",
        "\xe2\x96\x8E",
        "\xe2\x96\x8D",
        "\xe2\x96\x8C",
        "\xe2\x96\x8B",
        "\xe2\x96\x8A",
        "\xe2\x96\x89",
        "\xe2\x96\x88",
    };

    int mode = (g_session.emoji_mode == EMO_EMOJI);

    const char *block[] = {"#", "\xe2\x96\x88"};
    // use a 3-byte space in emoji mode to ease computations
    const char *space[] = {" ", "\xe2\x80\x80"};

    size_t unit = strlen(block[mode]);
    // +1 for \0
    char *bar = (char *)calloc(unit * width + 1, sizeof(uint8_t));

    uint8_t value = PERCENTAGE(count, max);

    int i = 0;
    // prefix is added already.
    for (; i < unit * value; i += unit) {
        memcpy(bar + i, block[mode], unit);
    }
    // add last block
    if (mode == 1) {
        memcpy(bar + i, smoothtable[PERCENTAGEFRAC(count, max)], unit);
    } else {
        memcpy(bar + i, space[mode], unit);
    }
    i += unit;
    // add spaces
    for (; i < unit * width; i += unit) {
        memcpy(bar + i, space[mode], unit);
    }
    // color buffer
    size_t collen = strlen(bar) + 40;
    char *cbar = (char *)calloc(collen, sizeof(uint8_t));

    // Add colors
    if (g_session.supports_colors) {
        int p60 = unit * (width * 60 / 100);
        int p20 = unit * (width * 20 / 100);
        snprintf(cbar,  collen,  _GREEN_("%.*s"), p60, bar);
        snprintf(cbar + strlen(cbar), collen - strlen(cbar), _CYAN_("%.*s"), p20,  bar + p60);
        snprintf(cbar + strlen(cbar), collen - strlen(cbar), _YELLOW_("%.*s"), (int)(unit * width - p60 - p20), bar + p60 + p20);
    } else {
        snprintf(cbar,  collen,  "%s", bar);
    }

    switch (style) {
        case STYLE_BAR: {
            printf("\b%c[2K\r[" _YELLOW_("=")"] %s", 27, cbar);
            break;
        }
        case STYLE_MIXED: {
            printf("\b%c[2K\r[" _YELLOW_("=")"] %s [ %zu mV / %2u V / %2u Vmax ]", 27, cbar, count, (uint32_t)(count / 1000), (uint32_t)(max / 1000));
            break;
        }
        case STYLE_VALUE: {
            printf("[" _YELLOW_("=")"] %zu mV / %2u V / %2u Vmax   \r", count, (uint32_t)(count / 1000), (uint32_t)(max / 1000));
            break;
        }
    }
    fflush(stdout);
    free(bar);
    free(cbar);
}
