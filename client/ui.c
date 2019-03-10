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

#include "ui.h"

double CursorScaleFactor = 1;
int PlotGridX = 0, PlotGridY = 0, PlotGridXdefault = 64, PlotGridYdefault = 64, CursorCPos = 0, CursorDPos = 0;
bool flushAfterWrite = 0;
int GridOffset = 0;
bool GridLocked = false;
bool showDemod = true;

pthread_mutex_t print_lock = PTHREAD_MUTEX_INITIALIZER;
static char *logfilename = "proxmark3.log";

void PrintAndLogOptions(char *str[][2], size_t size, size_t space) {
    char buff[2000] = "Options:\n";
    char format[2000] = "";
    size_t counts[2] = {0, 0};
    for (int i = 0; i < size; i++)
        for (int j = 0 ; j < 2 ; j++)
            if (counts[j] < strlen(str[i][j])) {
                counts[j] = strlen(str[i][j]);
            }
    for (int i = 0; i < size; i++) {
        for (int j = 0; j < 2; j++) {
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
void PrintAndLogEx(logLevel_t level, char *fmt, ...) {

    // skip debug messages if client debugging is turned off i.e. 'DATA SETDEBUG 0'
    if (g_debugMode == 0 && level == DEBUG)
        return;

    char prefix[20] = {0};
    char buffer[MAX_PRINT_BUFFER] = {0};
    char buffer2[MAX_PRINT_BUFFER + 20] = {0};
    char *token = NULL;
    int size = 0;
    //   {NORMAL, SUCCESS, INFO, FAILED, WARNING, ERR, DEBUG}
    static char *prefixes[7] = { "", "[+] ", "[=] ", "[-] ", "[!] ", "[!!] ", "[#] "};

    switch (level) {
        case ERR:
            strncpy(prefix, _RED_("[!!]"), sizeof(prefix) - 1);
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
        default:
            strncpy(prefix, prefixes[level], sizeof(prefix) - 1);
            break;
    }

    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    // no prefixes for normal
    if (level == NORMAL) {
        PrintAndLog("%s", buffer);
        return;
    }

    if (strchr(buffer, '\n')) {

        const char delim[2] = "\n";

        // line starts with newline
        if (buffer[0] == '\n')
            PrintAndLog("");

        token = strtok(buffer, delim);

        while (token != NULL) {

            size = strlen(buffer2);

            if (strlen(token))
                snprintf(buffer2 + size, sizeof(buffer2) - size, "%s%s\n", prefix, token);
            else
                snprintf(buffer2 + size, sizeof(buffer2) - size, "\n");

            token = strtok(NULL, delim);
        }
        PrintAndLog("%s", buffer2);
    } else {
        snprintf(buffer2, sizeof(buffer2), "%s%s", prefix, buffer);
        PrintAndLog("%s", buffer2);
    }
}

void PrintAndLog(char *fmt, ...) {
    char *saved_line;
    int saved_point;
    va_list argptr, argptr2;
    static FILE *logfile = NULL;
    static int logging = 1;

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
    va_copy(argptr2, argptr);
    vprintf(fmt, argptr);
    printf("          "); // cleaning prompt
    va_end(argptr);
    printf("\n");

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
        vfprintf(logfile, fmt, argptr2);
        fprintf(logfile, "\n");
        fflush(logfile);
    }
    va_end(argptr2);

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

void iceIIR_Butterworth(int *data, const size_t len) {

    int i, j;

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

    float sample           = 0;      // input sample read from array
    float complex x_prime  = 1.0f;   // save sample for estimating frequency
    float complex x;

    for (i = 0; i < adjustedLen; ++i) {

        sample = data[i];

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
    for (j = 0; j < adjustedLen; ++j)
        data[j] = output[j];

    free(output);
}

void iceSimple_Filter(int *data, const size_t len, uint8_t k) {
// ref: http://www.edn.com/design/systems-design/4320010/A-simple-software-lowpass-filter-suits-embedded-system-applications
// parameter K
#define FILTER_SHIFT 4

    int32_t filter_reg = 0;
    int16_t input, output;
    int8_t shift = (k <= 8) ? k : FILTER_SHIFT;

    for (int i = 0; i < len; ++i) {

        input = data[i];
        // Update filter with current sample
        filter_reg = filter_reg - (filter_reg >> shift) + input;

        // Scale output for unity gain
        output = filter_reg >> shift;
        data[i] = output;
    }
}

float complex cexpf(float complex Z) {
    float complex  Res;
    double rho = exp(__real__ Z);
    __real__ Res = rho * cosf(__imag__ Z);
    __imag__ Res = rho * sinf(__imag__ Z);
    return Res;
}
