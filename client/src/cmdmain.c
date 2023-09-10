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
// Main command parser entry point
//-----------------------------------------------------------------------------

// ensure gmtime_r is available even with -std=c99; must be included before
#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200112L
#endif
#include "cmdmain.h"

#include <string.h>
#include <ctype.h>
#include <time.h>    // MingW
#include <stdlib.h>  // calloc

#include "comms.h"
#include "cmdhf.h"
#include "cmddata.h"
#include "cmdhw.h"
#include "cmdlf.h"
#include "cmdnfc.h"
#include "cmdtrace.h"
#include "cmdscript.h"
#include "cmdcrc.h"
#include "cmdanalyse.h"
#include "emv/cmdemv.h"   // EMV
#include "cmdflashmem.h"  // rdv40 flashmem commands
#include "cmdpiv.h"
#include "cmdsmartcard.h" // rdv40 smart card ISO7816 commands
#include "cmdusart.h"     // rdv40 FPC USART commands
#include "cmdwiegand.h"   // wiegand commands
#include "ui.h"
#include "util_posix.h"
#include "commonutil.h"   // ARRAYLEN
#include "preferences.h"
#include "cliparser.h"

static int CmdHelp(const char *Cmd);

static void AppendDate(char *s, size_t slen, const char *fmt) {
    struct tm *ct, tm_buf;
    time_t now = time(NULL);
#if defined(_WIN32)
    ct = gmtime_s(&tm_buf, &now) == 0 ? &tm_buf : NULL;
#else
    ct = gmtime_r(&now, &tm_buf);
#endif
    if (fmt == NULL)
        strftime(s, slen, "%Y-%m-%dT%H:%M:%SZ", ct);  // ISO8601
    else
        strftime(s, slen, fmt, ct);
}

static int lf_search_plus(const char *Cmd) {

    sample_config oldconfig;
    memset(&oldconfig, 0, sizeof(sample_config));

    int retval = lf_getconfig(&oldconfig);

    if (retval != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "failed to get current device config");
        return retval;
    }

    // Divisor : frequency(khz)
    // 95      88      47      31      23
    // 125.00  134.83  250.00  375.00  500.00

    int16_t default_divisor[] = {95, 88, 47, 31, 23};

    /*
      default LF config is set to:
      decimation = 1
      bits_per_sample = 8
      averaging = YES
      divisor = 95 (125kHz)
      trigger_threshold = 0
      samples_to_skip = 0
      verbose = YES
    */
    sample_config config = {
        .decimation = 1,
        .bits_per_sample = 8,
        .averaging = 1,
        .trigger_threshold = 0,
        .samples_to_skip = 0,
        .verbose = false
    };

    // Iteration defaults
    for (int i = 0; i < ARRAYLEN(default_divisor); ++i) {

        if (kbd_enter_pressed()) {
            PrintAndLogEx(INFO, "Keyboard pressed. Done.");
            break;
        }
        // Try to change config!
        uint32_t d;
        d = config.divisor = default_divisor[i];
        PrintAndLogEx(INFO, "-->  trying  ( " _GREEN_("%d.%02d kHz")" )", 12000 / (d + 1), ((1200000 + (d + 1) / 2) / (d + 1)) - ((12000 / (d + 1)) * 100));

        retval = lf_config(&config);
        if (retval != PM3_SUCCESS)
            break;

        // The config for pm3 is changed, we can trying search!
        retval = CmdLFfind(Cmd);
        if (retval == PM3_SUCCESS)
            break;

    }

    lf_config(&oldconfig);
    return retval;
}

static int CmdAuto(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "auto",
                  "Run LF SEARCH / HF SEARCH / DATA PLOT / DATA SAVE",
                  "auto"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("c", NULL, "Continue searching even after a first hit"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool exit_first = (arg_get_lit(ctx, 1) == false);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "lf search");
    int ret = CmdLFfind("");
    if (ret == PM3_SUCCESS && exit_first)
        return ret;

    PrintAndLogEx(INFO, "hf search");
    ret = CmdHFSearch("");
    if (ret == PM3_SUCCESS && exit_first)
        return ret;

    PrintAndLogEx(INFO, "lf search - unknown");
    ret = lf_search_plus("");
    if (ret == PM3_SUCCESS && exit_first)
        return ret;

    if (ret != PM3_SUCCESS)
        PrintAndLogEx(INFO, "Failed both LF / HF SEARCH,");

    PrintAndLogEx(INFO, "Trying " _YELLOW_("`lf read`") " and save a trace for you");

    CmdPlot("");
    lf_read(false, 40000);
    char *fname = calloc(100, sizeof(uint8_t));
    AppendDate(fname, 100, "-f lf_unknown_%Y-%m-%d_%H:%M");
    CmdSave(fname);
    free(fname);
    return PM3_SUCCESS;
}

int CmdRem(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "rem",
                  "Add a text line in log file",
                  "rem my message    -> adds a timestamp with `my message`"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_strx1(NULL, NULL, NULL, "message line you want inserted"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    struct arg_str *foo = arg_get_str(ctx, 1);
    size_t count = 0;
    size_t len = 0;
    do {
        count += strlen(foo->sval[len]);
    } while (len++ < (foo->count - 1));

    char s[count + foo->count];
    memset(s, 0, sizeof(s));

    len = 0;
    do {
        snprintf(s + strlen(s), sizeof(s) - strlen(s), "%s ", foo->sval[len]);
    } while (len++ < (foo->count - 1));

    CLIParserFree(ctx);
    char buf[22] = {0};
    AppendDate(buf, sizeof(buf), NULL);
    PrintAndLogEx(SUCCESS, "%s remark: %s", buf, s);
    return PM3_SUCCESS;
}

static int CmdHints(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hints",
                  "Turn on/off hints",
                  "hints --on\n"
                  "hints -1\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("1", "on", "turn on hints"),
        arg_lit0("0", "off", "turn off hints"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool turn_on = arg_get_lit(ctx, 1);
    bool turn_off = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    if (turn_on && turn_off) {
        PrintAndLogEx(ERR, "you can't turn off and on at the same time");
        return PM3_EINVARG;
    }

    if (turn_off) {
        g_session.show_hints = false;
    } else if (turn_on) {
        g_session.show_hints = true;
    }

    PrintAndLogEx(INFO, "Hints are %s", (g_session.show_hints) ? "ON" : "OFF");
    return PM3_SUCCESS;
}

static int CmdMsleep(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "msleep",
                  "Sleep for given amount of milliseconds",
                  "msleep -t 100"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("t", "ms", "<ms>", "time in milliseconds"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    uint32_t ms = arg_get_u32_def(ctx, 1, 0);
    CLIParserFree(ctx);

    if (ms == 0) {
        PrintAndLogEx(ERR, "Specified invalid input. Can't be zero");
        return PM3_EINVARG;
    }

    msleep(ms);
    return PM3_SUCCESS;
}

static int CmdQuit(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "quit",
                  "Quit the Proxmark3 client terminal",
                  "quit"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return PM3_SQUIT;
}

static int CmdRev(const char *Cmd) {
    CmdCrc(Cmd);
    return PM3_SUCCESS;
}

static int CmdPref(const char *Cmd) {
    CmdPreferences(Cmd);
    return PM3_SUCCESS;
}

static int CmdClear(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "clear",
                  "Clear the Proxmark3 client terminal screen",
                  "clear      -> clear the terminal screen\n"
                  "clear -b   -> clear the terminal screen and the scrollback buffer"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("b", "back", "also clear the scrollback buffer"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool scrollback = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    if (!scrollback)
        PrintAndLogEx(NORMAL, _CLEAR_ _TOP_ "");
    else
        PrintAndLogEx(NORMAL, _CLEAR_ _TOP_ _CLEAR_SCROLLBACK_ "");

    return PM3_SUCCESS;
}

static command_t CommandTable[] = {

    {"help",         CmdHelp,      AlwaysAvailable,         "Use `" _YELLOW_("<command> help") "` for details of a command"},
    {"prefs",        CmdPref,      AlwaysAvailable,         "{ Edit client/device preferences... }"},
    {"--------",     CmdHelp,      AlwaysAvailable,         "----------------------- " _CYAN_("Technology") " -----------------------"},
    {"analyse",      CmdAnalyse,   AlwaysAvailable,         "{ Analyse utils... }"},
    {"data",         CmdData,      AlwaysAvailable,         "{ Plot window / data buffer manipulation... }"},
    {"emv",          CmdEMV,       AlwaysAvailable,         "{ EMV ISO-14443 / ISO-7816... }"},
    {"hf",           CmdHF,        AlwaysAvailable,         "{ High frequency commands... }"},
    {"hw",           CmdHW,        AlwaysAvailable,         "{ Hardware commands... }"},
    {"lf",           CmdLF,        AlwaysAvailable,         "{ Low frequency commands... }"},
    {"mem",          CmdFlashMem,  IfPm3Flash,              "{ Flash memory manipulation... }"},
    {"nfc",          CmdNFC,       AlwaysAvailable,         "{ NFC commands... }"},
    {"piv",          CmdPIV,       AlwaysAvailable,         "{ PIV commands... }"},
    {"reveng",       CmdRev,       AlwaysAvailable,         "{ CRC calculations from RevEng software... }"},
    {"smart",        CmdSmartcard, AlwaysAvailable,         "{ Smart card ISO-7816 commands... }"},
    {"script",       CmdScript,    AlwaysAvailable,         "{ Scripting commands... }"},
    {"trace",        CmdTrace,     AlwaysAvailable,         "{ Trace manipulation... }"},
    {"usart",        CmdUsart,     IfPm3FpcUsartFromUsb,    "{ USART commands... }"},
    {"wiegand",      CmdWiegand,   AlwaysAvailable,         "{ Wiegand format manipulation... }"},
    {"--------",     CmdHelp,      AlwaysAvailable,         "----------------------- " _CYAN_("General") " -----------------------"},
    {"auto",         CmdAuto,      IfPm3Present,            "Automated detection process for unknown tags"},
    {"clear",        CmdClear,     AlwaysAvailable,         "Clear screen"},
    {"hints",        CmdHints,     AlwaysAvailable,         "Turn hints on / off"},
    {"msleep",       CmdMsleep,    AlwaysAvailable,         "Add a pause in milliseconds"},
    {"rem",          CmdRem,       AlwaysAvailable,         "Add a text line in log file"},
    {"quit",         CmdQuit,      AlwaysAvailable,         ""},
    {"exit",         CmdQuit,      AlwaysAvailable,         "Exit program"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

//-----------------------------------------------------------------------------
// Entry point into our code: called whenever the user types a command and
// then presses Enter, which the full command line that they typed.
//-----------------------------------------------------------------------------
int CommandReceived(const char *Cmd) {
    return CmdsParse(CommandTable, Cmd);
}

command_t *getTopLevelCommandTable(void) {
    return CommandTable;
}

