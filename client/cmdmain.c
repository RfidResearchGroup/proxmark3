//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// Modified 2018 iceman <iceman at iuse.se>
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
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
#include <time.h> // MingW
#include <stdlib.h>  // calloc

#include "comms.h"
#include "cmdhf.h"
#include "cmddata.h"
#include "cmdhw.h"
#include "cmdlf.h"
#include "cmdtrace.h"
#include "cmdscript.h"
#include "cmdcrc.h"
#include "cmdanalyse.h"
#include "emv/cmdemv.h"   // EMV
#include "cmdflashmem.h"  // rdv40 flashmem commands
#include "cmdsmartcard.h" // rdv40 smart card ISO7816 commands
#include "cmdusart.h"     // rdv40 FPC USART commands
#include "cmdwiegand.h"   // wiegand commands
#include "ui.h"
#include "util_posix.h"

static int CmdHelp(const char *Cmd);

static int usage_msleep(void) {
    PrintAndLogEx(NORMAL, "Sleep for given amount of milliseconds");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  msleep <ms>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h          This help");
    PrintAndLogEx(NORMAL, "       <ms>       time in milliseconds");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       msleep 100");
    return PM3_SUCCESS;
}

static int usage_auto(void) {
    PrintAndLogEx(NORMAL, "Run LF SEARCH / HF SEARCH / DATA PLOT / DATA SAVE ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  auto <ms>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h          This help");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       auto");
    return PM3_SUCCESS;
}

static void AppendDate(char *s, size_t slen, char *fmt) {
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

static int CmdAuto(const char *Cmd) {
    char ctmp = tolower(param_getchar(Cmd, 0));
    if (ctmp == 'h') return usage_auto();

    int ret = CmdLFfind("");
    if (ret == PM3_SUCCESS)
        return ret;

    ret = CmdHFSearch("");
    if (ret == PM3_SUCCESS)
        return ret;

    PrintAndLogEx(INFO, "Failed both LF / HF SEARCH,");
    PrintAndLogEx(INFO, "Trying 'lf read' and save a trace for you...");

    CmdPlot("");
    lf_read(false, 40000);
    char *fname = calloc(100, sizeof(uint8_t));
    AppendDate(fname, 100, "f lf_unknown_%Y-%m-%d_%H:%M");
    CmdSave(fname);
    free(fname);
    return PM3_SUCCESS;
}

int CmdRem(const char *Cmd) {
    char buf[22] = {0};
    AppendDate(buf, sizeof(buf), NULL);
    PrintAndLogEx(NORMAL, "%s remark: %s", buf, Cmd);
    return PM3_SUCCESS;
}

static int CmdMsleep(const char *Cmd) {
    uint32_t ms = 0;
    char ctmp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 1 || ctmp == 'h') return usage_msleep();
    if (param_getchar(Cmd, 0) != 0x00) {
        ms = param_get32ex(Cmd, 0, 0, 10);
        if (ms == 0)
            return usage_msleep();
    }
    msleep(ms);
    return PM3_SUCCESS;
}

static int CmdQuit(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    return PM3_EFATAL;
}

static int CmdRev(const char *Cmd) {
    CmdCrc(Cmd);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,      AlwaysAvailable,         "This help. Use '<command> help' for details of a particular command."},
    {"auto",    CmdAuto,      IfPm3Present,           "Automated detection process for unknown tags"},
    {"analyse", CmdAnalyse,   AlwaysAvailable,         "{ Analyse utils... }"},
    {"data",    CmdData,      AlwaysAvailable,         "{ Plot window / data buffer manipulation... }"},
    {"emv",     CmdEMV,       AlwaysAvailable,         "{ EMV ISO-14443 / ISO-7816... }"},
    {"hf",      CmdHF,        AlwaysAvailable,         "{ High frequency commands... }"},
    {"hw",      CmdHW,        AlwaysAvailable,         "{ Hardware commands... }"},
    {"lf",      CmdLF,        AlwaysAvailable,         "{ Low frequency commands... }"},
    {"mem",     CmdFlashMem,  IfPm3Flash,              "{ Flash Memory manipulation... }"},
    {"reveng",  CmdRev,       AlwaysAvailable,         "{ CRC calculations from RevEng software }"},
    {"sc",      CmdSmartcard, IfPm3Smartcard,          "{ Smart card ISO-7816 commands... }"},
    {"script",  CmdScript,    AlwaysAvailable,         "{ Scripting commands }"},
    {"trace",   CmdTrace,     AlwaysAvailable,         "{ Trace manipulation... }"},
    {"usart",   CmdUsart,     IfPm3FpcUsartFromUsb,    "{ USART commands... }"},
    {"wiegand", CmdWiegand,   AlwaysAvailable,         "{ Wiegand format manipulation... }"},
    {"",        CmdHelp,      AlwaysAvailable,         ""},
    {"msleep",  CmdMsleep,    AlwaysAvailable,         "Add a pause in milliseconds"},
    {"rem",     CmdRem,       AlwaysAvailable,         "Add a text line in log file"},
    {"quit",    CmdQuit,      AlwaysAvailable,         ""},
    {"exit",    CmdQuit,      AlwaysAvailable,         "Exit program"},
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
int CommandReceived(char *Cmd) {
    return CmdsParse(CommandTable, Cmd);
}

command_t *getTopLevelCommandTable() {
    return CommandTable;
}

