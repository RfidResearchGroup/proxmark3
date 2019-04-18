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

static int CmdHelp(const char *Cmd);

static int CmdRem(const char *Cmd) {
    char buf[22] = {0};
    struct tm *ct, tm_buf;
    time_t now = time(NULL);
#if defined(_WIN32)
    ct = gmtime_s(&tm_buf, &now) == 0 ? &tm_buf : NULL;
#else
    ct = gmtime_r(&now, &tm_buf);
#endif
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", ct);  // ISO8601
    PrintAndLogEx(NORMAL, "%s remark: %s", buf, Cmd);
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
    {"help",    CmdHelp,      1, "This help. Use '<command> help' for details of a particular command."},
    {"analyse", CmdAnalyse,   1, "{ Analyse utils... }"},
    {"data",    CmdData,      1, "{ Plot window / data buffer manipulation... }"},
    {"hf",      CmdHF,        1, "{ High Frequency commands... }"},
    {"hw",      CmdHW,        1, "{ Hardware commands... }"},
    {"lf",      CmdLF,        1, "{ Low Frequency commands... }"},
    {"emv",     CmdEMV,       1, "{ EMV iso14443 and iso7816... }"},
    {"rem",     CmdRem,       1, "{ Add text to row in log file }"},
    {"reveng",  CmdRev,       1, "{ Crc calculations from the RevEng software... }"},
    {"script",  CmdScript,    1, "{ Scripting commands }"},
    {"trace",   CmdTrace,     1, "{ Trace manipulation... }"},
#ifdef WITH_FLASH
    {"mem",     CmdFlashMem,  1, "{ Flash Memory manipulation... }"},
#endif
#ifdef WITH_SMARTCARD
    {"sc",      CmdSmartcard, 1, "{ Smart card ISO7816 commands... }"},
#endif
    {"quit",    CmdQuit,      1, ""},
    {"exit",    CmdQuit,      1, "Exit program"},
    {NULL, NULL, 0, NULL}
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

