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
    {"help",    CmdHelp,      AlwaysAvailable,         "This help. Use '<command> help' for details of a particular command."},
    {"analyse", CmdAnalyse,   AlwaysAvailable,         "{ Analyse utils... }"},
    {"data",    CmdData,      AlwaysAvailable,         "{ Plot window / data buffer manipulation... }"},
    {"emv",     CmdEMV,       AlwaysAvailable,         "{ EMV iso14443 and iso7816... }"},
    {"hf",      CmdHF,        AlwaysAvailable,         "{ High Frequency commands... }"},
    {"hw",      CmdHW,        AlwaysAvailable,         "{ Hardware commands... }"},
    {"lf",      CmdLF,        AlwaysAvailable,         "{ Low Frequency commands... }"},
    {"mem",     CmdFlashMem,  IfPm3Flash,              "{ Flash Memory manipulation... }"},
    {"rem",     CmdRem,       AlwaysAvailable,         "{ Add text to row in log file }"},
    {"reveng",  CmdRev,       AlwaysAvailable,         "{ Crc calculations from the RevEng software... }"},
    {"sc",      CmdSmartcard, IfPm3Smartcard,          "{ Smart card ISO7816 commands... }"},
    {"script",  CmdScript,    AlwaysAvailable,         "{ Scripting commands }"},
    {"trace",   CmdTrace,     AlwaysAvailable,         "{ Trace manipulation... }"},
    {"usart",   CmdUsart,     IfPm3FpcUsartDevFromUsb, "{ USART commands... }"},
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

