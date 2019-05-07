//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Command parser
//-----------------------------------------------------------------------------

#ifndef CMDPARSER_H__
#define CMDPARSER_H__

typedef struct command_s {
    const char *Name;
    int (*Parse)(const char *Cmd);
    bool (*IsAvailable)(void);
    const char *Help;
} command_t;
// command_t array are expected to be NULL terminated

// helpers for command_t IsAvailable
bool AlwaysAvailable(void);
bool IfPm3Present(void);
bool IfPm3Flash(void);
bool IfPm3Smartcard(void);
bool IfPm3FpcUsart(void);
bool IfPm3FpcUsartHost(void);
bool IfPm3FpcUsartHostFromUsb(void);
bool IfPm3FpcUsartDevFromUsb(void);
bool IfPm3Lf(void);
bool IfPm3Hitag(void);
bool IfPm3Hfsniff(void);
bool IfPm3Iso14443a(void);
bool IfPm3Iso14443b(void);
bool IfPm3Iso14443(void);
bool IfPm3Iso15693(void);
bool IfPm3Felica(void);
bool IfPm3Legicrf(void);
bool IfPm3Iclass(void);
bool IfPm3Lcd(void);

// Print help for each command in the command array
void CmdsHelp(const command_t Commands[]);
// Print each command in the command array without help
void CmdsLS(const command_t Commands[]);
// Parse a command line
int CmdsParse(const command_t Commands[], const char *Cmd);
void dumpCommandsRecursive(const command_t cmds[], int markdown);

#endif
