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
// Command parser
//-----------------------------------------------------------------------------

#ifndef CMDPARSER_H__
#define CMDPARSER_H__

#include "common.h"

#define MAX_PM3_INPUT_ARGS_LENGTH    4096

typedef struct command_s {
    const char *Name;
    int (*Parse)(const char *Cmd);
    bool (*IsAvailable)(void);
    const char *Help;
} command_t;
// command_t array are expected to be NULL terminated

// Maximum nesting depth of the command tree supported by walkCommandsRecursive()
#define CMD_WALK_MAX_DEPTH 8

// Called by walkCommandsRecursive() for each leaf command.
// path[0..depth-1] are the command_t entries from the top level category
// down to the leaf command itself (path[depth-1]).
typedef void (*command_visitor_t)(const command_t *const path[], size_t depth, void *ctx);

// helpers for command_t IsAvailable
bool AlwaysAvailable(void);
bool IfClientDebugEnabled(void);
bool IfPm3Present(void);
bool IfPm3Rdv4Fw(void);
bool IfPm3Flash(void);
bool IfPm3Smartcard(void);
bool IfPm3FpcUsart(void);
bool IfPm3FpcUsartHost(void);
bool IfPm3FpcUsartHostFromUsb(void);
bool IfPm3FpcUsartDevFromUsb(void);
bool IfPm3FpcUsartFromUsb(void);
bool IfPm5(void);
bool IfPm5StdAnt(void);
bool IfFpgaFlash(void);
bool IfI2cEeprom(void);
bool IfPm3Lf(void);
bool IfPm3Hitag(void);
bool IfPm3EM4x50(void);
bool IfPm3EM4x70(void);
bool IfPm3Hfsniff(void);
bool IfPm3Hfplot(void);
bool IfPm3Iso14443a(void);
bool IfPm3Iso14443b(void);
bool IfPm3Iso14443(void);
bool IfPm3Iso15693(void);
bool IfPm3Felica(void);
bool IfPm3Legicrf(void);
bool IfPm3Iclass(void);
bool IfPm3Seos(void);
bool IfPm3NfcBarcode(void);
bool IfPm3Lcd(void);
bool IfPm3Zx8211(void);

// Print help for each command in the command array
void CmdsHelp(const command_t Commands[]);
// Print each command in the command array without help
void CmdsLS(const command_t Commands[]);
// Parse a command line
int CmdsParse(const command_t Commands[], const char *Cmd);
void dumpCommandsRecursive(const command_t cmds[], int markdown, bool full_help);
// Walk the command tree, calling visitor for every leaf command
void walkCommandsRecursive(const command_t cmds[], command_visitor_t visitor, void *ctx);

#endif
