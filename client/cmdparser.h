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

typedef struct command_s
{
  const char * Name;
  int (*Parse)(const char *Cmd);
  int Offline;
  const char * Help;
} command_t;

// command_t array are expected to be NULL terminated

// Print help for each command in the command array
void CmdsHelp(const command_t Commands[]);
// Print each command in the command array without help
void CmdsLS(const command_t Commands[]);
// Parse a command line
int CmdsParse(const command_t Commands[], const char *Cmd);
void dumpCommandsRecursive(const command_t cmds[], int markdown);

#endif
