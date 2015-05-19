//-----------------------------------------------------------------------------
// Copyright (C) 2015 iceman <iceman at iuse.se>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// CRC Calculations from the software reveng commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>
#include "cmdparser.h"
#include "cmdcrc.h"
//#include "reveng/reveng.h"
//#include "reveng/cli.h"
static int CmdHelp(const char *Cmd);

int CmdCrcCalc(const char *Cmd)
{
	//pm3main(Cmd);
	return 0;
}

static command_t CommandTable[] = 
{
	{"help",	CmdHelp,	1, "This help"},
	{"calc",	CmdCrcCalc,	1, "{ Calculate CRC's }"},
	{NULL, NULL, 0, NULL}
};

int CmdCrc(const char *Cmd)
{
  CmdsParse(CommandTable, Cmd);
  return 0; 
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}
