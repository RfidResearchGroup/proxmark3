//-----------------------------------------------------------------------------
// Copyright (C) 2012 Chalk <chalk.secu at gmail.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency PCF7931 commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>
#include "proxusb.h"
#include "ui.h"
#include "graph.h"
#include "cmdparser.h"
#include "cmddata.h"
#include "cmdmain.h"
#include "cmdlf.h"
#include "cmdlfpcf7931.h"

static int CmdHelp(const char *Cmd);

int CmdLFPCF7931Read(const char *Cmd)
{
  UsbCommand c = {CMD_PCF7931_READ};
  SendCommand(&c);
  WaitForResponse(CMD_ACK);
  return 0;
}

static command_t CommandTable[] = 
{
  {"help", CmdHelp, 1, "This help"},
  {"read", CmdLFPCF7931Read, 1, "Read content of a PCF7931 transponder"},
  {NULL, NULL, 0, NULL}
};

int CmdLFPCF7931(const char *Cmd)
{
  CmdsParse(CommandTable, Cmd);
  return 0;
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}
