//-----------------------------------------------------------------------------
// Copyright (C) 2012 nuit
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency MIFARE DESfire commands
//-----------------------------------------------------------------------------

#include "cmdhfdes.h"
#include "proxmark3.h"
#include "cmdmain.h"

static int CmdHelp(const char *Cmd);

int CmdHFDESReader(const char *Cmd)
{
    UsbCommand c  ={CMD_MIFARE_DES_READER, {3, 0x60, 0}};
    SendCommand(&c);

    UsbCommand resp;
	WaitForResponseTimeout(CMD_ACK,&resp,2000);
    return 0;
}  

int CmdHFDESDbg(const char *Cmd)
{
    int dbgMode = param_get32ex(Cmd, 0, 0, 10);
    if (dbgMode > 4) {
        PrintAndLog("Max debud mode parameter is 4 \n");
    }

    if (strlen(Cmd) < 1 || !param_getchar(Cmd, 0) || dbgMode > 4) {
        PrintAndLog("Usage:  hf des dbg  <debug level>");
        PrintAndLog(" 0 - no debug messages");
        PrintAndLog(" 1 - error messages");
        PrintAndLog(" 2 - all messages");
        PrintAndLog(" 4 - extended debug mode");
        return 0;
    }

  UsbCommand c = {CMD_MIFARE_SET_DBGMODE, {dbgMode, 0, 0}};
  SendCommand(&c);

  return 0;
}

static command_t CommandTable[] = 
{
    {"help",    CmdHelp,    1,  "This help"},
    {"dbg",     CmdHFDESDbg, 0, "Set default debug mode"},
    {"reader",  CmdHFDESReader, 0, "Reader"},
  {NULL, NULL, 0, NULL}
};

int CmdHFDES(const char *Cmd)
{
    //flush
    WaitForResponseTimeout(CMD_ACK,NULL,100);
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd)
{
    CmdsHelp(CommandTable);
    return 0;
}
