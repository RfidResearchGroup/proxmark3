//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency ISO15693 commands
//-----------------------------------------------------------------------------

#ifndef CMDHF15_H__
#define CMDHF15_H__

int CmdHF15(const char *Cmd);

extern int CmdHF15Demod(const char *Cmd);
extern int CmdHF15Read(const char *Cmd);
extern int CmdHF15Info(const char *Cmd);
extern int CmdHF15Record(const char *Cmd);
extern int HF15Reader(const char *Cmd, bool verbose);
extern int CmdHF15Reader(const char *Cmd);
extern int CmdHF15Sim(const char *Cmd);
extern int CmdHF15Cmd(const char*Cmd);
extern int CmdHF15Afi(const char *Cmd);
extern int CmdHF15DumpMem(const char*Cmd);
extern int CmdHF15CmdDebug( const char *Cmd);

// cmd sub.
extern int CmdHF15CmdRaw(const char *cmd);
extern int CmdHF15CmdReadmulti(const char *Cmd);
extern int CmdHF15CmdRead(const char *Cmd);
extern int CmdHF15CmdWrite(const char *Cmd);

extern int CmdHF15CmdHelp(const char*Cmd);
extern int CmdHF15Help(const char*Cmd);

extern int prepareHF15Cmd(char **cmd, UsbCommand *c, uint8_t iso15cmd);
#endif
