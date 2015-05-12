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

int CmdHF15Demod(const char *Cmd);
int CmdHF15Read(const char *Cmd);
int HF15Reader(const char *Cmd, bool verbose);
int CmdHF15Reader(const char *Cmd);
int CmdHF15Sim(const char *Cmd);
int CmdHF15Record(const char *Cmd);
int CmdHF15Cmd(const char*Cmd);
int CmdHF15CmdHelp(const char*Cmd);
int CmdHF15Help(const char*Cmd);

#endif
