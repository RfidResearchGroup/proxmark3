//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency commands
//-----------------------------------------------------------------------------

#ifndef CMDLF_H__
#define CMDLF_H__

int CmdLF(const char *Cmd);

int CmdLFCommandRead(const char *Cmd);
int CmdFlexdemod(const char *Cmd);
int CmdIndalaDemod(const char *Cmd);
int CmdIndalaClone(const char *Cmd);
int CmdLFRead(const char *Cmd);
int CmdLFSim(const char *Cmd);
int CmdLFaskSim(const char *Cmd);
int CmdLFfskSim(const char *Cmd);
int CmdLFpskSim(const char *Cmd);
int CmdLFSimBidir(const char *Cmd);
int CmdLFSnoop(const char *Cmd);
int CmdVchDemod(const char *Cmd);
int CmdLFfind(const char *Cmd);

#endif
