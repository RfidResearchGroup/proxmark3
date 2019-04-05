//-----------------------------------------------------------------------------
// Copyright (C) 2012 Roel Verdult
// 2017 iceman
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Hitag support
//-----------------------------------------------------------------------------

#ifndef CMDLFHITAG_H__
#define CMDLFHITAG_H__

int CmdLFHitag(const char *Cmd);

int CmdLFHitagList(const char *Cmd);
int CmdLFHitagSniff(const char *Cmd);
int CmdLFHitagSim(const char *Cmd);
int CmdLFHitagInfo(const char *Cmd);
int CmdLFHitagReader(const char *Cmd);
int CmdLFHitagCheckChallenges(const char *Cmd);
int CmdLFHitagWriter(const char *Cmd);
int CmdLFHitagDump(const char *cmd);

#endif
