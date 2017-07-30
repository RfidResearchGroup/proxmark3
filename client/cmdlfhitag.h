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

extern int CmdLFHitag(const char *Cmd);

extern int CmdLFHitagList(const char *Cmd);
extern int CmdLFHitagReader(const char *Cmd);
extern int CmdLFHitagSim(const char *Cmd);
extern int CmdLFHitagSimS(const char *Cmd);
extern int CmdLFHitagSnoop(const char *Cmd);
extern int CmdLFHitagWP(const char *Cmd);
extern int CmdLFHitagCheckChallenges(const char *Cmd);

#endif
