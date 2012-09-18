//-----------------------------------------------------------------------------
// Copyright (C) 2012 Roel Verdult
//
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
int CmdLFHitagSnoop(const char *Cmd);
int CmdLFHitagSim(const char *Cmd);
int CmdLFHitagReader(const char *Cmd);

#endif
