//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency EM4x commands
//-----------------------------------------------------------------------------

#ifndef CMDLFEM4X_H__
#define CMDLFEM4X_H__

int CmdLFEM4X(const char *Cmd);

int CmdEM410xRead(const char *Cmd);
int CmdEM410xSim(const char *Cmd);
int CmdEM410xWatch(const char *Cmd);
int CmdEM410xWrite(const char *Cmd);
int CmdEM4x50Read(const char *Cmd);

#endif
