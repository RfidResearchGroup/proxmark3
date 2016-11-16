//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Hardware commands
//-----------------------------------------------------------------------------

#ifndef CMDHW_H__
#define CMDHW_H__

int CmdHW(const char *Cmd);

int CmdDetectReader(const char *Cmd);
int CmdFPGAOff(const char *Cmd);
int CmdLCD(const char *Cmd);
int CmdLCDReset(const char *Cmd);
int CmdReadmem(const char *Cmd);
int CmdReset(const char *Cmd);
int CmdSetDivisor(const char *Cmd);
int CmdSetMux(const char *Cmd);
int CmdTune(const char *Cmd);
int CmdVersion(const char *Cmd);
int CmdPing(const char *Cmd);
#endif
