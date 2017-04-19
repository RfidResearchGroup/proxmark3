//-----------------------------------------------------------------------------
// Copyright (C) 2015 Piwi
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency Topaz (NFC Type 1) commands
//-----------------------------------------------------------------------------

#ifndef CMDHFTOPAZ_H__
#define CMDHFTOPAZ_H__

extern int CmdHFTopaz(const char *Cmd);
extern int CmdHFTopazReader(const char *Cmd);
extern int CmdHFTopazSim(const char *Cmd);
extern int CmdHFTopazCmdRaw(const char *Cmd);
extern int CmdHFTopazList(const char *Cmd);

#endif
