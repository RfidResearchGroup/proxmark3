//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency HID commands
//-----------------------------------------------------------------------------

#ifndef CMDLFHID_H__
#define CMDLFHID_H__

int CmdLFHID(const char *Cmd);

int CmdHIDDemod(const char *Cmd);
int CmdHIDDemodFSK(const char *Cmd);
int CmdHIDSim(const char *Cmd);

#endif
