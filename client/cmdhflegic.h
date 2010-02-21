//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency Legic commands
//-----------------------------------------------------------------------------

#ifndef CMDHFLEGIC_H__
#define CMDHFLEGIC_H__

int CmdHFLegic(const char *Cmd);

int CmdLegicRFRead(const char *Cmd);
int CmdLegicDecode(const char *Cmd);

#endif
