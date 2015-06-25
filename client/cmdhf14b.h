//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency ISO14443B commands
//-----------------------------------------------------------------------------

#ifndef CMDHF14B_H__
#define CMDHF14B_H__

int CmdHF14B(const char *Cmd);
int CmdHF14BList(const char *Cmd);
int CmdHF14BInfo(const char *Cmd);
int CmdHF14BSim(const char *Cmd);
int CmdHF14BSnoop(const char *Cmd);
int CmdSri512Read(const char *Cmd);
int CmdSrix4kRead(const char *Cmd);
int CmdHF14BWrite( const char *cmd);
int HF14BInfo(bool verbose);

#endif
