//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
// Copyright (C) 2011 Gerhard de Koning Gans
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency iClass support
//-----------------------------------------------------------------------------

#ifndef CMDHFICLASS_H__
#define CMDHFICLASS_H__

int CmdHFiClass(const char *Cmd);

int CmdHFiClassSnoop(const char *Cmd);
int CmdHFiClassList(const char *Cmd);

#endif
