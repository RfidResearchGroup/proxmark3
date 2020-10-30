//-----------------------------------------------------------------------------
// Copyright (C) 2019 iceman <iceman at iuse.se>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Trace commands
//-----------------------------------------------------------------------------

#ifndef CMDWIEGAND_H__
#define CMDWIEGAND_H__

#include "common.h"

int CmdWiegand(const char *Cmd);
int CmdWiegandList(const char *Cmd);
int CmdWiegandEncode(const char *Cmd);
int CmdWiegandDecode(const char *Cmd);
#endif
