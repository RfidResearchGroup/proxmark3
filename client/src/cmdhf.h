//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
// Piwi, Feb 2019
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency commands
//-----------------------------------------------------------------------------

#ifndef CMDHF_H__
#define CMDHF_H__

#include "common.h"

int CmdHF(const char *Cmd);
int CmdHFTune(const char *Cmd);
int CmdHFSearch(const char *Cmd);
int CmdHFSniff(const char *Cmd);
int CmdHFPlot(const char *Cmd);

#endif
