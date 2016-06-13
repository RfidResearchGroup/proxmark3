//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Data and Graph commands
//-----------------------------------------------------------------------------

#ifndef CMDANALYSE_H__
#define CMDANALYSE_H__

#include <stdlib.h>  //size_t
#include <string.h>
#include "cmdmain.h"
#include "proxmark3.h"
#include "ui.h"		// PrintAndLog
command_t * CmdDataCommands();

int CmdAnalyse(const char *Cmd);
int CmdAnalyseLCR(const char *Cmd);
int CmdAnalyseDates(const char *Cmd);
#endif
