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
#include "util.h"
#include "crc.h"
#include "../common/iso15693tools.h"
#include "tea.h"

int usage_analyse_lcr(void);
int usage_analyse_checksum(void);
int usage_analyse_crc(void);

int CmdAnalyse(const char *Cmd);
int CmdAnalyseLCR(const char *Cmd);
int CmdAnalyseCHKSUM(const char *Cmd);
int CmdAnalyseDates(const char *Cmd);
int CmdAnalyseCRC(const char *Cmd);
int CmdAnalyseTEASelfTest(const char *Cmd);
#endif
