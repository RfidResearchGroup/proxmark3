//-----------------------------------------------------------------------------
// Copyright (C) 2016 iceman <iceman at ...>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Data and Graph commands
//-----------------------------------------------------------------------------

#ifndef CMDANALYSE_H__
#define CMDANALYSE_H__

#include <stdlib.h>       // size_t
#include <string.h>
#include <unistd.h>
#include "cmdmain.h"
#include "proxmark3.h"
#include "ui.h"           // PrintAndLog
#include "util.h"
#include "crc.h"
#include "crc16.h"        // crc16 ccitt
#include "tea.h"
#include "legic_prng.h"
#include "loclass/elite_crack.h"
#include "mifare/mfkey.h" // nonce2key
#include "util_posix.h"   // msclock


int usage_analyse_lcr(void);
int usage_analyse_checksum(void);
int usage_analyse_crc(void);
int usage_analyse_hid(void);
int usage_analyse_nuid(void);

int CmdAnalyse(const char *Cmd);
int CmdAnalyseLCR(const char *Cmd);
int CmdAnalyseCHKSUM(const char *Cmd);
int CmdAnalyseDates(const char *Cmd);
int CmdAnalyseCRC(const char *Cmd);
int CmdAnalyseTEASelfTest(const char *Cmd);
int CmdAnalyseLfsr(const char *Cmd);
int CmdAnalyseHid(const char *Cmd);
int CmdAnalyseNuid(const char *Cmd);
#endif
