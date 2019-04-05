//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency AWID commands
//-----------------------------------------------------------------------------

#ifndef CMDLFAWID_H__
#define CMDLFAWID_H__

#include <stdio.h>      // sscanf
#include <stdbool.h>    // bool
#include "proxmark3.h"  // Definitions, USB controls, etc
#include "ui.h"         // PrintAndLog
#include "cmdparser.h"  // CmdsParse, CmdsHelp
#include "lfdemod.h"    // parityTest
#include "util.h"       // weigandparity
#include "cmdlf.h"      // lf read
#include "protocols.h"  // for T55xx config register definitions
#include "cmdmain.h"
#include "util_posix.h"


int CmdLFAWID(const char *Cmd);
int CmdAWIDDemod(const char *Cmd);
int CmdAWIDRead(const char *Cmd);
int CmdAWIDSim(const char *Cmd);
int CmdAWIDClone(const char *Cmd);
int CmdAWIDBrute(const char *Cmd);
int getAWIDBits(uint8_t fmtlen, uint32_t fc, uint32_t cn, uint8_t *bits);

int usage_lf_awid_read(void);
int usage_lf_awid_sim(void);
int usage_lf_awid_clone(void);
int usage_lf_awid_brute(void);

#endif
