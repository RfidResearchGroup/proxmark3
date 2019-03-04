//-----------------------------------------------------------------------------
// Copyright (C) 2017 Merlok
// modified 2017 iceman
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// EMV commands
//-----------------------------------------------------------------------------

#ifndef CMDEMV_H__
#define CMDEMV_H__

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <ctype.h>
#include "proxmark3.h"
#include "ui.h"
#include "cmdparser.h"
#include "common.h"
#include "util.h"
#include "util_posix.h"
#include "cmdmain.h"
#include "emvcore.h"
#include "apduinfo.h"
#include "emv_roca.h"

int CmdEMV(const char *Cmd);

extern int CmdEMVSelect(const char *cmd);
extern int CmdEMVSearch(const char *cmd);
extern int CmdEMVPPSE(const char *cmd);
extern int CmdEMVExec(const char *cmd);
extern int CmdEMVGetrng(const char *Cmd);
extern int CmdEMVList(const char *Cmd);
extern int CmdEMVRoca(const char *Cmd);

#endif
