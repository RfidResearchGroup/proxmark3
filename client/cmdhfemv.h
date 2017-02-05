//-----------------------------------------------------------------------------
// Copyright (C) 2014 Peter Fillmore
// 2017 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency EMV commands
//-----------------------------------------------------------------------------

#ifndef CMDHFEMV_H__
#define CMDHFEMV_H__

#include <stdio.h>
#include <string.h>
#include "proxmark3.h"
#include "data.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdmain.h"
#include "util.h"
#include "cmdhf.h" // "hf list"

int CmdHFEmv(const char *Cmd);

int CmdHfEmvTransaction(const char *Cmd);
int CmdHfEmvGetrng(const char *Cmd);
int CmdHfEmvELoad(const char *Cmd);
int CmdHfEmvDump(const char *Cmd);
//int CmdHfEmvSim(const char *Cmd);
int CmdHfEmvList(const char *Cmd);

int usage_hf_emv_trans(void);
int usage_hf_emv_getrnd(void);
int usage_hf_emv_eload(void);
int usage_hf_emv_dump(void);
int usage_hf_emv_sim(void);

#endif
