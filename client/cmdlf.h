//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency commands
//-----------------------------------------------------------------------------

#ifndef CMDLF_H__
#define CMDLF_H__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "proxmark3.h"
#include "data.h"
#include "graph.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdmain.h"
#include "cmddata.h"
#include "util.h"
#include "cmdlfhid.h"
#include "cmdlfawid.h"
#include "cmdlfti.h"
#include "cmdlfem4x.h"
#include "cmdlfhitag.h"
#include "cmdlft55xx.h"
#include "cmdlfpcf7931.h"
#include "cmdlfio.h"
#include "lfdemod.h"
#include "cmdlfviking.h"
#include "cmdlfpresco.h"
#include "cmdlfpyramid.h"
#include "cmdlfguard.h"

int CmdLF(const char *Cmd);

int CmdLFCommandRead(const char *Cmd);
int CmdFlexdemod(const char *Cmd);
int CmdIndalaDemod(const char *Cmd);
int CmdIndalaClone(const char *Cmd);
int CmdLFRead(const char *Cmd);
int CmdLFSim(const char *Cmd);
int CmdLFaskSim(const char *Cmd);
int CmdLFfskSim(const char *Cmd);
int CmdLFpskSim(const char *Cmd);
int CmdLFSimBidir(const char *Cmd);
int CmdLFSnoop(const char *Cmd);
int CmdVchDemod(const char *Cmd);
int CmdLFfind(const char *Cmd);

// usages helptext
int usage_lf_cmdread(void);
int usage_lf_read(void);
int usage_lf_snoop(void);
int usage_lf_config(void);
int usage_lf_simfsk(void);
int usage_lf_simask(void);
int usage_lf_simpsk(void);
#endif
