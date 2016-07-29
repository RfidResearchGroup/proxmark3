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
#include "lfdemod.h"
			
#include "util.h"			// for parsing cli command utils
#include "ui.h"				// for show graph controls
#include "graph.h"			// for graph data
#include "cmdparser.h"		// for getting cli commands included in cmdmain.h
#include "cmdmain.h"		// for sending cmds to device
#include "data.h"			// for GetFromBigBuf
#include "cmddata.h"		// for `lf search`
#include "cmdlfawid.h"		// for awid menu
#include "cmdlfem4x.h"		// for em4x menu
#include "cmdlfhid.h"		// for hid menu
#include "cmdlfhitag.h"		// for hitag menu
#include "cmdlfio.h"		// for ioprox menu
#include "cmdlft55xx.h"		// for t55xx menu
#include "cmdlfti.h"		// for ti menu
#include "cmdlfpresco.h"	// for presco menu
#include "cmdlfpcf7931.h"	// for pcf7931 menu
#include "cmdlfpyramid.h"	// for pyramid menu
#include "cmdlfviking.h"	// for viking menu
#include "cmdlfguard.h"		// for GuardAll menu
#include "cmdlfnedap.h"		// for NEDAP menu
#include "cmdlfjablotron.h"	// for JABLOTRON menu

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
