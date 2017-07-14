//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency EM4x commands
//-----------------------------------------------------------------------------

#ifndef CMDLFEM4X_H__
#define CMDLFEM4X_H__

#include <stdio.h>
#include <stdbool.h>    // for bool
#include <string.h>
#include <inttypes.h>
#include "proxmark3.h"
#include "ui.h"
#include "util.h"
#include "graph.h"
#include "cmdparser.h"
#include "cmddata.h"
#include "cmdmain.h"
#include "cmdmain.h"
#include "cmdlf.h"
#include "lfdemod.h"

extern int CmdEMdemodASK(const char *Cmd);
extern int CmdEM410xRead(const char *Cmd);
extern int CmdEM410xSim(const char *Cmd);
extern int CmdEM410xWatch(const char *Cmd);
extern int CmdEM410xWatchnSpoof(const char *Cmd);
extern int CmdEM410xWrite(const char *Cmd);
extern int CmdEM4x50Read(const char *Cmd);
extern int CmdLFEM4X(const char *Cmd);
extern int CmdReadWord(const char *Cmd);
extern int CmdWriteWord(const char *Cmd);
extern int EM4x50Read(const char *Cmd, bool verbose);

bool EM4x05IsBlock0(uint32_t *word);

int usage_lf_em410x_sim(void);
int usage_lf_em_read(void);
int usage_lf_em_write(void);

#endif
