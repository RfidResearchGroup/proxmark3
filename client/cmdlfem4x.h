//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
// 2016, 2017 marshmellow, iceman
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
#include "comms.h"
#include "cmdlf.h"
#include "lfdemod.h"

extern int CmdLFEM4X(const char *Cmd);


extern int CmdEM410xDemod(const char *Cmd);
extern int CmdEM410xRead(const char *Cmd);
extern int CmdEM410xSim(const char *Cmd);
extern int CmdEM410xBrute(const char *Cmd);
extern int CmdEM410xWatch(const char *Cmd);
extern int CmdEM410xWatchnSpoof(const char *Cmd);
extern int CmdEM410xWrite(const char *Cmd);
extern int CmdEM4x05Dump(const char *Cmd);
extern int CmdEM4x05Info(const char *Cmd);
extern int CmdEM4x05Read(const char *Cmd);
extern int CmdEM4x05Write(const char *Cmd);
extern int CmdEM4x50Read(const char *Cmd);
extern int CmdEM4x50Write(const char *Cmd);
extern int CmdEM4x50Dump(const char *Cmd);

extern int EM4x50Read(const char *Cmd, bool verbose);
bool EM4x05IsBlock0(uint32_t *word);

extern void printEM410x(uint32_t hi, uint64_t id);
extern int AskEm410xDecode(bool verbose, uint32_t *hi, uint64_t *lo);
extern int AskEm410xDemod(const char *Cmd, uint32_t *hi, uint64_t *lo, bool verbose);

extern int usage_lf_em410x_sim(void);
extern int usage_lf_em410x_ws(void);
extern int usage_lf_em410x_clone(void);
extern int usage_lf_em410x_sim(void);
extern int usage_lf_em410x_brute(void);

extern int usage_lf_em4x50_dump(void);
extern int usage_lf_em4x50_read(void);
extern int usage_lf_em4x50_write(void);

extern int usage_lf_em4x05_dump(void);
extern int usage_lf_em4x05_read(void);
extern int usage_lf_em4x05_write(void);
extern int usage_lf_em4x05_info(void);

#endif
