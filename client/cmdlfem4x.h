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

int CmdEMdemodASK(const char *Cmd);
int CmdEM410xRead(const char *Cmd);
int CmdEM410xSim(const char *Cmd);
int CmdEM410xWatch(const char *Cmd);
int CmdEM410xWatchnSpoof(const char *Cmd);
int CmdEM410xWrite(const char *Cmd);
int CmdEM4x50Read(const char *Cmd);
int CmdLFEM4X(const char *Cmd);
int CmdReadWord(const char *Cmd);
int CmdReadWordPWD(const char *Cmd);
int CmdWriteWord(const char *Cmd);
int CmdWriteWordPWD(const char *Cmd);
int EM4x50Read(const char *Cmd, bool verbose);

#endif
