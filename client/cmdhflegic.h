//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency Legic commands
//-----------------------------------------------------------------------------

#ifndef CMDHFLEGIC_H__
#define CMDHFLEGIC_H__

#include <stdio.h>
#include <string.h>
#include "proxmark3.h"
#include "data.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdmain.h"
#include "util.h"
#include "crc.h"

int CmdHFLegic(const char *Cmd);

int CmdLegicRFRead(const char *Cmd);
int CmdLegicDecode(const char *Cmd);
int CmdLegicLoad(const char *Cmd);
int CmdLegicSave(const char *Cmd);
int CmdLegicRfSim(const char *Cmd);
int CmdLegicRfWrite(const char *Cmd);
int CmdLegicRfRawWrite(const char *Cmd);
int CmdLegicRfFill(const char *Cmd);

int CmdLegicCalcCrc8(const char *Cmd);

int usage_legic_calccrc8(void);
int usage_legic_load(void);
int usage_legic_read(void);
#endif
