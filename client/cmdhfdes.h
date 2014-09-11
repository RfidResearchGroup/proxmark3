//-----------------------------------------------------------------------------
// Copyright (C) 2012 nuit
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency MIFARE DESfire commands
//-----------------------------------------------------------------------------

#ifndef CMDHFDES_H__
#define CMDHFDES_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "proxmark3.h"
#include "data.h"
#include "ui.h"
#include "cmdparser.h"
#include "common.h"
#include "util.h"
int CmdHFDES(const char *Cmd);
int CmdHFDESReader(const char *Cmd);
int CmdHFDESDbg(const char *Cmd);
#endif
