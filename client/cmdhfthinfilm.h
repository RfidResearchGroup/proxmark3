//-----------------------------------------------------------------------------
// Copyright (C) 2019 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Thinfilm commands
//-----------------------------------------------------------------------------

#ifndef CMDHFTHINFILM_H__
#define CMDHFTHINFILM_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "proxmark3.h"
#include "ui.h"
#include "cmdparser.h"
#include "util.h"
#include "cmdhf.h"  // list cmd

int infoThinFilm(void);

int CmdHFThinfilm(const char *Cmd);

#endif
