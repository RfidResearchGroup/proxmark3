//-----------------------------------------------------------------------------
// Copyright (C) 2012 Frederik Möllers
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Commands related to the German electronic Identification Card
//-----------------------------------------------------------------------------

#ifndef CMDHFEPA_H__
#define CMDHFEPA_H__

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include "util.h"
#include "proxmark3.h"
#include "common.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdmain.h"
#include "util_posix.h"


int CmdHFEPA(const char *Cmd);

#endif // CMDHFEPA_H__
