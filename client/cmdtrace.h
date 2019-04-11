//-----------------------------------------------------------------------------
// Copyright (C) 2018 iceman <iceman at iuse.se>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Trace commands
//-----------------------------------------------------------------------------

#ifndef CMDTRACE_H__
#define CMDTRACE_H__
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include "proxmark3.h"
#include "protocols.h"
#include "parity.h"             // oddparity
#include "cmdhflist.h"          // annotations
#include "iso15693tools.h"      // ISO15693 crc
#include "util.h"               // for parsing cli command utils
#include "ui.h"                 // for show graph controls
#include "cmdparser.h"          // for getting cli commands included in cmdmain.h
#include "comms.h"              // for sending cmds to device. GetFromBigBuf
#include "loclass/fileutils.h"  // for saveFile

int CmdTrace(const char *Cmd);
int CmdTraceList(const char *Cmd);

#endif
