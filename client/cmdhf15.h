//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency ISO15693 commands
//-----------------------------------------------------------------------------

#ifndef CMDHF15_H__
#define CMDHF15_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "proxmark3.h"
#include "graph.h"
#include "ui.h"
#include "util.h"
#include "cmdparser.h"
#include "crc16.h"             // iso15 crc
#include "cmdmain.h"
#include "cmddata.h"           // getsamples
#include "loclass/fileutils.h" // savefileEML

int CmdHF15(const char *Cmd);

int readHF15Uid(bool verbose);

#endif
