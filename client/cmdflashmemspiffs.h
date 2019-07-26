//-----------------------------------------------------------------------------
// Copyright (C) 2018 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Proxmark3 RDV40 Flash memory commands
//-----------------------------------------------------------------------------

#ifndef CMDFLASHMEMSPIFFS_H__
#define CMDFLASHMEMSPIFFS_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "pmflash.h"
#include "common.h"
#include "proxmark3.h"
#include "ui.h"
#include "cmdparser.h"
#include "util.h"
#include "util_posix.h"         // msclock
#include "loclass/fileutils.h"  //saveFile
#include "comms.h"              //getfromdevice

int CmdFlashMemSpiFFS(const char *Cmd);

#endif
