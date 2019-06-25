//-----------------------------------------------------------------------------
// Copyright (C) 2016 iceman <iceman at ...>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Data and Graph commands
//-----------------------------------------------------------------------------

#ifndef CMDUSART_H__
#define CMDUSART_H__

#include <stdlib.h>       // size_t
#include <string.h>
#include <unistd.h>
#include "cmdmain.h"
#include "proxmark3.h"
#include "ui.h"           // PrintAndLog
#include "util.h"
//#include "util_posix.h"   // msclock

int CmdUsart(const char *Cmd);
#endif
