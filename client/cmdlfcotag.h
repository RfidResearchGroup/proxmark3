//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency AWID commands
//-----------------------------------------------------------------------------

#ifndef CMDLFCOTAG_H__
#define CMDLFCOTAG_H__

#include "proxmark3.h"  // Definitions, USB controls, etc
#include "cmddata.h"	// getSamples
#include "cmdparser.h"  // CmdsParse, CmdsHelp
#include "cmdmain.h"

int CmdLFCOTAG(const char *Cmd);
int CmdCOTAGRead(const char *Cmd);

#endif
