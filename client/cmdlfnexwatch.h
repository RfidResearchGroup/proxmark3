//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Honeywell NexWatch tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFNEXWATCH_H__
#define CMDLFNEXWATCH_H__

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include "proxmark3.h"
#include "ui.h"
#include "util.h"
#include "graph.h"
#include "cmdparser.h"
#include "cmddata.h" // preamblesearch
#include "cmdlf.h"
#include "lfdemod.h"  

extern int CmdLFNEXWATCH(const char *Cmd);
extern int CmdNexWatchDemod(const char *Cmd);
extern int CmdNexWatchRead(const char *Cmd);

extern int detectNexWatch(uint8_t *dest, size_t *size, bool *invert);
#endif
