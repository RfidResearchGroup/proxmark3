//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency viking tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFVIKING_H__
#define CMDLFVIKING_H__
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "proxmark3.h"
#include "ui.h"
#include "util.h"
#include "graph.h"
#include "cmdparser.h"
#include "cmddata.h"
#include "cmdmain.h"
#include "cmdlf.h"
#include "lfdemod.h"

int CmdLFViking(const char *Cmd);

int CmdVikingDemod(const char *Cmd);
int CmdVikingRead(const char *Cmd);
int CmdVikingClone(const char *Cmd);
int CmdVikingSim(const char *Cmd);

int detectViking(uint8_t *dest, size_t *size);

#endif

