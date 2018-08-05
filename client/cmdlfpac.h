//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Stanley/PAC tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFPAC_H__
#define CMDLFPAC_H__

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
#include "lfdemod.h"    // preamble test

extern int CmdLFPac(const char *Cmd);
extern int CmdPacRead(const char *Cmd);
extern int CmdPacDemod(const char *Cmd);

extern int detectPac(uint8_t *dest, size_t *size);
#endif

