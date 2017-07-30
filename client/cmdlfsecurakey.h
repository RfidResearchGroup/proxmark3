//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Securakey tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFSECURAKEY_H__
#define CMDLFSECURAKEY_H__

#include <string.h>
#include <inttypes.h>
#include <math.h>
#include "proxmark3.h"
#include "ui.h"
#include "util.h"
#include "graph.h"
#include "cmdparser.h"
#include "cmddata.h"
#include "cmdmain.h"
#include "cmdlf.h"
#include "protocols.h"  // for T55xx config register definitions
#include "lfdemod.h"    // preamble test
#include "parity.h"     // for wiegand parity test

extern int CmdLFSecurakey(const char *Cmd);
//extern int CmdSecurakeyClone(const char *Cmd);
//extern int CmdSecurakeySim(const char *Cmd);
extern int CmdSecurakeyRead(const char *Cmd);
extern int CmdSecurakeyDemod(const char *Cmd);

#endif

