//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Stanley/PAC tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFKERI_H__
#define CMDLFKERI_H__

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
#include "protocols.h"  // for T55xx config register definitions
#include "lfdemod.h"    // preamble test

extern int CmdLFKeri(const char *Cmd);
extern int CmdKeriRead(const char *Cmd);
extern int CmdKeriDemod(const char *Cmd);
extern int CmdKeriClone(const char *Cmd);
extern int CmdKeriSim(const char *Cmd);

extern int detectKeri(uint8_t *dest, size_t *size, bool *invert);

extern int usage_lf_keri_clone(void);
extern int usage_lf_keri_sim(void);
#endif

