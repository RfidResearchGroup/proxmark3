//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency G Prox II tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFGUARD_H__
#define CMDLFGUARD_H__
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
#include "lfdemod.h"    // parityTest
#include "crc.h"

extern int CmdLFGuard(const char *Cmd);
extern int CmdGuardDemod(const char *Cmd);
extern int CmdGuardRead(const char *Cmd);
extern int CmdGuardClone(const char *Cmd);
extern int CmdGuardSim(const char *Cmd);

extern int usage_lf_guard_clone(void);
extern int usage_lf_quard_sim(void);
#endif
