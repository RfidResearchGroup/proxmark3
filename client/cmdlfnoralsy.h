//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Noralsy tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFNORALSY_H__
#define CMDLFNORALSY_H__
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
#include "lfdemod.h"    // parityTest

extern int CmdLFNoralsy(const char *Cmd);
extern int CmdNoralsyDemod(const char *Cmd);
extern int CmdNoralsyRead(const char *Cmd);
extern int CmdNoralsyClone(const char *Cmd);
extern int CmdNoralsySim(const char *Cmd);

int getnoralsyBits(uint32_t id, uint16_t year, uint8_t *bits);

extern int usage_lf_noralsy_clone(void);
extern int usage_lf_noralsy_sim(void);
//extern int usage_lf_noralsy_read(void);
//extern int usage_lf_noralsy_demod(void);
#endif

