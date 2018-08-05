//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency NEDAP tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFNEDAP_H__
#define CMDLFNEDAP_H__
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

extern int CmdLFNedap(const char *Cmd);
extern int CmdLFNedapDemod(const char *Cmd);
extern int CmdLFNedapRead(const char *Cmd);
//extern int CmdLFNedapClone(const char *Cmd);
extern int CmdLFNedapSim(const char *Cmd);
extern int CmdLFNedapChk(const char *Cmd);

extern int detectNedap(uint8_t *dest, size_t *size);

extern int usage_lf_nedap_read(void);
//extern int usage_lf_nedap_clone(void);
extern int usage_lf_nedap_sim(void);
#endif

