//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency visa 2000 commands
//-----------------------------------------------------------------------------
#ifndef CMDLFVISA2000_H__
#define CMDLFVISA2000_H__
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
extern int CmdLFVisa2k(const char *Cmd);

extern int CmdVisa2kDemod(const char *Cmd);
extern int CmdVisa2kRead(const char *Cmd);
extern int CmdVisa2kClone(const char *Cmd);
extern int CmdVisa2kSim(const char *Cmd);

int getvisa2kBits(uint64_t fullcode, uint8_t *bits);
extern int detectVisa2k(uint8_t *dest, size_t *size);

extern int usage_lf_visa2k_clone(void);
extern int usage_lf_visa2k_sim(void);
//extern int usage_lf_visa2k_read(void);
//extern int usage_lf_visa2k_demod(void);
#endif

