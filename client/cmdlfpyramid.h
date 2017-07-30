//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Farpoint / Pyramid commands
//-----------------------------------------------------------------------------
#ifndef CMDLFPYRAMID_H__
#define CMDLFPYRAMID_H__
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

extern int CmdLFPyramid(const char *Cmd);
extern int CmdPyramidDemod(const char *Cmd);
extern int CmdPyramidRead(const char *Cmd);
extern int CmdPyramidClone(const char *Cmd);
extern int CmdPyramidSim(const char *Cmd);

extern int detectPyramid(uint8_t *dest, size_t *size, int *waveStartIdx);

extern int usage_lf_pyramid_clone(void);
extern int usage_lf_pyramid_sim(void);
#endif

