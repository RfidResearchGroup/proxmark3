//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Indala commands
//-----------------------------------------------------------------------------

#ifndef CMDLFINDALA_H__
#define CMDLFINDALA_H__

#include <stdio.h>      // sscanf
#include <stdlib.h>
#include <string.h>
#include "proxmark3.h"  // Definitions, USB controls, etc
#include "ui.h"         // PrintAndLog
#include "cmdparser.h"  // CmdsParse, CmdsHelp
#include "lfdemod.h"    // parityTest, bitbytes_to_byte
#include "util.h"       // weigandparity
#include "protocols.h"  // for T55xx config register definitions
#include "cmdmain.h"
#include "cmddata.h"
#include "cmdlf.h"      // lf_read

extern int CmdLFINDALA(const char *Cmd);

extern int CmdIndalaDemod(const char *Cmd);
extern int CmdIndalaDemodAlt(const char *Cmd);
extern int CmdIndalaRead(const char *Cmd);
extern int CmdIndalaClone(const char *Cmd);
extern int CmdIndalaSim(const char *Cmd);

extern int detectIndala26(uint8_t *bitStream, size_t *size, uint8_t *invert);
extern int detectIndala64(uint8_t *bitStream, size_t *size, uint8_t *invert);
extern int detectIndala224(uint8_t *bitStream, size_t *size, uint8_t *invert);

extern int usage_lf_indala_demod(void);
extern int usage_lf_indala_clone(void);
extern int usage_lf_indala_sim(void);
#endif
