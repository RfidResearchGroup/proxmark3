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

int CmdLFINDALA(const char *Cmd);

int CmdIndalaDemod(const char *Cmd);
int CmdIndalaDemodAlt(const char *Cmd);
int CmdIndalaRead(const char *Cmd);
int CmdIndalaClone(const char *Cmd);
int CmdIndalaSim(const char *Cmd);

int detectIndala26(uint8_t *bitStream, size_t *size, uint8_t *invert);
int detectIndala64(uint8_t *bitStream, size_t *size, uint8_t *invert);
int detectIndala224(uint8_t *bitStream, size_t *size, uint8_t *invert);

int usage_lf_indala_demod(void);
int usage_lf_indala_clone(void);
int usage_lf_indala_sim(void);
#endif
