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
#include <ctype.h>
#include <stdlib.h>
#include "common.h"
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "graph.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "protocols.h"  // for T55xx config register definitions
#include "lfdemod.h"    // parityTest
#include "cmdlft55xx.h"    // write verify

int CmdLFVisa2k(const char *Cmd);

int getvisa2kBits(uint64_t fullcode, uint8_t *bits);
int demodVisa2k(void);
int detectVisa2k(uint8_t *dest, size_t *size);

#endif

