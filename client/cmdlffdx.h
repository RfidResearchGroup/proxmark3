//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency fdx-b tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFFDX_H__
#define CMDLFFDX_H__
#include "proxmark3.h"  // Definitions, USB controls, etc
#include "ui.h"         // PrintAndLog
#include "util.h"       // weigandparity
#include "cmdparser.h"
#include "cmddata.h"
#include "cmdmain.h"
#include "cmdlf.h"      // lf read
#include "crc16.h"      // for checksum crc-16_ccitt
#include "protocols.h"  // for T55xx config register definitions
#include "lfdemod.h"    // parityTest

int CmdLFFdx(const char *Cmd);
int detectFDXB(uint8_t *dest, size_t *size);
int demodFDX(void);
int getFDXBits(uint64_t national_id, uint16_t country, uint8_t isanimal, uint8_t isextended, uint32_t extended, uint8_t *bits);

#endif

