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

#include "common.h"

int CmdLFGuard(const char *Cmd);
int detectGProxII(uint8_t *bits, size_t *size);
int demodGuard(void);
int getGuardBits(uint8_t fmtlen, uint32_t fc, uint32_t cn, uint8_t *guardBits);
#endif
