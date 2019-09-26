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

#include "common.h"

int CmdLFNoralsy(const char *Cmd);

int demodNoralsy(void);
int detectNoralsy(uint8_t *dest, size_t *size);
int getnoralsyBits(uint32_t id, uint16_t year, uint8_t *bits);

#endif

