//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Stanley/PAC tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFPAC_H__
#define CMDLFPAC_H__

#include "common.h"

int CmdLFPac(const char *Cmd);

int demodPac(void);
int detectPac(uint8_t *dest, size_t *size);
#endif

