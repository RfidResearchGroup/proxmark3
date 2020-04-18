//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Verichip tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFVERICHIP_H__
#define CMDLFVERICHIP_H__

#include "common.h"

int CmdLFVerichip(const char *Cmd);

int demodVerichip(void);
int detectVerichip(uint8_t *dest, size_t *size);
#endif

