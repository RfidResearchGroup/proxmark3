//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Stanley/PAC tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFKERI_H__
#define CMDLFKERI_H__

#include "common.h"

int CmdLFKeri(const char *Cmd);

int demodKeri(void);
int detectKeri(uint8_t *dest, size_t *size, bool *invert);

#endif

