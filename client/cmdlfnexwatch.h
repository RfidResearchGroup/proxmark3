//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Honeywell NexWatch tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFNEXWATCH_H__
#define CMDLFNEXWATCH_H__

#include "common.h"

int CmdLFNEXWATCH(const char *Cmd);

int demodNexWatch(void);
int detectNexWatch(uint8_t *dest, size_t *size, bool *invert);
#endif
