//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Securakey tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFSECURAKEY_H__
#define CMDLFSECURAKEY_H__

#include "common.h"

int CmdLFSecurakey(const char *Cmd);

int demodSecurakey(void);
int detectSecurakey(uint8_t *dest, size_t *size);

#endif

