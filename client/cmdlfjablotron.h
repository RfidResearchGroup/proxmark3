//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Jablotron tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFJABLOTRON_H__
#define CMDLFJABLOTRON_H__

#include "common.h"

int CmdLFJablotron(const char *Cmd);

int demodJablotron(void);
int detectJablotron(uint8_t *bits, size_t *size);
int getJablotronBits(uint64_t fullcode, uint8_t *bits);

#endif

