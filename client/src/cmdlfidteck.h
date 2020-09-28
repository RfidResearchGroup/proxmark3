//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Idteck tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFIDTECK_H__
#define CMDLFIDTECK_H__

#include "common.h"

int CmdLFIdteck(const char *Cmd);

int demodIdteck(bool verbose);
int detectIdteck(uint8_t *dest, size_t *size);

#endif
