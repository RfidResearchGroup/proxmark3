//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency viking tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFVIKING_H__
#define CMDLFVIKING_H__

#include "common.h"

int CmdLFViking(const char *Cmd);

int demodViking(void);
int detectViking(uint8_t *src, size_t *size);
uint64_t getVikingBits(uint32_t id);

#endif

