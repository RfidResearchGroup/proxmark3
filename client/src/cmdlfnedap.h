//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency NEDAP tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFNEDAP_H__
#define CMDLFNEDAP_H__

#include "common.h"

int CmdLFNedap(const char *Cmd);

int demodNedap(void);
int detectNedap(uint8_t *dest, size_t *size);
int getNedapBits(uint32_t cn, uint8_t *nedapBits);

#endif

