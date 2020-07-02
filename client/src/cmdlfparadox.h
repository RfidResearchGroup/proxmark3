//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Paradox tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFPARADOX_H__
#define CMDLFPARADOX_H__

#include "common.h"

int CmdLFParadox(const char *Cmd);

int demodParadox(void);
int detectParadox(uint8_t *dest, size_t *size, int *wave_start_idx);
#endif
