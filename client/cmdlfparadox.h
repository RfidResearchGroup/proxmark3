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
int CmdLFParadox(const char *Cmd);

int demodParadox(void);
int detectParadox(uint8_t *dest, size_t *size, uint32_t *hi2, uint32_t *hi, uint32_t *lo, int *waveStartIdx);
#endif
