//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Farpoint / Pyramid commands
//-----------------------------------------------------------------------------
#ifndef CMDLFPYRAMID_H__
#define CMDLFPYRAMID_H__

#include "common.h"

int CmdLFPyramid(const char *Cmd);

int demodPyramid(void);
int detectPyramid(uint8_t *dest, size_t *size, int *waveStartIdx);
int getPyramidBits(uint32_t fc, uint32_t cn, uint8_t *pyramidBits);
#endif

