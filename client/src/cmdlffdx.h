//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency fdx-b tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFFDX_H__
#define CMDLFFDX_H__

#include "common.h"

int CmdLFFdx(const char *Cmd);
int detectFDXB(uint8_t *dest, size_t *size);
int demodFDX(void);
int getFDXBits(uint64_t national_id, uint16_t country, uint8_t is_animal, uint8_t is_extended, uint32_t extended, uint8_t *bits);

#endif

