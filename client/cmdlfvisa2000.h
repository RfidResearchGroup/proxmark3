//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency visa 2000 commands
//-----------------------------------------------------------------------------
#ifndef CMDLFVISA2000_H__
#define CMDLFVISA2000_H__

#include "common.h"

int CmdLFVisa2k(const char *Cmd);

int getvisa2kBits(uint64_t fullcode, uint8_t *bits);
int demodVisa2k(void);
int detectVisa2k(uint8_t *dest, size_t *size);

#endif

