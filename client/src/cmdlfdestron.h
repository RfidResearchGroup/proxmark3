//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency FDX-A FECAVA Destron tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFDESTRON_H__
#define CMDLFDESTRON_H__

#include "common.h"

int CmdLFDestron(const char *Cmd);
int detectDestron(uint8_t *bits, size_t *size);
int demodDestron(bool verbose);
int readDestronUid(void);
#endif

