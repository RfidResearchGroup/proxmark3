//-----------------------------------------------------------------------------
// Iceman, 2019
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency GALLAGHER tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFGALLAGHER_H__
#define CMDLFGALLAGHER_H__

#include "common.h"

int CmdLFGallagher(const char *Cmd);

int demodGallagher(void);
int detectGallagher(uint8_t *dest, size_t *size);
#endif

