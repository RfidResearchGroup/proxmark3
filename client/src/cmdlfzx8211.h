//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency ZX8211 commands
//-----------------------------------------------------------------------------
#ifndef CMDLFZX8211_H__
#define CMDLFZX8211_H__

#include "common.h"

int CmdLFZx8211(const char *Cmd);

int demodzx(bool verbose);
int detectzx(uint8_t *dest, size_t *size);

#endif

