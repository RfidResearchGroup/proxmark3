//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Presco tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFPRESCO_H__
#define CMDLFPRESCO_H__

#include "common.h"

int CmdLFPresco(const char *Cmd);
int demodPresco(bool verbose);
#endif

