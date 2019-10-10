//-----------------------------------------------------------------------------
// Iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency COTAG commands
//-----------------------------------------------------------------------------

#ifndef CMDLFCOTAG_H__
#define CMDLFCOTAG_H__

#include "common.h"

#ifndef COTAG_BITS
#define COTAG_BITS 264
#endif

int CmdLFCOTAG(const char *Cmd);
int demodCOTAG(void);
int readCOTAGUid(void);
#endif
