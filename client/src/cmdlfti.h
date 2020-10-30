//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency TI commands
//-----------------------------------------------------------------------------

#ifndef CMDLFTI_H__
#define CMDLFTI_H__

#include "common.h"

int CmdLFTI(const char *Cmd);

int demodTI(bool verbose);
#endif
