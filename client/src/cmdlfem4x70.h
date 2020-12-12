//-----------------------------------------------------------------------------
// Copyright (C) 2020 sirloins
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency EM4x70 commands
//-----------------------------------------------------------------------------

#ifndef CMDLFEM4X70_H__
#define CMDLFEM4X70_H__

#include "common.h"
#include "em4x50.h"

#define TIMEOUT                     2000

int CmdLFEM4X70(const char *Cmd);
int CmdEM4x70Info(const char *Cmd);
int CmdEM4x70Write(const char *Cmd);

int em4x70_info(void);
bool detect_4x70_block(void);

#endif
