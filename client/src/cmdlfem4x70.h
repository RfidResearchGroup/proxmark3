//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// Low frequency EM4x70 commands
//-----------------------------------------------------------------------------

#ifndef CMDLFEM4X70_H__
#define CMDLFEM4X70_H__

#include "common.h"

#define TIMEOUT                     2000

int CmdLFEM4X70(const char *Cmd);
int CmdEM4x70Info(const char *Cmd);
int CmdEM4x70Write(const char *Cmd);
int CmdEM4x70Brute(const char *Cmd);
int CmdEM4x70Unlock(const char *Cmd);
int CmdEM4x70Auth(const char *Cmd);
int CmdEM4x70WritePIN(const char *Cmd);
int CmdEM4x70WriteKey(const char *Cmd);

int em4x70_info(void);
bool detect_4x70_block(void);

#endif
