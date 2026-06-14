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
// MAD commands
//-----------------------------------------------------------------------------

#ifndef CMDMAD_H__
#define CMDMAD_H__

#include "common.h"

int CmdMAD(const char *Cmd);

int CmdMADMFRead(const char *Cmd);
int CmdMADMFWrite(const char *Cmd);
int CmdMADMFVerify(const char *Cmd);
int CmdMADMFPRead(const char *Cmd);
int CmdMADMFPWrite(const char *Cmd);
int CmdMADMFPVerify(const char *Cmd);

#endif
