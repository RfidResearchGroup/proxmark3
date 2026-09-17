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
// High frequency proximity cards from ISO14443A / FUDAN commands
//-----------------------------------------------------------------------------

#ifndef CMDHFFUDAN_H__
#define CMDHFFUDAN_H__

#include "common.h"
#include "pm3_cmd.h"

int CmdHFFudan(const char *Cmd);
int read_fudan_uid(bool loop, bool verbose);

#endif

