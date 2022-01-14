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
// Trace commands
//-----------------------------------------------------------------------------

#ifndef CMDTRACE_H__
#define CMDTRACE_H__

#include "common.h"

int CmdTrace(const char *Cmd);
int CmdTraceList(const char *Cmd);
int CmdTraceListAlias(const char *Cmd, const char *alias, const char *protocol);

#endif
