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
// High frequency JavaCard / GlobalPlatform commands
//-----------------------------------------------------------------------------

#ifndef CMDHFJAVACARD_H__
#define CMDHFJAVACARD_H__

#include "common.h"

int CmdHFJavaCard(const char *Cmd);

// Lua-accessible GP primitives — registered by scripting.c under core.*
// Declared here to avoid including lua headers in scripting.c directly.
struct lua_State;
int CmdHFJavaCard_lua_send(struct lua_State *L);
int CmdHFJavaCard_lua_auth(struct lua_State *L);
int CmdHFJavaCard_lua_session(struct lua_State *L);

#endif // CMDHFJAVACARD_H__
