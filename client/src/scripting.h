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
// Some lua scripting glue to proxmark core.
//-----------------------------------------------------------------------------
#ifndef SCRIPTING_H__
#define SCRIPTING_H__

#include <lua.h>
//#include <lualib.h>
//#include <lauxlib.h>

#define LUA_LIBRARIES_WILDCARD  "?.lua"

/**
 * @brief set_libraries loads the core components of pm3 into the 'pm3'
 *  namespace within the given lua_State
 * @param L
 */

int set_pm3_libraries(lua_State *L);

#endif
