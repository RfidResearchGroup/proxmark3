//-----------------------------------------------------------------------------
// Borrowed initially from https://github.com/LuaDist/lpack/blob/master/lpack.c
// Copyright (C) 2007 Luiz Henrique de Figueiredo <lhf@tecgraf.puc-rio.br>
// Copyright (C) Ignacio Castao <castanyo@yahoo.es>
// Copyright (C) Roberto Ierusalimschy <roberto@inf.puc-rio.br>
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
// a Lua library for packing and unpacking binary data
//-----------------------------------------------------------------------------
#ifndef PM3_BINLIB
#define PM3_BINLIB

#include <lua.h>
int set_bin_library(lua_State *L);

#endif /* PM3_BINLIB */
