//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#ifndef EMV_TERM_LUA_H__
#define EMV_TERM_LUA_H__

struct lua_State;

void emv_term_lua_register(struct lua_State *L);

#endif
