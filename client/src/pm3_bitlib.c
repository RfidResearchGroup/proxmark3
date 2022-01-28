//-----------------------------------------------------------------------------
// Borrowed initially from https://github.com/LuaDist/bitlib
// Copyright (C) Reuben Thomas 2000-2008
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
// Bitwise operations library
//-----------------------------------------------------------------------------

#include <lua.h>
#include <lauxlib.h>
#include <limits.h>

#include "pm3_bit_limits.h"
#include "pm3_bitlib.h"


/* FIXME: Assumes lua_Integer is ptrdiff_t */
#define LUA_INTEGER_MAX PTRDIFF_MAX
#define LUA_INTEGER_MIN PTRDIFF_MIN

/* FIXME: Assumes size_t is an unsigned lua_Integer */
typedef size_t lua_UInteger;
#define LUA_UINTEGER_MAX SIZE_MAX


/* Bit type size and limits */

#define BIT_BITS                                                        \
    (CHAR_BIT * sizeof(lua_Integer) > BITLIB_FLOAT_BITS ?                 \
     BITLIB_FLOAT_BITS : (CHAR_BIT * sizeof(lua_Integer)))

/* This code may give warnings if BITLIB_FLOAT_* are too big to fit in
   long, but that doesn't matter since in that case they won't be
   used. */
#define BIT_MAX                                                         \
    (CHAR_BIT * sizeof(lua_Integer) > BITLIB_FLOAT_BITS ? BITLIB_FLOAT_MAX : LUA_INTEGER_MAX)

#define BIT_MIN                                                         \
    (CHAR_BIT * sizeof(lua_Integer) > BITLIB_FLOAT_BITS ? BITLIB_FLOAT_MIN : LUA_INTEGER_MIN)

#define BIT_UMAX                                                        \
    (CHAR_BIT * sizeof(lua_Integer) > BITLIB_FLOAT_BITS ? BITLIB_FLOAT_UMAX : LUA_UINTEGER_MAX)


/* Define TOBIT to get a bit value */
#ifdef BUILTIN_CAST
#define
#define TOBIT(L, n, res)                    \
    ((void)(res), luaL_checkinteger((L), (n)))
#else
#include <stdint.h>
#include <math.h>

/* FIXME: Assumes lua_Number fits in a double (use of fmod). */
#define TOBIT(L, n, res)                                            \
    ((lua_Integer)(((res) = fmod(luaL_checknumber(L, (n)), (double)BIT_UMAX + 1.0)), \
                   (res) > BIT_MAX ? ((res) -= (double)BIT_UMAX, (res) -= 1) : \
                   ((res) < BIT_MIN ? ((res) += (double)BIT_UMAX, (res) += 1) : (res))))
#endif


#define BIT_TRUNCATE(i)                         \
    ((i) & BIT_UMAX)


/* Operations

   The macros MONADIC and VARIADIC only deal with bitwise operations.

   LOGICAL_SHIFT truncates its left-hand operand before shifting so
   that any extra bits at the most-significant end are not shifted
   into the result.

   ARITHMETIC_SHIFT does not truncate its left-hand operand, so that
   the sign bits are not removed and right shift work properly.
   */

#define MONADIC(name, op)                                       \
    static int bit_ ## name(lua_State *L) {                       \
        lua_Number f;                                               \
        lua_pushinteger(L, BIT_TRUNCATE(op TOBIT(L, 1, f)));        \
        return 1;                                                   \
    }

#define VARIADIC(name, op)                      \
    static int bit_ ## name(lua_State *L) {       \
        lua_Number f;                               \
        int n = lua_gettop(L), i;                   \
        lua_Integer w = TOBIT(L, 1, f);             \
        for (i = 2; i <= n; i++)                    \
            w op TOBIT(L, i, f);                      \
        lua_pushinteger(L, BIT_TRUNCATE(w));        \
        return 1;                                   \
    }

#define LOGICAL_SHIFT(name, op)                                         \
    static int bit_ ## name(lua_State *L) {                               \
        lua_Number f;                                                       \
        lua_Number n = luaL_checknumber(L, 2);                              \
        lua_pushinteger(L, BIT_TRUNCATE(BIT_TRUNCATE((lua_UInteger)TOBIT(L, 1, f)) op \
                                        (unsigned)n)); \
        return 1;                                                           \
    }

#define ARITHMETIC_SHIFT(name, op)                                      \
    static int bit_ ## name(lua_State *L) {                               \
        lua_Number f;                                                       \
        lua_Number n = luaL_checknumber(L, 2);                              \
        lua_pushinteger(L, BIT_TRUNCATE((lua_Integer)TOBIT(L, 1, f) op      \
                                        (unsigned)n)); \
        return 1;                                                           \
    }

MONADIC(cast,  +)
MONADIC(bnot,  ~)
VARIADIC(band, &=)
VARIADIC(bor,  |=)
VARIADIC(bxor, ^=)
ARITHMETIC_SHIFT(lshift,  <<)
LOGICAL_SHIFT(rshift,     >>)
ARITHMETIC_SHIFT(arshift, >>)

static const struct luaL_Reg bitlib[] = {
    {"cast",    bit_cast},
    {"bnot",    bit_bnot},
    {"band",    bit_band},
    {"bor",     bit_bor},
    {"bxor",    bit_bxor},
    {"lshift",  bit_lshift},
    {"rshift",  bit_rshift},
    {"arshift", bit_arshift},
    {NULL, NULL}
};

LUALIB_API int luaopen_bit(lua_State *L);
LUALIB_API int luaopen_bit(lua_State *L) {
    luaL_newlib(L, bitlib);
    //luaL_register(L, "bit", bitlib);
    lua_pushnumber(L, BIT_BITS);
    lua_setfield(L, -2, "bits");
    return 1;
}

/**
LUALIB_API int luaopen_bit (lua_State *L) {
  luaL_register(L, "bit", bitlib);
  lua_pushnumber(L, BIT_BITS);
  lua_setfield(L, -2, "bits");
  return 1;
}
**/
/*
** Open bit library
*/
int set_bit_library(lua_State *L) {

    luaL_requiref(L, "bit", luaopen_bit, 1);
    lua_pop(L, 1);
    return 1;
}
