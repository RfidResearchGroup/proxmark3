/*
** $Id: lbitlib.c,v 1.18 2013/03/19 13:19:12 roberto Exp $
** Standard library for bitwise operations
** See Copyright Notice in lua.h
**
** Patched to provide a compatibility layer with Lua5.3+ where
** bit32 library was removed.
*/

#include "lua_bitlib.h"

#include "lauxlib.h"

/* number of bits to consider in a number */
#define LUA_BITLIB_NBITS 32


#define ALLONES (~(((~(lua_Unsigned)0) << (LUA_BITLIB_NBITS - 1)) << 1))

/* macro to trim extra bits */
#define trim(x) ((x) & ALLONES)


/* builds a number with 'n' ones (1 <= n <= LUA_BITLIB_NBITS) */
#define mask(n) (~((ALLONES << 1) << ((n) - 1)))


typedef lua_Unsigned b_uint;


static b_uint andaux(lua_State *L) {
    int i, n = lua_gettop(L);
    b_uint r = ~(b_uint)0;
    for (i = 1; i <= n; i++)
        r &= (b_uint)luaL_checkinteger(L, i);
    return trim(r);
}


static int b_and(lua_State *L) {
    b_uint r = andaux(L);
    lua_pushinteger(L, r);
    return 1;
}


static int b_test(lua_State *L) {
    b_uint r = andaux(L);
    lua_pushboolean(L, r != 0);
    return 1;
}


static int b_or(lua_State *L) {
    int i, n = lua_gettop(L);
    b_uint r = 0;
    for (i = 1; i <= n; i++)
        r |= (b_uint) luaL_checkinteger(L, i);
    lua_pushinteger(L, trim(r));
    return 1;
}


static int b_xor(lua_State *L) {
    int i, n = lua_gettop(L);
    b_uint r = 0;
    for (i = 1; i <= n; i++)
        r ^= (b_uint) luaL_checkinteger(L, i);
    lua_pushinteger(L, trim(r));
    return 1;
}


static int b_not(lua_State *L) {
    b_uint r = ~((b_uint)luaL_checkinteger(L, 1));
    lua_pushinteger(L, trim(r));
    return 1;
}


static int b_shift(lua_State *L, b_uint r, int i) {
    if (i < 0) {  /* shift right? */
        i = -i;
        r = trim(r);
        if (i >= LUA_BITLIB_NBITS) r = 0;
        else r >>= i;
    } else { /* shift left */
        if (i >= LUA_BITLIB_NBITS) r = 0;
        else r <<= i;
        r = trim(r);
    }
    lua_pushinteger(L, r);
    return 1;
}


static int b_lshift(lua_State *L) {
    return b_shift(L, (b_uint)luaL_checkinteger(L, 1), luaL_checkinteger(L, 2));
}


static int b_rshift(lua_State *L) {
    return b_shift(L, (b_uint)luaL_checkinteger(L, 1), -luaL_checkinteger(L, 2));
}


static int b_arshift(lua_State *L) {
    b_uint r = (b_uint)luaL_checkinteger(L, 1);
    int i = luaL_checkinteger(L, 2);
    if (i < 0 || !(r & ((b_uint)1 << (LUA_BITLIB_NBITS - 1))))
        return b_shift(L, r, -i);
    else {  /* arithmetic shift for 'negative' number */
        if (i >= LUA_BITLIB_NBITS) r = ALLONES;
        else
            r = trim((r >> i) | ~(~(b_uint)0 >> i));  /* add signal bit */
        lua_pushinteger(L, r);
        return 1;
    }
}


static int b_rot(lua_State *L, int i) {
    b_uint r = (b_uint)luaL_checkinteger(L, 1);
    i &= (LUA_BITLIB_NBITS - 1);  /* i = i % NBITS */
    r = trim(r);
    if (i != 0)  /* avoid undefined shift of LUA_BITLIB_NBITS when i == 0 */
        r = (r << i) | (r >> (LUA_BITLIB_NBITS - i));

    lua_pushinteger(L, trim(r));
    return 1;
}


static int b_lrot(lua_State *L) {
    return b_rot(L, luaL_checkinteger(L, 2));
}


static int b_rrot(lua_State *L) {
    return b_rot(L, -luaL_checkinteger(L, 2));
}


/*
** get field and width arguments for field-manipulation functions,
** checking whether they are valid.
** ('luaL_error' called without 'return' to avoid later warnings about
** 'width' being used uninitialized.)
*/
static int fieldargs(lua_State *L, int farg, int *width) {
    int f = luaL_checkinteger(L, farg);
    int w = luaL_optinteger(L, farg + 1, 1);
    luaL_argcheck(L, 0 <= f, farg, "field cannot be negative");
    luaL_argcheck(L, 0 < w, farg + 1, "width must be positive");
    if (f + w > LUA_BITLIB_NBITS)
        luaL_error(L, "trying to access non-existent bits");
    *width = w;
    return f;
}


static int b_extract(lua_State *L) {
    int w;
    b_uint r = (b_uint)luaL_checkinteger(L, 1);
    int f = fieldargs(L, 2, &w);
    r = (r >> f) & mask(w);
    lua_pushinteger(L, r);
    return 1;
}


static int b_replace(lua_State *L) {
    int w;
    b_uint r = (b_uint)luaL_checkinteger(L, 1);
    b_uint v = (b_uint)luaL_checkinteger(L, 2);
    int f = fieldargs(L, 3, &w);
    int m = mask(w);
    v &= m;  /* erase bits outside given width */
    r = (r & ~(m << f)) | (v << f);
    lua_pushinteger(L, r);
    return 1;
}


void register_bit32_lib(lua_State *L) {
  static const luaL_Reg bitlib[] = {
    {"arshift", b_arshift},
    {"band", b_and},
    {"bnot", b_not},
    {"bor", b_or},
    {"bxor", b_xor},
    {"btest", b_test},
    {"extract", b_extract},
    {"lrotate", b_lrot},
    {"lshift", b_lshift},
    {"replace", b_replace},
    {"rrotate", b_rrot},
    {"rshift", b_rshift},
    {NULL, NULL}
  };

  luaL_newlib(L, bitlib);
  lua_setfield(L, -2, "bit32");
}

