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

#define    OP_ZSTRING      'z'        /* zero-terminated string */
#define    OP_BSTRING      'p'        /* string preceded by length byte */
#define    OP_WSTRING      'P'        /* string preceded by length word */
#define    OP_SSTRING      'a'        /* string preceded by length size_t */
#define    OP_STRING       'A'        /* string */
#define    OP_FLOAT        'f'        /* float */
#define    OP_DOUBLE       'd'        /* double */
#define    OP_NUMBER       'n'        /* Lua number */
#define    OP_CHAR         'c'        /* char (1-byte int) */
#define    OP_BYTE         'C'        /* byte = unsigned char (1-byte unsigned int) */
#define    OP_SHORT        's'        /* short (2-byte int) */
#define    OP_USHORT       'S'        /* unsigned short (2-byte unsigned int) */
#define    OP_INT          'i'        /* int (4-byte int) */
#define    OP_UINT         'I'        /* unsigned int (4-byte unsigned int) */
#define    OP_LONG         'l'        /* long (8-byte int) */
#define    OP_ULONG        'L'        /* unsigned long (8-byte unsigned int) */
#define    OP_LITTLEENDIAN '<'        /* little endian */
#define    OP_BIGENDIAN    '>'        /* big endian */
#define    OP_NATIVE       '='        /* native endian */

#define OP_HEX 'H'

#include <ctype.h>
#include <string.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <stdint.h>
#include "pm3_binlib.h"


static void badcode(lua_State *L, int c) {
    char s[] = "bad code `?'";
    s[sizeof(s) - 3] = c;
    luaL_argerror(L, 1, s);
}

static int doendian(int c) {
    int x = 1;
    int e = *(char *)&x;
    if (c == OP_LITTLEENDIAN) return !e;
    if (c == OP_BIGENDIAN) return e;
    if (c == OP_NATIVE) return 0;
    return 0;
}

static void doswap(int swap, void *p, size_t n) {
    if (swap) {
        char *a = (char *)p;
        int i, j;
        for (i = 0, j = n - 1, n = n / 2; n--; i++, j--) {
            char t = a[i];
            a[i] = a[j];
            a[j] = t;
        }
    }
}

#define UNPACKNUMBER(OP,T)                      \
    case OP:                                     \
    {                                            \
        T a;                                        \
        int m=sizeof(a);                            \
        if (i+m>len) { done = 1;    break;}         \
        memcpy(&a,s+i,m);                           \
        i+=m;                                       \
        doswap(swap,&a,m);                          \
        lua_pushnumber(L,(lua_Number)a);            \
        ++n;                                        \
        break;                                      \
    }

#define UNPACKSTRING(OP,T)                      \
    case OP:                                     \
    {                                            \
        T l;                                        \
        int m = sizeof(l);                          \
        if (i + m > len) { done = 1;    break; }    \
        memcpy(&l, s+i, m);                         \
        doswap(swap,&l,m);                          \
        if (i + m + l > len) { done = 1; break;}    \
        i += m;                                     \
        lua_pushlstring(L,s+i,l);                   \
        i += l;                                     \
        ++n;                                        \
        break;                                      \
    }

#define HEXDIGITS(DIG) \
    "0123456789ABCDEF"[DIG]

static int l_unpack(lua_State *L) {       /** unpack(f,s, [init]) */
    size_t len;
    const char *s = luaL_checklstring(L, 2, &len); /* switched s and f */
    const char *f = luaL_checkstring(L, 1);
    int i_read = luaL_optinteger(L, 3, 1) - 1;
//int i_read = (int)luaL_optint(L,(3),(1))-1;
    unsigned int i;
    if (i_read >= 0) {
        i = i_read;
    } else {
        i = 0;
    }
    int n = 0;
    int swap = 0;
    int done = 0;
    lua_pushnil(L);
    while (*f && done == 0) {
        int c = *f++;
        int N = 1;
        if (isdigit((int)(unsigned char) *f)) {
            N = 0;
            while (isdigit((int)(unsigned char) *f)) N = 10 * N + (*f++) - '0';
            if (N == 0 && c == OP_STRING) { lua_pushliteral(L, ""); ++n; }
        }
        while (N-- && done == 0) switch (c) {
                case OP_LITTLEENDIAN:
                case OP_BIGENDIAN:
                case OP_NATIVE: {
                    swap = doendian(c);
                    N = 0;
                    break;
                }
                case OP_STRING: {
                    ++N;
                    if (i + N > len) {done = 1; break; }
                    lua_pushlstring(L, s + i, N);
                    i += N;
                    ++n;
                    N = 0;
                    break;
                }
                case OP_ZSTRING: {
                    size_t l;
                    if (i >= len) {done = 1; break; }
                    l = strlen(s + i);
                    lua_pushlstring(L, s + i, l);
                    i += l + 1;
                    ++n;
                    break;
                }

                UNPACKSTRING(OP_BSTRING, uint8_t)
                UNPACKSTRING(OP_WSTRING, uint16_t)
                UNPACKSTRING(OP_SSTRING, uint32_t)
                UNPACKNUMBER(OP_NUMBER, lua_Number)
                UNPACKNUMBER(OP_DOUBLE, double)
                UNPACKNUMBER(OP_FLOAT, float)
                UNPACKNUMBER(OP_CHAR, int8_t)
                UNPACKNUMBER(OP_BYTE, uint8_t)
                UNPACKNUMBER(OP_SHORT, int16_t)
                UNPACKNUMBER(OP_USHORT, uint16_t)
                UNPACKNUMBER(OP_INT, int32_t)
                UNPACKNUMBER(OP_UINT, uint32_t)
                UNPACKNUMBER(OP_LONG, int64_t)
                UNPACKNUMBER(OP_ULONG, uint64_t)
                case OP_HEX: {
                    luaL_Buffer buf;
                    char hdigit = '0';
                    luaL_buffinit(L, &buf);
                    N++;
                    if (i + N > len) {done = 1; break;}
                    for (unsigned int ii = i; ii < i + N; ii++) {
                        int val = s[ii] & 0xF0;
                        val = val >> 4;
                        hdigit = HEXDIGITS(val);
                        luaL_addlstring(&buf, &hdigit, 1);

                        val = s[ii] & 0x0F;
                        hdigit = HEXDIGITS(val);
                        luaL_addlstring(&buf, &hdigit, 1);
                    }
                    luaL_pushresult(&buf);
                    n++;
                    i += N;
                    N = 0;
                    break;
                }

                case ' ':
                case ',':
                    break;
                default:
                    badcode(L, c);
                    break;
            }
    }
    lua_pushnumber(L, i + 1);
    lua_replace(L, -n - 2);
    return n + 1;
}

#define PACKNUMBER(OP,T)                        \
    case OP:                                     \
    {                                            \
        lua_Number n = luaL_checknumber(L,i++);  \
        T a=(T)n;                                \
        doswap(swap,&a,sizeof(a));                  \
        luaL_addlstring(&b,(char*)&a,sizeof(a));    \
        break;                                      \
    }

#define PACKSTRING(OP,T)                        \
    case OP:                                     \
    {                                            \
        size_t l;                                   \
        const char *a=luaL_checklstring(L,i++,&l);  \
        T ll=(T)l;                                  \
        doswap(swap,&ll,sizeof(ll));                \
        luaL_addlstring(&b,(char*)&ll,sizeof(ll));  \
        luaL_addlstring(&b,a,l);                    \
        break;                                      \
    }

static int l_pack(lua_State *L) {       /** pack(f,...) */
    int i = 2;
    const char *f = luaL_checkstring(L, 1);
    int swap = 0;
    luaL_Buffer b;
    luaL_buffinit(L, &b);
    while (*f) {
        int c = *f++;
        int N = 1;
        if (isdigit((int)(unsigned char) *f)) {
            N = 0;
            while (isdigit((int)(unsigned char) *f)) N = 10 * N + (*f++) - '0';
        }
        while (N--) switch (c) {
                case OP_LITTLEENDIAN:
                case OP_BIGENDIAN:
                case OP_NATIVE: {
                    swap = doendian(c);
                    N = 0;
                    break;
                }
                case OP_STRING:
                case OP_ZSTRING: {
                    size_t l;
                    const char *a = luaL_checklstring(L, i++, &l);
                    luaL_addlstring(&b, a, l + (c == OP_ZSTRING));
                    break;
                }
                PACKSTRING(OP_BSTRING, uint8_t)
                PACKSTRING(OP_WSTRING, uint16_t)
                PACKSTRING(OP_SSTRING, uint32_t)
                PACKNUMBER(OP_NUMBER, lua_Number)
                PACKNUMBER(OP_DOUBLE, double)
                PACKNUMBER(OP_FLOAT, float)
                PACKNUMBER(OP_CHAR, int8_t)
                PACKNUMBER(OP_BYTE, uint8_t)
                PACKNUMBER(OP_SHORT, int16_t)
                PACKNUMBER(OP_USHORT, uint16_t)
                PACKNUMBER(OP_INT, int32_t)
                PACKNUMBER(OP_UINT, uint32_t)
                PACKNUMBER(OP_LONG, int64_t)
                PACKNUMBER(OP_ULONG, uint64_t)
                case OP_HEX: {
                    // doing digit parsing the lpack way
                    unsigned char sbyte = 0;
                    size_t l;
                    unsigned int ii = 0;
                    int odd = 0;
                    const char *a = luaL_checklstring(L, i++, &l);
                    for (ii = 0; ii < l; ii++) {
                        if (isxdigit((int)(unsigned char) a[ii])) {
                            if (isdigit((int)(unsigned char) a[ii])) {
                                sbyte += a[ii] - '0';
                                odd++;
                            } else if (a[ii] >= 'A' && a[ii] <= 'F') {
                                sbyte += a[ii] - 'A' + 10;
                                odd++;
                            } else if (a[ii] >= 'a' && a[ii] <= 'f') {
                                sbyte += a[ii] - 'a' + 10;
                                odd++;
                            }
                            if (odd == 1) {
                                sbyte = sbyte << 4;
                            } else if (odd == 2) {
                                luaL_addlstring(&b, (char *) &sbyte, 1);
                                sbyte = 0;
                                odd = 0;
                            }
                        } else if (isspace(a[ii])) {
                            /* ignore */
                        } else {
                            /* err ... ignore too*/
                        }
                    }
                    if (odd == 1) {
                        luaL_addlstring(&b, (char *) &sbyte, 1);
                    }
                    break;
                }
                case ' ':
                case ',':
                    break;
                default:
                    badcode(L, c);
                    break;
            }
    }
    luaL_pushresult(&b);
    return 1;
}

static const luaL_Reg binlib[] = {
    {"pack",   l_pack},
    {"unpack", l_unpack},
    {NULL,     NULL}
};

LUALIB_API int luaopen_binlib(lua_State *L);
LUALIB_API int luaopen_binlib(lua_State *L) {
    luaL_newlib(L, binlib);
    return 1;
}
/*
** Open bin library
*/
int set_bin_library(lua_State *L) {

    luaL_requiref(L, "bin", luaopen_binlib, 1);
    lua_pop(L, 1);
    return 1;
}

