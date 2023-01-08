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
// Interlib Definitions
//-----------------------------------------------------------------------------

#ifndef __COMMON_H
#define __COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef _WIN32
#define ABOVE "../"
#define PATHSEP "/"
#else
#define ABOVE "../"
#define PATHSEP "/"
#endif

// PM3 share path relative to executable when installed
#define PM3_SHARE_RELPATH    ".." PATHSEP "share" PATHSEP "proxmark3" PATHSEP

// PM3_USER_DIRECTORY will be expanded from $HOME, e.g. ~/.proxmark3/
#define PM3_USER_DIRECTORY   PATHSEP ".proxmark3" PATHSEP

// PM3 subdirectories:
#define PYTHON_SCRIPTS_SUBDIR "pyscripts" PATHSEP
#define CMD_SCRIPTS_SUBDIR   "cmdscripts" PATHSEP
#define DICTIONARIES_SUBDIR  "dictionaries" PATHSEP
#define LUA_LIBRARIES_SUBDIR "lualibs" PATHSEP
#define LUA_SCRIPTS_SUBDIR   "luascripts" PATHSEP
#define RESOURCES_SUBDIR     "resources" PATHSEP
#define TRACES_SUBDIR        "traces" PATHSEP
#define LOGS_SUBDIR          "logs" PATHSEP
#define FIRMWARES_SUBDIR     "firmware" PATHSEP
#define BOOTROM_SUBDIR       "bootrom" PATHSEP "obj" PATHSEP
#define FULLIMAGE_SUBDIR     "armsrc" PATHSEP "obj" PATHSEP

#define PACKED __attribute__((packed))

#define VERSION_INFORMATION_MAGIC 0x56334d50 // "PM3V"
struct version_information_t {
    int magic; /* Magic sequence to identify this as a correct version information structure. Must be VERSION_INFORMATION_MAGIC */
    char versionversion; /* Must be 1 */
    char present; /* 1 if the version information could be created at compile time, otherwise 0 and the remaining fields (except for magic) are empty */
    char clean; /* 1: Tree was clean, no local changes. 0: Tree was unclean. 2: Couldn't be determined */
    char gitversion[50]; /* String with the git revision */
    char buildtime[30]; /* string with the build time */
    char armsrc[10]; /* sha256sum of sha256sum of armsrc && common_arm files */
} PACKED;

// debug
#define DBG_NONE          0 // no messages
#define DBG_ERROR         1 // errors only
#define DBG_INFO          2 // errors + info messages
#define DBG_DEBUG         3 // errors + info + debug messages
#define DBG_EXTENDED      4 // errors + info + debug + breaking debug messages
extern int g_dbglevel;

// tear-off
extern uint16_t g_tearoff_delay_us;
extern bool g_tearoff_enabled;

// reader voltage field detector
#define MF_MINFIELDV      4000

#ifndef MIN
# define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
# define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#ifndef ABS
# define ABS(a) ( ((a)<0) ? -(a) : (a) )
#endif


//#define RAMFUNC __attribute((long_call, section(".ramfunc")))
#define RAMFUNC __attribute((long_call, section(".ramfunc"))) __attribute__((target("arm")))

#ifndef ROTR
# define ROTR(x,n) (((uintmax_t)(x) >> (n)) | ((uintmax_t)(x) << ((sizeof(x) * 8) - (n))))
#endif

#ifndef PM3_ROTL
# define PM3_ROTL(x,n) (((uintmax_t)(x) << (n)) | ((uintmax_t)(x) >> ((sizeof(x) * 8) - (n))))
#endif

// endian change for 64bit
#ifdef __GNUC__
#ifndef BSWAP_64
#define BSWAP_64(x) __builtin_bswap64(x)
#endif
#else
#ifdef _MSC_VER
#ifndef BSWAP_64
#define BSWAP_64(x) _byteswap_uint64(x)
#endif
#else
#ifndef BSWAP_64
#define BSWAP_64(x) \
    (((uint64_t)(x) << 56) | \
     (((uint64_t)(x) << 40) & 0xff000000000000ULL) | \
     (((uint64_t)(x) << 24) & 0xff0000000000ULL) | \
     (((uint64_t)(x) << 8)  & 0xff00000000ULL) | \
     (((uint64_t)(x) >> 8)  & 0xff000000ULL) | \
     (((uint64_t)(x) >> 24) & 0xff0000ULL) | \
     (((uint64_t)(x) >> 40) & 0xff00ULL) | \
     ((uint64_t)(x)  >> 56))
#endif
#endif
#endif

// endian change for 32bit
#ifdef __GNUC__
#ifndef BSWAP_32
#define BSWAP_32(x) __builtin_bswap32(x)
#endif
#else
#ifdef _MSC_VER
#ifndef BSWAP_32
#define BSWAP_32(x) _byteswap_ulong(x)
#endif
#else
#ifndef BSWAP_32
# define BSWAP_32(x) \
    ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) | \
     (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))
#endif
#endif
#endif

// convert 2 bytes to U16 in little endian
#ifndef BYTES2UINT16
# define BYTES2UINT16(x) ((x[1] << 8) | (x[0]))
#endif
// convert 4 bytes to U32 in little endian
#ifndef BYTES2UINT32
# define BYTES2UINT32(x) ((x[3] << 24) | (x[2] << 16) | (x[1] << 8) | (x[0]))
#endif

// convert 4 bytes to U32 in big endian
#ifndef BYTES2UINT32_BE
# define BYTES2UINT32_BE(x) ((x[0] << 24) | (x[1] << 16) | (x[2] << 8) | (x[3]))
#endif


#define EVEN                        0
#define ODD                         1

// Nibble logic
#ifndef NIBBLE_HIGH
# define NIBBLE_HIGH(b) ( ((b) & 0xF0) >> 4 )
#endif

#ifndef NIBBLE_LOW
# define NIBBLE_LOW(b)  ((b) & 0x0F )
#endif

#ifndef CRUMB
# define CRUMB(b,p)    (((b & (0x3 << p) ) >> p ) & 0xF)
#endif

#ifndef SWAP_NIBBLE
# define SWAP_NIBBLE(b)  ( (NIBBLE_LOW(b)<< 4) | NIBBLE_HIGH(b))
#endif

// Binary Encoded Digit
#ifndef BCD2DEC
# define BCD2DEC(bcd) HornerScheme(bcd, 0x10, 10)
#endif

#ifndef DEC2BCD
# define DEC2BCD(dec) HornerScheme(dec, 10, 0x10)
#endif

// bit stream operations
#define TEST_BIT(data, i) (*(data + (i / 8)) >> (7 - (i % 8))) & 1
#define SET_BIT(data, i)   *(data + (i / 8)) |= (1 << (7 - (i % 8)))
#define CLEAR_BIT(data, i) *(data + (i / 8)) &= ~(1 << (7 - (i % 8)))
#define FLIP_BIT(data, i)  *(data + (i / 8)) ^= (1 << (7 - (i % 8)))

#endif
