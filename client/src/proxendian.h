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
// Endianness convenience functions
//-----------------------------------------------------------------------------

#ifndef PROXENDIAN_H__
#define PROXENDIAN_H__

#include "common.h"

#ifdef _WIN32
# define HOST_LITTLE_ENDIAN
#else
// Only some OSes include endian.h from sys/types.h, not Termux, so let's include endian.h directly
# if defined(__APPLE__)
#  include <machine/endian.h>
# else
#  include <endian.h>
# endif
# if !defined(BYTE_ORDER)
#  if !defined(__BYTE_ORDER) || (__BYTE_ORDER != __LITTLE_ENDIAN && __BYTE_ORDER != __BIG_ENDIAN)
#   error Define BYTE_ORDER to be equal to either LITTLE_ENDIAN or BIG_ENDIAN
#  endif
#  if __BYTE_ORDER == __LITTLE_ENDIAN
#   define HOST_LITTLE_ENDIAN
#  endif
# else
#  if BYTE_ORDER != LITTLE_ENDIAN && BYTE_ORDER != BIG_ENDIAN
#   error Define BYTE_ORDER to be equal to either LITTLE_ENDIAN or BIG_ENDIAN
#  endif
#  if BYTE_ORDER == LITTLE_ENDIAN
#   define HOST_LITTLE_ENDIAN
#  endif
# endif
#endif

#ifdef HOST_LITTLE_ENDIAN
# define le16(x) (x)
# define le32(x) (x)
#else

static inline uint16_t le16(uint16_t v) {
    return (uint16_t)(
               (v >> 8) | (v << 8)
           );
}

static inline uint32_t le32(uint32_t v) {
    return (uint32_t)(
               (le16(v) << 16) | (le16(v >> 16))
           );
}
#endif // HOST_LITTLE_ENDIAN

#endif // PROXENDIAN_H__
