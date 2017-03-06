//-----------------------------------------------------------------------------
// Copyright (C) 2010 Hector Martin "marcan" <marcan@marcansoft.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Endianness convenience functions
//-----------------------------------------------------------------------------

#ifndef PROXENDIAN_H__
#define PROXENDIAN_H__

#include <stdint.h>

#ifdef _WIN32
# define HOST_LITTLE_ENDIAN
#else
# include <sys/types.h>

# if !defined(BYTE_ORDER) || (BYTE_ORDER != LITTLE_ENDIAN && BYTE_ORDER != BIG_ENDIAN)
#  error Define BYTE_ORDER to be equal to either LITTLE_ENDIAN or BIG_ENDIAN
# endif

# if BYTE_ORDER == LITTLE_ENDIAN
#  define HOST_LITTLE_ENDIAN
# endif
#endif

#ifdef HOST_LITTLE_ENDIAN
# define le16(x) (x)
# define le32(x) (x)
#else

static inline uint16_t le16(uint16_t v)
{
	return (v>>8) | (v<<8);
}

static inline uint32_t le32(uint32_t v)
{
	return (le16(v)<<16) | (le16(v>>16));
}
#endif // HOST_LITTLE_ENDIAN

#endif // PROXENDIAN_H__
