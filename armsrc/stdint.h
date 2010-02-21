//-----------------------------------------------------------------------------
// Copyright (C) 2010 Hector Martin "marcan" <marcan@marcansoft.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Replacement stdint.h because GCC doesn't come with it yet (C99)
//-----------------------------------------------------------------------------

#ifndef __STDINT_H
#define __STDINT_H

typedef signed char				int8_t;
typedef short int				int16_t;
typedef int						int32_t;
typedef long long int			int64_t;

typedef unsigned char			uint8_t;
typedef unsigned short int		uint16_t;
typedef unsigned int			uint32_t;
typedef unsigned long long int	uint64_t;

typedef int						intptr_t;
typedef unsigned int			uintptr_t;

#endif /* __STDINT_H */
