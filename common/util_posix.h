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
// utilities requiring Posix library functions
//-----------------------------------------------------------------------------

#ifndef UTIL_POSIX_H__
#define UTIL_POSIX_H__

#include "common.h"

#ifdef _WIN32
# include <windows.h>
# define sleep(n) Sleep(1000 *(n))
# define msleep(n) Sleep((n))
#else
void msleep(uint32_t n); // sleep n milliseconds
#endif // _WIN32

uint64_t msclock(void);      // a milliseconds clock

#endif
