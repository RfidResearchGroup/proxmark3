//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
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
