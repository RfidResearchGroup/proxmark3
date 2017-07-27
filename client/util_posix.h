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

#include <stdint.h>

#ifdef _WIN32
# include <windows.h>
# define sleep(n) Sleep(1000 *(n))
# define msleep(n) Sleep((n))
#else
extern void msleep(uint32_t n);		// sleep n milliseconds
#endif // _WIN32

extern uint64_t msclock(); 			// a milliseconds clock

#endif
