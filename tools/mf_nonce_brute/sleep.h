//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// platform-independant sleep macros
//-----------------------------------------------------------------------------

#ifndef SLEEP_H__
#define SLEEP_H__

#ifdef _WIN32
# include <windows.h>
# define sleep(n) Sleep(1000 * n)
# define msleep(n) Sleep(n)
#else
# include <inttypes.h>
# include <unistd.h>
void nsleep(uint64_t n);
# define msleep(n) nsleep(1000000 * n)
# define usleep(n) nsleep(1000 * n)
#endif // _WIN32

#endif // SLEEP_H__

