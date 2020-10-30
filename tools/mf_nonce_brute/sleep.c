//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// platform-independant sleep macros
//-----------------------------------------------------------------------------

#ifndef _WIN32

#define _POSIX_C_SOURCE 199309L
#include "sleep.h"
#include <time.h>
#include <stdio.h>
#include <sys/time.h>
#include <errno.h>

void nsleep(uint64_t n) {
    struct timespec timeout;
    timeout.tv_sec = n / 1000000000;
    timeout.tv_nsec = n % 1000000000;
    while (nanosleep(&timeout, &timeout) && errno == EINTR);
}

#endif // _WIN32

