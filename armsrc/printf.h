//-----------------------------------------------------------------------------
// Borrowed initially from subr_prf.c 8.3 (Berkeley) 1/21/94
// Copyright (c) 1986, 1988, 1991, 1993
// The Regents of the University of California.  All rights reserved.
// (c) UNIX System Laboratories, Inc.
// All or some portions of this file are derived from material licensed
// to the University of California by American Telephone and Telegraph
// Co. or Unix System Laboratories, Inc. and are reproduced herein with
// the permission of UNIX System Laboratories, Inc.
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
// Common *printf() functions
//-----------------------------------------------------------------------------

#ifndef __PRINTF_H
#define __PRINTF_H

#include "common.h"
#include <stdarg.h> // va_list

int kvsprintf(const char *fmt, void *arg, int radix, va_list ap) __attribute__((format(printf, 1, 0)));
int vsprintf(char *dest, const char *fmt, va_list ap) __attribute__((format(printf, 2, 0)));
int sprintf(char *dest, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

#endif
