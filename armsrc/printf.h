//-----------------------------------------------------------------------------
// Copyright (C) 2010 Hector Martin "marcan" <marcan@marcansoft.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Common *printf() functions
//-----------------------------------------------------------------------------

#ifndef __PRINTF_H
#define __PRINTF_H

#include <stdarg.h>

int kvsprintf(const char *format, void *arg, int radix, va_list ap) __attribute__ ((format (printf, 1, 0)));
int vsprintf(char *str, const char *format, va_list ap) __attribute__ ((format (printf, 2, 0)));
int sprintf(char *str, const char *format, ...) __attribute__ ((format (printf, 2, 3)));

#endif
