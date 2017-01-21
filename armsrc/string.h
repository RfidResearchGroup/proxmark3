//-----------------------------------------------------------------------------
// Jonathan Westhues, Aug 2005
// Copyright (C) 2010 Hector Martin "marcan" <marcan@marcansoft.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Common string.h functions
//-----------------------------------------------------------------------------

#ifndef __STRING_H
#define __STRING_H

#include <common.h>

int strlen(const char *str);
RAMFUNC void *memcpy(void *dest, const void *src, int len);
void *memset(void *dest, int c, int len);
RAMFUNC int memcmp(const void *av, const void *bv, int len);
void memxor(uint8_t * dest, uint8_t * src, size_t len);
char *strncat(char *dest, const char *src, unsigned int n);
char *strcat(char *dest, const char *src);
void strreverse(char s[]);
void itoa(int n, char s[]);

#endif /* __STRING_H */