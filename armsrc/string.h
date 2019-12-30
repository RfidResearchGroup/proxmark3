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

#include "common.h"

int strlen(const char *str);
void *memcpy(void *dest, const void *src, int len);
void *memset(void *dest, int c, int len);
int memcmp(const void *av, const void *bv, int len);
void memxor(uint8_t *dest, uint8_t *src, size_t len);
char *strncat(char *dest, const char *src, unsigned int n);
char *strcat(char *dest, const char *src);
void strreverse(char s[]);
void itoa(int n, char s[]);
char *strcpy(char *dst, const char *src);
char *strncpy(char *dst, const char *src, size_t n);
int strcmp(const char *s1, const char *s2);
char *strtok(char *s, const char *delim);
char *strchr(const char *s, int c);
size_t strspn(const char *s1, const char *s2);
char *strrchr(const char *s, int c);
size_t strcspn(const char *s1, const char *s2);
char *strpbrk(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t n);
char c_tolower(int c);
char c_isprint(unsigned char c);

#endif /* __STRING_H */
