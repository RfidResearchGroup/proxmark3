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
// Common string.h functions
//-----------------------------------------------------------------------------

#ifndef __STRING_H
#define __STRING_H

#include "common.h"

int strlen(const char *str);
void *memcpy(void *dest, const void *src, int len);
void *memmove(void *dest, const void *src, size_t len);
void *memset(void *dest, uint8_t c, int len);
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
unsigned long strtoul(const char *p, char **out_p, int base);
long strtol(const char *p, char **out_p, int base);
char c_tolower(int c);
char c_isprint(unsigned char c);

#endif /* __STRING_H */
