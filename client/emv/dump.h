/*
 * libopenemv - a library to work with EMV family of smart cards
 * Copyright (C) 2015 Dmitry Eremin-Solenikov
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#ifndef DUMP_H
#define DUMP_H

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

void dump_buffer_simple(const unsigned char *ptr, size_t len, FILE *f);
void dump_buffer(const unsigned char *ptr, size_t len, FILE *f, int level);
void dump_buffer_tab(const unsigned char *ptr, size_t len, FILE *f, int tabs);

#endif
