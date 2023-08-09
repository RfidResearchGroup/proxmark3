//-----------------------------------------------------------------------------
// Copyright (C) Jonathan Westhues, Aug 2005
// Copyright (C) Gerhard de Koning Gans, April 2008
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

#ifndef __DBPRINT_H
#define __DBPRINT_H

#include "common.h"
#include "ansi.h"

void DbpString(const char *str);
void DbpStringEx(uint32_t flags, const char *src, size_t srclen);
void Dbprintf(const char *fmt, ...);
void DbprintfEx(uint32_t flags, const char *fmt, ...);
void Dbhexdump(int len, const uint8_t *d, bool bAsci);
void print_result(const char *name, const uint8_t *buf, size_t len);
//void PrintToSendBuffer(void);

#endif
