//-----------------------------------------------------------------------------
// Borrowed initially from
// https://web.archive.org/web/20070920142755/http://www.simonshepherd.supanet.com:80/source.htm#ansi
// Copyright (C) Simon Shepherd 2003
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
// Generic TEA crypto code.
//-----------------------------------------------------------------------------

#ifndef __TEA_H
#define __TEA_H

#include "common.h"

void tea_encrypt(uint8_t *v, uint8_t *key);
void tea_decrypt(uint8_t *v, uint8_t *key);

#endif /* __TEA_H */
