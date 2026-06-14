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
// Hitag2 crack implementeation
//-----------------------------------------------------------------------------

#ifndef _HITAG2_CRACK__H_
#define _HITAG2_CRACK__H_

#include <stdbool.h>
#include "common.h"

void ht2_crack1(uint8_t *nrar_hex);
void ht2_crack2(uint8_t *nrar_hex);
#endif
