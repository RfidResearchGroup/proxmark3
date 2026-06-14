//-----------------------------------------------------------------------------
// Copyright (C) Aaron Tulino - December 2025
// Copyright (C) Christian Herrmman, Iceman - October 2025
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
// Calculate CMAC 3DES
//-----------------------------------------------------------------------------

#ifndef __CMAC_3DES_H
#define __CMAC_3DES_H


#include "common.h"

void des3_cmac(const uint8_t *key, size_t key_len, const uint8_t *input, size_t ilen, uint8_t output[8]);

#endif
