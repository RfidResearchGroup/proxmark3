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
// Generic Wiegand Calculation code
//-----------------------------------------------------------------------------

#ifndef __WIEGAND_H
#define __WIEGAND_H

#include "common.h"

uint8_t getParity(const uint8_t *bits, uint8_t len, uint8_t type);
uint8_t checkParity(uint32_t bits, uint8_t len, uint8_t type);

void num_to_wiegand_bytes(uint64_t oem, uint64_t fc, uint64_t cn, uint8_t *dest, uint8_t formatlen);
void num_to_wiegand_bits(uint64_t oem, uint64_t fc, uint64_t cn, uint8_t *dest, uint8_t formatlen);

#endif /* __WIEGAND_H */
