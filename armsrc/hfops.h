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
// HF general operations
//-----------------------------------------------------------------------------

#ifndef HFOPS_H
#define HFOPS_H

#include "common.h"

int HfReadADC(uint32_t samplesCount, bool ledcontrol);
int HfSimulateTkm(const uint8_t *uid, uint8_t modulation, uint32_t timeout);

#endif
