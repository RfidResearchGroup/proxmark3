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
// Hitag2 type prototyping
//-----------------------------------------------------------------------------

#ifndef _HITAG2_H_
#define _HITAG2_H_

#include "common.h"
#include "hitag.h"

void SniffHitag2(bool ledcontrol);
void SimulateHitag2(bool ledcontrol);
void ReaderHitag(hitag_function htf, const hitag_data *htd, bool ledcontrol);
void WriterHitag(hitag_function htf, const hitag_data *htd, int page, bool ledcontrol);
void EloadHitag(const uint8_t *data, uint16_t len);
#endif
