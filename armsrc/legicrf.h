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
// LEGIC RF emulation public interface
//-----------------------------------------------------------------------------

#ifndef __LEGICRF_H
#define __LEGICRF_H

#include "common.h"
#include "legic.h"              /* legic_card_select_t struct */

void LegicRfInfo(void);
int LegicRfReaderEx(uint16_t offset, uint16_t len, uint8_t iv);
void LegicRfReader(uint16_t offset, uint16_t len, uint8_t iv);
void LegicRfWriter(uint16_t offset, uint16_t len, uint8_t iv, const uint8_t *data);

legic_card_select_t *getLegicCardInfo(void);
#endif /* __LEGICRF_H */
