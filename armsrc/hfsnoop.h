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
#ifndef __HFSNOOP_H
#define __HFSNOOP_H

#include "proxmark3_arm.h"

// what to do with skipped data
#define HF_SNOOP_SKIP_NONE (0)
#define HF_SNOOP_SKIP_DROP (1)
#define HF_SNOOP_SKIP_MAX  (2)
#define HF_SNOOP_SKIP_MIN  (3)
#define HF_SNOOP_SKIP_AVG  (4)

int HfSniff(uint32_t samplesToSkip, uint32_t triggersToSkip, uint16_t *len, uint8_t skipMode, uint8_t skipRatio);
void HfPlotDownload(void);
#endif
