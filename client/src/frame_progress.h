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
// Flashing progress functions
//-----------------------------------------------------------------------------

#ifndef __FRAME_PROGRESS_H__
#define __FRAME_PROGRESS_H__

#include "common.h"
#include "elf.h"

void hadouken_start(double fps, int glyph_mode, int wave_mode);
void hadouken_set_progress(int pct);
void hadouken_stop(void);

void hadouken_on_sigint(int s);
void hadouken_on_sigwinch(int s);

#endif

