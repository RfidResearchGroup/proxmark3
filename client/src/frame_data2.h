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

#ifndef __FRAME_DATA2_H__
#define __FRAME_DATA2_H__

#include "common.h"


void fx_matrix_run(int rows, double duration_ms);
void fx_matrix_start(int rows);
void fx_matrix_stop(void);
void fx_printf(const char *fmt, ...);

// Async-signal-safe, for use from the client's signal handlers. A stopped or
// killed process must not leave the cursor hidden behind it
void fx_terminal_restore(void);
void fx_terminal_resume(void);

#endif // __FRAME_DATA2_H__
