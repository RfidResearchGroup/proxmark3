//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#ifndef EMV_TERMINAL_H__
#define EMV_TERMINAL_H__

#include "emv_term_ctx.h"

int emv_terminal_run(emv_term_ctx_t *ctx);
int emv_terminal_step(emv_term_ctx_t *ctx, emv_term_phase_t phase);

#endif
