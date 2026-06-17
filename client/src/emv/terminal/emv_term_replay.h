//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// EMV terminal emulator — mock APDU replay driver
//-----------------------------------------------------------------------------

#ifndef EMV_TERM_REPLAY_H__
#define EMV_TERM_REPLAY_H__

#include "emv_term_ctx.h"

int emv_term_replay_run(emv_term_ctx_t *ctx, const char *from_phase, const char *to_phase);

#endif
