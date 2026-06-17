//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// EMV terminal emulator — card GET DATA probe / enumeration
//-----------------------------------------------------------------------------

#ifndef EMV_TERM_PROBE_H__
#define EMV_TERM_PROBE_H__

#include "emv_term_ctx.h"

int emv_term_probe_card(emv_term_ctx_t *ctx, bool sweep_all);

#endif
