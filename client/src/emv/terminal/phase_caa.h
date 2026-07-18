//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#ifndef PHASE_CAA_H__
#define PHASE_CAA_H__

#include "emv_term_ctx.h"

int phase_caa_run(emv_term_ctx_t *ctx);
int phase_caa_ac2(emv_term_ctx_t *ctx);

#endif
