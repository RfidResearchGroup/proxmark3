//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#ifndef PHASE_SCRIPTS_H__
#define PHASE_SCRIPTS_H__

#include "emv_term_ctx.h"

int phase_scripts_run(emv_term_ctx_t *ctx, tlv_tag_t template_tag, bool before_ac2);

#endif
