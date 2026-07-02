//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#ifndef EMV_TERM_SIM_EXPORT_H__
#define EMV_TERM_SIM_EXPORT_H__

#include "emv_term_ctx.h"

int emv_term_sim_export_session(const char *session_path, const char *out_path);
int emv_term_sim_export_ctx(const emv_term_ctx_t *ctx, const char *out_path);

#endif
