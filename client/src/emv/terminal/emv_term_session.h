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

#ifndef EMV_TERM_SESSION_H__
#define EMV_TERM_SESSION_H__

#include "emv_term_ctx.h"

int emv_term_session_save_json(const emv_term_ctx_t *ctx, const char *path);
int emv_term_session_load_json(emv_term_ctx_t *ctx, const char *path);
int emv_term_session_merge(const char *scan_path, const char *session_path, const char *out_path);

#endif
