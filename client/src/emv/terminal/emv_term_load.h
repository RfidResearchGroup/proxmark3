//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#ifndef EMV_TERM_LOAD_H__
#define EMV_TERM_LOAD_H__

#include "emv_term_ctx.h"

int emv_term_load_from_scan(emv_term_ctx_t *ctx, const char *path);
int emv_term_load_card_tlv(emv_term_ctx_t *ctx, const char *path);

#endif
