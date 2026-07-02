//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// EMV terminal emulator - card GET DATA probe / enumeration
//-----------------------------------------------------------------------------

#ifndef EMV_TERM_PROBE_H__
#define EMV_TERM_PROBE_H__

#include "emv_term_ctx.h"

typedef struct {
    bool sweep_all;
    bool read_records;
    bool decode_tlv;
} emv_term_probe_opts_t;

int emv_term_prepare_card(emv_term_ctx_t *ctx, bool jload, const char *session_path);
int emv_term_probe_card(emv_term_ctx_t *ctx, const emv_term_probe_opts_t *opts);

#endif
