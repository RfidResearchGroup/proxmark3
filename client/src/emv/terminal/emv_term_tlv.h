//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// EMV terminal emulator — TLV lookup across terminal/card trees
//-----------------------------------------------------------------------------

#ifndef EMV_TERM_TLV_H__
#define EMV_TERM_TLV_H__

#include "emv_term_ctx.h"

const struct tlv *emv_term_tlv_lookup(const emv_term_ctx_t *ctx, tlv_tag_t tag);
void emv_term_copy_terminal_tags_to_card(emv_term_ctx_t *ctx);

#endif
