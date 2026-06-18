//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// EMV terminal emulator - TLV lookup across terminal/card trees
//-----------------------------------------------------------------------------

#include "emv_term_tlv.h"
#include "../tlv.h"

const struct tlv *emv_term_tlv_lookup(const emv_term_ctx_t *ctx, tlv_tag_t tag) {
    if (!ctx) {
        return NULL;
    }

    const struct tlv *tlv = NULL;
    if (ctx->terminal) {
        tlv = tlvdb_get(ctx->terminal, tag, NULL);
    }
    if (!tlv && ctx->card) {
        tlv = tlvdb_get(ctx->card, tag, NULL);
    }
    return tlv;
}

static void copy_terminal_node(struct tlvdb *card, const struct tlvdb *node) {
    if (!card || !node) {
        return;
    }

    if (node->tag.tag > 1) {
        tlvdb_change_or_add_node(card, node->tag.tag, node->tag.len, node->tag.value);
    }

    for (struct tlvdb *child = node->children; child; child = tlvdb_elm_get_next(child)) {
        copy_terminal_node(card, child);
    }
}

void emv_term_copy_terminal_tags_to_card(emv_term_ctx_t *ctx) {
    if (!ctx || !ctx->terminal || !ctx->card) {
        return;
    }

    for (struct tlvdb *node = ctx->terminal; node; node = tlvdb_elm_get_next(node)) {
        copy_terminal_node(ctx->card, node);
    }
}
