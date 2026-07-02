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

#include "emv_term_tvr.h"
#include <string.h>

void emv_term_tvr_get(emv_term_ctx_t *ctx, uint8_t tvr[5]) {
    memset(tvr, 0, 5);
    if (!ctx) {
        return;
    }
    const struct tlv *tlv = tlvdb_get(ctx->card, 0x95, NULL);
    if (tlv && tlv->len >= 5) {
        memcpy(tvr, tlv->value, 5);
    }
}

void emv_term_tvr_set_bit(emv_term_ctx_t *ctx, size_t byte_idx, uint8_t bit_mask, bool set) {
    if (!ctx || byte_idx >= 5) {
        return;
    }
    uint8_t tvr[5];
    emv_term_tvr_get(ctx, tvr);
    if (set) {
        tvr[byte_idx] |= bit_mask;
    } else {
        tvr[byte_idx] &= (uint8_t)~bit_mask;
    }
    tlvdb_change_or_add_node(ctx->card, 0x95, 5, tvr);
}

void emv_term_tsi_get(emv_term_ctx_t *ctx, uint8_t tsi[2]) {
    memset(tsi, 0, 2);
    if (!ctx) {
        return;
    }
    const struct tlv *tlv = tlvdb_get(ctx->card, 0x9b, NULL);
    if (tlv && tlv->len >= 2) {
        memcpy(tsi, tlv->value, 2);
    }
}

void emv_term_tsi_set_bit(emv_term_ctx_t *ctx, size_t byte_idx, uint8_t bit_mask, bool set) {
    if (!ctx || byte_idx >= 2) {
        return;
    }
    uint8_t tsi[2];
    emv_term_tsi_get(ctx, tsi);
    if (set) {
        tsi[byte_idx] |= bit_mask;
    } else {
        tsi[byte_idx] &= (uint8_t)~bit_mask;
    }
    tlvdb_change_or_add_node(ctx->card, 0x9b, 2, tsi);
}

bool emv_term_tlv_get_bytes(const struct tlvdb *root, tlv_tag_t tag, uint8_t *out, size_t *out_len, size_t max_len) {
    if (out_len) {
        *out_len = 0;
    }
    const struct tlv *tlv = tlvdb_get(root, tag, NULL);
    if (!tlv || !tlv->len) {
        return false;
    }
    if (out && max_len >= tlv->len) {
        memcpy(out, tlv->value, tlv->len);
        if (out_len) {
            *out_len = tlv->len;
        }
        return true;
    }
    if (out_len) {
        *out_len = tlv->len;
    }
    return false;
}

uint64_t emv_term_bcd_to_uint(const uint8_t *bcd, size_t len) {
    uint64_t val = 0;
    if (!bcd || !len) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        val = val * 100 + ((bcd[i] >> 4) & 0x0F) * 10 + (bcd[i] & 0x0F);
    }
    return val;
}

bool emv_term_tac_match(const uint8_t tvr[5], const uint8_t tac[5], const uint8_t iac[5]) {
    for (size_t i = 0; i < 5; i++) {
        if ((tvr[i] & tac[i]) || (tvr[i] & iac[i])) {
            return true;
        }
    }
    return false;
}
