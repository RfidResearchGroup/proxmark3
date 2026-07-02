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

#ifndef EMV_TERM_TVR_H__
#define EMV_TERM_TVR_H__

#include "emv_term_ctx.h"

void emv_term_tvr_get(emv_term_ctx_t *ctx, uint8_t tvr[5]);
void emv_term_tvr_set_bit(emv_term_ctx_t *ctx, size_t byte_idx, uint8_t bit_mask, bool set);
void emv_term_tsi_get(emv_term_ctx_t *ctx, uint8_t tsi[2]);
void emv_term_tsi_set_bit(emv_term_ctx_t *ctx, size_t byte_idx, uint8_t bit_mask, bool set);

bool emv_term_tlv_get_bytes(const struct tlvdb *root, tlv_tag_t tag, uint8_t *out, size_t *out_len, size_t max_len);
uint64_t emv_term_bcd_to_uint(const uint8_t *bcd, size_t len);

bool emv_term_tac_match(const uint8_t tvr[5], const uint8_t tac[5], const uint8_t iac[5]);

#endif
