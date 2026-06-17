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

#ifndef EMV_TRANSACTION_H__
#define EMV_TRANSACTION_H__

#include "emv_term_ctx.h"

void emv_transaction_process_gpo_format1(struct tlvdb *tlvRoot, uint8_t *buf, size_t len, bool decodeTLV);
void emv_transaction_process_ac_format1(struct tlvdb *tlvRoot, uint8_t *buf, size_t len, bool decodeTLV);

int emv_transaction_init(emv_term_ctx_t *ctx);
int emv_transaction_oda(emv_term_ctx_t *ctx);
int emv_transaction_genac1(emv_term_ctx_t *ctx);

emv_term_outcome_t emv_transaction_outcome_from_cid(uint8_t cid);

#endif
