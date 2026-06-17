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

#ifndef PHASE_CVM_H__
#define PHASE_CVM_H__

#include "emv_term_ctx.h"

int phase_cvm_run(emv_term_ctx_t *ctx);
int phase_cvm_verify_pin(emv_term_ctx_t *ctx, const char *pin, bool enciphered);

void emv_term_pin_zeroize(uint8_t *buf, size_t len);

#endif
