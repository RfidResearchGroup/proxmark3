//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// EMV terminal emulator - crypto playground digest / compare
//-----------------------------------------------------------------------------

#ifndef EMV_TERM_CRYPTO_DIGEST_H__
#define EMV_TERM_CRYPTO_DIGEST_H__

#include "emv_term_crypto.h"

int emv_term_crypto_print_msd_summary(const emv_term_ctx_t *ctx);
int emv_term_crypto_print_digest(const emv_term_ctx_t *ctx, const emv_term_crypto_bench_result_t *result);
int emv_term_crypto_compare_json(const char *path_a, const char *path_b);

#endif
