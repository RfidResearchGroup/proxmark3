//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#ifndef EMV_TERM_HOST_H__
#define EMV_TERM_HOST_H__

#include "emv_term_ctx.h"
#include "emv_term_arqc.h"

typedef struct {
    char scheme[32];
    uint8_t ac_master_key[16];
    size_t ac_master_key_len;
    emv_arpc_method_t arpc_method;
    uint8_t default_arpc_rc[2];
    bool default_arpc_rc_set;
    bool verify_arqc;
} emv_term_host_keys_t;

int emv_term_host_keys_load(emv_term_host_keys_t *keys, const char *path);
int emv_term_host_keys_default(emv_term_host_keys_t *keys, const emv_term_ctx_t *ctx);

int emv_term_host_build_issuer_auth(emv_term_ctx_t *ctx, const emv_term_host_keys_t *keys,
                                    uint8_t *tag91, size_t *tag91_len, size_t max_len);

int emv_term_host_sim_run(emv_term_ctx_t *ctx, const char *keys_path);

#endif
