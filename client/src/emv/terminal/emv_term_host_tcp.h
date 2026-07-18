//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#ifndef EMV_TERM_HOST_TCP_H__
#define EMV_TERM_HOST_TCP_H__

#include "emv_term_ctx.h"
#include "emv_term_host.h"

typedef struct {
    char arc[8];
    char arpc[128];
    char arpc_rc[16];
    char script71[512];
} emv_term_host_tcp_resp_t;

int emv_term_host_tcp_listen(uint16_t port, const char *keys_path);
int emv_term_host_tcp_request(emv_term_ctx_t *ctx, const char *host_port,
                              const emv_term_host_keys_t *keys,
                              emv_term_host_tcp_resp_t *resp);

#endif
