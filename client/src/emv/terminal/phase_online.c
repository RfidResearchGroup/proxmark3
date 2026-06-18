//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "phase_online.h"
#include "phase_caa.h"
#include "phase_scripts.h"
#include "emv_term_host.h"
#include "emv_term_host_tcp.h"
#include "emv_term_tvr.h"
#include "../emvcore.h"
#include "ui.h"
#include "commonutil.h"
#include "protocols.h"
#include <string.h>
#include <stdlib.h>

static int parse_hex_field(const char *hex, uint8_t *out, size_t *out_len, size_t max_len) {
    if (!hex || !hex[0] || !out || !out_len) {
        return PM3_EINVARG;
    }
    int buflen = 0;
    if (param_gethex_to_eol(hex, 0, out, max_len, &buflen)) {
        return PM3_ESOFT;
    }
    *out_len = (size_t)buflen;
    return PM3_SUCCESS;
}

static void build_default_arc(emv_term_ctx_t *ctx) {
    if (ctx->arc[0] || ctx->arc[1]) {
        return;
    }
    ctx->arc[0] = '0';
    ctx->arc[1] = '0';
    tlvdb_change_or_add_node(ctx->card, 0x8a, 2, ctx->arc);
}

static int build_issuer_auth(emv_term_ctx_t *ctx) {
    uint8_t tag91[32] = {0};
    size_t tag91_len = 0;

    if (ctx->opts.arpc && ctx->opts.arpc[0]) {
        size_t arpc_len = 0;
        if (parse_hex_field(ctx->opts.arpc, tag91, &arpc_len, 16) != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Invalid --arpc hex");
            return PM3_EINVARG;
        }
        tag91_len = arpc_len;

        if (ctx->opts.arpc_rc && ctx->opts.arpc_rc[0]) {
            size_t rc_len = 0;
            if (parse_hex_field(ctx->opts.arpc_rc, tag91 + tag91_len, &rc_len, sizeof(tag91) - tag91_len) == PM3_SUCCESS) {
                tag91_len += rc_len;
            }
        } else if (GetCardPSVendor(ctx->aid, ctx->aid_len) == CV_INTERAC) {
            tag91[tag91_len++] = 0x88;
            tag91[tag91_len++] = 0x40;
        }
    } else if (ctx->opts.host_tcp && ctx->opts.host_tcp[0]) {
        emv_term_host_keys_t keys;
        int hres = emv_term_host_keys_default(&keys, ctx);
        if (hres) {
            return hres;
        }
        emv_term_host_tcp_resp_t tcp_resp;
        PrintAndLogEx(INFO, "* Online processing (TCP host %s)", ctx->opts.host_tcp);
        if (emv_term_host_tcp_request(ctx, ctx->opts.host_tcp, &keys, &tcp_resp) != PM3_SUCCESS) {
            return PM3_ESOFT;
        }
        ctx->host_tcp_applied = true;
        if (parse_hex_field(tcp_resp.arpc, tag91, &tag91_len, sizeof(tag91)) != PM3_SUCCESS) {
            return PM3_ESOFT;
        }
        if (tcp_resp.arpc_rc[0]) {
            size_t rc_len = 0;
            parse_hex_field(tcp_resp.arpc_rc, tag91 + tag91_len, &rc_len, sizeof(tag91) - tag91_len);
            tag91_len += rc_len;
        }
    } else if (ctx->opts.host_sim || ctx->host_keys_path[0]) {
        emv_term_host_keys_t keys;
        int hres;
        if (ctx->opts.host_keys && ctx->opts.host_keys[0]) {
            hres = emv_term_host_keys_load(&keys, ctx->opts.host_keys);
        } else if (ctx->host_keys_path[0]) {
            hres = emv_term_host_keys_load(&keys, ctx->host_keys_path);
        } else {
            hres = emv_term_host_keys_default(&keys, ctx);
        }
        if (hres) {
            return hres;
        }
        PrintAndLogEx(INFO, "* Online processing (host-sim)");
        if (emv_term_host_build_issuer_auth(ctx, &keys, tag91, &tag91_len, sizeof(tag91)) != PM3_SUCCESS) {
            return PM3_ESOFT;
        }
    } else {
        const struct tlv *AC = tlvdb_get(ctx->card, 0x9f26, NULL);
        if (AC && AC->len >= 2) {
            memcpy(tag91, AC->value, AC->len > 8 ? 8 : AC->len);
            tag91_len = AC->len > 8 ? 8 : AC->len;
            for (size_t i = 0; i < 2 && i < tag91_len; i++) {
                tag91[i] ^= ctx->arc[i];
            }
            PrintAndLogEx(INFO, "Lab stub: raw ARPC XOR ARC (no bank keys)");
        }
    }

    if (tag91_len == 0) {
        PrintAndLogEx(WARNING, "No ARPC data - skipping EXTERNAL AUTHENTICATE");
        return PM3_ESOFT;
    }

    ctx->issuer_auth_len = tag91_len;
    memcpy(ctx->issuer_auth, tag91, tag91_len);
    tlvdb_change_or_add_node(ctx->card, 0x91, tag91_len, tag91);
    return PM3_SUCCESS;
}

int phase_online_run(emv_term_ctx_t *ctx) {
    if (!ctx) {
        return PM3_EINVARG;
    }

    if (!ctx->ac1_performed || (ctx->ac1_cid & 0xC0) != EMVAC_ARQC_BYTE) {
        PrintAndLogEx(INFO, "Online phase skipped - ARQC not requested");
        return PM3_SUCCESS;
    }

    ctx->online_performed = true;
    if (!ctx->opts.host_sim && !(ctx->host_keys_path[0] && !ctx->opts.arpc)) {
        PrintAndLogEx(INFO, "\n* Online processing (lab stub)");
    }

    if (ctx->opts.arc && ctx->opts.arc[0]) {
        size_t arc_len = 0;
        parse_hex_field(ctx->opts.arc, ctx->arc, &arc_len, 2);
        if (arc_len == 1) {
            ctx->arc[1] = ctx->arc[0];
            ctx->arc[0] = '0';
        }
    }
    build_default_arc(ctx);
    tlvdb_change_or_add_node(ctx->card, 0x8a, 2, ctx->arc);
    PrintAndLogEx(INFO, "Authorization Response Code (8A): %c%c", ctx->arc[0], ctx->arc[1]);

    const struct tlv *AC = tlvdb_get(ctx->card, 0x9f26, NULL);
    const struct tlv *ATC = tlvdb_get(ctx->card, 0x9f36, NULL);
    if (AC) {
        PrintAndLogEx(INFO, "ARQC: %s", sprint_hex(AC->value, AC->len));
    }
    if (ATC) {
        PrintAndLogEx(INFO, "ATC: %s", sprint_hex(ATC->value, ATC->len));
    }

    if (build_issuer_auth(ctx) != PM3_SUCCESS) {
        ctx->online_success = false;
        return PM3_ESOFT;
    }

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = EMVExternalAuthenticate(ctx->channel, true, ctx->issuer_auth, ctx->issuer_auth_len,
                                      buf, sizeof(buf), &len, &sw, ctx->card);
    if (res || sw != 0x9000) {
        PrintAndLogEx(ERR, "EXTERNAL AUTHENTICATE failed SW=%04x", sw);
        emv_term_tvr_set_bit(ctx, 0, 0x04, true);
        ctx->online_success = false;
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "EXTERNAL AUTHENTICATE OK");
    ctx->online_success = true;
    emv_term_tsi_set_bit(ctx, 0, 0x02, true);

    const struct tlv *s71 = tlvdb_get(ctx->card, 0x71, NULL);
    if (s71 && s71->len) {
        phase_scripts_run(ctx, 0x71, true);
    }

    return phase_caa_ac2(ctx);
}
