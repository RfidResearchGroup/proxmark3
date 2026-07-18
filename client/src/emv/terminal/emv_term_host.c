//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "emv_term_host.h"
#include "emv_term_arqc.h"
#include "phase_online.h"
#include "phase_complete.h"
#include "ui.h"
#include "commonutil.h"
#include <jansson.h>
#include <string.h>

static int parse_hex_key(json_t *root, const char *field, uint8_t *out, size_t *out_len, size_t max_len) {
    json_t *j = json_object_get(root, field);
    if (!j) {
        j = json_object_get(root, field); // try snake vs camel - handled below
    }
    const char *keys[] = { field, NULL };
    if (strcmp(field, "ACMasterKey") == 0) {
        keys[1] = "ac_master_key";
    } else if (strcmp(field, "DefaultARPCRC") == 0) {
        keys[1] = "arpc_rc_contact_recommended";
    }

    for (int i = 0; keys[i]; i++) {
        j = json_object_get(root, keys[i]);
        if (json_is_string(j)) {
            int buflen = 0;
            if (param_gethex_to_eol(json_string_value(j), 0, out, max_len, &buflen)) {
                return PM3_ESOFT;
            }
            *out_len = (size_t)buflen;
            return PM3_SUCCESS;
        }
    }
    return PM3_ESOFT;
}

int emv_term_host_keys_load(emv_term_host_keys_t *keys, const char *path) {
    if (!keys || !path || !path[0]) {
        return PM3_EINVARG;
    }

    memset(keys, 0, sizeof(*keys));
    keys->arpc_method = EMV_ARPC_CVN18;
    keys->verify_arqc = true;

    json_error_t error;
    json_t *root = json_load_file(path, 0, &error);
    if (!root) {
        PrintAndLogEx(ERR, "Host keys load error line %d: %s", error.line, error.text);
        return PM3_ESOFT;
    }

    json_t *scheme = json_object_get(root, "Scheme");
    if (!scheme) {
        scheme = json_object_get(root, "scheme");
    }
    if (json_is_string(scheme)) {
        str_copy(keys->scheme, sizeof(keys->scheme), json_string_value(scheme));
    }

    json_t *method = json_object_get(root, "ARPCMethod");
    if (json_is_string(method)) {
        const char *m = json_string_value(method);
        if (strstr(m, "10") || strcmp(m, "cvn10") == 0) {
            keys->arpc_method = EMV_ARPC_CVN10;
        } else if (strcmp(m, "xor") == 0) {
            keys->arpc_method = EMV_ARPC_XOR_STUB;
        }
    }

    if (parse_hex_key(root, "ACMasterKey", keys->ac_master_key, &keys->ac_master_key_len, 16) != PM3_SUCCESS) {
        json_decref(root);
        PrintAndLogEx(ERR, "Host keys missing AC master key");
        return PM3_ESOFT;
    }

    uint8_t rc[4] = {0};
    size_t rc_len = 0;
    if (parse_hex_key(root, "DefaultARPCRC", rc, &rc_len, sizeof(rc)) == PM3_SUCCESS && rc_len >= 2) {
        keys->default_arpc_rc[0] = rc[0];
        keys->default_arpc_rc[1] = rc[1];
        keys->default_arpc_rc_set = true;
    }

    json_decref(root);
    PrintAndLogEx(INFO, "Host keys loaded: scheme=%s method=%d", keys->scheme, keys->arpc_method);
    return PM3_SUCCESS;
}

int emv_term_host_keys_default(emv_term_host_keys_t *keys, const emv_term_ctx_t *ctx) {
    if (!keys) {
        return PM3_EINVARG;
    }

    char *path = NULL;
    if (ctx && ctx->host_keys_path[0]) {
        return emv_term_host_keys_load(keys, ctx->host_keys_path);
    }

    if (searchFile(&path, RESOURCES_SUBDIR, "host_sim_interac", ".json", false) == PM3_SUCCESS ||
        searchFile(&path, RESOURCES_SUBDIR, "interac_test_keys", ".json", false) == PM3_SUCCESS) {
        int res = emv_term_host_keys_load(keys, path);
        free(path);
        return res;
    }

    PrintAndLogEx(ERR, "Default host keys file not found");
    return PM3_ESOFT;
}

int emv_term_host_build_issuer_auth(emv_term_ctx_t *ctx, const emv_term_host_keys_t *keys,
                                    uint8_t *tag91, size_t *tag91_len, size_t max_len) {
    if (!ctx || !keys || !tag91 || !tag91_len) {
        return PM3_EINVARG;
    }

    const struct tlv *AC = tlvdb_get(ctx->card, 0x9f26, NULL);
    const struct tlv *ATC = tlvdb_get(ctx->card, 0x9f36, NULL);
    if (!AC || AC->len < 8) {
        PrintAndLogEx(ERR, "Host-sim: ARQC (9F26) missing");
        return PM3_ESOFT;
    }

    uint16_t atc_val = 0;
    if (ATC && ATC->len >= 2) {
        atc_val = (ATC->value[0] << 8) | ATC->value[1];
    }

    uint8_t sk[16] = {0};
    emv_term_sk_derive_ac(keys->ac_master_key, atc_val, sk);

    if (keys->verify_arqc && ctx->cdol1_len > 0) {
        if (emv_term_arqc_verify(sk, ctx->cdol1_data, ctx->cdol1_len, AC->value, AC->len)) {
            PrintAndLogEx(SUCCESS, "ARQC verify: OK (CVN18 retail MAC)");
            ctx->host_arqc_ok = true;
        } else {
            PrintAndLogEx(WARNING, "ARQC verify: FAIL");
            ctx->host_arqc_ok = false;
            if (!ctx->opts.continue_on_bad_arqc) {
                return PM3_ESOFT;
            }
        }
    }

    size_t arpc_len = 0;
    if (!emv_term_arpc_compute(keys->arpc_method, sk, AC->value, AC->len,
                               ctx->arc, 2, tag91, &arpc_len)) {
        return PM3_ESOFT;
    }

    size_t total = arpc_len;
    if (ctx->opts.arpc_rc && ctx->opts.arpc_rc[0]) {
        size_t rc_len = 0;
        param_gethex_to_eol(ctx->opts.arpc_rc, 0, tag91 + total, max_len - total, (int *)&rc_len);
        total += rc_len;
    } else if (keys->default_arpc_rc_set) {
        if (total + 2 <= max_len) {
            tag91[total++] = keys->default_arpc_rc[0];
            tag91[total++] = keys->default_arpc_rc[1];
        }
    } else if (GetCardPSVendor(ctx->aid, ctx->aid_len) == CV_INTERAC) {
        if (total + 2 <= max_len) {
            tag91[total++] = 0x88;
            tag91[total++] = 0x40;
        }
    }

    *tag91_len = total;
    PrintAndLogEx(INFO, "Host-sim ARPC: %s", sprint_hex(tag91, total));
    return PM3_SUCCESS;
}

int emv_term_host_sim_run(emv_term_ctx_t *ctx, const char *keys_path) {
    if (!ctx) {
        return PM3_EINVARG;
    }

    emv_term_host_keys_t keys;
    int res;
    if (keys_path && keys_path[0]) {
        res = emv_term_host_keys_load(&keys, keys_path);
    } else {
        res = emv_term_host_keys_default(&keys, ctx);
    }
    if (res) {
        return res;
    }

    ctx->opts.host_sim = true;
    memcpy(ctx->host_keys_path, keys_path ? keys_path : "", sizeof(ctx->host_keys_path));

    if (!ctx->ac1_performed || (ctx->ac1_cid & 0xC0) != EMVAC_ARQC_BYTE) {
        PrintAndLogEx(ERR, "Host-sim requires ARQC from AC1 in session/card context");
        return PM3_EINVARG;
    }

    res = phase_online_run(ctx);
    if (res == PM3_SUCCESS) {
        phase_complete_run(ctx);
    }
    return res;
}
