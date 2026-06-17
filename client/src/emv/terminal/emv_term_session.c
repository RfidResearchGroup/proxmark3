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
// EMV terminal emulator — session JSON export
//-----------------------------------------------------------------------------

#include "emv_term_session.h"
#include "emv_term_tvr.h"
#include "../emvjson.h"
#include "emv_term_redact.h"
#include "ui.h"
#include "util.h"
#include "commonutil.h"
#include <jansson.h>
#include <string.h>
#include <stdlib.h>

static bool session_no_redact(const emv_term_ctx_t *ctx) {
    if (ctx->opts.no_redact) {
        return true;
    }
    const char *env = getenv("EMV_TERMINAL_FULL_SESSION");
    return env && env[0] && strcmp(env, "0") != 0;
}

static void mask_pan(char *out, size_t outlen, const uint8_t *pan, size_t panlen) {
    if (!out || outlen == 0) {
        return;
    }
    out[0] = '\0';
    if (!pan || panlen == 0) {
        return;
    }

    size_t pos = 0;
    for (size_t i = 0; i < panlen && pos + 1 < outlen; i++) {
        uint8_t hi = (pan[i] >> 4) & 0x0F;
        uint8_t lo = pan[i] & 0x0F;
        if (hi <= 9) {
            out[pos++] = '0' + hi;
        }
        if (lo <= 9 && pos + 1 < outlen) {
            out[pos++] = '0' + lo;
        }
    }
    out[pos] = '\0';

    if (pos > 10) {
        for (size_t i = 6; i < pos - 4; i++) {
            out[i] = '*';
        }
    }
}

int emv_term_session_save_json(const emv_term_ctx_t *ctx, const char *path) {
    if (!ctx || !path || !path[0]) {
        return PM3_EINVARG;
    }

    json_t *root = json_object();
    json_t *file = json_object();
    json_t *terminal = json_object();
    json_t *phases = json_array();
    json_t *card = json_object();
    json_t *crypto = json_object();

    JsonSaveStr(file, "Created", "proxmark3 emv terminal");
    JsonSaveStr(file, "Version", "1");
    json_object_set_new(root, "File", file);

    JsonSaveStr(terminal, "Profile", ctx->opts.profile_path ? ctx->opts.profile_path : "default");
    JsonSaveStr(terminal, "Channel", ctx->channel == CC_CONTACT ? "contact" : "contactless");
    if (ctx->opts.exception_file && ctx->opts.exception_file[0]) {
        JsonSaveStr(terminal, "ExceptionFile", ctx->opts.exception_file);
    }
    if (ctx->scheme_name[0]) {
        JsonSaveStr(terminal, "Scheme", ctx->scheme_name);
    }
    if (ctx->atr_len) {
        JsonSaveStr(terminal, "ATR", ctx->atr_hex);
    }
    json_object_set_new(root, "Terminal", terminal);

    JsonSaveStr(root, "Outcome", emv_term_outcome_str(ctx->outcome));
    JsonSaveStr(root, "TransactionType", TransactionTypeStr[ctx->tr_type]);

    for (size_t i = 0; i < ctx->event_count; i++) {
        json_t *pe = json_object();
        JsonSaveInt(pe, "id", ctx->events[i].id);
        JsonSaveStr(pe, "name", emv_term_phase_name(ctx->events[i].id));
        JsonSaveInt(pe, "result", ctx->events[i].result);
        JsonSaveHex(pe, "sw", ctx->events[i].sw, 2);
        if (ctx->events[i].note[0]) {
            JsonSaveStr(pe, "notes", ctx->events[i].note);
        }
        if (ctx->opts.timing_report || ctx->events[i].duration_ms) {
            JsonSaveInt(pe, "duration_ms", ctx->events[i].duration_ms);
        }
        json_array_append_new(phases, pe);
    }
    json_object_set_new(root, "Phases", phases);

    if (ctx->aid_len) {
        JsonSaveBufAsHexCompact(card, "AID", (uint8_t *)ctx->aid, ctx->aid_len);
    }

    const struct tlv *pan = tlvdb_get(ctx->card, 0x5a, NULL);
    if (pan && pan->len) {
        char masked[32] = {0};
        mask_pan(masked, sizeof(masked), pan->value, pan->len);
        JsonSaveStr(card, "PAN", masked);
    }

    const struct tlv *cvmres = tlvdb_get(ctx->card, 0x9f34, NULL);
    if (cvmres && cvmres->len == 3) {
        JsonSaveBufAsHexCompact(card, "CVMResults", (uint8_t *)cvmres->value, cvmres->len);
    }

    json_object_set_new(root, "Card", card);

    if (ctx->opts.full_tlv) {
        json_t *tlv_arr = json_array();
        struct tlvdb *child = ctx->card->children;
        while (child) {
            json_t *snap = json_object();
            json_array_append_new(tlv_arr, snap);
            JsonSaveTLVTreeElm(snap, "$", child, true, true, false);
            child = tlvdb_elm_get_next(child);
        }
        json_object_set_new(card, "TLV", tlv_arr);
    }

    const struct tlv *cid = tlvdb_get(ctx->card, 0x9f27, NULL);
    const struct tlv *ac = tlvdb_get(ctx->card, 0x9f26, NULL);
    const struct tlv *atc = tlvdb_get(ctx->card, 0x9f36, NULL);

    if (cid && cid->len) {
        uint8_t ctype = cid->value[0] & 0xC0;
        if (ctype == 0x00) {
            JsonSaveStr(crypto, "Type", "AAC");
        } else if (ctype == 0x40) {
            JsonSaveStr(crypto, "Type", "TC");
        } else if (ctype == 0x80) {
            JsonSaveStr(crypto, "Type", "ARQC");
        }
    }
    if (atc && atc->len) {
        JsonSaveBufAsHexCompact(crypto, "ATC", (uint8_t *)atc->value, atc->len);
    }
    if (ac && ac->len) {
        JsonSaveBufAsHexCompact(crypto, "AC", (uint8_t *)ac->value, ac->len);
    }
    if (ctx->cda_verify_performed) {
        JsonSaveStr(crypto, "CDAVerify", ctx->cda_verify_ok ? "ok" : "fail");
    }
    json_object_set_new(root, "Cryptogram", crypto);

    uint8_t tvr[5] = {0};
    emv_term_tvr_get((emv_term_ctx_t *)ctx, tvr);
    JsonSaveBufAsHexCompact(root, "TVR", tvr, 5);

    if (!session_no_redact(ctx)) {
        emv_term_redact_session_json(root, false);
    } else {
        PrintAndLogEx(WARNING, "Session export without redaction (lab only)");
    }

    int res = json_dump_file(root, path, JSON_INDENT(2));
    json_decref(root);

    if (res) {
        PrintAndLogEx(ERR, "Failed to write session JSON: %s", path);
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Session saved: %s", path);
    return PM3_SUCCESS;
}

int emv_term_session_load_json(emv_term_ctx_t *ctx, const char *path) {
    if (!ctx || !path || !path[0]) {
        return PM3_EINVARG;
    }

    json_error_t error;
    json_t *root = json_load_file(path, 0, &error);
    if (!root) {
        PrintAndLogEx(ERR, "Session load error line %d: %s", error.line, error.text);
        return PM3_ESOFT;
    }

    char outcome[32] = {0};
    if (JsonLoadStr(root, "Outcome", outcome) == 0) {
        if (strcmp(outcome, "approved_offline") == 0) {
            ctx->outcome = EMV_OUTCOME_APPROVED_OFFLINE;
        } else if (strcmp(outcome, "declined") == 0) {
            ctx->outcome = EMV_OUTCOME_DECLINED;
        } else if (strcmp(outcome, "online_required") == 0) {
            ctx->outcome = EMV_OUTCOME_ONLINE_REQUIRED;
        } else if (strcmp(outcome, "approved_online") == 0) {
            ctx->outcome = EMV_OUTCOME_APPROVED_ONLINE;
        } else if (strcmp(outcome, "aborted") == 0) {
            ctx->outcome = EMV_OUTCOME_ABORTED;
        }
    }

    json_t *phases = json_object_get(root, "Phases");
    if (json_is_array(phases)) {
        size_t idx = json_array_size(phases);
        for (size_t i = 0; i < idx; i++) {
            json_t *pe = json_array_get(phases, i);
            if (!json_is_object(pe)) {
                continue;
            }
            json_t *jid = json_object_get(pe, "id");
            json_t *jres = json_object_get(pe, "result");
            json_t *jsw = json_object_get(pe, "sw");
            json_t *jnote = json_object_get(pe, "notes");

            emv_term_phase_t phase = EMV_PHASE_INIT;
            if (json_is_integer(jid)) {
                phase = (emv_term_phase_t)(int)json_integer_value(jid);
            }
            int result = json_is_integer(jres) ? (int)json_integer_value(jres) : PM3_SUCCESS;
            uint16_t sw = 0;
            if (json_is_string(jsw)) {
                uint8_t swbuf[2] = {0};
                int swlen = 0;
                param_gethex_to_eol(json_string_value(jsw), 0, swbuf, sizeof(swbuf), &swlen);
                if (swlen == 2) {
                    sw = (swbuf[0] << 8) | swbuf[1];
                }
            }
            const char *note = json_is_string(jnote) ? json_string_value(jnote) : NULL;
            json_t *jdur = json_object_get(pe, "duration_ms");
            uint32_t dur = json_is_integer(jdur) ? (uint32_t)json_integer_value(jdur) : 0;
            if (dur) {
                emv_term_event_add_timed(ctx, phase, result, sw, note, dur);
            } else {
                emv_term_event_add(ctx, phase, result, sw, note);
            }
        }
    }

    str_copy(ctx->session_file, sizeof(ctx->session_file), path);
    json_decref(root);
    PrintAndLogEx(SUCCESS, "Session loaded: %s", path);
    return PM3_SUCCESS;
}

static bool aid_hex_match(json_t *a, json_t *b) {
    if (!json_is_string(a) || !json_is_string(b)) {
        return true;
    }
    return strcmp(json_string_value(a), json_string_value(b)) == 0;
}

int emv_term_session_merge(const char *scan_path, const char *session_path, const char *out_path) {
    if (!scan_path || !session_path || !out_path) {
        return PM3_EINVARG;
    }

    json_error_t error;
    json_t *scan = json_load_file(scan_path, 0, &error);
    if (!scan) {
        PrintAndLogEx(ERR, "Scan load error: %s", error.text);
        return PM3_ESOFT;
    }
    json_t *sess = json_load_file(session_path, 0, &error);
    if (!sess) {
        json_decref(scan);
        PrintAndLogEx(ERR, "Session load error: %s", error.text);
        return PM3_ESOFT;
    }

    json_t *scan_aid = json_path_get(scan, "$.Application.AID");
    json_t *sess_card = json_object_get(sess, "Card");
    json_t *sess_aid = json_is_object(sess_card) ? json_object_get(sess_card, "AID") : NULL;
    if (!aid_hex_match(scan_aid, sess_aid)) {
        json_decref(scan);
        json_decref(sess);
        PrintAndLogEx(ERR, "Merge rejected: AID mismatch between scan and session");
        return PM3_EINVARG;
    }

    json_t *out = json_object();
    json_t *file = json_object();
    JsonSaveStr(file, "Created", "proxmark3 emv terminal merge");
    JsonSaveStr(file, "Version", "1");
    json_object_set_new(out, "File", file);
    json_object_set_new(out, "Scan", scan);
    json_t *term = json_object_get(sess, "Terminal");
    if (term) {
        json_object_set_new(out, "Terminal", json_deep_copy(term));
    }
    json_t *outcome = json_object_get(sess, "Outcome");
    if (outcome) {
        json_object_set_new(out, "Outcome", json_deep_copy(outcome));
    }
    json_t *phases = json_object_get(sess, "Phases");
    if (phases) {
        json_object_set_new(out, "Phases", json_deep_copy(phases));
    }
    json_t *crypto = json_object_get(sess, "Cryptogram");
    if (crypto) {
        json_object_set_new(out, "Cryptogram", json_deep_copy(crypto));
    }

    emv_term_redact_session_json(out, false);
    int res = json_dump_file(out, out_path, JSON_INDENT(2));
    json_decref(out);
    json_decref(sess);

    if (res) {
        PrintAndLogEx(ERR, "Failed to write merged JSON: %s", out_path);
        return PM3_ESOFT;
    }
    PrintAndLogEx(SUCCESS, "Merged session: %s", out_path);
    return PM3_SUCCESS;
}
