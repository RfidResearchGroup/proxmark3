//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "emv_term_sim_export.h"
#include "../emvjson.h"
#include "ui.h"
#include "commonutil.h"
#include <jansson.h>
#include <string.h>

static void patch_add_hex(json_t *patch, const char *tag_hex, json_t *src, const char *field) {
    json_t *j = json_object_get(src, field);
    if (json_is_string(j) && json_string_value(j)[0]) {
        json_object_set_new(patch, tag_hex, json_string(json_string_value(j)));
    }
}

static int write_patch_json(json_t *root, const char *out_path) {
    int res = json_dump_file(root, out_path, JSON_INDENT(2));
    if (res) {
        PrintAndLogEx(ERR, "Failed to write sim patch: %s", out_path);
        return PM3_ESOFT;
    }
    PrintAndLogEx(SUCCESS, "Sim patch exported: %s", out_path);
    PrintAndLogEx(WARNING, "Research replay only — modern terminals reject replayed ARQC");
    return PM3_SUCCESS;
}

static json_t *build_patch_from_session(json_t *sess) {
    json_t *out = json_object();
    json_t *file = json_object();
    JsonSaveStr(file, "Created", "proxmark3 emv terminal export-sim");
    JsonSaveStr(file, "Version", "1");
    json_object_set_new(out, "File", file);

    json_object_set_new(out, "Warning",
                        json_string("Research replay only — modern terminals reject replayed ARQC"));

    json_t *card = json_object_get(sess, "Card");
    if (json_is_object(card)) {
        json_t *aid = json_object_get(card, "AID");
        if (json_is_string(aid)) {
            json_object_set_new(out, "AID", json_string(json_string_value(aid)));
        }
    }

    json_t *patch = json_object();
    json_t *app_data = json_object();

    if (json_is_object(card)) {
        patch_add_hex(app_data, "9F34", card, "CVMResults");
    }

    json_t *crypto = json_object_get(sess, "Cryptogram");
    if (json_is_object(crypto)) {
        patch_add_hex(app_data, "9F26", crypto, "AC");
        patch_add_hex(app_data, "9F36", crypto, "ATC");
        json_t *jtype = json_object_get(crypto, "Type");
        if (json_is_string(jtype)) {
            const char *t = json_string_value(jtype);
            if (strcmp(t, "AAC") == 0) {
                json_object_set_new(app_data, "9F27", json_string("00"));
            } else if (strcmp(t, "TC") == 0) {
                json_object_set_new(app_data, "9F27", json_string("40"));
            } else if (strcmp(t, "ARQC") == 0) {
                json_object_set_new(app_data, "9F27", json_string("80"));
            }
        }
    }

    json_object_set_new(patch, "ApplicationData", app_data);
    json_object_set_new(out, "CardPatch", patch);

    json_t *hist = json_array();
    if (json_is_object(crypto)) {
        json_t *entry = json_object();
        json_t *jtype = json_object_get(crypto, "Type");
        json_t *jac = json_object_get(crypto, "AC");
        json_t *jatc = json_object_get(crypto, "ATC");
        if (json_is_string(jtype)) {
            JsonSaveStr(entry, "Type", json_string_value(jtype));
        }
        if (json_is_string(jac)) {
            JsonSaveStr(entry, "AC", json_string_value(jac));
        }
        if (json_is_string(jatc)) {
            JsonSaveStr(entry, "ATC", json_string_value(jatc));
        }
        json_array_append_new(hist, entry);
    }
    json_object_set_new(out, "CryptogramHistory", hist);

    json_t *outcome = json_object_get(sess, "Outcome");
    if (json_is_string(outcome)) {
        json_object_set_new(out, "Outcome", json_string(json_string_value(outcome)));
    }

    return out;
}

int emv_term_sim_export_session(const char *session_path, const char *out_path) {
    if (!session_path || !session_path[0] || !out_path || !out_path[0]) {
        return PM3_EINVARG;
    }

    json_error_t error;
    json_t *sess = json_load_file(session_path, 0, &error);
    if (!sess) {
        PrintAndLogEx(ERR, "Session load error: %s", error.text);
        return PM3_ESOFT;
    }

    json_t *out = build_patch_from_session(sess);
    json_decref(sess);
    if (!out) {
        return PM3_ESOFT;
    }

    int res = write_patch_json(out, out_path);
    json_decref(out);
    return res;
}

int emv_term_sim_export_ctx(const emv_term_ctx_t *ctx, const char *out_path) {
    if (!ctx || !out_path || !out_path[0]) {
        return PM3_EINVARG;
    }

    json_t *out = json_object();
    json_t *file = json_object();
    JsonSaveStr(file, "Created", "proxmark3 emv terminal export-sim");
    JsonSaveStr(file, "Version", "1");
    json_object_set_new(out, "File", file);
    json_object_set_new(out, "Warning",
                        json_string("Research replay only — modern terminals reject replayed ARQC"));

    if (ctx->aid_len) {
        JsonSaveBufAsHexCompact(out, "AID", (uint8_t *)ctx->aid, ctx->aid_len);
    }

    json_t *app_data = json_object();
    const struct tlv *ac = tlvdb_get(ctx->card, 0x9f26, NULL);
    const struct tlv *atc = tlvdb_get(ctx->card, 0x9f36, NULL);
    const struct tlv *cid = tlvdb_get(ctx->card, 0x9f27, NULL);
    const struct tlv *cvm = tlvdb_get(ctx->card, 0x9f34, NULL);

    if (ac && ac->len) {
        JsonSaveBufAsHexCompact(app_data, "9F26", (uint8_t *)ac->value, ac->len);
    }
    if (atc && atc->len) {
        JsonSaveBufAsHexCompact(app_data, "9F36", (uint8_t *)atc->value, atc->len);
    }
    if (cid && cid->len) {
        JsonSaveBufAsHexCompact(app_data, "9F27", (uint8_t *)cid->value, cid->len);
    }
    if (cvm && cvm->len) {
        JsonSaveBufAsHexCompact(app_data, "9F34", (uint8_t *)cvm->value, cvm->len);
    }

    json_t *patch = json_object();
    json_object_set_new(patch, "ApplicationData", app_data);
    json_object_set_new(out, "CardPatch", patch);

    json_t *hist = json_array();
    json_t *entry = json_object();
    if (cid && cid->len) {
        uint8_t ctype = cid->value[0] & 0xC0;
        if (ctype == 0x00) {
            JsonSaveStr(entry, "Type", "AAC");
        } else if (ctype == 0x40) {
            JsonSaveStr(entry, "Type", "TC");
        } else if (ctype == 0x80) {
            JsonSaveStr(entry, "Type", "ARQC");
        }
    }
    if (ac && ac->len) {
        JsonSaveBufAsHexCompact(entry, "AC", (uint8_t *)ac->value, ac->len);
    }
    if (atc && atc->len) {
        JsonSaveBufAsHexCompact(entry, "ATC", (uint8_t *)atc->value, atc->len);
    }
    json_array_append_new(hist, entry);
    json_object_set_new(out, "CryptogramHistory", hist);

    JsonSaveStr(out, "Outcome", emv_term_outcome_str(ctx->outcome));

    int res = write_patch_json(out, out_path);
    json_decref(out);
    return res;
}
