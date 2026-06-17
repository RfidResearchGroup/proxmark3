//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "emv_term_load.h"
#include "../emvjson.h"
#include "../tlv.h"
#include "ui.h"
#include "util.h"
#include "commonutil.h"
#include <jansson.h>
#include <string.h>

static bool parse_json_hex_field(json_t *obj, const char *key, uint8_t *out, size_t *out_len, size_t max_len) {
    json_t *jelm = json_object_get(obj, key);
    if (!jelm || !json_is_string(jelm)) {
        return false;
    }
    int buflen = 0;
    if (param_gethex_to_eol(json_string_value(jelm), 0, out, max_len, &buflen)) {
        return false;
    }
    if (out_len) {
        *out_len = (size_t)buflen;
    }
    return true;
}

static tlv_tag_t parse_json_tag(json_t *obj) {
    uint8_t buf[4] = {0};
    size_t len = 0;
    if (!parse_json_hex_field(obj, "tag", buf, &len, sizeof(buf)) || len == 0) {
        return 0;
    }
    tlv_tag_t tag = buf[0];
    if (len >= 2) {
        tag = (tag << 8) | buf[1];
    }
    if (len >= 3) {
        tag = (tag << 8) | buf[2];
    }
    return tag;
}

static struct tlvdb *json_tlv_to_tlvdb(json_t *node) {
    if (!node || !json_is_object(node)) {
        return NULL;
    }

    tlv_tag_t tag = parse_json_tag(node);
    if (!tag) {
        return NULL;
    }

    uint8_t value[4096] = {0};
    size_t value_len = 0;
    parse_json_hex_field(node, "value", value, &value_len, sizeof(value));

    struct tlvdb *elm = tlvdb_fixed(tag, value_len, value);

    json_t *childs = json_object_get(node, "Childs");
    if (json_is_array(childs)) {
        size_t n = json_array_size(childs);
        for (size_t i = 0; i < n; i++) {
            struct tlvdb *child = json_tlv_to_tlvdb(json_array_get(childs, i));
            if (child) {
                if (!elm->children) {
                    elm->children = child;
                    child->parent = elm;
                } else {
                    tlvdb_add(elm->children, child);
                    child->parent = elm;
                }
            }
        }
    }

    return elm;
}

static void merge_tlv_tree(struct tlvdb *root, json_t *node) {
    struct tlvdb *parsed = json_tlv_to_tlvdb(node);
    if (parsed) {
        tlvdb_add(root, parsed);
    }
}

static void merge_tlv_json_path(struct tlvdb *root, json_t *doc, const char *path) {
    json_t *node = json_path_get(doc, path);
    if (!node) {
        return;
    }
    if (json_is_array(node)) {
        size_t n = json_array_size(node);
        for (size_t i = 0; i < n; i++) {
            merge_tlv_tree(root, json_array_get(node, i));
        }
    } else if (json_is_object(node)) {
        merge_tlv_tree(root, node);
    }
}

static void load_application_data(struct tlvdb *root, json_t *doc) {
    JsonLoadApplicationData(doc, root);
}

static struct tlv *encode_target_tlv(const struct tlvdb *parsed, uint8_t sfi) {
    const struct tlvdb *target = parsed;
    if (sfi < 11) {
        const struct tlvdb *child = tlvdb_elm_get_children(parsed);
        if (child) {
            target = child;
            while (tlvdb_elm_get_next(target)) {
                target = tlvdb_elm_get_next(target);
            }
        }
    }
    return (struct tlv *)tlvdb_get_tlv(target);
}

static void append_oda_bytes(uint8_t *list, size_t *list_len, size_t max_len, const uint8_t *data, size_t data_len) {
    if (!data || !data_len || !list || !list_len || *list_len + data_len > max_len) {
        return;
    }
    memcpy(list + *list_len, data, data_len);
    *list_len += data_len;
}

static void rebuild_oda_list_from_records(emv_term_ctx_t *ctx, json_t *doc) {
    if (!ctx || tlvdb_get(ctx->card, 0x21, NULL)) {
        return;
    }

    json_t *records = json_path_get(doc, "$.Application.Records");
    if (!json_is_array(records)) {
        return;
    }

    uint8_t oda_list[4096] = {0};
    size_t oda_list_len = 0;

    size_t n = json_array_size(records);
    for (size_t i = 0; i < n; i++) {
        json_t *rec = json_array_get(records, i);
        if (!json_is_object(rec)) {
            continue;
        }

        json_t *joffline = json_object_get(rec, "Offline");
        if (!json_is_string(joffline)) {
            continue;
        }
        uint8_t offline_cnt = 0;
        int buflen = 0;
        if (param_gethex_to_eol(json_string_value(joffline), 0, &offline_cnt, 1, &buflen) || buflen != 1) {
            continue;
        }
        if (offline_cnt == 0) {
            continue;
        }

        uint8_t sfi = 0;
        json_t *jsfi = json_object_get(rec, "SFI");
        if (json_is_string(jsfi)) {
            param_gethex_to_eol(json_string_value(jsfi), 0, &sfi, 1, &buflen);
        }

        json_t *data = json_path_get(rec, "$.Data");
        struct tlvdb *parsed = json_tlv_to_tlvdb(data);
        if (!parsed) {
            continue;
        }

        struct tlv *encode_tlv = encode_target_tlv(parsed, sfi);
        if (!encode_tlv) {
            tlvdb_free(parsed);
            continue;
        }

        size_t enc_len = 0;
        unsigned char *enc = tlv_encode(encode_tlv, &enc_len);
        if (enc && enc_len) {
            append_oda_bytes(oda_list, &oda_list_len, sizeof(oda_list), enc, enc_len);
        }
        free(enc);
        tlvdb_free(parsed);
    }

    if (oda_list_len) {
        ctx->oda_list_len = oda_list_len;
        memcpy(ctx->oda_list, oda_list, oda_list_len);
        struct tlvdb *oda = tlvdb_fixed(0x21, oda_list_len, ctx->oda_list);
        tlvdb_add(ctx->card, oda);
        PrintAndLogEx(INFO, "Rebuilt ODA input list from scan records (%zu bytes)", oda_list_len);
    }
}

static void load_records(struct tlvdb *root, json_t *doc) {
    json_t *records = json_path_get(doc, "$.Application.Records");
    if (!json_is_array(records)) {
        return;
    }

    size_t n = json_array_size(records);
    for (size_t i = 0; i < n; i++) {
        json_t *rec = json_array_get(records, i);
        if (!json_is_object(rec)) {
            continue;
        }
        merge_tlv_json_path(root, rec, "$.Data");
    }
}

int emv_term_load_from_scan(emv_term_ctx_t *ctx, const char *path) {
    if (!ctx || !path || !path[0]) {
        return PM3_EINVARG;
    }

    json_error_t error;
    json_t *root = json_load_file(path, 0, &error);
    if (!root) {
        PrintAndLogEx(ERR, "Scan load error line %d: %s", error.line, error.text);
        return PM3_ESOFT;
    }

    uint8_t aid[APDU_AID_LEN] = {0};
    size_t aid_len = 0;
    if (JsonLoadBufAsHex(root, "$.Application.AID", aid, sizeof(aid), &aid_len) != 0 || aid_len == 0) {
        PrintAndLogEx(ERR, "Scan JSON missing $.Application.AID");
        json_decref(root);
        return PM3_EINVARG;
    }

    memcpy(ctx->aid, aid, aid_len);
    ctx->aid_len = aid_len;

    merge_tlv_json_path(ctx->card, root, "$.Application.FCITemplate");
    merge_tlv_json_path(ctx->card, root, "$.Application.GPO");
    load_application_data(ctx->card, root);
    load_records(ctx->card, root);
    rebuild_oda_list_from_records(ctx, root);

    json_decref(root);

    if (!tlvdb_get(ctx->card, 0x82, NULL)) {
        PrintAndLogEx(ERR, "Loaded card data missing AIP (82) — run emv scan with full TLV");
        return PM3_EINVARG;
    }

    if (!tlvdb_get(ctx->card, 0x8c, NULL) && !tlvdb_get(ctx->card, 0x9f26, NULL)) {
        PrintAndLogEx(WARNING, "No CDOL1 (8C) or AC (9F26) — offline GEN AC testing may be limited");
    }

    PrintAndLogEx(SUCCESS, "Loaded card TLV from scan: AID=%s", sprint_hex_inrow(ctx->aid, ctx->aid_len));
    return PM3_SUCCESS;
}

int emv_term_load_card_tlv(emv_term_ctx_t *ctx, const char *path) {
    if (!ctx || !path || !path[0]) {
        return PM3_EINVARG;
    }

    json_error_t error;
    json_t *root = json_load_file(path, 0, &error);
    if (!root) {
        PrintAndLogEx(ERR, "Card TLV load error line %d: %s", error.line, error.text);
        return PM3_ESOFT;
    }

    uint8_t aid[APDU_AID_LEN] = {0};
    size_t aid_len = 0;
    json_t *jaid = json_object_get(root, "aid");
    if (json_is_string(jaid)) {
        int buflen = 0;
        if (param_gethex_to_eol(json_string_value(jaid), 0, aid, sizeof(aid), &buflen)) {
            json_decref(root);
            return PM3_ESOFT;
        }
        aid_len = (size_t)buflen;
        memcpy(ctx->aid, aid, aid_len);
        ctx->aid_len = aid_len;
    }

    json_t *tags = json_object_get(root, "tags");
    if (json_is_array(tags)) {
        size_t n = json_array_size(tags);
        for (size_t i = 0; i < n; i++) {
            json_t *tag = json_array_get(tags, i);
            if (!json_is_object(tag)) {
                continue;
            }
            tlv_tag_t t = parse_json_tag(tag);
            if (!t) {
                continue;
            }
            uint8_t value[256] = {0};
            size_t value_len = 0;
            if (parse_json_hex_field(tag, "value", value, &value_len, sizeof(value))) {
                tlvdb_change_or_add_node(ctx->card, t, value_len, value);
            }
        }
    }

    json_decref(root);
    PrintAndLogEx(INFO, "Loaded card TLV fixture: AID=%s", ctx->aid_len ? sprint_hex_inrow(ctx->aid, ctx->aid_len) : "(none)");
    return PM3_SUCCESS;
}
