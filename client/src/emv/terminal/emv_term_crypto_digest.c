//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// EMV terminal emulator — crypto playground digest / compare
//-----------------------------------------------------------------------------

#include "emv_term_crypto_digest.h"
#include "emv_term_scheme.h"
#include "emv_term_tlv.h"
#include "emv_term_ctx.h"
#include "../emv_tags.h"
#include "../emvjson.h"
#include "ui.h"
#include "commonutil.h"
#include <jansson.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

static const struct tlv *digest_card_tlv(const emv_term_ctx_t *ctx, tlv_tag_t tag) {
    if (!ctx || !ctx->card) {
        return NULL;
    }
    struct tlvdb *db = tlvdb_find_full(ctx->card, tag);
    return db ? tlvdb_get_tlv(db) : NULL;
}

static uint16_t digest_card_aip(const emv_term_ctx_t *ctx) {
    const struct tlv *aip = tlvdb_get(ctx->card, 0x82, NULL);
    if (!aip || aip->len < 2) {
        return 0;
    }
    return (uint16_t)(aip->value[0] | (aip->value[1] << 8));
}

static const char *digest_scheme_label(const emv_term_ctx_t *ctx) {
    if (!ctx || !ctx->aid_len) {
        return "unknown";
    }
    enum CardPSVendor v = GetCardPSVendor((uint8_t *)ctx->aid, ctx->aid_len);
    switch (v) {
        case CV_NA: return "unknown";
        case CV_VISA: return "Visa";
        case CV_MASTERCARD: return "Mastercard";
        case CV_INTERAC: return "Interac";
        case CV_AMERICANEXPRESS: return "Amex";
        case CV_JCB: return "JCB";
        case CV_CB: return "CB";
        case CV_SWITCH: return "Switch";
        case CV_DINERS: return "Diners";
        case CV_OTHER: break;
    }
    const char *s = emv_term_scheme_name_for_aid(ctx->aid, ctx->aid_len);
    return s ? s : "other";
}

static const char *digest_crypto_path(const emv_term_ctx_t *ctx) {
    uint16_t aip = digest_card_aip(ctx);
    if (digest_card_tlv(ctx, 0x9f26)) {
        if (!tlvdb_get(ctx->card, 0x8c, NULL)) {
            return "qVSDC (AC in GPO)";
        }
    }
    if (tlvdb_get(ctx->card, 0x8c, NULL)) {
        if (GetCardPSVendor((uint8_t *)ctx->aid, ctx->aid_len) == CV_MASTERCARD) {
            return "M/Chip contactless (CDOL1 + GET CHALLENGE)";
        }
        return "EMV contact/chip (CDOL1 GEN AC)";
    }
    if (aip == 0x8000) {
        return "Visa qVSDC MSD (track / online)";
    }
    if (aip == 0x0000 || aip == 0x0001) {
        return "Interac contactless";
    }
    return "unknown / MSD";
}

static void digest_mask_pan(char *out, size_t outlen, const uint8_t *pan, size_t panlen) {
    if (!out || outlen < 8 || !pan || !panlen) {
        if (out && outlen) {
            out[0] = '\0';
        }
        return;
    }
    size_t digits = panlen * 2;
    if (pan[panlen - 1] >> 4 == 0x0f) {
        digits--;
    }
    size_t show_head = digits > 10 ? 6 : 2;
    size_t show_tail = digits > 10 ? 4 : 2;
    size_t pos = 0;
    for (size_t i = 0; i < digits && pos + 1 < outlen; i++) {
        uint8_t nib = (i & 1) ? (pan[i / 2] & 0x0f) : (pan[i / 2] >> 4);
        if (nib > 9) {
            break;
        }
        if (i >= show_head && i < digits - show_tail) {
            out[pos++] = '*';
        } else {
            out[pos++] = (char)('0' + nib);
        }
    }
    out[pos] = '\0';
}

int emv_term_crypto_print_msd_summary(const emv_term_ctx_t *ctx) {
    if (!ctx) {
        return PM3_EINVARG;
    }

    const struct tlv *t2 = digest_card_tlv(ctx, 0x57);
    if (!t2 || !t2->len) {
        return PM3_SUCCESS;
    }

    PrintAndLogEx(INFO, "--- Visa / MSD track data ---");
    PrintAndLogEx(INFO, "Track2 equivalent (57) [%zu]: %s", t2->len, sprint_hex(t2->value, t2->len));

    const struct tlv *pan = digest_card_tlv(ctx, 0x5a);
    if (!pan) {
        pan = tlvdb_get(ctx->card, 0x5a, NULL);
    }
    if (pan && pan->len) {
        char masked[32] = {0};
        digest_mask_pan(masked, sizeof(masked), pan->value, pan->len);
        PrintAndLogEx(INFO, "PAN (masked): %s", masked);
    }

    const struct tlv *ffi = digest_card_tlv(ctx, 0x9f6e);
    if (ffi && ffi->len) {
        PrintAndLogEx(INFO, "Form Factor (9F6E): %s", sprint_hex(ffi->value, ffi->len));
    }
    const struct tlv *ctq = digest_card_tlv(ctx, 0x9f6c);
    if (ctq && ctq->len) {
        PrintAndLogEx(INFO, "CTQ (9F6C): %s", sprint_hex(ctq->value, ctq->len));
    }
    const struct tlv *ttq = emv_term_tlv_lookup(ctx, 0x9f66);
    if (ttq && ttq->len) {
        PrintAndLogEx(INFO, "TTQ sent (9F66): %s", sprint_hex(ttq->value, ttq->len));
    }

    return PM3_SUCCESS;
}

static void digest_print_afl_fingerprint(const emv_term_ctx_t *ctx) {
    const struct tlv *afl = tlvdb_get(ctx->card, 0x94, NULL);
    if (!afl || !afl->len) {
        PrintAndLogEx(INFO, "  AFL: (none)");
        return;
    }
    PrintAndLogEx(INFO, "  AFL [%zu]: %s", afl->len, sprint_hex(afl->value, afl->len));

    char line[256] = {0};
    size_t pos = 0;
    for (size_t i = 0; i + 3 < afl->len && pos + 16 < sizeof(line); i += 4) {
        uint8_t sfi = afl->value[i] >> 3;
        uint8_t start = afl->value[i + 1];
        uint8_t end = afl->value[i + 2];
        int n = snprintf(line + pos, sizeof(line) - pos, "%sSFI%02x:%u-%u",
                         pos ? ", " : "", sfi, start, end);
        if (n < 0) {
            break;
        }
        pos += (size_t)n;
    }
    PrintAndLogEx(INFO, "  AFL map: %s", line);
}

static const char *digest_cid_name(uint8_t cid) {
    switch (cid & 0xC0) {
        case 0x00: return "AAC (declined)";
        case 0x40: return "TC (approved offline)";
        case 0x80: return "ARQC (online)";
        default: return "unknown";
    }
}

int emv_term_crypto_print_digest(const emv_term_ctx_t *ctx, const emv_term_crypto_bench_result_t *result) {
    if (!ctx) {
        return PM3_EINVARG;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "╔══════════════════════════════════════════════════════════╗");
    PrintAndLogEx(INFO, "║           EMV crypto card digest                         ║");
    PrintAndLogEx(INFO, "╚══════════════════════════════════════════════════════════╝");

    if (ctx->aid_len) {
        PrintAndLogEx(INFO, "Scheme .............. %s", digest_scheme_label(ctx));
        PrintAndLogEx(INFO, "AID ................. %s", sprint_hex_inrow(ctx->aid, ctx->aid_len));
    }

    if (ctx->crypto_ppse_app_count > 1) {
        PrintAndLogEx(INFO, "PPSE applications ... %zu on card (using index %zu%s)",
                      ctx->crypto_ppse_app_count,
                      ctx->crypto_ppse_app_index + 1,
                      ctx->crypto_aid_fallback_used ? ", fallback" : "");
    }

    uint16_t aip = digest_card_aip(ctx);
    PrintAndLogEx(INFO, "AIP (82) ............ %04X  SDA:%s DDA:%s CVM:%s TRM:%s CDA:%s",
                  aip,
                  (aip & 0x0040) ? "y" : "n",
                  (aip & 0x0020) ? "y" : "n",
                  (aip & 0x0010) ? "y" : "n",
                  (aip & 0x0008) ? "y" : "n",
                  (aip & 0x0001) ? "y" : "n");
    PrintAndLogEx(INFO, "Crypto path ......... %s", digest_crypto_path(ctx));

    digest_print_afl_fingerprint(ctx);

    const struct tlv *cdol1 = tlvdb_get(ctx->card, 0x8c, NULL);
    const struct tlv *cdol2 = tlvdb_get(ctx->card, 0x8d, NULL);
    const struct tlv *ddol = tlvdb_get(ctx->card, 0x9f49, NULL);
    PrintAndLogEx(INFO, "DOLs ................ CDOL1:%s CDOL2:%s DDOL:%s",
                  (cdol1 && cdol1->len) ? "yes" : "no",
                  (cdol2 && cdol2->len) ? "yes" : "no",
                  (ddol && ddol->len) ? "yes" : "no");

    if (cdol1 && cdol1->len >= 3 && cdol1->len <= 39) {
        bool has_9f7c = false;
        const unsigned char *p = cdol1->value;
        size_t left = cdol1->len;
        while (left >= 2) {
            struct tlv e;
            if (!tlv_parse_tl(&p, &left, &e)) {
                break;
            }
            if (e.tag == 0x9f7c) {
                has_9f7c = true;
            }
        }
        if (has_9f7c) {
            PrintAndLogEx(INFO, "Neat ................ MC CED tag 9F7C in CDOL1 (20-byte merchant field)");
        }
    }

    const struct tlv *cvm = tlvdb_get(ctx->card, 0x8e, NULL);
    if (cvm && cvm->len) {
        PrintAndLogEx(INFO, "CVM list (8E) ....... present [%zu bytes] — run `emv terminal cvm -s`", cvm->len);
    }

    const struct tlv *ac = digest_card_tlv(ctx, 0x9f26);
    const struct tlv *cid = digest_card_tlv(ctx, 0x9f27);
    const struct tlv *atc = digest_card_tlv(ctx, 0x9f36);
    const struct tlv *iad = digest_card_tlv(ctx, 0x9f10);

    if (ac && ac->len) {
        PrintAndLogEx(SUCCESS, "Cryptogram (9F26) ... %s", sprint_hex(ac->value, ac->len));
    }
    if (cid && cid->len) {
        PrintAndLogEx(INFO, "CID (9F27) .......... %02X — %s", cid->value[0], digest_cid_name(cid->value[0]));
    }
    if (atc && atc->len == 2) {
        uint16_t atcv = (uint16_t)((atc->value[0] << 8) | atc->value[1]);
        PrintAndLogEx(INFO, "ATC (9F36) .......... %s (decimal %u)", sprint_hex(atc->value, atc->len), atcv);
    }
    if (iad && iad->len) {
        PrintAndLogEx(INFO, "IAD (9F10) .......... [%zu] %s", iad->len, sprint_hex(iad->value, iad->len));
    }

    if (result) {
        PrintAndLogEx(INFO, "Bench ............... genac:%s sw:%04X qvsdc:%s msd:%s vary:%zu",
                      result->genac_ok ? "OK" : (result->genac_attempted ? "fail" : "skip"),
                      result->genac_sw,
                      result->qvsdc_path ? "yes" : "no",
                      result->visa_msd ? "yes" : "no",
                      result->vary_runs);
    }

    if (aip == 0x0000 && GetCardPSVendor((uint8_t *)ctx->aid, ctx->aid_len) == CV_INTERAC) {
        PrintAndLogEx(INFO, "Neat ................ Interac minimal AIP 0000 — standalone ARQC path");
    }
    if (aip == 0x0001 && GetCardPSVendor((uint8_t *)ctx->aid, ctx->aid_len) == CV_INTERAC) {
        PrintAndLogEx(INFO, "Neat ................ Interac AIP 0001 (CDA) — needs full terminal pipeline");
    }
    if (aip == 0x8019 && GetCardPSVendor((uint8_t *)ctx->aid, ctx->aid_len) == CV_MASTERCARD) {
        PrintAndLogEx(INFO, "Neat ................ MC AIP 8019 — full M/Chip contactless + CVM");
    }

    const struct tlv *label = tlvdb_get(ctx->card, 0x50, NULL);
    if (label && label->len) {
        PrintAndLogEx(INFO, "App label (50) ...... %.*s", (int)label->len, label->value);
    }

    if (!ac && !cdol1 && digest_card_aip(ctx) == 0x8000) {
        PrintAndLogEx(INFO, "---");
        emv_term_crypto_print_msd_summary(ctx);
    }

    PrintAndLogEx(INFO, "--- Suggested next steps ---");
    if (!cdol1 && ctx->crypto_ppse_app_count > 1 && !ctx->crypto_aid_fallback_used) {
        PrintAndLogEx(HINT, "  emv terminal crypto run --aid <hex>   try Maestro/alt PPSE app");
    }
    if (cdol1 && GetCardPSVendor((uint8_t *)ctx->aid, ctx->aid_len) == CV_MASTERCARD) {
        PrintAndLogEx(HINT, "  emv terminal crypto vary -s --count 5   UN sensitivity lab");
    }
    if (cdol1 && GetCardPSVendor((uint8_t *)ctx->aid, ctx->aid_len) == CV_INTERAC && result && !result->genac_ok) {
        PrintAndLogEx(HINT, "  emv terminal run -s                   full CVM/TRM/TAA pipeline");
        PrintAndLogEx(HINT, "  emv terminal crypto run -s --decision tc");
    }
    if (!ac && !cdol1 && digest_card_aip(ctx) == 0x8000) {
        PrintAndLogEx(HINT, "  emv terminal run -s                   online / MSD flow");
    }
    if (ctx->opts.crypto_quick_afl) {
        PrintAndLogEx(HINT, "  (quick AFL was used — omit --quick for full record sweep)");
    } else if (cdol1 && GetCardPSVendor((uint8_t *)ctx->aid, ctx->aid_len) == CV_MASTERCARD) {
        PrintAndLogEx(HINT, "  emv terminal crypto run -s --quick    faster, fewer -20 timeouts");
    }
    PrintAndLogEx(HINT, "  emv terminal crypto run -s -o card.json && crypto compare a.json b.json");

    return PM3_SUCCESS;
}

static const char *json_hex_field(json_t *obj, const char *key) {
    if (!obj || !key) {
        return NULL;
    }
    json_t *j = json_object_get(obj, key);
    if (!json_is_string(j)) {
        return NULL;
    }
    return json_string_value(j);
}

static void compare_field(const char *label, const char *a, const char *b) {
    if (!a && !b) {
        return;
    }
    if (!a) {
        a = "(missing)";
    }
    if (!b) {
        b = "(missing)";
    }
    if (strcmp(a, b) == 0) {
        PrintAndLogEx(INFO, "  %-12s same: %s", label, a);
    } else {
        PrintAndLogEx(WARNING, "  %-12s A: %s", label, a);
        PrintAndLogEx(WARNING, "  %-12s B: %s", label, b);
    }
}

int emv_term_crypto_compare_json(const char *path_a, const char *path_b) {
    if (!path_a || !path_a[0] || !path_b || !path_b[0]) {
        return PM3_EINVARG;
    }

    json_error_t err;
    json_t *ja = json_load_file(path_a, 0, &err);
    if (!ja) {
        PrintAndLogEx(ERR, "Cannot load %s: %s", path_a, err.text);
        return PM3_ESOFT;
    }
    json_t *jb = json_load_file(path_b, 0, &err);
    if (!jb) {
        PrintAndLogEx(ERR, "Cannot load %s: %s", path_b, err.text);
        json_decref(ja);
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "=== Crypto export compare ===");
    PrintAndLogEx(INFO, "A: %s", path_a);
    PrintAndLogEx(INFO, "B: %s", path_b);

    compare_field("AID", json_hex_field(ja, "AID"), json_hex_field(jb, "AID"));
    compare_field("AIP", json_hex_field(ja, "AIP"), json_hex_field(jb, "AIP"));
    compare_field("CDOL1", json_hex_field(ja, "CDOL1"), json_hex_field(jb, "CDOL1"));
    compare_field("CDOL2", json_hex_field(ja, "CDOL2"), json_hex_field(jb, "CDOL2"));
    compare_field("DDOL", json_hex_field(ja, "DDOL"), json_hex_field(jb, "DDOL"));
    compare_field("AC", json_hex_field(ja, "AC"), json_hex_field(jb, "AC"));
    compare_field("ATC", json_hex_field(ja, "ATC"), json_hex_field(jb, "ATC"));
    compare_field("CID", json_hex_field(ja, "CID"), json_hex_field(jb, "CID"));
    compare_field("IAD", json_hex_field(ja, "IAD"), json_hex_field(jb, "IAD"));
    compare_field("AFL", json_hex_field(ja, "AFL"), json_hex_field(jb, "AFL"));
    compare_field("Track2", json_hex_field(ja, "Track2"), json_hex_field(jb, "Track2"));
    compare_field("CryptoPath", json_hex_field(ja, "CryptoPath"), json_hex_field(jb, "CryptoPath"));

    json_t *pa = json_object_get(ja, "PPSEAppCount");
    json_t *pb = json_object_get(jb, "PPSEAppCount");
    if (json_is_integer(pa) || json_is_integer(pb)) {
        int ia = json_is_integer(pa) ? (int)json_integer_value(pa) : -1;
        int ib = json_is_integer(pb) ? (int)json_integer_value(pb) : -1;
        if (ia == ib) {
            PrintAndLogEx(INFO, "  PPSEApps     same: %d", ia);
        } else {
            PrintAndLogEx(WARNING, "  PPSEApps     A:%d  B:%d", ia, ib);
        }
    }

    json_t *fa = json_object_get(ja, "AIDFallbackUsed");
    json_t *fb = json_object_get(jb, "AIDFallbackUsed");
    if (json_is_boolean(fa) || json_is_boolean(fb)) {
        bool ba = json_is_boolean(fa) ? json_is_true(fa) : false;
        bool bb = json_is_boolean(fb) ? json_is_true(fb) : false;
        if (ba == bb) {
            PrintAndLogEx(INFO, "  AIDFallback  same: %s", ba ? "yes" : "no");
        } else {
            PrintAndLogEx(WARNING, "  AIDFallback  A:%s  B:%s", ba ? "yes" : "no", bb ? "yes" : "no");
        }
    }

    json_t *ra = json_object_get(ja, "Runs");
    json_t *rb = json_object_get(jb, "Runs");
    size_t na = json_is_array(ra) ? json_array_size(ra) : 0;
    size_t nb = json_is_array(rb) ? json_array_size(rb) : 0;
    if (na || nb) {
        PrintAndLogEx(INFO, "  Runs         A:%zu entries  B:%zu entries", na, nb);
    }

    json_decref(ja);
    json_decref(jb);
    return PM3_SUCCESS;
}
