//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// EMV terminal emulator — card GET DATA probe / enumeration
//-----------------------------------------------------------------------------

#include "emv_term_probe.h"
#include "emv_term_tlv.h"
#include "emv_term_profile.h"
#include "emv_term_session.h"
#include "phase_cvm.h"
#include "emv_transaction.h"
#include "../emvcore.h"
#include "../emv_tags.h"
#include "../tlv.h"
#include "ui.h"
#include "commonutil.h"
#include <string.h>

static const uint16_t probe_tags_default[] = {
    0x9F36, // ATC
    0x9F13, // Last Online ATC Register
    0x9F17, // PIN Try Counter
    0x9F4D, // Log Entry
    0x9F4F, // Log Format
    0x9F50, // Offline counters
    0x9F51, // DRDOL
    0x9F52, // Application Default Action
    0x9F53, // Transaction Category Code
    0x9F54, // Cumulative Total Transaction Amount
    0x9F58, // Consecutive Transaction Counter
    0x9F5A, // Available Offline Spending Amount
    0x9F6E, // Form Factor Indicator
    0x9F7C, // Customer Exclusive Data
    0x9F7E, // Mobile Support Indicator
};

static const uint16_t probe_tags_sweep[] = {
    0x0057, 0x005A, 0x008C, 0x008E, 0x009F08, 0x009F0D, 0x009F0E, 0x009F0F,
    0x009F10, 0x009F11, 0x009F12, 0x009F13, 0x009F14, 0x009F17, 0x009F1F, 0x009F23,
    0x009F26, 0x009F27, 0x009F2D, 0x009F32, 0x009F36, 0x009F38, 0x009F42, 0x009F44,
    0x009F46, 0x009F47, 0x009F48, 0x009F49, 0x009F4A, 0x009F4B, 0x009F4C, 0x009F4D,
    0x009F4E, 0x009F4F, 0x009F50, 0x009F51, 0x009F52, 0x009F53, 0x009F54, 0x009F55,
    0x009F56, 0x009F57, 0x009F58, 0x009F59, 0x009F5A, 0x009F5B, 0x009F5C, 0x009F5D,
    0x009F5E, 0x009F6A, 0x009F6B, 0x009F6C, 0x009F6D, 0x009F6E, 0x009F7C, 0x009F7D,
    0x009F7E, 0x009F7F,
};

static const tlv_tag_t probe_highlight_tags[] = {
    0x57, 0x5A, 0x82, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x92, 0x94,
    0x9F07, 0x9F08, 0x9F0D, 0x9F0E, 0x9F0F, 0x9F10, 0x9F11, 0x9F12, 0x9F17,
    0x9F1F, 0x9F2D, 0x9F32, 0x9F38, 0x9F42, 0x9F46, 0x9F47, 0x9F48, 0x9F49,
    0x9F4A, 0x9F4B, 0x9F4C, 0x9F6C, 0x9F6E,
};

typedef struct {
    tlv_tag_t tags[64];
    size_t count;
} tag_set_t;

static bool tag_set_has(const tag_set_t *set, tlv_tag_t tag) {
    for (size_t i = 0; i < set->count; i++) {
        if (set->tags[i] == tag) {
            return true;
        }
    }
    return false;
}

static void tag_set_add(tag_set_t *set, tlv_tag_t tag) {
    if (!tag || tag == 1 || tag_set_has(set, tag) || set->count >= ARRAYLEN(set->tags)) {
        return;
    }
    set->tags[set->count++] = tag;
}

static void collect_tags_cb(void *data, const struct tlv *tlv, int level, bool is_leaf) {
    (void)level;
    if (!is_leaf || !tlv) {
        return;
    }
    tag_set_add((tag_set_t *)data, tlv->tag);
}

static void print_tag_set(const char *label, const tag_set_t *set) {
    if (!set->count) {
        PrintAndLogEx(INFO, "%s: (none)", label);
        return;
    }

    char line[512] = {0};
    size_t pos = 0;
    for (size_t i = 0; i < set->count && pos + 12 < sizeof(line); i++) {
        int n = snprintf(line + pos, sizeof(line) - pos, "%s%04X",
                         i ? ", " : "", set->tags[i]);
        if (n < 0) {
            break;
        }
        pos += (size_t)n;
    }
    PrintAndLogEx(INFO, "%s: %s", label, line);
}

int emv_term_prepare_card(emv_term_ctx_t *ctx, bool jload, const char *session_path) {
    if (!ctx) {
        return PM3_EINVARG;
    }

    if (session_path && session_path[0]) {
        int res = emv_term_session_load_json(ctx, session_path);
        if (res) {
            return res;
        }
        emv_term_init_transaction_params(ctx->terminal, jload, NULL, TT_QVSDCMCHIP, false);
        emv_term_copy_terminal_tags_to_card(ctx);
        return PM3_SUCCESS;
    }

    return emv_transaction_init(ctx);
}

static int probe_one_tag(emv_term_ctx_t *ctx, uint16_t tag, int *found) {
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    int res = EMVGetData(ctx->channel, true, tag, buf, sizeof(buf), &len, &sw, ctx->card);
    if (res) {
        PrintAndLogEx(INFO, "GET DATA %04X: transport error (%d)", tag, res);
        return res;
    }

    if (sw == 0x9000 && len > 0) {
        (*found)++;
        PrintAndLogEx(SUCCESS, "GET DATA %04X [%zu]: %s", tag, len, sprint_hex(buf, len));
        TLVPrintFromBuffer(buf, len);
        return PM3_SUCCESS;
    }

    PrintAndLogEx(INFO, "GET DATA %04X: %04X - %s", tag, sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
    return PM3_SUCCESS;
}

static void probe_print_highlights(emv_term_ctx_t *ctx) {
    PrintAndLogEx(INFO, "--- Card context highlights ---");
    for (size_t i = 0; i < ARRAYLEN(probe_highlight_tags); i++) {
        tlv_tag_t tag = probe_highlight_tags[i];
        const struct tlv *tlv = tlvdb_get(ctx->card, tag, NULL);
        if (!tlv || !tlv->len) {
            continue;
        }
        struct tlv stub = {.tag = tag, .len = tlv->len, .value = tlv->value};
        PrintAndLogEx(SUCCESS, "  %04X %s [%zu]", tag, emv_get_tag_name(&stub), tlv->len);
        if (tag == 0x8E) {
            emv_term_cvm_dump_list(ctx);
        } else if (tag == 0x8C || tag == 0x8D) {
            emv_tag_dump(&stub, 0);
        }
    }
}

static int emv_term_probe_afl_records(emv_term_ctx_t *ctx, bool decode_tlv) {
    const struct tlv *AFL = tlvdb_get(ctx->card, 0x94, NULL);
    if (!AFL || !AFL->len) {
        PrintAndLogEx(WARNING, "No AFL (94) in context — use probe -s for live init (not session-only)");
        return PM3_ESOFT;
    }

    if (AFL->len % 4) {
        PrintAndLogEx(ERR, "AFL length %zu is not a multiple of 4", AFL->len);
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "--- AFL record sweep ---");
    PrintAndLogEx(INFO, "AFL (%zu): %s", AFL->len, sprint_hex(AFL->value, AFL->len));

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int records_ok = 0;
    tag_set_t all_tags = {0};

    for (size_t i = 0; i < AFL->len / 4; i++) {
        uint8_t SFI = AFL->value[i * 4 + 0] >> 3;
        uint8_t SFIstart = AFL->value[i * 4 + 1];
        uint8_t SFIend = AFL->value[i * 4 + 2];

        if (SFI == 0 || SFI == 31 || SFIstart == 0 || SFIstart > SFIend) {
            PrintAndLogEx(WARNING, "AFL entry %zu: invalid SFI=%02x start=%02x end=%02x — skipped",
                          i + 1, SFI, SFIstart, SFIend);
            continue;
        }

        for (int n = SFIstart; n <= SFIend; n++) {
            int res = EMVReadRecord(ctx->channel, true, SFI, (uint8_t)n, buf, sizeof(buf), &len, &sw, ctx->card);
            if (res || sw != 0x9000 || len == 0) {
                PrintAndLogEx(INFO, "READ RECORD SFI %02x #%d: %04X - %s", SFI, n, sw,
                              GetAPDUCodeDescription(sw >> 8, sw & 0xff));
                continue;
            }

            records_ok++;
            tag_set_t rec_tags = {0};
            struct tlvdb *rec_db = tlvdb_parse(buf, len);
            if (rec_db) {
                tlvdb_visit(rec_db, collect_tags_cb, &rec_tags, 0);
                tlvdb_free(rec_db);
            }

            for (size_t t = 0; t < rec_tags.count; t++) {
                tag_set_add(&all_tags, rec_tags.tags[t]);
            }

            PrintAndLogEx(SUCCESS, "READ RECORD SFI %02x #%d [%zu bytes]", SFI, n, len);
            print_tag_set("  tags", &rec_tags);

            if (decode_tlv) {
                TLVPrintFromBuffer(buf, len);
            }
        }
    }

    print_tag_set("All unique record tags", &all_tags);
    probe_print_highlights(ctx);

    if (records_ok == 0) {
        PrintAndLogEx(WARNING, "No AFL records returned data — card may need fresh init on reader");
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "AFL sweep: %d record(s) read", records_ok);
    return PM3_SUCCESS;
}

int emv_term_probe_card(emv_term_ctx_t *ctx, const emv_term_probe_opts_t *opts) {
    if (!ctx || !opts) {
        return PM3_EINVARG;
    }

    const uint16_t *tags = probe_tags_default;
    size_t tag_count = ARRAYLEN(probe_tags_default);
    if (opts->sweep_all) {
        tags = probe_tags_sweep;
        tag_count = ARRAYLEN(probe_tags_sweep);
    }

    PrintAndLogEx(INFO, "--- EMV card probe (%s) ---",
                  opts->sweep_all ? "extended GET DATA sweep" : "common GET DATA tags");

    const struct tlv *cvm_list = tlvdb_get(ctx->card, 0x8e, NULL);
    if (cvm_list && cvm_list->len >= 10) {
        PrintAndLogEx(INFO, "CVM List (8E) already in card context:");
        emv_term_cvm_dump_list(ctx);
    } else if (!opts->read_records) {
        PrintAndLogEx(INFO, "No CVM List (8E) in context — try probe -s --records");
    }

    const struct tlv *aip = tlvdb_get(ctx->card, 0x82, NULL);
    if (aip && aip->len >= 2) {
        PrintAndLogEx(INFO, "AIP (82): %s", sprint_hex(aip->value, aip->len));
        bool cvm_supported = (aip->value[0] & 0x10) != 0;
        PrintAndLogEx(INFO, "  Cardholder verification supported (AIP b4): %s", cvm_supported ? "yes" : "no");
    }

    int found = 0;
    for (size_t i = 0; i < tag_count; i++) {
        probe_one_tag(ctx, tags[i], &found);
    }

    if (found == 0) {
        PrintAndLogEx(WARNING, "No GET DATA tags returned data — tags may be record-only (try --records)");
    } else {
        PrintAndLogEx(SUCCESS, "GET DATA probe: %d tag(s) returned data", found);
    }

    if (opts->read_records) {
        emv_term_probe_afl_records(ctx, opts->decode_tlv);
    } else {
        probe_print_highlights(ctx);
    }

    if (ctx->channel == CC_CONTACTLESS) {
        PrintAndLogEx(INFO, "Note: contactless cards rarely support offline PIN VERIFY (00 20); use contact (-w) or expect online PIN / no-CVM");
    }

    return PM3_SUCCESS;
}
