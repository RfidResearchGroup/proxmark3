//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// EMV terminal emulator — crypto playground
//-----------------------------------------------------------------------------

#include "emv_term_crypto.h"
#include "emv_term_tlv.h"
#include "emv_term_tvr.h"
#include "emv_transaction.h"
#include "../dol.h"
#include "../emv_tags.h"
#include "../emvcore.h"
#include "../emvjson.h"
#include "ui.h"
#include "commonutil.h"
#include "protocols.h"
#include <jansson.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#define EMVAC_CDAREQ 0x10

void emv_term_uint_to_bcd(uint64_t val, uint8_t *out, size_t len) {
    if (!out || !len) {
        return;
    }
    memset(out, 0, len);
    for (size_t i = 0; i < len; i++) {
        uint8_t lo = (uint8_t)(val % 10);
        val /= 10;
        uint8_t hi = (uint8_t)(val % 10);
        val /= 10;
        out[len - 1 - i] = (uint8_t)((hi << 4) | lo);
    }
}

void emv_term_crypto_genac_opts_defaults(emv_term_crypto_genac_opts_t *opts) {
    if (!opts) {
        return;
    }
    memset(opts, 0, sizeof(*opts));
    opts->ac_type = EMV_CRYPTO_AC_ARQC;
}

void emv_term_crypto_set_amount_cents(emv_term_ctx_t *ctx, uint64_t cents) {
    if (!ctx || !ctx->terminal) {
        return;
    }
    uint8_t bcd[6] = {0};
    emv_term_uint_to_bcd(cents, bcd, sizeof(bcd));
    tlvdb_change_or_add_node(ctx->terminal, 0x9f02, sizeof(bcd), bcd);
    emv_term_copy_terminal_tags_to_card(ctx);
}

void emv_term_crypto_set_un_bytes(emv_term_ctx_t *ctx, const uint8_t un[4]) {
    if (!ctx || !ctx->terminal || !un) {
        return;
    }
    tlvdb_change_or_add_node(ctx->terminal, 0x9f37, 4, un);
    emv_term_copy_terminal_tags_to_card(ctx);
}

void emv_term_crypto_randomize_un(emv_term_ctx_t *ctx) {
    uint8_t un[4] = {0};
    un[0] = (uint8_t)(rand() & 0xFF);
    un[1] = (uint8_t)(rand() & 0xFF);
    un[2] = (uint8_t)(rand() & 0xFF);
    un[3] = (uint8_t)(rand() & 0xFF);
    emv_term_crypto_set_un_bytes(ctx, un);
}

void emv_term_crypto_apply_field_overrides(emv_term_ctx_t *ctx, const emv_term_crypto_genac_opts_t *opts) {
    if (!ctx || !opts) {
        return;
    }
    if (opts->amount_set) {
        tlvdb_change_or_add_node(ctx->terminal, 0x9f02, sizeof(opts->amount), opts->amount);
    }
    if (opts->un_set) {
        tlvdb_change_or_add_node(ctx->terminal, 0x9f37, 4, opts->un);
    }
    if (opts->date_set) {
        tlvdb_change_or_add_node(ctx->terminal, 0x9a, 3, opts->date);
    }
    if (opts->country_set) {
        tlvdb_change_or_add_node(ctx->terminal, 0x9f1a, 2, opts->country);
    }
    if (opts->currency_set) {
        tlvdb_change_or_add_node(ctx->terminal, 0x5f2a, 2, opts->currency);
    }
    emv_term_copy_terminal_tags_to_card(ctx);
}

static void print_dol_tag(const char *label, tlv_tag_t tag, const struct tlv *dol) {
    if (!dol || !dol->len) {
        PrintAndLogEx(INFO, "%s (%04X): not present", label, tag);
        return;
    }
    PrintAndLogEx(INFO, "%s (%04X) [%zu]: %s", label, tag, dol->len, sprint_hex(dol->value, dol->len));
    struct tlv stub = {.tag = tag, .len = dol->len, .value = dol->value};
    if (tag == 0x8c || tag == 0x8d || tag == 0x9f49) {
        emv_tag_dump(&stub, 0);
    }
}

static void print_aip_bits(uint16_t aip) {
    PrintAndLogEx(INFO, "  SDA: %s  DDA: %s  CVM: %s  TRM: %s  CDA: %s",
                  (aip & 0x0040) ? "yes" : "no",
                  (aip & 0x0020) ? "yes" : "no",
                  (aip & 0x0010) ? "yes" : "no",
                  (aip & 0x0008) ? "yes" : "no",
                  (aip & 0x0001) ? "yes" : "no");
}

int emv_term_crypto_print_summary(const emv_term_ctx_t *ctx) {
    if (!ctx) {
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "=== EMV crypto playground summary ===");

    if (ctx->aid_len) {
        PrintAndLogEx(INFO, "AID: %s", sprint_hex_inrow(ctx->aid, ctx->aid_len));
    }

    const struct tlv *aip = tlvdb_get(ctx->card, 0x82, NULL);
    if (aip && aip->len >= 2) {
        uint16_t aipv = (uint16_t)(aip->value[0] | (aip->value[1] << 8));
        PrintAndLogEx(INFO, "AIP (82): %04x", aipv);
        print_aip_bits(aipv);
    }

    print_dol_tag("CDOL1", 0x8c, tlvdb_get(ctx->card, 0x8c, NULL));
    print_dol_tag("CDOL2", 0x8d, tlvdb_get(ctx->card, 0x8d, NULL));
    print_dol_tag("DDOL", 0x9f49, tlvdb_get(ctx->card, 0x9f49, NULL));

    const struct tlv *amount = emv_term_tlv_lookup(ctx, 0x9f02);
    const struct tlv *un = emv_term_tlv_lookup(ctx, 0x9f37);
    if (amount && amount->len) {
        PrintAndLogEx(INFO, "Terminal amount (9F02): %s (%" PRIu64 " cents)",
                      sprint_hex(amount->value, amount->len),
                      emv_term_bcd_to_uint(amount->value, amount->len));
    }
    if (un && un->len == 4) {
        PrintAndLogEx(INFO, "Terminal UN (9F37): %s", sprint_hex(un->value, un->len));
    }

    const struct tlv *cid = tlvdb_get(ctx->card, 0x9f27, NULL);
    const struct tlv *atc = tlvdb_get(ctx->card, 0x9f36, NULL);
    const struct tlv *ac = tlvdb_get(ctx->card, 0x9f26, NULL);
    const struct tlv *iad = tlvdb_get(ctx->card, 0x9f10, NULL);

    if (cid && cid->len) {
        uint8_t c = cid->value[0];
        const char *name = "unknown";
        switch (c & 0xC0) {
            case 0x00: name = "AAC"; break;
            case 0x40: name = "TC"; break;
            case 0x80: name = "ARQC"; break;
        }
        PrintAndLogEx(INFO, "Last CID (9F27): %02x (%s)", c, name);
    }
    if (atc && atc->len) {
        PrintAndLogEx(INFO, "Last ATC (9F36): %s", sprint_hex(atc->value, atc->len));
    }
    if (ac && ac->len) {
        PrintAndLogEx(INFO, "Last AC (9F26): %s", sprint_hex(ac->value, ac->len));
    }
    if (iad && iad->len) {
        PrintAndLogEx(INFO, "Last IAD (9F10): %s", sprint_hex(iad->value, iad->len));
    }

    return PM3_SUCCESS;
}

int emv_term_crypto_challenge(emv_term_ctx_t *ctx, bool decode_tlv, bool store_9f4c) {
    if (!ctx) {
        return PM3_EINVARG;
    }

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    PrintAndLogEx(INFO, "--- GET CHALLENGE ---");
    int res = EMVGenerateChallenge(ctx->channel, true, buf, sizeof(buf), &len, &sw, ctx->card);
    if (res) {
        PrintAndLogEx(ERR, "GET CHALLENGE transport error (%d)", res);
        return res;
    }

    PrintAndLogEx(INFO, "SW: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
    if (sw != 0x9000 || len == 0) {
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Challenge [%zu]: %s", len, sprint_hex(buf, len));
    if (store_9f4c) {
        tlvdb_change_or_add_node(ctx->card, 0x9f4c, len, buf);
        PrintAndLogEx(INFO, "Stored as 9F4C for GEN AC");
    }
    if (decode_tlv) {
        TLVPrintFromBuffer(buf, len);
    }
    return PM3_SUCCESS;
}

static int crypto_genac_inner(emv_term_ctx_t *ctx, const emv_term_crypto_genac_opts_t *opts,
                              bool ac2, uint16_t *sw_out) {
    tlv_tag_t cdol_tag = ac2 ? 0x8d : 0x8c;
    const struct tlv *cdol_tlv = tlvdb_get(ctx->card, cdol_tag, NULL);
    if (!cdol_tlv || !cdol_tlv->len) {
        PrintAndLogEx(ERR, "CDOL%s (%04X) not found — run init first", ac2 ? "2" : "1", cdol_tag);
        return PM3_ESOFT;
    }

    if (!ac2 && opts->mc_challenge &&
            GetCardPSVendor((uint8_t *)ctx->aid, ctx->aid_len) == CV_MASTERCARD) {
        int cres = emv_term_crypto_challenge(ctx, ctx->opts.decode_tlv, true);
        if (cres) {
            PrintAndLogEx(WARNING, "MC GET CHALLENGE failed — continuing GEN AC");
        }
    }

    emv_term_crypto_apply_field_overrides(ctx, opts);

    struct tlv *cdol = dol_process(cdol_tlv, ctx->card, 0x01);
    if (!cdol) {
        PrintAndLogEx(ERR, "Cannot build CDOL data");
        return PM3_ESOFT;
    }

    uint8_t p1 = (uint8_t)opts->ac_type;
    if (opts->cda) {
        p1 |= EMVAC_CDAREQ;
    }

    PrintAndLogEx(INFO, "--- GENERATE AC (%s) P1=%02x ---", ac2 ? "CDOL2" : "CDOL1", p1);
    PrintAndLogEx(INFO, "CDOL data [%zu]: %s", cdol->len, sprint_hex(cdol->value, cdol->len));

    size_t cdol_len = cdol->len;
    uint8_t cdol_copy[256] = {0};
    if (cdol_len > sizeof(cdol_copy)) {
        free(cdol);
        PrintAndLogEx(ERR, "CDOL data too large");
        return PM3_ESOFT;
    }
    memcpy(cdol_copy, cdol->value, cdol_len);

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    int res = EMVAC(ctx->channel, true, p1, (uint8_t *)cdol->value, cdol->len,
                    buf, sizeof(buf), &len, &sw, ctx->card);
    free(cdol);

    if (sw_out) {
        *sw_out = sw;
    }

    if (res) {
        PrintAndLogEx(ERR, "GEN AC transport error (%d)", res);
        return res;
    }

    PrintAndLogEx(INFO, "SW: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
    if (sw != 0x9000) {
        return PM3_ESOFT;
    }

    if (ctx->opts.decode_tlv) {
        TLVPrintFromBuffer(buf, len);
    }

    emv_transaction_process_ac_format1(ctx->card, buf, len, ctx->opts.decode_tlv);

    const struct tlv *cid = tlvdb_get(ctx->card, 0x9f27, NULL);
    const struct tlv *atc = tlvdb_get(ctx->card, 0x9f36, NULL);
    const struct tlv *ac = tlvdb_get(ctx->card, 0x9f26, NULL);

    if (ac && ac->len) {
        PrintAndLogEx(SUCCESS, "AC (9F26): %s", sprint_hex(ac->value, ac->len));
    }
    if (atc && atc->len) {
        PrintAndLogEx(SUCCESS, "ATC (9F36): %s", sprint_hex(atc->value, atc->len));
    }
    if (cid && cid->len) {
        PrintAndLogEx(SUCCESS, "CID (9F27): %02x", cid->value[0]);
    }

    if (!ac2) {
        ctx->ac1_performed = true;
        if (cid && cid->len) {
            ctx->ac1_cid = cid->value[0];
        }
        if (cdol_len <= sizeof(ctx->cdol1_data)) {
            memcpy(ctx->cdol1_data, cdol_copy, cdol_len);
            ctx->cdol1_len = cdol_len;
        }
    } else {
        ctx->ac2_performed = true;
        if (cid && cid->len) {
            ctx->ac2_cid = cid->value[0];
        }
    }

    return PM3_SUCCESS;
}

int emv_term_crypto_genac(emv_term_ctx_t *ctx, const emv_term_crypto_genac_opts_t *opts, bool ac2) {
    if (!ctx || !opts) {
        return PM3_EINVARG;
    }
    return crypto_genac_inner(ctx, opts, ac2, NULL);
}

static void fill_run_entry(emv_term_crypto_run_entry_t *e, const emv_term_ctx_t *ctx, uint16_t sw) {
    if (!e) {
        return;
    }
    memset(e, 0, sizeof(*e));
    e->sw = sw;
    const struct tlv *un = emv_term_tlv_lookup(ctx, 0x9f37);
    if (un && un->len == 4) {
        memcpy(e->un, un->value, 4);
    }
    const struct tlv *ac = tlvdb_get(ctx->card, 0x9f26, NULL);
    if (ac && ac->len && ac->len <= sizeof(e->ac)) {
        memcpy(e->ac, ac->value, ac->len);
        e->ac_len = ac->len;
    }
    const struct tlv *atc = tlvdb_get(ctx->card, 0x9f36, NULL);
    if (atc && atc->len && atc->len <= sizeof(e->atc)) {
        memcpy(e->atc, atc->value, atc->len);
        e->atc_len = atc->len;
    }
}

int emv_term_crypto_vary_un(emv_term_ctx_t *ctx, const emv_term_crypto_genac_opts_t *opts,
                            int count, emv_term_crypto_run_entry_t *entries, size_t *entry_count) {
    if (!ctx || !opts || count < 1) {
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "=== Vary UN: %d GEN AC iteration(s) ===", count);
    size_t written = 0;

    for (int i = 0; i < count; i++) {
        emv_term_crypto_genac_opts_t iter = *opts;
        uint8_t un[4] = {0, 0, 0, (uint8_t)(i + 1)};
        if (opts->un_set) {
            memcpy(un, opts->un, 4);
            un[3] ^= (uint8_t)i;
        } else if (i > 0) {
            un[0] = (uint8_t)(rand() & 0xFF);
            un[1] = (uint8_t)(rand() & 0xFF);
            un[2] = (uint8_t)(rand() & 0xFF);
            un[3] = (uint8_t)(rand() & 0xFF);
        }
        iter.un_set = true;
        memcpy(iter.un, un, 4);

        PrintAndLogEx(INFO, "--- iteration %d/%d UN=%s ---", i + 1, count, sprint_hex(un, 4));

        uint16_t sw = 0;
        int res = crypto_genac_inner(ctx, &iter, false, &sw);
        if (entries && entry_count && written < *entry_count) {
            fill_run_entry(&entries[written], ctx, sw);
            written++;
        }
        if (res) {
            PrintAndLogEx(WARNING, "iteration %d failed (%d)", i + 1, res);
        }
    }

    if (entry_count) {
        *entry_count = written;
    }
    return PM3_SUCCESS;
}

int emv_term_crypto_intauth(emv_term_ctx_t *ctx, bool decode_tlv) {
    if (!ctx) {
        return PM3_EINVARG;
    }

    const struct tlv *aip = tlvdb_get(ctx->card, 0x82, NULL);
    if (!aip || aip->len < 1 || (aip->value[0] & 0x20) == 0) {
        PrintAndLogEx(WARNING, "Card AIP does not indicate DDA support");
    }

    const struct tlv *ddol = tlvdb_get(ctx->card, 0x9f49, NULL);
    static const unsigned char default_ddol[] = {0x9f, 0x37, 0x04};
    struct tlv default_ddol_tlv = {.tag = 0x9f49, .len = 3, .value = default_ddol};

    if (!ddol || !ddol->len) {
        ddol = &default_ddol_tlv;
        PrintAndLogEx(INFO, "Using default DDOL 9F37 04");
    }

    emv_term_crypto_randomize_un(ctx);

    struct tlv *ddol_data = dol_process(ddol, ctx->card, 0x01);
    if (!ddol_data) {
        PrintAndLogEx(ERR, "Cannot build DDOL data");
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "--- INTERNAL AUTHENTICATE ---");
    PrintAndLogEx(INFO, "DDOL data [%zu]: %s", ddol_data->len, sprint_hex(ddol_data->value, ddol_data->len));

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    int res = EMVInternalAuthenticate(ctx->channel, true, (uint8_t *)ddol_data->value, ddol_data->len,
                                      buf, sizeof(buf), &len, &sw, ctx->card);
    free(ddol_data);

    if (res) {
        PrintAndLogEx(ERR, "INTERNAL AUTHENTICATE transport error (%d)", res);
        return res;
    }

    PrintAndLogEx(INFO, "SW: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
    if (sw != 0x9000 || len == 0) {
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "DDA response [%zu]: %s", len, sprint_hex(buf, len));
    if (decode_tlv) {
        TLVPrintFromBuffer(buf, len);
    }
    return PM3_SUCCESS;
}

int emv_term_crypto_msc_checksum(emv_term_ctx_t *ctx, bool decode_tlv) {
    if (!ctx) {
        return PM3_EINVARG;
    }

    const struct tlv *udol = tlvdb_get(ctx->card, 0x9f6a, NULL);
    if (!udol || !udol->len) {
        PrintAndLogEx(INFO, "No UDOL (9F6A) — MSC checksum not applicable for this card");
        return PM3_SUCCESS;
    }

    struct tlv *udol_data = dol_process(udol, ctx->card, 0x01);
    if (!udol_data) {
        PrintAndLogEx(ERR, "Cannot build UDOL data");
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "--- COMPUTE CRYPTOGRAPHIC CHECKSUM (MSD) ---");

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    int res = MSCComputeCryptoChecksum(ctx->channel, true, (uint8_t *)udol_data->value,
                                       (uint8_t)udol_data->len, buf, sizeof(buf), &len, &sw, ctx->card);
    free(udol_data);

    if (res) {
        PrintAndLogEx(ERR, "MSC checksum transport error (%d)", res);
        return res;
    }

    PrintAndLogEx(INFO, "SW: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
    if (sw == 0x9000 && len) {
        PrintAndLogEx(SUCCESS, "Checksum [%zu]: %s", len, sprint_hex(buf, len));
        if (decode_tlv) {
            TLVPrintFromBuffer(buf, len);
        }
    }
    return (sw == 0x9000) ? PM3_SUCCESS : PM3_ESOFT;
}

static void json_add_tlv_hex(json_t *obj, const char *key, const struct tlv *tlv) {
    if (!obj || !tlv || !tlv->len) {
        return;
    }
    JsonSaveBufAsHexCompact(obj, key, (uint8_t *)tlv->value, tlv->len);
}

int emv_term_crypto_export_json(const emv_term_ctx_t *ctx, const char *path,
                                const emv_term_crypto_run_entry_t *entries, size_t entry_count) {
    if (!ctx || !path || !path[0]) {
        return PM3_EINVARG;
    }

    json_t *root = json_object();
    json_t *file = json_object();
    JsonSaveStr(file, "Created", "proxmark3 emv terminal crypto");
    JsonSaveStr(file, "Version", "1");
    json_object_set_new(root, "File", file);

    if (ctx->aid_len) {
        JsonSaveBufAsHexCompact(root, "AID", (uint8_t *)ctx->aid, ctx->aid_len);
    }

    json_add_tlv_hex(root, "AIP", tlvdb_get(ctx->card, 0x82, NULL));
    json_add_tlv_hex(root, "CDOL1", tlvdb_get(ctx->card, 0x8c, NULL));
    json_add_tlv_hex(root, "CDOL2", tlvdb_get(ctx->card, 0x8d, NULL));
    json_add_tlv_hex(root, "DDOL", tlvdb_get(ctx->card, 0x9f49, NULL));
    json_add_tlv_hex(root, "ATC", tlvdb_get(ctx->card, 0x9f36, NULL));
    json_add_tlv_hex(root, "AC", tlvdb_get(ctx->card, 0x9f26, NULL));
    json_add_tlv_hex(root, "CID", tlvdb_get(ctx->card, 0x9f27, NULL));
    json_add_tlv_hex(root, "IAD", tlvdb_get(ctx->card, 0x9f10, NULL));

    const struct tlv *un = emv_term_tlv_lookup(ctx, 0x9f37);
    json_add_tlv_hex(root, "UN", un);

    if (entries && entry_count) {
        json_t *runs = json_array();
        for (size_t i = 0; i < entry_count; i++) {
            json_t *r = json_object();
            JsonSaveBufAsHexCompact(r, "UN", (uint8_t *)entries[i].un, 4);
            if (entries[i].ac_len) {
                JsonSaveBufAsHexCompact(r, "AC", (uint8_t *)entries[i].ac, entries[i].ac_len);
            }
            if (entries[i].atc_len) {
                JsonSaveBufAsHexCompact(r, "ATC", (uint8_t *)entries[i].atc, entries[i].atc_len);
            }
            JsonSaveHex(r, "SW", entries[i].sw, 2);
            json_array_append_new(runs, r);
        }
        json_object_set_new(root, "Runs", runs);
    }

    int res = json_dump_file(root, path, JSON_INDENT(2));
    json_decref(root);

    if (res) {
        PrintAndLogEx(ERR, "Failed to write %s", path);
        return PM3_ESOFT;
    }
    PrintAndLogEx(SUCCESS, "Crypto export: %s", path);
    return PM3_SUCCESS;
}

int emv_term_crypto_bench(emv_term_ctx_t *ctx, const emv_term_crypto_bench_opts_t *opts,
                          const char *export_path) {
    if (!ctx || !opts) {
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "=== EMV crypto playground bench ===");
    emv_term_crypto_print_summary(ctx);

    emv_term_crypto_run_entry_t entries[32] = {0};
    size_t entry_count = 0;

    if (opts->do_challenge) {
        emv_term_crypto_challenge(ctx, ctx->opts.decode_tlv, opts->genac.mc_challenge);
    }

    if (opts->do_genac) {
        uint16_t sw = 0;
        int res = crypto_genac_inner(ctx, &opts->genac, false, &sw);
        if (entry_count < ARRAYLEN(entries)) {
            fill_run_entry(&entries[entry_count], ctx, sw);
            entry_count++;
        }
        if (res) {
            PrintAndLogEx(WARNING, "GEN AC failed in bench (%d)", res);
        }
    }

    if (opts->do_intauth) {
        emv_term_crypto_intauth(ctx, ctx->opts.decode_tlv);
    }

    if (opts->do_checksum) {
        emv_term_crypto_msc_checksum(ctx, ctx->opts.decode_tlv);
    }

    if (opts->do_vary && opts->vary_count > 0) {
        size_t cap = ARRAYLEN(entries) - entry_count;
        emv_term_crypto_vary_un(ctx, &opts->genac, opts->vary_count,
                                entries + entry_count, &cap);
        entry_count += cap;
    }

    emv_term_crypto_print_summary(ctx);

    if (export_path && export_path[0]) {
        emv_term_crypto_export_json(ctx, export_path, entries, entry_count);
    }

    return PM3_SUCCESS;
}
