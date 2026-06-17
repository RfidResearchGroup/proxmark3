//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// EMV terminal emulator — crypto playground
//-----------------------------------------------------------------------------

#include "emv_term_crypto.h"
#include "emv_term_crypto_digest.h"
#include "emv_term_tlv.h"
#include "emv_term_tvr.h"
#include "emv_transaction.h"
#include "../dol.h"
#include "../emv_tags.h"
#include "emv_term_profile.h"
#include "emv_term_session.h"
#include "../emvcore.h"
#include "../emvjson.h"
#include "crypto/libpcrypto.h"
#include "ui.h"
#include "commonutil.h"
#include "protocols.h"
#include "util.h"
#include "util_posix.h"
#include <jansson.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
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

static uint16_t crypto_card_aip(const emv_term_ctx_t *ctx) {
    const struct tlv *aip = tlvdb_get(ctx->card, 0x82, NULL);
    if (!aip || aip->len < 2) {
        return 0;
    }
    return (uint16_t)(aip->value[0] | (aip->value[1] << 8));
}

static bool crypto_card_supports_cda(const emv_term_ctx_t *ctx) {
    return (crypto_card_aip(ctx) & 0x0001) != 0;
}

static const struct tlv *crypto_card_tlv(const emv_term_ctx_t *ctx, tlv_tag_t tag) {
    if (!ctx || !ctx->card) {
        return NULL;
    }
    struct tlvdb *db = tlvdb_find_full(ctx->card, tag);
    return db ? tlvdb_get_tlv(db) : NULL;
}

static bool crypto_is_visa_qvsdc(const emv_term_ctx_t *ctx) {
    if (!ctx || !ctx->aid_len) {
        return false;
    }
    if (GetCardPSVendor((uint8_t *)ctx->aid, ctx->aid_len) != CV_VISA) {
        return false;
    }
    const struct tlv *cdol1 = tlvdb_get(ctx->card, 0x8c, NULL);
    if (cdol1 && cdol1->len) {
        return false;
    }
    return crypto_card_aip(ctx) == 0x8000;
}

static bool crypto_is_qvsdc_gpo_ac(const emv_term_ctx_t *ctx) {
    const struct tlv *ac = crypto_card_tlv(ctx, 0x9f26);
    if (!ac || !ac->len) {
        return false;
    }
    const struct tlv *cdol1 = tlvdb_get(ctx->card, 0x8c, NULL);
    return !cdol1 || !cdol1->len;
}

static void crypto_apply_genac_defaults(emv_term_ctx_t *ctx, emv_term_crypto_genac_opts_t *opts) {
    if (!ctx || !opts || opts->cda) {
        return;
    }
    if (crypto_card_supports_cda(ctx) &&
            GetCardPSVendor((uint8_t *)ctx->aid, ctx->aid_len) == CV_MASTERCARD) {
        opts->cda = true;
    }
}

static void crypto_print_sw_hint(uint16_t sw) {
    if (sw == 0x6985) {
        PrintAndLogEx(WARNING, "Card declined GEN AC (6985) — one cryptogram per tap; re-tap for another sample, or try `--decision tc`");
    } else if (sw == 0x6a86) {
        PrintAndLogEx(WARNING, "GEN AC bad P1/P2 (6A86) — card rejected repeat AC in this session; re-tap for another sample");
    } else if (sw == 0x6700) {
        PrintAndLogEx(WARNING, "GEN AC wrong length (6700) — check CDOL1 field sizes (9F7C/9F21/9F03) and terminal profile");
    }
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

    const struct tlv *cid = crypto_card_tlv(ctx, 0x9f27);
    const struct tlv *atc = crypto_card_tlv(ctx, 0x9f36);
    const struct tlv *ac = crypto_card_tlv(ctx, 0x9f26);
    const struct tlv *iad = crypto_card_tlv(ctx, 0x9f10);

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
        if (!ac2 && crypto_is_visa_qvsdc(ctx)) {
            int gres = emv_transaction_visa_request_gpo_ac(ctx);
            if (!gres && crypto_is_qvsdc_gpo_ac(ctx)) {
                PrintAndLogEx(INFO, "qVSDC: AC obtained from GPO — no GEN AC needed");
                emv_term_crypto_print_summary(ctx);
                return PM3_SUCCESS;
            }
            PrintAndLogEx(INFO, "qVSDC: no CDOL1 — GEN AC not used; see summary for GPO/AFL data");
            emv_term_crypto_print_summary(ctx);
            return PM3_SUCCESS;
        }
        if (!ac2 && crypto_is_qvsdc_gpo_ac(ctx)) {
            PrintAndLogEx(INFO, "No CDOL1 — qVSDC card (cryptogram returned in GPO, not GEN AC)");
            emv_term_crypto_print_summary(ctx);
            return PM3_SUCCESS;
        }
        PrintAndLogEx(ERR, "CDOL%s (%04X) not found — run init first", ac2 ? "2" : "1", cdol_tag);
        if (!ac2 && crypto_card_aip(ctx) == 0x8000) {
            PrintAndLogEx(WARNING, "Visa qVSDC (AIP 8000) typically has no CDOL1 — AC is in GPO response");
        }
        return PM3_ESOFT;
    }

    emv_term_crypto_genac_opts_t genac = *opts;
    crypto_apply_genac_defaults(ctx, &genac);

    if (!ac2 && genac.mc_challenge &&
            GetCardPSVendor((uint8_t *)ctx->aid, ctx->aid_len) == CV_MASTERCARD) {
        int cres = emv_term_crypto_challenge(ctx, ctx->opts.decode_tlv, true);
        if (cres) {
            PrintAndLogEx(WARNING, "MC GET CHALLENGE failed — continuing GEN AC");
        }
    }

    emv_term_crypto_apply_field_overrides(ctx, &genac);
    emv_term_copy_terminal_tags_to_card(ctx);

    struct tlv *cdol = dol_process(cdol_tlv, ctx->card, 0x01);
    if (!cdol) {
        PrintAndLogEx(ERR, "Cannot build CDOL data");
        return PM3_ESOFT;
    }

    uint8_t p1 = (uint8_t)genac.ac_type;
    if (genac.cda) {
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
        crypto_print_sw_hint(sw);
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

#define CRYPTO_RNG_POOL_MAX 1024

static void crypto_rng_pool_append(uint8_t *pool, size_t *pool_len, size_t pool_max,
                                   uint8_t tag, const uint8_t *data, size_t len) {
    if (!pool || !pool_len || !data || !len || *pool_len + 2 + len > pool_max) {
        return;
    }
    pool[(*pool_len)++] = tag;
    pool[(*pool_len)++] = (uint8_t)(len > 255 ? 255 : len);
    size_t copy = len > 255 ? 255 : len;
    memcpy(pool + *pool_len, data, copy);
    *pool_len += copy;
}

static void crypto_rng_pool_append_tlv(uint8_t *pool, size_t *pool_len, size_t pool_max,
                                       uint8_t tag, const struct tlv *tlv) {
    if (!tlv || !tlv->len) {
        return;
    }
    crypto_rng_pool_append(pool, pool_len, pool_max, tag, tlv->value, tlv->len);
}

static bool crypto_rng_collect_weak(emv_term_ctx_t *ctx, uint8_t *pool, size_t *pool_len, size_t pool_max) {
    bool got = false;
    const struct tlv *un = emv_term_tlv_lookup(ctx, 0x9f37);
    const struct tlv *t2 = tlvdb_get(ctx->card, 0x57, NULL);
    const struct tlv *afl = tlvdb_get(ctx->card, 0x94, NULL);
    if (un && un->len) {
        crypto_rng_pool_append_tlv(pool, pool_len, pool_max, 0x37, un);
        got = true;
    }
    if (t2 && t2->len) {
        crypto_rng_pool_append_tlv(pool, pool_len, pool_max, 0x57, t2);
        got = true;
    }
    if (afl && afl->len) {
        crypto_rng_pool_append_tlv(pool, pool_len, pool_max, 0x94, afl);
        got = true;
    }
    return got;
}

static void crypto_rng_stream_write(const uint8_t *data, size_t len, emv_term_crypto_stream_fmt_t fmt) {
    if (!data || !len || fmt == EMV_CRYPTO_STREAM_OFF) {
        return;
    }
    if (fmt == EMV_CRYPTO_STREAM_HEX) {
        static const char hex[] = "0123456789abcdef";
        for (size_t i = 0; i < len; i++) {
            fputc(hex[data[i] >> 4], stdout);
            fputc(hex[data[i] & 0x0f], stdout);
        }
    } else {
        fwrite(data, 1, len, stdout);
    }
    fflush(stdout);
}

static uint64_t crypto_rng_u64_from_hash(const uint8_t hash[32]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | hash[i];
    }
    return v;
}

static void crypto_rng_clear_cryptogram(emv_term_ctx_t *ctx) {
    static const tlv_tag_t tags[] = {0x9f26, 0x9f27, 0x9f36, 0x9f10};
    static const uint8_t empty = 0;
    for (size_t i = 0; i < ARRAYLEN(tags); i++) {
        tlvdb_change_or_add_node(ctx->card, tags[i], 0, &empty);
    }
}

static bool crypto_rng_tlv_same(const struct tlv *tlv, const uint8_t *prev, size_t prev_len) {
    return tlv && tlv->len && prev_len && tlv->len == prev_len &&
           memcmp(tlv->value, prev, prev_len) == 0;
}

static void crypto_rng_log_sample(int idx, int total, const struct tlv *ac, const struct tlv *atc,
                                  uint16_t sw, bool accepted) {
    char ac_hex[32] = "-";
    char atc_hex[16] = "-";
    if (ac && ac->len) {
        snprintf(ac_hex, sizeof(ac_hex), "%s", sprint_hex(ac->value, ac->len));
    }
    if (atc && atc->len) {
        snprintf(atc_hex, sizeof(atc_hex), "%s", sprint_hex(atc->value, atc->len));
    }
    if (accepted) {
        PrintAndLogEx(INFO, "  sample %d/%d: AC=%s ATC=%s", idx, total, ac_hex, atc_hex);
    } else if (sw != 0x9000) {
        PrintAndLogEx(WARNING, "  sample %d/%d: declined (sw=%04X)", idx, total, sw);
    } else if (!ac || !ac->len) {
        PrintAndLogEx(WARNING, "  sample %d/%d: no AC (sw=%04X)", idx, total, sw);
    } else {
        PrintAndLogEx(WARNING, "  sample %d/%d: duplicate AC/ATC (re-tap for a fresh cryptogram)", idx, total);
    }
}

static bool crypto_rng_append_sample(emv_term_ctx_t *ctx, uint8_t *pool, size_t *pool_len, size_t pool_max,
                                   uint8_t sample_idx) {
    const struct tlv *ac = crypto_card_tlv(ctx, 0x9f26);
    const struct tlv *atc = crypto_card_tlv(ctx, 0x9f36);
    if (!ac || !ac->len) {
        return false;
    }
    crypto_rng_pool_append(pool, pool_len, pool_max, 0xFF, &sample_idx, 1);
    crypto_rng_pool_append_tlv(pool, pool_len, pool_max, 0x37, emv_term_tlv_lookup(ctx, 0x9f37));
    crypto_rng_pool_append_tlv(pool, pool_len, pool_max, 0x26, ac);
    crypto_rng_pool_append_tlv(pool, pool_len, pool_max, 0x36, atc);
    crypto_rng_pool_append_tlv(pool, pool_len, pool_max, 0x27, tlvdb_get(ctx->card, 0x9f27, NULL));
    crypto_rng_pool_append_tlv(pool, pool_len, pool_max, 0x10, tlvdb_get(ctx->card, 0x9f10, NULL));
    crypto_rng_pool_append_tlv(pool, pool_len, pool_max, 0x4c, tlvdb_get(ctx->card, 0x9f4c, NULL));
    return true;
}

int emv_term_crypto_rng(emv_term_ctx_t *ctx, const emv_term_crypto_rng_opts_t *opts) {
    if (!ctx || !opts) {
        return PM3_EINVARG;
    }

    int samples = opts->samples > 0 ? opts->samples : 1;
    int out_bytes = opts->out_bytes > 0 ? opts->out_bytes : 8;
    if (out_bytes > 32) {
        out_bytes = 32;
    }

    uint8_t pool[CRYPTO_RNG_POOL_MAX] = {0};
    size_t pool_len = 0;
    bool weak = false;
    unsigned got_samples = 0;
    unsigned attempted = 0;

    bool has_cdol = tlvdb_get(ctx->card, 0x8c, NULL) != NULL;
    bool can_query = has_cdol || crypto_is_visa_qvsdc(ctx) || crypto_is_qvsdc_gpo_ac(ctx);

    if (opts->stream_fmt == EMV_CRYPTO_STREAM_OFF && !opts->quiet) {
        PrintAndLogEx(INFO, "=== EMV card RNG (lab toy — not a certified TRNG) ===");
    }

    if (can_query) {
        emv_term_crypto_genac_opts_t genac = opts->genac;
        if (!opts->quiet) {
            if (samples == 1) {
                PrintAndLogEx(INFO, "Collecting 1 card sample (AC/ATC/UN/IAD)...");
            } else {
                PrintAndLogEx(INFO, "Collecting up to %d card sample(s) (AC/ATC/UN/IAD)...", samples);
                PrintAndLogEx(HINT, "Most cards allow one GEN AC per tap — re-tap between samples if declined");
            }
        }

        uint8_t prev_ac[8] = {0};
        size_t prev_ac_len = 0;
        uint8_t prev_atc[2] = {0};
        size_t prev_atc_len = 0;

        for (int i = 0; i < samples; i++) {
            attempted++;
            crypto_rng_clear_cryptogram(ctx);

            emv_term_crypto_genac_opts_t iter = genac;
            if (!iter.un_set) {
                emv_term_crypto_randomize_un(ctx);
            }
            uint16_t sw = 0;
            int res = PM3_SUCCESS;
            if (!has_cdol && crypto_is_visa_qvsdc(ctx)) {
                emv_term_copy_terminal_tags_to_card(ctx);
                res = emv_transaction_visa_request_gpo_ac(ctx);
                sw = (res == PM3_SUCCESS) ? 0x9000 : 0x0000;
            } else {
                res = crypto_genac_inner(ctx, &iter, false, &sw);
            }
            (void)res;

            const struct tlv *ac = crypto_card_tlv(ctx, 0x9f26);
            const struct tlv *atc = crypto_card_tlv(ctx, 0x9f36);
            bool fresh = sw == 0x9000 && ac && ac->len &&
                         !crypto_rng_tlv_same(ac, prev_ac, prev_ac_len) &&
                         !(atc && crypto_rng_tlv_same(atc, prev_atc, prev_atc_len) && prev_ac_len);

            if (fresh && crypto_rng_append_sample(ctx, pool, &pool_len, sizeof(pool), (uint8_t)got_samples)) {
                if (ac->len <= sizeof(prev_ac)) {
                    memcpy(prev_ac, ac->value, ac->len);
                    prev_ac_len = ac->len;
                }
                if (atc && atc->len && atc->len <= sizeof(prev_atc)) {
                    memcpy(prev_atc, atc->value, atc->len);
                    prev_atc_len = atc->len;
                }
                got_samples++;
                if (!opts->quiet) {
                    crypto_rng_log_sample(i + 1, samples, ac, atc, sw, true);
                }
            } else if (!opts->quiet) {
                crypto_rng_log_sample(i + 1, samples, ac, atc, sw, false);
            }
        }
    }

    if (!got_samples) {
        weak = true;
        PrintAndLogEx(WARNING, "No AC from card — using weak MSD/GPO entropy (UN/track2/AFL)");
        emv_term_crypto_randomize_un(ctx);
        if (!crypto_rng_collect_weak(ctx, pool, &pool_len, sizeof(pool))) {
            PrintAndLogEx(ERR, "Card exposes no usable entropy — try MC/Interac with CDOL1");
            return PM3_ESOFT;
        }
        got_samples = 1;
    }

    uint8_t hash[32] = {0};
    sha256hash(pool, (int)pool_len, hash);

    switch (opts->mode) {
        case EMV_CRYPTO_RNG_RAW:
            if (opts->no_emit) {
                break;
            }
            if (opts->stream_fmt == EMV_CRYPTO_STREAM_HEX) {
                crypto_rng_stream_write(hash, (size_t)out_bytes, EMV_CRYPTO_STREAM_HEX);
            } else if (opts->stream_fmt == EMV_CRYPTO_STREAM_RAW) {
                crypto_rng_stream_write(hash, (size_t)out_bytes, EMV_CRYPTO_STREAM_RAW);
            } else {
                PrintAndLogEx(SUCCESS, "Card entropy [%d bytes]: %s",
                              out_bytes, sprint_hex(hash, (size_t)out_bytes));
            }
            break;
        case EMV_CRYPTO_RNG_DICE: {
            uint32_t roll = (uint32_t)((crypto_rng_u64_from_hash(hash) % 6) + 1);
            PrintAndLogEx(SUCCESS, "Card d6: %u", roll);
            break;
        }
        case EMV_CRYPTO_RNG_COIN: {
            bool heads = (hash[0] & 1) == 0;
            PrintAndLogEx(SUCCESS, "Card coin: %s", heads ? "heads" : "tails");
            break;
        }
        case EMV_CRYPTO_RNG_RANGE: {
            if (opts->range_max < 2) {
                return PM3_EINVARG;
            }
            uint64_t n = crypto_rng_u64_from_hash(hash) % opts->range_max;
            PrintAndLogEx(SUCCESS, "Card number [0..%" PRIu64 "]: %" PRIu64,
                          opts->range_max - 1, n);
            break;
        }
    }

    if (!opts->quiet && opts->stream_fmt == EMV_CRYPTO_STREAM_OFF) {
        if (attempted > got_samples && got_samples > 0) {
            PrintAndLogEx(INFO, "Mixed %u fresh sample(s) of %u attempt(s), pool %zu bytes, sha256 → %s%s",
                          got_samples, attempted, pool_len, sprint_hex(hash, 8), weak ? " (weak)" : "");
        } else {
            PrintAndLogEx(INFO, "Mixed %u sample(s), pool %zu bytes, sha256 → %s%s",
                          got_samples, pool_len, sprint_hex(hash, 8), weak ? " (weak)" : "");
        }
    }
    if (opts->stream_fmt == EMV_CRYPTO_STREAM_OFF) {
        PrintAndLogEx(HINT, "Re-tap the card for a new value — most cards issue one AC per session");
    }
    return PM3_SUCCESS;
}

typedef struct {
    int res;
    bool rng_ok;
    bool used_fast_init;
} crypto_rng_cycle_info_t;

static void json_add_tlv_hex(json_t *obj, const char *key, const struct tlv *tlv);

static const char *crypto_rng_vendor_label(const emv_term_ctx_t *ctx) {
    if (!ctx || !ctx->aid_len) {
        return "unknown";
    }
    switch (GetCardPSVendor((uint8_t *)ctx->aid, ctx->aid_len)) {
        case CV_NA: return "unknown";
        case CV_VISA: return "Visa";
        case CV_MASTERCARD: return "Mastercard";
        case CV_INTERAC: return "Interac";
        case CV_AMERICANEXPRESS: return "Amex";
        case CV_JCB: return "JCB";
        case CV_CB: return "CB";
        case CV_DINERS: return "Diners";
        case CV_SWITCH: return "Switch";
        case CV_OTHER: return "other";
    }
    return "other";
}

static const char *crypto_rng_path_label(const emv_term_ctx_t *ctx) {
    if (!ctx || !ctx->aid_len) {
        return "unknown";
    }
    if (crypto_card_tlv(ctx, 0x9f26) && !tlvdb_get(ctx->card, 0x8c, NULL)) {
        return "qVSDC (AC in GPO)";
    }
    if (tlvdb_get(ctx->card, 0x8c, NULL)) {
        if (GetCardPSVendor((uint8_t *)ctx->aid, ctx->aid_len) == CV_MASTERCARD) {
            return "M/Chip contactless (CDOL1 + GET CHALLENGE)";
        }
        return "EMV contactless (CDOL1 GEN AC)";
    }
    if (crypto_card_aip(ctx) == 0x8000) {
        return "Visa qVSDC MSD";
    }
    return "unknown / MSD";
}

static int crypto_rng_app_label(const emv_term_ctx_t *ctx, char *out, size_t outlen) {
    if (!out || !outlen) {
        return PM3_EINVARG;
    }
    out[0] = '\0';
    const struct tlv *label = tlvdb_get(ctx->card, 0x50, NULL);
    if (!label || !label->len) {
        label = tlvdb_get(ctx->card, 0x9f12, NULL);
    }
    if (!label || !label->len) {
        return PM3_ESOFT;
    }
    size_t n = label->len < outlen - 1 ? label->len : outlen - 1;
    memcpy(out, label->value, n);
    out[n] = '\0';
    return PM3_SUCCESS;
}

static int crypto_rng_pan_last4(const emv_term_ctx_t *ctx, char *out, size_t outlen) {
    if (!out || outlen < 5) {
        return PM3_EINVARG;
    }
    out[0] = '\0';
    const struct tlv *t2 = tlvdb_get(ctx->card, 0x57, NULL);
    if (!t2 || t2->len < 8) {
        return PM3_ESOFT;
    }
    char digits[32] = {0};
    size_t di = 0;
    for (size_t i = 0; i < t2->len && di + 1 < sizeof(digits); i++) {
        uint8_t hi = (t2->value[i] >> 4) & 0x0f;
        uint8_t lo = t2->value[i] & 0x0f;
        if (hi <= 9) {
            digits[di++] = (char)('0' + hi);
        }
        if (lo <= 9) {
            digits[di++] = (char)('0' + lo);
        } else if (lo == 0x0f) {
            break;
        }
    }
    if (di < 4) {
        return PM3_ESOFT;
    }
    snprintf(out, outlen, "%.4s", digits + di - 4);
    return PM3_SUCCESS;
}

static int crypto_rng_cycle(emv_term_ctx_t *ctx, const emv_term_crypto_rng_opts_t *opts,
                            Iso7816CommandChannel channel, emv_term_crypto_prepare_opts_t *prep,
                            bool *have_session, uint32_t poll_ms, crypto_rng_cycle_info_t *info) {
    if (info) {
        memset(info, 0, sizeof(*info));
    }

    int res = PM3_SUCCESS;
    if (channel == CC_CONTACTLESS) {
        res = EMVContactlessReselect(channel, poll_ms);
    }
    if (res == PM3_SUCCESS) {
        ctx->opts.activate_field = false;
        bool used_fast = false;
        if (have_session && *have_session) {
            res = emv_transaction_crypto_fast_init(ctx);
            if (res) {
                if (have_session) {
                    *have_session = false;
                }
                ctx->crypto_stream_profile_valid = false;
            } else {
                used_fast = true;
            }
        }
        if (have_session && !*have_session) {
            res = emv_term_crypto_prepare_card(ctx, ctx->opts.param_load_json, NULL, prep);
            if (res == PM3_SUCCESS && ctx->aid_len) {
                *have_session = true;
                emv_transaction_stream_cache_update(ctx);
            }
        }
        if (info) {
            info->used_fast_init = used_fast && res == PM3_SUCCESS;
        }
    }

    if (res == PM3_SUCCESS) {
        res = emv_term_crypto_rng(ctx, opts);
        if (info) {
            info->rng_ok = res == PM3_SUCCESS;
        }
        if (res != PM3_SUCCESS) {
            ctx->crypto_stream_profile_valid = false;
        } else {
            emv_transaction_stream_cache_update(ctx);
        }
    }

    if (info) {
        info->res = res;
    }
    return res;
}

static int crypto_rng_latency_cmp(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    if (va < vb) {
        return -1;
    }
    if (va > vb) {
        return 1;
    }
    return 0;
}

static uint64_t crypto_rng_percentile(uint64_t *samples, size_t count, unsigned pct) {
    if (!samples || !count) {
        return 0;
    }
    qsort(samples, count, sizeof(samples[0]), crypto_rng_latency_cmp);
    size_t idx = (count * pct) / 100;
    if (idx >= count) {
        idx = count - 1;
    }
    return samples[idx];
}

int emv_term_crypto_rng_stream(emv_term_ctx_t *ctx, const emv_term_crypto_rng_opts_t *opts,
                               Iso7816CommandChannel channel) {
    if (!ctx || !opts) {
        return PM3_EINVARG;
    }
    if (opts->stream_fmt == EMV_CRYPTO_STREAM_OFF) {
        return PM3_EINVARG;
    }

    emv_term_crypto_rng_opts_t ropts = *opts;
    ropts.quiet = true;
    ropts.samples = 1;
    ropts.mode = EMV_CRYPTO_RNG_RAW;
    if (ropts.stream_fmt == EMV_CRYPTO_STREAM_OFF) {
        ropts.stream_fmt = EMV_CRYPTO_STREAM_HEX;
    }

    ctx->opts.crypto_quick_afl = true;
    ctx->opts.crypto_stream_fast = true;

    char forced_aid_hex[sizeof(ctx->opts.crypto_forced_aid) * 2 + 1] = {0};
    const char *forced_ptr = NULL;
    if (ctx->opts.crypto_forced_aid_len) {
        snprintf(forced_aid_hex, sizeof(forced_aid_hex), "%s",
                 sprint_hex_inrow(ctx->opts.crypto_forced_aid, ctx->opts.crypto_forced_aid_len));
        forced_ptr = forced_aid_hex;
    }

    emv_term_crypto_prepare_opts_t prep = {
        .quick_afl = true,
        .aid_fallback = ctx->opts.crypto_aid_fallback,
        .forced_aid_hex = forced_ptr,
    };

    bool have_session = false;
    uint8_t saved_log = g_printAndLog;
    uint32_t poll_ms = 0;

    while (true) {
        if (kbd_enter_pressed()) {
            break;
        }

        g_printAndLog = 0;

        crypto_rng_cycle(ctx, &ropts, channel, &prep, &have_session, poll_ms, NULL);

        g_printAndLog = saved_log;
    }

    return PM3_SUCCESS;
}

int emv_term_crypto_rng_bench(emv_term_ctx_t *ctx, const emv_term_crypto_rng_bench_opts_t *opts,
                              Iso7816CommandChannel channel,
                              emv_term_crypto_rng_bench_result_t *result_out) {
    if (!ctx || !opts || !result_out) {
        return PM3_EINVARG;
    }

    uint32_t duration_sec = opts->duration_sec ? opts->duration_sec : 30;
    int out_bytes = opts->out_bytes > 0 ? opts->out_bytes : 8;
    if (out_bytes > 32) {
        out_bytes = 32;
    }

    emv_term_crypto_rng_opts_t ropts = {0};
    ropts.samples = 1;
    ropts.out_bytes = out_bytes;
    ropts.quiet = true;
    ropts.no_emit = true;
    ropts.mode = EMV_CRYPTO_RNG_RAW;
    ropts.stream_fmt = EMV_CRYPTO_STREAM_OFF;
    ropts.genac = opts->genac;

    ctx->opts.crypto_quick_afl = true;
    ctx->opts.crypto_stream_fast = true;

    char forced_aid_hex[sizeof(ctx->opts.crypto_forced_aid) * 2 + 1] = {0};
    const char *forced_ptr = NULL;
    if (ctx->opts.crypto_forced_aid_len) {
        snprintf(forced_aid_hex, sizeof(forced_aid_hex), "%s",
                 sprint_hex_inrow(ctx->opts.crypto_forced_aid, ctx->opts.crypto_forced_aid_len));
        forced_ptr = forced_aid_hex;
    }

    emv_term_crypto_prepare_opts_t prep = {
        .quick_afl = true,
        .aid_fallback = ctx->opts.crypto_aid_fallback,
        .forced_aid_hex = forced_ptr,
    };

    memset(result_out, 0, sizeof(*result_out));

    bool have_session = false;
    uint32_t poll_ms = 0;
    uint64_t bench_start = msclock();
    uint64_t bench_end = bench_start + (uint64_t)duration_sec * 1000;
    uint64_t next_progress = bench_start + 5000;
    uint64_t latency_sum = 0;
    uint64_t *latencies = NULL;
    size_t latency_cap = 0;
    size_t latency_count = 0;

    PrintAndLogEx(INFO, "=== EMV card RNG speed bench (%u s) ===", duration_sec);
    PrintAndLogEx(INFO, "Hold the card on the antenna — Enter to stop early");

    while (msclock() < bench_end) {
        if (kbd_enter_pressed()) {
            break;
        }

        uint64_t cycle_start = msclock();
        crypto_rng_cycle_info_t cycle = {0};
        crypto_rng_cycle(ctx, &ropts, channel, &prep, &have_session, poll_ms, &cycle);
        uint64_t cycle_ms = msclock() - cycle_start;

        result_out->cycles_total++;
        if (cycle.rng_ok) {
            result_out->cycles_ok++;
            latency_sum += cycle_ms;
            if (latency_count == latency_cap) {
                size_t new_cap = latency_cap ? latency_cap * 2 : 64;
                uint64_t *tmp = realloc(latencies, new_cap * sizeof(*latencies));
                if (!tmp) {
                    free(latencies);
                    latencies = NULL;
                    PrintAndLogEx(ERR, "Out of memory recording bench latencies");
                    return PM3_ESOFT;
                }
                latencies = tmp;
                latency_cap = new_cap;
            }
            latencies[latency_count++] = cycle_ms;

            if (result_out->cycles_ok == 1 || cycle_ms < result_out->cycle_ms_min) {
                result_out->cycle_ms_min = cycle_ms;
            }
            if (cycle_ms > result_out->cycle_ms_max) {
                result_out->cycle_ms_max = cycle_ms;
            }

            if (cycle.used_fast_init) {
                result_out->fast_init_cycles++;
            } else {
                result_out->full_init_cycles++;
            }
        } else {
            result_out->cycles_fail++;
        }

        uint64_t now = msclock();
        if (now >= next_progress) {
            double elapsed_s = (double)(now - bench_start) / 1000.0;
            double bps = elapsed_s > 0 ? (double)result_out->cycles_ok / elapsed_s : 0.0;
            PrintAndLogEx(INFO, "  %.1f s — %.2f blocks/s (%u ok, %u fail)",
                          elapsed_s, bps, result_out->cycles_ok, result_out->cycles_fail);
            next_progress = now + 5000;
        }
    }

    result_out->elapsed_ms = msclock() - bench_start;
    double elapsed_s = (double)result_out->elapsed_ms / 1000.0;
    if (elapsed_s > 0) {
        result_out->blocks_per_sec = (double)result_out->cycles_ok / elapsed_s;
        result_out->bytes_per_sec = result_out->blocks_per_sec * (double)out_bytes;
    }
    if (result_out->cycles_ok) {
        result_out->cycle_ms_avg = latency_sum / result_out->cycles_ok;
        result_out->cycle_ms_p50 = crypto_rng_percentile(latencies, latency_count, 50);
        result_out->cycle_ms_p95 = crypto_rng_percentile(latencies, latency_count, 95);
    }
    free(latencies);

    PrintAndLogEx(INFO, "--- bench result (%.1f s) ---", elapsed_s);
    if (ctx->aid_len) {
        PrintAndLogEx(INFO, "Card: %s — AID %s",
                      crypto_rng_vendor_label(ctx), sprint_hex_inrow(ctx->aid, ctx->aid_len));
    }
    PrintAndLogEx(INFO, "Path: %s  AIP=%04x", crypto_rng_path_label(ctx), crypto_card_aip(ctx));

    char app_label[64] = {0};
    if (crypto_rng_app_label(ctx, app_label, sizeof(app_label)) == PM3_SUCCESS) {
        PrintAndLogEx(INFO, "Application label: %s", app_label);
    }

    char pan_last4[8] = {0};
    if (crypto_rng_pan_last4(ctx, pan_last4, sizeof(pan_last4)) == PM3_SUCCESS) {
        PrintAndLogEx(INFO, "PAN last 4: %s (from track2)", pan_last4);
    }

    if (result_out->cycles_total) {
        double success_pct = 100.0 * (double)result_out->cycles_ok / (double)result_out->cycles_total;
        PrintAndLogEx(INFO, "Cycles: %u ok / %u fail (%.1f%% success)",
                      result_out->cycles_ok, result_out->cycles_fail, success_pct);
    } else {
        PrintAndLogEx(WARNING, "No cycles completed — was the card on the antenna?");
    }

    PrintAndLogEx(INFO, "Throughput: %.2f blocks/s  %.1f bytes/s (%d bytes/block)",
                  result_out->blocks_per_sec, result_out->bytes_per_sec, out_bytes);

    if (result_out->cycles_ok) {
        PrintAndLogEx(INFO, "Latency (ok cycles): min %" PRIu64 " ms  avg %" PRIu64 " ms  "
                      "p50 %" PRIu64 " ms  p95 %" PRIu64 " ms  max %" PRIu64 " ms",
                      result_out->cycle_ms_min, result_out->cycle_ms_avg,
                      result_out->cycle_ms_p50, result_out->cycle_ms_p95, result_out->cycle_ms_max);
    }

    PrintAndLogEx(INFO, "Init mix: %u full  %u fast",
                  result_out->full_init_cycles, result_out->fast_init_cycles);
    PrintAndLogEx(HINT, "Lab timing only — compare cards with `-o bench.json` for spreadsheets");

    return PM3_SUCCESS;
}

int emv_term_crypto_rng_bench_export_json(const emv_term_ctx_t *ctx,
                                          const emv_term_crypto_rng_bench_result_t *result,
                                          const char *path) {
    if (!ctx || !result || !path || !path[0]) {
        return PM3_EINVARG;
    }

    json_t *root = json_object();
    json_t *file = json_object();
    JsonSaveStr(file, "Created", "proxmark3 emv terminal crypto rng bench");
    JsonSaveStr(file, "Version", "1");
    json_object_set_new(root, "File", file);

    json_t *card = json_object();
    if (ctx->aid_len) {
        JsonSaveBufAsHexCompact(card, "AID", (uint8_t *)ctx->aid, ctx->aid_len);
        JsonSaveStr(card, "Vendor", crypto_rng_vendor_label(ctx));
    }
    JsonSaveStr(card, "CryptoPath", crypto_rng_path_label(ctx));
    JsonSaveHex(card, "AIP", crypto_card_aip(ctx), 2);
    json_add_tlv_hex(card, "ATC", tlvdb_get(ctx->card, 0x9f36, NULL));

    char app_label[64] = {0};
    if (crypto_rng_app_label(ctx, app_label, sizeof(app_label)) == PM3_SUCCESS) {
        JsonSaveStr(card, "ApplicationLabel", app_label);
    }
    char pan_last4[8] = {0};
    if (crypto_rng_pan_last4(ctx, pan_last4, sizeof(pan_last4)) == PM3_SUCCESS) {
        JsonSaveStr(card, "PANLast4", pan_last4);
    }
    json_object_set_new(root, "Card", card);

    json_t *bench = json_object();
    json_object_set_new(bench, "DurationMs", json_integer((json_int_t)result->elapsed_ms));
    json_object_set_new(bench, "CyclesTotal", json_integer(result->cycles_total));
    json_object_set_new(bench, "CyclesOk", json_integer(result->cycles_ok));
    json_object_set_new(bench, "CyclesFail", json_integer(result->cycles_fail));
    json_object_set_new(bench, "FastInitCycles", json_integer(result->fast_init_cycles));
    json_object_set_new(bench, "FullInitCycles", json_integer(result->full_init_cycles));
    json_object_set_new(bench, "BlocksPerSec", json_real(result->blocks_per_sec));
    json_object_set_new(bench, "BytesPerSec", json_real(result->bytes_per_sec));
    json_object_set_new(bench, "CycleMsMin", json_integer((json_int_t)result->cycle_ms_min));
    json_object_set_new(bench, "CycleMsAvg", json_integer((json_int_t)result->cycle_ms_avg));
    json_object_set_new(bench, "CycleMsP50", json_integer((json_int_t)result->cycle_ms_p50));
    json_object_set_new(bench, "CycleMsP95", json_integer((json_int_t)result->cycle_ms_p95));
    json_object_set_new(bench, "CycleMsMax", json_integer((json_int_t)result->cycle_ms_max));
    json_object_set_new(root, "Bench", bench);

    int res = json_dump_file(root, path, JSON_INDENT(2));
    json_decref(root);

    if (res) {
        PrintAndLogEx(ERR, "Failed to write %s", path);
        return PM3_ESOFT;
    }
    PrintAndLogEx(SUCCESS, "RNG bench export: %s", path);
    return PM3_SUCCESS;
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
    json_add_tlv_hex(root, "AFL", tlvdb_get(ctx->card, 0x94, NULL));
    json_add_tlv_hex(root, "Track2", crypto_card_tlv(ctx, 0x57));

    if (ctx->aid_len) {
        enum CardPSVendor v = GetCardPSVendor((uint8_t *)ctx->aid, ctx->aid_len);
        const char *cp = "unknown";
        if (v == CV_VISA && !tlvdb_get(ctx->card, 0x8c, NULL)) {
            cp = "qvsdc";
        } else if (v == CV_MASTERCARD && tlvdb_get(ctx->card, 0x8c, NULL)) {
            cp = "mchip";
        } else if (v == CV_INTERAC) {
            cp = "interac";
        }
        JsonSaveStr(root, "CryptoPath", cp);
    }

    if (ctx->crypto_ppse_app_count) {
        JsonSaveInt(root, "PPSEAppCount", (int)ctx->crypto_ppse_app_count);
    }
    JsonSaveBoolean(root, "AIDFallbackUsed", ctx->crypto_aid_fallback_used);

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

int emv_term_crypto_prepare_card(emv_term_ctx_t *ctx, bool jload, const char *session_path,
                                 const emv_term_crypto_prepare_opts_t *prep) {
    if (!ctx) {
        return PM3_EINVARG;
    }

    if (prep) {
        ctx->opts.crypto_quick_afl = prep->quick_afl;
        ctx->opts.crypto_aid_fallback = prep->aid_fallback;
        ctx->opts.crypto_forced_aid_len = 0;
        if (prep->forced_aid_hex && prep->forced_aid_hex[0]) {
            int buflen = 0;
            if (!param_gethex_to_eol(prep->forced_aid_hex, 0, ctx->opts.crypto_forced_aid,
                                     sizeof(ctx->opts.crypto_forced_aid), &buflen) && buflen > 0) {
                ctx->opts.crypto_forced_aid_len = (size_t)buflen;
            }
        }
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

int emv_term_crypto_bench(emv_term_ctx_t *ctx, const emv_term_crypto_bench_opts_t *opts,
                          const char *export_path) {
    return emv_term_crypto_bench_ex(ctx, opts, export_path, NULL);
}

int emv_term_crypto_bench_ex(emv_term_ctx_t *ctx, const emv_term_crypto_bench_opts_t *opts,
                             const char *export_path, emv_term_crypto_bench_result_t *result_out) {
    if (!ctx || !opts) {
        return PM3_EINVARG;
    }

    emv_term_crypto_bench_result_t result_storage = {0};
    emv_term_crypto_bench_result_t *result = result_out ? result_out : &result_storage;

    PrintAndLogEx(INFO, "=== EMV crypto playground bench ===");
    emv_term_crypto_print_summary(ctx);

    emv_term_crypto_run_entry_t entries[32] = {0};
    size_t entry_count = 0;

    if (opts->do_challenge) {
        emv_term_crypto_challenge(ctx, ctx->opts.decode_tlv, opts->genac.mc_challenge);
    }

    if (opts->do_genac) {
        result->genac_attempted = true;
        if (!crypto_is_qvsdc_gpo_ac(ctx) && crypto_is_visa_qvsdc(ctx)) {
            emv_transaction_visa_request_gpo_ac(ctx);
        }
        if (crypto_is_qvsdc_gpo_ac(ctx)) {
            result->qvsdc_path = true;
            result->genac_ok = true;
            PrintAndLogEx(SUCCESS, "qVSDC: cryptogram from GPO — skipping GEN AC");
            emv_term_crypto_print_summary(ctx);
        } else if (crypto_is_visa_qvsdc(ctx)) {
            result->visa_msd = true;
            result->genac_ok = false;
            PrintAndLogEx(INFO, "qVSDC: no AC in GPO — MSD / online profile");
            emv_term_crypto_print_msd_summary(ctx);
        } else {
            uint16_t sw = 0;
            int res = crypto_genac_inner(ctx, &opts->genac, false, &sw);
            result->genac_sw = sw;
            result->genac_ok = (res == PM3_SUCCESS);
            if (entry_count < ARRAYLEN(entries)) {
                fill_run_entry(&entries[entry_count], ctx, sw);
                entry_count++;
            }
            if (res) {
                PrintAndLogEx(WARNING, "GEN AC failed in bench (%d)", res);
            }
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
        result->vary_runs = cap;
    }

    result->aid_fallback_used = ctx->crypto_aid_fallback_used;

    emv_term_crypto_print_summary(ctx);

    if (opts->do_digest) {
        emv_term_crypto_print_digest(ctx, result);
    }

    if (export_path && export_path[0]) {
        emv_term_crypto_export_json(ctx, export_path, entries, entry_count);
    }

    return PM3_SUCCESS;
}
