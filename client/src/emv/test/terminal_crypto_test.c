//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "terminal_crypto_test.h"
#include "../terminal/emv_term_crypto.h"
#include "../terminal/emv_term_load.h"
#include "../terminal/emv_term_profile.h"
#include "../terminal/emv_term_tvr.h"
#include "../dol.h"
#include "ui.h"
#include <string.h>

static int test_uint_to_bcd(bool verbose) {
    uint8_t bcd[6] = {0};
    emv_term_uint_to_bcd(100, bcd, sizeof(bcd));
    if (bcd[4] != 0x01 || bcd[5] != 0x00) {
        if (verbose) {
            PrintAndLogEx(ERR, "BCD encode 100 failed: %s", sprint_hex(bcd, sizeof(bcd)));
        }
        return 1;
    }
    if (emv_term_bcd_to_uint(bcd, sizeof(bcd)) != 100) {
        if (verbose) {
            PrintAndLogEx(ERR, "BCD roundtrip failed");
        }
        return 1;
    }
    if (verbose) {
        PrintAndLogEx(SUCCESS, "BCD encode/decode OK");
    }
    return 0;
}

static int test_cdol_un_override(bool verbose) {
    emv_term_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    const char *alr = "card";
    const char *alt = "terminal";
    ctx.card = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);
    ctx.terminal = tlvdb_fixed(1, strlen(alt), (const unsigned char *)alt);

    uint8_t cdol1_val[] = {0x9f, 0x37, 0x04};
    tlvdb_change_or_add_node(ctx.card, 0x8c, sizeof(cdol1_val), cdol1_val);

    emv_term_crypto_genac_opts_t opts;
    emv_term_crypto_genac_opts_defaults(&opts);
    opts.un_set = true;
    opts.un[0] = 0x01;
    opts.un[1] = 0x02;
    opts.un[2] = 0x03;
    opts.un[3] = 0x04;
    emv_term_crypto_apply_field_overrides(&ctx, &opts);

    const struct tlv *cdol_tlv = tlvdb_get(ctx.card, 0x8c, NULL);
    struct tlv *cdol = dol_process(cdol_tlv, ctx.card, 0x01);
    if (!cdol || cdol->len != 4) {
        if (verbose) {
            PrintAndLogEx(ERR, "CDOL build failed");
        }
        tlvdb_free(ctx.card);
        tlvdb_free(ctx.terminal);
        return 1;
    }
    if (memcmp(cdol->value, opts.un, 4) != 0) {
        if (verbose) {
            PrintAndLogEx(ERR, "CDOL UN mismatch: %s", sprint_hex(cdol->value, cdol->len));
        }
        free(cdol);
        tlvdb_free(ctx.card);
        tlvdb_free(ctx.terminal);
        return 1;
    }
    free(cdol);

    if (verbose) {
        PrintAndLogEx(SUCCESS, "CDOL UN override OK");
    }
    tlvdb_free(ctx.card);
    tlvdb_free(ctx.terminal);
    return 0;
}

static int test_summary_fixture(bool verbose) {
    emv_term_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    const char *alr = "card";
    const char *alt = "terminal";
    ctx.card = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);
    ctx.terminal = tlvdb_fixed(1, strlen(alt), (const unsigned char *)alt);

    int res = emv_term_load_card_tlv(&ctx, "client/src/emv/test/fixtures/crypto_cdol_build/card_tlv.json");
    if (res) {
        res = emv_term_load_card_tlv(&ctx, "src/emv/test/fixtures/crypto_cdol_build/card_tlv.json");
    }
    if (res) {
        if (verbose) {
            PrintAndLogEx(ERR, "fixture load failed");
        }
        tlvdb_free(ctx.card);
        tlvdb_free(ctx.terminal);
        return 1;
    }

    if (!tlvdb_get(ctx.card, 0x8c, NULL)) {
        if (verbose) {
            PrintAndLogEx(ERR, "fixture missing CDOL1");
        }
        tlvdb_free(ctx.card);
        tlvdb_free(ctx.terminal);
        return 1;
    }

    res = emv_term_crypto_print_summary(&ctx);
    tlvdb_free(ctx.card);
    tlvdb_free(ctx.terminal);
    return (res == PM3_SUCCESS) ? 0 : 1;
}

static int test_export_json(bool verbose) {
    emv_term_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    const char *alr = "card";
    ctx.card = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);
    ctx.aid_len = 7;
    memcpy(ctx.aid, "\xA0\x00\x00\x00\x03\x10\x10", 7);

    uint8_t ac[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    uint8_t atc[] = {0x00, 0x05};
    tlvdb_change_or_add_node(ctx.card, 0x9f26, sizeof(ac), ac);
    tlvdb_change_or_add_node(ctx.card, 0x9f36, sizeof(atc), atc);

    const char *path = "/tmp/emv_crypto_test_export.json";
    int res = emv_term_crypto_export_json(&ctx, path, NULL, 0);
    tlvdb_free(ctx.card);

    if (res) {
        if (verbose) {
            PrintAndLogEx(ERR, "export failed");
        }
        return 1;
    }

    if (verbose) {
        PrintAndLogEx(SUCCESS, "export JSON OK: %s", path);
    }
    return 0;
}

static int test_param_defaults_currency(bool verbose) {
    struct tlvdb *terminal = NULL;
    const char *al = "terminal";
    terminal = tlvdb_fixed(1, strlen(al), (const unsigned char *)al);
    emv_term_param_defaults(terminal);

    const struct tlv *ccy = tlvdb_get(terminal, 0x5f2a, NULL);
    if (!ccy || ccy->len != 2) {
        if (verbose) {
            PrintAndLogEx(ERR, "5F2A missing or wrong len");
        }
        tlvdb_free(terminal);
        return 1;
    }
    if (ccy->value[0] == 0x90 && ccy->value[1] == 0x78) {
        if (verbose) {
            PrintAndLogEx(ERR, "5F2A still has legacy bad escape value 9078");
        }
        tlvdb_free(terminal);
        return 1;
    }

    const struct tlv *country = tlvdb_get(terminal, 0x9f1a, NULL);
    if (!country || country->len != 2 || country->value[0] == 'r') {
        if (verbose) {
            PrintAndLogEx(ERR, "9F1A should be numeric country code");
        }
        tlvdb_free(terminal);
        return 1;
    }

    if (verbose) {
        PrintAndLogEx(SUCCESS, "terminal param defaults OK");
    }
    tlvdb_free(terminal);
    return 0;
}

int exec_terminal_crypto_test(bool verbose) {
    if (test_uint_to_bcd(verbose)) {
        return 1;
    }
    if (test_param_defaults_currency(verbose)) {
        return 1;
    }
    if (test_cdol_un_override(verbose)) {
        return 1;
    }
    if (test_summary_fixture(verbose)) {
        return 1;
    }
    if (test_export_json(verbose)) {
        return 1;
    }
    return 0;
}
