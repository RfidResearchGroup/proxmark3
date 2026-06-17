//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "terminal_cvm_test.h"
#include "../terminal/emv_term_secure.h"
#include "../terminal/phase_cvm.h"
#include "../terminal/emv_term_tvr.h"
#include "../terminal/emv_term_redact.h"
#include "../emvcore.h"
#include "ui.h"
#include <jansson.h>
#include <string.h>

static int test_secure_zero(bool verbose) {
    uint8_t buf[32];
    memset(buf, 0xA5, sizeof(buf));
    emv_term_secure_zero(buf, sizeof(buf));
    for (size_t i = 0; i < sizeof(buf); i++) {
        if (buf[i] != 0) {
            if (verbose) {
                PrintAndLogEx(ERR, "secure_zero left byte %zu = %02x", i, buf[i]);
            }
            return 1;
        }
    }
    if (verbose) {
        PrintAndLogEx(SUCCESS, "secure_zero OK");
    }
    return 0;
}

static int test_pin_zeroize(bool verbose) {
    uint8_t block[8] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    emv_term_pin_zeroize(block, sizeof(block));
    for (size_t i = 0; i < sizeof(block); i++) {
        if (block[i] != 0) {
            if (verbose) {
                PrintAndLogEx(ERR, "pin_zeroize failed at %zu", i);
            }
            return 1;
        }
    }
    if (verbose) {
        PrintAndLogEx(SUCCESS, "pin_zeroize OK");
    }
    return 0;
}

static int test_terminal_caps_from_terminal_tree(bool verbose) {
    emv_term_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    const char *alr = "Root terminal TLV tree";
    ctx.card = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);
    const char *alt = "Terminal TLV tree";
    ctx.terminal = tlvdb_fixed(1, strlen(alt), (const unsigned char *)alt);

    uint8_t caps_terminal[] = {0xE0, 0x00, 0xC8};
    uint8_t caps_card[] = {0xE0, 0xF8, 0xC8};
    tlvdb_change_or_add_node(ctx.terminal, 0x9f33, sizeof(caps_terminal), caps_terminal);
    tlvdb_change_or_add_node(ctx.card, 0x9f33, sizeof(caps_card), caps_card);

    uint8_t cvm_list[] = {
        0x00, 0x00, 0x27, 0x10,
        0x00, 0x00, 0x4E, 0x20,
        0x01, 0x00,
        0x1F, 0x00,
    };
    tlvdb_change_or_add_node(ctx.card, 0x8e, sizeof(cvm_list), cvm_list);
    ctx.opts.pin = "1234";

    int res = phase_cvm_run(&ctx);
    if (res != PM3_SUCCESS) {
        if (verbose) {
            PrintAndLogEx(ERR, "CVM run failed (%d)", res);
        }
        tlvdb_free(ctx.card);
        tlvdb_free(ctx.terminal);
        return 1;
    }
    if (ctx.cvm_results[0] == 0x01) {
        if (verbose) {
            PrintAndLogEx(ERR, "offline PIN ran despite terminal 9F33 lacking support bit");
        }
        tlvdb_free(ctx.card);
        tlvdb_free(ctx.terminal);
        return 1;
    }

    if (verbose) {
        PrintAndLogEx(SUCCESS, "terminal 9F33 precedence OK (offline PIN skipped)");
    }
    tlvdb_free(ctx.card);
    tlvdb_free(ctx.terminal);
    return 0;
}

static int test_online_pin_stash(bool verbose) {
    emv_term_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    const char *alr = "Root terminal TLV tree";
    ctx.card = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);
    const char *alt = "Terminal TLV tree";
    ctx.terminal = tlvdb_fixed(1, strlen(alt), (const unsigned char *)alt);

    uint8_t cvm_list[] = {
        0x00, 0x00, 0x27, 0x10,
        0x00, 0x00, 0x4E, 0x20,
        0x02, 0x00,
        0x1F, 0x00,
    };
    uint8_t caps[] = {0xE0, 0xF8, 0xC8};
    tlvdb_change_or_add_node(ctx.card, 0x8e, sizeof(cvm_list), cvm_list);
    tlvdb_change_or_add_node(ctx.terminal, 0x9f33, sizeof(caps), caps);

    ctx.opts.pin = "1234";
    int res = phase_cvm_run(&ctx);
    if (res != PM3_SUCCESS) {
        if (verbose) {
            PrintAndLogEx(ERR, "online PIN CVM run failed (%d)", res);
        }
        tlvdb_free(ctx.card);
        tlvdb_free(ctx.terminal);
        return 1;
    }
    if (ctx.online_pin_block_len != 8) {
        if (verbose) {
            PrintAndLogEx(ERR, "online PIN block not stashed (len=%zu)", ctx.online_pin_block_len);
        }
        tlvdb_free(ctx.card);
        tlvdb_free(ctx.terminal);
        return 1;
    }

    uint8_t tvr[5] = {0};
    emv_term_tvr_get(&ctx, tvr);
    if ((tvr[2] & 0x08) == 0) {
        if (verbose) {
            PrintAndLogEx(ERR, "TVR online PIN entered bit not set");
        }
        tlvdb_free(ctx.card);
        tlvdb_free(ctx.terminal);
        return 1;
    }

    emv_term_pin_zeroize(ctx.online_pin_block, sizeof(ctx.online_pin_block));
    ctx.online_pin_block_len = 0;

    if (verbose) {
        PrintAndLogEx(SUCCESS, "online PIN stash OK");
    }
    tlvdb_free(ctx.card);
    tlvdb_free(ctx.terminal);
    return 0;
}

static int test_no_cvm_without_pin(bool verbose) {
    emv_term_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    const char *alr = "Root terminal TLV tree";
    ctx.card = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);
    const char *alt = "Terminal TLV tree";
    ctx.terminal = tlvdb_fixed(1, strlen(alt), (const unsigned char *)alt);

    uint8_t cvm_list[] = {
        0x00, 0x00, 0x27, 0x10,
        0x00, 0x00, 0x4E, 0x20,
        0x1F, 0x00,
    };
    uint8_t aip[] = {0x18, 0x00};
    tlvdb_change_or_add_node(ctx.card, 0x82, sizeof(aip), aip);
    tlvdb_change_or_add_node(ctx.card, 0x8e, sizeof(cvm_list), cvm_list);

    int res = phase_cvm_run(&ctx);
    if (res != PM3_SUCCESS) {
        if (verbose) {
            PrintAndLogEx(ERR, "no-CVM run failed (%d)", res);
        }
        tlvdb_free(ctx.card);
        tlvdb_free(ctx.terminal);
        return 1;
    }
    if (ctx.cvm_results[0] != 0x1F) {
        if (verbose) {
            PrintAndLogEx(ERR, "expected no-CVM result, got %02x", ctx.cvm_results[0]);
        }
        tlvdb_free(ctx.card);
        tlvdb_free(ctx.terminal);
        return 1;
    }

    if (verbose) {
        PrintAndLogEx(SUCCESS, "no-CVM without PIN prompt OK");
    }
    tlvdb_free(ctx.card);
    tlvdb_free(ctx.terminal);
    return 0;
}

static int test_aip_skips_cvm(bool verbose) {
    emv_term_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    const char *alr = "Root terminal TLV tree";
    ctx.card = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);
    const char *alt = "Terminal TLV tree";
    ctx.terminal = tlvdb_fixed(1, strlen(alt), (const unsigned char *)alt);

    uint8_t aip[] = {0x80, 0x00};
    uint8_t cvm_list[] = {
        0x00, 0x00, 0x27, 0x10,
        0x00, 0x00, 0x4E, 0x20,
        0x01, 0x00,
    };
    tlvdb_change_or_add_node(ctx.card, 0x82, sizeof(aip), aip);
    tlvdb_change_or_add_node(ctx.card, 0x8e, sizeof(cvm_list), cvm_list);

    int res = phase_cvm_run(&ctx);
    if (res != PM3_SUCCESS) {
        if (verbose) {
            PrintAndLogEx(ERR, "AIP skip CVM failed (%d)", res);
        }
        tlvdb_free(ctx.card);
        tlvdb_free(ctx.terminal);
        return 1;
    }
    if (ctx.cvm_results[0] != 0x1F) {
        if (verbose) {
            PrintAndLogEx(ERR, "expected skipped CVM (1F), got %02x", ctx.cvm_results[0]);
        }
        tlvdb_free(ctx.card);
        tlvdb_free(ctx.terminal);
        return 1;
    }

    if (verbose) {
        PrintAndLogEx(SUCCESS, "AIP no-CVM-support skip OK");
    }
    tlvdb_free(ctx.card);
    tlvdb_free(ctx.terminal);
    return 0;
}

static int test_contactless_offline_pin_skipped(bool verbose) {
    emv_term_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.channel = CC_CONTACTLESS;

    const char *alr = "Root terminal TLV tree";
    ctx.card = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);
    const char *alt = "Terminal TLV tree";
    ctx.terminal = tlvdb_fixed(1, strlen(alt), (const unsigned char *)alt);

    uint8_t caps[] = {0xE0, 0xF8, 0xC8};
    uint8_t cvm_list[] = {
        0x00, 0x00, 0x27, 0x10,
        0x00, 0x00, 0x4E, 0x20,
        0x01, 0x00,
        0x1F, 0x00,
    };
    tlvdb_change_or_add_node(ctx.terminal, 0x9f33, sizeof(caps), caps);
    tlvdb_change_or_add_node(ctx.card, 0x8e, sizeof(cvm_list), cvm_list);

    int res = phase_cvm_run(&ctx);
    if (res != PM3_SUCCESS) {
        if (verbose) {
            PrintAndLogEx(ERR, "contactless offline skip failed (%d)", res);
        }
        tlvdb_free(ctx.card);
        tlvdb_free(ctx.terminal);
        return 1;
    }
    if (ctx.cvm_results[0] != 0x1F) {
        if (verbose) {
            PrintAndLogEx(ERR, "expected no-CVM after skip, got %02x", ctx.cvm_results[0]);
        }
        tlvdb_free(ctx.card);
        tlvdb_free(ctx.terminal);
        return 1;
    }

    if (verbose) {
        PrintAndLogEx(SUCCESS, "contactless offline PIN skip OK");
    }
    tlvdb_free(ctx.card);
    tlvdb_free(ctx.terminal);
    return 0;
}

static int test_session_redact(bool verbose) {
    json_t *root = json_object();
    json_t *crypto = json_object();
    json_t *card = json_object();

    json_object_set_new(crypto, "AC", json_string("AABBCCDDEEFF0011"));
    json_object_set_new(crypto, "IAD", json_string("06010A03A00000"));
    json_object_set_new(card, "Track2", json_string("4111111111111111D25122011234567890"));
    json_object_set_new(root, "Cryptogram", crypto);
    json_object_set_new(root, "Card", card);

    emv_term_redact_session_json(root, false);

    json_t *ac = json_object_get(crypto, "AC");
    if (!json_is_string(ac) || strstr(json_string_value(ac), "...") == NULL) {
        if (verbose) {
            PrintAndLogEx(ERR, "AC redaction failed");
        }
        json_decref(root);
        return 1;
    }
    if (json_object_get(crypto, "IAD")) {
        if (verbose) {
            PrintAndLogEx(ERR, "IAD should be removed");
        }
        json_decref(root);
        return 1;
    }

    if (verbose) {
        PrintAndLogEx(SUCCESS, "session redact OK");
    }
    json_decref(root);
    return 0;
}

int exec_terminal_pin_audit_test(bool verbose) {
    if (test_secure_zero(verbose)) {
        return 1;
    }
    if (test_pin_zeroize(verbose)) {
        return 1;
    }
    if (verbose) {
        PrintAndLogEx(SUCCESS, "PIN audit (zeroize) OK");
    }
    return 0;
}

int exec_terminal_cvm_test(bool verbose) {
    if (test_secure_zero(verbose)) {
        return 1;
    }
    if (test_pin_zeroize(verbose)) {
        return 1;
    }
    if (test_terminal_caps_from_terminal_tree(verbose)) {
        return 1;
    }
    if (test_online_pin_stash(verbose)) {
        return 1;
    }
    if (test_no_cvm_without_pin(verbose)) {
        return 1;
    }
    if (test_aip_skips_cvm(verbose)) {
        return 1;
    }
    if (test_contactless_offline_pin_skipped(verbose)) {
        return 1;
    }
    if (test_session_redact(verbose)) {
        return 1;
    }
    return 0;
}
