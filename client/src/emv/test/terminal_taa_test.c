//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "terminal_taa_test.h"
#include "../terminal/emv_term_tvr.h"
#include "../terminal/phase_taa.h"
#include "../terminal/emv_term_ctx.h"
#include "ui.h"
#include <string.h>

static int test_tac_match(bool verbose) {
    uint8_t tvr[5] = {0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t tac[5] = {0x00, 0x00, 0x00, 0x80, 0x00};
    uint8_t iac[5] = {0x00, 0x00, 0x00, 0x00, 0x00};

    if (emv_term_tac_match(tvr, tac, iac)) {
        if (verbose) {
            PrintAndLogEx(ERR, "TAC match should fail on zero TVR");
        }
        return 1;
    }

    tvr[3] = 0x80;
    if (!emv_term_tac_match(tvr, tac, iac)) {
        if (verbose) {
            PrintAndLogEx(ERR, "TAC match should succeed when TVR bit set");
        }
        return 1;
    }

    memset(tvr, 0, sizeof(tvr));
    iac[1] = 0x04;
    tvr[1] = 0x04;
    if (!emv_term_tac_match(tvr, tac, iac)) {
        if (verbose) {
            PrintAndLogEx(ERR, "IAC match should succeed when TVR bit set");
        }
        return 1;
    }

    if (verbose) {
        PrintAndLogEx(SUCCESS, "TAC/IAC match tests OK");
    }
    return 0;
}

static int test_phase_taa_denial(bool verbose) {
    emv_term_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    const char *alr = "Root terminal TLV tree";
    ctx.card = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);

    uint8_t tvr[5] = {0x00, 0x04, 0x00, 0x00, 0x00};
    tlvdb_change_or_add_node(ctx.card, 0x95, 5, tvr);

    uint8_t iac_deny[5] = {0x00, 0x04, 0x00, 0x00, 0x00};
    tlvdb_change_or_add_node(ctx.card, 0x9f0e, 5, iac_deny);

    ctx.aid_len = 7;
    memcpy(ctx.aid, "\xA0\x00\x00\x00\x03\x10\x10", 7);

    if (phase_taa_run(&ctx) != PM3_SUCCESS) {
        tlvdb_free(ctx.card);
        return 1;
    }

    if (ctx.requested_ac != EMVAC_AAC_BYTE) {
        if (verbose) {
            PrintAndLogEx(ERR, "Expected AAC for expired-card TVR, got %02x", ctx.requested_ac);
        }
        tlvdb_free(ctx.card);
        return 1;
    }

    if (verbose) {
        PrintAndLogEx(SUCCESS, "phase_taa denial test OK");
    }
    tlvdb_free(ctx.card);
    return 0;
}

static int test_bcd_amount(bool verbose) {
    uint8_t bcd[] = {0x00, 0x00, 0x00, 0x00, 0x01, 0x00};
    if (emv_term_bcd_to_uint(bcd, sizeof(bcd)) != 100) {
        if (verbose) {
            PrintAndLogEx(ERR, "BCD 100 decode failed");
        }
        return 1;
    }
    if (verbose) {
        PrintAndLogEx(SUCCESS, "BCD decode test OK");
    }
    return 0;
}

int exec_terminal_taa_test(bool verbose) {
    if (test_tac_match(verbose)) {
        return 1;
    }
    if (test_bcd_amount(verbose)) {
        return 1;
    }
    if (test_phase_taa_denial(verbose)) {
        return 1;
    }
    return 0;
}
