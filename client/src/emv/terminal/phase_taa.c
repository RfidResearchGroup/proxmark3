//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "phase_taa.h"
#include "emv_term_tvr.h"
#include "ui.h"
#include <string.h>

static void default_tac(uint8_t tac[5], bool denial) {
    if (denial) {
        memset(tac, 0, 5);
    } else {
        memset(tac, 0, 5);
        tac[0] = 0xFC;
        tac[2] = 0x50;
        tac[3] = 0xA8;
    }
}

static void get_action_codes(emv_term_ctx_t *ctx, uint8_t tac_denial[5], uint8_t tac_online[5], uint8_t tac_default[5],
                             uint8_t iac_denial[5], uint8_t iac_online[5], uint8_t iac_default[5]) {
    default_tac(tac_denial, true);
    default_tac(tac_online, false);
    default_tac(tac_default, false);

    emv_term_tlv_get_bytes(ctx->card, 0xdf8121, tac_denial, NULL, 5);
    emv_term_tlv_get_bytes(ctx->card, 0xdf8122, tac_online, NULL, 5);
    emv_term_tlv_get_bytes(ctx->card, 0xdf8120, tac_default, NULL, 5);

    emv_term_tlv_get_bytes(ctx->card, 0x9f0e, iac_denial, NULL, 5);
    emv_term_tlv_get_bytes(ctx->card, 0x9f0f, iac_online, NULL, 5);
    emv_term_tlv_get_bytes(ctx->card, 0x9f0d, iac_default, NULL, 5);

    if (GetCardPSVendor(ctx->aid, ctx->aid_len) == CV_INTERAC && ctx->channel == CC_CONTACTLESS) {
        emv_term_tlv_get_bytes(ctx->card, 0x9f6d, tac_online, NULL, 5);
        emv_term_tlv_get_bytes(ctx->card, 0x9f6b, tac_denial, NULL, 5);
    }
}

int phase_taa_run(emv_term_ctx_t *ctx) {
    if (!ctx) {
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "\n* Terminal action analysis");

    if (ctx->oda_performed && !ctx->oda_success) {
        emv_term_tvr_set_bit(ctx, 0, 0x08, true);
        PrintAndLogEx(WARNING, "ODA failed - TVR updated");
    }

    uint8_t tvr[5];
    emv_term_tvr_get(ctx, tvr);

    uint8_t tac_denial[5], tac_online[5], tac_default[5];
    uint8_t iac_denial[5], iac_online[5], iac_default[5];
    memset(iac_denial, 0, 5);
    memset(iac_online, 0, 5);
    memset(iac_default, 0, 5);
    get_action_codes(ctx, tac_denial, tac_online, tac_default, iac_denial, iac_online, iac_default);

    uint8_t requested = EMVAC_TC_BYTE;

    if (emv_term_tac_match(tvr, tac_denial, iac_denial)) {
        requested = EMVAC_AAC_BYTE;
        PrintAndLogEx(INFO, "TAA: Denial action -> AAC");
    } else if (emv_term_tac_match(tvr, tac_online, iac_online)) {
        requested = EMVAC_ARQC_BYTE;
        PrintAndLogEx(INFO, "TAA: Online action -> ARQC");
    } else if (emv_term_tac_match(tvr, tac_default, iac_default)) {
        requested = EMVAC_TC_BYTE;
        PrintAndLogEx(INFO, "TAA: Default action -> TC");
    } else {
        requested = EMVAC_TC_BYTE;
        PrintAndLogEx(INFO, "TAA: No match - default TC");
    }

    ctx->requested_ac = requested;
    return PM3_SUCCESS;
}
