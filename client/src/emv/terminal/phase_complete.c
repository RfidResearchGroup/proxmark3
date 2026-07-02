//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "phase_complete.h"
#include "phase_scripts.h"
#include "emv_transaction.h"
#include "emv_term_tvr.h"
#include "ui.h"

int phase_complete_run(emv_term_ctx_t *ctx) {
    if (!ctx) {
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "\n* Completion");

    if (ctx->online_success || ctx->ac2_performed) {
        phase_scripts_run(ctx, 0x72, false);
    }

    if (ctx->outcome == EMV_OUTCOME_UNKNOWN) {
        if (ctx->ac2_performed && (ctx->ac2_cid & 0xC0) == EMVAC_TC_BYTE) {
            ctx->outcome = EMV_OUTCOME_APPROVED_ONLINE;
        } else if (ctx->ac1_performed) {
            ctx->outcome = emv_transaction_outcome_from_cid(ctx->ac1_cid);
        }
    }

    emv_term_tsi_set_bit(ctx, 0, 0x80, true);

    PrintAndLogEx(INFO, "Final outcome: %s", emv_term_outcome_str(ctx->outcome));
    return PM3_SUCCESS;
}
