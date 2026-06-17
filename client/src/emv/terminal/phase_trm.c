//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "phase_trm.h"
#include "emv_term_tvr.h"
#include "emv_term_tlv.h"
#include "ui.h"
#include <inttypes.h>
#include <stdlib.h>

int phase_trm_run(emv_term_ctx_t *ctx) {
    if (!ctx) {
        return PM3_EINVARG;
    }

    ctx->floor_limit_exceeded = false;
    PrintAndLogEx(INFO, "\n* Terminal risk management");

    const struct tlv *amount = emv_term_tlv_lookup(ctx, 0x9f02);
    const struct tlv *floor = emv_term_tlv_lookup(ctx, 0x9f1b);
    if (amount && amount->len >= 6 && floor && floor->len >= 6) {
        uint64_t amt = emv_term_bcd_to_uint(amount->value, amount->len);
        uint64_t lim = emv_term_bcd_to_uint(floor->value, floor->len);
        PrintAndLogEx(INFO, "Amount=%" PRIu64 " Floor limit=%" PRIu64, amt, lim);
        if (amt > lim) {
            PrintAndLogEx(WARNING, "Transaction amount exceeds floor limit");
            emv_term_tvr_set_bit(ctx, 3, 0x80, true);
            ctx->floor_limit_exceeded = true;
        }
    }

    uint8_t un[4] = {0};
    un[0] = (uint8_t)(rand() & 0xFF);
    un[1] = (uint8_t)(rand() & 0xFF);
    un[2] = (uint8_t)(rand() & 0xFF);
    un[3] = (uint8_t)(rand() & 0xFF);
    tlvdb_change_or_add_node(ctx->card, 0x9f37, 4, un);

    if (ctx->floor_limit_exceeded) {
        PrintAndLogEx(INFO, "TRM: floor limit exceeded (TVR updated)");
    } else {
        PrintAndLogEx(INFO, "TRM: OK");
    }

    return PM3_SUCCESS;
}
