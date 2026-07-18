//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "phase_restrict.h"
#include "emv_term_tvr.h"
#include "emv_term_exception.h"
#include "ui.h"
#include <string.h>
#include <time.h>

static size_t pan_from_card(const struct tlvdb *card, uint8_t *pan, size_t max_len) {
    const struct tlv *p = tlvdb_get(card, 0x5a, NULL);
    if (p && p->len && p->len <= max_len) {
        memcpy(pan, p->value, p->len);
        return p->len;
    }
    return 0;
}

int phase_restrict_run(emv_term_ctx_t *ctx) {
    if (!ctx) {
        return PM3_EINVARG;
    }

    ctx->restrict_failed = false;
    PrintAndLogEx(INFO, "\n* Processing restrictions");

    const struct tlv *exp = tlvdb_get(ctx->card, 0x5f24, NULL);
    if (exp && exp->len >= 3) {
        time_t now = time(NULL);
        struct tm *tm_now = localtime(&now);
        if (tm_now) {
            uint8_t yy = (uint8_t)(tm_now->tm_year % 100);
            uint8_t mm = (uint8_t)(tm_now->tm_mon + 1);
            uint8_t dd = (uint8_t)tm_now->tm_mday;
            uint8_t card_yy = exp->value[0];
            uint8_t card_mm = exp->value[1];
            uint8_t card_dd = exp->value[2];
            bool expired = (card_yy < yy) ||
                           (card_yy == yy && card_mm < mm) ||
                           (card_yy == yy && card_mm == mm && card_dd < dd);
            if (expired) {
                PrintAndLogEx(WARNING, "Application expired (5F24=%02x%02x%02x)", card_yy, card_mm, card_dd);
                emv_term_tvr_set_bit(ctx, 1, 0x04, true);
                ctx->restrict_failed = true;
            }
        }
    }

    const struct tlv *eff = tlvdb_get(ctx->card, 0x5f25, NULL);
    if (eff && eff->len >= 3) {
        time_t now = time(NULL);
        struct tm *tm_now = localtime(&now);
        if (tm_now) {
            uint8_t yy = (uint8_t)(tm_now->tm_year % 100);
            uint8_t mm = (uint8_t)(tm_now->tm_mon + 1);
            uint8_t dd = (uint8_t)tm_now->tm_mday;
            uint8_t eff_yy = eff->value[0];
            uint8_t eff_mm = eff->value[1];
            uint8_t eff_dd = eff->value[2];
            bool not_yet = (eff_yy > yy) ||
                           (eff_yy == yy && eff_mm > mm) ||
                           (eff_yy == yy && eff_mm == mm && eff_dd > dd);
            if (not_yet) {
                PrintAndLogEx(WARNING, "Application not yet effective (5F25)");
                emv_term_tvr_set_bit(ctx, 1, 0x02, true);
                ctx->restrict_failed = true;
            }
        }
    }

    const struct tlv *auc = tlvdb_get(ctx->card, 0x9f07, NULL);
    const struct tlv *tt = tlvdb_get(ctx->card, 0x9c, NULL);
    if (auc && auc->len >= 2 && tt && tt->len >= 1) {
        uint8_t txn_type = tt->value[0];
        if (txn_type == 0x00 && !(auc->value[0] & 0x80)) {
            PrintAndLogEx(WARNING, "AUC: goods/services not allowed");
            emv_term_tvr_set_bit(ctx, 2, 0x80, true);
            ctx->restrict_failed = true;
        }
        if (txn_type == 0x01 && !(auc->value[0] & 0x40)) {
            PrintAndLogEx(WARNING, "AUC: cash not allowed");
            emv_term_tvr_set_bit(ctx, 2, 0x40, true);
            ctx->restrict_failed = true;
        }
    }

    const struct tlv *ver = tlvdb_get(ctx->card, 0x9f08, NULL);
    const struct tlv *term_ver = tlvdb_get(ctx->card, 0x9f09, NULL);
    if (ver && ver->len >= 2 && term_ver && term_ver->len >= 2) {
        if (memcmp(ver->value, term_ver->value, 2) > 0) {
            PrintAndLogEx(WARNING, "Application version older than terminal");
            emv_term_tvr_set_bit(ctx, 2, 0x08, true);
        }
    }

    if (ctx->exception_file) {
        uint8_t pan[32] = {0};
        size_t pan_len = pan_from_card(ctx->card, pan, sizeof(pan));
        if (pan_len && emv_term_exception_pan_match(ctx->exception_file, pan, pan_len)) {
            PrintAndLogEx(WARNING, "PAN on exception file");
            emv_term_tvr_set_bit(ctx, 1, 0x10, true);
            ctx->restrict_failed = true;
        }
    }

    if (ctx->restrict_failed) {
        PrintAndLogEx(INFO, "Processing restrictions: failed checks (TVR updated)");
    } else {
        PrintAndLogEx(INFO, "Processing restrictions: OK");
    }

    return PM3_SUCCESS;
}
