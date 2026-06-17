//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// EMV terminal emulator — card GET DATA probe / enumeration
//-----------------------------------------------------------------------------

#include "emv_term_probe.h"
#include "emv_term_tlv.h"
#include "phase_cvm.h"
#include "../emvcore.h"
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

int emv_term_probe_card(emv_term_ctx_t *ctx, bool sweep_all) {
    if (!ctx) {
        return PM3_EINVARG;
    }

    const uint16_t *tags = probe_tags_default;
    size_t tag_count = ARRAYLEN(probe_tags_default);
    if (sweep_all) {
        tags = probe_tags_sweep;
        tag_count = ARRAYLEN(probe_tags_sweep);
    }

    PrintAndLogEx(INFO, "--- EMV card probe (%s) ---", sweep_all ? "extended sweep" : "common tags");

    const struct tlv *cvm_list = tlvdb_get(ctx->card, 0x8e, NULL);
    if (cvm_list && cvm_list->len >= 10) {
        PrintAndLogEx(INFO, "CVM List (8E) already in card context:");
        emv_term_cvm_dump_list(ctx);
    } else {
        PrintAndLogEx(INFO, "No CVM List (8E) in context — run init or load scan data first for CVM decode");
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
        PrintAndLogEx(WARNING, "No GET DATA tags returned data — card may require prior SELECT/GPO or tags are record-only");
    } else {
        PrintAndLogEx(SUCCESS, "Probe complete: %d tag(s) returned data", found);
    }

    if (ctx->channel == CC_CONTACTLESS) {
        PrintAndLogEx(INFO, "Note: contactless cards rarely support offline PIN VERIFY (00 20); use contact (-w) or expect online PIN / no-CVM");
    }

    return PM3_SUCCESS;
}
