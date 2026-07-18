//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "phase_scripts.h"
#include "emv_term_tvr.h"
#include "../emvcore.h"
#include "ui.h"
#include "protocols.h"
#include <string.h>

static bool script_ins_sensitive(uint8_t ins) {
    return ins == 0x24 || ins == 0x25;
}

int phase_scripts_run(emv_term_ctx_t *ctx, tlv_tag_t template_tag, bool before_ac2) {
    if (!ctx) {
        return PM3_EINVARG;
    }

    const struct tlv *script = tlvdb_get(ctx->card, template_tag, NULL);
    if (!script || script->len < 2) {
        return PM3_SUCCESS;
    }

    PrintAndLogEx(INFO, "Issuer script template %04X (%s AC2): %zu bytes",
                  template_tag, before_ac2 ? "before" : "after", script->len);

    const unsigned char *p = script->value;
    size_t left = script->len;
    while (left >= 2) {
        struct tlv e;
        if (!tlv_parse_tl(&p, &left, &e)) {
            break;
        }
        if (e.tag != 0x86 || e.len < 4) {
            continue;
        }

        uint8_t ins = e.value[1];
        if (script_ins_sensitive(ins)) {
            PrintAndLogEx(INFO, " Script INS=%02x [SCRIPT REDACTED]", ins);
        } else {
            PrintAndLogEx(INFO, " Script: %s", sprint_hex_inrow(e.value, e.len));
        }

        sAPDU_t apdu = {
            .CLA = e.value[0],
            .INS = ins,
            .P1 = e.value[2],
            .P2 = e.value[3],
            .Lc = (uint8_t)(e.len > 4 ? e.len - 4 : 0),
            .data = (uint8_t *)(e.len > 4 ? e.value + 4 : NULL),
        };

        uint8_t buf[APDU_RES_LEN] = {0};
        size_t len = 0;
        uint16_t sw = 0;
        int res = EMVExchange(ctx->channel, true, apdu, buf, sizeof(buf), &len, &sw, ctx->card);
        if (res || sw != 0x9000) {
            PrintAndLogEx(WARNING, "Issuer script failed SW=%04x", sw);
            if (before_ac2) {
                emv_term_tvr_set_bit(ctx, 3, 0x40, true);
            } else {
                emv_term_tvr_set_bit(ctx, 3, 0x20, true);
            }
            return PM3_ESOFT;
        }
    }

    emv_term_tsi_set_bit(ctx, 0, 0x04, true);
    return PM3_SUCCESS;
}
