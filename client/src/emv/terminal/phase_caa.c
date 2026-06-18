//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "phase_caa.h"
#include "emv_transaction.h"
#include "emv_term_tvr.h"
#include "../dol.h"
#include "../emv_tags.h"
#include "ui.h"
#include "proxmark3.h"
#include <string.h>

#define EMVAC_AC_MASK  0xC0
#define EMVAC_CDAREQ   0x10

static uint8_t legacy_ref_control(emv_term_ctx_t *ctx, bool cda) {
    if (GetCardPSVendor(ctx->aid, ctx->aid_len) == CV_INTERAC) {
        return EMVAC_ARQC_BYTE;
    }
    if (cda && ctx->tr_type == TT_CDA) {
        return EMVAC_TC_BYTE + EMVAC_CDAREQ;
    }
    return EMVAC_TC_BYTE;
}

static uint8_t ac_ref_control(emv_term_ctx_t *ctx, bool ac2, bool cda) {
    if (ac2) {
        if (ctx->arc[0] == '0' && ctx->arc[1] == '0') {
            return EMVAC_TC_BYTE;
        }
        if (ctx->arc[0] == '0' && ctx->arc[1] == '5') {
            return EMVAC_AAC_BYTE;
        }
        return EMVAC_TC_BYTE;
    }
    if (ctx->requested_ac) {
        if (cda && ctx->tr_type == TT_CDA) {
            return ctx->requested_ac + EMVAC_CDAREQ;
        }
        return ctx->requested_ac;
    }
    return legacy_ref_control(ctx, cda);
}

static void record_ac1_result(emv_term_ctx_t *ctx) {
    uint8_t CID = 0;
    if (tlvdb_get_uint8(ctx->card, 0x9f27, &CID)) {
        ctx->ac1_cid = CID;
        ctx->ac1_performed = true;
        ctx->outcome = emv_transaction_outcome_from_cid(CID);
        if ((CID & EMVAC_AC_MASK) != ctx->requested_ac && ctx->requested_ac) {
            emv_term_tvr_set_bit(ctx, 4, 0x04, true);
            PrintAndLogEx(WARNING, "CID type mismatch with TAA request");
        }
    }
}

static int gen_ac(emv_term_ctx_t *ctx, uint8_t ref_control, struct tlv *cdol_tlv, bool is_ac1) {
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    PrintAndLogEx(INFO, "* * GEN AC P1=%02x data[%zu]: %s", ref_control, cdol_tlv->len,
                  sprint_hex(cdol_tlv->value, cdol_tlv->len));

    int res = EMVAC(ctx->channel, true, ref_control, (uint8_t *)cdol_tlv->value, cdol_tlv->len,
                    buf, sizeof(buf), &len, &sw, ctx->card);
    if (res) {
        PrintAndLogEx(ERR, "GEN AC error(%d): %4x", res, sw);
        return PM3_ERFTRANS;
    }

    if (ctx->opts.decode_tlv) {
        TLVPrintFromBuffer(buf, len);
    }

    if (is_ac1 && ctx->tr_type == TT_CDA) {
        struct tlvdb *ac_tlv = tlvdb_parse_multi(buf, len);
        if (ac_tlv && tlvdb_get(ac_tlv, 0x9f4b, NULL)) {
            ctx->cda_verify_performed = true;
            if (trCDA(ctx->card, ac_tlv, ctx->pdol_data_tlv, cdol_tlv) == 0) {
                ctx->cda_verify_ok = true;
                PrintAndLogEx(SUCCESS, "CDA verify: OK");
            } else {
                ctx->cda_verify_ok = false;
                emv_term_tvr_set_bit(ctx, 4, 0x04, true);
                PrintAndLogEx(WARNING, "CDA verify: FAIL");
            }
        }
        if (ac_tlv) {
            free(ac_tlv);
        }
    }

    emv_transaction_process_ac_format1(ctx->card, buf, len, ctx->opts.decode_tlv);
    return PM3_SUCCESS;
}

static void save_cdol1(emv_term_ctx_t *ctx, struct tlv *cdol) {
    if (!ctx || !cdol || !cdol->len) {
        return;
    }
    if (cdol->len <= sizeof(ctx->cdol1_data)) {
        memcpy(ctx->cdol1_data, cdol->value, cdol->len);
        ctx->cdol1_len = cdol->len;
    }
}

int phase_caa_run(emv_term_ctx_t *ctx) {
    if (!ctx) {
        return PM3_EINVARG;
    }

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res;

    uint16_t AIP = 0;
    const struct tlv *AIPtlv = tlvdb_get(ctx->card, 0x82, NULL);
    if (AIPtlv) {
        AIP = AIPtlv->value[0] + AIPtlv->value[1] * 0x100;
    }

    if (ctx->tr_type == TT_QVSDCMCHIP || ctx->tr_type == TT_CDA) {
        const struct tlv *AC = tlvdb_get(ctx->card, 0x9F26, NULL);
        if (AC) {
            PrintAndLogEx(INFO, "\n--> qVSDC transaction (AC from GPO).");
            ctx->ac1_performed = true;
            ctx->outcome = EMV_OUTCOME_APPROVED_OFFLINE;
            return PM3_SUCCESS;
        }
    }

    if (GetCardPSVendor(ctx->aid, ctx->aid_len) == CV_MASTERCARD &&
            (ctx->tr_type == TT_QVSDCMCHIP || ctx->tr_type == TT_CDA)) {
        const struct tlv *CDOL1 = tlvdb_get(ctx->card, 0x8c, NULL);
        if (CDOL1) {
            PrintAndLogEx(INFO, "\n--> Mastercard M/Chip GEN AC1.");
            res = EMVGenerateChallenge(ctx->channel, true, buf, sizeof(buf), &len, &sw, ctx->card);
            if (res) {
                return PM3_ERFTRANS;
            }
            struct tlvdb *ICCDynN = tlvdb_fixed(0x9f4c, len, buf);
            tlvdb_add(ctx->card, ICCDynN);

            struct tlv *cdol = dol_process(CDOL1, ctx->card, 0x01);
            if (!cdol) {
                return PM3_ESOFT;
            }
            res = gen_ac(ctx, ac_ref_control(ctx, false, true), cdol, true);
            save_cdol1(ctx, cdol);
            free(cdol);
            if (res) {
                return res;
            }
            record_ac1_result(ctx);
            return PM3_SUCCESS;
        }
    }

    if (AIP & 0x8000 && ctx->tr_type == TT_MSD) {
        PrintAndLogEx(INFO, "\n--> MSD transaction (mag-stripe mode - no GEN AC).");
        ctx->ac1_performed = false;
        ctx->outcome = EMV_OUTCOME_APPROVED_OFFLINE;
        emv_term_tsi_set_bit(ctx, 0, 0x08, true);
        return PM3_SUCCESS;
    }

    const struct tlv *CDOL1 = tlvdb_get(ctx->card, 0x8c, NULL);
    if (CDOL1 && (ctx->tr_type == TT_VSDC || ctx->tr_type == TT_CDA ||
                  GetCardPSVendor(ctx->aid, ctx->aid_len) == CV_VISA ||
                  GetCardPSVendor(ctx->aid, ctx->aid_len) == CV_INTERAC)) {

        PrintAndLogEx(INFO, "\n--> GEN AC1 (Card Action Analysis).");
        struct tlv *cdol = dol_process(CDOL1, ctx->card, 0x01);
        if (!cdol) {
            PrintAndLogEx(ERR, "Error: can't create CDOL1 TLV.");
            return PM3_ESOFT;
        }

        bool cda = (ctx->tr_type == TT_CDA);
        res = gen_ac(ctx, ac_ref_control(ctx, false, cda), cdol, true);
        save_cdol1(ctx, cdol);
        free(cdol);
        if (res) {
            return res;
        }
        record_ac1_result(ctx);

        uint8_t CID = ctx->ac1_cid;
        if ((CID & EMVAC_AC_MASK) == EMVAC_AAC_BYTE) {
            PrintAndLogEx(INFO, "AC1 result: AAC (declined)");
        } else if ((CID & EMVAC_AC_MASK) == EMVAC_TC_BYTE) {
            PrintAndLogEx(INFO, "AC1 result: TC (approved offline)");
        } else if ((CID & EMVAC_AC_MASK) == EMVAC_ARQC_BYTE) {
            PrintAndLogEx(INFO, "AC1 result: ARQC (online required)");
        }
        return PM3_SUCCESS;
    }

    PrintAndLogEx(INFO, "No GEN AC1 path for current transaction type / card.");
    return PM3_SUCCESS;
}

int phase_caa_ac2(emv_term_ctx_t *ctx) {
    if (!ctx) {
        return PM3_EINVARG;
    }

    if (!ctx->ac1_performed) {
        PrintAndLogEx(WARNING, "AC2 skipped - AC1 not performed");
        return PM3_ESOFT;
    }

    if ((ctx->ac1_cid & EMVAC_AC_MASK) != EMVAC_ARQC_BYTE) {
        PrintAndLogEx(INFO, "AC2 not required (first AC was not ARQC)");
        return PM3_SUCCESS;
    }

    const struct tlv *CDOL2 = tlvdb_get(ctx->card, 0x8d, NULL);
    if (!CDOL2) {
        PrintAndLogEx(WARNING, "CDOL2 (8D) not found - cannot perform AC2");
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "\n* * GEN AC2 (second Card Action Analysis)");
    struct tlv *cdol2 = dol_process(CDOL2, ctx->card, 0x01);
    if (!cdol2) {
        PrintAndLogEx(ERR, "Error: can't create CDOL2 TLV.");
        return PM3_ESOFT;
    }

    int res = gen_ac(ctx, ac_ref_control(ctx, true, false), cdol2, false);
    free(cdol2);
    if (res) {
        return res;
    }

    uint8_t CID = 0;
    if (tlvdb_get_uint8(ctx->card, 0x9f27, &CID)) {
        ctx->ac2_cid = CID;
        ctx->ac2_performed = true;
        ctx->outcome = emv_transaction_outcome_from_cid(CID);
        if ((CID & EMVAC_AC_MASK) == EMVAC_TC_BYTE) {
            ctx->outcome = EMV_OUTCOME_APPROVED_ONLINE;
            PrintAndLogEx(SUCCESS, "AC2 result: TC (approved online)");
        } else if ((CID & EMVAC_AC_MASK) == EMVAC_AAC_BYTE) {
            ctx->outcome = EMV_OUTCOME_DECLINED;
            PrintAndLogEx(WARNING, "AC2 result: AAC (declined)");
        }
    }

    emv_term_tsi_set_bit(ctx, 0, 0x08, true);
    return PM3_SUCCESS;
}
