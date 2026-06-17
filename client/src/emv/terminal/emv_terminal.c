//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "emv_terminal.h"
#include "phase_init.h"
#include "phase_oda.h"
#include "phase_restrict.h"
#include "phase_cvm.h"
#include "phase_trm.h"
#include "phase_taa.h"
#include "phase_caa.h"
#include "phase_online.h"
#include "phase_complete.h"
#include "emv_transaction.h"
#include "emv_term_session.h"
#include "emv_term_scheme.h"
#include "emv_term_mock.h"
#include "emv_term_sim_export.h"
#include "emv_term_timing.h"
#include "emv_term_pcap.h"
#include "../emvcore.h"
#include "comms.h"
#include "ui.h"
#include "util_posix.h"
#include <string.h>

static bool stop_after_phase(const emv_term_ctx_t *ctx, emv_term_phase_t phase) {
    if (!ctx->opts.stop_after || !ctx->opts.stop_after[0]) {
        return false;
    }
    return strcmp(ctx->opts.stop_after, emv_term_phase_name(phase)) == 0;
}

static bool should_run_online(const emv_term_ctx_t *ctx) {
    if (!ctx->ac1_performed || (ctx->ac1_cid & 0xC0) != EMVAC_ARQC_BYTE) {
        return false;
    }
    if (ctx->opts.auto_online) {
        return true;
    }
    if (ctx->opts.host_sim) {
        return true;
    }
    if (ctx->opts.host_keys && ctx->opts.host_keys[0]) {
        return true;
    }
    if (ctx->opts.host_tcp && ctx->opts.host_tcp[0]) {
        return true;
    }
    if (ctx->opts.arc && ctx->opts.arc[0]) {
        return true;
    }
    if (ctx->opts.arpc && ctx->opts.arpc[0]) {
        return true;
    }
    return false;
}

static bool terminal_phase_needs_live_card(emv_term_phase_t phase) {
    switch (phase) {
        case EMV_PHASE_ODA:
        case EMV_PHASE_CVM:
        case EMV_PHASE_CAA:
        case EMV_PHASE_ONLINE:
            return true;
        case EMV_PHASE_INIT:
        case EMV_PHASE_RESTRICT:
        case EMV_PHASE_TRM:
        case EMV_PHASE_TAA:
        case EMV_PHASE_COMPLETE:
        case EMV_PHASE_COUNT:
            return false;
    }
    return false;
}

int emv_terminal_step(emv_term_ctx_t *ctx, emv_term_phase_t phase) {
    if (!ctx) {
        return PM3_EINVARG;
    }

    if (terminal_phase_needs_live_card(phase) && !emv_term_mock_active()) {
        int pres = EMVPrepareContactless(ctx->channel, ctx->opts.activate_field);
        if (pres) {
            return pres;
        }
        ctx->opts.activate_field = false;
    }

    int res = PM3_ENOTIMPL;
    uint16_t sw = 0;

    ctx->current_phase = phase;

    uint64_t t0 = 0;
    if (ctx->opts.timing_report) {
        t0 = msclock();
    }

    switch (phase) {
        case EMV_PHASE_INIT:
            res = phase_init_run(ctx);
            break;
        case EMV_PHASE_ODA:
            res = phase_oda_run(ctx);
            break;
        case EMV_PHASE_RESTRICT:
            res = phase_restrict_run(ctx);
            break;
        case EMV_PHASE_CVM:
            res = phase_cvm_run(ctx);
            break;
        case EMV_PHASE_TRM:
            res = phase_trm_run(ctx);
            break;
        case EMV_PHASE_TAA:
            res = phase_taa_run(ctx);
            break;
        case EMV_PHASE_CAA:
            res = phase_caa_run(ctx);
            break;
        case EMV_PHASE_ONLINE:
            res = phase_online_run(ctx);
            break;
        case EMV_PHASE_COMPLETE:
            res = phase_complete_run(ctx);
            break;
        case EMV_PHASE_COUNT:
        default:
            return PM3_EINVARG;
    }

    uint32_t duration_ms = 0;
    if (ctx->opts.timing_report) {
        duration_ms = (uint32_t)(msclock() - t0);
    }

    if (ctx->opts.timing_report) {
        emv_term_event_add_timed(ctx, phase, res, sw, NULL, duration_ms);
    } else {
        emv_term_event_add(ctx, phase, res, sw, NULL);
    }
    return res;
}

static int run_pipeline_phase(emv_term_ctx_t *ctx, emv_term_phase_t phase, int *last_res) {
    int res = emv_terminal_step(ctx, phase);

    if (res && phase == EMV_PHASE_CVM && res == PM3_ESOFT) {
        PrintAndLogEx(WARNING, "CVM phase failed — continuing for lab visibility");
        *last_res = PM3_SUCCESS;
    } else if (res && phase == EMV_PHASE_ONLINE && res == PM3_ESOFT) {
        PrintAndLogEx(WARNING, "Online phase failed — continuing to completion");
        if (ctx->outcome == EMV_OUTCOME_UNKNOWN) {
            ctx->outcome = EMV_OUTCOME_ONLINE_REQUIRED;
        }
        *last_res = PM3_SUCCESS;
    } else if (res) {
        *last_res = res;
        if (ctx->outcome == EMV_OUTCOME_UNKNOWN) {
            ctx->outcome = EMV_OUTCOME_ABORTED;
        }
        return res;
    } else {
        *last_res = PM3_SUCCESS;
    }

    if (stop_after_phase(ctx, phase)) {
        PrintAndLogEx(INFO, "Stopped after phase: %s", emv_term_phase_name(phase));
        return 1;
    }

    return 0;
}

int emv_terminal_run(emv_term_ctx_t *ctx) {
    if (!ctx) {
        return PM3_EINVARG;
    }

    emv_term_phase_t pipeline[] = {
        EMV_PHASE_INIT,
        EMV_PHASE_ODA,
        EMV_PHASE_RESTRICT,
        EMV_PHASE_CVM,
        EMV_PHASE_TRM,
        EMV_PHASE_TAA,
        EMV_PHASE_CAA,
    };

    int last_res = PM3_SUCCESS;

    for (size_t i = 0; i < sizeof(pipeline) / sizeof(pipeline[0]); i++) {
        if (run_pipeline_phase(ctx, pipeline[i], &last_res)) {
            goto finish;
        }
        if (pipeline[i] == EMV_PHASE_INIT && ctx->opts.scheme_profile && ctx->opts.scheme_profile[0]) {
            emv_term_scheme_info_t sinfo;
            if (emv_term_scheme_resolve(ctx->opts.scheme_profile, ctx->aid, ctx->aid_len, &sinfo) == PM3_SUCCESS) {
                emv_term_scheme_apply(ctx, &sinfo);
            }
        }
    }

    if (should_run_online(ctx)) {
        if (run_pipeline_phase(ctx, EMV_PHASE_ONLINE, &last_res)) {
            goto finish;
        }
    } else if (ctx->ac1_performed && (ctx->ac1_cid & 0xC0) == EMVAC_ARQC_BYTE &&
               ctx->outcome == EMV_OUTCOME_UNKNOWN) {
        ctx->outcome = EMV_OUTCOME_ONLINE_REQUIRED;
    }

    run_pipeline_phase(ctx, EMV_PHASE_COMPLETE, &last_res);

finish:
    if (ctx->outcome == EMV_OUTCOME_UNKNOWN) {
        if (ctx->ac2_performed) {
            ctx->outcome = emv_transaction_outcome_from_cid(ctx->ac2_cid);
            if ((ctx->ac2_cid & 0xC0) == EMVAC_TC_BYTE && ctx->online_performed) {
                ctx->outcome = EMV_OUTCOME_APPROVED_ONLINE;
            }
        } else if (ctx->ac1_performed) {
            ctx->outcome = emv_transaction_outcome_from_cid(ctx->ac1_cid);
        } else if (ctx->cvm_success) {
            ctx->outcome = EMV_OUTCOME_APPROVED_OFFLINE;
        }
    }

    const char *outpath = ctx->opts.output_session;
    if (!outpath || !outpath[0]) {
        outpath = ctx->session_file[0] ? ctx->session_file : NULL;
    }
    if (outpath && outpath[0]) {
        emv_term_session_save_json(ctx, outpath);
        if (ctx->opts.pcap_meta && ctx->opts.pcap_meta[0]) {
            emv_term_pcap_write_meta(ctx->opts.pcap_out, ctx->opts.pcap_meta);
        } else if (ctx->opts.pcap_out && ctx->opts.pcap_out[0]) {
            emv_term_pcap_write_meta(ctx->opts.pcap_out, outpath);
        }
    }

    if (ctx->opts.timing_report) {
        emv_term_timing_print_summary(ctx);
    }

    if (ctx->opts.export_sim && ctx->opts.export_sim[0]) {
        emv_term_sim_export_ctx(ctx, ctx->opts.export_sim);
    }

    DropFieldEx(ctx->channel);
    SetAPDULogging(false);

    PrintAndLogEx(SUCCESS, "[+] Terminal outcome: %s", emv_term_outcome_str(ctx->outcome));
    return last_res;
}
