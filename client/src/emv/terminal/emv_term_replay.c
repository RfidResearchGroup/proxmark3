//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "emv_term_replay.h"
#include "emv_terminal.h"
#include "emv_term_load.h"
#include "emv_term_session.h"
#include "emv_term_timing.h"
#include "emv_term_pcap.h"
#include "emv_transaction.h"
#include "ui.h"
#include <string.h>

static emv_term_phase_t parse_phase(const char *name) {
    if (!name || !name[0]) {
        return EMV_PHASE_COUNT;
    }
    for (emv_term_phase_t p = EMV_PHASE_INIT; p < EMV_PHASE_COUNT; p++) {
        if (strcmp(name, emv_term_phase_name(p)) == 0) {
            return p;
        }
    }
    return EMV_PHASE_COUNT;
}

static bool should_run_online_replay(const emv_term_ctx_t *ctx) {
    if (!ctx->ac1_performed || (ctx->ac1_cid & 0xC0) != EMVAC_ARQC_BYTE) {
        return false;
    }
    if (ctx->opts.auto_online || ctx->opts.host_sim) {
        return true;
    }
    if (ctx->opts.host_keys && ctx->opts.host_keys[0]) {
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

int emv_term_replay_run(emv_term_ctx_t *ctx, const char *from_phase, const char *to_phase) {
    if (!ctx || !ctx->opts.mock_apdu || !ctx->opts.mock_apdu[0]) {
        PrintAndLogEx(ERR, "Replay requires --mock-apdu-file");
        return PM3_EINVARG;
    }

    emv_term_phase_t start = parse_phase(from_phase);
    emv_term_phase_t end = parse_phase(to_phase);
    if (from_phase && from_phase[0] && start >= EMV_PHASE_COUNT) {
        PrintAndLogEx(ERR, "Unknown --from-phase '%s'", from_phase);
        return PM3_EINVARG;
    }
    if (to_phase && to_phase[0] && end >= EMV_PHASE_COUNT) {
        PrintAndLogEx(ERR, "Unknown --to-phase '%s'", to_phase);
        return PM3_EINVARG;
    }

    if (start >= EMV_PHASE_COUNT) {
        start = EMV_PHASE_INIT;
    }
    if (end >= EMV_PHASE_COUNT) {
        end = EMV_PHASE_COMPLETE;
    }
    if (start > end) {
        PrintAndLogEx(ERR, "Replay range invalid: from=%s to=%s",
                      emv_term_phase_name(start), emv_term_phase_name(end));
        return PM3_EINVARG;
    }

    if (start > EMV_PHASE_INIT && ctx->opts.session_path && ctx->opts.session_path[0]) {
        emv_term_session_load_json(ctx, ctx->opts.session_path);
    } else if (start > EMV_PHASE_INIT) {
        char sidecar[FILE_PATH_SIZE];
        str_copy(sidecar, sizeof(sidecar), ctx->opts.mock_apdu);
        char *slash = strrchr(sidecar, '/');
        if (slash) {
            *slash = '\0';
            strncat(sidecar, "/card_tlv.json", sizeof(sidecar) - strlen(sidecar) - 1);
            if (emv_term_load_card_tlv(ctx, sidecar) == PM3_SUCCESS) {
                PrintAndLogEx(INFO, "Replay loaded card TLV sidecar: %s", sidecar);
            }
        }
    }

    int last_res = PM3_SUCCESS;
    for (emv_term_phase_t p = start; p <= end; p++) {
        int res = emv_terminal_step(ctx, p);
        if (res && p == EMV_PHASE_CVM && res == PM3_ESOFT) {
            last_res = PM3_SUCCESS;
        } else if (res) {
            last_res = res;
            if (ctx->outcome == EMV_OUTCOME_UNKNOWN) {
                ctx->outcome = EMV_OUTCOME_ABORTED;
            }
            break;
        } else {
            last_res = PM3_SUCCESS;
        }

        if (p == EMV_PHASE_CAA && should_run_online_replay(ctx) &&
            end >= EMV_PHASE_ONLINE && start <= EMV_PHASE_ONLINE) {
            res = emv_terminal_step(ctx, EMV_PHASE_ONLINE);
            if (res && res != PM3_ESOFT) {
                last_res = res;
            }
            if (end >= EMV_PHASE_COMPLETE) {
                emv_terminal_step(ctx, EMV_PHASE_COMPLETE);
            }
            break;
        }
    }

    if (ctx->outcome == EMV_OUTCOME_UNKNOWN && ctx->ac1_performed) {
        ctx->outcome = emv_transaction_outcome_from_cid(ctx->ac1_cid);
    }

    if (ctx->opts.timing_report) {
        emv_term_timing_print_summary(ctx);
    }

    const char *outpath = ctx->opts.output_session;
    if (!outpath || !outpath[0]) {
        outpath = ctx->session_file[0] ? ctx->session_file : NULL;
    }
    if (outpath && outpath[0]) {
        emv_term_session_save_json(ctx, outpath);
        if (ctx->opts.pcap_out && ctx->opts.pcap_out[0]) {
            emv_term_pcap_write_meta(ctx->opts.pcap_out, outpath);
        }
    }

    return last_res;
}
