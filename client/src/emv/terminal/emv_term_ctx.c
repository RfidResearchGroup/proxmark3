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
// EMV terminal emulator - session context
//-----------------------------------------------------------------------------

#include "emv_term_ctx.h"
#include "emv_term_mock.h"
#include "emv_term_exception.h"
#include "emv_term_secure.h"
#include "emv_term_pcap.h"
#include "../emv_pk.h"
#include "proxmark3.h"
#include "util.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "ui.h"

static const char *phase_names[] = {
    "init",
    "oda",
    "restrict",
    "cvm",
    "trm",
    "taa",
    "caa",
    "online",
    "complete",
};

static const char *outcome_names[] = {
    "unknown",
    "approved_offline",
    "declined",
    "online_required",
    "approved_online",
    "aborted",
};

const char *emv_term_phase_name(emv_term_phase_t phase) {
    if (phase >= EMV_PHASE_COUNT) {
        return "invalid";
    }
    return phase_names[phase];
}

const char *emv_term_outcome_str(emv_term_outcome_t outcome) {
    if (outcome > EMV_OUTCOME_ABORTED) {
        return "unknown";
    }
    return outcome_names[outcome];
}

int emv_term_ctx_init(emv_term_ctx_t *ctx, const emv_term_cli_opts_t *opts) {
    if (!ctx || !opts) {
        return PM3_EINVARG;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->opts = *opts;
    ctx->channel = opts->channel;
    ctx->tr_type = opts->tr_type;
    ctx->outcome = EMV_OUTCOME_UNKNOWN;
    ctx->current_phase = EMV_PHASE_INIT;

    const char *al = "Terminal TLV tree";
    ctx->terminal = tlvdb_fixed(1, strlen(al), (const unsigned char *)al);

    const char *alr = "Root terminal TLV tree";
    ctx->card = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);

    const char *als = "Applets list";
    ctx->select = tlvdb_fixed(1, strlen(als), (const unsigned char *)als);

    if (opts->session_path && opts->session_path[0]) {
        str_copy(ctx->session_file, sizeof(ctx->session_file), opts->session_path);
    }

    ctx->event_cap = 16;
    ctx->events = calloc(ctx->event_cap, sizeof(emv_phase_event_t));
    if (!ctx->events) {
        emv_term_ctx_free(ctx);
        return PM3_EMALLOC;
    }

    return PM3_SUCCESS;
}

int emv_term_cli_setup(emv_term_ctx_t *ctx) {
    if (!ctx) {
        return PM3_EINVARG;
    }

    if (ctx->opts.mock_apdu && ctx->opts.mock_apdu[0]) {
        int res = emv_term_mock_load(ctx->opts.mock_apdu);
        if (res) {
            return res;
        }
    }

    if (ctx->opts.host_keys && ctx->opts.host_keys[0]) {
        str_copy(ctx->host_keys_path, sizeof(ctx->host_keys_path), ctx->opts.host_keys);
    }

    if (ctx->opts.host_sim) {
        ctx->opts.host_sim = true;
    }

    if (ctx->opts.exception_file && ctx->opts.exception_file[0]) {
        ctx->exception_file = emv_term_exception_load(ctx->opts.exception_file);
    }

    if (ctx->opts.capk_extra && ctx->opts.capk_extra[0]) {
        emv_pk_load_extra_file(ctx->opts.capk_extra);
    }

    if (ctx->opts.pcap_out && ctx->opts.pcap_out[0]) {
        bool redact = !ctx->opts.no_redact;
        int pres = emv_term_pcap_open(ctx->opts.pcap_out, redact);
        if (pres) {
            return pres;
        }
    }

    return PM3_SUCCESS;
}

void emv_term_ctx_free(emv_term_ctx_t *ctx) {
    if (!ctx) {
        return;
    }

    if (ctx->pdol_data_tlv) {
        free(ctx->pdol_data_tlv);
        ctx->pdol_data_tlv = NULL;
    }

    tlvdb_free(ctx->select);
    ctx->select = NULL;

    tlvdb_free(ctx->card);
    ctx->card = NULL;

    tlvdb_free(ctx->terminal);
    ctx->terminal = NULL;

    free(ctx->events);
    ctx->events = NULL;
    ctx->event_count = 0;
    ctx->event_cap = 0;

    emv_term_exception_free(ctx->exception_file);
    ctx->exception_file = NULL;
    emv_term_secure_zero(ctx->online_pin_block, sizeof(ctx->online_pin_block));
    emv_term_pcap_close();

    memset(ctx, 0, sizeof(*ctx));
}

int emv_term_event_add(emv_term_ctx_t *ctx, emv_term_phase_t phase, int result, uint16_t sw, const char *note) {
    if (!ctx) {
        return PM3_EINVARG;
    }

    if (ctx->event_count >= ctx->event_cap) {
        size_t new_cap = ctx->event_cap * 2;
        emv_phase_event_t *ev = realloc(ctx->events, new_cap * sizeof(emv_phase_event_t));
        if (!ev) {
            return PM3_EMALLOC;
        }
        ctx->events = ev;
        ctx->event_cap = new_cap;
    }

    emv_phase_event_t *e = &ctx->events[ctx->event_count++];
    e->id = phase;
    e->result = result;
    e->sw = sw;
    e->ts_ms = (uint64_t)time(NULL) * 1000ULL;
    e->duration_ms = 0;
    e->note[0] = '\0';
    if (note) {
        str_copy(e->note, sizeof(e->note), note);
    }

    if (ctx->opts.trace_phases) {
        PrintAndLogEx(INFO, "[phase] %s result=%d sw=%04x %s",
                      emv_term_phase_name(phase), result, sw, note ? note : "");
    }

    return PM3_SUCCESS;
}

int emv_term_event_add_timed(emv_term_ctx_t *ctx, emv_term_phase_t phase, int result, uint16_t sw,
                             const char *note, uint32_t duration_ms) {
    int res = emv_term_event_add(ctx, phase, result, sw, note);
    if (res == PM3_SUCCESS && ctx->event_count > 0) {
        ctx->events[ctx->event_count - 1].duration_ms = duration_ms;
    }
    return res;
}

struct tlvdb *emv_term_get_root(emv_term_ctx_t *ctx) {
    if (!ctx) {
        return NULL;
    }
    return ctx->card;
}
