//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "emv_term_timing.h"
#include "ui.h"
#include <stdio.h>
#include <string.h>

void emv_term_timing_print_summary(const emv_term_ctx_t *ctx) {
    if (!ctx || !ctx->opts.timing_report || ctx->event_count == 0) {
        return;
    }

    uint64_t total = 0;
    char parts[256] = {0};
    size_t pos = 0;

    for (size_t i = 0; i < ctx->event_count; i++) {
        total += ctx->events[i].duration_ms;
        if (ctx->events[i].duration_ms == 0) {
            continue;
        }
        int n = snprintf(parts + pos, sizeof(parts) - pos, "%s%s=%u",
                         pos ? ", " : "",
                         emv_term_phase_name(ctx->events[i].id),
                         ctx->events[i].duration_ms);
        if (n > 0) {
            pos += (size_t)n;
        }
    }

    PrintAndLogEx(INFO, "Timing: Total: %llu ms (%s)", (unsigned long long)total, parts);
}
