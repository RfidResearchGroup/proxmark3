//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "terminal_replay_test.h"
#include "../terminal/emv_term_ctx.h"
#include "../terminal/emv_term_session.h"
#include "../terminal/emv_term_load.h"
#include "../terminal/emv_terminal.h"
#include "../terminal/emv_term_timing.h"
#include "terminal_test_util.h"
#include "ui.h"
#include "fileutils.h"
#include <jansson.h>
#include <stdio.h>
#include <string.h>

static int fixtures_root(char *out, size_t outlen) {
    const char *paths[] = {
        "client/src/emv/test/fixtures",
        "src/emv/test/fixtures",
        NULL,
    };
    for (int i = 0; paths[i]; i++) {
        if (fileExists(paths[i])) {
            str_copy(out, outlen, paths[i]);
            return PM3_SUCCESS;
        }
    }
    return PM3_ESOFT;
}

static int test_replay_outcome(bool verbose) {
    char root[FILE_PATH_SIZE];
    if (fixtures_root(root, sizeof(root))) {
        return 1;
    }

    char card_path[FILE_PATH_SIZE];
    str_copy(card_path, sizeof(card_path), root);
    strncat(card_path, "/taa_denial_expired/card_tlv.json", sizeof(card_path) - strlen(card_path) - 1);
    if (!fileExists(card_path)) {
        return 1;
    }

    emv_term_cli_opts_t opts = {0};
    opts.timing_report = true;
    emv_term_ctx_t ctx;
    if (emv_term_ctx_init(&ctx, &opts) != PM3_SUCCESS) {
        return 1;
    }
    if (emv_term_load_card_tlv(&ctx, card_path) != PM3_SUCCESS) {
        emv_term_ctx_free(&ctx);
        return 1;
    }

    int res = emv_terminal_step(&ctx, EMV_PHASE_TAA);
    if (res != PM3_SUCCESS) {
        emv_term_ctx_free(&ctx);
        return 1;
    }

    if (ctx.requested_ac != EMVAC_AAC_BYTE) {
        if (verbose) {
            PrintAndLogEx(ERR, "replay/timing: expected AAC request, got %02x", ctx.requested_ac);
        }
        emv_term_ctx_free(&ctx);
        return 1;
    }

    if (ctx.event_count == 0) {
        if (verbose) {
            PrintAndLogEx(ERR, "replay/timing: no phase events");
        }
        emv_term_ctx_free(&ctx);
        return 1;
    }

    char path[256];
    emv_term_test_temp_path(path, sizeof(path), "replay_test.json");
    if (emv_term_session_save_json(&ctx, path) != PM3_SUCCESS) {
        emv_term_ctx_free(&ctx);
        return 1;
    }
    emv_term_ctx_free(&ctx);

    json_error_t error;
    json_t *root_j = json_load_file(path, 0, &error);
    remove(path);
    if (!root_j) {
        return 1;
    }

    json_t *phases = json_object_get(root_j, "Phases");
    json_t *pe = json_is_array(phases) && json_array_size(phases) ? json_array_get(phases, 0) : NULL;
    json_t *dur = json_is_object(pe) ? json_object_get(pe, "duration_ms") : NULL;
    int fail = !json_is_integer(dur);
    json_decref(root_j);

    if (verbose && !fail) {
        PrintAndLogEx(SUCCESS, "replay outcome + timing OK");
    }
    return fail ? 1 : 0;
}

int exec_terminal_replay_test(bool verbose) {
    return test_replay_outcome(verbose);
}
