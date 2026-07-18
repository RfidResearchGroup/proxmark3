//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "terminal_sim_export_test.h"
#include "../terminal/emv_term_sim_export.h"
#include "terminal_test_util.h"
#include "ui.h"
#include "fileutils.h"
#include <jansson.h>
#include <stdio.h>

static int test_export_session_json(bool verbose) {
    char path[256];
    emv_term_test_temp_path(path, sizeof(path), "sim_export_test.json");

    json_t *sess = json_object();
    json_t *card = json_object();
    json_t *crypto = json_object();
    JsonSaveStr(card, "AID", "A0000000031010");
    JsonSaveStr(card, "CVMResults", "010002");
    JsonSaveStr(crypto, "Type", "ARQC");
    JsonSaveStr(crypto, "AC", "AABBCCDDEEFF0011");
    JsonSaveStr(crypto, "ATC", "0042");
    json_object_set_new(sess, "Card", card);
    json_object_set_new(sess, "Cryptogram", crypto);
    JsonSaveStr(sess, "Outcome", "online_required");

    if (json_dump_file(sess, path, JSON_INDENT(2))) {
        json_decref(sess);
        return 1;
    }
    json_decref(sess);

    char out[256];
    emv_term_test_temp_path(out, sizeof(out), "sim_patch.json");
    if (emv_term_sim_export_session(path, out) != PM3_SUCCESS) {
        remove(path);
        return 1;
    }

    json_error_t error;
    json_t *patch = json_load_file(out, 0, &error);
    if (!patch) {
        remove(path);
        remove(out);
        return 1;
    }

    json_t *card_patch = json_object_get(patch, "CardPatch");
    json_t *app = json_is_object(card_patch) ? json_object_get(card_patch, "ApplicationData") : NULL;
    json_t *ac = json_is_object(app) ? json_object_get(app, "9F26") : NULL;
    int fail = !json_is_string(ac);
    if (verbose && !fail) {
        PrintAndLogEx(SUCCESS, "export-sim patch OK");
    }

    json_decref(patch);
    remove(path);
    remove(out);
    return fail ? 1 : 0;
}

int exec_terminal_sim_export_test(bool verbose) {
    return test_export_session_json(verbose);
}
