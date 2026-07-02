//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "emv_term_session_view.h"
#include "emv_term_tvr.h"
#include "ui.h"
#include "commonutil.h"
#include <jansson.h>
#include <string.h>

static void print_tvr_bits(const char *hex) {
    uint8_t tvr[5] = {0};
    int len = 0;
    if (param_gethex_to_eol(hex, 0, tvr, sizeof(tvr), &len) || len < 5) {
        return;
    }
    PrintAndLogEx(INFO, "TVR: %s", hex);
    if (tvr[1] & 0x04) {
        PrintAndLogEx(INFO, "  [byte2 b3] Application expired");
    }
    if (tvr[1] & 0x10) {
        PrintAndLogEx(INFO, "  [byte2 b5] Card on exception file");
    }
    if (tvr[2] & 0x80) {
        PrintAndLogEx(INFO, "  [byte3 b8] CVM not successful");
    }
    if (tvr[3] & 0x80) {
        PrintAndLogEx(INFO, "  [byte4 b8] Exceeds floor limit");
    }
    if (tvr[4] & 0x04) {
        PrintAndLogEx(INFO, "  [byte5 b3] CDA failed");
    }
}

static void print_phases(json_t *phases) {
    if (!json_is_array(phases)) {
        return;
    }
    PrintAndLogEx(INFO, "Phases:");
    size_t n = json_array_size(phases);
    for (size_t i = 0; i < n; i++) {
        json_t *pe = json_array_get(phases, i);
        if (!json_is_object(pe)) {
            continue;
        }
        json_t *jname = json_object_get(pe, "name");
        json_t *jres = json_object_get(pe, "result");
        const char *name = json_is_string(jname) ? json_string_value(jname) : "?";
        int res = json_is_integer(jres) ? (int)json_integer_value(jres) : 0;
        PrintAndLogEx(INFO, "  %-10s %s", name, res ? "FAIL" : "OK");
    }
}

int emv_term_session_print(const char *path, bool as_json) {
    if (!path || !path[0]) {
        return PM3_EINVARG;
    }

    json_error_t error;
    json_t *root = json_load_file(path, 0, &error);
    if (!root) {
        PrintAndLogEx(ERR, "Session load error: %s", error.text);
        return PM3_ESOFT;
    }

    if (as_json) {
        char *dump = json_dumps(root, JSON_INDENT(2));
        if (dump) {
            PrintAndLogEx(NORMAL, "%s", dump);
            free(dump);
        }
        json_decref(root);
        return PM3_SUCCESS;
    }

    char outcome[64] = {0};
    json_t *jout = json_object_get(root, "Outcome");
    if (json_is_string(jout)) {
        str_copy(outcome, sizeof(outcome), json_string_value(jout));
    }
    PrintAndLogEx(INFO, "Outcome: %s", outcome[0] ? outcome : "unknown");

    json_t *card = json_object_get(root, "Card");
    if (json_is_object(card)) {
        json_t *aid = json_object_get(card, "AID");
        json_t *pan = json_object_get(card, "PAN");
        if (json_is_string(aid)) {
            PrintAndLogEx(INFO, "AID: %s", json_string_value(aid));
        }
        if (json_is_string(pan)) {
            PrintAndLogEx(INFO, "PAN: %s", json_string_value(pan));
        }
    }

    print_phases(json_object_get(root, "Phases"));

    json_t *crypto = json_object_get(root, "Cryptogram");
    if (json_is_object(crypto)) {
        json_t *jtype = json_object_get(crypto, "Type");
        json_t *jac = json_object_get(crypto, "AC");
        if (json_is_string(jtype)) {
            PrintAndLogEx(INFO, "Cryptogram type: %s", json_string_value(jtype));
        }
        if (json_is_string(jac)) {
            PrintAndLogEx(INFO, "AC: %s", json_string_value(jac));
        }
    }

    json_t *tvr = json_object_get(root, "TVR");
    if (json_is_string(tvr)) {
        print_tvr_bits(json_string_value(tvr));
    } else if (json_is_object(card)) {
        json_t *jtvr = json_object_get(card, "TVR");
        if (json_is_string(jtvr)) {
            print_tvr_bits(json_string_value(jtvr));
        }
    }

    json_decref(root);
    return PM3_SUCCESS;
}
