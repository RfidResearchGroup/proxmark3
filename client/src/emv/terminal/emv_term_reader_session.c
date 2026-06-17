//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "emv_term_reader_session.h"
#include "../emvjson.h"
#include "ui.h"
#include <jansson.h>
#include <string.h>

int emv_term_reader_session_log(const char *path, const char *aid_hex, const char *note) {
    if (!path || !path[0]) {
        return PM3_EINVARG;
    }

    json_error_t error;
    json_t *root = json_load_file(path, 0, &error);
    if (!root) {
        root = json_object();
        json_t *file = json_object();
        JsonSaveStr(file, "Created", "proxmark3 emv reader trace");
        JsonSaveStr(file, "Version", "1");
        json_object_set_new(root, "File", file);
        json_object_set_new(root, "Outcome", json_string("unknown"));
    }

    json_t *phases = json_object_get(root, "Phases");
    if (!json_is_array(phases)) {
        phases = json_array();
        json_object_set_new(root, "Phases", phases);
    }

    json_t *pe = json_object();
    JsonSaveStr(pe, "name", "reader");
    JsonSaveInt(pe, "result", 0);
    if (aid_hex && aid_hex[0]) {
        json_t *card = json_object_get(root, "Card");
        if (!json_is_object(card)) {
            card = json_object();
            json_object_set_new(root, "Card", card);
        }
        JsonSaveStr(card, "AID", aid_hex);
    }
    if (note && note[0]) {
        JsonSaveStr(pe, "notes", note);
    }
    json_array_append_new(phases, pe);

    int res = json_dump_file(root, path, JSON_INDENT(2));
    json_decref(root);
    if (res) {
        PrintAndLogEx(ERR, "Failed to write reader session: %s", path);
        return PM3_ESOFT;
    }
    PrintAndLogEx(INFO, "Reader trace appended: %s", path);
    return PM3_SUCCESS;
}

void emv_term_reader_compare_hint(void) {
    PrintAndLogEx(INFO, "Terminal compare: reader observes card responses; terminal also drives CDOL/TVR/CVM/AC.");
    PrintAndLogEx(INFO, "Use `emv terminal run -a` on the same card to diff APDU sequences.");
}
