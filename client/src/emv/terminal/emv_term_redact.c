//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "emv_term_redact.h"
#include "../emvjson.h"
#include "commonutil.h"
#include "util.h"
#include <string.h>

static void redact_ac(json_t *crypto) {
    json_t *ac = json_object_get(crypto, "AC");
    if (!json_is_string(ac)) {
        return;
    }
    const char *s = json_string_value(ac);
    uint8_t buf[32] = {0};
    int len = 0;
    if (param_gethex_to_eol(s, 0, buf, sizeof(buf), &len) || len < 4) {
        return;
    }
    char out[64] = {0};
    snprintf(out, sizeof(out), "%02X%02X%02X%02X...", buf[0], buf[1], buf[2], buf[3]);
    json_object_set_new(crypto, "AC", json_string(out));
}

static void mask_track2(json_t *card) {
    json_t *t2 = json_object_get(card, "Track2");
    if (!json_is_string(t2)) {
        return;
    }
    json_object_set_new(card, "Track2", json_string("****"));
}

void emv_term_redact_session_json(json_t *root, bool full_export) {
    if (!root || full_export) {
        return;
    }

    json_t *crypto = json_object_get(root, "Cryptogram");
    if (json_is_object(crypto)) {
        redact_ac(crypto);
        json_object_del(crypto, "IAD");
    }

    json_t *card = json_object_get(root, "Card");
    if (json_is_object(card)) {
        mask_track2(card);
        json_object_del(card, "9F10");
    }
}
