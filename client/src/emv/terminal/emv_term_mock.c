//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "emv_term_mock.h"
#include "emv_term_pcap.h"
#include "ui.h"
#include "util.h"
#include "commonutil.h"
#include <jansson.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    char name[64];
    uint8_t capdu[APDU_RES_LEN];
    size_t capdu_len;
    uint8_t rapdu[APDU_RES_LEN];
    size_t rapdu_len;
    uint16_t sw;
} emv_mock_step_t;

static emv_mock_step_t *g_steps = NULL;
static size_t g_step_count = 0;
static size_t g_step_idx = 0;
static bool g_strict = false;

static int hex_to_buf(const char *hex, uint8_t *out, size_t *out_len, size_t max_len) {
    int buflen = 0;
    if (param_gethex_to_eol(hex, 0, out, max_len, &buflen)) {
        return PM3_ESOFT;
    }
    *out_len = (size_t)buflen;
    return PM3_SUCCESS;
}

static bool capdu_match(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen) {
    size_t min = alen < blen ? alen : blen;
    if (min == 0) {
        return false;
    }
    return memcmp(a, b, min) == 0;
}

int emv_term_mock_load(const char *path) {
    emv_term_mock_clear();

    json_error_t error;
    json_t *root = json_load_file(path, 0, &error);
    if (!root) {
        PrintAndLogEx(ERR, "Mock APDU load error line %d: %s", error.line, error.text);
        return PM3_ESOFT;
    }

    json_t *steps = json_object_get(root, "steps");
    if (!json_is_array(steps)) {
        json_decref(root);
        PrintAndLogEx(ERR, "Mock file missing steps array");
        return PM3_ESOFT;
    }

    size_t n = json_array_size(steps);
    g_steps = calloc(n, sizeof(emv_mock_step_t));
    if (!g_steps) {
        json_decref(root);
        return PM3_EMALLOC;
    }

    for (size_t i = 0; i < n; i++) {
        json_t *st = json_array_get(steps, i);
        if (!json_is_object(st)) {
            continue;
        }
        emv_mock_step_t *m = &g_steps[g_step_count];
        json_t *jn = json_object_get(st, "name");
        if (json_is_string(jn)) {
            str_copy(m->name, sizeof(m->name), json_string_value(jn));
        }
        json_t *jc = json_object_get(st, "capdu");
        json_t *jr = json_object_get(st, "rapdu");
        json_t *jsw = json_object_get(st, "sw");
        if (!json_is_string(jc) || hex_to_buf(json_string_value(jc), m->capdu, &m->capdu_len, sizeof(m->capdu))) {
            continue;
        }
        if (json_is_string(jr)) {
            hex_to_buf(json_string_value(jr), m->rapdu, &m->rapdu_len, sizeof(m->rapdu));
        }
        m->sw = 0x9000;
        if (json_is_string(jsw)) {
            uint8_t swb[2] = {0};
            size_t swl = 0;
            hex_to_buf(json_string_value(jsw), swb, &swl, 2);
            if (swl == 2) {
                m->sw = (swb[0] << 8) | swb[1];
            }
        }
        g_step_count++;
    }

    json_decref(root);
    g_step_idx = 0;
    PrintAndLogEx(SUCCESS, "Mock APDU loaded: %zu steps from %s", g_step_count, path);
    return g_step_count ? PM3_SUCCESS : PM3_ESOFT;
}

void emv_term_mock_clear(void) {
    free(g_steps);
    g_steps = NULL;
    g_step_count = 0;
    g_step_idx = 0;
}

bool emv_term_mock_active(void) {
    return g_steps != NULL && g_step_idx < g_step_count;
}

int emv_term_mock_exchange(Iso7816CommandChannel channel, bool activate_field, bool leave_field_on,
                           sAPDU_t apdu, bool include_le, uint8_t *result, size_t max_result_len,
                           size_t *result_len, uint16_t *sw) {
    (void)channel;
    (void)activate_field;
    (void)leave_field_on;
    (void)include_le;

    if (!g_steps || g_step_idx >= g_step_count) {
        PrintAndLogEx(ERR, "Mock APDU: no more steps");
        return PM3_ERFTRANS;
    }

    uint8_t capdu[APDU_RES_LEN] = {0};
    size_t capdu_len = 0;
    capdu[capdu_len++] = apdu.CLA;
    capdu[capdu_len++] = apdu.INS;
    capdu[capdu_len++] = apdu.P1;
    capdu[capdu_len++] = apdu.P2;
    if (apdu.Lc) {
        capdu[capdu_len++] = apdu.Lc;
        if (apdu.data && apdu.Lc) {
            memcpy(capdu + capdu_len, apdu.data, apdu.Lc);
            capdu_len += apdu.Lc;
        }
    }
    if (include_le) {
        capdu[capdu_len++] = 0x00;
    }

    emv_mock_step_t *m = &g_steps[g_step_idx];
    if (!capdu_match(capdu, capdu_len, m->capdu, m->capdu_len)) {
        PrintAndLogEx(WARNING, "Mock mismatch step %zu (%s)", g_step_idx, m->name);
        PrintAndLogEx(WARNING, " expected: %s", sprint_hex_inrow(m->capdu, m->capdu_len));
        PrintAndLogEx(WARNING, " got:      %s", sprint_hex_inrow(capdu, capdu_len));
        if (g_strict) {
            return PM3_ERFTRANS;
        }
    }

    if (m->rapdu_len > max_result_len) {
        return PM3_ESOFT;
    }
    memcpy(result, m->rapdu, m->rapdu_len);
    *result_len = m->rapdu_len;
    *sw = m->sw;

    PrintAndLogEx(INFO, "Mock step %zu/%zu: %s SW=%04x", g_step_idx + 1, g_step_count, m->name, m->sw);
    emv_term_pcap_record(capdu, capdu_len, m->rapdu, m->rapdu_len, m->sw);
    g_step_idx++;
    return PM3_SUCCESS;
}
