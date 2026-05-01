//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// High frequency Calypso commands
//-----------------------------------------------------------------------------

#include "cmdhfcalypso.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "aidsearch.h"
#include "cliparser.h"
#include "cmdparser.h"
#include "commonutil.h"
#include "comms.h"
#include "emv/emvcore.h"
#include "emv/tlv.h"
#include "fileutils.h"
#include "iso7816/apduinfo.h"
#include "iso7816/iso7816core.h"
#include "protocols.h"
#include "ui.h"
#include "util.h"

#define CALYPSO_SERIAL_LEN       8
#define CALYPSO_STARTUP_LEN      7
#define CALYPSO_MAX_AID_LEN      16
#define CALYPSO_ICC_RECORD_LEN   29
#define CALYPSO_ICC_SFI          0x02
#define CALYPSO_ICC_FILE_ID      0x0002
#define CALYPSO_TICKET_ENV_SFI   0x07
#define CALYPSO_TICKET_DIR_ID    0x2000
#define CALYPSO_TICKET_ENV_FILE_ID 0x2001
#define CALYPSO_ICC_SERIAL_OFF   0x0C
#define CALYPSO_ICC_CHECK_OFF    0x1B
#define CALYPSO_ICC_CHECK_META_OFF 0x10

#define CALYPSO_MANUFACTURERS_RESOURCE "calypso/manufacturers"
#define CALYPSO_IC_FAMILIES_RESOURCE   "calypso/ic_families"
#define CALYPSO_OPERATORS_RESOURCE     "calypso/operators"

typedef struct {
    bool has_df_name;
    uint8_t df_name[CALYPSO_MAX_AID_LEN];
    size_t df_name_len;
    bool has_serial;
    uint8_t serial[CALYPSO_SERIAL_LEN];
    bool has_startup;
    uint8_t startup[CALYPSO_STARTUP_LEN];
} calypso_fci_t;

typedef struct {
    uint8_t requested_aid[CALYPSO_MAX_AID_LEN];
    size_t requested_aid_len;
    uint8_t fci[APDU_RES_LEN];
    size_t fci_len;
    uint16_t sw;
    calypso_fci_t parsed;
} calypso_select_result_t;

typedef struct {
    bool found;
    const char *source;
    const char *aid_hex;
    const char *vendor;
    const char *name;
    const char *country;
    const char *description;
    const char *type;
    bool prefix;
    bool generic;
    size_t aid_len;
} calypso_aid_match_t;

typedef struct {
    json_t *root;
    calypso_aid_match_t selected_match;
    calypso_aid_match_t df_name_match;
    const calypso_aid_match_t *best;
} calypso_aid_attribution_t;

typedef struct {
    const char *path;
    json_t *root;
    bool loaded;
} calypso_resource_t;

static calypso_resource_t calypso_manufacturers_resource = {CALYPSO_MANUFACTURERS_RESOURCE, NULL, false};
static calypso_resource_t calypso_ic_families_resource = {CALYPSO_IC_FAMILIES_RESOURCE, NULL, false};
static calypso_resource_t calypso_operators_resource = {CALYPSO_OPERATORS_RESOURCE, NULL, false};

static const char *calypso_json_lookup_name(calypso_resource_t *resource, uint32_t id);

static int CmdHelp(const char *Cmd);

static const char *calypso_file_structure_desc(uint8_t subtype) {
    switch (subtype) {
        case 0x00:
            return "RFU / forbidden";
        case 0x01:
            return "Calypso Rev 2 minimum";
        case 0x02:
            return "Calypso Rev 2 minimum with MF files";
        case 0x03:
            return "Calypso Rev 2 extended";
        case 0x04:
            return "Calypso Rev 2 extended with MF files";
        case 0x05:
            return "CD Light / GTML compatibility";
        case 0x06:
            return "CD97 structure 2 compatibility";
        case 0x07:
            return "CD97 structure 3 compatibility";
        case 0x08:
            return "Extended ticketing with loyalty";
        case 0x09:
            return "Extended ticketing with loyalty and miscellaneous";
        case 0x20:
            return "Stored Value";
        case 0xFF:
            return "RFU / forbidden";
        default:
            if (subtype <= 0xBF) {
                return "Calypso generic example file structure";
            }
            return "Proprietary file structure";
    }
}

static const char *calypso_application_type_desc(uint8_t type) {
    if (type >= 0x01 && type <= 0x04) {
        return "Calypso Rev 1 or Rev 2";
    }
    if (type >= 0x06 && type <= 0x1F) {
        return "Calypso Rev 2";
    }
    if (type >= 0x20 && type <= 0x7F) {
        return "Calypso Rev 3";
    }
    if (type == 0xFF) {
        return "Not a Calypso application";
    }
    return "RFU";
}

static const char *calypso_platform_desc(uint8_t platform) {
    return calypso_json_lookup_name(&calypso_ic_families_resource, platform);
}

static const char *calypso_company_name(uint8_t id) {
    return calypso_json_lookup_name(&calypso_manufacturers_resource, id);
}

static const char *calypso_network_name(uint32_t id) {
    return calypso_json_lookup_name(&calypso_operators_resource, id);
}

static uint16_t calypso_session_buffer_size(uint8_t session_modifications) {
    switch (session_modifications) {
        case 0x06:
            return 215;
        case 0x07:
            return 256;
        case 0x08:
            return 304;
        case 0x09:
            return 362;
        case 0x0A:
            return 430;
        case 0x0B:
            return 512;
        case 0x0C:
            return 608;
        case 0x0D:
            return 724;
        case 0x0E:
            return 861;
        case 0x0F:
            return 1024;
        default:
            return 0;
    }
}

static const char *calypso_product_type_desc(const uint8_t *serial) {
    switch (serial[3] >> 6) {
        case 0:
            return "Calypso Prime / Light";
        case 1:
            return "Calypso Basic";
        default:
            return "Calypso HCE";
    }
}

static bool calypso_serial_is_hce(const uint8_t *serial) {
    return serial != NULL && (serial[3] & 0x80) != 0x00;
}

static const char *calypso_sprint_serial(const uint8_t *serial) {
    static char buf[CALYPSO_SERIAL_LEN * 3 + 1];

    if (calypso_serial_is_hce(serial) == false) {
        return sprint_hex(serial, CALYPSO_SERIAL_LEN);
    }

    char *p = buf;
    size_t remaining = sizeof(buf);
    for (size_t i = 0; i < CALYPSO_SERIAL_LEN; i++) {
        int written;
        if (i < 2) {
            written = snprintf(p, remaining, "XX ");
        } else {
            written = snprintf(p, remaining, "%02X ", serial[i]);
        }
        if (written < 0 || (size_t)written >= remaining) {
            break;
        }
        p += written;
        remaining -= (size_t)written;
    }
    return buf;
}

static bool calypso_tlv_get_bytes(struct tlvdb *tlv, tlv_tag_t tag, uint8_t *out, size_t out_len) {
    const struct tlv *found = tlvdb_get_tlv(tlvdb_find_full(tlv, tag));
    if (found == NULL || found->len != out_len) {
        return false;
    }

    memcpy(out, found->value, out_len);
    return true;
}

static bool calypso_tlv_get_df_name(struct tlvdb *tlv, calypso_fci_t *fci) {
    const struct tlv *df_name = tlvdb_get_tlv(tlvdb_find_full(tlv, 0x84));
    if (df_name == NULL || df_name->len == 0 || df_name->len > sizeof(fci->df_name)) {
        return false;
    }

    memcpy(fci->df_name, df_name->value, df_name->len);
    fci->df_name_len = df_name->len;
    fci->has_df_name = true;
    return true;
}

static bool calypso_parse_fci(const uint8_t *data, size_t data_len, calypso_fci_t *fci) {
    memset(fci, 0, sizeof(*fci));

    struct tlvdb *tlv = tlvdb_parse_multi(data, data_len);
    if (tlv == NULL) {
        return false;
    }

    calypso_tlv_get_df_name(tlv, fci);
    fci->has_serial = calypso_tlv_get_bytes(tlv, 0xC7, fci->serial, sizeof(fci->serial));
    fci->has_startup = calypso_tlv_get_bytes(tlv, 0x53, fci->startup, sizeof(fci->startup));

    tlvdb_free(tlv);
    return fci->has_serial && fci->has_startup;
}

static const char *calypso_json_string_get(json_t *obj, const char *name) {
    json_t *value = json_object_get(obj, name);
    return json_is_string(value) ? json_string_value(value) : NULL;
}

static bool calypso_json_string_is(json_t *obj, const char *name, const char *expected) {
    const char *value = calypso_json_string_get(obj, name);
    return value != NULL && strcmp(value, expected) == 0;
}

static json_t *calypso_json_resource_root(calypso_resource_t *resource) {
    if (resource == NULL) {
        return NULL;
    }

    if (resource->loaded) {
        return resource->root;
    }
    resource->loaded = true;

    char *path = NULL;
    if (searchFile(&path, RESOURCES_SUBDIR, resource->path, ".json", true) != PM3_SUCCESS) {
        return NULL;
    }

    json_error_t error;
    resource->root = json_load_file(path, 0, &error);
    if (resource->root == NULL) {
        PrintAndLogEx(ERR, "json (%s) error on line %d: %s", path, error.line, error.text);
        free(path);
        return NULL;
    }

    if (json_is_array(resource->root) == false) {
        PrintAndLogEx(ERR, "Invalid json (%s) format. root must be an array.", path);
        json_decref(resource->root);
        resource->root = NULL;
    } else {
        PrintAndLogEx(DEBUG, "Loaded file " _YELLOW_("%s") " " _GREEN_("%zu") " records ( " _GREEN_("ok") " )",
                      path,
                      json_array_size(resource->root));
    }

    free(path);
    return resource->root;
}

static bool calypso_json_lookup_id(json_t *obj, uint32_t *id) {
    if (obj == NULL || id == NULL) {
        return false;
    }

    json_t *value = json_object_get(obj, "id");
    if (value == NULL) {
        value = json_object_get(obj, "ID");
    }

    if (json_is_integer(value)) {
        json_int_t int_id = json_integer_value(value);
        if (int_id < 0 || int_id > UINT32_MAX) {
            return false;
        }
        *id = (uint32_t)int_id;
        return true;
    }

    if (json_is_string(value) == false) {
        return false;
    }

    const char *text = json_string_value(value);
    if (text == NULL) {
        return false;
    }

    while (isspace((unsigned char)*text)) {
        text++;
    }

    errno = 0;
    char *end = NULL;
    unsigned long parsed = strtoul(text, &end, 16);
    if (errno != 0 || end == text || parsed > UINT32_MAX) {
        return false;
    }

    while (isspace((unsigned char)*end)) {
        end++;
    }

    if (*end != '\0') {
        return false;
    }

    *id = (uint32_t)parsed;
    return true;
}

static const char *calypso_json_lookup_name(calypso_resource_t *resource, uint32_t id) {
    json_t *root = calypso_json_resource_root(resource);
    if (root == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < json_array_size(root); i++) {
        json_t *obj = json_array_get(root, i);
        if (json_is_object(obj) == false) {
            continue;
        }

        uint32_t entry_id = 0;
        if (calypso_json_lookup_id(obj, &entry_id) == false || entry_id != id) {
            continue;
        }

        const char *name = calypso_json_string_get(obj, "name");
        if (name == NULL) {
            name = calypso_json_string_get(obj, "Name");
        }
        return name;
    }

    return NULL;
}

static bool calypso_aid_is_prefix(const uint8_t *aid, size_t aid_len) {
    return aid != NULL && aid_len == 5;
}

static bool calypso_aid_is_generic(const uint8_t *aid, size_t aid_len) {
    return aid != NULL && aid_len > 0 && aid_len <= 8 && aid[0] >= 0x30 && aid[0] <= 0x34;
}

static int calypso_aid_specificity(bool prefix, bool generic, size_t aid_len) {
    if (prefix) {
        return (int)aid_len;
    }

    if (generic) {
        return 1000 + (int)aid_len;
    }

    return 2000 + (int)aid_len;
}

static void calypso_find_aid_match(json_t *root, const uint8_t *aid, size_t aid_len, const char *source, calypso_aid_match_t *match) {
    memset(match, 0, sizeof(*match));
    match->source = source;

    if (root == NULL || aid == NULL || aid_len == 0) {
        return;
    }

    for (size_t elmindx = 0; elmindx < json_array_size(root); elmindx++) {
        json_t *data = AIDSearchGetElm(root, elmindx);
        if (data == NULL || calypso_json_string_is(data, "Protocol", "cna_calypso") == false) {
            continue;
        }

        uint8_t entry_aid[CALYPSO_MAX_AID_LEN] = {0};
        int entry_aid_len = 0;
        if (AIDGetFromElm(data, entry_aid, sizeof(entry_aid), &entry_aid_len) == false || entry_aid_len <= 0) {
            continue;
        }

        if (aid_len < (size_t)entry_aid_len || memcmp(aid, entry_aid, (size_t)entry_aid_len) != 0) {
            continue;
        }

        bool prefix = calypso_aid_is_prefix(entry_aid, (size_t)entry_aid_len);
        bool generic = calypso_aid_is_generic(entry_aid, (size_t)entry_aid_len);
        int score = calypso_aid_specificity(prefix, generic, (size_t)entry_aid_len);
        if (match->found) {
            int current_score = calypso_aid_specificity(match->prefix, match->generic, match->aid_len);
            if (current_score >= score) {
                continue;
            }
        }

        match->found = true;
        match->aid_hex = calypso_json_string_get(data, "AID");
        match->vendor = calypso_json_string_get(data, "Vendor");
        match->name = calypso_json_string_get(data, "Name");
        match->country = calypso_json_string_get(data, "Country");
        match->description = calypso_json_string_get(data, "Description");
        match->type = calypso_json_string_get(data, "Type");
        match->prefix = prefix;
        match->generic = generic;
        match->aid_len = (size_t)entry_aid_len;
    }
}

static int calypso_aid_match_score(const calypso_aid_match_t *match) {
    if (match == NULL || match->found == false) {
        return -1;
    }

    return calypso_aid_specificity(match->prefix, match->generic, match->aid_len);
}

static bool calypso_aid_match_is_specific(const calypso_aid_match_t *match) {
    return match != NULL && match->found && match->prefix == false && match->generic == false;
}

static const calypso_aid_match_t *calypso_best_aid_match(const calypso_aid_match_t *selected, const calypso_aid_match_t *df_name) {
    int selected_score = calypso_aid_match_score(selected);
    int df_name_score = calypso_aid_match_score(df_name);
    return df_name_score > selected_score ? df_name : selected;
}

static void calypso_aid_attribution_init(const calypso_select_result_t *selected, bool verbose, calypso_aid_attribution_t *attribution) {
    memset(attribution, 0, sizeof(*attribution));

    attribution->root = AIDSearchInit(verbose);
    if (attribution->root == NULL) {
        return;
    }

    calypso_find_aid_match(attribution->root, selected->requested_aid, selected->requested_aid_len, "selected AID", &attribution->selected_match);
    if (selected->parsed.has_df_name) {
        calypso_find_aid_match(attribution->root, selected->parsed.df_name, selected->parsed.df_name_len, "DF name", &attribution->df_name_match);
    }

    attribution->best = calypso_best_aid_match(&attribution->selected_match, &attribution->df_name_match);
}

static void calypso_aid_attribution_free(calypso_aid_attribution_t *attribution) {
    if (attribution->root != NULL) {
        AIDSearchFree(attribution->root);
    }

    memset(attribution, 0, sizeof(*attribution));
}

static bool calypso_aid_match_same(const calypso_aid_match_t *a, const calypso_aid_match_t *b) {
    if (a == NULL || b == NULL || a->found == false || b->found == false || a->aid_hex == NULL || b->aid_hex == NULL) {
        return false;
    }

    return strcmp(a->aid_hex, b->aid_hex) == 0;
}

static void calypso_print_aid_match_line(const char *label, const calypso_aid_match_t *match) {
    if (match == NULL || match->found == false) {
        return;
    }

    PrintAndLogEx(SUCCESS, "%s : " _YELLOW_("%s") "%s | %s | %s",
                  label,
                  match->aid_hex ? match->aid_hex : "",
                  match->prefix ? " (prefix)" : (match->generic ? " (generic)" : ""),
                  match->vendor ? match->vendor : "",
                  match->name ? match->name : "");
}

static const char *calypso_nonempty(const char *value) {
    return value != NULL && value[0] != '\0' ? value : NULL;
}

static void calypso_print_aid_attribution_details(const calypso_aid_attribution_t *attribution, bool verbose) {
    if (attribution == NULL || attribution->root == NULL) {
        return;
    }

    const calypso_aid_match_t *best = attribution->best;

    if (verbose && best != NULL && best->found) {
        PrintAndLogEx(SUCCESS, " AID source        : " _YELLOW_("%s") "%s", best->source, best->prefix ? " (prefix)" : (best->generic ? " (generic)" : ""));
        if (best->type) {
            PrintAndLogEx(SUCCESS, " AID type          : " _YELLOW_("%s"), best->type);
        }
        if (best->country) {
            PrintAndLogEx(SUCCESS, " AID country       : " _YELLOW_("%s"), best->country);
        }
        if (best->description) {
            PrintAndLogEx(SUCCESS, " AID description   : " _YELLOW_("%s"), best->description);
        }
    }

    if (verbose && attribution->selected_match.found && attribution->df_name_match.found && calypso_aid_match_same(&attribution->selected_match, &attribution->df_name_match) == false) {
        PrintAndLogEx(INFO, " AID attribution   : " _YELLOW_("%s match preferred"), best->source);
        calypso_print_aid_match_line(" Selected AID ref", &attribution->selected_match);
        calypso_print_aid_match_line(" DF name ref     ", &attribution->df_name_match);
    }
}

static bool calypso_df_name_matches_specific_aid(json_t *root, const calypso_select_result_t *selected) {
    if (selected->parsed.has_df_name == false) {
        return false;
    }

    calypso_aid_match_t df_name_match;
    calypso_find_aid_match(root, selected->parsed.df_name, selected->parsed.df_name_len, "DF name", &df_name_match);
    return calypso_aid_match_is_specific(&df_name_match);
}

static int calypso_select_attribution_score(json_t *root, const calypso_select_result_t *selected) {
    calypso_aid_match_t selected_match;
    calypso_aid_match_t df_name_match;
    memset(&df_name_match, 0, sizeof(df_name_match));

    calypso_find_aid_match(root, selected->requested_aid, selected->requested_aid_len, "selected AID", &selected_match);
    if (selected->parsed.has_df_name) {
        calypso_find_aid_match(root, selected->parsed.df_name, selected->parsed.df_name_len, "DF name", &df_name_match);
    }

    const calypso_aid_match_t *best = calypso_best_aid_match(&selected_match, &df_name_match);
    return calypso_aid_match_score(best);
}

static int calypso_select_aid(const uint8_t *aid, size_t aid_len, bool activate_field, bool verbose, calypso_select_result_t *selected, bool *matched) {
    *matched = false;

    uint8_t response[APDU_RES_LEN] = {0};
    size_t response_len = 0;
    uint16_t sw = 0;

    int res = PM3_SUCCESS;
    if (activate_field) {
        res = Iso7816Connect(CC_CONTACTLESS);
        if (res != PM3_SUCCESS) {
            return res;
        }
    }

    res = Iso7816Select(CC_CONTACTLESS, false, true, (uint8_t *)aid, aid_len, response, sizeof(response), &response_len, &sw);
    if (res != PM3_SUCCESS) {
        if (verbose) {
            PrintAndLogEx(DEBUG, "Select AID %s failed: %d", sprint_hex_inrow(aid, aid_len), res);
        }
        return res;
    }

    if (sw != ISO7816_OK && sw != 0x6283) {
        if (verbose) {
            PrintAndLogEx(DEBUG, "Select AID %s returned %04X - %s", sprint_hex_inrow(aid, aid_len), sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
        }
        return PM3_SUCCESS;
    }

    calypso_fci_t fci = {0};
    if (calypso_parse_fci(response, response_len, &fci) == false) {
        if (verbose) {
            PrintAndLogEx(DEBUG, "Select AID %s returned non-Calypso FCI", sprint_hex_inrow(aid, aid_len));
        }
        return PM3_SUCCESS;
    }

    memset(selected, 0, sizeof(*selected));
    memcpy(selected->requested_aid, aid, aid_len);
    selected->requested_aid_len = aid_len;
    memcpy(selected->fci, response, response_len);
    selected->fci_len = response_len;
    selected->sw = sw;
    selected->parsed = fci;

    *matched = true;
    return PM3_SUCCESS;
}

static int calypso_scan_aidlist(bool verbose, calypso_select_result_t *selected, bool *matched) {
    *matched = false;

    json_t *root = AIDSearchInit(verbose);
    if (root == NULL) {
        return PM3_EFILE;
    }

    bool activate_field = true;
    bool probe_matched = false;
    int probe_score = -1;
    calypso_select_result_t probe_selected = {0};

    for (int scan_pass = 0; scan_pass < 3; scan_pass++) {
        for (size_t elmindx = 0; elmindx < json_array_size(root); elmindx++) {
            json_t *data = AIDSearchGetElm(root, elmindx);
            if (data == NULL || calypso_json_string_is(data, "Protocol", "cna_calypso") == false) {
                continue;
            }

            uint8_t aid[CALYPSO_MAX_AID_LEN] = {0};
            int aid_len = 0;
            if (AIDGetFromElm(data, aid, sizeof(aid), &aid_len) == false || aid_len <= 0) {
                continue;
            }

            bool prefix = calypso_aid_is_prefix(aid, (size_t)aid_len);
            bool generic = calypso_aid_is_generic(aid, (size_t)aid_len);
            if ((scan_pass == 0 && prefix == false) ||
                    (scan_pass == 1 && (prefix || generic == false)) ||
                    (scan_pass == 2 && (prefix || generic))) {
                continue;
            }

            if (AIDSeenBefore(root, aid, (size_t)aid_len, elmindx)) {
                continue;
            }

            int res = calypso_select_aid(aid, (size_t)aid_len, activate_field, verbose, selected, matched);
            if (res != PM3_SUCCESS) {
                AIDSearchFree(root);
                return res;
            }

            activate_field = false;
            if (*matched) {
                if (prefix || generic) {
                    if (calypso_df_name_matches_specific_aid(root, selected)) {
                        AIDSearchFree(root);
                        return PM3_SUCCESS;
                    }

                    int score = calypso_select_attribution_score(root, selected);
                    if (probe_matched == false || score > probe_score) {
                        probe_selected = *selected;
                        probe_score = score;
                        probe_matched = true;
                    }
                    *matched = false;
                    continue;
                }

                AIDSearchFree(root);
                return PM3_SUCCESS;
            }
        }
    }

    if (probe_matched) {
        bool restored = false;
        int res = calypso_select_aid(probe_selected.requested_aid, probe_selected.requested_aid_len, false, verbose, selected, &restored);
        if (res != PM3_SUCCESS || restored == false) {
            res = calypso_select_aid(probe_selected.requested_aid, probe_selected.requested_aid_len, true, verbose, selected, &restored);
        }
        if (res != PM3_SUCCESS) {
            AIDSearchFree(root);
            return res;
        }
        if (restored == false) {
            if (verbose) {
                PrintAndLogEx(DEBUG, "Unable to restore selected Calypso AID %s", sprint_hex_inrow(probe_selected.requested_aid, probe_selected.requested_aid_len));
            }
        } else {
            *matched = true;
        }
    }

    AIDSearchFree(root);
    return PM3_SUCCESS;
}

static bool calypso_date_from_days(uint16_t days_since_1990, int *year, int *month, int *day) {
    static const uint8_t month_days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    int y = 1990;
    uint32_t days = days_since_1990;

    while (true) {
        bool leap = ((y % 4) == 0 && (((y % 100) != 0) || ((y % 400) == 0)));
        uint16_t year_days = leap ? 366 : 365;
        if (days < year_days) {
            break;
        }
        days -= year_days;
        y++;
    }

    int m = 1;
    for (size_t i = 0; i < ARRAYLEN(month_days); i++) {
        uint8_t mdays = month_days[i];
        if (i == 1 && ((y % 4) == 0 && (((y % 100) != 0) || ((y % 400) == 0)))) {
            mdays++;
        }
        if (days < mdays) {
            m = (int)i + 1;
            break;
        }
        days -= mdays;
    }

    *year = y;
    *month = m;
    *day = (int)days + 1;
    return true;
}

static int calypso_count_zero_bits(const uint8_t *data, size_t len) {
    int count = 0;
    for (size_t i = 0; i < len; i++) {
        for (uint8_t bit = 0; bit < 8; bit++) {
            if ((data[i] & (1U << bit)) == 0) {
                count++;
            }
        }
    }
    return count;
}

static bool calypso_is_zero(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (data[i] != 0x00) {
            return false;
        }
    }
    return true;
}

static bool calypso_has_ascii_hint(const uint8_t *data, size_t len) {
    if (len == 0) {
        return false;
    }

    size_t printable = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = data[i];
        if (isprint(c) && c != 0xFF) {
            printable++;
        }
    }

    return printable > ((len * 40) / 100);
}

static void calypso_print_hex_ascii_line(const char *label, const uint8_t *data, size_t len) {
    if (calypso_has_ascii_hint(data, len)) {
        PrintAndLogEx(SUCCESS, "%s" _GREEN_("%s") " (" _YELLOW_("%s") ")", label, sprint_hex(data, len), sprint_ascii(data, len));
    } else {
        PrintAndLogEx(SUCCESS, "%s" _GREEN_("%s"), label, sprint_hex(data, len));
    }
}

static void calypso_print_aid_match_summary(const calypso_aid_match_t *match) {
    if (match == NULL || match->found == false) {
        return;
    }

    const char *vendor = calypso_nonempty(match->vendor);
    const char *name = calypso_nonempty(match->name);
    if (name != NULL && vendor != NULL) {
        PrintAndLogEx(SUCCESS, " AID info          : " _YELLOW_("%s") " (" _YELLOW_("%s") ")", name, vendor);
    } else if (name != NULL) {
        PrintAndLogEx(SUCCESS, " AID info          : " _YELLOW_("%s"), name);
    } else if (vendor != NULL) {
        PrintAndLogEx(SUCCESS, " AID info          : " _YELLOW_("%s"), vendor);
    }
}

static uint8_t calypso_icc_check_value(const uint8_t *data, size_t len) {
    return (uint8_t)(5 + calypso_count_zero_bits(data, len));
}

static bool calypso_bcd_country(const uint8_t *data, uint16_t *country_code) {
    uint8_t nibbles[] = {
        data[0] >> 4,
        data[0] & 0x0F,
        data[1] >> 4,
        data[1] & 0x0F,
    };

    for (size_t i = 0; i < ARRAYLEN(nibbles); i++) {
        if (nibbles[i] > 9) {
            return false;
        }
    }

    *country_code = (nibbles[1] * 100) + (nibbles[2] * 10) + nibbles[3];
    return true;
}

static const char *calypso_country_name(uint16_t country_code) {
    switch (country_code) {
        case 56:
            return "Belgium";
        case 156:
            return "China";
        case 250:
            return "France";
        default:
            return NULL;
    }
}

static bool calypso_get_bits_be(const uint8_t *data, size_t data_len, size_t bit_offset, size_t bit_len, uint32_t *value) {
    if (data == NULL || value == NULL || bit_len == 0 || bit_len > 32 || bit_offset + bit_len > data_len * 8) {
        return false;
    }

    uint32_t v = 0;
    for (size_t i = 0; i < bit_len; i++) {
        size_t pos = bit_offset + i;
        v = (v << 1) | ((data[pos / 8] >> (7 - (pos % 8))) & 0x01);
    }

    *value = v;
    return true;
}

static bool calypso_extract_network_id(const uint8_t *data, size_t data_len, uint32_t *network_id, size_t *bit_offset) {
    uint32_t candidate = 0;
    if (calypso_get_bits_be(data, data_len, 13, 24, &candidate) && candidate != 0) {
        *network_id = candidate;
        *bit_offset = 13;
        if (calypso_network_name(candidate) != NULL || (candidate >> 12) == 0x250 || (candidate >> 12) == 0x056) {
            return true;
        }
    }

    uint32_t alternate = 0;
    if (calypso_get_bits_be(data, data_len, 5, 24, &alternate) && calypso_network_name(alternate) != NULL) {
        *network_id = alternate;
        *bit_offset = 5;
        return true;
    }

    return candidate != 0;
}

static int calypso_read_sfi_record(uint8_t sfi, uint8_t record, uint16_t le, uint8_t *out, size_t out_len, size_t *read_len, uint16_t *sw) {
    uint8_t response[APDU_RES_LEN] = {0};
    size_t response_len = 0;

    sAPDU_t apdu = {0x00, CALYPSO_READ_RECORD, record, (sfi << 3) | 0x04, 0, NULL};
    int res = Iso7816ExchangeEx(CC_CONTACTLESS, false, true, apdu, true, le, response, sizeof(response), &response_len, sw);

    if (res == PM3_SUCCESS && *sw != ISO7816_OK) {
        apdu.CLA = 0x94;
        response_len = 0;
        *sw = 0;
        res = Iso7816ExchangeEx(CC_CONTACTLESS, false, true, apdu, true, le, response, sizeof(response), &response_len, sw);
    }

    if (res != PM3_SUCCESS || *sw != ISO7816_OK) {
        *read_len = 0;
        return res;
    }

    *read_len = MIN(response_len, out_len);
    memcpy(out, response, *read_len);
    return PM3_SUCCESS;
}

static int calypso_select_file_by_id(uint16_t file_id, uint16_t *sw) {
    uint8_t file_id_data[] = {
        (uint8_t)(file_id >> 8),
        (uint8_t)(file_id & 0xFF),
    };
    uint8_t response[APDU_RES_LEN] = {0};
    size_t response_len = 0;
    sAPDU_t apdu = {0x00, ISO7816_SELECT_FILE, 0x00, 0x00, sizeof(file_id_data), file_id_data};

    return Iso7816ExchangeEx(CC_CONTACTLESS, false, true, apdu, true, 0, response, sizeof(response), &response_len, sw);
}

static int calypso_read_current_record(uint8_t record, uint16_t le, uint8_t *out, size_t out_len, size_t *read_len, uint16_t *sw) {
    uint8_t response[APDU_RES_LEN] = {0};
    size_t response_len = 0;

    sAPDU_t apdu = {0x00, CALYPSO_READ_RECORD, record, 0x04, 0, NULL};
    int res = Iso7816ExchangeEx(CC_CONTACTLESS, false, true, apdu, true, le, response, sizeof(response), &response_len, sw);

    if (res == PM3_SUCCESS && *sw != ISO7816_OK) {
        apdu.CLA = 0x94;
        response_len = 0;
        *sw = 0;
        res = Iso7816ExchangeEx(CC_CONTACTLESS, false, true, apdu, true, le, response, sizeof(response), &response_len, sw);
    }

    if (res != PM3_SUCCESS || *sw != ISO7816_OK) {
        *read_len = 0;
        return res;
    }

    *read_len = MIN(response_len, out_len);
    memcpy(out, response, *read_len);
    return PM3_SUCCESS;
}

static int calypso_read_icc_file(uint8_t *icc, size_t icc_len, size_t *read_len, uint16_t *sw) {
    int res = calypso_select_file_by_id(CALYPSO_ICC_FILE_ID, sw);
    if (res != PM3_SUCCESS || *sw != ISO7816_OK) {
        *read_len = 0;
        return res;
    }

    return calypso_read_current_record(0x01, CALYPSO_ICC_RECORD_LEN, icc, icc_len, read_len, sw);
}

static int calypso_read_icc(uint8_t *icc, size_t icc_len, size_t *read_len, uint16_t *sw) {
    int res = calypso_read_sfi_record(CALYPSO_ICC_SFI, 0x01, CALYPSO_ICC_RECORD_LEN, icc, icc_len, read_len, sw);
    if (res == PM3_SUCCESS && *sw == ISO7816_OK) {
        return res;
    }

    return calypso_read_icc_file(icc, icc_len, read_len, sw);
}

static int calypso_read_ticketing_environment_file(uint8_t *env, size_t env_len, size_t *read_len, uint16_t *sw) {
    int res = calypso_select_file_by_id(CALYPSO_TICKET_DIR_ID, sw);
    if (res != PM3_SUCCESS || *sw != ISO7816_OK) {
        *read_len = 0;
        return res;
    }

    res = calypso_select_file_by_id(CALYPSO_TICKET_ENV_FILE_ID, sw);
    if (res != PM3_SUCCESS || *sw != ISO7816_OK) {
        *read_len = 0;
        return res;
    }

    return calypso_read_current_record(0x01, 0, env, env_len, read_len, sw);
}

static int calypso_read_ticketing_environment(uint8_t *env, size_t env_len, size_t *read_len, uint16_t *sw) {
    int res = calypso_read_sfi_record(CALYPSO_TICKET_ENV_SFI, 0x01, 0, env, env_len, read_len, sw);
    if (res == PM3_SUCCESS && *sw == ISO7816_OK) {
        return res;
    }

    return calypso_read_ticketing_environment_file(env, env_len, read_len, sw);
}

static void calypso_print_icc_ignored(const uint8_t *icc, size_t icc_len, bool verbose, const char *reason) {
    if (verbose == false) {
        return;
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "ICC manufacturing record ignored: " _YELLOW_("%s"), reason);
    if (icc_len > 0) {
        PrintAndLogEx(SUCCESS, " ICC raw           : " _YELLOW_("%s"), sprint_hex(icc, icc_len));
    }
}

static void calypso_print_startup(const uint8_t *startup) {
    uint8_t session_modifications = startup[0];
    uint8_t platform = startup[1];
    uint8_t application_type = startup[2];
    uint8_t application_subtype = startup[3];
    uint8_t software_issuer = startup[4];
    uint8_t software_version = startup[5];
    uint8_t software_revision = startup[6];
    const char *platform_desc = calypso_platform_desc(platform);
    const char *software_issuer_desc = calypso_company_name(software_issuer);
    uint16_t session_buffer_size = calypso_session_buffer_size(session_modifications);

    PrintAndLogEx(SUCCESS, " Startup info      : " _YELLOW_("%s"), sprint_hex(startup, CALYPSO_STARTUP_LEN));
    if (session_buffer_size > 0) {
        PrintAndLogEx(SUCCESS, " Session mod. byte : " _GREEN_("%02X") " (" _YELLOW_("%u-byte command buffer") ")", session_modifications, session_buffer_size);
    } else {
        PrintAndLogEx(SUCCESS, " Session mod. byte : " _GREEN_("%02X"), session_modifications);
    }
    if (platform_desc != NULL) {
        PrintAndLogEx(SUCCESS, " Platform / chip   : " _GREEN_("%02X") " (" _YELLOW_("%s") ")", platform, platform_desc);
    } else {
        PrintAndLogEx(SUCCESS, " Platform / chip   : " _GREEN_("%02X"), platform);
    }
    PrintAndLogEx(SUCCESS, " Application type  : " _GREEN_("%02X") " (" _YELLOW_("%s") ")", application_type, calypso_application_type_desc(application_type));
    PrintAndLogEx(SUCCESS, " File structure    : " _GREEN_("%02X") " (" _YELLOW_("%s") ")", application_subtype, calypso_file_structure_desc(application_subtype));
    if (software_issuer_desc != NULL) {
        PrintAndLogEx(SUCCESS, " Software issuer   : " _GREEN_("%02X") " (" _YELLOW_("%s") ")", software_issuer, software_issuer_desc);
    } else {
        PrintAndLogEx(SUCCESS, " Software issuer   : " _GREEN_("%02X"), software_issuer);
    }
    PrintAndLogEx(SUCCESS, " Software version  : " _GREEN_("%02X"), software_version);
    PrintAndLogEx(SUCCESS, " Software revision : " _GREEN_("%02X"), software_revision);

    if (application_type >= 0x20 && application_type <= 0x3F) {
        PrintAndLogEx(SUCCESS, " Calypso PIN       : %s", (application_type & 0x01) ? _GREEN_("yes") : _YELLOW_("no"));
        PrintAndLogEx(SUCCESS, " Stored value      : %s", (application_type & 0x02) ? _GREEN_("yes") : _YELLOW_("no"));
        PrintAndLogEx(SUCCESS, " Ratify on deselect: %s", (application_type & 0x04) ? _YELLOW_("no (command required)") : _GREEN_("yes"));
    } else if (application_type >= 0x40 && application_type <= 0x7F) {
        PrintAndLogEx(INFO, " Application options: " _YELLOW_("Extended Rev 3 range; option bits not decoded"));
    }
}

static void calypso_print_ticketing_environment(const uint8_t *env, size_t env_len, bool verbose) {
    if (env_len == 0 || calypso_is_zero(env, env_len)) {
        if (verbose) {
            PrintAndLogEx(INFO, "");
            PrintAndLogEx(INFO, "Ticketing environment ignored: empty record");
        }
        return;
    }

    uint32_t version = 0;
    uint32_t network_id = 0;
    size_t network_bit_offset = 0;
    bool has_version = calypso_get_bits_be(env, env_len, 0, 6, &version);
    bool has_network = calypso_extract_network_id(env, env_len, &network_id, &network_bit_offset);

    if (has_version == false && has_network == false) {
        if (verbose) {
            PrintAndLogEx(INFO, "");
            PrintAndLogEx(INFO, "Ticketing environment ignored: record too short");
            PrintAndLogEx(SUCCESS, " Environment raw   : " _YELLOW_("%s"), sprint_hex(env, env_len));
        }
        return;
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Ticketing Environment") " -------------------");
    if (has_version) {
        PrintAndLogEx(SUCCESS, " Environment ver.  : " _GREEN_("%u"), version);
    }
    if (has_network) {
        const char *network_name = calypso_network_name(network_id);
        if (network_name != NULL) {
            PrintAndLogEx(SUCCESS, " Network ID        : " _GREEN_("%06X") " (" _YELLOW_("%s") ")", network_id, network_name);
        } else {
            PrintAndLogEx(SUCCESS, " Network ID        : " _GREEN_("%06X"), network_id);
        }
        if (verbose && network_bit_offset != 13) {
            PrintAndLogEx(INFO, " Network ID source : bit offset " _YELLOW_("%zu"), network_bit_offset);
        }
    }
    if (verbose) {
        PrintAndLogEx(SUCCESS, " Environment raw   : " _YELLOW_("%s"), sprint_hex(env, env_len));
    }
}

static void calypso_print_icc(const uint8_t *icc, size_t icc_len, bool verbose, const uint8_t *fci_serial) {
    if (icc_len < CALYPSO_ICC_RECORD_LEN) {
        calypso_print_icc_ignored(icc, icc_len, verbose, "record too short");
        return;
    }

    if (calypso_is_zero(icc, icc_len)) {
        calypso_print_icc_ignored(icc, icc_len, verbose, "all-zero record");
        return;
    }

    if (fci_serial && memcmp(&icc[CALYPSO_ICC_SERIAL_OFF], fci_serial, CALYPSO_SERIAL_LEN) != 0) {
        calypso_print_icc_ignored(icc, icc_len, verbose, "serial differs from FCI serial");
        return;
    }

    uint16_t country_code = 0;
    bool country_ok = calypso_bcd_country(&icc[0x14], &country_code);
    uint16_t init_days = ((uint16_t)icc[0x19] << 8) | icc[0x1A];
    int year = 0;
    int month = 0;
    int day = 0;
    calypso_date_from_days(init_days, &year, &month, &day);

    uint8_t expected_check = calypso_icc_check_value(&icc[CALYPSO_ICC_CHECK_META_OFF], CALYPSO_ICC_CHECK_OFF - CALYPSO_ICC_CHECK_META_OFF);
    uint8_t expected_full_check = calypso_icc_check_value(icc, CALYPSO_ICC_CHECK_OFF);
    bool check_ok = expected_check == icc[CALYPSO_ICC_CHECK_OFF] || expected_full_check == icc[CALYPSO_ICC_CHECK_OFF];

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("ICC Manufacturing Information") " -----------");
    PrintAndLogEx(SUCCESS, " ICC serial        : " _GREEN_("%s"), sprint_hex(&icc[CALYPSO_ICC_SERIAL_OFF], CALYPSO_SERIAL_LEN));
    if (country_ok) {
        const char *country_name = calypso_country_name(country_code);
        if (country_name != NULL) {
            PrintAndLogEx(SUCCESS, " Country code      : " _GREEN_("%03u") " (" _YELLOW_("%s") ", BCD " _YELLOW_("%02X%02X") ")", country_code, country_name, icc[0x14], icc[0x15]);
        } else {
            PrintAndLogEx(SUCCESS, " Country code      : " _GREEN_("%03u") " (BCD " _YELLOW_("%02X%02X") ")", country_code, icc[0x14], icc[0x15]);
        }
    } else {
        PrintAndLogEx(SUCCESS, " Country code      : " _YELLOW_("%s"), sprint_hex(&icc[0x14], 2));
    }
    const char *manufacturer_name = calypso_company_name(icc[0x16]);
    if (manufacturer_name != NULL) {
        PrintAndLogEx(SUCCESS, " Manufacturer ID   : " _GREEN_("%02X") " (" _YELLOW_("%s") ")", icc[0x16], manufacturer_name);
    } else {
        PrintAndLogEx(SUCCESS, " Manufacturer ID   : " _GREEN_("%02X"), icc[0x16]);
    }
    PrintAndLogEx(SUCCESS, " Manufacturer info : " _GREEN_("%02X"), icc[0x18]);
    PrintAndLogEx(SUCCESS, " Init date         : " _GREEN_("%04d-%02d-%02d") " (" _YELLOW_("%u days since 1990-01-01") ")", year, month, day, init_days);
    if (check_ok) {
        PrintAndLogEx(SUCCESS, " Check value       : " _GREEN_("%02X") " (%s)", icc[CALYPSO_ICC_CHECK_OFF], _GREEN_("ok"));
    } else {
        PrintAndLogEx(SUCCESS, " Check value       : " _YELLOW_("%02X") " (%s, expected " _YELLOW_("%02X") " or " _YELLOW_("%02X") ")", icc[CALYPSO_ICC_CHECK_OFF], _RED_("fail"), expected_check, expected_full_check);
    }

    if (verbose) {
        PrintAndLogEx(SUCCESS, " Manufacturing data: " _YELLOW_("%s"), sprint_hex(&icc[0x00], 12));
        if (icc[0x17] != 0x00 || icc[0x1C] != 0x00) {
            PrintAndLogEx(INFO, " ICC RFU bytes     : offset 17h=" _YELLOW_("%02X") " offset 1Ch=" _YELLOW_("%02X"), icc[0x17], icc[0x1C]);
        }
        PrintAndLogEx(SUCCESS, " ICC raw           : " _YELLOW_("%s"), sprint_hex(icc, icc_len));
    }
}

static void calypso_print_select_info(const calypso_select_result_t *selected, bool verbose) {
    calypso_aid_attribution_t attribution;
    calypso_aid_attribution_init(selected, verbose, &attribution);
    const calypso_aid_match_t *aid_line_match = attribution.best != NULL && attribution.best->found ? attribution.best : NULL;

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Calypso Information") " ---------------------");
    calypso_print_hex_ascii_line(" SELECT AID        : ", selected->requested_aid, selected->requested_aid_len);

    if (selected->parsed.has_df_name) {
        calypso_print_hex_ascii_line(" FCI DF Name       : ", selected->parsed.df_name, selected->parsed.df_name_len);
    }
    calypso_print_aid_match_summary(aid_line_match);

    bool hce = calypso_serial_is_hce(selected->parsed.serial);
    PrintAndLogEx(SUCCESS, " Serial number     : " _GREEN_("%s"), calypso_sprint_serial(selected->parsed.serial));
    if (hce) {
        PrintAndLogEx(SUCCESS, " HCE token expiry  : " _YELLOW_("%s"), sprint_hex(selected->parsed.serial, 2));
    }
    PrintAndLogEx(SUCCESS, " Card type         : " _YELLOW_("%s"), calypso_product_type_desc(selected->parsed.serial));
    if (selected->sw == 0x6283) {
        PrintAndLogEx(WARNING, " Application status: " _YELLOW_("DF invalidated") " (" _YELLOW_("%04X") ")", selected->sw);
    }

    calypso_print_startup(selected->parsed.startup);

    calypso_print_aid_attribution_details(&attribution, verbose);

    if (verbose) {
        PrintAndLogEx(INFO, "");
        PrintAndLogEx(INFO, "--- " _CYAN_("FCI") " -------------------------------------");
        PrintAndLogEx(SUCCESS, " FCI raw           : " _YELLOW_("%s"), sprint_hex(selected->fci, selected->fci_len));
        TLVPrintFromBuffer((uint8_t *)selected->fci, (int)selected->fci_len);
    }

    calypso_aid_attribution_free(&attribution);
}

static int CmdHFCalypsoInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf calypso info",
                  "Tag information for Calypso cards",
                  "hf calypso info\n"
                  "hf calypso info -v\n"
                  "hf calypso info --aid 315449432E494341");

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "aid", "<hex>", "Calypso application AID or AID prefix (5..16 bytes)"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t user_aid[CALYPSO_MAX_AID_LEN] = {0};
    int user_aid_len = 0;
    int parse_res = CLIParamHexToBuf(arg_get_str(ctx, 1), user_aid, sizeof(user_aid), &user_aid_len);
    bool verbose = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    if (parse_res != PM3_SUCCESS) {
        return PM3_EINVARG;
    }
    if (user_aid_len > 0 && (user_aid_len < 5 || user_aid_len > CALYPSO_MAX_AID_LEN)) {
        PrintAndLogEx(ERR, "AID length must be 5..16 bytes, got %d", user_aid_len);
        return PM3_EINVARG;
    }

    calypso_select_result_t selected = {0};
    bool matched = false;
    int res = PM3_SUCCESS;

    if (user_aid_len > 0) {
        res = calypso_select_aid(user_aid, (size_t)user_aid_len, true, verbose, &selected, &matched);
    } else {
        res = calypso_scan_aidlist(verbose, &selected, &matched);
    }

    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(WARNING, "No ISO14443-4 Calypso application selected");
        return res;
    }

    if (matched == false) {
        DropField();
        PrintAndLogEx(WARNING, "No Calypso application found");
        return PM3_EOPABORTED;
    }

    calypso_print_select_info(&selected, verbose);

    uint8_t icc[CALYPSO_ICC_RECORD_LEN] = {0};
    size_t icc_len = 0;
    uint16_t icc_sw = 0;
    res = calypso_read_icc(icc, sizeof(icc), &icc_len, &icc_sw);
    if (res == PM3_SUCCESS && icc_sw == ISO7816_OK) {
        calypso_print_icc(icc, icc_len, verbose, selected.parsed.serial);
    } else if (verbose) {
        PrintAndLogEx(INFO, "");
        PrintAndLogEx(INFO, "ICC manufacturing record unavailable (%04X - %s)", icc_sw, GetAPDUCodeDescription(icc_sw >> 8, icc_sw & 0xFF));
    }

    uint8_t ticket_env[APDU_RES_LEN] = {0};
    size_t ticket_env_len = 0;
    uint16_t ticket_env_sw = 0;
    res = calypso_read_ticketing_environment(ticket_env, sizeof(ticket_env), &ticket_env_len, &ticket_env_sw);
    if (res == PM3_SUCCESS && ticket_env_sw == ISO7816_OK) {
        calypso_print_ticketing_environment(ticket_env, ticket_env_len, verbose);
    } else if (verbose) {
        PrintAndLogEx(INFO, "");
        PrintAndLogEx(INFO, "Ticketing environment unavailable (%04X - %s)", ticket_env_sw, GetAPDUCodeDescription(ticket_env_sw >> 8, ticket_env_sw & 0xFF));
    }

    DropField();
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help", CmdHelp,          AlwaysAvailable, "This help"},
    {"info", CmdHFCalypsoInfo, IfPm3Iso14443,   "Tag information"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd;
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFCalypso(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
