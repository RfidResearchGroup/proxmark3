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
#include "cmdhf14a.h"
#include "cmdhf14b.h"
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
#define CALYPSO_LEGACY_RECORD_LEN 0x1D
#define CALYPSO_ICC_SFI          0x02
#define CALYPSO_ICC_FILE_ID      0x0002
#define CALYPSO_TICKET_ENV_SFI   0x07
#define CALYPSO_TICKET_DIR_ID    0x2000
#define CALYPSO_TICKET_ENV_FILE_ID 0x2001
#define CALYPSO_ICC_SERIAL_OFF   0x0C
#define CALYPSO_ICC_CHECK_OFF    0x1B
#define CALYPSO_ICC_CHECK_META_OFF 0x10
#define CALYPSO_MAX_ENCODED_SFI  0x1F
#define CALYPSO_HCE_TOKEN_LEN    2
#define CALYPSO_DUMP_FILENAME_MAX_SERIALS 8

#define CALYPSO_MANUFACTURERS_RESOURCE "calypso/manufacturers"
#define CALYPSO_IC_FAMILIES_RESOURCE   "calypso/ic_families"
#define CALYPSO_OPERATORS_RESOURCE     "calypso/operators"
#define CALYPSO_DUMP_PATH_MAX    2
// https://docs.keyple.org/keyple-card-calypso-cpp-lib/2.2.5.6/_cmd_card_select_file_8cpp_source.html
#define CALYPSO_SELECT_FIRST_EF_P1      0x02
#define CALYPSO_SELECT_FIRST_EF_P2      0x00
#define CALYPSO_SELECT_NEXT_EF_P1       0x02
#define CALYPSO_SELECT_NEXT_EF_P2       0x02
#define CALYPSO_SELECT_CURRENT_DF_P1    0x09
#define CALYPSO_SELECT_CURRENT_DF_P2    0x00
// Most existing public code uses P1=00 for LID selection, and on many cards it exposes more files.
#define CALYPSO_SELECT_FILE_ID_P1       0x00
#define CALYPSO_SELECT_FILE_ID_P2       0x00

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
    bool present;
    isodep_state_t protocol;
    bool has_14a;
    iso14a_card_select_t card_a;
    bool has_14b;
    iso14b_card_select_t card_b;
} calypso_rf_info_t;

typedef struct {
    uint8_t requested_aid[CALYPSO_MAX_AID_LEN];
    size_t requested_aid_len;
    calypso_rf_info_t rf;
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

typedef struct {
    const char *name;
    int sfi;
    uint16_t path[CALYPSO_DUMP_PATH_MAX];
    size_t path_len;
} calypso_file_ref_t;

typedef struct {
    uint16_t tag;
    const char *name;
    bool tlv;
} calypso_get_data_probe_t;

typedef struct {
    uint8_t aid[CALYPSO_MAX_AID_LEN];
    size_t aid_len;
} calypso_app_identity_t;

typedef struct {
    size_t serial_count;
    uint8_t serials[CALYPSO_DUMP_FILENAME_MAX_SERIALS][CALYPSO_SERIAL_LEN];
} calypso_dump_context_t;

static calypso_resource_t calypso_manufacturers_resource = {CALYPSO_MANUFACTURERS_RESOURCE, NULL, false};
static calypso_resource_t calypso_ic_families_resource = {CALYPSO_IC_FAMILIES_RESOURCE, NULL, false};
static calypso_resource_t calypso_operators_resource = {CALYPSO_OPERATORS_RESOURCE, NULL, false};

static const char *calypso_json_lookup_name(calypso_resource_t *resource, uint32_t id);
static void calypso_reselect_exact_df_name(const calypso_select_result_t *selected, bool verbose);
static void calypso_print_rf_info(const calypso_rf_info_t *rf);

static int CmdHelp(const char *Cmd);

static const calypso_file_ref_t calypso_file_refs[] = {
    {"TICKETING_ENVIRONMENT", 0x07, {0x2000, 0x2001}, 2},
    {"AID", 0x04, {0x3F04}, 1},
    {"ICC", 0x02, {0x0002}, 1},
    {"ID", 0x03, {0x0003}, 1},
    {"HOLDER_EXTENDED", -1, {0x3F1C}, 1},
    {"DISPLAY", 0x05, {0x2F10}, 1},
    {"TICKETING_HOLDER", -1, {0x2000, 0x2002}, 2},
    {"TICKETING_AID", -1, {0x2000, 0x2004}, 2},
    {"TICKETING_LOG", 0x08, {0x2000, 0x2010}, 2},
    {"TICKETING_CONTRACTS_1", 0x09, {0x2000, 0x2020}, 2},
    {"TICKETING_CONTRACTS_2", 0x06, {0x2000, 0x2030}, 2},
    {"TICKETING_COUNTERS_1", 0x0A, {0x2000, 0x202A}, 2},
    {"TICKETING_COUNTERS_2", 0x0B, {0x2000, 0x202B}, 2},
    {"TICKETING_COUNTERS_3", 0x0C, {0x2000, 0x202C}, 2},
    {"TICKETING_COUNTERS_4", 0x0D, {0x2000, 0x202D}, 2},
    {"TICKETING_COUNTERS_5", -1, {0x2000, 0x202E}, 2},
    {"TICKETING_COUNTERS_6", -1, {0x2000, 0x202F}, 2},
    {"TICKETING_SPECIAL_EVENTS", 0x1D, {0x2000, 0x2040}, 2},
    {"TICKETING_CONTRACT_LIST", 0x1E, {0x2000, 0x2050}, 2},
    {"TICKETING_COUNTERS_7", -1, {0x2000, 0x2060}, 2},
    {"TICKETING_COUNTERS_8", -1, {0x2000, 0x2062}, 2},
    {"TICKETING_COUNTERS_9", 0x19, {0x2000, 0x2069}, 2},
    {"TICKETING_COUNTERS_10", 0x10, {0x2000, 0x206A}, 2},
    {"TICKETING_FREE", 0x01, {0x2000, 0x20F0}, 2},
    {"MPP_PUBLIC_PARAMETERS", 0x17, {0x3100, 0x3102}, 2},
    {"MPP_AID", -1, {0x3100, 0x3104}, 2},
    {"MPP_LOG", -1, {0x3100, 0x3115}, 2},
    {"MPP_CONTRACTS", -1, {0x3100, 0x3120}, 2},
    {"MPP_COUNTERS_1", -1, {0x3100, 0x3113}, 2},
    {"MPP_COUNTERS_2", -1, {0x3100, 0x3123}, 2},
    {"MPP_COUNTERS_3", -1, {0x3100, 0x3133}, 2},
    {"MPP_MISCELLANEOUS", -1, {0x3100, 0x3150}, 2},
    {"MPP_COUNTERS_4", -1, {0x3100, 0x3169}, 2},
    {"MPP_FREE", -1, {0x3100, 0x31F0}, 2},
    {"RT2_ENVIRONMENT", -1, {0x2100, 0x2101}, 2},
    {"RT2_AID", -1, {0x2100, 0x2104}, 2},
    {"RT2_LOG", -1, {0x2100, 0x2110}, 2},
    {"RT2_CONTRACTS", -1, {0x2100, 0x2120}, 2},
    {"RT2_SPECIAL_EVENTS", -1, {0x2100, 0x2140}, 2},
    {"RT2_CONTRACT_LIST", -1, {0x2100, 0x2150}, 2},
    {"RT2_COUNTERS", -1, {0x2100, 0x2169}, 2},
    {"RT2_FREE", -1, {0x2100, 0x21F0}, 2},
    {"EP_AID", -1, {0x1000, 0x1004}, 2},
    {"EP_LOAD_LOG", 0x14, {0x1000, 0x1014}, 2},
    {"EP_PURCHASE_LOG", 0x15, {0x1000, 0x1015}, 2},
    {"ETICKET", -1, {0x8000, 0x8004}, 2},
    {"ETICKET_EVENT_LOGS", -1, {0x8000, 0x8010}, 2},
    {"ETICKET_PRESELECTION", -1, {0x8000, 0x8030}, 2},
};

// https://docs.keypop.org/keypop-calypso-card-cpp-api/latest-stable/namespacekeypop_1_1calypso_1_1card.html#aa274077fbdeafe85dfe208791490462f
// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-2.0.pdf
static const calypso_get_data_probe_t calypso_get_data_probes[] = {
    {0x004F, "Current DF AID", true},
    {0x0062, "FCP For Current File", true},
    {0x006F, "FCI For Current DF", true},
    {0x00C0, "EF List", true},
    {0x00D0, "Other application AIDs", true},
    {0x0185, "Traceability Information", false},
    {0x5F52, "ATR historical bytes", true},
};

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

static const char *calypso_rf_protocol_desc(isodep_state_t protocol) {
    if (protocol == ISODEP_NFCA) {
        return "ISO14443-A";
    }
    if (protocol == ISODEP_NFCB) {
        return "ISO14443-B";
    }
    return "unknown";
}

static int calypso_connect_contactless(bool verbose, calypso_rf_info_t *rf) {
    if (rf != NULL) {
        memset(rf, 0, sizeof(*rf));
    }

    iso14a_card_select_t card_a = {0};
    int res = SelectCard14443A_4(false, verbose, &card_a);
    if (res == PM3_SUCCESS) {
        if (rf != NULL) {
            rf->present = true;
            rf->protocol = ISODEP_NFCA;
            rf->has_14a = true;
            rf->card_a = card_a;
        }
        return PM3_SUCCESS;
    }

    iso14b_card_select_t card_b = {0};
    res = select_card_14443b_4(false, &card_b);
    if (res == PM3_SUCCESS) {
        if (rf != NULL) {
            rf->present = true;
            rf->protocol = ISODEP_NFCB;
            rf->has_14b = true;
            rf->card_b = card_b;
        }
        return PM3_SUCCESS;
    }

    return res;
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

static int calypso_select_aid(const uint8_t *aid, size_t aid_len, bool verbose, const calypso_rf_info_t *rf, calypso_select_result_t *selected, bool *matched) {
    *matched = false;

    uint8_t response[APDU_RES_LEN] = {0};
    size_t response_len = 0;
    uint16_t sw = 0;

    int res = Iso7816Select(CC_CONTACTLESS, false, true, (uint8_t *)aid, aid_len, response, sizeof(response), &response_len, &sw);
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
    if (rf != NULL) {
        selected->rf = *rf;
    }
    if (selected->rf.present == false) {
        selected->rf.protocol = GetISODEPState();
    }
    memcpy(selected->fci, response, response_len);
    selected->fci_len = response_len;
    selected->sw = sw;
    selected->parsed = fci;

    *matched = true;
    return PM3_SUCCESS;
}

static int calypso_scan_aidlist(const calypso_rf_info_t *rf, bool verbose, calypso_select_result_t *selected, bool *matched) {
    *matched = false;

    json_t *root = AIDSearchInit(verbose);
    if (root == NULL) {
        return PM3_EFILE;
    }

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

            int res = calypso_select_aid(aid, (size_t)aid_len, verbose, rf, selected, matched);
            if (res != PM3_SUCCESS) {
                AIDSearchFree(root);
                return res;
            }

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
        int res = calypso_select_aid(probe_selected.requested_aid, probe_selected.requested_aid_len, verbose, rf, selected, &restored);
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

static bool calypso_sw_is_acceptable_warning(uint16_t sw) {
    return sw == 0x6282 || sw == 0x6283;
}

static bool calypso_sw_should_try_legacy_cla(uint16_t sw) {
    return sw == 0x6D00 || sw == 0x6E00;
}

static bool calypso_read_sw_has_data(uint16_t sw, size_t read_len) {
    return (sw == ISO7816_OK || sw == 0x6282) && read_len > 0;
}

static bool calypso_read_sw_is_eof(uint16_t sw) {
    return sw == 0x6A83;
}

static bool calypso_read_sw_is_unavailable(uint16_t sw) {
    return sw == 0x6A82 || sw == 0x6982 || sw == 0x6986 || sw == 0x6A83;
}

static bool calypso_select_sw_has_file(uint16_t sw) {
    return sw == ISO7816_OK || sw == 0x6283;
}

static int calypso_exchange_apdu(sAPDU_t apdu, bool include_le, uint16_t le, uint8_t *out, size_t out_len, size_t *read_len, uint16_t *sw) {
    int res = Iso7816ExchangeEx(CC_CONTACTLESS, false, true, apdu, include_le, le, out, out_len, read_len, sw);
    if (res == PM3_SUCCESS && sw != NULL && (*sw >> 8) == 0x6C && include_le) {
        // ISO 7816 SW 6Cxx means Le was wrong; SW2 carries the length to retry.
        uint16_t corrected_le = *sw & 0xFF;
        if (corrected_le == 0) {
            corrected_le = 0x100;
        }
        *read_len = 0;
        *sw = 0;
        res = Iso7816ExchangeEx(CC_CONTACTLESS, false, true, apdu, include_le, corrected_le, out, out_len, read_len, sw);
    }
    return res;
}

static int calypso_exchange_apdu_with_cla_fallback(sAPDU_t apdu, bool include_le, uint16_t le, uint8_t *out, size_t out_len, size_t *read_len, uint16_t *sw) {
    int res = calypso_exchange_apdu(apdu, include_le, le, out, out_len, read_len, sw);
    if (res == PM3_SUCCESS && sw != NULL && calypso_sw_should_try_legacy_cla(*sw) && calypso_sw_is_acceptable_warning(*sw) == false && apdu.CLA == 0x00) {
        // Some legacy Calypso file/record commands reject CLA 00 but accept CLA 94.
        // Only retry when the standard CLA is explicitly unsupported.
        apdu.CLA = 0x94;
        *read_len = 0;
        *sw = 0;
        res = calypso_exchange_apdu(apdu, include_le, le, out, out_len, read_len, sw);
    }
    return res;
}

static int calypso_get_data_object(uint16_t tag, uint8_t *out, size_t out_len, size_t *read_len, uint16_t *sw) {
    sAPDU_t apdu = {
        0x00,
        ISO7816_GET_DATA,
        (uint8_t)(tag >> 8),
        (uint8_t)(tag & 0xFF),
        0,
        NULL
    };

    return calypso_exchange_apdu(apdu, true, 0, out, out_len, read_len, sw);
}

static int calypso_unselect_file(uint16_t *sw) {
    uint8_t response[APDU_RES_LEN] = {0};
    size_t response_len = 0;
    sAPDU_t apdu = {0x00, ISO7816_SELECT_FILE, CALYPSO_SELECT_CURRENT_DF_P1, CALYPSO_SELECT_CURRENT_DF_P2, 0, NULL};
    return calypso_exchange_apdu_with_cla_fallback(apdu, true, 0, response, sizeof(response), &response_len, sw);
}

static int calypso_read_sfi_record(uint8_t sfi, uint8_t record, uint16_t le, uint8_t *out, size_t out_len, size_t *read_len, uint16_t *sw) {
    uint8_t response[APDU_RES_LEN] = {0};
    size_t response_len = 0;

    sAPDU_t apdu = {0x00, CALYPSO_READ_RECORD, record, (sfi << 3) | 0x04, 0, NULL};
    int res = calypso_exchange_apdu_with_cla_fallback(apdu, true, le, response, sizeof(response), &response_len, sw);

    if (res != PM3_SUCCESS || calypso_read_sw_has_data(*sw, response_len) == false) {
        *read_len = 0;
        return res;
    }

    *read_len = MIN(response_len, out_len);
    memcpy(out, response, *read_len);
    return PM3_SUCCESS;
}

static int calypso_select_file_id_with_p1_fallback(uint16_t file_id, uint8_t *response, size_t response_max, size_t *response_len, uint16_t *sw) {
    uint8_t file_id_data[] = {
        (uint8_t)(file_id >> 8),
        (uint8_t)(file_id & 0xFF),
    };
    sAPDU_t apdu = {0x00, ISO7816_SELECT_FILE, CALYPSO_SELECT_FILE_ID_P1, CALYPSO_SELECT_FILE_ID_P2, sizeof(file_id_data), file_id_data};
    int res = calypso_exchange_apdu_with_cla_fallback(apdu, true, 0, response, response_max, response_len, sw);
    if (res != PM3_SUCCESS || calypso_select_sw_has_file(*sw)) {
        return res;
    }

    // Prefer ISO-style file-id selection, but retry the Calypso current-DF LID form when rejected.
    *response_len = 0;
    *sw = 0;
    apdu.P1 = CALYPSO_SELECT_CURRENT_DF_P1;
    apdu.P2 = CALYPSO_SELECT_CURRENT_DF_P2;
    return calypso_exchange_apdu_with_cla_fallback(apdu, true, 0, response, response_max, response_len, sw);
}

static int calypso_select_file_by_id(uint16_t file_id, uint16_t *sw) {
    uint8_t response[APDU_RES_LEN] = {0};
    size_t response_len = 0;

    return calypso_select_file_id_with_p1_fallback(file_id, response, sizeof(response), &response_len, sw);
}

static int calypso_read_current_record(uint8_t record, uint16_t le, uint8_t *out, size_t out_len, size_t *read_len, uint16_t *sw) {
    uint8_t response[APDU_RES_LEN] = {0};
    size_t response_len = 0;

    sAPDU_t apdu = {0x00, CALYPSO_READ_RECORD, record, 0x04, 0, NULL};
    int res = calypso_exchange_apdu_with_cla_fallback(apdu, true, le, response, sizeof(response), &response_len, sw);

    if (res != PM3_SUCCESS || calypso_read_sw_has_data(*sw, response_len) == false) {
        *read_len = 0;
        return res;
    }

    *read_len = MIN(response_len, out_len);
    memcpy(out, response, *read_len);
    return PM3_SUCCESS;
}

static int calypso_read_icc_file(uint8_t *icc, size_t icc_len, size_t *read_len, uint16_t *sw) {
    uint16_t unselect_sw = 0;
    calypso_unselect_file(&unselect_sw);

    int res = calypso_select_file_by_id(CALYPSO_ICC_FILE_ID, sw);
    if (res != PM3_SUCCESS || calypso_select_sw_has_file(*sw) == false) {
        *read_len = 0;
        return res;
    }

    return calypso_read_current_record(0x01, CALYPSO_ICC_RECORD_LEN, icc, icc_len, read_len, sw);
}

static int calypso_read_icc(uint8_t *icc, size_t icc_len, size_t *read_len, uint16_t *sw) {
    int res = calypso_read_sfi_record(CALYPSO_ICC_SFI, 0x01, 0, icc, icc_len, read_len, sw);
    if (res == PM3_SUCCESS && *sw == ISO7816_OK && *read_len > 0) {
        return res;
    }
    if (res == PM3_SUCCESS && *sw == ISO7816_OK && *read_len == 0) {
        res = calypso_read_sfi_record(CALYPSO_ICC_SFI, 0x01, CALYPSO_ICC_RECORD_LEN, icc, icc_len, read_len, sw);
        if (res == PM3_SUCCESS && *sw == ISO7816_OK && *read_len > 0) {
            return res;
        }
    }

    return calypso_read_icc_file(icc, icc_len, read_len, sw);
}

static bool calypso_icc_matches_fci_serial(const uint8_t *icc, size_t icc_len, const uint8_t *fci_serial) {
    if (icc_len < CALYPSO_ICC_RECORD_LEN || calypso_is_zero(icc, icc_len)) {
        return false;
    }

    if (fci_serial != NULL && memcmp(&icc[CALYPSO_ICC_SERIAL_OFF], fci_serial, CALYPSO_SERIAL_LEN) != 0) {
        return false;
    }

    return true;
}

static bool calypso_should_try_master_file_icc(const calypso_select_result_t *selected) {
    if (selected->parsed.has_serial == false || calypso_serial_is_hce(selected->parsed.serial)) {
        return false;
    }

    return selected->parsed.has_startup == false || selected->parsed.startup[1] != 0xE0;
}

static bool calypso_read_icc_from_master_file(const calypso_select_result_t *selected, bool verbose, uint8_t *icc, size_t icc_len, size_t *read_len, uint16_t *sw) {
    static const uint8_t calypso_mf_aid[] = {0x33, 0x4D, 0x54, 0x52, 0x2E, 0x49, 0x43, 0x41};
    const uint8_t *fci_serial = selected->parsed.has_serial ? selected->parsed.serial : NULL;
    calypso_select_result_t mf = {0};
    bool matched = false;
    calypso_rf_info_t rf = selected->rf;

    int res = calypso_select_aid(calypso_mf_aid, sizeof(calypso_mf_aid), verbose, &rf, &mf, &matched);
    if (res != PM3_SUCCESS || matched == false) {
        return false;
    }
    if (mf.parsed.has_serial && fci_serial != NULL && memcmp(mf.parsed.serial, fci_serial, CALYPSO_SERIAL_LEN) != 0) {
        return false;
    }

    uint8_t candidate[CALYPSO_ICC_RECORD_LEN] = {0};
    size_t candidate_len = 0;
    uint16_t candidate_sw = 0;
    res = calypso_read_icc(candidate, sizeof(candidate), &candidate_len, &candidate_sw);
    if (res != PM3_SUCCESS || candidate_sw != ISO7816_OK || calypso_icc_matches_fci_serial(candidate, candidate_len, fci_serial) == false) {
        return false;
    }

    *read_len = MIN(candidate_len, icc_len);
    memcpy(icc, candidate, *read_len);
    *sw = candidate_sw;
    return true;
}

static int calypso_read_ticketing_environment_file(uint8_t *env, size_t env_len, size_t *read_len, uint16_t *sw) {
    uint16_t unselect_sw = 0;
    calypso_unselect_file(&unselect_sw);

    int res = calypso_select_file_by_id(CALYPSO_TICKET_DIR_ID, sw);
    if (res != PM3_SUCCESS || calypso_select_sw_has_file(*sw) == false) {
        *read_len = 0;
        return res;
    }

    res = calypso_select_file_by_id(CALYPSO_TICKET_ENV_FILE_ID, sw);
    if (res != PM3_SUCCESS || calypso_select_sw_has_file(*sw) == false) {
        *read_len = 0;
        return res;
    }

    res = calypso_read_current_record(0x01, 0, env, env_len, read_len, sw);
    if (res == PM3_SUCCESS && *sw == ISO7816_OK && *read_len == 0) {
        res = calypso_read_current_record(0x01, CALYPSO_LEGACY_RECORD_LEN, env, env_len, read_len, sw);
    }
    return res;
}

static int calypso_read_ticketing_environment(uint8_t *env, size_t env_len, size_t *read_len, uint16_t *sw) {
    int res = calypso_read_sfi_record(CALYPSO_TICKET_ENV_SFI, 0x01, 0, env, env_len, read_len, sw);
    if (res == PM3_SUCCESS && *sw == ISO7816_OK && *read_len > 0) {
        return res;
    }
    if (res == PM3_SUCCESS && *sw == ISO7816_OK && *read_len == 0) {
        res = calypso_read_sfi_record(CALYPSO_TICKET_ENV_SFI, 0x01, CALYPSO_LEGACY_RECORD_LEN, env, env_len, read_len, sw);
        if (res == PM3_SUCCESS && *sw == ISO7816_OK && *read_len > 0) {
            return res;
        }
    }

    return calypso_read_ticketing_environment_file(env, env_len, read_len, sw);
}

static void calypso_hex_nospace(const uint8_t *data, size_t data_len, char *out, size_t out_len) {
    if (out_len == 0) {
        return;
    }

    size_t pos = 0;
    for (size_t i = 0; i < data_len && pos + 2 < out_len; i++) {
        int written = snprintf(out + pos, out_len - pos, "%02X", data[i]);
        if (written != 2) {
            break;
        }
        pos += 2;
    }
    out[pos] = '\0';
}

static void calypso_dump_context_add_serial(calypso_dump_context_t *ctx, const calypso_select_result_t *selected) {
    if (ctx == NULL || selected == NULL || selected->parsed.has_serial == false) {
        return;
    }

    for (size_t i = 0; i < ctx->serial_count; i++) {
        if (memcmp(ctx->serials[i], selected->parsed.serial, CALYPSO_SERIAL_LEN) == 0) {
            return;
        }
    }

    if (ctx->serial_count >= ARRAYLEN(ctx->serials)) {
        return;
    }

    memcpy(ctx->serials[ctx->serial_count], selected->parsed.serial, CALYPSO_SERIAL_LEN);
    ctx->serial_count++;
}

static void calypso_dump_default_filename(const calypso_select_result_t *selected, const calypso_dump_context_t *ctx, char *filename, size_t filename_len) {
    bool hce_filename = selected != NULL && selected->parsed.has_serial && calypso_serial_is_hce(selected->parsed.serial);

    if (ctx != NULL && ctx->serial_count > 0) {
        char serials[CALYPSO_DUMP_FILENAME_MAX_SERIALS * (CALYPSO_SERIAL_LEN * 2 + 1)] = {0};
        size_t pos = 0;

        for (size_t i = 0; i < ctx->serial_count && pos < sizeof(serials); i++) {
            int written = 0;
            if (i > 0) {
                written = snprintf(serials + pos, sizeof(serials) - pos, "-");
                if (written < 0 || (size_t)written >= sizeof(serials) - pos) {
                    break;
                }
                pos += (size_t)written;
            }

            const uint8_t *serial_data = ctx->serials[i];
            size_t serial_len = CALYPSO_SERIAL_LEN;
            if (hce_filename && calypso_serial_is_hce(serial_data)) {
                serial_data += CALYPSO_HCE_TOKEN_LEN;
                serial_len -= CALYPSO_HCE_TOKEN_LEN;
            }

            char serial[CALYPSO_SERIAL_LEN * 2 + 1] = {0};
            calypso_hex_nospace(serial_data, serial_len, serial, sizeof(serial));
            written = snprintf(serials + pos, sizeof(serials) - pos, "%s", serial);
            if (written < 0 || (size_t)written >= sizeof(serials) - pos) {
                break;
            }
            pos += (size_t)written;
        }

        snprintf(filename, filename_len, "%s%s-dump", hce_filename ? "hf-calypso-hce-" : "hf-calypso-", serials);
        return;
    }

    if (selected == NULL || selected->parsed.has_serial == false) {
        snprintf(filename, filename_len, "hf-calypso-dump");
        return;
    }

    char serial[CALYPSO_SERIAL_LEN * 2 + 1] = {0};
    const uint8_t *serial_data = selected->parsed.serial;
    size_t serial_len = CALYPSO_SERIAL_LEN;
    if (hce_filename) {
        serial_data += CALYPSO_HCE_TOKEN_LEN;
        serial_len -= CALYPSO_HCE_TOKEN_LEN;
    }

    calypso_hex_nospace(serial_data, serial_len, serial, sizeof(serial));
    snprintf(filename, filename_len, "%s%s-dump", hce_filename ? "hf-calypso-hce-" : "hf-calypso-", serial);
}

static void calypso_json_set_hex(json_t *obj, const char *key, const uint8_t *data, size_t data_len) {
    char hex[APDU_RES_LEN * 2 + 1] = {0};
    calypso_hex_nospace(data, data_len, hex, sizeof(hex));
    json_object_set_new(obj, key, json_string(hex));
}

static void calypso_json_set_sw(json_t *obj, const char *key, uint16_t sw) {
    char hex[5] = {0};
    snprintf(hex, sizeof(hex), "%04X", sw);
    json_object_set_new(obj, key, json_string(hex));
}

static void calypso_json_add_record(json_t *records, uint8_t record, const uint8_t *data, size_t data_len) {
    json_t *entry = json_object();
    json_object_set_new(entry, "record", json_integer(record));
    calypso_json_set_hex(entry, "data", data, data_len);
    json_array_append_new(records, entry);
}

static void calypso_json_add_select(json_t *root, const calypso_select_result_t *selected) {
    json_object_set_new(root, "type", json_string("calypso"));
    calypso_json_set_sw(root, "selectStatus", selected->sw);
    calypso_json_set_hex(root, "selectAid", selected->requested_aid, selected->requested_aid_len);
    calypso_json_set_hex(root, "fci", selected->fci, selected->fci_len);
    if (selected->parsed.has_df_name) {
        calypso_json_set_hex(root, "fciDfName", selected->parsed.df_name, selected->parsed.df_name_len);
    }
    if (selected->parsed.has_serial) {
        calypso_json_set_hex(root, "serial", selected->parsed.serial, sizeof(selected->parsed.serial));
    }
    if (selected->parsed.has_startup) {
        calypso_json_set_hex(root, "startupInfo", selected->parsed.startup, sizeof(selected->parsed.startup));
    }
}

static void calypso_json_add_get_data(json_t *entries, const calypso_get_data_probe_t *probe, const uint8_t *data, size_t data_len) {
    char tag[5] = {0};
    snprintf(tag, sizeof(tag), "%04X", probe->tag);

    json_t *entry = json_object();
    json_object_set_new(entry, "tag", json_string(tag));
    json_object_set_new(entry, "name", json_string(probe->name));
    calypso_json_set_hex(entry, "data", data, data_len);
    json_array_append_new(entries, entry);
}

static size_t calypso_probe_get_data_objects(json_t *entries, bool print_results, bool verbose) {
    size_t found = 0;

    if (print_results || verbose) {
        PrintAndLogEx(INFO, "");
        PrintAndLogEx(INFO, "--- " _CYAN_("Get Data Objects") " ----------------------");
    }

    for (size_t i = 0; i < ARRAYLEN(calypso_get_data_probes); i++) {
        const calypso_get_data_probe_t *probe = &calypso_get_data_probes[i];
        uint8_t response[APDU_RES_LEN] = {0};
        size_t response_len = 0;
        uint16_t sw = 0;
        int res = calypso_get_data_object(probe->tag, response, sizeof(response), &response_len, &sw);

        if (res != PM3_SUCCESS) {
            if (verbose) {
                PrintAndLogEx(INFO, " %04X %-24s : exchange failed (%d)", probe->tag, probe->name, res);
            }
            continue;
        }

        if (calypso_read_sw_has_data(sw, response_len)) {
            if (print_results || verbose) {
                PrintAndLogEx(SUCCESS, " %04X %-24s : " _YELLOW_("%s"), probe->tag, probe->name, sprint_hex(response, response_len));
                if (verbose && probe->tlv) {
                    TLVPrintFromBuffer(response, (int)response_len);
                }
            }
            if (entries != NULL) {
                calypso_json_add_get_data(entries, probe, response, response_len);
            }
            found++;
            continue;
        }

        if (verbose) {
            PrintAndLogEx(INFO, " %04X %-24s : " _YELLOW_("%04X") " - %s", probe->tag, probe->name, sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
        }
    }

    return found;
}

static const char *calypso_file_name_for_sfi(uint8_t sfi) {
    for (size_t i = 0; i < ARRAYLEN(calypso_file_refs); i++) {
        if (calypso_file_refs[i].sfi == sfi) {
            return calypso_file_refs[i].name;
        }
    }
    return NULL;
}

static void calypso_file_path_string(const calypso_file_ref_t *file, char *out, size_t out_len) {
    if (out_len == 0) {
        return;
    }

    size_t pos = 0;
    for (size_t i = 0; i < file->path_len; i++) {
        int written = snprintf(out + pos, out_len - pos, "%s%04X", i == 0 ? "" : ":", file->path[i]);
        if (written < 0 || (size_t)written >= out_len - pos) {
            break;
        }
        pos += (size_t)written;
    }
}

static int calypso_read_binary_sfi(uint8_t sfi, uint8_t *out, size_t out_len, size_t *read_len, uint16_t *sw) {
    uint8_t response[APDU_RES_LEN] = {0};
    size_t response_len = 0;
    sAPDU_t apdu = {0x00, CALYPSO_READ_BINARY, (uint8_t)(0x80 | sfi), 0x00, 0, NULL};
    int res = calypso_exchange_apdu_with_cla_fallback(apdu, true, 0, response, sizeof(response), &response_len, sw);

    if (res != PM3_SUCCESS || calypso_read_sw_has_data(*sw, response_len) == false) {
        *read_len = 0;
        return res;
    }

    *read_len = MIN(response_len, out_len);
    memcpy(out, response, *read_len);
    return PM3_SUCCESS;
}

static int calypso_read_current_binary(uint8_t *out, size_t out_len, size_t *read_len, uint16_t *sw) {
    uint8_t response[APDU_RES_LEN] = {0};
    size_t response_len = 0;
    sAPDU_t apdu = {0x00, CALYPSO_READ_BINARY, 0x00, 0x00, 0, NULL};
    int res = calypso_exchange_apdu_with_cla_fallback(apdu, true, 0, response, sizeof(response), &response_len, sw);

    if (res != PM3_SUCCESS || calypso_read_sw_has_data(*sw, response_len) == false) {
        *read_len = 0;
        return res;
    }

    *read_len = MIN(response_len, out_len);
    memcpy(out, response, *read_len);
    return PM3_SUCCESS;
}

static int calypso_select_file_element(uint16_t file_id, uint8_t *fci, size_t fci_len, size_t *read_len, uint16_t *sw) {
    uint8_t response[APDU_RES_LEN] = {0};
    size_t response_len = 0;
    int res = calypso_select_file_id_with_p1_fallback(file_id, response, sizeof(response), &response_len, sw);

    *read_len = MIN(response_len, fci_len);
    memcpy(fci, response, *read_len);
    return res;
}

static int calypso_select_file_path(const calypso_file_ref_t *file, uint8_t *fci, size_t fci_len, size_t *read_len, uint16_t *sw) {
    uint16_t unselect_sw = 0;
    calypso_unselect_file(&unselect_sw);

    size_t last_len = 0;
    uint16_t last_sw = 0;
    int res = PM3_SUCCESS;
    for (size_t i = 0; i < file->path_len; i++) {
        last_len = 0;
        last_sw = 0;
        res = calypso_select_file_element(file->path[i], fci, fci_len, &last_len, &last_sw);
        if (res != PM3_SUCCESS || calypso_select_sw_has_file(last_sw) == false) {
            break;
        }
    }

    if (res == PM3_SUCCESS && calypso_select_sw_has_file(last_sw)) {
        *read_len = last_len;
        *sw = last_sw;
        return PM3_SUCCESS;
    }

    if (res != PM3_SUCCESS) {
        *read_len = 0;
        *sw = last_sw;
        return res;
    }

    *read_len = 0;
    *sw = last_sw;
    return PM3_SUCCESS;
}

static bool calypso_dump_print_record(uint8_t record, const uint8_t *data, size_t data_len, json_t *records, bool print_record) {
    if (data_len == 0) {
        return false;
    }

    if (print_record) {
        PrintAndLogEx(SUCCESS, "  record " _GREEN_("%03u") "       : " _GREEN_("%s"), record, sprint_hex(data, data_len));
    }
    if (records != NULL) {
        calypso_json_add_record(records, record, data, data_len);
    }
    return true;
}

static void calypso_dump_print_json_records(json_t *records) {
    if (records == NULL) {
        return;
    }

    size_t index = 0;
    json_t *entry = NULL;
    json_array_foreach(records, index, entry) {
        json_t *record_value = json_object_get(entry, "record");
        json_t *data_value = json_object_get(entry, "data");
        if (json_is_integer(record_value) == false || json_is_string(data_value) == false) {
            continue;
        }
        const char *hex = json_string_value(data_value);
        char grouped[APDU_RES_LEN * 3 + 1] = {0};
        size_t grouped_pos = 0;
        for (size_t i = 0; hex[i] != '\0' && hex[i + 1] != '\0' && grouped_pos + 3 < sizeof(grouped); i += 2) {
            grouped[grouped_pos++] = hex[i];
            grouped[grouped_pos++] = hex[i + 1];
            grouped[grouped_pos++] = ' ';
        }
        grouped[grouped_pos] = '\0';
        PrintAndLogEx(SUCCESS, "  record " _GREEN_("%03lld") "       : " _GREEN_("%s"),
                      (long long)json_integer_value(record_value),
                      grouped);
    }
}

static bool calypso_dump_read_records(bool sfi_mode, uint8_t sfi, json_t *records, bool print_records, bool verbose, size_t *record_count, int *first_error) {
    bool found = false;

    for (uint16_t record = 1; record <= 0xFF; record++) {
        uint8_t data[APDU_RES_LEN] = {0};
        size_t data_len = 0;
        uint16_t sw = 0;
        int res = sfi_mode ?
                  calypso_read_sfi_record(sfi, (uint8_t)record, 0, data, sizeof(data), &data_len, &sw) :
                  calypso_read_current_record((uint8_t)record, 0, data, sizeof(data), &data_len, &sw);
        if (res == PM3_SUCCESS && calypso_read_sw_has_data(sw, data_len) == false && calypso_read_sw_is_unavailable(sw) == false) {
            data_len = 0;
            sw = 0;
            res = sfi_mode ?
                  calypso_read_sfi_record(sfi, (uint8_t)record, CALYPSO_LEGACY_RECORD_LEN, data, sizeof(data), &data_len, &sw) :
                  calypso_read_current_record((uint8_t)record, CALYPSO_LEGACY_RECORD_LEN, data, sizeof(data), &data_len, &sw);
        }

        if (res != PM3_SUCCESS) {
            if (first_error != NULL && *first_error == PM3_SUCCESS) {
                *first_error = res;
            }
            return found;
        }

        if (calypso_read_sw_has_data(sw, data_len)) {
            if (data_len == 0) {
                if (verbose) {
                    PrintAndLogEx(INFO, "  record %03u stopped (empty response)", record);
                }
                return found;
            }
            found |= calypso_dump_print_record((uint8_t)record, data, data_len, records, print_records);
            (*record_count)++;
            continue;
        }

        if (calypso_read_sw_is_eof(sw) || calypso_read_sw_is_unavailable(sw)) {
            if (verbose && found == false && sw != 0) {
                PrintAndLogEx(INFO, "  records unavailable (%04X - %s)", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
            }
            return found;
        }

        if (verbose) {
            PrintAndLogEx(INFO, "  record %03u stopped (%04X - %s)", record, sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
        }
        return found;
    }

    return found;
}

static bool calypso_dump_sfi(uint8_t sfi, json_t *sfi_files, bool verbose, size_t *file_count, size_t *record_count, int *first_error) {
    uint8_t binary[APDU_RES_LEN] = {0};
    size_t binary_len = 0;
    uint16_t binary_sw = 0;
    int res = calypso_read_binary_sfi(sfi, binary, sizeof(binary), &binary_len, &binary_sw);
    if (res != PM3_SUCCESS) {
        if (first_error != NULL && *first_error == PM3_SUCCESS) {
            *first_error = res;
        }
        return false;
    }

    json_t *file = json_object();
    json_t *records = json_array();
    json_object_set_new(file, "sfi", json_integer(sfi));
    const char *name = calypso_file_name_for_sfi(sfi);
    if (name != NULL) {
        json_object_set_new(file, "name", json_string(name));
    }

    bool has_binary = calypso_read_sw_has_data(binary_sw, binary_len) && binary_len > 0;
    bool has_records = false;
    if (has_binary) {
        calypso_json_set_hex(file, "binary", binary, binary_len);
    }

    has_records = calypso_dump_read_records(true, sfi, records, false, false, record_count, first_error);
    if (json_array_size(records) > 0) {
        json_object_set_new(file, "records", records);
    } else {
        json_decref(records);
    }

    if (has_binary == false && has_records == false) {
        if (verbose && binary_sw != 0 && calypso_read_sw_is_unavailable(binary_sw) == false) {
            PrintAndLogEx(INFO, " SFI %02X unavailable (%04X - %s)", sfi, binary_sw, GetAPDUCodeDescription(binary_sw >> 8, binary_sw & 0xFF));
        }
        json_decref(file);
        return false;
    }

    PrintAndLogEx(INFO, "");
    if (name != NULL) {
        PrintAndLogEx(INFO, "--- " _CYAN_("SFI %02X") " (%s) ----------------------------", sfi, name);
    } else {
        PrintAndLogEx(INFO, "--- " _CYAN_("SFI %02X") " -----------------------------------", sfi);
    }
    if (has_binary) {
        PrintAndLogEx(SUCCESS, "  binary           : " _GREEN_("%s"), sprint_hex(binary, binary_len));
    }
    json_t *records_to_print = json_object_get(file, "records");
    calypso_dump_print_json_records(records_to_print);
    if (has_records == false && verbose) {
        calypso_dump_read_records(true, sfi, NULL, false, verbose, record_count, first_error);
    }

    json_array_append_new(sfi_files, file);
    (*file_count)++;
    return true;
}

static bool calypso_dump_file_path(const calypso_file_ref_t *ref, json_t *files, bool verbose, size_t *file_count, size_t *record_count, int *first_error) {
    uint8_t fci[APDU_RES_LEN] = {0};
    size_t fci_len = 0;
    uint16_t select_sw = 0;
    int res = calypso_select_file_path(ref, fci, sizeof(fci), &fci_len, &select_sw);
    if (res != PM3_SUCCESS) {
        if (first_error != NULL && *first_error == PM3_SUCCESS) {
            *first_error = res;
        }
        return false;
    }

    if (calypso_select_sw_has_file(select_sw) == false) {
        if (verbose && calypso_read_sw_is_unavailable(select_sw) == false) {
            char path[16] = {0};
            calypso_file_path_string(ref, path, sizeof(path));
            PrintAndLogEx(INFO, " File %s unavailable (%04X - %s)", path, select_sw, GetAPDUCodeDescription(select_sw >> 8, select_sw & 0xFF));
        }
        return false;
    }

    uint8_t binary[APDU_RES_LEN] = {0};
    size_t binary_len = 0;
    uint16_t binary_sw = 0;
    res = calypso_read_current_binary(binary, sizeof(binary), &binary_len, &binary_sw);
    if (res != PM3_SUCCESS) {
        if (first_error != NULL && *first_error == PM3_SUCCESS) {
            *first_error = res;
        }
        return false;
    }

    json_t *file = json_object();
    json_t *records = json_array();
    char path[16] = {0};
    calypso_file_path_string(ref, path, sizeof(path));
    json_object_set_new(file, "name", json_string(ref->name));
    json_object_set_new(file, "path", json_string(path));
    if (fci_len > 0) {
        calypso_json_set_hex(file, "fci", fci, fci_len);
    }
    if (calypso_read_sw_has_data(binary_sw, binary_len) && binary_len > 0) {
        calypso_json_set_hex(file, "binary", binary, binary_len);
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("%s") " (%s) --------------------", ref->name, path);
    if (fci_len > 0) {
        PrintAndLogEx(SUCCESS, "  fci              : " _YELLOW_("%s"), sprint_hex(fci, fci_len));
    }
    if (calypso_read_sw_has_data(binary_sw, binary_len) && binary_len > 0) {
        PrintAndLogEx(SUCCESS, "  binary           : " _GREEN_("%s"), sprint_hex(binary, binary_len));
    } else if (verbose && binary_sw != 0 && calypso_read_sw_is_unavailable(binary_sw) == false) {
        PrintAndLogEx(INFO, "  binary unavailable (%04X - %s)", binary_sw, GetAPDUCodeDescription(binary_sw >> 8, binary_sw & 0xFF));
    }

    calypso_dump_read_records(false, 0, records, true, verbose, record_count, first_error);
    if (json_array_size(records) > 0) {
        json_object_set_new(file, "records", records);
    } else {
        json_decref(records);
    }

    json_array_append_new(files, file);
    (*file_count)++;
    return true;
}

static void calypso_reselect_exact_df_name(const calypso_select_result_t *selected, bool verbose) {
    if (selected->parsed.has_df_name == false || selected->parsed.df_name_len == 0) {
        return;
    }

    calypso_select_result_t exact = {0};
    bool matched = false;
    calypso_rf_info_t rf = selected->rf;
    int res = calypso_select_aid(selected->parsed.df_name, selected->parsed.df_name_len, verbose, &rf, &exact, &matched);
    if (verbose && (res != PM3_SUCCESS || matched == false)) {
        PrintAndLogEx(DEBUG, "Unable to reselect exact Calypso DF name %s before file reads", sprint_hex_inrow(selected->parsed.df_name, selected->parsed.df_name_len));
    }
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

static void calypso_print_rf_hex_line(const char *label, const uint8_t *data, size_t data_len) {
    if (data == NULL || data_len == 0) {
        return;
    }
    PrintAndLogEx(SUCCESS, "%s" _YELLOW_("%s"), label, sprint_hex(data, data_len));
}

static void calypso_print_rf_info(const calypso_rf_info_t *rf) {
    isodep_state_t protocol = rf != NULL && rf->present ? rf->protocol : GetISODEPState();

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("RF Interface") " ----------------------------");
    PrintAndLogEx(SUCCESS, " RF protocol       : " _GREEN_("%s"), calypso_rf_protocol_desc(protocol));

    if (rf == NULL || rf->present == false) {
        return;
    }

    if (rf->has_14a) {
        calypso_print_rf_hex_line(" UID               : ", rf->card_a.uid, rf->card_a.uidlen);
        calypso_print_rf_hex_line(" ATS               : ", rf->card_a.ats, rf->card_a.ats_len);
    } else if (rf->has_14b) {
        calypso_print_rf_hex_line(" PUPI              : ", rf->card_b.uid, rf->card_b.uidlen);
        calypso_print_rf_hex_line(" ATQB              : ", rf->card_b.atqb, sizeof(rf->card_b.atqb));
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

static void calypso_select_identity(const calypso_select_result_t *selected, calypso_app_identity_t *identity) {
    memset(identity, 0, sizeof(*identity));

    const uint8_t *aid = selected->requested_aid;
    size_t aid_len = selected->requested_aid_len;
    if (selected->parsed.has_df_name && selected->parsed.df_name_len > 0) {
        aid = selected->parsed.df_name;
        aid_len = selected->parsed.df_name_len;
    }

    identity->aid_len = MIN(aid_len, sizeof(identity->aid));
    memcpy(identity->aid, aid, identity->aid_len);
}

static bool calypso_dump_identity_seen(const calypso_app_identity_t *seen, size_t seen_count, const calypso_select_result_t *selected) {
    calypso_app_identity_t identity = {0};
    calypso_select_identity(selected, &identity);

    for (size_t i = 0; i < seen_count; i++) {
        if (seen[i].aid_len == identity.aid_len && memcmp(seen[i].aid, identity.aid, identity.aid_len) == 0) {
            return true;
        }
    }

    return false;
}

static void calypso_dump_identity_add(calypso_app_identity_t *seen, size_t seen_capacity, size_t *seen_count, const calypso_select_result_t *selected) {
    if (*seen_count >= seen_capacity) {
        return;
    }

    calypso_select_identity(selected, &seen[*seen_count]);
    (*seen_count)++;
}

static int calypso_dump_selected_df(const calypso_select_result_t *selected, json_t *dfs, bool verbose, size_t *total_sfi_file_count, size_t *total_lid_file_count, size_t *total_record_count) {
    calypso_print_select_info(selected, verbose);

    calypso_reselect_exact_df_name(selected, verbose);

    json_t *app = json_object();
    json_t *sfi_files = json_array();
    json_t *lid_files = json_array();
    calypso_json_add_select(app, selected);

    json_t *get_data = json_array();
    if (calypso_probe_get_data_objects(get_data, true, verbose) > 0) {
        json_object_set_new(app, "dataObjects", get_data);
    } else {
        json_decref(get_data);
    }
    // Some cards misbehaved on further commands after GET DATA unless the DF was reselected.
    calypso_reselect_exact_df_name(selected, verbose);

    json_object_set_new(app, "filesBySFI", sfi_files);
    json_object_set_new(app, "filesByLID", lid_files);

    size_t sfi_file_count = 0;
    size_t lid_file_count = 0;
    size_t record_count = 0;
    int first_error = PM3_SUCCESS;

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("SFI Sweep") " -------------------------------");
    // Calypso EF SFIs are 1..30, but the APDU field encodes five bits; probe 31 too for diagnostics.
    for (uint8_t sfi = 1; sfi <= CALYPSO_MAX_ENCODED_SFI; sfi++) {
        if (kbd_enter_pressed()) {
            PrintAndLogEx(WARNING, "Aborted by user");
            first_error = PM3_EOPABORTED;
            break;
        }
        calypso_dump_sfi(sfi, sfi_files, verbose, &sfi_file_count, &record_count, &first_error);
        if (first_error != PM3_SUCCESS) {
            break;
        }
    }

    if (first_error == PM3_SUCCESS) {
        calypso_reselect_exact_df_name(selected, verbose);
        PrintAndLogEx(INFO, "");
        PrintAndLogEx(INFO, "--- " _CYAN_("Search known file LID paths") " -------------");
        for (size_t i = 0; i < ARRAYLEN(calypso_file_refs); i++) {
            if (kbd_enter_pressed()) {
                PrintAndLogEx(WARNING, "Aborted by user");
                first_error = PM3_EOPABORTED;
                break;
            }
            calypso_reselect_exact_df_name(selected, verbose);
            calypso_dump_file_path(&calypso_file_refs[i], lid_files, verbose, &lid_file_count, &record_count, &first_error);
            if (first_error != PM3_SUCCESS) {
                break;
            }
        }
    }

    json_object_set_new(app, "sfiFileCount", json_integer(sfi_file_count));
    json_object_set_new(app, "lidFileCount", json_integer(lid_file_count));
    json_object_set_new(app, "recordCount", json_integer(record_count));
    json_array_append_new(dfs, app);

    *total_sfi_file_count += sfi_file_count;
    *total_lid_file_count += lid_file_count;
    *total_record_count += record_count;
    return first_error;
}

static int calypso_dump_all_declared_dfs(json_t *dfs, calypso_rf_info_t *rf, bool verbose, calypso_select_result_t *first_selected, bool *have_first_selected, calypso_dump_context_t *dump_ctx, size_t *df_count, size_t *total_sfi_file_count, size_t *total_lid_file_count, size_t *total_record_count) {
    json_t *root = AIDSearchInit(verbose);
    if (root == NULL) {
        return PM3_EFILE;
    }

    size_t seen_capacity = json_array_size(root);
    calypso_app_identity_t *seen = calloc(seen_capacity == 0 ? 1 : seen_capacity, sizeof(*seen));
    if (seen == NULL) {
        AIDSearchFree(root);
        return PM3_EMALLOC;
    }
    size_t seen_count = 0;
    int first_error = PM3_SUCCESS;
    bool reactivate_before_next_probe = false;

    for (int scan_pass = 0; scan_pass < 3 && first_error == PM3_SUCCESS; scan_pass++) {
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

            if (reactivate_before_next_probe) {
                if (verbose) {
                    PrintAndLogEx(DEBUG, "Reactivating ISO14443-4 target before probing next Calypso DF");
                }
                DropField();
                int res = calypso_connect_contactless(verbose, rf);
                if (res != PM3_SUCCESS) {
                    first_error = res;
                    break;
                }
                reactivate_before_next_probe = false;
            }

            calypso_select_result_t selected = {0};
            bool matched = false;
            int res = calypso_select_aid(aid, (size_t)aid_len, verbose, rf, &selected, &matched);
            if (res != PM3_SUCCESS) {
                first_error = res;
                break;
            }
            if (matched == false) {
                continue;
            }
            if (calypso_dump_identity_seen(seen, seen_count, &selected)) {
                if (verbose) {
                    calypso_app_identity_t identity = {0};
                    calypso_select_identity(&selected, &identity);
                    PrintAndLogEx(DEBUG, "Skipping duplicate Calypso DF %s", sprint_hex_inrow(identity.aid, identity.aid_len));
                }
                continue;
            }

            calypso_dump_identity_add(seen, seen_capacity, &seen_count, &selected);
            if (*have_first_selected == false) {
                *first_selected = selected;
                *have_first_selected = true;
            }
            (*df_count)++;
            calypso_dump_context_add_serial(dump_ctx, &selected);

            first_error = calypso_dump_selected_df(&selected, dfs, verbose, total_sfi_file_count, total_lid_file_count, total_record_count);
            if (first_error != PM3_SUCCESS) {
                break;
            }
            // HCE implementations may stop responding after sustained access; refresh before the next DF probe.
            reactivate_before_next_probe = true;
        }
    }

    free(seen);
    AIDSearchFree(root);
    return first_error;
}

static int CmdHFCalypsoDump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf calypso dump",
                  "Dump readable files and records from Calypso DFs",
                  "hf calypso dump\n"
                  "hf calypso dump --aid 315449432E494341\n"
                  "hf calypso dump -f my-calypso-dump\n"
                  "hf calypso dump --ns -v");

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "aid", "<hex>", "Calypso application AID or AID prefix (5..16 bytes)"),
        arg_str0("f", "file", "<fn>", "Specify a filename for JSON dump file"),
        arg_lit0(NULL, "ns", "no save to file"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t user_aid[CALYPSO_MAX_AID_LEN] = {0};
    int user_aid_len = 0;
    int parse_res = CLIParamHexToBuf(arg_get_str(ctx, 1), user_aid, sizeof(user_aid), &user_aid_len);

    char filename[FILE_PATH_SIZE] = {0};
    int fnlen = 0;
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool no_save = arg_get_lit(ctx, 3);
    bool verbose = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if (parse_res != PM3_SUCCESS) {
        return PM3_EINVARG;
    }
    if (user_aid_len > 0 && (user_aid_len < 5 || user_aid_len > CALYPSO_MAX_AID_LEN)) {
        PrintAndLogEx(ERR, "AID length must be 5..16 bytes, got %d", user_aid_len);
        return PM3_EINVARG;
    }

    calypso_rf_info_t rf = {0};
    int res = calypso_connect_contactless(verbose, &rf);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(WARNING, "No ISO14443-4 Calypso application selected");
        return res;
    }
    calypso_print_rf_info(&rf);

    json_t *root = json_object();
    json_t *dfs = json_array();
    json_object_set_new(root, "type", json_string("calypso-dump"));
    json_object_set_new(root, "dfs", dfs);

    size_t df_count = 0;
    size_t sfi_file_count = 0;
    size_t lid_file_count = 0;
    size_t record_count = 0;
    int first_error = PM3_SUCCESS;
    calypso_select_result_t first_selected = {0};
    bool have_first_selected = false;
    calypso_dump_context_t dump_ctx = {0};

    if (user_aid_len > 0) {
        calypso_select_result_t selected = {0};
        bool matched = false;
        res = calypso_select_aid(user_aid, (size_t)user_aid_len, verbose, &rf, &selected, &matched);
        if (res != PM3_SUCCESS) {
            DropField();
            json_decref(root);
            PrintAndLogEx(WARNING, "No ISO14443-4 Calypso application selected");
            return res;
        }

        if (matched == false) {
            DropField();
            json_decref(root);
            PrintAndLogEx(WARNING, "No Calypso application found");
            return PM3_EOPABORTED;
        }

        first_selected = selected;
        have_first_selected = true;
        df_count = 1;
        calypso_dump_context_add_serial(&dump_ctx, &selected);
        first_error = calypso_dump_selected_df(&selected, dfs, verbose, &sfi_file_count, &lid_file_count, &record_count);
    } else {
        first_error = calypso_dump_all_declared_dfs(dfs, &rf, verbose, &first_selected, &have_first_selected, &dump_ctx, &df_count, &sfi_file_count, &lid_file_count, &record_count);
        if (first_error != PM3_SUCCESS && df_count == 0) {
            DropField();
            json_decref(root);
            return first_error;
        }
        if (first_error == PM3_SUCCESS && df_count == 0) {
            DropField();
            json_decref(root);
            PrintAndLogEx(WARNING, "No Calypso application found");
            return PM3_EOPABORTED;
        }
    }

    json_object_set_new(root, "dfCount", json_integer(df_count));
    json_object_set_new(root, "sfiFileCount", json_integer(sfi_file_count));
    json_object_set_new(root, "lidFileCount", json_integer(lid_file_count));
    json_object_set_new(root, "recordCount", json_integer(record_count));

    DropField();

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Calypso Dump Summary") " --------------------");
    PrintAndLogEx(SUCCESS, " DFs               : " _GREEN_("%zu"), df_count);
    PrintAndLogEx(SUCCESS, " SFI files         : " _GREEN_("%zu"), sfi_file_count);
    PrintAndLogEx(SUCCESS, " LID files         : " _GREEN_("%zu"), lid_file_count);
    PrintAndLogEx(SUCCESS, " Records           : " _GREEN_("%zu"), record_count);

    if (no_save == false) {
        if (fnlen == 0) {
            if (have_first_selected) {
                calypso_dump_default_filename(&first_selected, &dump_ctx, filename, sizeof(filename));
            } else {
                snprintf(filename, sizeof(filename), "hf-calypso-dump");
            }
        }
        int save_res = saveFileJSONroot(filename, root, JSON_INDENT(2), true);
        if (first_error == PM3_SUCCESS && save_res != PM3_SUCCESS) {
            first_error = save_res;
        }
    }

    json_decref(root);
    PrintAndLogEx(NORMAL, "");
    return first_error;
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

    calypso_rf_info_t rf = {0};
    int res = calypso_connect_contactless(verbose, &rf);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(WARNING, "No ISO14443-4 Calypso application selected");
        return res;
    }
    calypso_print_rf_info(&rf);

    calypso_select_result_t selected = {0};
    bool matched = false;
    if (user_aid_len > 0) {
        res = calypso_select_aid(user_aid, (size_t)user_aid_len, verbose, &rf, &selected, &matched);
    } else {
        res = calypso_scan_aidlist(&rf, verbose, &selected, &matched);
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
    calypso_reselect_exact_df_name(&selected, verbose);

    uint8_t icc[CALYPSO_ICC_RECORD_LEN] = {0};
    size_t icc_len = 0;
    uint16_t icc_sw = 0;
    const uint8_t *fci_serial = selected.parsed.has_serial ? selected.parsed.serial : NULL;
    res = calypso_read_icc(icc, sizeof(icc), &icc_len, &icc_sw);
    bool icc_read_ok = res == PM3_SUCCESS && icc_sw == ISO7816_OK;
    bool icc_valid = icc_read_ok && calypso_icc_matches_fci_serial(icc, icc_len, fci_serial);
    if (icc_valid == false && calypso_should_try_master_file_icc(&selected)) {
        if (calypso_read_icc_from_master_file(&selected, verbose, icc, sizeof(icc), &icc_len, &icc_sw)) {
            icc_read_ok = true;
            icc_valid = true;
        }
        calypso_reselect_exact_df_name(&selected, verbose);
    }
    if (icc_valid || icc_read_ok) {
        calypso_print_icc(icc, icc_len, verbose, fci_serial);
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
    {"dump", CmdHFCalypsoDump, IfPm3Iso14443,   "Dump readable files and records"},
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
