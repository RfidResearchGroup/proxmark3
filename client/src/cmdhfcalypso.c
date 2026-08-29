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
#include "cmdtrace.h"
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
#include "util_posix.h" // msleep

#define CALYPSO_SERIAL_LEN       8
#define CALYPSO_STARTUP_LEN      7
#define CALYPSO_MIN_AID_LEN      5
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
#define CALYPSO_HCE_EXPIRY_LEN   2
#define CALYPSO_DUMP_FILENAME_MAX_SERIALS 8
#define CALYPSO_GET_DATA_NAME_WIDTH 22
#define CALYPSO_HEX_ENTRY_BREAK 32
#define CALYPSO_PROBE_FORM_NAME_WIDTH 10
#define CALYPSO_PROBE_SELECT_WIDTH 56
#define CALYPSO_PROBE_RESPONSE_HEX_WIDTH 81
#define CALYPSO_DUMP_HEX_ENTRY_BREAK 48

#define CALYPSO_MANUFACTURERS_RESOURCE "calypso/manufacturers"
#define CALYPSO_IC_FAMILIES_RESOURCE   "calypso/ic_families"
#define CALYPSO_OPERATORS_RESOURCE     "calypso/operators"
#define CALYPSO_NODES_RESOURCE         "calypso/nodes"
#define CALYPSO_DUMP_PATH_MAX    2
#define CALYPSO_DUMP_NODE_PATH_MAX    8
// https://docs.keyple.org/keyple-card-calypso-cpp-lib/2.2.5.6/_cmd_card_select_file_8cpp_source.html
#define CALYPSO_SELECT_CURRENT_DF_P1    0x09
#define CALYPSO_SELECT_CURRENT_DF_P2    0x00
// ISO-style path selection: data is one or more big-endian file IDs.
#define CALYPSO_SELECT_PATH_P1          0x08
#define CALYPSO_SELECT_PATH_P2          0x00
#define CALYPSO_SELECT_FILE_ID_P1       0x00
#define CALYPSO_SELECT_FILE_ID_P2       0x00
#define CALYPSO_DUMP_SOURCE_EFLIST      0x01
#define CALYPSO_DUMP_SOURCE_KNOWN       0x02
#define CALYPSO_DUMP_SOURCE_SELECTED    0x08
#define CALYPSO_DUMP_SOURCE_BRUTE       0x10
#define CALYPSO_DUMP_CANDIDATE_MAX      1600

static const uint8_t calypso_mf_aid[] = {0x33, 0x4D, 0x54, 0x52, 0x2E, 0x49, 0x43, 0x41}; // "3MTR.ICA"

typedef struct {
    bool has_df_name;
    uint8_t df_name[CALYPSO_MAX_AID_LEN];
    size_t df_name_len;
    bool has_serial;
    uint8_t serial[CALYPSO_SERIAL_LEN];
    bool has_startup;
    uint8_t startup[CALYPSO_STARTUP_LEN];
} calypso_fci_t;

typedef enum {
    CALYPSO_FILE_MF = 0x01,
    CALYPSO_FILE_DF = 0x02,
    CALYPSO_FILE_EF = 0x04,
} calypso_file_type_t;

typedef struct {
    uint8_t sfi;
    calypso_file_type_t file_type;
    uint8_t ef_type;
    uint8_t record_size;
    uint8_t num_records;
    uint16_t lids[2];
    size_t lid_count;
} calypso_fcp_t;

typedef struct {
    isodep_state_t protocol;
    union {
        iso14a_card_select_t a;
        iso14b_card_select_t b;
        iso14b_prime_card_select_t prime;
    } card;
} calypso_rf_info_t;

typedef enum {
    CALYPSO_SELECTION_NONE = 0,
    CALYPSO_SELECTION_ACTIVATION,
    CALYPSO_SELECTION_CURRENT_DF,
    CALYPSO_SELECTION_AID,
} calypso_selection_origin_t;

typedef struct {
    uint8_t data[APDU_RES_LEN];
    size_t len;
    uint16_t sw;
} calypso_apdu_response_t;

typedef struct {
    uint8_t requested_aid[CALYPSO_MAX_AID_LEN];
    size_t requested_aid_len;
    calypso_selection_origin_t origin;
    bool has_df_lid;
    uint16_t df_lid;
    calypso_rf_info_t rf;
    calypso_apdu_response_t response;
    calypso_fci_t parsed;
} calypso_select_result_t;

typedef struct {
    bool found;
    const char *vendor;
    const char *name;
    bool prefix;
    bool generic;
    size_t aid_len;
} calypso_aid_match_t;

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
    uint8_t preferred_cla;
    uint8_t alternate_cla;
    bool select_with_le;
} calypso_transport_profile_t;

typedef struct {
    uint16_t tag;
    const char *name;
    bool tlv;
    const char *profile_json_key;
} calypso_get_data_probe_t;

typedef struct {
    size_t serial_count;
    uint8_t serials[CALYPSO_DUMP_FILENAME_MAX_SERIALS][CALYPSO_SERIAL_LEN];
} calypso_dump_filename_context_t;

typedef struct {
    uint8_t p1;
    uint8_t p2;
    const char *name;
} calypso_probe_select_form_t;

typedef struct {
    const char *name;
    const uint8_t *data;
    size_t data_len;
} calypso_probe_select_data_t;

typedef struct {
    const char *name;
    bool include_le;
    uint16_t le;
} calypso_probe_select_le_t;

typedef struct {
    uint8_t aid[CALYPSO_MAX_AID_LEN];
    size_t aid_len;
} calypso_probe_anchor_t;

typedef struct {
    uint16_t lid;
    uint8_t sources;
} calypso_dump_lid_candidate_t;

typedef enum {
    CALYPSO_DUMP_PRESET_KNOWN = 0,
    CALYPSO_DUMP_PRESET_BRUTE,
} calypso_dump_preset_t;

static const CLIParserOption calypsoDumpPresetOpts[] = {
    {CALYPSO_DUMP_PRESET_KNOWN, "known"},
    {CALYPSO_DUMP_PRESET_BRUTE, "brute"},
    {0, NULL},
};

typedef struct {
    calypso_dump_lid_candidate_t items[CALYPSO_DUMP_CANDIDATE_MAX];
    size_t count;
} calypso_dump_candidate_list_t;

typedef struct {
    uint16_t path[CALYPSO_DUMP_NODE_PATH_MAX];
    size_t path_len;
    size_t depth;
    bool from_root;
    bool is_mf;
    bool has_lid;
    uint16_t lid;
    bool has_seed_lid;
    uint16_t seed_lid;
} calypso_dump_walk_context_t;

typedef struct {
    calypso_select_result_t selected;
    uint8_t select_aid[CALYPSO_MAX_AID_LEN];
    size_t select_aid_len;
    bool has_select_lid;
    uint16_t select_lid;
    calypso_apdu_response_t select_fci;
    calypso_apdu_response_t select_fcp;
    calypso_apdu_response_t select_current_fcp;
    calypso_apdu_response_t get_data_fci;
    calypso_apdu_response_t get_data_fcp;
    bool has_lid;
    uint16_t lid;
    uint8_t sources;
} calypso_dump_node_t;

typedef struct {
    uint8_t serial[CALYPSO_SERIAL_LEN];
    calypso_dump_node_t *nodes;
    size_t node_count;
    size_t node_capacity;
} calypso_dump_profile_t;

typedef struct {
    calypso_dump_profile_t items[CALYPSO_DUMP_FILENAME_MAX_SERIALS];
    size_t count;
} calypso_dump_profile_list_t;

typedef struct {
    json_t *nodes;
    const calypso_dump_profile_t *profile;
} calypso_dump_json_context_t;

static calypso_resource_t calypso_manufacturers_resource = {CALYPSO_MANUFACTURERS_RESOURCE, NULL, false};
static calypso_resource_t calypso_ic_families_resource = {CALYPSO_IC_FAMILIES_RESOURCE, NULL, false};
static calypso_resource_t calypso_operators_resource = {CALYPSO_OPERATORS_RESOURCE, NULL, false};
static calypso_resource_t calypso_nodes_resource = {CALYPSO_NODES_RESOURCE, NULL, false};

static const char *calypso_json_lookup_name(calypso_resource_t *resource, uint32_t id);
static void calypso_set_selected_result(calypso_selection_origin_t origin, const uint8_t *aid, size_t aid_len, bool has_df_lid, uint16_t df_lid, const calypso_rf_info_t *rf, const calypso_apdu_response_t *response, const calypso_fci_t *fci, calypso_select_result_t *selected);
static bool calypso_fcp_primary_lid(const calypso_fcp_t *fcp, uint16_t *lid);
static bool calypso_get_current_ef_lid(bool verbose, uint16_t *lid);
static bool calypso_get_current_file_lid(bool verbose, uint16_t *lid);
static bool calypso_read_sw_has_data(uint16_t sw, size_t read_len);
static bool calypso_select_sw_has_file(uint16_t sw);
static int calypso_get_data_object(uint16_t tag, calypso_apdu_response_t *response);
static void calypso_dump_add_profile_data_objects(json_t *profile);
static void calypso_print_hex_entry(const char *label, const uint8_t *data, size_t data_len, const char *ansi_color);
static void calypso_print_rf_info(const calypso_rf_info_t *rf);
static int calypso_exchange_read(sAPDU_t apdu, uint16_t le, calypso_apdu_response_t *response);
static int calypso_exchange_select(sAPDU_t apdu, calypso_apdu_response_t *response);
static int calypso_dump_reselect_base(const calypso_select_result_t *selected, const calypso_dump_walk_context_t *ctx, bool verbose);
static bool calypso_lid_is_valid(uint16_t lid);
static bool calypso_tlv_read_len(const uint8_t *data, size_t data_len, size_t *pos, size_t *len);
static bool calypso_fcp_lid(const uint8_t *fcp, size_t fcp_len, uint16_t *lid);
static bool calypso_fcp_lid_with_hint(const uint8_t *fcp, size_t fcp_len, bool have_hint, uint16_t hint, uint16_t *lid);
static void calypso_dump_node_copy_raw(uint8_t *dst, size_t *dst_len, const uint8_t *src, size_t src_len, size_t dst_size);
static void calypso_dump_node_set_select_response(calypso_dump_node_t *node, const uint8_t *data, size_t data_len, uint16_t sw);
static void calypso_apdu_response_set(calypso_apdu_response_t *dst, const uint8_t *src, size_t src_len, uint16_t sw);
static size_t calypso_dump_node_aid(const calypso_dump_node_t *node, const uint8_t **aid);
static bool calypso_dump_node_first_fcp(const calypso_dump_node_t *node, const uint8_t **fcp, size_t *fcp_len);
static bool calypso_dump_node_known_lid(const calypso_dump_node_t *node, uint16_t *lid);
static void calypso_dump_node_init_from_selected(calypso_dump_node_t *node, const calypso_select_result_t *selected);
static void calypso_dump_apply_fci_identity(calypso_dump_node_t *node);
static void calypso_dump_apply_profile_node(calypso_dump_node_t *node, const calypso_dump_profile_t *profile);

static int CmdHelp(const char *Cmd);

// https://docs.keypop.org/keypop-calypso-card-cpp-api/latest-stable/namespacekeypop_1_1calypso_1_1card.html#aa274077fbdeafe85dfe208791490462f
// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-2.0.pdf
static const calypso_get_data_probe_t calypso_get_data_probes[] = {
    {0x0062, "FCP For Current File", true, NULL},
    {0x006F, "FCI For Current DF", true, NULL},
    {0x00C0, "EF List", true, "efList"},
    {0x00D0, "Other application AIDs", true, "otherApplicationAids"},
    {0x0185, "Traceability Info", false, "traceabilityInformation"},
    {0x5F52, "ATR historical bytes", true, "atrHistoricalBytes"},
    {0xDF4C, "Card Certificate", false, "cardCertificate"},
    {0xDF4A, "CA Certificate", false, "caCertificate"},
    {0xDF2C, "Card Public Key", false, "cardPublicKey"},
};

static const uint8_t calypso_probe_cla_values[] = {
    0x00,
    0x94,
};

static const calypso_probe_select_form_t calypso_probe_select_forms[] = {
    {0x00, 0x00, "file-id"},
    {0x02, 0x00, "ef-ref"},
    {0x02, 0x02, "next-ef"},
    {0x03, 0x00, "parent-df"},
    {0x08, 0x00, "path"},
    {0x09, 0x00, "curr-child"},
};

static const uint8_t calypso_probe_select_data_0000[] = {0x00, 0x00};
static const uint8_t calypso_probe_select_data_3f00[] = {0x3F, 0x00};

static const calypso_probe_select_data_t calypso_probe_select_data[] = {
    {"NONE", NULL, 0},
    {"0000", calypso_probe_select_data_0000, sizeof(calypso_probe_select_data_0000)},
    {"3F00", calypso_probe_select_data_3f00, sizeof(calypso_probe_select_data_3f00)},
};

static const calypso_probe_select_le_t calypso_probe_select_le[] = {
    {"NONE", false, 0},
    {"00", true, 0},
    {"19", true, 0x19},
};

const char *CalypsoGetDataTagName(uint16_t tag) {
    for (size_t i = 0; i < ARRAYLEN(calypso_get_data_probes); i++) {
        if (calypso_get_data_probes[i].tag == tag) {
            return calypso_get_data_probes[i].name;
        }
    }
    return NULL;
}

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
    if (protocol == ISODEP_NFCB_PRIME) {
        return "ISO14443-B' / Innovatron";
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
            rf->protocol = ISODEP_NFCA;
            rf->card.a = card_a;
        }
        return PM3_SUCCESS;
    }

    iso14b_card_select_t card_b = {0};
    res = select_card_14443b_4(false, &card_b);
    if (res == PM3_SUCCESS) {
        if (rf != NULL) {
            rf->protocol = ISODEP_NFCB;
            rf->card.b = card_b;
        }
        return PM3_SUCCESS;
    }

    iso14b_prime_card_select_t card_prime = {0};
    res = select_card_14443b_prime(false, &card_prime, verbose);
    if (res == PM3_SUCCESS) {
        if (rf != NULL) {
            rf->protocol = ISODEP_NFCB_PRIME;
            rf->card.prime = card_prime;
        }
        return PM3_SUCCESS;
    }

    return res;
}

static int calypso_reactivate(bool verbose, calypso_rf_info_t *rf) {
    DropField();
    return calypso_connect_contactless(verbose, rf);
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

static void calypso_normalize_profile_serial(const uint8_t *source, uint8_t *serial) {
    memcpy(serial, source, CALYPSO_SERIAL_LEN);
    if (calypso_serial_is_hce(source)) {
        memset(serial, 0, CALYPSO_HCE_EXPIRY_LEN);
    }
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
    if (data == NULL || data_len == 0 || fci == NULL) {
        return false;
    }
    memset(fci, 0, sizeof(*fci));

    struct tlvdb *tlv = tlvdb_parse_multi(data, data_len);
    if (tlv == NULL) {
        return false;
    }

    calypso_tlv_get_df_name(tlv, fci);
    fci->has_serial = calypso_tlv_get_bytes(tlv, 0xC7, fci->serial, sizeof(fci->serial));
    fci->has_startup = calypso_tlv_get_bytes(tlv, 0x53, fci->startup, sizeof(fci->startup));

    tlvdb_free(tlv);
    return fci->has_df_name || fci->has_serial || fci->has_startup;
}

static bool calypso_fci_is_complete(const calypso_fci_t *fci) {
    return fci != NULL && fci->has_serial && fci->has_startup;
}

static void calypso_fci_merge_missing(calypso_fci_t *fci, const calypso_fci_t *fallback) {
    if (fci == NULL || fallback == NULL) {
        return;
    }
    if (fci->has_df_name == false && fallback->has_df_name) {
        memcpy(fci->df_name, fallback->df_name, fallback->df_name_len);
        fci->df_name_len = fallback->df_name_len;
        fci->has_df_name = true;
    }
    if (fci->has_serial == false && fallback->has_serial) {
        memcpy(fci->serial, fallback->serial, sizeof(fci->serial));
        fci->has_serial = true;
    }
    if (fci->has_startup == false && fallback->has_startup) {
        memcpy(fci->startup, fallback->startup, sizeof(fci->startup));
        fci->has_startup = true;
    }
}

static void calypso_fcp_add_lid(calypso_fcp_t *fcp, uint16_t lid) {
    if (calypso_lid_is_valid(lid) == false) {
        return;
    }
    for (size_t i = 0; i < fcp->lid_count; i++) {
        if (fcp->lids[i] == lid) {
            return;
        }
    }
    if (fcp->lid_count < ARRAYLEN(fcp->lids)) {
        fcp->lids[fcp->lid_count++] = lid;
    }
}

static bool calypso_parse_fcp_value(const uint8_t *value, size_t value_len, calypso_fcp_t *fcp) {
    if (value == NULL || value_len < 2) {
        return false;
    }

    fcp->sfi = value[0];
    switch (value[1]) {
        case CALYPSO_FILE_MF:
        case CALYPSO_FILE_DF:
        case CALYPSO_FILE_EF:
            fcp->file_type = (calypso_file_type_t)value[1];
            break;
        default:
            return false;
    }

    if (value_len >= 5) {
        fcp->ef_type = value[2];
        fcp->record_size = value[3];
        fcp->num_records = value[4];
    }

    if (value_len >= 0x16) {
        uint16_t tail = ((uint16_t)value[value_len - 2] << 8) | value[value_len - 1];
        if (tail == 0x3F3F) {
            return true;
        }

        uint16_t shifted = ((uint16_t)value[value_len - 3] << 8) | value[value_len - 2];
        if (value_len == 0x17) {
            calypso_fcp_add_lid(fcp, tail);
            calypso_fcp_add_lid(fcp, shifted);
            return true;
        }

        bool has_trailer = value_len >= 3 && value[value_len - 1] == 0x00;
        if (has_trailer && (shifted & 0xFF00) != 0) {
            calypso_fcp_add_lid(fcp, shifted);
        }
        calypso_fcp_add_lid(fcp, tail);
        calypso_fcp_add_lid(fcp, shifted);
    }
    return true;
}

static bool calypso_parse_fcp(const uint8_t *data, size_t data_len, calypso_fcp_t *fcp) {
    if (data == NULL || fcp == NULL) {
        return false;
    }
    memset(fcp, 0, sizeof(*fcp));

    struct tlvdb *tlv = tlvdb_parse_multi(data, data_len);
    if (tlv != NULL) {
        const struct tlv *header = tlvdb_get_tlv(tlvdb_find_full(tlv, 0x85));
        if (header != NULL) {
            bool parsed = calypso_parse_fcp_value(header->value, header->len, fcp);
            tlvdb_free(tlv);
            return parsed;
        }
        tlvdb_free(tlv);
    }

    if (data_len >= 2 && data[0] == 0x85) {
        size_t pos = 1;
        size_t value_len = 0;
        if (calypso_tlv_read_len(data, data_len, &pos, &value_len) && pos <= data_len && value_len <= data_len - pos) {
            return calypso_parse_fcp_value(data + pos, value_len, fcp);
        }
        return false;
    }
    return calypso_parse_fcp_value(data, data_len, fcp);
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

static bool calypso_json_parse_hex_uint(json_t *value, uint32_t max, uint32_t *out) {
    if (out == NULL) {
        return false;
    }

    if (json_is_integer(value)) {
        json_int_t int_value = json_integer_value(value);
        if (int_value < 0 || (uint64_t)int_value > max) {
            return false;
        }
        *out = (uint32_t)int_value;
        return true;
    }

    if (json_is_string(value) == false) {
        return false;
    }

    const char *text = json_string_value(value);
    if (text == NULL) {
        return false;
    }

    while (isspace((unsigned char) * text)) {
        text++;
    }

    errno = 0;
    char *end = NULL;
    unsigned long parsed = strtoul(text, &end, 16);
    if (errno != 0 || end == text || parsed > max) {
        return false;
    }

    while (isspace((unsigned char) * end)) {
        end++;
    }

    if (*end != '\0') {
        return false;
    }

    *out = (uint32_t)parsed;
    return true;
}

static bool calypso_json_lookup_id(json_t *obj, uint32_t *id) {
    if (obj == NULL || id == NULL) {
        return false;
    }

    json_t *value = json_object_get(obj, "id");
    if (value == NULL) {
        value = json_object_get(obj, "ID");
    }

    if (calypso_json_parse_hex_uint(value, UINT32_MAX, id) == false) {
        return false;
    }

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

static bool calypso_json_file_ref_parse(json_t *obj, calypso_file_ref_t *file) {
    if (json_is_object(obj) == false || file == NULL) {
        return false;
    }

    const char *name = calypso_json_string_get(obj, "name");
    json_t *path = json_object_get(obj, "path");
    if (name == NULL || json_is_array(path) == false) {
        return false;
    }

    size_t path_len = json_array_size(path);
    if (path_len == 0 || path_len > CALYPSO_DUMP_PATH_MAX) {
        return false;
    }

    memset(file, 0, sizeof(*file));
    file->name = name;
    file->sfi = -1;

    json_t *sfi = json_object_get(obj, "sfi");
    if (sfi != NULL && json_is_null(sfi) == false) {
        uint32_t parsed_sfi = 0;
        if (calypso_json_parse_hex_uint(sfi, CALYPSO_MAX_ENCODED_SFI, &parsed_sfi) == false) {
            return false;
        }
        file->sfi = (int)parsed_sfi;
    }

    for (size_t i = 0; i < path_len; i++) {
        uint32_t parsed_lid = 0;
        if (calypso_json_parse_hex_uint(json_array_get(path, i), UINT16_MAX, &parsed_lid) == false) {
            return false;
        }
        file->path[i] = (uint16_t)parsed_lid;
    }
    file->path_len = path_len;
    return true;
}

static bool calypso_aid_is_prefix(const uint8_t *aid, size_t aid_len) {
    return aid != NULL && aid_len == CALYPSO_MIN_AID_LEN;
}

static bool calypso_aid_is_generic(const uint8_t *aid, size_t aid_len) {
    return aid != NULL && aid_len > 0 && aid_len <= 8 && aid[0] >= 0x30 && aid[0] <= 0x34;
}

static size_t calypso_aid_len_without_trailing_zeroes(const uint8_t *aid, size_t aid_len) {
    while (aid_len > 0 && aid[aid_len - 1] == 0x00) {
        aid_len--;
    }

    return aid_len;
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

static void calypso_find_aid_match(json_t *root, const uint8_t *aid, size_t aid_len, bool fci_aid, calypso_aid_match_t *match) {
    memset(match, 0, sizeof(*match));

    if (root == NULL || aid == NULL || aid_len == 0) {
        return;
    }

    size_t prefix_aid_len = fci_aid ? calypso_aid_len_without_trailing_zeroes(aid, aid_len) : aid_len;
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

        bool exact = fci_aid && aid_len == (size_t)entry_aid_len && memcmp(aid, entry_aid, aid_len) == 0;
        if (exact == false && (prefix_aid_len < (size_t)entry_aid_len || memcmp(aid, entry_aid, (size_t)entry_aid_len) != 0)) {
            continue;
        }

        bool prefix = calypso_aid_is_prefix(entry_aid, (size_t)entry_aid_len);
        bool generic = calypso_aid_is_generic(entry_aid, (size_t)entry_aid_len);
        int score = calypso_aid_specificity(prefix, generic, (size_t)entry_aid_len);
        if (match->found && exact == false) {
            int current_score = calypso_aid_specificity(match->prefix, match->generic, match->aid_len);
            if (current_score >= score) {
                continue;
            }
        }

        match->found = true;
        match->vendor = calypso_json_string_get(data, "Vendor");
        match->name = calypso_json_string_get(data, "Name");
        match->prefix = prefix;
        match->generic = generic;
        match->aid_len = (size_t)entry_aid_len;
        if (exact) {
            return;
        }
    }
}

static const calypso_aid_match_t *calypso_best_aid_match(const calypso_aid_match_t *selected, const calypso_aid_match_t *df_name) {
    if (df_name != NULL && df_name->found) {
        return df_name;
    }

    return selected;
}

static bool calypso_df_name_matches_known_aid(json_t *root, const calypso_select_result_t *selected) {
    if (selected->parsed.has_df_name == false) {
        return false;
    }

    calypso_aid_match_t df_name_match;
    calypso_find_aid_match(root, selected->parsed.df_name, selected->parsed.df_name_len, true, &df_name_match);
    return df_name_match.found;
}

static int calypso_select_attribution_score(json_t *root, const calypso_select_result_t *selected) {
    calypso_aid_match_t selected_match;
    calypso_aid_match_t df_name_match;
    memset(&df_name_match, 0, sizeof(df_name_match));

    calypso_find_aid_match(root, selected->requested_aid, selected->requested_aid_len, false, &selected_match);
    if (selected->parsed.has_df_name) {
        calypso_find_aid_match(root, selected->parsed.df_name, selected->parsed.df_name_len, true, &df_name_match);
    }

    const calypso_aid_match_t *best = calypso_best_aid_match(&selected_match, &df_name_match);
    return best != NULL && best->found ? calypso_aid_specificity(best->prefix, best->generic, best->aid_len) : -1;
}

static int calypso_select_aid(const uint8_t *aid, size_t aid_len, bool verbose, const calypso_rf_info_t *rf, calypso_select_result_t *selected) {
    memset(selected, 0, sizeof(*selected));

    calypso_apdu_response_t response = {0};
    bool has_df_lid = false;
    uint16_t df_lid = 0;

    sAPDU_t apdu = {0x00, ISO7816_SELECT_FILE, 0x04, 0x00, (uint8_t)aid_len, (uint8_t *)aid};
    int res = calypso_exchange_select(apdu, &response);
    if (res != PM3_SUCCESS) {
        if (verbose) {
            PrintAndLogEx(DEBUG, "Select AID %s failed: %d", sprint_hex_inrow(aid, aid_len), res);
        }
        return res;
    }
    if (response.sw == 0 && response.len == 0) {
        if (verbose) {
            PrintAndLogEx(DEBUG, "Select AID %s returned an empty RF/APDU response", sprint_hex_inrow(aid, aid_len));
        }
        return PM3_EAPDU_FAIL;
    }

    if (calypso_select_sw_has_file(response.sw) == false) {
        if (verbose) {
            PrintAndLogEx(DEBUG, "Select AID %s returned %04X - %s", sprint_hex_inrow(aid, aid_len), response.sw, GetAPDUCodeDescription(response.sw >> 8, response.sw & 0xFF));
        }
        return PM3_SUCCESS;
    }

    calypso_fci_t fci = {0};
    bool has_fci = calypso_parse_fci(response.data, response.len, &fci);
    if (verbose && (has_fci == false || calypso_fci_is_complete(&fci) == false)) {
        PrintAndLogEx(DEBUG, "Select AID %s returned incomplete Calypso FCI", sprint_hex_inrow(aid, aid_len));
    }

    has_df_lid = calypso_get_current_file_lid(verbose, &df_lid);

    calypso_set_selected_result(CALYPSO_SELECTION_AID, aid, aid_len, has_df_lid, df_lid, rf,
                                &response, &fci, selected);

    return PM3_SUCCESS;
}

static bool calypso_selected_application_matches(const calypso_select_result_t *anchor,
                                                 const calypso_select_result_t *candidate,
                                                 bool selected_exact_df_name) {
    if (candidate->origin != CALYPSO_SELECTION_AID) {
        return false;
    }
    if (anchor->parsed.has_df_name) {
        if (candidate->parsed.has_df_name) {
            if (candidate->parsed.df_name_len != anchor->parsed.df_name_len ||
                    memcmp(candidate->parsed.df_name, anchor->parsed.df_name, anchor->parsed.df_name_len) != 0) {
                return false;
            }
        } else if (selected_exact_df_name == false) {
            return false;
        }
    }
    if (anchor->parsed.has_serial && candidate->parsed.has_serial &&
            memcmp(candidate->parsed.serial, anchor->parsed.serial, sizeof(anchor->parsed.serial)) != 0) {
        return false;
    }
    if (anchor->parsed.has_startup && candidate->parsed.has_startup &&
            memcmp(candidate->parsed.startup, anchor->parsed.startup, sizeof(anchor->parsed.startup)) != 0) {
        return false;
    }
    if (selected_exact_df_name == false &&
            ((anchor->parsed.has_serial && candidate->parsed.has_serial == false) ||
             (anchor->parsed.has_startup && candidate->parsed.has_startup == false))) {
        return false;
    }
    return true;
}

static int calypso_restore_selection(const calypso_select_result_t *selected, bool verbose,
                                     calypso_select_result_t *restored) {
    if (selected == NULL) {
        return PM3_EINVARG;
    }

    calypso_select_result_t anchor = *selected;
    if (restored != NULL) {
        memset(restored, 0, sizeof(*restored));
    }
    if (anchor.origin == CALYPSO_SELECTION_NONE) {
        if (restored != NULL) {
            *restored = anchor;
        }
        return PM3_SUCCESS;
    }

    const uint8_t *aids[] = {
        anchor.parsed.has_df_name ? anchor.parsed.df_name : NULL,
        anchor.requested_aid_len > 0 ? anchor.requested_aid : NULL,
    };
    const size_t aid_lens[] = {
        anchor.parsed.has_df_name ? anchor.parsed.df_name_len : 0,
        anchor.requested_aid_len,
    };

    if (aid_lens[0] == 0 && aid_lens[1] == 0) {
        if (anchor.origin == CALYPSO_SELECTION_AID) {
            return PM3_EOPABORTED;
        }
        calypso_rf_info_t rf = {0};
        int res = calypso_reactivate(verbose, &rf);
        if (res != PM3_SUCCESS || rf.protocol != anchor.rf.protocol ||
                (anchor.origin == CALYPSO_SELECTION_ACTIVATION &&
                 memcmp(rf.card.prime.div, anchor.rf.card.prime.div, ISO14B_PRIME_DIV_LEN) != 0)) {
            return res == PM3_SUCCESS ? PM3_EOPABORTED : res;
        }
        anchor.rf = rf;
        if (restored != NULL) {
            *restored = anchor;
        }
        return PM3_SUCCESS;
    }

    for (size_t i = 0; i < ARRAYLEN(aids); i++) {
        if (aids[i] == NULL || aid_lens[i] == 0 ||
                (i > 0 && aid_lens[i] == aid_lens[0] && memcmp(aids[i], aids[0], aid_lens[i]) == 0)) {
            continue;
        }

        calypso_select_result_t candidate = {0};
        int res = calypso_select_aid(aids[i], aid_lens[i], verbose, &anchor.rf, &candidate);
        if (res != PM3_SUCCESS) {
            return res;
        }
        if (calypso_selected_application_matches(&anchor, &candidate, i == 0 && anchor.parsed.has_df_name)) {
            candidate.origin = anchor.origin;
            memcpy(candidate.requested_aid, anchor.requested_aid, sizeof(candidate.requested_aid));
            candidate.requested_aid_len = anchor.requested_aid_len;
            if (candidate.has_df_lid == false && anchor.has_df_lid) {
                candidate.has_df_lid = true;
                candidate.df_lid = anchor.df_lid;
            }
            calypso_fci_merge_missing(&candidate.parsed, &anchor.parsed);
            if (restored != NULL) {
                *restored = candidate;
            }
            return PM3_SUCCESS;
        }
        if (verbose && candidate.origin != CALYPSO_SELECTION_NONE) {
            PrintAndLogEx(DEBUG, "Reselected AID %s did not match the original Calypso application", sprint_hex_inrow(aids[i], aid_lens[i]));
        }
    }

    if (verbose) {
        PrintAndLogEx(DEBUG, "Unable to restore the selected Calypso application");
    }
    return PM3_EOPABORTED;
}

static int calypso_scan_aidlist(const calypso_rf_info_t *rf, bool verbose, calypso_select_result_t *selected) {
    memset(selected, 0, sizeof(*selected));

    json_t *root = AIDSearchInit(verbose);
    if (root == NULL) {
        return PM3_EFILE;
    }

    bool probe_matched = false;
    int probe_score = -1;
    calypso_select_result_t probe_selected = {0};

    for (size_t scan_aid_len = CALYPSO_MIN_AID_LEN; scan_aid_len <= CALYPSO_MAX_AID_LEN; scan_aid_len++) {
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

            if ((size_t)aid_len != scan_aid_len) {
                continue;
            }

            bool prefix = calypso_aid_is_prefix(aid, (size_t)aid_len);
            bool generic = calypso_aid_is_generic(aid, (size_t)aid_len);

            if (AIDSeenBefore(root, aid, (size_t)aid_len, elmindx)) {
                continue;
            }

            calypso_select_result_t candidate = {0};
            int res = calypso_select_aid(aid, (size_t)aid_len, verbose, rf, &candidate);
            if (res != PM3_SUCCESS) {
                AIDSearchFree(root);
                return res;
            }

            if (candidate.origin == CALYPSO_SELECTION_NONE || calypso_fci_is_complete(&candidate.parsed) == false) {
                continue;
            }

            if (prefix || generic) {
                if (calypso_df_name_matches_known_aid(root, &candidate)) {
                    *selected = candidate;
                    AIDSearchFree(root);
                    return PM3_SUCCESS;
                }

                int score = calypso_select_attribution_score(root, &candidate);
                if (probe_matched == false || score > probe_score) {
                    probe_selected = candidate;
                    probe_score = score;
                    probe_matched = true;
                }
                continue;
            }

            *selected = candidate;
            AIDSearchFree(root);
            return PM3_SUCCESS;
        }
    }

    if (probe_matched) {
        calypso_select_result_t restored_selected = {0};
        int res = calypso_restore_selection(&probe_selected, verbose, &restored_selected);
        if (res != PM3_SUCCESS) {
            AIDSearchFree(root);
            return res;
        }
        if (restored_selected.origin == CALYPSO_SELECTION_NONE || calypso_fci_is_complete(&restored_selected.parsed) == false) {
            if (verbose) {
                PrintAndLogEx(DEBUG, "Unable to restore selected Calypso AID %s", sprint_hex_inrow(probe_selected.requested_aid, probe_selected.requested_aid_len));
            }
        } else {
            *selected = restored_selected;
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

static const char *calypso_nonempty(const char *value) {
    return value != NULL && value[0] != '\0' ? value : NULL;
}

static void calypso_print_aid_info(const calypso_select_result_t *selected, bool verbose) {
    json_t *root = AIDSearchInit(verbose);
    if (root == NULL) {
        return;
    }

    calypso_aid_match_t selected_match = {0};
    calypso_aid_match_t df_name_match = {0};
    calypso_find_aid_match(root, selected->requested_aid, selected->requested_aid_len, false, &selected_match);
    if (selected->parsed.has_df_name) {
        calypso_find_aid_match(root, selected->parsed.df_name, selected->parsed.df_name_len, true, &df_name_match);
    }

    const calypso_aid_match_t *match = calypso_best_aid_match(&selected_match, &df_name_match);
    const char *name = match != NULL ? calypso_nonempty(match->name) : NULL;
    const char *vendor = match != NULL ? calypso_nonempty(match->vendor) : NULL;
    if (name != NULL && vendor != NULL) {
        PrintAndLogEx(SUCCESS, " AID info          : " _YELLOW_("%s") " (" _YELLOW_("%s") ")", name, vendor);
    } else if (name != NULL) {
        PrintAndLogEx(SUCCESS, " AID info          : " _YELLOW_("%s"), name);
    } else if (vendor != NULL) {
        PrintAndLogEx(SUCCESS, " AID info          : " _YELLOW_("%s"), vendor);
    }

    AIDSearchFree(root);
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
    if (data == NULL || value == NULL || bit_len == 0 || bit_len > 32 || data_len > SIZE_MAX / 8) {
        return false;
    }
    size_t data_bits = data_len * 8;
    if (bit_offset > data_bits || bit_len > data_bits - bit_offset) {
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

static bool calypso_sw_should_try_alternate_cla(uint16_t sw) {
    return sw == ISO7816_INS_NOT_SUPPORTED || sw == ISO7816_CLA_NOT_SUPPORTED;
}

static bool calypso_read_sw_has_data(uint16_t sw, size_t read_len) {
    return (sw == ISO7816_OK || sw == ISO7816_FILE_EOF) && read_len > 0;
}

static bool calypso_read_sw_is_unavailable(uint16_t sw) {
    return sw == ISO7816_FILE_NOT_FOUND || sw == ISO7816_SECURITY_STATUS_NOT_SATISFIED ||
           sw == ISO7816_COMMAND_NOT_ALLOWED || sw == ISO7816_RECORD_NOT_FOUND;
}

static bool calypso_select_sw_has_file(uint16_t sw) {
    return sw == ISO7816_OK || sw == ISO7816_INVALID_DF;
}

static calypso_transport_profile_t calypso_transport_profile(void) {
    if (GetISODEPState() == ISODEP_NFCB_PRIME) {
        return (calypso_transport_profile_t) {0x94, 0x00, false};
    }
    return (calypso_transport_profile_t) {0x00, 0x94, true};
}

static int calypso_exchange_once(sAPDU_t apdu, bool include_le, uint16_t le, calypso_apdu_response_t *response) {
    if (response == NULL) {
        return PM3_EINVARG;
    }

    response->len = 0;
    response->sw = 0;
    int res = Iso7816ExchangeEx(CC_CONTACTLESS, false, true, apdu, include_le, le,
                                response->data, sizeof(response->data), &response->len, &response->sw);

    // Iso7816ExchangeEx currently returns a positive status for a valid error
    // R-APDU only when APDU logging is enabled. A received SW is transport
    // success regardless of that presentation setting.
    if (res > PM3_SUCCESS && response->sw != 0) {
        return PM3_SUCCESS;
    }
    return res;
}

static uint16_t calypso_correct_le(uint16_t sw) {
    uint16_t le = sw & 0xFF;
    return le == 0 ? 0x100 : le;
}

static int calypso_exchange_read(sAPDU_t apdu, uint16_t le, calypso_apdu_response_t *response) {
    calypso_transport_profile_t profile = calypso_transport_profile();
    const uint8_t cla[] = {profile.preferred_cla, profile.alternate_cla};
    int res = PM3_EINVARG;

    for (size_t i = 0; i < ARRAYLEN(cla); i++) {
        apdu.CLA = cla[i];
        res = calypso_exchange_once(apdu, true, le, response);
        if (res == PM3_SUCCESS && (response->sw & 0xFF00) == ISO7816_CORRECT_LENGTH_00) {
            res = calypso_exchange_once(apdu, true, calypso_correct_le(response->sw), response);
        }
        if (res != PM3_SUCCESS || calypso_sw_should_try_alternate_cla(response->sw) == false) {
            return res;
        }
    }
    return res;
}

static int calypso_exchange_select(sAPDU_t apdu, calypso_apdu_response_t *response) {
    calypso_transport_profile_t profile = calypso_transport_profile();
    const uint8_t cla[] = {profile.preferred_cla, profile.alternate_cla};
    int res = PM3_EINVARG;

    for (size_t i = 0; i < ARRAYLEN(cla); i++) {
        apdu.CLA = cla[i];
        bool include_le = profile.select_with_le;
        uint16_t le = 0;
        bool retried_6700 = false;
        bool retried_6c = false;

        for (size_t attempt = 0; attempt < 3; attempt++) {
            res = calypso_exchange_once(apdu, include_le, le, response);
            if (res != PM3_SUCCESS) {
                return res;
            }

            if ((response->sw & 0xFF00) == ISO7816_CORRECT_LENGTH_00 && retried_6c == false) {
                include_le = true;
                le = calypso_correct_le(response->sw);
                retried_6c = true;
                continue;
            }
            if (response->sw == ISO7816_WRONG_LENGTH && retried_6700 == false) {
                include_le = !include_le;
                le = 0;
                retried_6700 = true;
                continue;
            }
            break;
        }

        if (calypso_sw_should_try_alternate_cla(response->sw) == false) {
            return PM3_SUCCESS;
        }
    }
    return res;
}

static int calypso_get_data_object(uint16_t tag, calypso_apdu_response_t *response) {
    sAPDU_t apdu = {
        0x00,
        ISO7816_GET_DATA,
        (uint8_t)(tag >> 8),
        (uint8_t)(tag & 0xFF),
        0,
        NULL
    };

    return calypso_exchange_read(apdu, 0, response);
}

static void calypso_set_selected_result(calypso_selection_origin_t origin, const uint8_t *aid, size_t aid_len, bool has_df_lid, uint16_t df_lid, const calypso_rf_info_t *rf, const calypso_apdu_response_t *response, const calypso_fci_t *fci, calypso_select_result_t *selected) {
    memset(selected, 0, sizeof(*selected));
    if (aid != NULL && aid_len > 0) {
        memcpy(selected->requested_aid, aid, aid_len);
        selected->requested_aid_len = aid_len;
    }
    selected->origin = origin;
    selected->has_df_lid = has_df_lid;
    selected->df_lid = df_lid;
    selected->rf = *rf;
    if (response != NULL) {
        selected->response = *response;
    }
    if (fci != NULL) {
        selected->parsed = *fci;
    }
}

static bool calypso_activation_result(const calypso_rf_info_t *rf, calypso_select_result_t *selected) {
    if (rf == NULL || selected == NULL || rf->protocol != ISODEP_NFCB_PRIME) {
        return false;
    }

    calypso_set_selected_result(CALYPSO_SELECTION_ACTIVATION, NULL, 0, false, 0, rf, NULL, NULL, selected);
    return true;
}

static int calypso_repoll_activation(const calypso_rf_info_t *rf, bool verbose, calypso_select_result_t *selected) {
    if (rf == NULL || selected == NULL || rf->protocol != ISODEP_NFCB_PRIME) {
        return PM3_EOPABORTED;
    }

    calypso_rf_info_t repolled = {0};
    int res = calypso_reactivate(verbose, &repolled);
    if (res == PM3_SUCCESS && repolled.protocol == ISODEP_NFCB_PRIME &&
            memcmp(repolled.card.prime.div, rf->card.prime.div, ISO14B_PRIME_DIV_LEN) == 0 &&
            calypso_activation_result(&repolled, selected)) {
        return PM3_SUCCESS;
    }

    // Retain the already observed activation identity for failure reporting,
    // but never continue with operational reads unless the repoll succeeded.
    calypso_activation_result(rf, selected);
    return res == PM3_SUCCESS ? PM3_EOPABORTED : res;
}

static bool calypso_selection_is_default(const calypso_select_result_t *selected) {
    return selected != NULL &&
           (selected->origin == CALYPSO_SELECTION_ACTIVATION || selected->origin == CALYPSO_SELECTION_CURRENT_DF);
}

static bool calypso_selection_profile_serial(const calypso_select_result_t *selected, uint8_t *serial) {
    if (selected == NULL || serial == NULL) {
        return false;
    }

    if (selected->parsed.has_serial) {
        calypso_normalize_profile_serial(selected->parsed.serial, serial);
        return true;
    }
    if (selected->origin == CALYPSO_SELECTION_ACTIVATION && selected->rf.protocol == ISODEP_NFCB_PRIME) {
        memset(serial, 0, CALYPSO_SERIAL_LEN);
        memcpy(serial + CALYPSO_SERIAL_LEN - ISO14B_PRIME_DIV_LEN,
               selected->rf.card.prime.div, ISO14B_PRIME_DIV_LEN);
        return true;
    }
    return false;
}

static bool calypso_fcp_find_lid(const calypso_fcp_t *fcp, bool have_hint, uint16_t hint, uint16_t *lid) {
    if (fcp == NULL || lid == NULL || fcp->lid_count == 0) {
        return false;
    }
    for (size_t i = 0; i < fcp->lid_count; i++) {
        if (have_hint == false || fcp->lids[i] == hint) {
            *lid = fcp->lids[i];
            return true;
        }
    }
    return false;
}

static bool calypso_fcp_primary_lid(const calypso_fcp_t *fcp, uint16_t *lid) {
    return calypso_fcp_find_lid(fcp, false, 0, lid);
}

static bool calypso_get_current_ef_lid(bool verbose, uint16_t *lid) {
    calypso_apdu_response_t response = {0};
    int res = calypso_get_data_object(0x0062, &response);
    if (res != PM3_SUCCESS) {
        if (verbose) {
            PrintAndLogEx(DEBUG, "GET DATA 0062 exchange failed: %d", res);
        }
        return false;
    }

    calypso_fcp_t fcp = {0};
    if (calypso_read_sw_has_data(response.sw, response.len) && calypso_parse_fcp(response.data, response.len, &fcp)) {
        return calypso_fcp_primary_lid(&fcp, lid);
    }
    if (verbose) {
        PrintAndLogEx(DEBUG, "GET DATA 0062 did not return Calypso FCP (%04X - %s)", response.sw, GetAPDUCodeDescription(response.sw >> 8, response.sw & 0xFF));
    }
    return false;
}

static int calypso_select_current_df(bool include_file_id, calypso_apdu_response_t *response) {
    uint8_t current_df_id[] = {0x00, 0x00};
    sAPDU_t apdu = {
        0x00,
        ISO7816_SELECT_FILE,
        CALYPSO_SELECT_CURRENT_DF_P1,
        CALYPSO_SELECT_CURRENT_DF_P2,
        include_file_id ? sizeof(current_df_id) : 0,
        include_file_id ? current_df_id : NULL
    };

    return calypso_exchange_select(apdu, response);
}

static int calypso_select_current_df_with_file_id_fallback(calypso_apdu_response_t *response) {
    int res = calypso_select_current_df(false, response);
    if (res != PM3_SUCCESS || calypso_select_sw_has_file(response->sw)) {
        return res;
    }

    return calypso_select_current_df(true, response);
}

static int calypso_select_current_file_fcp(bool verbose, calypso_apdu_response_t *response, calypso_fcp_t *fcp) {
    if (response == NULL) {
        return PM3_EINVARG;
    }
    if (fcp != NULL) {
        memset(fcp, 0, sizeof(*fcp));
    }

    int res = calypso_select_current_df_with_file_id_fallback(response);
    if (res != PM3_SUCCESS) {
        response->len = 0;
        return res;
    }
    if (calypso_select_sw_has_file(response->sw) == false) {
        response->len = 0;
        return PM3_SUCCESS;
    }

    calypso_fcp_t parsed = {0};
    if (calypso_parse_fcp(response->data, response->len, &parsed) == false) {
        response->len = 0;
        if (verbose) {
            PrintAndLogEx(DEBUG, "Current DF SELECT did not return Calypso FCP (%04X - %s)", response->sw, GetAPDUCodeDescription(response->sw >> 8, response->sw & 0xFF));
        }
    } else if (fcp != NULL) {
        *fcp = parsed;
    }
    return PM3_SUCCESS;
}

static bool calypso_get_current_file_lid(bool verbose, uint16_t *lid) {
    if (lid == NULL) {
        return false;
    }

    if (calypso_get_current_ef_lid(verbose, lid)) {
        return true;
    }

    calypso_apdu_response_t response = {0};
    calypso_fcp_t fcp = {0};
    int res = calypso_select_current_file_fcp(verbose, &response, &fcp);
    if (res != PM3_SUCCESS) {
        if (verbose) {
            PrintAndLogEx(DEBUG, "Current DF SELECT exchange failed while reading LID: %d", res);
        }
        return false;
    }
    bool has_lid = calypso_fcp_primary_lid(&fcp, lid);
    if (verbose && has_lid == false && calypso_select_sw_has_file(response.sw) == false) {
        PrintAndLogEx(DEBUG, "Current DF SELECT did not select a file while reading LID (%04X - %s)", response.sw, GetAPDUCodeDescription(response.sw >> 8, response.sw & 0xFF));
    }
    return has_lid;
}

static int calypso_probe_current_df(const calypso_rf_info_t *rf, bool verbose, calypso_select_result_t *selected) {
    memset(selected, 0, sizeof(*selected));

    bool has_df_lid = false;
    uint16_t df_lid = 0;
    bool has_fci = false;
    calypso_fci_t fci = {0};
    calypso_apdu_response_t fci_response = {0};

    calypso_apdu_response_t select_response = {0};
    int select_res = calypso_select_current_df_with_file_id_fallback(&select_response);
    if (select_res != PM3_SUCCESS) {
        if (verbose) {
            PrintAndLogEx(DEBUG, "Current DF SELECT exchange failed: %d", select_res);
        }
        return PM3_SUCCESS;
    }
    bool select_has_file = calypso_select_sw_has_file(select_response.sw);
    if (select_has_file == false) {
        if (verbose) {
            PrintAndLogEx(DEBUG, "Current DF SELECT did not select a file (%04X - %s)", select_response.sw, GetAPDUCodeDescription(select_response.sw >> 8, select_response.sw & 0xFF));
        }
        return PM3_SUCCESS;
    }

    calypso_fci_t select_fci = {0};
    if (calypso_parse_fci(select_response.data, select_response.len, &select_fci)) {
        has_fci = true;
        fci_response = select_response;
        fci = select_fci;
    } else {
        calypso_fcp_t fcp = {0};
        if (calypso_parse_fcp(select_response.data, select_response.len, &fcp)) {
            has_df_lid = calypso_fcp_primary_lid(&fcp, &df_lid);
        }
        if (verbose) {
            PrintAndLogEx(DEBUG, "Current DF SELECT did not return Calypso FCI (%04X - %s)", select_response.sw, GetAPDUCodeDescription(select_response.sw >> 8, select_response.sw & 0xFF));
        }
    }

    uint8_t aid[CALYPSO_MAX_AID_LEN] = {0};
    size_t aid_len = 0;

    calypso_apdu_response_t response = {0};
    int res = calypso_get_data_object(0x006F, &response);
    if (res != PM3_SUCCESS) {
        if (verbose) {
            PrintAndLogEx(DEBUG, "GET DATA 006F exchange failed: %d", res);
        }
    } else {
        calypso_fci_t get_data_fci = {0};
        if (calypso_read_sw_has_data(response.sw, response.len) && calypso_parse_fci(response.data, response.len, &get_data_fci)) {
            calypso_fci_merge_missing(&get_data_fci, &fci);
            has_fci = true;
            fci_response = response;
            fci = get_data_fci;
        } else if (verbose) {
            PrintAndLogEx(DEBUG, "GET DATA 006F did not return Calypso FCI (%04X - %s)", response.sw, GetAPDUCodeDescription(response.sw >> 8, response.sw & 0xFF));
        }
    }

    uint16_t get_data_lid = 0;
    if (calypso_get_current_file_lid(verbose, &get_data_lid)) {
        has_df_lid = true;
        df_lid = get_data_lid;
    }

    if (fci.has_df_name && fci.df_name_len <= sizeof(aid)) {
        memcpy(aid, fci.df_name, fci.df_name_len);
        aid_len = fci.df_name_len;
    }
    calypso_set_selected_result(CALYPSO_SELECTION_CURRENT_DF, aid_len > 0 ? aid : NULL, aid_len,
                                has_df_lid, df_lid, rf, has_fci ? &fci_response : &select_response,
                                has_fci ? &fci : NULL, selected);

    return PM3_SUCCESS;
}

static int calypso_discover_primary(const calypso_rf_info_t *rf, const uint8_t *aid, size_t aid_len,
                                    bool verbose, calypso_select_result_t *selected) {
    if (rf == NULL || selected == NULL || (aid_len > 0 && aid == NULL)) {
        return PM3_EINVARG;
    }

    memset(selected, 0, sizeof(*selected));

    calypso_select_result_t current = {0};
    int res = calypso_probe_current_df(rf, verbose, &current);
    if (res != PM3_SUCCESS) {
        calypso_repoll_activation(rf, verbose, selected);
        return res;
    }

    if (aid_len > 0) {
        calypso_select_result_t requested = {0};
        res = calypso_select_aid(aid, aid_len, verbose, rf, &requested);
        if (res == PM3_SUCCESS && requested.origin != CALYPSO_SELECTION_NONE) {
            *selected = requested;
            return PM3_SUCCESS;
        }

        calypso_repoll_activation(rf, verbose, selected);
        return res == PM3_SUCCESS ? PM3_EOPABORTED : res;
    }

    if (current.origin != CALYPSO_SELECTION_NONE && calypso_fci_is_complete(&current.parsed)) {
        *selected = current;
        return PM3_SUCCESS;
    }

    res = calypso_scan_aidlist(rf, verbose, selected);
    if (res != PM3_SUCCESS) {
        calypso_repoll_activation(rf, verbose, selected);
        return res;
    }
    if (selected->origin != CALYPSO_SELECTION_NONE) {
        return PM3_SUCCESS;
    }
    return calypso_repoll_activation(rf, verbose, selected);
}

static int calypso_read_sfi_record(uint8_t sfi, uint8_t record, uint16_t le, uint8_t *out, size_t out_len, size_t *read_len, uint16_t *sw) {
    calypso_apdu_response_t response = {0};

    sAPDU_t apdu = {0x00, CALYPSO_READ_RECORD, record, (sfi << 3) | 0x04, 0, NULL};
    int res = calypso_exchange_read(apdu, le, &response);
    *sw = response.sw;

    if (res != PM3_SUCCESS || calypso_read_sw_has_data(response.sw, response.len) == false) {
        *read_len = 0;
        return res;
    }

    *read_len = MIN(response.len, out_len);
    memcpy(out, response.data, *read_len);
    return PM3_SUCCESS;
}

static int calypso_select_file_id_with_p1_fallback(uint16_t file_id, calypso_apdu_response_t *response) {
    uint8_t file_id_data[] = {
        (uint8_t)(file_id >> 8),
        (uint8_t)(file_id & 0xFF),
    };
    sAPDU_t apdu = {0x00, ISO7816_SELECT_FILE, CALYPSO_SELECT_CURRENT_DF_P1, CALYPSO_SELECT_CURRENT_DF_P2, sizeof(file_id_data), file_id_data};
    int res = calypso_exchange_select(apdu, response);
    if (res != PM3_SUCCESS || calypso_select_sw_has_file(response->sw)) {
        return res;
    }

    // Prefer modern Calypso relative-path LID selection, then retry ISO-style file-id lookup.
    apdu.P1 = CALYPSO_SELECT_FILE_ID_P1;
    apdu.P2 = CALYPSO_SELECT_FILE_ID_P2;
    return calypso_exchange_select(apdu, response);
}

static int calypso_select_file_path(const uint16_t *path, size_t path_len, calypso_apdu_response_t *response) {
    if (path == NULL || path_len == 0 || path_len > (UINT8_MAX / 2)) {
        return PM3_EINVARG;
    }

    uint8_t path_data[CALYPSO_DUMP_NODE_PATH_MAX * 2 + 2] = {0};
    if (path_len * 2 > sizeof(path_data)) {
        return PM3_EINVARG;
    }

    for (size_t i = 0; i < path_len; i++) {
        path_data[i * 2] = (uint8_t)(path[i] >> 8);
        path_data[i * 2 + 1] = (uint8_t)(path[i] & 0xFF);
    }

    sAPDU_t apdu = {
        0x00,
        ISO7816_SELECT_FILE,
        CALYPSO_SELECT_PATH_P1,
        CALYPSO_SELECT_PATH_P2,
        (uint8_t)(path_len * 2),
        path_data
    };
    return calypso_exchange_select(apdu, response);
}

static int calypso_select_file_path_then_id_fallback(const uint16_t *path, size_t path_len, uint16_t file_id, calypso_apdu_response_t *response) {
    if (path != NULL && path_len > 0) {
        int res = calypso_select_file_path(path, path_len, response);
        if (res != PM3_SUCCESS || calypso_select_sw_has_file(response->sw)) {
            return res;
        }

        if (path_len == 1 && path[0] == file_id &&
                file_id != 0x0000 && file_id != 0x3F00 && (file_id & 0x00FF) == 0) {
            // Some legacy Calypso root DFs use a duplicated path component.
            const uint16_t legacy_path[] = {file_id, file_id};
            res = calypso_select_file_path(legacy_path, ARRAYLEN(legacy_path), response);
            if (res != PM3_SUCCESS || calypso_select_sw_has_file(response->sw)) {
                return res;
            }
        }
    }

    return calypso_select_file_id_with_p1_fallback(file_id, response);
}

static int calypso_select_file_by_id(uint16_t file_id, uint16_t *sw) {
    calypso_apdu_response_t response = {0};
    int res = calypso_select_file_id_with_p1_fallback(file_id, &response);
    *sw = response.sw;
    return res;
}

static int calypso_read_current_record(uint8_t record, uint16_t le, uint8_t *out, size_t out_len, size_t *read_len, uint16_t *sw) {
    calypso_apdu_response_t response = {0};

    sAPDU_t apdu = {0x00, CALYPSO_READ_RECORD, record, 0x04, 0, NULL};
    int res = calypso_exchange_read(apdu, le, &response);
    *sw = response.sw;

    if (res != PM3_SUCCESS || calypso_read_sw_has_data(response.sw, response.len) == false) {
        *read_len = 0;
        return res;
    }

    *read_len = MIN(response.len, out_len);
    memcpy(out, response.data, *read_len);
    return PM3_SUCCESS;
}

static int calypso_read_icc_file(uint8_t *icc, size_t icc_len, size_t *read_len, uint16_t *sw) {
    calypso_apdu_response_t current_df = {0};
    calypso_select_current_df_with_file_id_fallback(&current_df);

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
    const uint8_t *fci_serial = selected->parsed.has_serial ? selected->parsed.serial : NULL;
    calypso_select_result_t mf = {0};
    calypso_rf_info_t rf = selected->rf;

    int res = calypso_select_aid(calypso_mf_aid, sizeof(calypso_mf_aid), verbose, &rf, &mf);
    if (res != PM3_SUCCESS || mf.origin == CALYPSO_SELECTION_NONE) {
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
    calypso_apdu_response_t current_df = {0};
    calypso_select_current_df_with_file_id_fallback(&current_df);

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

static void calypso_dump_filename_add_serial(calypso_dump_filename_context_t *ctx, const calypso_select_result_t *selected) {
    uint8_t serial[CALYPSO_SERIAL_LEN] = {0};
    if (ctx == NULL || calypso_selection_profile_serial(selected, serial) == false) {
        return;
    }

    for (size_t i = 0; i < ctx->serial_count; i++) {
        if (memcmp(ctx->serials[i], serial, CALYPSO_SERIAL_LEN) == 0) {
            return;
        }
    }

    if (ctx->serial_count >= ARRAYLEN(ctx->serials)) {
        return;
    }

    memcpy(ctx->serials[ctx->serial_count], serial, CALYPSO_SERIAL_LEN);
    ctx->serial_count++;
}

static void calypso_dump_default_filename(const calypso_select_result_t *selected, const calypso_dump_filename_context_t *ctx, char *filename, size_t filename_len) {
    bool hce_filename = selected != NULL && selected->parsed.has_serial && calypso_serial_is_hce(selected->parsed.serial);
    uint8_t selected_serial[CALYPSO_SERIAL_LEN] = {0};
    bool have_selected_serial = calypso_selection_profile_serial(selected, selected_serial);

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

            written = snprintf(serials + pos, sizeof(serials) - pos, "%s", sprint_hex_inrow(ctx->serials[i], CALYPSO_SERIAL_LEN));
            if (written < 0 || (size_t)written >= sizeof(serials) - pos) {
                break;
            }
            pos += (size_t)written;
        }

        snprintf(filename, filename_len, "%s%s-dump", hce_filename ? "hf-calypso-hce-" : "hf-calypso-", serials);
        return;
    }

    if (have_selected_serial == false) {
        snprintf(filename, filename_len, "hf-calypso-dump");
        return;
    }

    snprintf(filename, filename_len, "%s%s-dump", hce_filename ? "hf-calypso-hce-" : "hf-calypso-",
             sprint_hex_inrow(selected_serial, sizeof(selected_serial)));
}

static void calypso_json_set_hex(json_t *obj, const char *key, const uint8_t *data, size_t data_len) {
    json_object_set_new(obj, key, json_string(sprint_hex_inrow(data, data_len)));
}

static void calypso_json_set_lid(json_t *obj, const char *key, uint16_t lid) {
    char hex[5] = {0};
    snprintf(hex, sizeof(hex), "%04X", lid);
    json_object_set_new(obj, key, json_string(hex));
}

static void calypso_print_get_data_object(const calypso_get_data_probe_t *probe, const uint8_t *data, size_t data_len) {
    char label[64] = {0};
    snprintf(label, sizeof(label), " %04X %-*s : ", probe->tag, CALYPSO_GET_DATA_NAME_WIDTH, probe->name);
    calypso_print_hex_entry(label, data, data_len, ANSI_YELLOW);
}

static void calypso_dump_add_profile_data_objects(json_t *profile) {
    if (profile == NULL) {
        return;
    }

    for (size_t i = 0; i < ARRAYLEN(calypso_get_data_probes); i++) {
        const calypso_get_data_probe_t *probe = &calypso_get_data_probes[i];
        if (probe->profile_json_key == NULL) {
            continue;
        }

        calypso_apdu_response_t response = {0};
        int res = calypso_get_data_object(probe->tag, &response);
        if (res != PM3_SUCCESS) {
            continue;
        }
        if (response.sw == ISO7816_INS_NOT_SUPPORTED || response.sw == ISO7816_CLA_NOT_SUPPORTED) {
            break;
        }
        if (calypso_read_sw_has_data(response.sw, response.len) == false) {
            continue;
        }

        calypso_json_set_hex(profile, probe->profile_json_key, response.data, response.len);
    }
}

static void calypso_print_info_data_objects(void) {
    bool printed_header = false;

    for (size_t i = 0; i < ARRAYLEN(calypso_get_data_probes); i++) {
        const calypso_get_data_probe_t *probe = &calypso_get_data_probes[i];
        if (probe->tag != 0x0185 && probe->tag != 0x5F52 &&
                probe->tag != 0xDF4C && probe->tag != 0xDF4A && probe->tag != 0xDF2C) {
            continue;
        }

        calypso_apdu_response_t response = {0};
        int res = calypso_get_data_object(probe->tag, &response);
        bool has_data = res == PM3_SUCCESS && calypso_read_sw_has_data(response.sw, response.len);

        if (printed_header == false && has_data) {
            PrintAndLogEx(INFO, "");
            PrintAndLogEx(INFO, "--- " _CYAN_("Get Data") " ------------------------------");
            printed_header = true;
        }

        if (res != PM3_SUCCESS) {
            continue;
        }

        if (response.sw == ISO7816_INS_NOT_SUPPORTED || response.sw == ISO7816_CLA_NOT_SUPPORTED) {
            break;
        }

        if (has_data == false) {
            continue;
        }

        calypso_print_get_data_object(probe, response.data, response.len);
    }
}

static int calypso_read_current_binary(uint8_t *out, size_t out_len, size_t *read_len, uint16_t *sw) {
    calypso_apdu_response_t response = {0};
    sAPDU_t apdu = {0x00, CALYPSO_READ_BINARY, 0x00, 0x00, 0, NULL};
    int res = calypso_exchange_read(apdu, 0, &response);
    *sw = response.sw;

    if (res != PM3_SUCCESS || calypso_read_sw_has_data(response.sw, response.len) == false) {
        *read_len = 0;
        return res;
    }

    *read_len = MIN(response.len, out_len);
    memcpy(out, response.data, *read_len);
    return PM3_SUCCESS;
}

static void calypso_print_hex_entry_wrapped(const char *label, const uint8_t *data, size_t data_len, const char *ansi_color, size_t break_len) {
    if (label == NULL || data == NULL || data_len == 0) {
        return;
    }

    if (break_len == 0) {
        break_len = CALYPSO_HEX_ENTRY_BREAK;
    }
    if (ansi_color == NULL) {
        ansi_color = "";
    }

    const char *suffix = ansi_color[0] == '\0' ? "" : AEND;
    if (data_len <= break_len) {
        PrintAndLogEx(SUCCESS, "%s%s%s%s", label, ansi_color, sprint_hex(data, data_len), suffix);
        return;
    }

    size_t first_len = MIN(data_len, break_len);
    PrintAndLogEx(SUCCESS, "%s%s%s%s", label, ansi_color, sprint_hex(data, first_len), suffix);

    char prefix[128] = {0};
    char visible_label[128] = {0};
    size_t label_len = strlen(label) + 1;
    if (label_len > sizeof(visible_label)) {
        label_len = sizeof(visible_label);
    }
    memcpy_filter_ansi(visible_label, label, label_len, true);
    visible_label[sizeof(visible_label) - 1] = '\0';
    size_t visible_len = strlen(visible_label);
    size_t decoration_len = 0;
    char *last_pipe = strrchr(visible_label, '|');
    if (last_pipe != NULL) {
        decoration_len = (size_t)(last_pipe - visible_label) + 1;
        while (visible_label[decoration_len] == ' ') {
            decoration_len++;
        }
    }
    size_t color_len = strlen(ansi_color);
    if (color_len >= sizeof(prefix)) {
        color_len = sizeof(prefix) - 1;
    }
    visible_len = MIN(visible_len, sizeof(prefix) - color_len - 1);
    decoration_len = MIN(decoration_len, visible_len);
    memcpy(prefix, visible_label, decoration_len);
    memset(prefix + decoration_len, ' ', visible_len - decoration_len);
    size_t pos = visible_len;
    memcpy(prefix + pos, ansi_color, color_len);
    print_hex_noascii_break_ex(data + first_len, data_len - first_len, break_len, prefix, ' ', suffix);
}

static void calypso_print_hex_entry(const char *label, const uint8_t *data, size_t data_len, const char *ansi_color) {
    calypso_print_hex_entry_wrapped(label, data, data_len, ansi_color, CALYPSO_HEX_ENTRY_BREAK);
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
    const char *platform_desc = calypso_json_lookup_name(&calypso_ic_families_resource, platform);
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
    PrintAndLogEx(INFO, "--- " _CYAN_("ICC Manufacturing Info") " ------------------");
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
    isodep_state_t protocol = rf != NULL ? rf->protocol : GetISODEPState();

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("RF Interface") " ----------------------------");
    PrintAndLogEx(SUCCESS, " RF protocol       : " _GREEN_("%s"), calypso_rf_protocol_desc(protocol));

    if (rf == NULL || rf->protocol == ISODEP_INACTIVE) {
        return;
    }

    switch (rf->protocol) {
        case ISODEP_NFCA:
            calypso_print_rf_hex_line(" UID               : ", rf->card.a.uid, rf->card.a.uidlen);
            calypso_print_rf_hex_line(" ATS               : ", rf->card.a.ats, rf->card.a.ats_len);
            break;
        case ISODEP_NFCB:
            calypso_print_rf_hex_line(" PUPI              : ", rf->card.b.uid, rf->card.b.uidlen);
            calypso_print_rf_hex_line(" ATQB              : ", rf->card.b.atqb, sizeof(rf->card.b.atqb));
            break;
        case ISODEP_NFCB_PRIME:
            PrintAndLogEx(SUCCESS, " V&T Ad            : " _GREEN_("%02X"), rf->card.prime.vt_addr);
            calypso_print_rf_hex_line(" DIV               : ", rf->card.prime.div, sizeof(rf->card.prime.div));
            calypso_print_rf_hex_line(" ATR               : ", rf->card.prime.atr, rf->card.prime.atr_len);
            break;
        case ISODEP_INACTIVE:
        case ISODEP_NFCV:
            break;
    }
}

static void calypso_print_select_info_ex(const calypso_select_result_t *selected, bool verbose, bool header) {
    bool default_selection = calypso_selection_is_default(selected);

    if (header) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "--- " _CYAN_("Calypso Info") " ----------------------------");
    }
    if (selected->requested_aid_len > 0) {
        calypso_print_hex_ascii_line(default_selection ? " Default AID       : " : " Selected AID      : ", selected->requested_aid, selected->requested_aid_len);
    }
    if (selected->has_df_lid) {
        uint8_t lid[2] = {
            (uint8_t)(selected->df_lid >> 8),
            (uint8_t)(selected->df_lid & 0xFF)
        };
        PrintAndLogEx(SUCCESS, "%s" _GREEN_("%s"), default_selection ? " Default DF LID    : " : " DF LID            : ", sprint_hex(lid, sizeof(lid)));
    }

    if (selected->origin == CALYPSO_SELECTION_ACTIVATION) {
        uint8_t serial[CALYPSO_SERIAL_LEN] = {0};
        if (calypso_selection_profile_serial(selected, serial)) {
            PrintAndLogEx(SUCCESS, " Serial number     : " _GREEN_("%s"), sprint_hex(serial, sizeof(serial)));
        }
        return;
    }

    if (selected->parsed.has_df_name && default_selection == false) {
        calypso_print_hex_ascii_line(" DF Name           : ", selected->parsed.df_name, selected->parsed.df_name_len);
    }
    calypso_print_aid_info(selected, verbose);

    if (selected->parsed.has_serial) {
        bool hce = calypso_serial_is_hce(selected->parsed.serial);
        uint8_t serial[CALYPSO_SERIAL_LEN] = {0};
        calypso_normalize_profile_serial(selected->parsed.serial, serial);
        PrintAndLogEx(SUCCESS, " Serial number     : " _GREEN_("%s"), sprint_hex(serial, sizeof(serial)));
        if (hce) {
            PrintAndLogEx(SUCCESS, " HCE token expiry  : " _YELLOW_("%s"), sprint_hex(selected->parsed.serial, 2));
        }
        PrintAndLogEx(SUCCESS, " Card type         : " _YELLOW_("%s"), calypso_product_type_desc(selected->parsed.serial));
    }
    if (selected->response.sw == ISO7816_INVALID_DF) {
        PrintAndLogEx(WARNING, " Application status: " _YELLOW_("DF invalidated") " (" _YELLOW_("%04X") ")", selected->response.sw);
    }

    if (selected->parsed.has_startup) {
        calypso_print_startup(selected->parsed.startup);
    }
}

static void calypso_print_select_info(const calypso_select_result_t *selected, bool verbose) {
    calypso_print_select_info_ex(selected, verbose, true);
}

static bool calypso_dump_candidate_add(calypso_dump_candidate_list_t *list, uint16_t lid, uint8_t source) {
    // LID 0000 is a special SELECT target, not a real file candidate.
    if (lid == 0x0000) {
        return true;
    }

    for (size_t i = 0; i < list->count; i++) {
        if (list->items[i].lid == lid) {
            list->items[i].sources |= source;
            return true;
        }
    }

    if (list->count >= ARRAYLEN(list->items)) {
        return false;
    }

    list->items[list->count].lid = lid;
    list->items[list->count].sources = source;
    list->count++;
    return true;
}

static int calypso_dump_candidate_compare(const void *a, const void *b) {
    const calypso_dump_lid_candidate_t *left = a;
    const calypso_dump_lid_candidate_t *right = b;
    if (left->lid < right->lid) {
        return -1;
    }
    if (left->lid > right->lid) {
        return 1;
    }
    return 0;
}

static size_t calypso_dump_walk_effective_path(const calypso_dump_walk_context_t *ctx, uint16_t *path, size_t path_max) {
    if (ctx == NULL || path == NULL || path_max == 0) {
        return 0;
    }

    size_t path_len = MIN(ctx->path_len, path_max);
    if (path_len > 0) {
        memcpy(path, ctx->path, path_len * sizeof(path[0]));
        if (ctx->has_lid) {
            path[path_len - 1] = ctx->lid;
        }
        return path_len;
    }

    if (ctx->from_root == false && ctx->is_mf == false && ctx->has_lid) {
        path[0] = ctx->lid;
        return 1;
    }

    return 0;
}

static size_t calypso_dump_walk_lid_path(const calypso_dump_walk_context_t *ctx, uint16_t lid, uint16_t *path, size_t path_max) {
    if (path == NULL || path_max == 0) {
        return 0;
    }

    size_t path_len = calypso_dump_walk_effective_path(ctx, path, path_max);
    if (path_len > 0 && path[path_len - 1] == lid) {
        return path_len;
    }
    if (path_len >= path_max) {
        return 0;
    }

    path[path_len++] = lid;
    return path_len;
}

static void calypso_dump_profile_list_free(calypso_dump_profile_list_t *list) {
    if (list == NULL) {
        return;
    }

    for (size_t i = 0; i < list->count; i++) {
        free(list->items[i].nodes);
    }
    memset(list, 0, sizeof(*list));
}

static bool calypso_empty_response_lost(size_t read_len, uint16_t sw) {
    return sw == 0 && read_len == 0;
}

static int calypso_dump_select_lid(const calypso_dump_walk_context_t *ctx, uint16_t lid, uint8_t *response, size_t response_max, size_t *response_len, uint16_t *sw) {
    uint16_t path[CALYPSO_DUMP_NODE_PATH_MAX + 1] = {0};
    size_t path_len = calypso_dump_walk_lid_path(ctx, lid, path, ARRAYLEN(path));
    calypso_apdu_response_t select_response = {0};
    int res = calypso_select_file_path_then_id_fallback(path, path_len, lid, &select_response);
    *response_len = MIN(select_response.len, response_max);
    if (response != NULL && *response_len > 0) {
        memcpy(response, select_response.data, *response_len);
    }
    *sw = select_response.sw;
    return res;
}

static bool calypso_dump_result_lost(int res) {
    return res == PM3_ETIMEOUT || res == PM3_ECARDEXCHANGE || res == PM3_ERFTRANS;
}

static bool calypso_dump_exchange_lost(int res, size_t read_len, uint16_t sw) {
    return calypso_dump_result_lost(res) || (res == PM3_SUCCESS && calypso_empty_response_lost(read_len, sw));
}

static int calypso_dump_repoll_context(const calypso_select_result_t *selected, const calypso_dump_walk_context_t *ctx, bool verbose) {
    calypso_rf_info_t rf = selected->rf;
    PrintAndLogEx(WARNING, "Card connection lost; re-polling and resuming");
    DropField();
    int res = calypso_connect_contactless(verbose, &rf);
    if (res != PM3_SUCCESS) {
        return res;
    }
    return calypso_dump_reselect_base(selected, ctx, verbose);
}

static int calypso_dump_repoll_file(const calypso_select_result_t *selected, const calypso_dump_walk_context_t *ctx, uint16_t lid, bool verbose) {
    int res = calypso_dump_repoll_context(selected, ctx, verbose);
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint8_t response[APDU_RES_LEN] = {0};
    size_t response_len = 0;
    uint16_t sw = 0;
    res = calypso_dump_select_lid(ctx, lid, response, sizeof(response), &response_len, &sw);
    if (calypso_dump_exchange_lost(res, response_len, sw)) {
        return PM3_ETIMEOUT;
    }
    if (res != PM3_SUCCESS) {
        return res;
    }
    return calypso_select_sw_has_file(sw) ? PM3_SUCCESS : PM3_EOPABORTED;
}

typedef enum {
    CALYPSO_DUMP_RESUME_CONTEXT,
    CALYPSO_DUMP_RESUME_FILE,
} calypso_dump_resume_scope_t;

typedef struct {
    const calypso_select_result_t *selected;
    const calypso_dump_walk_context_t *ctx;
    bool verbose;
    calypso_dump_resume_scope_t scope;
    uint16_t lid;
} calypso_dump_resume_t;

typedef int (*calypso_dump_command_fn_t)(void *arg, size_t *read_len, uint16_t *sw);

static int calypso_dump_resume_restore(const calypso_dump_resume_t *resume) {
    return resume->scope == CALYPSO_DUMP_RESUME_FILE ?
           calypso_dump_repoll_file(resume->selected, resume->ctx, resume->lid, resume->verbose) :
           calypso_dump_repoll_context(resume->selected, resume->ctx, resume->verbose);
}

static int calypso_dump_command_with_resume(const calypso_dump_resume_t *resume, calypso_dump_command_fn_t command, void *arg, size_t *read_len, uint16_t *sw) {
    int res = PM3_SUCCESS;
    for (uint8_t attempt = 0; attempt < 4; attempt++) {
        *read_len = 0;
        *sw = 0;
        res = command(arg, read_len, sw);
        if (calypso_dump_exchange_lost(res, *read_len, *sw) == false || attempt == 3) {
            break;
        }
        res = calypso_dump_resume_restore(resume);
        if (res != PM3_SUCCESS && calypso_dump_result_lost(res) == false) {
            return res;
        }
    }
    return calypso_dump_exchange_lost(res, *read_len, *sw) ? PM3_ETIMEOUT : res;
}

typedef struct {
    uint8_t *out;
    size_t out_len;
} calypso_dump_buffer_args_t;

typedef struct {
    uint16_t tag;
    calypso_dump_buffer_args_t buffer;
} calypso_dump_get_data_args_t;

static int calypso_dump_send_get_data(void *arg, size_t *read_len, uint16_t *sw) {
    calypso_dump_get_data_args_t *cmd = arg;
    calypso_apdu_response_t response = {0};
    int res = calypso_get_data_object(cmd->tag, &response);
    *read_len = MIN(response.len, cmd->buffer.out_len);
    if (cmd->buffer.out != NULL && *read_len > 0) {
        memcpy(cmd->buffer.out, response.data, *read_len);
    }
    *sw = response.sw;
    return res;
}

typedef struct {
    bool verbose;
    uint8_t *out;
    size_t out_len;
} calypso_dump_current_fcp_args_t;

static int calypso_dump_send_current_fcp(void *arg, size_t *read_len, uint16_t *sw) {
    calypso_dump_current_fcp_args_t *cmd = arg;
    calypso_apdu_response_t response = {0};
    int res = calypso_select_current_file_fcp(cmd->verbose, &response, NULL);
    *read_len = MIN(response.len, cmd->out_len);
    if (cmd->out != NULL && *read_len > 0) {
        memcpy(cmd->out, response.data, *read_len);
    }
    *sw = response.sw;
    return res;
}

typedef struct {
    const calypso_dump_walk_context_t *ctx;
    uint16_t lid;
    uint8_t *out;
    size_t out_len;
} calypso_dump_select_lid_args_t;

static int calypso_dump_send_select_lid(void *arg, size_t *read_len, uint16_t *sw) {
    calypso_dump_select_lid_args_t *cmd = arg;
    return calypso_dump_select_lid(cmd->ctx, cmd->lid, cmd->out, cmd->out_len, read_len, sw);
}

typedef struct {
    uint8_t record;
    uint16_t le;
    uint8_t *out;
    size_t out_len;
} calypso_dump_read_record_args_t;

static int calypso_dump_send_read_binary(void *arg, size_t *read_len, uint16_t *sw) {
    calypso_dump_buffer_args_t *cmd = arg;
    return calypso_read_current_binary(cmd->out, cmd->out_len, read_len, sw);
}

static int calypso_dump_send_read_record(void *arg, size_t *read_len, uint16_t *sw) {
    calypso_dump_read_record_args_t *cmd = arg;
    return calypso_read_current_record(cmd->record, cmd->le, cmd->out, cmd->out_len, read_len, sw);
}

static void calypso_dump_add_c0_candidates(calypso_dump_candidate_list_t *candidates, const uint8_t *data, size_t data_len) {
    if (candidates == NULL || data == NULL || data_len == 0) {
        return;
    }

    size_t pos = 0;
    size_t end = data_len;
    if (data[0] == 0xC0) {
        pos = 1;
        size_t len = 0;
        if (calypso_tlv_read_len(data, data_len, &pos, &len) == false || pos > data_len || len > data_len - pos) {
            return;
        }
        end = pos + len;
    }

    while (pos < end) {
        uint8_t tag = data[pos++];
        size_t len = 0;
        if (calypso_tlv_read_len(data, end, &pos, &len) == false) {
            return;
        }
        if (pos > end || len > end - pos) {
            return;
        }
        if (tag != 0xC1 || len < 2) {
            pos += len;
            continue;
        }

        uint16_t lid = ((uint16_t)data[pos] << 8) | data[pos + 1];
        if (calypso_dump_candidate_add(candidates, lid, CALYPSO_DUMP_SOURCE_EFLIST) == false) {
            return;
        }
        pos += len;
    }
}

static bool calypso_dump_infer_parent_from_c0(const calypso_dump_candidate_list_t *candidates, uint16_t *parent) {
    bool have_parent = false;
    uint16_t inferred_parent = 0;

    for (size_t i = 0; i < candidates->count; i++) {
        if ((candidates->items[i].sources & CALYPSO_DUMP_SOURCE_EFLIST) == 0) {
            continue;
        }

        uint16_t candidate_parent = candidates->items[i].lid & 0xFF00;
        if (candidate_parent == 0x0000) {
            return false;
        }
        if (have_parent == false) {
            inferred_parent = candidate_parent;
            have_parent = true;
            continue;
        }
        if (candidate_parent != inferred_parent) {
            return false;
        }
    }

    if (have_parent == false) {
        return false;
    }
    *parent = inferred_parent;
    return true;
}

static bool calypso_dump_add_known_candidates(calypso_dump_candidate_list_t *candidates, const calypso_dump_walk_context_t *ctx, bool have_inferred_parent, uint16_t inferred_parent) {
    uint16_t path[CALYPSO_DUMP_NODE_PATH_MAX] = {0};
    size_t path_len = ctx->path_len;

    if (path_len > 0) {
        memcpy(path, ctx->path, path_len * sizeof(path[0]));
        if (ctx->has_lid) {
            path[path_len - 1] = ctx->lid;
        }
    } else if (ctx->depth == 0 && ctx->from_root == false && ctx->is_mf == false) {
        if (ctx->has_lid) {
            path[0] = ctx->lid;
            path_len = 1;
        } else if (have_inferred_parent) {
            path[0] = inferred_parent;
            path_len = 1;
        } else {
            path_len = 0;
        }
    } else if (ctx->depth == 0) {
        path_len = 0;
    } else if (ctx->from_root == false && ctx->is_mf == false) {
        if (ctx->has_lid) {
            path[0] = ctx->lid;
            path_len = 1;
        } else if (have_inferred_parent) {
            path[0] = inferred_parent;
            path_len = 1;
        } else {
            return true;
        }
    }

    json_t *root = calypso_json_resource_root(&calypso_nodes_resource);
    if (root == NULL) {
        return true;
    }

    size_t index;
    json_t *entry;
    json_array_foreach(root, index, entry) {
        calypso_file_ref_t file = {0};
        if (calypso_json_file_ref_parse(entry, &file) == false || path_len >= file.path_len) {
            continue;
        }

        bool prefix_match = true;
        for (size_t j = 0; j < path_len; j++) {
            if (path[j] != file.path[j]) {
                prefix_match = false;
                break;
            }
        }
        if (prefix_match == false) {
            continue;
        }

        if (calypso_dump_candidate_add(candidates, file.path[path_len], CALYPSO_DUMP_SOURCE_KNOWN) == false) {
            return false;
        }
    }
    return true;
}

static bool calypso_dump_walk_is_current_lid(const calypso_dump_walk_context_t *ctx, uint16_t lid) {
    if (ctx == NULL) {
        return false;
    }
    if (ctx->has_lid && ctx->lid == lid) {
        return true;
    }
    if (ctx->path_len > 0 && ctx->path[ctx->path_len - 1] == lid) {
        return true;
    }
    return ctx->from_root && lid == 0x3F00;
}

static void calypso_dump_brute_status_clear(bool *visible) {
    if (visible != NULL && *visible) {
        PrintAndLogEx(INPLACE, "%80s\r", "");
        *visible = false;
    }
}

static void calypso_dump_brute_status_update(const calypso_dump_lid_candidate_t *candidate, bool *visible, uint16_t *last_lid) {
    if (candidate == NULL || candidate->sources != CALYPSO_DUMP_SOURCE_BRUTE) {
        calypso_dump_brute_status_clear(visible);
        return;
    }

    uint16_t range_start = candidate->lid & 0xFF00;
    uint16_t range_end = range_start | 0x00FF;
    if ((candidate->lid & 0x00FF) == 0x00) {
        range_start = 0x0000;
        range_end = 0xFF00;
    }
    if (visible != NULL && last_lid != NULL && *visible && *last_lid == candidate->lid) {
        return;
    }

    PrintAndLogEx(INPLACE, "Bruteforcing range " _YELLOW_("%04X-%04X") " (" _YELLOW_("%04X") ")" _CLR_, range_start, range_end, candidate->lid);
    if (visible != NULL) {
        *visible = true;
    }
    if (last_lid != NULL) {
        *last_lid = candidate->lid;
    }
}

static bool calypso_dump_walk_lid_base(const calypso_dump_walk_context_t *ctx, bool have_inferred_parent, uint16_t inferred_parent, uint16_t *base) {
    if (ctx->has_lid) {
        *base = ctx->lid & 0xFF00;
        return true;
    }
    if (ctx->path_len > 0) {
        *base = ctx->path[ctx->path_len - 1] & 0xFF00;
        return true;
    }
    if (have_inferred_parent) {
        *base = inferred_parent & 0xFF00;
        return *base != 0x0000;
    }
    return false;
}

static bool calypso_dump_add_brute_ef_range(calypso_dump_candidate_list_t *candidates, uint16_t base) {
    for (uint32_t low = 1; low <= 0xFF; low++) {
        uint16_t lid = base | (uint16_t)low;
        if (calypso_dump_candidate_add(candidates, lid, CALYPSO_DUMP_SOURCE_BRUTE) == false) {
            return false;
        }
    }
    return true;
}

static bool calypso_dump_add_root_brute_candidates(calypso_dump_candidate_list_t *candidates) {
    if (calypso_dump_add_brute_ef_range(candidates, 0x0000) == false ||
            calypso_dump_add_brute_ef_range(candidates, 0x2F00) == false ||
            calypso_dump_add_brute_ef_range(candidates, 0x3F00) == false) {
        return false;
    }

    for (uint32_t high = 0; high <= 0xFF; high++) {
        uint16_t base = (uint16_t)(high << 8);
        if (calypso_dump_candidate_add(candidates, base, CALYPSO_DUMP_SOURCE_BRUTE) == false) {
            return false;
        }
    }
    return true;
}

static bool calypso_dump_add_brute_file_candidates(calypso_dump_candidate_list_t *candidates, const calypso_dump_walk_context_t *ctx, bool have_inferred_parent, uint16_t inferred_parent) {
    if (ctx != NULL && ctx->depth == 0 && calypso_dump_add_root_brute_candidates(candidates) == false) {
        return false;
    }

    uint16_t base = 0;
    if (calypso_dump_walk_lid_base(ctx, have_inferred_parent, inferred_parent, &base) == false) {
        return true;
    }
    return calypso_dump_add_brute_ef_range(candidates, base);
}

static int calypso_dump_reselect_base(const calypso_select_result_t *selected, const calypso_dump_walk_context_t *ctx, bool verbose) {
    int res = PM3_SUCCESS;
    if (ctx->from_root == false) {
        res = calypso_restore_selection(selected, verbose, NULL);
        if (res != PM3_SUCCESS) {
            return res;
        }
    }

    if (ctx->from_root) {
        calypso_apdu_response_t response = {0};
        const uint16_t mf_path[] = {0x3F00};
        res = calypso_select_file_path_then_id_fallback(mf_path, ARRAYLEN(mf_path), 0x3F00, &response);
        if (res == PM3_SUCCESS && calypso_empty_response_lost(response.len, response.sw)) {
            return PM3_ETIMEOUT;
        }
        if (res != PM3_SUCCESS || calypso_select_sw_has_file(response.sw) == false) {
            if (verbose) {
                PrintAndLogEx(INFO, " SELECT 3F00 failed (%04X - %s)", response.sw, GetAPDUCodeDescription(response.sw >> 8, response.sw & 0xFF));
            }
            return res == PM3_SUCCESS ? PM3_EOPABORTED : res;
        }
    }

    for (size_t i = 0; i < ctx->path_len; i++) {
        calypso_apdu_response_t response = {0};
        res = calypso_select_file_path_then_id_fallback(ctx->path, i + 1, ctx->path[i], &response);
        if (res == PM3_SUCCESS && calypso_empty_response_lost(response.len, response.sw)) {
            return PM3_ETIMEOUT;
        }
        if (res != PM3_SUCCESS || calypso_select_sw_has_file(response.sw) == false) {
            if (verbose) {
                PrintAndLogEx(INFO, " SELECT %04X failed while restoring context (%04X - %s)", ctx->path[i], response.sw, GetAPDUCodeDescription(response.sw >> 8, response.sw & 0xFF));
            }
            return res == PM3_SUCCESS ? PM3_EOPABORTED : res;
        }
    }

    return PM3_SUCCESS;
}

static bool calypso_tlv_read_len(const uint8_t *data, size_t data_len, size_t *pos, size_t *len) {
    if (data == NULL || pos == NULL || len == NULL || *pos >= data_len) {
        return false;
    }

    uint8_t first = data[(*pos)++];
    if ((first & 0x80) == 0) {
        *len = first;
        return true;
    }

    size_t len_len = first & 0x7F;
    if (len_len == 0 || len_len > sizeof(size_t) || *pos > data_len || len_len > data_len - *pos) {
        return false;
    }

    size_t parsed = 0;
    for (size_t i = 0; i < len_len; i++) {
        parsed = (parsed << 8) | data[(*pos)++];
    }

    *len = parsed;
    return true;
}

static bool calypso_fcp_is_type(const uint8_t *fcp, size_t fcp_len, calypso_file_type_t file_type) {
    calypso_fcp_t parsed = {0};
    return calypso_parse_fcp(fcp, fcp_len, &parsed) && parsed.file_type == file_type;
}

static bool calypso_fcp_matches_lid(const calypso_fcp_t *fcp, uint16_t target_lid) {
    if (fcp == NULL || fcp->lid_count == 0) {
        return true;
    }
    for (size_t i = 0; i < fcp->lid_count; i++) {
        if (fcp->lids[i] == target_lid) {
            return true;
        }
    }
    return false;
}

static bool calypso_preferred_fcp(const uint8_t *select_fcp, size_t select_fcp_len,
                                  const uint8_t *get_data_fcp, size_t get_data_fcp_len,
                                  const uint8_t **fcp, size_t *fcp_len, calypso_fcp_t *parsed) {
    if (select_fcp != NULL && select_fcp_len > 0 && calypso_parse_fcp(select_fcp, select_fcp_len, parsed)) {
        *fcp = select_fcp;
        *fcp_len = select_fcp_len;
        return true;
    }

    if (get_data_fcp != NULL && get_data_fcp_len > 0 && calypso_parse_fcp(get_data_fcp, get_data_fcp_len, parsed)) {
        *fcp = get_data_fcp;
        *fcp_len = get_data_fcp_len;
        return true;
    }

    *fcp = NULL;
    *fcp_len = 0;
    return false;
}

static bool calypso_lid_is_valid(uint16_t lid) {
    return lid != 0x0000 && lid != 0xFFFF && lid != 0x3F3F;
}

static bool calypso_fcp_lid_with_hint(const uint8_t *fcp, size_t fcp_len, bool have_hint, uint16_t hint, uint16_t *lid) {
    calypso_fcp_t parsed = {0};
    return calypso_parse_fcp(fcp, fcp_len, &parsed) &&
           calypso_fcp_find_lid(&parsed, have_hint, hint, lid);
}

static bool calypso_fcp_lid(const uint8_t *fcp, size_t fcp_len, uint16_t *lid) {
    return calypso_fcp_lid_with_hint(fcp, fcp_len, false, 0, lid);
}

static void calypso_dump_prefix(size_t parent_depth, const char *suffix, char *out, size_t out_len) {
    if (out_len == 0) {
        return;
    }

    size_t pos = 0;
    int written = snprintf(out, out_len, "  ");
    if (written < 0 || (size_t)written >= out_len) {
        return;
    }
    pos = (size_t)written;

    for (size_t i = 0; i < parent_depth && pos < out_len; i++) {
        written = snprintf(out + pos, out_len - pos, "|     ");
        if (written < 0 || (size_t)written >= out_len - pos) {
            return;
        }
        pos += (size_t)written;
    }

    if (pos < out_len) {
        snprintf(out + pos, out_len - pos, "%s", suffix);
    }
}

static void calypso_dump_detail_prefix(size_t parent_depth, char *out, size_t out_len) {
    calypso_dump_prefix(parent_depth, "|   ", out, out_len);
}

static bool calypso_data_is_fci(const uint8_t *data, size_t data_len) {
    calypso_fci_t fci = {0};
    return data != NULL && data_len > 0 && calypso_parse_fci(data, data_len, &fci);
}

static bool calypso_data_is_fcp(const uint8_t *data, size_t data_len) {
    calypso_fcp_t fcp = {0};
    return data != NULL && data_len > 0 && calypso_parse_fcp(data, data_len, &fcp);
}

static void calypso_dump_print_inline_data(const char *prefix, const char *label, const uint8_t *data, size_t data_len) {
    if (data == NULL || data_len == 0) {
        return;
    }

    char full_label[160] = {0};
    snprintf(full_label, sizeof(full_label), "%s%s", prefix != NULL ? prefix : "", label);
    calypso_print_hex_entry_wrapped(full_label, data, data_len, ANSI_YELLOW, CALYPSO_DUMP_HEX_ENTRY_BREAK);
}

static void calypso_dump_print_inline_response(const char *prefix, const char *label, const uint8_t *data, size_t data_len, uint16_t sw, bool verbose) {
    if (data_len > 0) {
        calypso_dump_print_inline_data(prefix, label, data, data_len);
    } else if (verbose && sw != 0 && calypso_read_sw_is_unavailable(sw) == false) {
        PrintAndLogEx(INFO, "%s%sunavailable (%04X - %s)", prefix != NULL ? prefix : "", label, sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
    }
}

static void calypso_dump_print_inline_file_data(const char *prefix, bool is_df, const calypso_dump_node_t *node, bool verbose) {
    if (node == NULL) {
        return;
    }

    if (is_df) {
        calypso_dump_print_inline_response(prefix, "SEL FCI: ", node->select_fci.data, node->select_fci.len, node->select_fci.sw, verbose);
        calypso_dump_print_inline_response(prefix, "GET FCI: ", node->get_data_fci.data, node->get_data_fci.len, node->get_data_fci.sw, verbose);
    }
    calypso_dump_print_inline_response(prefix, "SEL FCP: ", node->select_fcp.data, node->select_fcp.len, is_df ? 0 : node->select_fcp.sw, verbose);
    calypso_dump_print_inline_response(prefix, "GET FCP: ", node->get_data_fcp.data, node->get_data_fcp.len, node->get_data_fcp.sw, verbose);
    if (is_df) {
        calypso_dump_print_inline_response(prefix, "CUR FCP: ", node->select_current_fcp.data, node->select_current_fcp.len, node->select_current_fcp.sw, verbose);
    }
}

static const char *calypso_ef_type_name(uint8_t ef_type, char *fallback, size_t fallback_len) {
    switch (ef_type) {
        case 0x01:
            return "binary";
        case 0x02:
            return "linear";
        case 0x04:
            return "cyclic";
        case 0x08:
        case 0x09:
            return "counter";
        default:
            snprintf(fallback, fallback_len, "type %02X", ef_type);
            return fallback;
    }
}

static void calypso_dump_print_root(const calypso_dump_walk_context_t *root, const calypso_dump_node_t *node) {
    char root_lid[8] = {0};
    if (root->from_root) {
        snprintf(root_lid, sizeof(root_lid), "3F00");
    } else if (root->has_lid) {
        snprintf(root_lid, sizeof(root_lid), "%04X", root->lid);
    } else {
        snprintf(root_lid, sizeof(root_lid), "AID");
    }

    const uint8_t *aid = NULL;
    size_t aid_len = calypso_dump_node_aid(node, &aid);

    const char *root_type = root->is_mf ? "MF" : "DF";
    if (aid != NULL && aid_len > 0) {
        PrintAndLogEx(INFO, "%s " _GREEN_("%s") " (AID " _YELLOW_("%s") "%s)", root_type, root_lid, sprint_hex_inrow(aid, aid_len),
                      node != NULL && calypso_selection_is_default(&node->selected) ? ", default" : "");
    } else {
        PrintAndLogEx(INFO, "%s " _GREEN_("%s"), root_type, root_lid);
    }
}

static void calypso_dump_add_fcp_sfi(json_t *node, const uint8_t *fcp, size_t fcp_len) {
    calypso_fcp_t parsed = {0};
    if (node == NULL || fcp == NULL || fcp_len == 0 || calypso_parse_fcp(fcp, fcp_len, &parsed) == false) {
        return;
    }

    json_object_set_new(node, "sfi", json_integer(parsed.sfi));
}

static void calypso_json_object_add_record(json_t *records, uint8_t record, const uint8_t *data, size_t data_len) {
    char key[3] = {0};
    snprintf(key, sizeof(key), "%02X", record);
    json_object_set_new(records, key, json_string(sprint_hex_inrow(data, data_len)));
}

static void calypso_json_set_dump_sources(json_t *node, uint8_t sources) {
    json_t *source_array = json_array();
    if (sources & CALYPSO_DUMP_SOURCE_EFLIST) {
        json_array_append_new(source_array, json_string("eflist"));
    }
    if (sources & CALYPSO_DUMP_SOURCE_BRUTE) {
        json_array_append_new(source_array, json_string("brute"));
    }
    if (sources & CALYPSO_DUMP_SOURCE_KNOWN) {
        json_array_append_new(source_array, json_string("known"));
    }
    if (sources & CALYPSO_DUMP_SOURCE_SELECTED) {
        json_array_append_new(source_array, json_string("selected"));
    }
    json_object_set_new(node, "sources", source_array);
}

static bool calypso_dump_parent_lid(const calypso_dump_walk_context_t *ctx, uint16_t *parent_lid) {
    if (ctx == NULL || parent_lid == NULL) {
        return false;
    }

    if (ctx->depth == 0 && (ctx->from_root || ctx->is_mf)) {
        *parent_lid = 0x3F00;
        return true;
    }
    if (ctx->has_lid) {
        *parent_lid = ctx->lid;
        return true;
    }
    if (ctx->path_len > 0) {
        *parent_lid = ctx->path[ctx->path_len - 1];
        return true;
    }
    return false;
}

static void calypso_dump_set_parent(json_t *node, bool have_parent, uint16_t parent_lid) {
    if (node == NULL) {
        return;
    }

    if (have_parent) {
        calypso_json_set_lid(node, "parent", parent_lid);
    } else {
        json_object_set_new(node, "parent", json_null());
    }
}

static void calypso_dump_add_response_fields(json_t *json_node, const calypso_dump_node_t *dump_node, bool is_df) {
    if (json_node == NULL || dump_node == NULL) {
        return;
    }

    if (is_df) {
        if (dump_node->select_fci.len > 0) {
            calypso_json_set_hex(json_node, "selectFci", dump_node->select_fci.data, dump_node->select_fci.len);
        }
        if (dump_node->get_data_fci.len > 0) {
            calypso_json_set_hex(json_node, "getFci", dump_node->get_data_fci.data, dump_node->get_data_fci.len);
        }
    }
    if (dump_node->get_data_fcp.len > 0) {
        calypso_json_set_hex(json_node, "getFcp", dump_node->get_data_fcp.data, dump_node->get_data_fcp.len);
    }
    if (dump_node->select_fcp.len > 0) {
        calypso_json_set_hex(json_node, "selectFcp", dump_node->select_fcp.data, dump_node->select_fcp.len);
    }
    if (dump_node->select_current_fcp.len > 0) {
        calypso_json_set_hex(json_node, "selectCurrentFcp", dump_node->select_current_fcp.data, dump_node->select_current_fcp.len);
    }
}

static json_t *calypso_dump_add_file_json(calypso_dump_json_context_t *dump, const calypso_dump_walk_context_t *ctx, const calypso_dump_node_t *dump_node, bool is_df, bool is_root) {
    if (dump == NULL || dump->nodes == NULL || ctx == NULL) {
        return NULL;
    }

    const uint8_t *aid = NULL;
    size_t aid_len = is_df ? calypso_dump_node_aid(dump_node, &aid) : 0;

    const uint8_t *fcp = NULL;
    size_t fcp_len = 0;
    bool have_fcp = calypso_dump_node_first_fcp(dump_node, &fcp, &fcp_len);

    uint16_t lid = 0;
    bool have_lid = calypso_dump_node_known_lid(dump_node, &lid);
    if (is_root && (ctx->from_root || ctx->is_mf)) {
        have_lid = true;
        lid = 0x3F00;
    }

    json_t *node = json_object();
    json_object_set_new(node, "kind", json_string(is_root && ctx->is_mf ? "mf" : (is_df ? "df" : "ef")));
    if (is_df) {
        json_object_set_new(node, "default", json_boolean(dump_node != NULL && calypso_selection_is_default(&dump_node->selected)));
    }
    if (aid_len > 0) {
        calypso_json_set_hex(node, "aid", aid, aid_len);
    }
    if (have_lid) {
        calypso_json_set_lid(node, "lid", lid);
    }
    if (is_root) {
        calypso_dump_set_parent(node, false, 0);
    } else {
        uint16_t parent_lid = 0;
        calypso_dump_set_parent(node, calypso_dump_parent_lid(ctx, &parent_lid), parent_lid);
    }
    if (have_fcp && is_df == false) {
        calypso_dump_add_fcp_sfi(node, fcp, fcp_len);
    }
    if (is_root == false) {
        calypso_json_set_dump_sources(node, dump_node != NULL ? dump_node->sources : 0);
    }
    calypso_dump_add_response_fields(node, dump_node, is_df);

    json_array_append_new(dump->nodes, node);
    return node;
}

static int calypso_dump_read_ef(const calypso_select_result_t *selected, const calypso_dump_walk_context_t *ctx, uint16_t lid, json_t *node, bool verbose) {
    char detail_prefix[96] = {0};
    calypso_dump_detail_prefix(ctx->depth, detail_prefix, sizeof(detail_prefix));
    calypso_dump_resume_t resume = {selected, ctx, verbose, CALYPSO_DUMP_RESUME_FILE, lid};

    uint8_t binary[APDU_RES_LEN] = {0};
    size_t binary_len = 0;
    uint16_t binary_sw = 0;
    calypso_dump_buffer_args_t binary_cmd = {binary, sizeof(binary)};
    int res = calypso_dump_command_with_resume(&resume, calypso_dump_send_read_binary, &binary_cmd, &binary_len, &binary_sw);
    if (res != PM3_SUCCESS) {
        return res;
    }
    if (calypso_read_sw_has_data(binary_sw, binary_len)) {
        calypso_json_set_hex(node, "data", binary, binary_len);
        char label[160] = {0};
        snprintf(label, sizeof(label), "%sbinary: ", detail_prefix);
        calypso_print_hex_entry_wrapped(label, binary, binary_len, ANSI_GREEN, CALYPSO_DUMP_HEX_ENTRY_BREAK);
    } else if (verbose && calypso_read_sw_is_unavailable(binary_sw) == false) {
        PrintAndLogEx(INFO, "%sbinary: %04X - %s", detail_prefix, binary_sw, GetAPDUCodeDescription(binary_sw >> 8, binary_sw & 0xFF));
    }

    json_t *records = json_object();
    bool found = false;
    for (uint16_t record = 1; record <= 0xFF; record++) {
        uint8_t data[APDU_RES_LEN] = {0};
        size_t data_len = 0;
        uint16_t sw = 0;
        calypso_dump_read_record_args_t record_cmd = {(uint8_t)record, 0, data, sizeof(data)};
        res = calypso_dump_command_with_resume(&resume, calypso_dump_send_read_record, &record_cmd, &data_len, &sw);
        if (res != PM3_SUCCESS) {
            json_decref(records);
            return res;
        }
        if (calypso_read_sw_has_data(sw, data_len) == false && calypso_read_sw_is_unavailable(sw) == false) {
            data_len = 0;
            sw = 0;
            record_cmd.le = CALYPSO_LEGACY_RECORD_LEN;
            res = calypso_dump_command_with_resume(&resume, calypso_dump_send_read_record, &record_cmd, &data_len, &sw);
            if (res != PM3_SUCCESS) {
                json_decref(records);
                return res;
            }
        }

        if (calypso_read_sw_has_data(sw, data_len)) {
            if (data_len > 0) {
                char label[160] = {0};
                snprintf(label, sizeof(label), "%srec " _GREEN_("%03u") ": ", detail_prefix, record);
                calypso_print_hex_entry_wrapped(label, data, data_len, ANSI_GREEN, CALYPSO_DUMP_HEX_ENTRY_BREAK);
                calypso_json_object_add_record(records, (uint8_t)record, data, data_len);
                found = true;
            }
            continue;
        }

        if (calypso_read_sw_is_unavailable(sw)) {
            if (verbose && found == false && sw != 0) {
                PrintAndLogEx(INFO, "%srecords       : unavailable (%04X - %s)", detail_prefix, sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
            }
            break;
        }

        if (verbose) {
            PrintAndLogEx(INFO, "%srec %03u: stopped (%04X - %s)", detail_prefix, record, sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
        }
        break;
    }

    if (json_object_size(records) > 0) {
        json_object_set_new(node, "records", records);
    } else {
        json_decref(records);
    }
    return PM3_SUCCESS;
}

static void calypso_dump_print_node(const calypso_dump_walk_context_t *ctx, const calypso_dump_node_t *node, bool is_df, bool verbose) {
    char prefix[96] = {0};
    calypso_dump_prefix(ctx->depth, "|-- ", prefix, sizeof(prefix));

    uint16_t lid = 0;
    calypso_dump_node_known_lid(node, &lid);

    char aid_details[CALYPSO_MAX_AID_LEN * 3 + 32] = {0};
    if (is_df) {
        const uint8_t *aid = NULL;
        size_t aid_len = calypso_dump_node_aid(node, &aid);
        if (aid != NULL && aid_len > 0) {
            snprintf(aid_details, sizeof(aid_details), " (AID " _YELLOW_("%s") "%s)", sprint_hex_inrow(aid, aid_len),
                     node != NULL && calypso_selection_is_default(&node->selected) ? ", default" : "");
        }
    }

    char fcp_details[96] = {0};
    const uint8_t *fcp = NULL;
    size_t fcp_len = 0;
    bool have_fcp = calypso_dump_node_first_fcp(node, &fcp, &fcp_len);
    if (have_fcp) {
        calypso_fcp_t parsed = {0};
        if (calypso_parse_fcp(fcp, fcp_len, &parsed)) {
            if (is_df == false && parsed.file_type == CALYPSO_FILE_EF) {
                char type_fallback[16] = {0};
                const char *type = calypso_ef_type_name(parsed.ef_type, type_fallback, sizeof(type_fallback));
                int record_pad = (int)(strlen(type) < 8 ? 8 - strlen(type) : 1);
                snprintf(fcp_details, sizeof(fcp_details), " (SFI " _YELLOW_("%02X") ", %s,%*srecords %3u, size %3u)",
                         parsed.sfi,
                         type,
                         record_pad,
                         "",
                         parsed.num_records,
                         parsed.record_size);
            }
        }
    }

    const char *source = "";
    uint8_t sources = node != NULL ? node->sources : 0;
    if (sources & CALYPSO_DUMP_SOURCE_SELECTED) {
        source = " (selected)";
    } else if (sources & CALYPSO_DUMP_SOURCE_EFLIST) {
        source = " (eflist)";
    } else if (sources & CALYPSO_DUMP_SOURCE_KNOWN) {
        source = " (known)";
    } else if (sources & CALYPSO_DUMP_SOURCE_BRUTE) {
        source = " (brute)";
    }

    PrintAndLogEx(INFO, "%s%s " _GREEN_("%04X") "%s%s%s",
                  prefix,
                  is_df ? "DF" : "EF",
                  lid,
                  aid_details,
                  fcp_details,
                  source);
}

static int calypso_dump_process_context(const calypso_select_result_t *selected, const calypso_dump_walk_context_t *base_ctx, uint16_t max_depth, calypso_dump_preset_t preset, bool verbose, calypso_dump_json_context_t *dump) {
    calypso_dump_walk_context_t ctx = *base_ctx;
    calypso_dump_resume_t context_resume = {selected, &ctx, verbose, CALYPSO_DUMP_RESUME_CONTEXT, 0};
    bool restore_base_needed = false;
    bool brute_status_visible = false;
    uint16_t brute_status_last_lid = 0;
    int res = calypso_dump_reselect_base(selected, &ctx, verbose);
    if (calypso_dump_result_lost(res)) {
        res = calypso_dump_resume_restore(&context_resume);
    }
    if (res != PM3_SUCCESS) {
        return res;
    }
    bool have_lid_hint = false;
    uint16_t lid_hint = 0;
    if (ctx.path_len > 0) {
        have_lid_hint = true;
        lid_hint = ctx.path[ctx.path_len - 1];
    } else if (ctx.from_root) {
        have_lid_hint = true;
        lid_hint = 0x3F00;
    } else if (ctx.has_lid) {
        have_lid_hint = true;
        lid_hint = ctx.lid;
    }
    ctx.has_lid = false;
    ctx.lid = 0;

    uint8_t baseline_fcp[APDU_RES_LEN] = {0};
    size_t baseline_fcp_len = 0;
    uint16_t baseline_fcp_sw = 0;
    calypso_dump_get_data_args_t get_baseline_fcp = {0x0062, {baseline_fcp, sizeof(baseline_fcp)}};
    res = calypso_dump_command_with_resume(&context_resume, calypso_dump_send_get_data, &get_baseline_fcp, &baseline_fcp_len, &baseline_fcp_sw);
    if (res != PM3_SUCCESS) {
        return res;
    }
    bool have_baseline_get_fcp = calypso_read_sw_has_data(baseline_fcp_sw, baseline_fcp_len);

    uint8_t baseline_cur_fcp[APDU_RES_LEN] = {0};
    size_t baseline_cur_fcp_len = 0;
    uint16_t baseline_cur_fcp_sw = 0;
    calypso_dump_current_fcp_args_t get_baseline_cur_fcp = {verbose, baseline_cur_fcp, sizeof(baseline_cur_fcp)};
    res = calypso_dump_command_with_resume(&context_resume, calypso_dump_send_current_fcp, &get_baseline_cur_fcp, &baseline_cur_fcp_len, &baseline_cur_fcp_sw);
    if (res != PM3_SUCCESS) {
        return res;
    }
    bool have_baseline_cur_fcp = baseline_cur_fcp_len > 0;

    const uint8_t *baseline_node_fcp = have_baseline_cur_fcp ? baseline_cur_fcp : baseline_fcp;
    size_t baseline_node_fcp_len = have_baseline_cur_fcp ? baseline_cur_fcp_len : baseline_fcp_len;
    bool have_baseline_fcp = have_baseline_get_fcp || have_baseline_cur_fcp;

    uint16_t baseline_lid = 0;
    if (have_baseline_fcp && calypso_fcp_lid_with_hint(baseline_node_fcp, baseline_node_fcp_len, have_lid_hint, lid_hint, &baseline_lid)) {
        ctx.has_lid = true;
        ctx.lid = baseline_lid;
    }

    if (ctx.depth == 0 || ctx.is_mf) {
        calypso_dump_node_t root_raw = {0};
        bool selected_is_root = ctx.from_root == false || ctx.is_mf || (selected->has_df_lid && selected->df_lid == 0x3F00);
        if (selected_is_root) {
            calypso_dump_node_init_from_selected(&root_raw, selected);
        }
        root_raw.sources = CALYPSO_DUMP_SOURCE_SELECTED;
        if (ctx.from_root || ctx.is_mf || ctx.has_lid) {
            root_raw.has_select_lid = true;
            root_raw.select_lid = (ctx.from_root || ctx.is_mf) ? 0x3F00 : ctx.lid;
            root_raw.has_lid = true;
            root_raw.lid = root_raw.select_lid;
        }
        if (have_baseline_get_fcp) {
            calypso_apdu_response_set(&root_raw.get_data_fcp, baseline_fcp, baseline_fcp_len, baseline_fcp_sw);
        }
        if (have_baseline_cur_fcp) {
            calypso_apdu_response_set(&root_raw.select_current_fcp, baseline_cur_fcp, baseline_cur_fcp_len, baseline_cur_fcp_sw);
        }

        char detail_prefix[96] = {0};
        calypso_dump_detail_prefix(0, detail_prefix, sizeof(detail_prefix));
        calypso_dump_print_root(&ctx, &root_raw);
        calypso_dump_print_inline_file_data(detail_prefix, true, &root_raw, verbose);
        calypso_dump_add_file_json(dump, &ctx, &root_raw, true, true);
    }

    calypso_dump_candidate_list_t candidates = {0};
    calypso_dump_candidate_list_t c0_candidates = {0};
    uint8_t ef_list[APDU_RES_LEN] = {0};
    size_t ef_list_len = 0;
    uint16_t ef_list_sw = 0;
    calypso_dump_get_data_args_t get_ef_list = {0x00C0, {ef_list, sizeof(ef_list)}};
    res = calypso_dump_command_with_resume(&context_resume, calypso_dump_send_get_data, &get_ef_list, &ef_list_len, &ef_list_sw);
    if (res != PM3_SUCCESS) {
        goto done;
    }
    bool have_ef_list = calypso_read_sw_has_data(ef_list_sw, ef_list_len);
    if (have_ef_list) {
        calypso_dump_add_c0_candidates(&c0_candidates, ef_list, ef_list_len);
    }
    uint16_t inferred_parent = 0;
    bool have_inferred_parent = ctx.is_mf == false && ctx.from_root == false && ctx.path_len == 0 &&
                                calypso_dump_infer_parent_from_c0(&c0_candidates, &inferred_parent);
    if (preset == CALYPSO_DUMP_PRESET_BRUTE && calypso_dump_add_brute_file_candidates(&candidates, &ctx, have_inferred_parent, inferred_parent) == false) {
        return PM3_EMALLOC;
    }
    if (calypso_dump_add_known_candidates(&candidates, &ctx, have_inferred_parent, inferred_parent) == false) {
        return PM3_EMALLOC;
    }
    if (ctx.has_seed_lid && (ctx.has_lid == false || ctx.seed_lid != ctx.lid) &&
            calypso_dump_candidate_add(&candidates, ctx.seed_lid, CALYPSO_DUMP_SOURCE_SELECTED) == false) {
        return PM3_EMALLOC;
    }
    for (size_t i = 0; i < c0_candidates.count; i++) {
        if (calypso_dump_candidate_add(&candidates, c0_candidates.items[i].lid, CALYPSO_DUMP_SOURCE_EFLIST) == false) {
            return PM3_EMALLOC;
        }
    }
    if (candidates.count > 1) {
        qsort(candidates.items, candidates.count, sizeof(candidates.items[0]), calypso_dump_candidate_compare);
    }

    if (verbose) {
        PrintAndLogEx(DEBUG, "Dump context has %zu candidates", candidates.count);
        if (have_ef_list) {
            PrintAndLogEx(DEBUG, "Dump context EF List %s", sprint_hex(ef_list, ef_list_len));
        } else {
            PrintAndLogEx(DEBUG, "Dump context EF List unavailable (%04X - %s)", ef_list_sw, GetAPDUCodeDescription(ef_list_sw >> 8, ef_list_sw & 0xFF));
        }
    }

    for (size_t i = 0; i < candidates.count; i++) {
        if (kbd_enter_pressed()) {
            calypso_dump_brute_status_clear(&brute_status_visible);
            PrintAndLogEx(WARNING, "Aborted by user");
            res = PM3_EOPABORTED;
            goto done;
        }

        const calypso_dump_lid_candidate_t *candidate = &candidates.items[i];
        calypso_dump_brute_status_update(candidate, &brute_status_visible, &brute_status_last_lid);

        uint16_t lid = candidate->lid;
        if (calypso_dump_walk_is_current_lid(&ctx, lid)) {
            continue;
        }
        if (restore_base_needed) {
            res = calypso_dump_reselect_base(selected, &ctx, verbose);
            if (calypso_dump_result_lost(res)) {
                calypso_dump_brute_status_clear(&brute_status_visible);
                res = calypso_dump_resume_restore(&context_resume);
            }
            if (res != PM3_SUCCESS) {
                goto done;
            }
            restore_base_needed = false;
        }

        uint8_t select_response[APDU_RES_LEN] = {0};
        size_t select_len = 0;
        uint16_t select_sw = 0;
        calypso_dump_select_lid_args_t select_cmd = {&ctx, lid, select_response, sizeof(select_response)};
        res = calypso_dump_command_with_resume(&context_resume, calypso_dump_send_select_lid, &select_cmd, &select_len, &select_sw);
        if (res != PM3_SUCCESS) {
            goto done;
        }
        if (select_sw == ISO7816_FILE_NOT_FOUND) {
            continue;
        }
        if (calypso_select_sw_has_file(select_sw) == false) {
            if (verbose && calypso_read_sw_is_unavailable(select_sw) == false) {
                calypso_dump_brute_status_clear(&brute_status_visible);
                PrintAndLogEx(INFO, " %*s%04X unavailable (%04X - %s)", (int)(ctx.depth * 2), "", lid, select_sw, GetAPDUCodeDescription(select_sw >> 8, select_sw & 0xFF));
            }
            continue;
        }

        restore_base_needed = true;
        calypso_dump_resume_t file_resume = {selected, &ctx, verbose, CALYPSO_DUMP_RESUME_FILE, lid};

        uint8_t df_fci[APDU_RES_LEN] = {0};
        size_t df_fci_len = 0;
        bool have_df_fci = false;
        uint16_t df_fci_sw = 0;

        bool select_is_fci = calypso_data_is_fci(select_response, select_len);
        calypso_fcp_t select_fcp = {0};
        bool select_is_fcp = calypso_parse_fcp(select_response, select_len, &select_fcp);
        bool is_df = select_is_fci || (select_is_fcp && select_fcp.file_type == CALYPSO_FILE_DF);
        bool is_ef = select_is_fcp && select_fcp.file_type == CALYPSO_FILE_EF;
        // Some HCE Calypso cards default unknown LID selection to another file.
        // Guard DF recursion against endlessly walking that fallback response.
        if (select_is_fcp && is_df && calypso_fcp_matches_lid(&select_fcp, lid) == false) {
            continue;
        }

        bool tried_df_fci = false;
        if (is_df || select_is_fcp == false) {
            tried_df_fci = true;
            calypso_dump_get_data_args_t get_fci = {0x006F, {df_fci, sizeof(df_fci)}};
            res = calypso_dump_command_with_resume(&file_resume, calypso_dump_send_get_data, &get_fci, &df_fci_len, &df_fci_sw);
            if (res != PM3_SUCCESS) {
                goto done;
            }
            have_df_fci = calypso_read_sw_has_data(df_fci_sw, df_fci_len);
            if (have_df_fci) {
                is_df = true;
            }
        }

        uint8_t fcp[APDU_RES_LEN] = {0};
        size_t fcp_len = 0;
        uint16_t fcp_sw = 0;
        calypso_dump_get_data_args_t get_fcp = {0x0062, {fcp, sizeof(fcp)}};
        res = calypso_dump_command_with_resume(&file_resume, calypso_dump_send_get_data, &get_fcp, &fcp_len, &fcp_sw);
        if (res != PM3_SUCCESS) {
            goto done;
        }
        bool have_fcp = calypso_read_sw_has_data(fcp_sw, fcp_len);

        const uint8_t *node_fcp = NULL;
        size_t node_fcp_len = 0;
        calypso_fcp_t parsed_node_fcp = {0};
        bool have_node_fcp = calypso_preferred_fcp(select_is_fcp ? select_response : NULL, select_is_fcp ? select_len : 0,
                                                   have_fcp ? fcp : NULL, have_fcp ? fcp_len : 0,
                                                   &node_fcp, &node_fcp_len, &parsed_node_fcp);
        if (have_node_fcp) {
            is_df = is_df || parsed_node_fcp.file_type == CALYPSO_FILE_DF;
            is_ef = is_ef || parsed_node_fcp.file_type == CALYPSO_FILE_EF;
        }

        if (is_df && tried_df_fci == false) {
            tried_df_fci = true;
            calypso_dump_get_data_args_t get_fci = {0x006F, {df_fci, sizeof(df_fci)}};
            res = calypso_dump_command_with_resume(&file_resume, calypso_dump_send_get_data, &get_fci, &df_fci_len, &df_fci_sw);
            if (res != PM3_SUCCESS) {
                goto done;
            }
            have_df_fci = calypso_read_sw_has_data(df_fci_sw, df_fci_len);
        }

        uint8_t current_df_fcp[APDU_RES_LEN] = {0};
        size_t current_df_fcp_len = 0;
        uint16_t current_df_fcp_sw = 0;
        bool have_current_df_fcp = false;
        if (is_df) {
            calypso_dump_current_fcp_args_t get_current_fcp = {verbose, current_df_fcp, sizeof(current_df_fcp)};
            res = calypso_dump_command_with_resume(&file_resume, calypso_dump_send_current_fcp, &get_current_fcp, &current_df_fcp_len, &current_df_fcp_sw);
            if (res != PM3_SUCCESS) {
                goto done;
            }
            have_current_df_fcp = current_df_fcp_len > 0;
            if (have_node_fcp == false && have_current_df_fcp && calypso_parse_fcp(current_df_fcp, current_df_fcp_len, &parsed_node_fcp)) {
                node_fcp = current_df_fcp;
                node_fcp_len = current_df_fcp_len;
                have_node_fcp = true;
                is_df = parsed_node_fcp.file_type == CALYPSO_FILE_DF;
                is_ef = parsed_node_fcp.file_type == CALYPSO_FILE_EF;
            }
        }

        if (have_node_fcp == false) {
            restore_base_needed = true;
            continue;
        }

        if (is_df == false && is_ef == false) {
            continue;
        }

        uint16_t node_lid = 0;
        bool have_node_lid = calypso_fcp_find_lid(&parsed_node_fcp, true, lid, &node_lid);

        calypso_dump_node_t raw_node = {0};
        raw_node.sources = candidate->sources;
        raw_node.has_select_lid = true;
        raw_node.select_lid = lid;
        raw_node.has_lid = true;
        raw_node.lid = have_node_lid ? node_lid : lid;
        calypso_dump_node_set_select_response(&raw_node, select_response, select_len, select_sw);
        if (tried_df_fci) {
            calypso_apdu_response_set(&raw_node.get_data_fci, df_fci, have_df_fci ? df_fci_len : 0, df_fci_sw);
        }
        calypso_apdu_response_set(&raw_node.get_data_fcp, fcp, have_fcp ? fcp_len : 0, fcp_sw);
        if (is_df) {
            calypso_apdu_response_set(&raw_node.select_current_fcp, current_df_fcp, have_current_df_fcp ? current_df_fcp_len : 0, current_df_fcp_sw);
        }
        if (is_df) {
            calypso_dump_apply_fci_identity(&raw_node);
            calypso_dump_apply_profile_node(&raw_node, dump != NULL ? dump->profile : NULL);
            calypso_dump_apply_fci_identity(&raw_node);
        }
        calypso_dump_brute_status_clear(&brute_status_visible);
        calypso_dump_print_node(&ctx, &raw_node, is_df, verbose);
        char detail_prefix[96] = {0};
        calypso_dump_detail_prefix(ctx.depth, detail_prefix, sizeof(detail_prefix));
        calypso_dump_print_inline_file_data(detail_prefix, is_df, &raw_node, verbose);
        json_t *json_node = calypso_dump_add_file_json(dump, &ctx, &raw_node, is_df, false);

        if (is_df) {
            uint16_t child_lid = have_node_lid ? node_lid : lid;
            if (ctx.depth + 1 < max_depth && ctx.path_len < CALYPSO_DUMP_NODE_PATH_MAX &&
                    calypso_dump_walk_is_current_lid(&ctx, child_lid) == false) {
                calypso_dump_walk_context_t child = ctx;
                child.path[child.path_len++] = lid;
                child.depth = ctx.depth + 1;
                child.is_mf = false;
                child.has_lid = have_node_lid;
                child.lid = have_node_lid ? node_lid : 0;
                child.has_seed_lid = false;
                child.seed_lid = 0;
                res = calypso_dump_process_context(selected, &child, max_depth, preset, verbose, dump);
                if (res != PM3_SUCCESS) {
                    goto done;
                }
            }
        } else {
            res = calypso_dump_read_ef(selected, &ctx, lid, json_node, verbose);
            if (res != PM3_SUCCESS) {
                goto done;
            }
        }
    }

    res = PM3_SUCCESS;
done:
    calypso_dump_brute_status_clear(&brute_status_visible);
    return res;
}

static int calypso_dump_select_root_mode(const calypso_select_result_t *selected, bool verbose, bool *from_root) {
    *from_root = false;

    calypso_dump_walk_context_t aid_ctx = {0};
    uint8_t response[APDU_RES_LEN] = {0};
    size_t response_len = 0;
    uint16_t sw = 0;
    int res = calypso_dump_select_lid(&aid_ctx, 0x3F00, response, sizeof(response), &response_len, &sw);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (calypso_select_sw_has_file(sw)) {
        if (calypso_fcp_is_type(response, response_len, CALYPSO_FILE_MF)) {
            *from_root = true;
            return PM3_SUCCESS;
        }

        uint16_t current_lid = 0;
        calypso_apdu_response_t current_fcp = {0};
        calypso_fcp_t parsed = {0};
        res = calypso_select_current_file_fcp(verbose, &current_fcp, &parsed);
        if (res != PM3_SUCCESS) {
            return res;
        }
        bool has_current_lid = calypso_fcp_primary_lid(&parsed, &current_lid);
        if ((has_current_lid && calypso_lid_is_valid(current_lid)) ||
                (calypso_get_current_ef_lid(verbose, &current_lid) && calypso_lid_is_valid(current_lid))) {
            *from_root = current_lid == 0x3F00;
            return PM3_SUCCESS;
        }
    }

    if (verbose && sw != ISO7816_FILE_NOT_FOUND && calypso_read_sw_is_unavailable(sw) == false) {
        PrintAndLogEx(INFO, " SELECT 3F00 unavailable for root reset (%04X - %s)", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
    }

    // If MF is not reachable, reset to the selected AID and discover that DF as the root.
    return calypso_dump_reselect_base(selected, &aid_ctx, verbose);
}

static int calypso_dump_selected_df(const calypso_select_result_t *selected, uint16_t max_depth, calypso_dump_preset_t preset, bool verbose, calypso_dump_json_context_t *dump) {
    calypso_print_select_info_ex(selected, verbose, false);

    uint16_t selected_lid = 0;
    bool have_selected_lid = false;
    calypso_apdu_response_t selected_fcp = {0};
    bool selected_lid_from_mf_select = false;
    int res = calypso_get_data_object(0x0062, &selected_fcp);
    if (res != PM3_SUCCESS) {
        return res;
    }
    bool have_selected_fcp = calypso_read_sw_has_data(selected_fcp.sw, selected_fcp.len);
    if (have_selected_fcp) {
        if (calypso_fcp_lid(selected_fcp.data, selected_fcp.len, &selected_lid)) {
            have_selected_lid = true;
        }
    }
    if (have_selected_lid == false) {
        calypso_apdu_response_t selected_cur_fcp = {0};
        calypso_fcp_t current_fcp = {0};
        res = calypso_select_current_file_fcp(verbose, &selected_cur_fcp, &current_fcp);
        if (res != PM3_SUCCESS) {
            return res;
        }
        have_selected_lid = calypso_fcp_primary_lid(&current_fcp, &selected_lid);
        if (have_selected_lid == false) {
            // Some cards return broken FCP LID fields; if selecting 3F00 returns the same FCP we already saw, treat it as MF.
            calypso_apdu_response_t mf_response = {0};
            const uint16_t mf_path[] = {0x3F00};
            res = calypso_select_file_path_then_id_fallback(mf_path, ARRAYLEN(mf_path), 0x3F00, &mf_response);
            if (res != PM3_SUCCESS) {
                return res;
            }
            uint16_t mf_lid = 0;
            bool matches_previous_fcp = (calypso_data_is_fcp(selected_fcp.data, selected_fcp.len) && selected_fcp.len == mf_response.len && memcmp(selected_fcp.data, mf_response.data, selected_fcp.len) == 0) ||
                                        (calypso_data_is_fcp(selected_cur_fcp.data, selected_cur_fcp.len) && selected_cur_fcp.len == mf_response.len && memcmp(selected_cur_fcp.data, mf_response.data, selected_cur_fcp.len) == 0);
            if (calypso_select_sw_has_file(mf_response.sw) && calypso_data_is_fcp(mf_response.data, mf_response.len) &&
                    (calypso_fcp_lid_with_hint(mf_response.data, mf_response.len, true, 0x3F00, &mf_lid) || matches_previous_fcp ||
                     calypso_fcp_is_type(mf_response.data, mf_response.len, CALYPSO_FILE_MF))) {
                selected_lid = 0x3F00;
                have_selected_lid = true;
                selected_lid_from_mf_select = true;
            }
        }
    }
    bool from_root = selected_lid_from_mf_select;
    if (from_root == false) {
        res = calypso_dump_select_root_mode(selected, verbose, &from_root);
        if (res != PM3_SUCCESS) {
            return res;
        }
    }

    calypso_dump_walk_context_t root = {0};
    root.from_root = from_root;
    root.is_mf = from_root || (have_selected_lid && selected_lid == 0x3F00);
    root.has_lid = have_selected_lid;
    root.lid = have_selected_lid ? selected_lid : 0;
    if (from_root && have_selected_lid) {
        root.has_seed_lid = true;
        root.seed_lid = selected_lid;
    }
    return calypso_dump_process_context(selected, &root, max_depth, preset, verbose, dump);
}

static void calypso_dump_node_copy_raw(uint8_t *dst, size_t *dst_len, const uint8_t *src, size_t src_len, size_t dst_size) {
    if (dst == NULL || dst_len == NULL || src == NULL || src_len == 0 || dst_size == 0) {
        return;
    }

    src_len = MIN(src_len, dst_size);
    memcpy(dst, src, src_len);
    *dst_len = src_len;
}

static void calypso_apdu_response_set(calypso_apdu_response_t *dst, const uint8_t *src, size_t src_len, uint16_t sw) {
    if (dst == NULL) {
        return;
    }

    dst->sw = sw;
    dst->len = 0;
    calypso_dump_node_copy_raw(dst->data, &dst->len, src, src_len, sizeof(dst->data));
}

static void calypso_dump_node_set_select_response(calypso_dump_node_t *node, const uint8_t *data, size_t data_len, uint16_t sw) {
    if (node == NULL) {
        return;
    }

    if (data == NULL || data_len == 0) {
        return;
    }

    if (calypso_data_is_fcp(data, data_len)) {
        calypso_apdu_response_set(&node->select_fcp, data, data_len, sw);
    } else if (calypso_data_is_fci(data, data_len)) {
        calypso_apdu_response_set(&node->select_fci, data, data_len, sw);
    }
}

static size_t calypso_dump_node_aid(const calypso_dump_node_t *node, const uint8_t **aid) {
    if (aid == NULL) {
        return 0;
    }
    *aid = NULL;
    if (node != NULL && node->select_aid_len > 0) {
        *aid = node->select_aid;
        return node->select_aid_len;
    }
    return 0;
}

static bool calypso_dump_node_first_fcp(const calypso_dump_node_t *node, const uint8_t **fcp, size_t *fcp_len) {
    if (node == NULL || fcp == NULL || fcp_len == NULL) {
        return false;
    }
    const calypso_apdu_response_t *views[] = {&node->select_current_fcp, &node->select_fcp, &node->get_data_fcp};
    for (size_t i = 0; i < ARRAYLEN(views); i++) {
        if (views[i]->len > 0) {
            *fcp = views[i]->data;
            *fcp_len = views[i]->len;
            return true;
        }
    }
    return false;
}

static bool calypso_fci_df_name(const uint8_t *fci_data, size_t fci_len, uint8_t *aid, size_t *aid_len) {
    if (fci_data == NULL || fci_len == 0 || aid == NULL || aid_len == NULL) {
        return false;
    }

    calypso_fci_t fci = {0};
    if (calypso_parse_fci(fci_data, fci_len, &fci) == false || fci.has_df_name == false) {
        return false;
    }

    memcpy(aid, fci.df_name, fci.df_name_len);
    *aid_len = fci.df_name_len;
    return true;
}

static void calypso_dump_apply_fci_identity(calypso_dump_node_t *node) {
    if (node == NULL || node->select_aid_len > 0) {
        return;
    }

    if (node->select_fci.len > 0 &&
            calypso_fci_df_name(node->select_fci.data, node->select_fci.len, node->select_aid, &node->select_aid_len)) {
        return;
    }
    if (node->get_data_fci.len > 0) {
        calypso_fci_df_name(node->get_data_fci.data, node->get_data_fci.len, node->select_aid, &node->select_aid_len);
    }
}

static const calypso_dump_node_t *calypso_dump_profile_unique_lid_node(const calypso_dump_profile_t *profile, const calypso_dump_node_t *node) {
    uint16_t node_lid = 0;
    if (profile == NULL || node == NULL || calypso_dump_node_known_lid(node, &node_lid) == false) {
        return NULL;
    }

    const calypso_dump_node_t *match = NULL;
    for (size_t i = 0; i < profile->node_count; i++) {
        uint16_t profile_lid = 0;
        if (calypso_dump_node_known_lid(&profile->nodes[i], &profile_lid) == false || profile_lid != node_lid) {
            continue;
        }
        if (match != NULL) {
            return NULL;
        }
        match = &profile->nodes[i];
    }

    return match;
}

static void calypso_apdu_response_copy_missing(calypso_apdu_response_t *dst, const calypso_apdu_response_t *src) {
    if (dst == NULL || src == NULL || dst->len > 0 || src->len == 0) {
        return;
    }

    calypso_apdu_response_set(dst, src->data, src->len, src->sw);
}

static void calypso_dump_apply_profile_node(calypso_dump_node_t *node, const calypso_dump_profile_t *profile) {
    const calypso_dump_node_t *match = calypso_dump_profile_unique_lid_node(profile, node);
    if (match == NULL) {
        return;
    }

    if (node->select_aid_len == 0) {
        calypso_dump_node_copy_raw(node->select_aid, &node->select_aid_len, match->select_aid, match->select_aid_len, sizeof(node->select_aid));
    }
    if (node->has_select_lid == false && match->has_select_lid) {
        node->has_select_lid = true;
        node->select_lid = match->select_lid;
    }
    if (node->has_lid == false && match->has_lid) {
        node->has_lid = true;
        node->lid = match->lid;
    }
    if (calypso_selection_is_default(&node->selected) == false && calypso_selection_is_default(&match->selected)) {
        node->selected = match->selected;
    }

    calypso_apdu_response_copy_missing(&node->select_fci, &match->select_fci);
    calypso_apdu_response_copy_missing(&node->select_fcp, &match->select_fcp);
    calypso_apdu_response_copy_missing(&node->select_current_fcp, &match->select_current_fcp);
    calypso_apdu_response_copy_missing(&node->get_data_fci, &match->get_data_fci);
    calypso_apdu_response_copy_missing(&node->get_data_fcp, &match->get_data_fcp);
}

static bool calypso_dump_profile_has_node_aid(const calypso_dump_profile_t *profile, const calypso_dump_node_t *node) {
    if (profile == NULL || node == NULL) {
        return false;
    }

    const uint8_t *aid = NULL;
    size_t aid_len = calypso_dump_node_aid(node, &aid);
    if (aid == NULL || aid_len == 0) {
        return false;
    }

    for (size_t i = 0; i < profile->node_count; i++) {
        const uint8_t *seen_aid = NULL;
        size_t seen_aid_len = calypso_dump_node_aid(&profile->nodes[i], &seen_aid);
        if (seen_aid != NULL && seen_aid_len == aid_len && memcmp(seen_aid, aid, aid_len) == 0) {
            return true;
        }
    }
    return false;
}

static calypso_dump_profile_t *calypso_dump_profile_list_get_or_add(calypso_dump_profile_list_t *profiles, const uint8_t *serial) {
    if (profiles == NULL || serial == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < profiles->count; i++) {
        if (memcmp(profiles->items[i].serial, serial, CALYPSO_SERIAL_LEN) == 0) {
            return &profiles->items[i];
        }
    }
    if (profiles->count >= ARRAYLEN(profiles->items)) {
        return NULL;
    }
    calypso_dump_profile_t *profile = &profiles->items[profiles->count++];
    memset(profile, 0, sizeof(*profile));
    memcpy(profile->serial, serial, CALYPSO_SERIAL_LEN);
    return profile;
}

static void calypso_dump_node_init_from_selected(calypso_dump_node_t *node, const calypso_select_result_t *selected) {
    memset(node, 0, sizeof(*node));
    node->selected = *selected;

    const uint8_t *aid = NULL;
    size_t aid_len = 0;
    if (selected->parsed.has_df_name && selected->parsed.df_name_len > 0) {
        aid = selected->parsed.df_name;
        aid_len = calypso_aid_len_without_trailing_zeroes(selected->parsed.df_name, selected->parsed.df_name_len);
    } else if (selected->requested_aid_len > 0) {
        aid = selected->requested_aid;
        aid_len = selected->requested_aid_len;
    }
    calypso_dump_node_copy_raw(node->select_aid, &node->select_aid_len, aid, aid_len, sizeof(node->select_aid));

    calypso_dump_node_set_select_response(node, selected->response.data, selected->response.len, selected->response.sw);

    if (selected->has_df_lid) {
        node->has_select_lid = true;
        node->select_lid = selected->df_lid;
        node->has_lid = true;
        node->lid = selected->df_lid;
    }
}

static int calypso_dump_record_preprobe(calypso_dump_profile_list_t *profiles, const calypso_select_result_t *selected, bool verbose) {
    if (profiles == NULL || selected == NULL) {
        return PM3_EINVARG;
    }

    calypso_dump_node_t node = {0};
    calypso_dump_node_init_from_selected(&node, selected);

    calypso_apdu_response_t fcp = {0};
    int res = calypso_get_data_object(0x0062, &fcp);
    if (res != PM3_SUCCESS) {
        return res;
    }
    if (calypso_read_sw_has_data(fcp.sw, fcp.len)) {
        node.get_data_fcp = fcp;
    }

    calypso_apdu_response_t current_fcp = {0};
    calypso_fcp_t parsed = {0};
    res = calypso_select_current_file_fcp(verbose, &current_fcp, &parsed);
    if (res != PM3_SUCCESS) {
        return res;
    }
    if (current_fcp.len > 0) {
        node.select_current_fcp = current_fcp;
    }
    uint16_t current_lid = 0;
    bool has_current_lid = calypso_fcp_primary_lid(&parsed, &current_lid);
    if (has_current_lid) {
        node.has_lid = true;
        node.lid = current_lid;
    }

    uint8_t serial[CALYPSO_SERIAL_LEN] = {0};
    bool serial_found = calypso_selection_profile_serial(&node.selected, serial);
    if (serial_found == false) {
        return PM3_SUCCESS;
    }

    calypso_dump_profile_t *profile = calypso_dump_profile_list_get_or_add(profiles, serial);
    if (profile == NULL) {
        return PM3_EMALLOC;
    }

    if (calypso_dump_profile_has_node_aid(profile, &node)) {
        return PM3_SUCCESS;
    }
    if (profile->node_count >= profile->node_capacity) {
        size_t new_capacity = profile->node_capacity == 0 ? 8 : profile->node_capacity * 2;
        calypso_dump_node_t *nodes = realloc(profile->nodes, new_capacity * sizeof(*nodes));
        if (nodes == NULL) {
            return PM3_EMALLOC;
        }
        profile->nodes = nodes;
        profile->node_capacity = new_capacity;
    }
    profile->nodes[profile->node_count++] = node;
    return PM3_SUCCESS;
}

static int calypso_dump_reselect_for_walk(const calypso_select_result_t *selected, calypso_rf_info_t *rf, bool verbose, calypso_select_result_t *walk_selected) {
    if (selected == NULL || rf == NULL || walk_selected == NULL) {
        return PM3_EINVARG;
    }

    int res = calypso_reactivate(verbose, rf);
    if (res != PM3_SUCCESS) {
        return res;
    }
    if (selected->origin == CALYPSO_SELECTION_ACTIVATION &&
            (rf->protocol != ISODEP_NFCB_PRIME ||
             memcmp(rf->card.prime.div, selected->rf.card.prime.div, ISO14B_PRIME_DIV_LEN) != 0)) {
        return PM3_EOPABORTED;
    }

    *walk_selected = *selected;
    walk_selected->rf = *rf;
    if (calypso_selection_is_default(walk_selected)) {
        return PM3_SUCCESS;
    }
    return calypso_restore_selection(walk_selected, verbose, walk_selected);
}

static bool calypso_dump_node_known_lid(const calypso_dump_node_t *node, uint16_t *lid) {
    if (node == NULL || lid == NULL) {
        return false;
    }

    if (node->has_select_lid && calypso_lid_is_valid(node->select_lid)) {
        *lid = node->select_lid;
        return true;
    }
    if (node->has_lid && calypso_lid_is_valid(node->lid)) {
        *lid = node->lid;
        return true;
    }
    const uint8_t *fcp = NULL;
    size_t fcp_len = 0;
    return calypso_dump_node_first_fcp(node, &fcp, &fcp_len) &&
           calypso_fcp_lid(fcp, fcp_len, lid);
}

static const calypso_dump_node_t *calypso_dump_select_root_node(const calypso_dump_profile_t *profile) {
    if (profile == NULL || profile->node_count == 0) {
        return NULL;
    }

    for (size_t i = 0; i < profile->node_count; i++) {
        uint16_t lid = 0;
        if (calypso_dump_node_known_lid(&profile->nodes[i], &lid) && lid == 0x3F00) {
            return &profile->nodes[i];
        }
    }

    for (size_t i = 0; i < profile->node_count; i++) {
        uint16_t lid = 0;
        if (calypso_dump_node_known_lid(&profile->nodes[i], &lid)) {
            continue;
        }
        const uint8_t *aid = NULL;
        size_t aid_len = calypso_dump_node_aid(&profile->nodes[i], &aid);
        if (aid != NULL && aid_len >= sizeof(calypso_mf_aid) && memcmp(aid, calypso_mf_aid, sizeof(calypso_mf_aid)) == 0) {
            return &profile->nodes[i];
        }
    }

    for (size_t i = 0; i < profile->node_count; i++) {
        const uint8_t *aid = NULL;
        size_t aid_len = calypso_dump_node_aid(&profile->nodes[i], &aid);
        if (aid_len > 0 || calypso_selection_is_default(&profile->nodes[i].selected)) {
            return &profile->nodes[i];
        }
    }

    return &profile->nodes[0];
}

static void calypso_dump_print_profile_map(const calypso_dump_profile_list_t *profiles) {
    if (profiles == NULL || profiles->count == 0) {
        return;
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Calypso dump Profile Map") " ----------------");
    for (size_t i = 0; i < profiles->count; i++) {
        const calypso_dump_profile_t *profile = &profiles->items[i];
        PrintAndLogEx(INFO, "Serial " _GREEN_("%s") ":", sprint_hex_inrow(profile->serial, CALYPSO_SERIAL_LEN));
        for (size_t j = 0; j < profile->node_count; j++) {
            const calypso_dump_node_t *node = &profile->nodes[j];
            const uint8_t *aid = NULL;
            size_t aid_len = calypso_dump_node_aid(node, &aid);
            uint16_t lid = 0;
            bool have_lid = calypso_dump_node_known_lid(node, &lid);
            char lid_text[8] = "unknown";
            if (have_lid) {
                snprintf(lid_text, sizeof(lid_text), "%04X", lid);
            }
            if (aid_len > 0) {
                PrintAndLogEx(INFO, "  " _YELLOW_("%s") " (LID " _GREEN_("%s") "%s)", sprint_hex_inrow(aid, aid_len), lid_text,
                              calypso_selection_is_default(&node->selected) ? ", default" : "");
            } else {
                PrintAndLogEx(INFO, "  " _YELLOW_("AID unknown") " (LID " _GREEN_("%s") "%s)", lid_text,
                              calypso_selection_is_default(&node->selected) ? ", default" : "");
            }
        }
    }
}

static int calypso_dump_scan_applications(calypso_rf_info_t *rf, bool verbose, calypso_dump_profile_list_t *profiles) {
    if (rf == NULL || profiles == NULL) {
        return PM3_EINVARG;
    }

    json_t *root = AIDSearchInit(verbose);
    if (root == NULL) {
        return PM3_EFILE;
    }

    int first_error = PM3_SUCCESS;
    calypso_select_result_t implicit_selected = {0};
    first_error = calypso_probe_current_df(rf, verbose, &implicit_selected);
    if (first_error == PM3_SUCCESS && implicit_selected.origin != CALYPSO_SELECTION_NONE &&
            calypso_fci_is_complete(&implicit_selected.parsed)) {
        first_error = calypso_dump_record_preprobe(profiles, &implicit_selected, verbose);
    }
    if (first_error != PM3_SUCCESS) {
        AIDSearchFree(root);
        return first_error;
    }

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

            calypso_select_result_t selected = {0};
            int res = calypso_select_aid(aid, (size_t)aid_len, verbose, rf, &selected);
            if (res != PM3_SUCCESS) {
                first_error = res;
                break;
            }
            if (selected.origin == CALYPSO_SELECTION_NONE) {
                continue;
            }
            if (calypso_fci_is_complete(&selected.parsed) == false) {
                continue;
            }

            first_error = calypso_dump_record_preprobe(profiles, &selected, verbose);
            if (first_error != PM3_SUCCESS) {
                break;
            }
        }
    }

    if (first_error == PM3_SUCCESS && profiles->count == 0 && rf->protocol == ISODEP_NFCB_PRIME) {
        calypso_select_result_t activation = {0};
        first_error = calypso_repoll_activation(rf, verbose, &activation);
        if (first_error == PM3_SUCCESS) {
            *rf = activation.rf;
            first_error = calypso_dump_record_preprobe(profiles, &activation, verbose);
        }
    }

    if (first_error == PM3_SUCCESS) {
        calypso_dump_print_profile_map(profiles);
    }

    AIDSearchFree(root);
    return first_error;
}

static int calypso_dump_profile(calypso_dump_profile_t *dump_profile, calypso_rf_info_t *rf, uint16_t max_depth, calypso_dump_preset_t preset, bool verbose, json_t *profiles_json, calypso_dump_filename_context_t *filename_ctx, calypso_select_result_t *first_selected, bool *have_first_selected) {
    if (dump_profile == NULL || rf == NULL || profiles_json == NULL) {
        return PM3_EINVARG;
    }

    const calypso_dump_node_t *root_node = calypso_dump_select_root_node(dump_profile);
    if (root_node == NULL) {
        return PM3_EOPABORTED;
    }
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Calypso dump Profile %s") " ----------", sprint_hex_inrow(dump_profile->serial, CALYPSO_SERIAL_LEN));

    calypso_select_result_t walk_selected = {0};
    int res = calypso_dump_reselect_for_walk(&root_node->selected, rf, verbose, &walk_selected);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (*have_first_selected == false) {
        *first_selected = walk_selected;
        *have_first_selected = true;
    }
    calypso_dump_filename_add_serial(filename_ctx, &walk_selected);

    json_t *profile = json_object();
    calypso_json_set_hex(profile, "serial", dump_profile->serial, sizeof(dump_profile->serial));
    if (walk_selected.parsed.has_startup) {
        calypso_json_set_hex(profile, "startupInfo", walk_selected.parsed.startup, sizeof(walk_selected.parsed.startup));
    } else if (walk_selected.origin == CALYPSO_SELECTION_ACTIVATION) {
        json_object_set_new(profile, "startupInfo", json_null());
    }
    calypso_dump_add_profile_data_objects(profile);
    json_t *nodes = json_array();
    json_object_set_new(profile, "nodes", nodes);

    calypso_dump_json_context_t dump = {
        .nodes = nodes,
        .profile = dump_profile,
    };
    res = calypso_dump_selected_df(&walk_selected, max_depth, preset, verbose, &dump);

    json_array_append_new(profiles_json, profile);
    return res;
}

static int CmdHFCalypsoDump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf calypso dump",
                  "Dump Calypso nodes by first scanning available application profiles",
                  "hf calypso dump\n"
                  "hf calypso dump --preset brute\n"
                  "hf calypso dump -f my-calypso-dump\n"
                  "hf calypso dump --ns -v");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "Specify a filename for JSON dump file"),
        arg_str0(NULL, "preset", "<known|brute>", "candidate preset (`known` default, `brute` also bruteforces LID candidates)"),
        arg_lit0(NULL, "ns", "no save to file"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    char filename[FILE_PATH_SIZE] = {0};
    int fnlen = 0;
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    int preset_arg = CALYPSO_DUMP_PRESET_KNOWN;
    if (CLIGetOptionList(arg_get_str(ctx, 2), calypsoDumpPresetOpts, &preset_arg)) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    calypso_dump_preset_t preset = (calypso_dump_preset_t)preset_arg;
    bool no_save = arg_get_lit(ctx, 3);
    bool verbose = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    uint16_t max_depth = 4;

    calypso_rf_info_t rf = {0};
    int res = calypso_connect_contactless(verbose, &rf);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(WARNING, "No ISO14443-4 Calypso application selected");
        return res;
    }
    calypso_print_rf_info(&rf);

    calypso_dump_profile_list_t dump_profiles = {0};
    int first_error = calypso_dump_scan_applications(&rf, verbose, &dump_profiles);
    if (first_error != PM3_SUCCESS) {
        calypso_dump_profile_list_free(&dump_profiles);
        DropField();
        return first_error;
    }

    if (dump_profiles.count == 0) {
        calypso_dump_profile_list_free(&dump_profiles);
        DropField();
        PrintAndLogEx(WARNING, "No serial-bearing Calypso profile found");
        return PM3_EOPABORTED;
    }

    json_t *root = json_object();
    json_t *profiles = json_array();
    json_object_set_new(root, "type", json_string("calypso-dump"));
    json_object_set_new(root, "profiles", profiles);

    calypso_select_result_t first_selected = {0};
    bool have_first_selected = false;
    calypso_dump_filename_context_t filename_ctx = {0};
    size_t dumped_profiles = 0;

    for (size_t i = 0; i < dump_profiles.count; i++) {
        first_error = calypso_dump_profile(&dump_profiles.items[i], &rf, max_depth, preset, verbose, profiles, &filename_ctx, &first_selected, &have_first_selected);
        if (first_error != PM3_SUCCESS) {
            break;
        }
        dumped_profiles++;
    }

    DropField();

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Calypso dump Summary") " --------------------");
    PrintAndLogEx(SUCCESS, " Profiles dumped   : " _GREEN_("%zu"), dumped_profiles);

    if (no_save == false) {
        if (fnlen == 0) {
            if (have_first_selected) {
                calypso_dump_default_filename(&first_selected, &filename_ctx, filename, sizeof(filename));
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
    calypso_dump_profile_list_free(&dump_profiles);
    PrintAndLogEx(NORMAL, "");
    return first_error;
}

static void calypso_probe_anchor_init(const calypso_select_result_t *selected, calypso_probe_anchor_t *anchor) {
    memset(anchor, 0, sizeof(*anchor));

    if (selected == NULL || selected->origin != CALYPSO_SELECTION_AID) {
        return;
    }

    const uint8_t *aid = selected->parsed.has_df_name ? selected->parsed.df_name : selected->requested_aid;
    size_t aid_len = selected->parsed.has_df_name ? selected->parsed.df_name_len : selected->requested_aid_len;
    if (aid != NULL && aid_len > 0 && aid_len <= sizeof(anchor->aid)) {
        memcpy(anchor->aid, aid, aid_len);
        anchor->aid_len = aid_len;
    }
}

static int calypso_probe_setup(const calypso_probe_anchor_t *anchor, bool verbose) {
    // Every compatibility row starts from a fresh ISO14443-4 activation so the
    // previous literal SELECT cannot influence it.
    DropField();
    msleep(50);

    calypso_rf_info_t rf = {0};
    int res = calypso_connect_contactless(verbose, &rf);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (anchor == NULL || anchor->aid_len == 0) {
        return PM3_SUCCESS;
    }

    calypso_apdu_response_t response = {0};
    sAPDU_t apdu = {0x00, ISO7816_SELECT_FILE, 0x04, 0x00, (uint8_t)anchor->aid_len, (uint8_t *)anchor->aid};
    res = calypso_exchange_select(apdu, &response);
    if (res != PM3_SUCCESS) {
        return res;
    }

    return calypso_select_sw_has_file(response.sw) ? PM3_SUCCESS : PM3_EOPABORTED;
}

static int calypso_probe_print_row(const calypso_probe_anchor_t *anchor, bool verbose, uint8_t cla, const calypso_probe_select_form_t *form, const calypso_probe_select_data_t *data_case, const calypso_probe_select_le_t *le_case) {
    sAPDU_t apdu = {
        cla,
        ISO7816_SELECT_FILE,
        form->p1,
        form->p2,
        (uint8_t)data_case->data_len,
        (uint8_t *)data_case->data
    };

    char apdu_hex[64] = {0};
    uint8_t encoded_apdu[APDU_RES_LEN] = {0};
    int encoded_apdu_len = 0;
    uint16_t encoded_le = 0;
    if (le_case->include_le) {
        encoded_le = le_case->le == 0 ? 0x100 : le_case->le;
    }
    if (APDUEncodeS(&apdu, false, encoded_le, encoded_apdu, &encoded_apdu_len) == PM3_SUCCESS) {
        snprintf(apdu_hex, sizeof(apdu_hex), "%s", encoded_apdu_len > 0 ? sprint_hex(encoded_apdu, (size_t)encoded_apdu_len) : "<empty>");
    } else {
        snprintf(apdu_hex, sizeof(apdu_hex), "<encode error>");
    }

    char select_label[CALYPSO_PROBE_SELECT_WIDTH + 1] = {0};
    snprintf(select_label, sizeof(select_label), "CLA=%02X, P1P2=%02X%02X (%-*s), DATA=%s, LE=%s", cla, form->p1, form->p2, CALYPSO_PROBE_FORM_NAME_WIDTH, form->name, data_case->name, le_case->name);

    int res = calypso_probe_setup(anchor, verbose);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, " %-*s | APDU %-24s | setup failed (%d)", CALYPSO_PROBE_SELECT_WIDTH, select_label, apdu_hex, res);
        return res;
    }

    uint8_t response[APDU_RES_LEN] = {0};
    size_t response_len = 0;
    uint16_t sw = 0;
    res = Iso7816ExchangeEx(CC_CONTACTLESS, false, true, apdu, le_case->include_le, le_case->le, response, sizeof(response), &response_len, &sw);

    uint8_t full_response[APDU_RES_LEN + 2] = {0};
    size_t full_response_len = MIN(response_len, APDU_RES_LEN);
    memcpy(full_response, response, full_response_len);
    bool have_sw = res == PM3_SUCCESS || sw != 0;
    if (have_sw && full_response_len + 2 <= sizeof(full_response)) {
        full_response[full_response_len++] = (uint8_t)(sw >> 8);
        full_response[full_response_len++] = (uint8_t)(sw & 0xFF);
    }

    char response_hex[(APDU_RES_LEN + 2) * 3 + 1] = {0};
    snprintf(response_hex, sizeof(response_hex), "%s", full_response_len > 0 ? sprint_hex(full_response, full_response_len) : "<none>");

    const char *sw_name = "";
    if (have_sw && full_response_len == 2) {
        sw_name = GetAPDUCodeDescription(sw >> 8, sw & 0xFF);
    }
    bool have_sw_name = (sw_name[0] != '\0' && strcmp(sw_name, " ") != 0 && strcmp(sw_name, "-") != 0);

    char response_display[sizeof(response_hex) + 128] = {0};
    if (have_sw_name) {
        snprintf(response_display, sizeof(response_display), "%s (%s)", response_hex, sw_name);
    } else {
        snprintf(response_display, sizeof(response_display), "%s", response_hex);
    }

    if (have_sw) {
        if (res == PM3_SUCCESS) {
            PrintAndLogEx(INFO, " %-*s | APDU %-24s | RSP %-*s", CALYPSO_PROBE_SELECT_WIDTH, select_label, apdu_hex, CALYPSO_PROBE_RESPONSE_HEX_WIDTH, response_display);
        } else {
            PrintAndLogEx(WARNING, " %-*s | APDU %-24s | RSP %-*s | exchange failed (%d)", CALYPSO_PROBE_SELECT_WIDTH, select_label, apdu_hex, CALYPSO_PROBE_RESPONSE_HEX_WIDTH, response_display, res);
        }
    } else {
        PrintAndLogEx(WARNING, " %-*s | APDU %-24s | RSP %-*s | exchange failed (%d)", CALYPSO_PROBE_SELECT_WIDTH, select_label, apdu_hex, CALYPSO_PROBE_RESPONSE_HEX_WIDTH, response_hex, res);
    }

    return PM3_SUCCESS;
}

static int calypso_probe_select_matrix(const calypso_probe_anchor_t *anchor, bool verbose) {
    int first_error = PM3_SUCCESS;

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Calypso SELECT Command Compatibility") " ------");

    for (size_t i = 0; i < ARRAYLEN(calypso_probe_cla_values); i++) {
        for (size_t j = 0; j < ARRAYLEN(calypso_probe_select_forms); j++) {
            for (size_t k = 0; k < ARRAYLEN(calypso_probe_select_data); k++) {
                for (size_t l = 0; l < ARRAYLEN(calypso_probe_select_le); l++) {
                    int res = calypso_probe_print_row(anchor, verbose, calypso_probe_cla_values[i], &calypso_probe_select_forms[j], &calypso_probe_select_data[k], &calypso_probe_select_le[l]);
                    if (res != PM3_SUCCESS) {
                        first_error = res;
                        goto out;
                    }
                }
            }
        }
    }

out:
    DropField();
    return first_error;
}

static int CmdHFCalypsoProbe(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf calypso probecmdcompat",
                  "Probe Calypso SELECT command compatibility",
                  "hf calypso probecmdcompat\n"
                  "hf calypso probecmdcompat -v\n"
                  "hf calypso probecmdcompat --aid 315449432E494341");

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

    bool restore_apdu_logging = GetAPDULogging();
    SetAPDULogging(false);

    int retval = PM3_SUCCESS;
    calypso_rf_info_t rf = {0};
    int res = calypso_connect_contactless(verbose, &rf);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "No ISO14443-4 Calypso application selected");
        retval = res;
        goto out;
    }
    calypso_print_rf_info(&rf);

    calypso_select_result_t selected = {0};
    res = calypso_discover_primary(&rf, user_aid, (size_t)user_aid_len, verbose, &selected);
    if (selected.origin != CALYPSO_SELECTION_NONE) {
        calypso_print_select_info(&selected, verbose);
    }

    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "%s", res == PM3_EOPABORTED ? "No Calypso application found" : "No ISO14443-4 Calypso application selected");
        retval = res;
        goto out;
    }

    calypso_probe_anchor_t anchor = {0};
    calypso_probe_anchor_init(&selected, &anchor);
    retval = calypso_probe_select_matrix(&anchor, verbose);

out:
    DropField();
    SetAPDULogging(restore_apdu_logging);
    PrintAndLogEx(NORMAL, "");
    return retval;
}

static int CmdHFCalypsoList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf calypso", "calypso");
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
    res = calypso_discover_primary(&rf, user_aid, (size_t)user_aid_len, verbose, &selected);
    if (selected.origin != CALYPSO_SELECTION_NONE) {
        calypso_print_select_info(&selected, verbose);
    }

    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(WARNING, "%s", res == PM3_EOPABORTED ? "No Calypso application found" : "No ISO14443-4 Calypso application selected");
        return res;
    }
    calypso_print_info_data_objects();

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
        res = calypso_restore_selection(&selected, verbose, NULL);
        if (res != PM3_SUCCESS) {
            DropField();
            return res;
        }
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
    {"dump", CmdHFCalypsoDump, IfPm3Iso14443, "Dump nodes after application profile scan"},
    {"probecmdcompat", CmdHFCalypsoProbe, IfPm3Iso14443, "Probe SELECT command compatibility"},
    {"list", CmdHFCalypsoList, AlwaysAvailable, "List Calypso history"},
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
