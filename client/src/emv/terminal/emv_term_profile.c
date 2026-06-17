//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// EMV terminal emulator — profile loading
//-----------------------------------------------------------------------------

#include "emv_term_profile.h"
#include "../emvjson.h"
#include "fileutils.h"
#include "ui.h"
#include "proxmark3.h"
#include <jansson.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#define TLV_ADD(tag, value)( tlvdb_change_or_add_node(tlvRoot, tag, sizeof(value) - 1, (const unsigned char *)value) )

static uint8_t bcd_byte(unsigned v) {
    return (uint8_t)(((v / 10) << 4) | (v % 10));
}

static void emv_term_set_transaction_datetime(struct tlvdb *tlvRoot) {
    time_t now = time(NULL);
    struct tm tm_now;
    if (!localtime_r(&now, &tm_now)) {
        return;
    }

    uint8_t date[3] = {
        bcd_byte((unsigned)(tm_now.tm_year % 100)),
        bcd_byte((unsigned)(tm_now.tm_mon + 1)),
        bcd_byte((unsigned)tm_now.tm_mday),
    };
    uint8_t txn_time[3] = {
        bcd_byte((unsigned)tm_now.tm_hour),
        bcd_byte((unsigned)tm_now.tm_min),
        bcd_byte((unsigned)tm_now.tm_sec),
    };

    tlvdb_change_or_add_node(tlvRoot, 0x9a, sizeof(date), date);
    tlvdb_change_or_add_node(tlvRoot, 0x9f21, sizeof(txn_time), txn_time);
}

void emv_term_param_defaults(struct tlvdb *tlvRoot) {
    TLV_ADD(0x9F02, "\x00\x00\x00\x00\x01\x00");
    TLV_ADD(0x9F03, "\x00\x00\x00\x00\x00\x00");
    TLV_ADD(0x9F1A, "\x08\x40");
    TLV_ADD(0x5F2A, "\x08\x40");
    TLV_ADD(0x9A,   "\x00\x00\x00");
    TLV_ADD(0x9C,   "\x00");
    TLV_ADD(0x9F37, "\x01\x02\x03\x04");
    TLV_ADD(0x9F6A, "\x01\x02\x03\x04");
    TLV_ADD(0x9F66, "\x26\x00\x00\x00");
    TLV_ADD(0x95,   "\x00\x00\x00\x00\x00");
    TLV_ADD(0x9F34, "\x00\x00\x00");
    TLV_ADD(0x9F45, "\x00\x00");
    TLV_ADD(0x9F7C, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    TLV_ADD(0x9F4E, "proxmark3rdv4\x00");
    TLV_ADD(0x9F33, "\xE0\xF8\xC8");
    TLV_ADD(0x9F40, "\xF0\x00\xF0\xA0\x01");
    TLV_ADD(0x9F35, "\x22");
    TLV_ADD(0x9F1B, "\x00\x00\x00\x00\x50\x00");
    emv_term_set_transaction_datetime(tlvRoot);
}

void emv_term_init_transaction_params(struct tlvdb *tlvRoot, bool paramLoadJSON, const char *profile_path,
                                      TransactionType_t TrType, bool GenACGPO) {
    emv_term_param_defaults(tlvRoot);

    if (profile_path && profile_path[0]) {
        emv_term_profile_load(tlvRoot, profile_path);
    } else {
        emv_term_profile_load(tlvRoot, NULL);
    }

    if (paramLoadJSON) {
        PrintAndLogEx(INFO, "* * Transaction parameters loading from JSON...");
        if (profile_path && profile_path[0]) {
            if (!ParamLoadFromJsonFile(tlvRoot, profile_path)) {
                PrintAndLogEx(WARNING, "Terminal profile load failed, trying default params...");
                ParamLoadFromJson(tlvRoot);
            }
        } else if (!ParamLoadFromJson(tlvRoot)) {
            PrintAndLogEx(WARNING, "emv_defparams.json not found — using bundled terminal profile");
        }
    }

    emv_term_set_transaction_datetime(tlvRoot);

    uint8_t un[4] = {0};
    un[0] = (uint8_t)(rand() & 0xFF);
    un[1] = (uint8_t)(rand() & 0xFF);
    un[2] = (uint8_t)(rand() & 0xFF);
    un[3] = (uint8_t)(rand() & 0xFF);
    tlvdb_change_or_add_node(tlvRoot, 0x9f37, sizeof(un), un);

    switch (TrType) {
        case TT_MSD:
            TLV_ADD(0x9F66, "\x86\x00\x00\x00");
            break;
        case TT_VSDC:
            TLV_ADD(0x9F66, "\x46\x00\x00\x00");
            break;
        case TT_QVSDCMCHIP:
            if (GenACGPO) {
                TLV_ADD(0x9F66, "\x26\x80\x00\x00");
            } else {
                TLV_ADD(0x9F66, "\x26\x00\x00\x00");
            }
            break;
        case TT_CDA:
            if (GenACGPO) {
                TLV_ADD(0x9F66, "\x26\x80\x00\x00");
            } else {
                TLV_ADD(0x9F66, "\x26\x00\x00\x00");
            }
            break;
        case TT_END:
        default:
            break;
    }
}

bool emv_term_profile_load(struct tlvdb *terminal, const char *profile_path) {
    if (profile_path && profile_path[0]) {
        return ParamLoadFromJsonFile(terminal, profile_path);
    }

    char *path = NULL;
    if (searchFile(&path, RESOURCES_SUBDIR, "emv_terminal_profile", ".json", false) == PM3_SUCCESS) {
        bool ok = ParamLoadFromJsonFile(terminal, path);
        free(path);
        return ok;
    }

    char *docpath = NULL;
    if (searchFile(&docpath, "docs/emv-terminal-emulator/examples", "emv_terminal_profile", ".json", false) == PM3_SUCCESS) {
        bool ok = ParamLoadFromJsonFile(terminal, docpath);
        free(docpath);
        return ok;
    }

    return false;
}

static bool profile_has_required_tags(json_t *root) {
    bool has_amount = false;
    bool has_country = false;
    bool has_currency = false;
    bool has_caps = false;

    for (size_t i = 0; i < json_array_size(root); i++) {
        json_t *data = json_array_get(root, i);
        if (!json_is_object(data)) {
            continue;
        }
        json_t *jtag = json_object_get(data, "tag");
        if (!json_is_string(jtag)) {
            continue;
        }
        const char *tag = json_string_value(jtag);
        if (strcmp(tag, "9F02") == 0) {
            has_amount = true;
        } else if (strcmp(tag, "9F1A") == 0) {
            has_country = true;
        } else if (strcmp(tag, "5F2A") == 0) {
            has_currency = true;
        } else if (strcmp(tag, "9F33") == 0) {
            has_caps = true;
        }
    }

    return has_amount && has_country && has_currency && has_caps;
}

int emv_term_profile_validate(const char *profile_path) {
    json_error_t error;
    const char *path = profile_path;

    if (!path || !path[0]) {
        char *found = NULL;
        if (searchFile(&found, RESOURCES_SUBDIR, "emv_terminal_profile", ".json", false) != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Terminal profile not found");
            return PM3_ESOFT;
        }
        path = found;
        int res = emv_term_profile_validate(path);
        free(found);
        return res;
    }

    json_t *root = json_load_file(path, 0, &error);
    if (!root) {
        PrintAndLogEx(ERR, "Profile json error line %d: %s", error.line, error.text);
        return PM3_ESOFT;
    }

    if (!json_is_array(root)) {
        PrintAndLogEx(ERR, "Profile root must be a JSON array");
        json_decref(root);
        return PM3_ESOFT;
    }

    if (!profile_has_required_tags(root)) {
        PrintAndLogEx(ERR, "Profile missing required tags (9F02, 9F1A, 5F2A, 9F33)");
        json_decref(root);
        return PM3_ESOFT;
    }

    json_decref(root);
    PrintAndLogEx(SUCCESS, "Profile valid: %s", path);
    return PM3_SUCCESS;
}

int emv_term_profile_print(const char *profile_path) {
    json_error_t error;
    const char *path = profile_path;

    if (!path || !path[0]) {
        char *found = NULL;
        if (searchFile(&found, RESOURCES_SUBDIR, "emv_terminal_profile", ".json", false) != PM3_SUCCESS) {
            if (searchFile(&found, "docs/emv-terminal-emulator/examples", "emv_terminal_profile", ".json", false) != PM3_SUCCESS) {
                PrintAndLogEx(ERR, "Terminal profile not found");
                return PM3_ESOFT;
            }
        }
        path = found;
        int res = emv_term_profile_print(path);
        free(found);
        return res;
    }

    json_t *root = json_load_file(path, 0, &error);
    if (!root) {
        PrintAndLogEx(ERR, "Profile json error line %d: %s", error.line, error.text);
        return PM3_ESOFT;
    }

    char *dump = json_dumps(root, JSON_INDENT(2));
    if (dump) {
        PrintAndLogEx(NORMAL, "%s", dump);
        free(dump);
    }
    json_decref(root);
    return PM3_SUCCESS;
}
