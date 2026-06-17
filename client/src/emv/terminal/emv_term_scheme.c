//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "emv_term_scheme.h"
#include "emv_term_tlv.h"
#include "emv_term_profile.h"
#include "../emvjson.h"
#include "fileutils.h"
#include "ui.h"
#include <jansson.h>
#include <string.h>

static bool aid_starts_with(const uint8_t *aid, size_t aid_len, const char *prefix_hex) {
    uint8_t buf[APDU_AID_LEN] = {0};
    int len = 0;
    if (param_gethex_to_eol(prefix_hex, 0, buf, sizeof(buf), &len)) {
        return false;
    }
    if ((size_t)len > aid_len) {
        return false;
    }
    return memcmp(aid, buf, (size_t)len) == 0;
}

const char *emv_term_scheme_name_for_aid(const uint8_t *aid, size_t aid_len) {
    if (!aid || !aid_len) {
        return NULL;
    }
    if (aid_starts_with(aid, aid_len, "A000000277")) {
        return "interac";
    }
    if (aid_starts_with(aid, aid_len, "A000000003") || aid_starts_with(aid, aid_len, "A000000004")) {
        if (aid_len >= 7 && aid[6] == 0x30) {
            return "mc";
        }
        return "visa";
    }
    if (aid_starts_with(aid, aid_len, "A000000004")) {
        return "mc";
    }
    if (aid_starts_with(aid, aid_len, "A000000005")) {
        return "mc";
    }
    return NULL;
}

static int load_scheme_index(const char *scheme, emv_term_scheme_info_t *info) {
    json_error_t error;
    char *index_path = NULL;
    if (searchFile(&index_path, RESOURCES_SUBDIR, "scheme_profiles/index", ".json", false) != PM3_SUCCESS) {
        if (searchFile(&index_path, "docs/emv-terminal-emulator/examples", "scheme_profiles/index", ".json", false) != PM3_SUCCESS) {
            return PM3_ESOFT;
        }
    }

    json_t *root = json_load_file(index_path, 0, &error);
    free(index_path);
    if (!root) {
        return PM3_ESOFT;
    }

    json_t *entry = json_object_get(root, scheme);
    if (!json_is_object(entry)) {
        json_decref(root);
        return PM3_ESOFT;
    }

    json_t *prof = json_object_get(entry, "profile");
    json_t *keys = json_object_get(entry, "host_keys");
    json_t *flash = json_object_get(entry, "flash_skip_offline_pin");

    if (json_is_string(prof)) {
        str_copy(info->profile_path, sizeof(info->profile_path), json_string_value(prof));
    }
    if (json_is_string(keys)) {
        str_copy(info->host_keys_path, sizeof(info->host_keys_path), json_string_value(keys));
    }
    if (json_is_boolean(flash)) {
        info->flash_skip_offline_pin = json_is_true(flash);
    }

    json_decref(root);
    return PM3_SUCCESS;
}

static int resolve_profile_file(const char *scheme, char *out, size_t outlen) {
    char base[64];
    snprintf(base, sizeof(base), "scheme_profiles/%s", scheme);
    char *path = NULL;
    if (searchFile(&path, RESOURCES_SUBDIR, base, ".json", false) == PM3_SUCCESS) {
        str_copy(out, outlen, path);
        free(path);
        return PM3_SUCCESS;
    }
    snprintf(base, sizeof(base), "scheme_profiles/%s", scheme);
    if (searchFile(&path, "docs/emv-terminal-emulator/examples", base, ".json", false) == PM3_SUCCESS) {
        str_copy(out, outlen, path);
        free(path);
        return PM3_SUCCESS;
    }
    return PM3_ESOFT;
}

int emv_term_scheme_resolve(const char *profile_arg, const uint8_t *aid, size_t aid_len,
                            emv_term_scheme_info_t *info) {
    if (!info) {
        return PM3_EINVARG;
    }
    memset(info, 0, sizeof(*info));

    const char *scheme = profile_arg;
    if (!scheme || !scheme[0] || strcmp(scheme, "default") == 0) {
        return PM3_SUCCESS;
    }

    if (strcmp(scheme, "auto") == 0) {
        scheme = emv_term_scheme_name_for_aid(aid, aid_len);
        if (!scheme) {
            PrintAndLogEx(WARNING, "Could not auto-detect scheme from AID");
            return PM3_ESOFT;
        }
        PrintAndLogEx(INFO, "Scheme auto-detect: %s", scheme);
    }

    str_copy(info->name, sizeof(info->name), scheme);

    if (load_scheme_index(scheme, info) != PM3_SUCCESS) {
        if (resolve_profile_file(scheme, info->profile_path, sizeof(info->profile_path)) != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Scheme profile not found: %s", scheme);
            return PM3_ESOFT;
        }
    }

    if (!info->profile_path[0]) {
        resolve_profile_file(scheme, info->profile_path, sizeof(info->profile_path));
    }

    if (!info->host_keys_path[0]) {
        if (strcmp(scheme, "interac") == 0) {
            char *hk = NULL;
            if (searchFile(&hk, "docs/emv-terminal-emulator/examples", "host_sim_interac", ".json", false) == PM3_SUCCESS ||
                searchFile(&hk, "docs/emv-terminal-emulator/examples", "interac_test_keys", ".json", false) == PM3_SUCCESS) {
                str_copy(info->host_keys_path, sizeof(info->host_keys_path), hk);
                free(hk);
            }
        }
    }

    return PM3_SUCCESS;
}

int emv_term_scheme_apply(emv_term_ctx_t *ctx, const emv_term_scheme_info_t *info) {
    if (!ctx || !info || !info->name[0]) {
        return PM3_SUCCESS;
    }

    str_copy(ctx->scheme_name, sizeof(ctx->scheme_name), info->name);
    ctx->flash_skip_offline_pin = info->flash_skip_offline_pin;
    if (info->host_keys_path[0]) {
        str_copy(ctx->host_keys_path, sizeof(ctx->host_keys_path), info->host_keys_path);
    }

    if (info->profile_path[0]) {
        PrintAndLogEx(INFO, "Loading scheme profile: %s (%s)", info->name, info->profile_path);
        if (!ParamLoadFromJsonFile(ctx->terminal, info->profile_path)) {
            PrintAndLogEx(WARNING, "Scheme profile load failed: %s", info->profile_path);
            return PM3_ESOFT;
        }
        emv_term_copy_terminal_tags_to_card(ctx);
    }

    PrintAndLogEx(INFO, "Kernel: %s (%s)", info->name,
                  ctx->channel == CC_CONTACTLESS ? "contactless" : "contact");
    return PM3_SUCCESS;
}
