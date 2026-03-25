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
// Proxmark3 RDV40 AID list library
//-----------------------------------------------------------------------------
#include "aidsearch.h"
#include <ctype.h>
#include <string.h>
#include "fileutils.h"
#include "pm3_cmd.h"
#include "util.h"

static int openAIDFile(json_t **root, bool verbose) {
    json_error_t error;

    char *path;
    int res = searchFile(&path, RESOURCES_SUBDIR, "aidlist", ".json", false);
    if (res != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    int retval = PM3_SUCCESS;
    *root = json_load_file(path, 0, &error);
    if (!*root) {
        PrintAndLogEx(ERR, "json (%s) error on line %d: %s", path, error.line, error.text);
        retval = PM3_ESOFT;
        goto out;
    }

    if (!json_is_array(*root)) {
        PrintAndLogEx(ERR, "Invalid json (%s) format. root must be an array.", path);
        retval = PM3_ESOFT;
        goto out;
    }

    PrintAndLogEx(DEBUG, "Loaded file " _YELLOW_("%s") " " _GREEN_("%zu") " records ( " _GREEN_("ok") " )"
                  , path
                  , json_array_size(*root)
                 );
out:
    free(path);
    return retval;
}

static int closeAIDFile(json_t *root) {
    json_decref(root);
    return PM3_SUCCESS;
}

json_t *AIDSearchInit(bool verbose) {
    json_t *root = NULL;
    int res = openAIDFile(&root, verbose);
    if (res != PM3_SUCCESS)
        return NULL;

    return root;
}

json_t *AIDSearchGetElm(json_t *root, size_t elmindx) {
    json_t *data = json_array_get(root, elmindx);
    if (!json_is_object(data)) {
        PrintAndLogEx(ERR, "data [%zu] is not an object\n", elmindx);
        return NULL;
    }
    return data;
}

int AIDSearchFree(json_t *root) {
    return closeAIDFile(root);
}

static const char *jsonStrGet(json_t *data, const char *name) {
    json_t *jstr;

    jstr = json_object_get(data, name);
    if (jstr == NULL) {
        return NULL;
    }

    if (!json_is_string(jstr)) {
        PrintAndLogEx(ERR, "`%s` is not a string", name);
        return NULL;
    }

    const char *cstr = json_string_value(jstr);
    if (strlen(cstr) == 0) {
        return NULL;
    }
    return cstr;
}

static bool aidCompare(const char *aidlarge, const char *aidsmall) {
    if (strcmp(aidlarge, aidsmall) == 0)
        return true;

    if (strlen(aidlarge) > strlen(aidsmall))
        if (strncmp(aidlarge, aidsmall, strlen(aidsmall)) == 0)
            return true;

    return false;
}

static bool ResponseContainsMatch(const char *needle, const char *text) {
    if (needle == NULL || text == NULL || needle[0] == '\0' || text[0] == '\0') {
        return false;
    }

    char *needle_lc = str_dup(needle);
    char *text_lc = str_dup(text);
    if (needle_lc == NULL || text_lc == NULL) {
        free(needle_lc);
        free(text_lc);
        return false;
    }

    str_lower(needle_lc);
    str_lower(text_lc);
    bool matched = (strstr(text_lc, needle_lc) != NULL);
    free(needle_lc);
    free(text_lc);
    return matched;
}

bool AIDGetFromElm(json_t *data, uint8_t *aid, size_t aidmaxlen, int *aidlen) {
    *aidlen = 0;
    const char *hexaid = jsonStrGet(data, "AID");
    if (hexaid == NULL || strlen(hexaid) == 0)
        return false;

    int res = param_gethex_to_eol(hexaid, 0, aid, (int)aidmaxlen, aidlen);
    if (res)
        return false;

    return true;
}

bool AIDSeenBefore(json_t *root, const uint8_t *aid, size_t aidlen, size_t before_index) {
    if (root == NULL || aid == NULL || aidlen == 0) {
        return false;
    }

    size_t limit = before_index;
    if (limit > json_array_size(root)) {
        limit = json_array_size(root);
    }

    for (size_t i = 0; i < limit; i++) {
        json_t *data = AIDSearchGetElm(root, i);
        if (data == NULL) {
            continue;
        }

        uint8_t prev_aid[200] = {0};
        int prev_aid_len = 0;
        if ((AIDGetFromElm(data, prev_aid, sizeof(prev_aid), &prev_aid_len) == false) || (prev_aid_len <= 0)) {
            continue;
        }

        if ((size_t)prev_aid_len == aidlen && memcmp(prev_aid, aid, aidlen) == 0) {
            return true;
        }
    }

    return false;
}

int PrintAIDDescription(json_t *xroot, char *aid, bool verbose) {
    return PrintAIDDescriptionEx(xroot, aid, NULL, 0, verbose);
}

int PrintAIDDescriptionBuf(json_t *root, uint8_t *aid, size_t aidlen, bool verbose) {
    return PrintAIDDescription(root, sprint_hex_inrow(aid, aidlen), verbose);
}

int PrintAIDDescriptionEx(json_t *xroot, char *aid, const uint8_t *response, size_t response_len, bool verbose) {
    if (aid == NULL || aid[0] == '\0') {
        return PM3_SUCCESS;
    }

    int retval = PM3_SUCCESS;

    json_t *root = xroot;
    if (root == NULL) {
        root = AIDSearchInit(verbose);
    }
    if (root == NULL) {
        goto out;
    }

    char *response_hex = NULL;
    if (response != NULL && response_len > 0) {
        if (response_len > ((SIZE_MAX - 1) / 2)) {
            goto out;
        }
        size_t response_hexlen = (response_len * 2) + 1;
        response_hex = calloc(response_hexlen, sizeof(char));
        if (response_hex == NULL) {
            goto out;
        }
        hex_to_buffer((uint8_t *)response_hex, response, response_len, response_hexlen - 1, 0, 0, true);
    }

    json_t *fallback_elm = NULL;
    json_t *contains_elm = NULL;
    size_t maxaidlen = 0;

    for (size_t elmindx = 0; elmindx < json_array_size(root); elmindx++) {
        json_t *data = AIDSearchGetElm(root, elmindx);
        if (data == NULL) {
            continue;
        }

        const char *dictaid = jsonStrGet(data, "AID");
        if (dictaid == NULL) {
            continue;
        }

        if (!aidCompare(aid, dictaid)) {  // dictaid may be less length than requested aid
            continue;
        }

        size_t dictaidlen = strlen(dictaid);
        if (dictaidlen > strlen(aid)) {
            continue;
        }

        if (dictaidlen > maxaidlen) {
            maxaidlen = dictaidlen;
            fallback_elm = data;
            contains_elm = NULL;
        } else if (dictaidlen < maxaidlen) {
            continue;
        }

        if (response_hex != NULL) {
            const char *response_contains = jsonStrGet(data, "ResponseContains");
            if (response_contains && ResponseContainsMatch(response_contains, response_hex)) {
                contains_elm = data;
            }
        }
    }

    json_t *elm = contains_elm ? contains_elm : fallback_elm;
    if (elm != NULL) {
        const char *vaid = jsonStrGet(elm, "AID");
        const char *vendor = jsonStrGet(elm, "Vendor");
        const char *name = jsonStrGet(elm, "Name");
        const char *country = jsonStrGet(elm, "Country");
        const char *description = jsonStrGet(elm, "Description");
        const char *type = jsonStrGet(elm, "Type");

        if (verbose == false) {
            PrintAndLogEx(SUCCESS, "AID : " _YELLOW_("%s") " | %s | %s", vaid, vendor, name);
        } else {
            PrintAndLogEx(SUCCESS, "Input AID..... " _YELLOW_("%s"), aid);
            if (aid)
                PrintAndLogEx(SUCCESS, "Found AID..... " _YELLOW_("%s"), vaid);
            if (vendor)
                PrintAndLogEx(SUCCESS, "Vendor........ " _YELLOW_("%s"), vendor);
            if (type)
                PrintAndLogEx(SUCCESS, "Type.......... " _YELLOW_("%s"), type);
            if (name)
                PrintAndLogEx(SUCCESS, "Name.......... " _YELLOW_("%s"), name);
            if (country)
                PrintAndLogEx(SUCCESS, "Country....... %s", country);
            if (description)
                PrintAndLogEx(SUCCESS, "Description... %s", description);
        }
    }

    if (response_hex != NULL) {
        free(response_hex);
    }

out:
    if (xroot == NULL) {
        AIDSearchFree(root);
    }
    return retval;
}
