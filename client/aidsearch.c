//-----------------------------------------------------------------------------
// Copyright (C) 2019 merlokk
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Proxmark3 RDV40 AID list library
//-----------------------------------------------------------------------------
#include "aidsearch.h"
#include <ctype.h>
#include <string.h>
#include "fileutils.h"
#include "pm3_cmd.h"

int openAIDFile(json_t **root, bool verbose) {
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

    if (verbose) PrintAndLogEx(SUCCESS, "Loaded file (%s) OK. %zu records.", path, json_array_size(*root));
out:
    free(path);
    return retval;
}

int closeAIDFile(json_t *root) {

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

json_t *AIDSearchGetElm(json_t *root, int elmindx) {
    json_t *data = json_array_get(root, elmindx);
    if (!json_is_object(data)) {
        PrintAndLogEx(ERR, "data [%d] is not an object\n", elmindx);
        return NULL;
    }
    return data;
}

int AIDSearchFree(json_t *root) {

    return closeAIDFile(root);
}

const char *jsonStrGet(json_t *data, char *name) {
    json_t *jstr;

    jstr = json_object_get(data, name);
    if (jstr == NULL)
        return NULL;
    if (!json_is_string(jstr)) {
        PrintAndLogEx(ERR, "`%s` is not a string", name);
        return NULL;
    }

    const char *cstr = json_string_value(jstr);
    if (strlen(cstr) == 0)
        return NULL;
    return cstr;
}

bool aidCompare(const char *aidlarge, const char *aidsmall) {
    if (strcmp(aidlarge, aidsmall) == 0)
        return true;

    if (strlen(aidlarge) > strlen(aidsmall))
        if (strncmp(aidlarge, aidsmall, strlen(aidsmall)) == 0)
            return true;

    return false;
}

bool AIDGetFromElm(json_t *data, uint8_t *aid, size_t aidmaxlen, int *aidlen) {
    *aidlen = 0;
    const char *hexaid = jsonStrGet(data, "AID");
    if (hexaid == NULL || strlen(hexaid) == 0)
        return false;

    int res = param_gethex_to_eol(hexaid, 0, aid, aidmaxlen, aidlen);
    if (res)
        return false;

    return true;
}

int PrintAIDDescription(json_t *xroot, char *aid, bool verbose) {
    int retval = PM3_SUCCESS;

    json_t *root = xroot;
    if (root == NULL)
        root = AIDSearchInit(verbose);
    if (root == NULL)
        goto out;

    json_t *elm = NULL;
    int maxaidlen = 0;
    for (int elmindx = 0; elmindx < json_array_size(root); elmindx++) {
        json_t *data = AIDSearchGetElm(root, elmindx);
        if (data == NULL)
            continue;
        const char *dictaid = jsonStrGet(data, "AID");
        if (aidCompare(aid, dictaid)) {  // dictaid may be less length than requested aid
            if (maxaidlen < strlen(dictaid) && strlen(dictaid) <= strlen(aid)) {
                maxaidlen = strlen(dictaid);
                elm = data;
            }
        }
    }

    if (elm == NULL)
        goto out;

    // print here
    const char *vaid = jsonStrGet(elm, "AID");
    const char *vendor = jsonStrGet(elm, "Vendor");
    const char *name = jsonStrGet(elm, "Name");
    const char *country = jsonStrGet(elm, "Country");
    const char *description = jsonStrGet(elm, "Description");
    const char *type = jsonStrGet(elm, "Type");

    if (!verbose) {
        PrintAndLogEx(SUCCESS, "AID %s | %s | %s", vaid, vendor, name);
    } else {
        PrintAndLogEx(SUCCESS, "Input AID: %s", aid);
        if (aid)
            PrintAndLogEx(SUCCESS, "Found AID: %s", vaid);
        if (vendor)
            PrintAndLogEx(SUCCESS, "Vendor: %s", vendor);
        if (type)
            PrintAndLogEx(SUCCESS, "Type: %s", type);
        if (name)
            PrintAndLogEx(SUCCESS, "Name: %s", name);
        if (country)
            PrintAndLogEx(SUCCESS, "Country: %s", country);
        if (description)
            PrintAndLogEx(SUCCESS, "Description: %s", description);
    }

out:
    if (xroot == NULL)
        AIDSearchFree(root);
    return retval;
}

int PrintAIDDescriptionBuf(json_t *root, uint8_t *aid, size_t aidlen, bool verbose) {
    return PrintAIDDescription(root, sprint_hex_inrow(aid, aidlen), verbose);
}

