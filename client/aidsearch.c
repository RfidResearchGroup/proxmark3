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


int openAIDFile(json_t *root) {
    json_error_t error;

    char *path;
    int res = searchFile(&path, RESOURCES_SUBDIR, "aidlist", ".json", false);
    if (res != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    int retval = PM3_SUCCESS;
    root = json_load_file(path, 0, &error);
    if (!root) {
        PrintAndLogEx(ERR, "json (%s) error on line %d: %s", path, error.line, error.text);
        retval = PM3_ESOFT;
        goto out;
    }

    if (!json_is_array(root)) {
        PrintAndLogEx(ERR, "Invalid json (%s) format. root must be an array.", path);
        retval = PM3_ESOFT;
        goto out;
    }

    PrintAndLogEx(SUCCESS, "Loaded file (%s) OK.", path);
out:
    free(path);
    return retval;
}

int closeAIDFile(json_t *root) {

    json_decref(root);
    return PM3_SUCCESS;
}

json_t *AIDSearchInit(json_t *root) {
    int res = openAIDFile(root);
    if (res != PM3_SUCCESS)
        return NULL;

    return AIDSearchGetElm(root, 0);
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

const char * jsonStrGet(json_t *data, char *name) {
    json_t *jstr;
    
    jstr = json_object_get(data, name);
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

int PrintAIDDescription(char *aid, bool verbose) {
    json_t *root = NULL;
    int retval = PM3_SUCCESS;
    
    int elmindx = 0;
    json_t *data = AIDSearchInit(root);
    if (data == NULL)
        goto out;
        
    while (aidCompare(jsonStrGet(data, "AID"), aid)) {
        elmindx++;
        if (elmindx > json_array_size(root))
            goto out;
        data = AIDSearchGetElm(root, elmindx);
        
        if (data == NULL)
            goto out;
    }
    
    // print here
    const char *vaid = jsonStrGet(data, "AID");
    const char *vendor = jsonStrGet(data, "Vendor");
    const char *name = jsonStrGet(data, "Name");
    const char *country = jsonStrGet(data, "Country");
    const char *description = jsonStrGet(data, "Description");
    const char *type = jsonStrGet(data, "Type");

    if (!verbose) {
        PrintAndLogEx(SUCCESS, "AID %s | %s | %s", vaid, vendor, name);
    } else {
        if (aid)
            PrintAndLogEx(SUCCESS, "AID: %s\n", vaid);
        if (vendor)
            PrintAndLogEx(SUCCESS, "Vendor: %s\n", vendor);
        if (type)
            PrintAndLogEx(SUCCESS, "Type: %s\n", type);
        if (name)
            PrintAndLogEx(SUCCESS, "Name: %s\n", name);
        if (country)
            PrintAndLogEx(SUCCESS, "Country: %s\n", country);
        if (description)
            PrintAndLogEx(SUCCESS, "Description: %s\n", description);
    }
        
out:
    AIDSearchFree(root);
    return retval;
}


