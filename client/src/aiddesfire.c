//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// AID DESFire functions
//-----------------------------------------------------------------------------

#include "aiddesfire.h"
#include "pm3_cmd.h"
#include "fileutils.h"
#include "jansson.h"

static json_t *df_known_aids = NULL;

static int open_aiddf_file(json_t **root, bool verbose) {

    char *path;
    int res = searchFile(&path, RESOURCES_SUBDIR, "aid_desfire", ".json", true);
    if (res != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    int retval = PM3_SUCCESS;
    json_error_t error;

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

    if (verbose)
        PrintAndLogEx(SUCCESS, "Loaded file " _YELLOW_("`%s`") " (%s) %zu records.", path,  _GREEN_("ok"), json_array_size(*root));
out:
    free(path);
    return retval;
}

static int close_aiddf_file(json_t *root) {
    json_decref(root);
    return PM3_SUCCESS;
}

static const char *aiddf_json_get_str(json_t *data, const char *name) {

    json_t *jstr = json_object_get(data, name);
    if (jstr == NULL)
        return NULL;

    if (!json_is_string(jstr)) {
        PrintAndLogEx(WARNING, _YELLOW_("`%s`") " is not a string", name);
        return NULL;
    }

    const char *cstr = json_string_value(jstr);
    if (strlen(cstr) == 0)
        return NULL;

    return cstr;
}

static int print_aiddf_description(json_t *root, uint8_t aid[3], char *fmt, bool verbose) {
    char laid[7] = {0};
    sprintf(laid, "%02x%02x%02x", aid[2], aid[1], aid[0]); // must be lowercase

    json_t *elm = NULL;

    for (uint32_t idx = 0; idx < json_array_size(root); idx++) {
        json_t *data = json_array_get(root, idx);
        if (!json_is_object(data)) {
            PrintAndLogEx(ERR, "data [%d] is not an object\n", idx);
            continue;
        }
        const char *faid = aiddf_json_get_str(data, "AID");
        char lfaid[strlen(faid) + 1];
        strcpy(lfaid, faid);
        str_lower(lfaid);
        if (strcmp(laid, lfaid) == 0) {
            elm = data;
            break;
        }
    }

    if (elm == NULL) {
        PrintAndLogEx(INFO, fmt, " (unknown)");
        return PM3_ENODATA;
    }
    const char *vaid = aiddf_json_get_str(elm, "AID");
    const char *vendor = aiddf_json_get_str(elm, "Vendor");
    const char *country = aiddf_json_get_str(elm, "Country");
    const char *name = aiddf_json_get_str(elm, "Name");
    const char *description = aiddf_json_get_str(elm, "Description");
    const char *type = aiddf_json_get_str(elm, "Type");

    if (name && vendor) {
        char result[4 + strlen(name) + strlen(vendor)];
        sprintf(result, " %s [%s]", name, vendor);
        PrintAndLogEx(INFO, fmt, result);
    }

    if (verbose) {
        PrintAndLogEx(SUCCESS, "    AID:               %s", vaid);
        if (name)
            PrintAndLogEx(SUCCESS, "    Name:              %s", name);
        if (description)
            PrintAndLogEx(SUCCESS, "    Description:       %s", description);
        if (type)
            PrintAndLogEx(SUCCESS, "    Type:              %s", type);
        if (vendor)
            PrintAndLogEx(SUCCESS, "    Vendor:            %s", vendor);
        if (country)
            PrintAndLogEx(SUCCESS, "    Country:           %s", country);
    }
    return PM3_SUCCESS;
}

int AIDDFDecodeAndPrint(uint8_t aid[3]) {
    open_aiddf_file(&df_known_aids, false);

    char fmt[50];
    sprintf(fmt, "  DF AID Function %02X%02X%02X     :" _YELLOW_("%s"), aid[2], aid[1], aid[0], "%s");
    print_aiddf_description(df_known_aids, aid, fmt, false);
    close_aiddf_file(df_known_aids);
    return PM3_SUCCESS;
}
