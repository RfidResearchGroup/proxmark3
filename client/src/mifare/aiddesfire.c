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
// AID DESFire functions
//-----------------------------------------------------------------------------

#include "aiddesfire.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pm3_cmd.h"
#include "fileutils.h"
#include "jansson.h"

// NXP Appnote AN10787 - Application Directory (MAD)
typedef enum {
    CL_ADMIN = 0,
    CL_MISC1,
    CL_MISC2,
    CL_MISC3,
    CL_MISC4,
    CL_MISC5,
    CL_MISC6,
    CL_MISC7,
    CL_AIRLINES = 8,
    CL_FERRY,
    CL_RAIL,
    CL_MISC,
    CL_TRANSPORT,
    CL_SECURITY = 0x14,
    CL_CITYTRAFFIC = 0x18,
    CL_CZECH_RAIL,
    CL_BUS,
    CL_MMT,
    CL_TAXI = 0x28,
    CL_TOLL = 0x30,
    CL_GENERIC_TRANS,
    CL_COMPANY_SERVICES = 0x38,
    CL_CITYCARD = 0x40,
    CL_ACCESS_CONTROL_1 = 0x47,
    CL_ACCESS_CONTROL_2,
    CL_VIGIK = 0x49,
    CL_NED_DEFENCE = 0x4A,
    CL_BOSCH_TELECOM = 0x4B,
    CL_EU = 0x4C,
    CL_SKI_TICKET = 0x50,
    CL_SOAA = 0x55,
    CL_ACCESS2 = 0x56,
    CL_FOOD = 0x60,
    CL_NONFOOD = 0x68,
    CL_HOTEL = 0x70,
    CL_LOYALTY = 0x71,
    CL_AIRPORT = 0x75,
    CL_CAR_RENTAL = 0x78,
    CL_NED_GOV = 0x79,
    CL_ADMIN2 = 0x80,
    CL_PURSE = 0x88,
    CL_TV = 0x90,
    CL_CRUISESHIP = 0x91,
    CL_IOPTA = 0x95,
    CL_METERING = 0x97,
    CL_TELEPHONE = 0x98,
    CL_HEALTH = 0xA0,
    CL_WAREHOUSE = 0xA8,
    CL_BANKING = 0xB8,
    CL_ENTERTAIN = 0xC0,
    CL_PARKING = 0xC8,
    CL_FLEET = 0xC9,
    CL_FUEL = 0xD0,
    CL_INFO = 0xD8,
    CL_PRESS = 0xE0,
    CL_NFC = 0xE1,
    CL_COMPUTER = 0xE8,
    CL_MAIL = 0xF0,
    CL_AMISC = 0xF8,
    CL_AMISC1 = 0xF9,
    CL_AMISC2 = 0xFA,
    CL_AMISC3 = 0xFB,
    CL_AMISC4 = 0xFC,
    CL_AMISC5 = 0xFD,
    CL_AMISC6 = 0xFE,
    CL_AMISC7 = 0xFF,
} aidcluster_h;

const char *nxp_cluster_to_text(uint8_t cluster) {
    switch (cluster) {
        case CL_ADMIN:
            return "Card administration";
        case CL_MISC1:
        case CL_MISC2:
        case CL_MISC3:
        case CL_MISC4:
        case CL_MISC5:
        case CL_MISC6:
        case CL_MISC7:
            return "Miscellaneous applications";
        case CL_AIRLINES:
            return "Airlines";
        case CL_FERRY:
            return "Ferry traffic";
        case CL_RAIL:
            return "Railway services";
        case CL_MISC:
            return "Miscellaneous applications";
        case CL_TRANSPORT:
            return "Transport";
        case CL_SECURITY:
            return "Security solutions";
        case CL_CITYTRAFFIC:
            return "City traffic";
        case CL_CZECH_RAIL:
            return "Czech Railways";
        case CL_BUS:
            return "Bus services";
        case CL_MMT:
            return "Multi modal transit";
        case CL_TAXI:
            return "Taxi";
        case CL_TOLL:
            return "Road toll";
        case CL_GENERIC_TRANS:
            return "Generic transport";
        case CL_COMPANY_SERVICES:
            return "Company services";
        case CL_CITYCARD:
            return "City card services";
        case CL_ACCESS_CONTROL_1:
        case CL_ACCESS_CONTROL_2:
            return "Access control & security";
        case CL_VIGIK:
            return "VIGIK";
        case CL_NED_DEFENCE:
            return "Ministry of Defence, Netherlands";
        case CL_BOSCH_TELECOM:
            return "Bosch Telecom, Germany";
        case CL_EU:
            return "European Union Institutions";
        case CL_SKI_TICKET:
            return "Ski ticketing";
        case CL_SOAA:
            return "SOAA standard for offline access standard";
        case CL_ACCESS2:
            return "Access control & security";
        case CL_FOOD:
            return "Food";
        case CL_NONFOOD:
            return "Non-food trade";
        case CL_HOTEL:
            return "Hotel";
        case CL_LOYALTY:
            return "Loyalty";
        case CL_AIRPORT:
            return "Airport services";
        case CL_CAR_RENTAL:
            return "Car rental";
        case CL_NED_GOV:
            return "Dutch government";
        case CL_ADMIN2:
            return "Administration services";
        case CL_PURSE:
            return "Electronic purse";
        case CL_TV:
            return "Television";
        case CL_CRUISESHIP:
            return "Cruise ship";
        case CL_IOPTA:
            return "IOPTA";
        case CL_METERING:
            return "Metering";
        case CL_TELEPHONE:
            return "Telephone";
        case CL_HEALTH:
            return "Health services";
        case CL_WAREHOUSE:
            return "Warehouse";
        case CL_BANKING:
            return "Banking";
        case CL_ENTERTAIN:
            return "Entertainment & sports";
        case CL_PARKING:
            return "Car parking";
        case CL_FLEET:
            return "Fleet management";
        case CL_FUEL:
            return "Fuel, gasoline";
        case CL_INFO:
            return "Info services";
        case CL_PRESS:
            return "Press";
        case CL_NFC:
            return "NFC Forum";
        case CL_COMPUTER:
            return "Computer";
        case CL_MAIL:
            return "Mail";
        case CL_AMISC:
        case CL_AMISC1:
        case CL_AMISC2:
        case CL_AMISC3:
        case CL_AMISC4:
        case CL_AMISC5:
        case CL_AMISC6:
        case CL_AMISC7:
            return "Miscellaneous applications";
        default:
            break;
    }
    return "Reserved";
}

static json_t *df_known_aids = NULL;
static bool df_known_aids_load_tried = false;

static int open_aiddf_file(json_t **root, bool verbose) {

    char *path;
    int res = searchFile(&path, RESOURCES_SUBDIR, "aid_desfire", ".json", true);
    if (res != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    int retval = PM3_SUCCESS;
    json_error_t error;

    *root = NULL;
    *root = json_load_file(path, 0, &error);
    if (!*root) {
        PrintAndLogEx(ERR, "json (%s) error on line %d: %s", path, error.line, error.text);
        retval = PM3_ESOFT;
        goto out;
    }

    if (!json_is_array(*root)) {
        PrintAndLogEx(ERR, "Invalid json (%s) format. root must be an array.", path);
        json_decref(*root);
        *root = NULL;
        retval = PM3_ESOFT;
        goto out;
    }

    if (verbose) {
        PrintAndLogEx(SUCCESS, "Loaded file `" _YELLOW_("%s") "` " _GREEN_("%zu") " records ( " _GREEN_("ok") " )"
                      , path
                      , json_array_size(*root)
                     );
    }

out:
    free(path);
    return retval;
}

static int ensure_aiddf_file_loaded(void) {
    if (df_known_aids != NULL) {
        return PM3_SUCCESS;
    }

    if (df_known_aids_load_tried) {
        return PM3_EFILE;
    }

    df_known_aids_load_tried = true;
    return open_aiddf_file(&df_known_aids, false);
}

static const char *aiddf_json_get_str_ex(json_t *data, const char *name, bool verbose) {

    json_t *jstr = json_object_get(data, name);
    if (jstr == NULL)
        return NULL;

    if (!json_is_string(jstr)) {
        if (verbose)
            PrintAndLogEx(WARNING, _YELLOW_("`%s`") " is not a string", name);
        return NULL;
    }

    const char *cstr = json_string_value(jstr);
    if (strlen(cstr) == 0)
        return NULL;

    return cstr;
}

static const char *aiddf_json_get_str(json_t *data, const char *name) {
    return aiddf_json_get_str_ex(data, name, true);
}

static const char *aiddf_json_get_str_quiet(json_t *data, const char *name) {
    return aiddf_json_get_str_ex(data, name, false);
}

static bool aiddf_parse_aid_str(const char *aid_str, uint32_t *aid) {
    if (aid_str == NULL || aid == NULL || strlen(aid_str) != 6) {
        return false;
    }

    for (int c = 0; c < 6; c++) {
        if (isxdigit((uint8_t)aid_str[c]) == 0) {
            return false;
        }
    }

    char *end = NULL;
    unsigned long parsed_aid = strtoul(aid_str, &end, 16);
    if (end == NULL || *end != '\0' || parsed_aid > 0xFFFFFFUL) {
        return false;
    }

    *aid = (uint32_t)parsed_aid;
    return true;
}

static json_t *find_aiddf_entry(json_t *root, uint32_t aid) {
    if (json_is_array(root) == false) {
        return NULL;
    }

    for (uint32_t idx = 0; idx < json_array_size(root); idx++) {
        json_t *data = json_array_get(root, idx);
        if (!json_is_object(data)) {
            continue;
        }

        uint32_t db_aid = 0;
        if (aiddf_parse_aid_str(aiddf_json_get_str_quiet(data, "AID"), &db_aid) == false) {
            continue;
        }

        if (db_aid == aid) {
            return data;
        }
    }

    return NULL;
}

static int print_aiddf_description(json_t *root, uint8_t aid[3], char *fmt, bool verbose) {
    uint32_t aid_num = aid[0] | ((uint32_t)aid[1] << 8) | ((uint32_t)aid[2] << 16);
    json_t *elm = find_aiddf_entry(root, aid_num);

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
        size_t result_len = 5 + strlen(name) + strlen(vendor);
        char result[result_len];
        snprintf(result, result_len, " %s [%s]", name, vendor);
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

const char *AIDDFGetCommentStr(uint32_t aid) {
    static char result[256] = {0};
    result[0] = '\0';

    if (ensure_aiddf_file_loaded() != PM3_SUCCESS) {
        return "";
    }

    json_t *elm = find_aiddf_entry(df_known_aids, aid);
    if (elm == NULL) {
        return "";
    }

    const char *name = aiddf_json_get_str_quiet(elm, "Name");
    const char *vendor = aiddf_json_get_str_quiet(elm, "Vendor");
    const char *description = aiddf_json_get_str_quiet(elm, "Description");

    if (name && vendor) {
        snprintf(result, sizeof(result), "%s [%s]", name, vendor);
    } else if (name) {
        snprintf(result, sizeof(result), "%s", name);
    } else if (description) {
        snprintf(result, sizeof(result), "%s", description);
    }

    return result;
}

int AIDDFDecodeAndPrint(uint8_t aid[3]) {
    if (ensure_aiddf_file_loaded() != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    char fmt[80];
    snprintf(fmt, sizeof(fmt), "  DF AID Function... %02X%02X%02X  :" _YELLOW_("%s"), aid[2], aid[1], aid[0], "%s");
    print_aiddf_description(df_known_aids, aid, fmt, false);
    return PM3_SUCCESS;
}
