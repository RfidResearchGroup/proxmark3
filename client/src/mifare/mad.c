//-----------------------------------------------------------------------------
// Copyright (C) 2019 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// MIFARE Application Directory (MAD) functions
//-----------------------------------------------------------------------------

#include "mad.h"
#include "ui.h"
#include "commonutil.h"  // ARRAYLEN
#include "pm3_cmd.h"
#include "crc.h"
#include "util.h"
#include "fileutils.h"
#include "jansson.h"

// https://www.nxp.com/docs/en/application-note/AN10787.pdf
static json_t *mad_known_aids = NULL;

static const char *holder_info_type[] = {
    "Surname",
    "Given name",
    "Sex",
    "Other"
};

static const char *aid_admin[] = {
    "free",
    "defect",
    "reserved",
    "additional directory info",
    "card holder info",
    "not applicable"
};

static int open_mad_file(json_t **root, bool verbose) {

    char *path;
    int res = searchFile(&path, RESOURCES_SUBDIR, "mad", ".json", true);
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

static int close_mad_file(json_t *root) {
    json_decref(root);
    return PM3_SUCCESS;
}

static const char *mad_json_get_str(json_t *data, const char *name) {

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

static int print_aid_description(json_t *root, uint16_t aid, char *fmt, bool verbose) {
    char lmad[7] = {0};
    sprintf(lmad, "0x%04x", aid); // must be lowercase

    json_t *elm = NULL;

    for (uint32_t idx = 0; idx < json_array_size(root); idx++) {
        json_t *data = json_array_get(root, idx);
        if (!json_is_object(data)) {
            PrintAndLogEx(ERR, "data [%d] is not an object\n", idx);
            continue;
        }
        const char *fmad = mad_json_get_str(data, "mad");
        char lfmad[strlen(fmad) + 1];
        strcpy(lfmad, fmad);
        str_lower(lfmad);
        if (strcmp(lmad, lfmad) == 0) {
            elm = data;
            break;
        }
    }

    if (elm == NULL) {
        PrintAndLogEx(INFO, fmt, " (unknown)");
        return PM3_ENODATA;
    }
    const char *vmad = mad_json_get_str(elm, "mad");
    const char *application = mad_json_get_str(elm, "application");
    const char *company = mad_json_get_str(elm, "company");
    const char *provider = mad_json_get_str(elm, "service_provider");
    const char *integrator = mad_json_get_str(elm, "system_integrator");

    if (application && company) {
        char result[4 + strlen(application) + strlen(company)];
        sprintf(result, " %s [%s]", application, company);
        PrintAndLogEx(INFO, fmt, result);
    }

    if (verbose) {
        PrintAndLogEx(SUCCESS, "    MAD:               %s", vmad);
        if (application)
            PrintAndLogEx(SUCCESS, "    Application:       %s", application);
        if (company)
            PrintAndLogEx(SUCCESS, "    Company:           %s", company);
        if (provider)
            PrintAndLogEx(SUCCESS, "    Service provider:  %s", provider);
        if (integrator)
            PrintAndLogEx(SUCCESS, "    System integrator: %s", integrator);
    }
    return PM3_SUCCESS;
}

static int madCRCCheck(uint8_t *sector, bool verbose, int MADver) {
    if (MADver == 1) {
        uint8_t crc = CRC8Mad(&sector[16 + 1], 15 + 16);
        if (crc != sector[16]) {
            PrintAndLogEx(WARNING, _RED_("Wrong MAD %d CRC") " calculated: 0x%02x != 0x%02x", MADver, crc, sector[16]);
            return PM3_ESOFT;
        };
    } else {
        uint8_t crc = CRC8Mad(&sector[1], 15 + 16 + 16);
        if (crc != sector[0]) {
            PrintAndLogEx(WARNING,  _RED_("Wrong MAD %d CRC") " calculated: 0x%02x != 0x%02x", MADver, crc, sector[0]);
            return PM3_ESOFT;
        };
    }
    return PM3_SUCCESS;
}

static uint16_t madGetAID(uint8_t *sector, bool swapmad, int MADver, int sectorNo) {
    uint16_t mad;
    if (MADver == 1)
        mad = (sector[16 + 2 + (sectorNo - 1) * 2 + 1] << 8) + (sector[16 + 2 + (sectorNo - 1) * 2]);
    else
        mad = (sector[2 + (sectorNo - 1) * 2 + 1] << 8) + (sector[2 + (sectorNo - 1) * 2]);
    if (swapmad) {
        return BSWAP_16(mad);
    } else {
        return mad;
    }
}

int MADCheck(uint8_t *sector0, uint8_t *sector10, bool verbose, bool *haveMAD2) {

    if (sector0 == NULL)
        return PM3_EINVARG;

    uint8_t GPB = sector0[3 * 16 + 9];
    if (verbose)
        PrintAndLogEx(SUCCESS, "%14s " _GREEN_("0x%02x"), "GPB", GPB);

    // DA (MAD available)
    if (!(GPB & 0x80)) {
        PrintAndLogEx(ERR, "DA = 0! MAD not available");
        return PM3_ESOFT;
    }

    uint8_t mad_ver = GPB & 0x03;
    if (verbose)
        PrintAndLogEx(SUCCESS, "%14s " _GREEN_("%d"), "MAD version", mad_ver);

    //  MAD version
    if ((mad_ver != 0x01) && (mad_ver != 0x02)) {
        PrintAndLogEx(ERR, "Wrong MAD version " _RED_("0x%02x"), mad_ver);
        return PM3_ESOFT;
    };

    if (haveMAD2)
        *haveMAD2 = (mad_ver == 2);

    int res = madCRCCheck(sector0, true, 1);

    if (verbose && res == PM3_SUCCESS)
        PrintAndLogEx(SUCCESS, "%14s " _GREEN_("0x%02x") " (%s)", "CRC8", sector0[16], _GREEN_("ok"));

    if (mad_ver == 2 && sector10) {
        int res2 = madCRCCheck(sector10, true, 2);
        if (res == PM3_SUCCESS)
            res = res2;

        if (verbose && !res2)
            PrintAndLogEx(SUCCESS, "%14s " _GREEN_("0x%02x") " (%s)", "CRC8", sector10[0], _GREEN_("ok"));
    }

    // MA (multi-application card)
    if (verbose) {
        if (GPB & 0x40)
            PrintAndLogEx(SUCCESS, "Multi application card");
        else
            PrintAndLogEx(SUCCESS, "Single application card");
    }
    return res;
}

int MADDecode(uint8_t *sector0, uint8_t *sector10, uint16_t *mad, size_t *madlen, bool swapmad) {
    *madlen = 0;
    bool haveMAD2 = false;
    int res = MADCheck(sector0, sector10, false, &haveMAD2);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Not a valid MAD");
        return res;
    }

    for (int i = 1; i < 16; i++) {
        mad[*madlen] = madGetAID(sector0, swapmad, 1, i);
        (*madlen)++;
    }

    if (haveMAD2) {
        // mad2 sector (0x10 == 16dec) here
        mad[*madlen] = 0x0005;
        (*madlen)++;

        for (int i = 1; i < 24; i++) {
            mad[*madlen] = madGetAID(sector10, swapmad, 2, i);
            (*madlen)++;
        }
    }
    return PM3_SUCCESS;
}

int MADCardHolderInfoDecode(uint8_t *data, size_t datalen, bool verbose) {
    size_t idx = 0;
    while (idx < datalen) {
        uint8_t len = data[idx] & 0x3f;
        uint8_t type = data[idx] >> 6;
        idx++;
        if (len > 0) {
            PrintAndLogEx(INFO, "%14s " _GREEN_("%.*s"), holder_info_type[type], len, &data[idx]);
            idx += len;
        } else {
            break;
        }
    }
    return PM3_SUCCESS;
}

static int MADInfoByteDecode(uint8_t *sector, bool swapmad, int mad_ver, bool verbose) {
    uint8_t info;
    if (mad_ver == 1) {
        info = sector[16 + 1] & 0x3f;
        if (info >= 0xF) {
            PrintAndLogEx(WARNING, "Invalid Info byte (MAD1) value " _YELLOW_("0x%02x"), info);
            if (verbose)
                // I understand the spec in a way that MAD1 InfoByte should not point into MAD2 sectors, @lukaskuzmiak
                PrintAndLogEx(WARNING, "MAD1 Info byte points outside of MAD1 sector space (0x%02x), report a bug?", info);
            return PM3_ESOFT;
        }
    } else {
        info = sector[1] & 0x3f;
        if (info == 0x10 || info >= 0x28) {
            PrintAndLogEx(WARNING, "Invalid Info byte (MAD2) value " _YELLOW_("0x%02x"), info);
            return PM3_ESOFT;
        }
    }

    return info;
}

int MAD1DecodeAndPrint(uint8_t *sector, bool swapmad, bool verbose, bool *haveMAD2) {
    open_mad_file(&mad_known_aids, verbose);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "------------ " _CYAN_("MAD v1 details") " -------------");

    // check MAD1 only
    MADCheck(sector, NULL, verbose, haveMAD2);

    int ibs = MADInfoByteDecode(sector, swapmad, 1, verbose);

    if (ibs) {
        PrintAndLogEx(SUCCESS, "Card publisher sector " _MAGENTA_("0x%02x"), ibs);
    } else {
        PrintAndLogEx(WARNING, "Card publisher " _RED_("not") " present " _YELLOW_("0x%02x"), ibs);
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "---------------- " _CYAN_("Listing") " ----------------");

    PrintAndLogEx(INFO, " 00 MAD v1");
    uint32_t prev_aid = 0xFFFFFFFF;
    for (int i = 1; i < 16; i++) {
        uint16_t aid = madGetAID(sector, swapmad, 1, i);
        if (aid < 6) {
            PrintAndLogEx(INFO, (ibs == i) ? _MAGENTA_(" %02d [%04X] (%s)") : " %02d [%04X] (%s)", i, aid, aid_admin[aid]);
        } else if (prev_aid == aid) {
            PrintAndLogEx(INFO, (ibs == i) ? _MAGENTA_(" %02d [%04X] (continuation)") : " %02d [%04X] (continuation)", i, aid);
        } else {
            char fmt[30];
            sprintf(fmt, (ibs == i) ? _MAGENTA_(" %02d [%04X]%s") : " %02d [%04X]%s", i, aid, "%s");
            print_aid_description(mad_known_aids, aid, fmt, verbose);
            prev_aid = aid;
        }
    }
    close_mad_file(mad_known_aids);
    return PM3_SUCCESS;
}

int MAD2DecodeAndPrint(uint8_t *sector, bool swapmad, bool verbose) {
    open_mad_file(&mad_known_aids, verbose);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "------------ " _CYAN_("MAD v2 details") " -------------");

    int res = madCRCCheck(sector, true, 2);
    if (verbose) {
        if (res == PM3_SUCCESS)
            PrintAndLogEx(SUCCESS, "CRC8 (%s)", _GREEN_("ok"));
        else
            PrintAndLogEx(WARNING, "CRC8 (%s)", _RED_("fail"));
    }

    int ibs = MADInfoByteDecode(sector, swapmad, 2, verbose);
    if (ibs) {
        PrintAndLogEx(SUCCESS, "Card publisher sector " _MAGENTA_("0x%02x"), ibs);
    } else {
        PrintAndLogEx(WARNING, "Card publisher " _RED_("not") " present " _YELLOW_("0x%02x"), ibs);
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "---------------- " _CYAN_("Listing") " ----------------");

    PrintAndLogEx(INFO, " 16 MAD v2");

    uint32_t prev_aid = 0xFFFFFFFF;
    for (int i = 1; i < 8 + 8 + 7 + 1; i++) {
        uint16_t aid = madGetAID(sector, swapmad, 2, i);
        if (aid < 6) {
            PrintAndLogEx(INFO, (ibs == i) ? _MAGENTA_(" %02d [%04X] (%s)") : " %02d [%04X] (%s)", i + 16, aid, aid_admin[aid]);
        } else if (prev_aid == aid) {
            PrintAndLogEx(INFO, (ibs == i) ? _MAGENTA_(" %02d [%04X] (continuation)") : " %02d [%04X] (continuation)", i + 16, aid);
        } else {
            char fmt[30];
            sprintf(fmt, (ibs == i) ? _MAGENTA_(" %02d [%04X]%s") : " %02d [%04X]%s", i + 16, aid, "%s");
            print_aid_description(mad_known_aids, aid, fmt, verbose);
            prev_aid = aid;
        }
    }
    close_mad_file(mad_known_aids);

    return PM3_SUCCESS;
}

int MADDFDecodeAndPrint(uint32_t short_aid) {
    open_mad_file(&mad_known_aids, false);

    char fmt[50];
    sprintf(fmt, "  MAD AID Function 0x%04X    :" _YELLOW_("%s"), short_aid, "%s");
    print_aid_description(mad_known_aids, short_aid, fmt, false);
    close_mad_file(mad_known_aids);
    return PM3_SUCCESS;
}
