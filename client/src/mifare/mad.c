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
#include "mifaredefault.h"
#include "mifare4.h"

// Compile-time size sanity checks (force a build error if the structs don't match a 4-block sector).
typedef char mad_assert_mad1[sizeof(mad1_sector_t) == MFBLOCK_SIZE * 4 ? 1 : -1];
typedef char mad_assert_mad2[sizeof(mad2_sector_t) == MFBLOCK_SIZE * 4 ? 1 : -1];

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

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

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
    if (root == NULL || fmt == NULL) {
        return PM3_EINVARG;
    }

    char lmad[7] = {0};
    snprintf(lmad, sizeof(lmad), "0x%04x", aid); // must be lowercase

    json_t *elm = NULL;

    for (uint32_t idx = 0; idx < json_array_size(root); idx++) {
        json_t *data = json_array_get(root, idx);
        if (!json_is_object(data)) {
            PrintAndLogEx(ERR, "data [%u] is not an object", idx);
            continue;
        }
        const char *fmad = mad_json_get_str(data, "mad");
        if (fmad == NULL)
            continue;
        char lfmad[16];
        strncpy(lfmad, fmad, sizeof(lfmad) - 1);
        lfmad[sizeof(lfmad) - 1] = '\0';
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
        char result[512];
        snprintf(result, sizeof(result), " %s [%s]", application, company);
        PrintAndLogEx(INFO, fmt, result);
    }

    if (verbose) {
        PrintAndLogEx(SUCCESS, "     MAD................. %s", vmad ? vmad : "n/a");
        if (application) {
            PrintAndLogEx(SUCCESS, "     Application......... %s", application);
        }
        if (company) {
            PrintAndLogEx(SUCCESS, "     Company............. %s", company);
        }
        if (provider) {
            PrintAndLogEx(SUCCESS, "     Service provider.... %s", provider);
        }
        if (integrator) {
            PrintAndLogEx(SUCCESS, "     System integrator... %s", integrator);
        }
    }
    return PM3_SUCCESS;
}

// ---------------------------------------------------------------------------
// Low-level MAD sector parsing
// ---------------------------------------------------------------------------

static bool mad_sector_valid(const mad_sector_t *sector) {
    return sector != NULL && sector->data != NULL && sector->len >= sizeof(mad1_sector_t);
}

static int madCRCCheck(const mad_sector_t *sector, int mad_ver) {
    if (!mad_sector_valid(sector)) {
        return PM3_EINVARG;
    }

    if (mad_ver == 1) {
        const mad1_sector_t *m = (const mad1_sector_t *)sector->data;
        uint8_t crc = MADComputeCRC(m);
        if (crc != m->crc) {
            PrintAndLogEx(WARNING, _RED_("Wrong MAD %d CRC") " calculated: 0x%02x != 0x%02x", mad_ver, crc, m->crc);
            return PM3_ESOFT;
        }
    } else {
        const mad2_sector_t *m = (const mad2_sector_t *)sector->data;
        uint8_t crc = MADComputeCRC(m);
        if (crc != m->crc) {
            PrintAndLogEx(WARNING,  _RED_("Wrong MAD %d CRC") " calculated: 0x%02x != 0x%02x", mad_ver, crc, m->crc);
            return PM3_ESOFT;
        }
    }
    return PM3_SUCCESS;
}

static uint16_t madGetAID(const mad_sector_t *sector, bool swapmad, int mad_ver, int sector_no) {
    if (!mad_sector_valid(sector)) {
        return 0;
    }

    const mad_aid_t *aid = NULL;

    if (mad_ver == 1) {
        const mad1_sector_t *m = (const mad1_sector_t *)sector->data;
        if (sector_no >= 1 && sector_no <= 15)
            aid = &m->aid[sector_no - 1];
        else
            return 0;
    } else {
        const mad2_sector_t *m = (const mad2_sector_t *)sector->data;
        if (sector_no >= 1 && sector_no <= 23)
            aid = &m->aid[sector_no - 1];
        else
            return 0;
    }

    uint16_t val = mad_aid_get(aid);
    return swapmad ? BSWAP_16(val) : val;
}

static int MADInfoByteDecode(const mad_sector_t *sector, int mad_ver, bool verbose) {
    if (!mad_sector_valid(sector)) {
        return PM3_EINVARG;
    }

    uint8_t info;
    if (mad_ver == 1) {
        const mad1_sector_t *m = (const mad1_sector_t *)sector->data;
        info = m->info & 0x3f;
        if (info >= 0x10) {
            PrintAndLogEx(WARNING, "Invalid Info byte (MAD1) value " _YELLOW_("0x%02x"), info);
            if (verbose) {
                PrintAndLogEx(WARNING, "MAD1 Info byte points outside of MAD1 sector space (0x%02x), report a bug?", info);
            }
            return PM3_ESOFT;
        }
    } else {
        const mad2_sector_t *m = (const mad2_sector_t *)sector->data;
        info = m->info & 0x3f;
        if (info == 0x10 || info >= 0x28) {
            PrintAndLogEx(WARNING, "Invalid Info byte (MAD2) value " _YELLOW_("0x%02x"), info);
            return PM3_ESOFT;
        }
    }

    return info;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

int MADCheck(const mad_sector_t *sector0, const mad_sector_t *sector16, bool verbose, bool *haveMAD2) {
    if (!mad_sector_valid(sector0)) {
        return PM3_EINVARG;
    }

    const mad1_sector_t *m1 = (const mad1_sector_t *)sector0->data;
    uint8_t GPB = m1->gpb;

    if (verbose) {
        PrintAndLogEx(SUCCESS, "GPB....... " _GREEN_("0x%02X"), GPB);
    }

    // DA (MAD available)
    if ((GPB & 0x80) == 0x00) {
        PrintAndLogEx(ERR, "DA = 0! MAD not available");
        return PM3_ESOFT;
    }

    uint8_t mad_ver = (GPB & 0x03);
    if (verbose)
        PrintAndLogEx(SUCCESS, "Version... " _GREEN_("%d"), mad_ver);

    // MAD version
    if ((mad_ver != 0x01) && (mad_ver != 0x02)) {
        PrintAndLogEx(ERR, "Wrong MAD version " _RED_("0x%02X"), mad_ver);
        return PM3_ESOFT;
    }

    bool mad2_available = (mad_ver == 2) && mad_sector_valid(sector16);
    if (haveMAD2) {
        *haveMAD2 = mad2_available;
    }

    int res = madCRCCheck(sector0, 1);
    if (verbose && res == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "CRC8...... 0x%02X ( %s )", m1->crc, _GREEN_("ok"));
    }

    if (mad2_available) {
        int res2 = madCRCCheck(sector16, 2);
        if (res == PM3_SUCCESS) {
            res = res2;
        }
        if (verbose && res2 == PM3_SUCCESS) {
            const mad2_sector_t *m2 = (const mad2_sector_t *)sector16->data;
            PrintAndLogEx(SUCCESS, "CRC8...... 0x%02X ( %s )", m2->crc, _GREEN_("ok"));
        }
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

int MADDecode(const mad_sector_t *sector0, const mad_sector_t *sector16, mad_t *out, bool swapmad, bool override) {
    if (out == NULL) {
        return PM3_EINVARG;
    }

    memset(out, 0, sizeof(mad_t));

    bool haveMAD2 = false;
    int res = MADCheck(sector0, sector16, false, &haveMAD2);
    out->has_mad2 = haveMAD2;

    if (mad_sector_valid(sector0)) {
        const mad1_sector_t *m1 = (const mad1_sector_t *)sector0->data;
        out->gpb = m1->gpb;
    }

    if (res != PM3_SUCCESS && override == false) {
        PrintAndLogEx(WARNING, "Not a valid MAD");
        return res;
    }

    if (override) {
        PrintAndLogEx(INFO, "overriding crc check");
    }

    out->crc1_ok = (madCRCCheck(sector0, 1) == PM3_SUCCESS);

    for (int i = 1; i <= MAD1_AID_COUNT; i++) {
        if (out->count >= MAD_MAX_AID_ENTRIES)
            break;
        out->entries[out->count++] = madGetAID(sector0, swapmad, 1, i);
    }

    if (haveMAD2) {
        out->crc2_ok = (madCRCCheck(sector16, 2) == PM3_SUCCESS);

        if (out->count >= MAD_MAX_AID_ENTRIES)
            return PM3_ESOFT;

        // MAD2 sector marker
        out->entries[out->count++] = 0x0005;

        for (int i = 1; i <= MAD2_AID_COUNT; i++) {
            if (out->count >= MAD_MAX_AID_ENTRIES)
                break;
            out->entries[out->count++] = madGetAID(sector16, swapmad, 2, i);
        }
    }
    return PM3_SUCCESS;
}

int MADCardHolderInfoDecode(const uint8_t *data, size_t datalen, bool verbose) {
    if (data == NULL) {
        return PM3_EINVARG;
    }

    size_t idx = 0;
    while (idx < datalen) {
        uint8_t len = data[idx] & 0x3f;
        uint8_t type = data[idx] >> 6;
        idx++;
        if (len == 0)
            break;
        if (idx + len > datalen) {
            PrintAndLogEx(WARNING, "Card holder info truncated (need %u bytes, %zu available)", len, datalen - idx);
            break;
        }
        if (type >= ARRAYLEN(holder_info_type)) {
            PrintAndLogEx(WARNING, "Unknown card holder info type %u", type);
            idx += len;
            continue;
        }
        PrintAndLogEx(INFO, "%14s " _GREEN_("%.*s"), holder_info_type[type], len, &data[idx]);
        idx += len;
    }
    return PM3_SUCCESS;
}

void MADPrintHeader(void) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("MIFARE App Directory Information") " ----------------");
}

int MAD1DecodeAndPrint(const mad_sector_t *sector, bool swapmad, bool verbose, bool *haveMAD2) {
    if (!mad_sector_valid(sector)) {
        return PM3_EINVARG;
    }

    int res = open_mad_file(&mad_known_aids, verbose);
    if (res != PM3_SUCCESS) {
        mad_known_aids = NULL;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "------------ " _CYAN_("MAD v1 details") " -------------");

    // check MAD1 only
    MADCheck(sector, NULL, verbose, haveMAD2);

    int ibs = MADInfoByteDecode(sector, 1, verbose);
    if (ibs < 0) {
        close_mad_file(mad_known_aids);
        mad_known_aids = NULL;
        return ibs;
    }

    if (ibs > 0) {
        PrintAndLogEx(SUCCESS, "Card publisher sector " _MAGENTA_("0x%02X"), ibs);
    } else {
        PrintAndLogEx(WARNING, "Card publisher " _RED_("not") " present " _YELLOW_("0x%02x"), ibs);
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "---------------- " _CYAN_("Listing") " ----------------");

    PrintAndLogEx(INFO, " 00 MAD v1");
    uint32_t prev_aid = 0xFFFFFFFF;
    for (int i = 1; i <= MAD1_AID_COUNT; i++) {
        uint16_t aid = madGetAID(sector, swapmad, 1, i);
        if (aid < ARRAYLEN(aid_admin)) {
            PrintAndLogEx(INFO,
                          (ibs == i) ? _MAGENTA_(" %02d [%04X] %s") : " %02d [" _GREEN_("%04X") "] %s",
                          i,
                          aid,
                          aid_admin[aid]
                         );

        } else if (prev_aid == aid) {
            PrintAndLogEx(INFO,
                          (ibs == i) ? _MAGENTA_(" %02d [%04X] continuation") : " %02d [" _YELLOW_("%04X") "] continuation",
                          i,
                          aid
                         );
        } else {
            char fmt[80];
            snprintf(fmt
                     , sizeof(fmt)
                     , (ibs == i) ?
                     _MAGENTA_(" %02d [%04X] %s") :
                     " %02d [" _GREEN_("%04X") "] %s"
                     , i
                     , aid
                     , "%s"
                    );
            print_aid_description(mad_known_aids, aid, fmt, verbose);
            prev_aid = aid;
        }
    }
    close_mad_file(mad_known_aids);
    mad_known_aids = NULL;
    return PM3_SUCCESS;
}

int MAD2DecodeAndPrint(const mad_sector_t *sector, bool swapmad, bool verbose) {
    if (!mad_sector_valid(sector)) {
        return PM3_EINVARG;
    }

    int res = open_mad_file(&mad_known_aids, false);
    if (res != PM3_SUCCESS) {
        mad_known_aids = NULL;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "------------ " _CYAN_("MAD v2 details") " -------------");

    int crc_res = madCRCCheck(sector, 2);
    if (verbose) {
        const mad2_sector_t *m2 = (const mad2_sector_t *)sector->data;
        if (crc_res == PM3_SUCCESS)
            PrintAndLogEx(SUCCESS, "CRC8...... 0x%02X ( " _GREEN_("%s") " )", m2->crc, "ok");
        else
            PrintAndLogEx(SUCCESS, "CRC8...... 0x%02X ( " _RED_("%s") " )", m2->crc, "fail");
    }

    int ibs = MADInfoByteDecode(sector, 2, verbose);
    if (ibs < 0) {
        close_mad_file(mad_known_aids);
        mad_known_aids = NULL;
        return ibs;
    }

    if (ibs > 0) {
        PrintAndLogEx(SUCCESS, "Card publisher sector " _MAGENTA_("0x%02X"), ibs);
    } else {
        PrintAndLogEx(WARNING, "Card publisher " _RED_("not") " present " _YELLOW_("0x%02x"), ibs);
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "---------------- " _CYAN_("Listing") " ----------------");

    PrintAndLogEx(INFO, " 16 MAD v2");

    uint32_t prev_aid = 0xFFFFFFFF;
    for (int i = 1; i <= MAD2_AID_COUNT; i++) {
        uint16_t aid = madGetAID(sector, swapmad, 2, i);
        if (aid < ARRAYLEN(aid_admin)) {
            PrintAndLogEx(INFO,
                          (ibs == i + 16) ? _MAGENTA_(" %02d [%04X] %s") : " %02d [" _GREEN_("%04X") "] %s",
                          i + 16,
                          aid,
                          aid_admin[aid]
                         );
        } else if (prev_aid == aid) {
            PrintAndLogEx(INFO,
                          (ibs == i + 16) ? _MAGENTA_(" %02d [%04X] continuation") : " %02d [" _YELLOW_("%04X") "] continuation",
                          i + 16,
                          aid
                         );
        } else {
            char fmt[80];
            snprintf(fmt
                     , sizeof(fmt)
                     , (ibs == i + 16) ?
                     _MAGENTA_(" %02d [%04X] %s") :
                     " %02d [" _GREEN_("%04X") "] %s"
                     , i + 16
                     , aid
                     , "%s"
                    );
            print_aid_description(mad_known_aids, aid, fmt, verbose);
            prev_aid = aid;
        }
    }
    close_mad_file(mad_known_aids);
    mad_known_aids = NULL;

    return PM3_SUCCESS;
}

int MADDFDecodeAndPrint(uint32_t short_aid, bool verbose) {
    int res = open_mad_file(&mad_known_aids, false);
    if (res != PM3_SUCCESS) {
        mad_known_aids = NULL;
    }

    char fmt[128];
    snprintf(fmt, sizeof(fmt), "   MAD AID Function 0x%04X... " _YELLOW_("%s"), short_aid, "%s");
    print_aid_description(mad_known_aids, short_aid, fmt, verbose);
    close_mad_file(mad_known_aids);
    mad_known_aids = NULL;
    return PM3_SUCCESS;
}

bool HasMADKey(const mad_sector_t *sector) {
    if (sector == NULL || sector->data == NULL) {
        return false;
    }

    if (sector->len < sizeof(mad1_sector_t)) {
        return false;
    }

    const mad1_sector_t *m = (const mad1_sector_t *)sector->data;
    return (memcmp(m->key_a, g_mifare_mad_key, sizeof(g_mifare_mad_key)) == 0);
}

int DetectHID(const mad_sector_t *sector, uint16_t manufacture) {
    if (!mad_sector_valid(sector)) {
        return -1;
    }

    for (int i = 1; i <= MAD1_AID_COUNT; i++) {
        uint16_t aid = madGetAID(sector, false, 1, i);
        if (aid == manufacture) {
            return i;
        }
    }

    return -1;
}

int convert_mad_to_arr(const uint8_t *in, size_t ilen, uint8_t *out, size_t *olen, size_t olen_max, bool override) {
    if (in == NULL || out == NULL || olen == NULL || ilen == 0 || olen_max == 0) {
        return PM3_EINVARG;
    }

    *olen = 0;

    mad_sector_t dump = { in, ilen };
    if (HasMADKey(&dump) == false) {
        PrintAndLogEx(FAILED, "No MAD key was detected in the dump file");
        return PM3_ESOFT;
    }

    uint8_t sector0_buf[MFBLOCK_SIZE * 4] = {0};
    uint8_t sector16_buf[MFBLOCK_SIZE * 4] = {0};

    memcpy(sector0_buf, in, MIN(sizeof(sector0_buf), ilen));

    mad_sector_t sector16 = { NULL, 0 };
    size_t sector16_offset = MF_MAD2_SECTOR * 4 * MFBLOCK_SIZE;
    if (ilen >= sector16_offset + sizeof(sector16_buf)) {
        memcpy(sector16_buf, in + sector16_offset, sizeof(sector16_buf));
        sector16.data = sector16_buf;
        sector16.len = sizeof(sector16_buf);
    }

    mad_sector_t sector0 = { sector0_buf, sizeof(sector0_buf) };
    mad_t mad = {0};
    int res = MADDecode(&sector0, &sector16, &mad, false, override);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "can't decode MAD");
        return PM3_ESOFT;
    }

    uint16_t ndef_aid = 0xE103;
    for (size_t i = 0; i < mad.count; i++) {
        if (ndef_aid == mad.entries[i]) {
            uint8_t sectorNo = i + 1;
            uint16_t first_block = mfFirstBlockOfSector(sectorNo);
            uint8_t num_blocks = mfNumBlocksPerSector(sectorNo);
            uint32_t offset = first_block * MFBLOCK_SIZE;
            uint16_t sector_size = num_blocks * MFBLOCK_SIZE;

            if (offset + sector_size > ilen) {
                PrintAndLogEx(WARNING, "NDEF sector %u exceeds input bounds", sectorNo);
                break;
            }

            uint16_t data_size = sector_size - MFBLOCK_SIZE;
            if (*olen + data_size > olen_max) {
                PrintAndLogEx(WARNING, "NDEF output buffer full");
                return PM3_ESOFT;
            }

            memcpy(out, in + offset, data_size);
            out += data_size;
            *olen += data_size;
        }
    }
    return PM3_SUCCESS;
}
