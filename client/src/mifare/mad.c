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
#include "commonutil.h"  // ARRAYLEN, BSWAP_16
#include "pm3_cmd.h"
#include "crc.h"
#include "util.h"
#include "fileutils.h"
#include "jansson.h"
#include "mifaredefault.h"
#include "mifare4.h"
#include "mifare.h"       // MF_MAD1_SECTOR, MF_MAD2_SECTOR

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

static uint16_t madGetAID(uint16_t raw, bool swapmad) {
    return swapmad ? BSWAP_16(raw) : raw;
}

static json_t *mad_lookup_aid(json_t *root, uint16_t aid) {
    char lmad[7] = {0};
    snprintf(lmad, sizeof(lmad), "0x%04x", aid);

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
            return data;
        }
    }
    return NULL;
}

static const char *mad_aid_description(json_t *elm) {
    static char result[256];
    const char *application = mad_json_get_str(elm, "application");
    const char *company = mad_json_get_str(elm, "company");
    if (application && company) {
        snprintf(result, sizeof(result), " %s [%s]", application, company);
    } else if (application) {
        snprintf(result, sizeof(result), " %s", application);
    } else {
        snprintf(result, sizeof(result), " (unknown)");
    }
    return result;
}

static void mad_print_aid_verbose(json_t *elm) {
    const char *vmad = mad_json_get_str(elm, "mad");
    const char *application = mad_json_get_str(elm, "application");
    const char *company = mad_json_get_str(elm, "company");
    const char *provider = mad_json_get_str(elm, "service_provider");
    const char *integrator = mad_json_get_str(elm, "system_integrator");

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

static int mad1CRCCheck(const mad1_t *mad1, bool verbose) {
    uint8_t crc = CRC8Mad((uint8_t *)&mad1->info, sizeof(mad1_t) - 1);
    if (crc != mad1->crc) {
        if (verbose)
            PrintAndLogEx(WARNING, _RED_("Wrong MAD 1 CRC") " calculated: 0x%02x != 0x%02x", crc, mad1->crc);
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

static int mad2CRCCheck(const mad2_t *mad2, bool verbose) {
    uint8_t crc = CRC8Mad((uint8_t *)&mad2->info, sizeof(mad2_t) - 1);
    if (crc != mad2->crc) {
        if (verbose)
            PrintAndLogEx(WARNING, _RED_("Wrong MAD 2 CRC") " calculated: 0x%02x != 0x%02x", crc, mad2->crc);
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

static int MADInfoByteDecode(uint8_t info, int mad_ver, bool verbose) {
    info &= MAD_INFO_MASK;
    if (mad_ver == 1 && info >= 0xF) {
        PrintAndLogEx(WARNING, "Invalid Info byte (MAD1) value " _YELLOW_("0x%02x"), info);
        if (verbose) {
            PrintAndLogEx(WARNING, "MAD1 Info byte points outside of MAD1 sector space (0x%02x)", info);
        }
        return PM3_ESOFT;
    }
    if (mad_ver == 2 && (info == 0x10 || info >= 0x28)) {
        PrintAndLogEx(WARNING, "Invalid Info byte (MAD2) value " _YELLOW_("0x%02x"), info);
        return PM3_ESOFT;
    }
    return info;
}

int MADCheck(const mad1_sector_t *sector0, const mad2_sector_t *mad2, bool verbose, bool *haveMAD2) {
    if (sector0 == NULL)
        return PM3_EINVARG;

    uint8_t GPB = sector0->trailer.gpb;
    if (verbose) {
        PrintAndLogEx(SUCCESS, "GPB....... " _GREEN_("0x%02X"), GPB);
    }

    if ((GPB & MAD_GPB_DA_MASK) == 0x00) {
        PrintAndLogEx(ERR, "DA = 0! MAD not available");
        return PM3_ESOFT;
    }

    uint8_t mad_ver = (GPB & MAD_GPB_VER_MASK);
    if (verbose)
        PrintAndLogEx(SUCCESS, "Version... " _GREEN_("%d"), mad_ver);

    if ((mad_ver != 0x01) && (mad_ver != 0x02)) {
        PrintAndLogEx(ERR, "Wrong MAD version " _RED_("0x%02X"), mad_ver);
        return PM3_ESOFT;
    };

    if (haveMAD2) {
        *haveMAD2 = (mad_ver == 2);
    }

    int res = mad1CRCCheck(&sector0->mad, verbose);
    if (verbose && res == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "CRC8...... 0x%02X ( %s )", sector0->mad.crc, _GREEN_("ok"));
    }

    if (mad_ver == 2 && mad2) {
        int res2 = mad2CRCCheck(&mad2->mad, verbose);
        if (res == PM3_SUCCESS) {
            res = res2;
        }

        if (verbose && !res2) {
            PrintAndLogEx(SUCCESS, "CRC8...... 0x%02X ( %s )", mad2->mad.crc, _GREEN_("ok"));
        }
    }

    if (verbose) {
        if (GPB & MAD_GPB_MA_MASK)
            PrintAndLogEx(SUCCESS, "Multi application card");
        else
            PrintAndLogEx(SUCCESS, "Single application card");
    }
    return res;
}

int MADDecode(const mad1_sector_t *sector0, const mad2_sector_t *mad2, mad_entry_list_t *mad_list, bool swapmad, bool override) {
    mad_list->len = 0;
    bool haveMAD2 = false;
    int res = MADCheck(sector0, mad2, false, &haveMAD2);

    if (res != PM3_SUCCESS && override == false) {
        PrintAndLogEx(WARNING, "Not a valid MAD");
        return res;
    }

    if (override) {
        PrintAndLogEx(INFO, "overriding crc check");
    }

    for (int i = 0; i < MAD1_NUM_AIDS; i++) {
        mad_list->entries[mad_list->len].sector = i + 1;
        mad_list->entries[mad_list->len].aid = madGetAID(sector0->mad.aid[i], swapmad);
        mad_list->len++;
    }

    if (haveMAD2 && mad2) {
        for (int i = 0; i < MAD2_NUM_AIDS; i++) {
            mad_list->entries[mad_list->len].sector = i + 17;
            mad_list->entries[mad_list->len].aid = madGetAID(mad2->mad.aid[i], swapmad);
            mad_list->len++;
        }
    }
    return PM3_SUCCESS;
}

int MADCardHolderInfoDecode(const uint8_t *data, size_t datalen, bool verbose) {
    size_t idx = 0;
    while (idx < datalen) {
        uint8_t len = data[idx] & MAD_TLV_LEN_MASK;
        uint8_t type = data[idx] >> MAD_TLV_TYPE_SHIFT;
        idx++;
        if (len == 0)
            break;
        if (idx + len > datalen) {
            PrintAndLogEx(WARNING, "Card holder info truncated (need %u bytes, %zu available)", len, datalen - idx);
            break;
        }
        if (type >= ARRAYLEN(holder_info_type))
            type = ARRAYLEN(holder_info_type) - 1;
        PrintAndLogEx(INFO, "%14s " _GREEN_("%.*s"), holder_info_type[type], len, &data[idx]);
        idx += len;
    }
    return PM3_SUCCESS;
}

void MADPrintHeader(void) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("MIFARE App Directory Information") " ----------------");
}

int MAD1DecodeAndPrint(const mad1_sector_t *sector, bool swapmad, bool verbose, bool *haveMAD2) {
    if (open_mad_file(&mad_known_aids, verbose) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Could not load MAD JSON, AID names will not be resolved");
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "------------ " _CYAN_("MAD v1 details") " -------------");

    MADCheck(sector, NULL, verbose, haveMAD2);

    int ibs = MADInfoByteDecode(sector->mad.info, 1, verbose);

    if (ibs > 0) {
        PrintAndLogEx(SUCCESS, "Card publisher sector " _MAGENTA_("0x%02X"), ibs);
    } else {
        PrintAndLogEx(WARNING, "Card publisher " _RED_("not") " present " _YELLOW_("0x%02x"), ibs);
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "---------------- " _CYAN_("Listing") " ----------------");

    PrintAndLogEx(INFO, " 00 MAD v1");
    uint32_t prev_aid = 0xFFFFFFFF;
    for (int i = 0; i < MAD1_NUM_AIDS; i++) {
        int sector_no = i + 1;
        uint16_t aid = madGetAID(sector->mad.aid[i], swapmad);
        if (aid <= MAD_AID_ADMIN_MAX) {
            PrintAndLogEx(INFO,
                          (ibs == sector_no) ? _MAGENTA_(" %02d [%04X] %s") : " %02d [" _GREEN_("%04X") "] %s",
                          sector_no,
                          aid,
                          aid_admin[aid]
                         );

        } else if (prev_aid == aid) {
            PrintAndLogEx(INFO,
                          (ibs == sector_no) ? _MAGENTA_(" %02d [%04X] continuation") : " %02d [" _YELLOW_("%04X") "] continuation",
                          sector_no,
                          aid
                         );
        } else {
            json_t *elm = mad_lookup_aid(mad_known_aids, aid);
            const char *desc = elm ? mad_aid_description(elm) : " (unknown)";
            PrintAndLogEx(INFO,
                          (ibs == sector_no) ? _MAGENTA_(" %02d [%04X]%s") : " %02d [" _GREEN_("%04X") "]%s",
                          sector_no,
                          aid,
                          desc
                         );
            if (verbose && elm) {
                mad_print_aid_verbose(elm);
            }
            prev_aid = aid;
        }
    }
    close_mad_file(mad_known_aids);
    return PM3_SUCCESS;
}

int MAD2DecodeAndPrint(const mad2_sector_t *sector, bool swapmad, bool verbose) {
    if (open_mad_file(&mad_known_aids, false) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Could not load MAD JSON, AID names will not be resolved");
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "------------ " _CYAN_("MAD v2 details") " -------------");

    int res = mad2CRCCheck(&sector->mad, true);
    if (verbose) {
        if (res == PM3_SUCCESS)
            PrintAndLogEx(SUCCESS, "CRC8...... 0x%02X ( " _GREEN_("%s") " )", sector->mad.crc, "ok");
        else
            PrintAndLogEx(SUCCESS, "CRC8...... 0x%02X ( " _RED_("%s") " )", sector->mad.crc, "fail");
    }

    int ibs = MADInfoByteDecode(sector->mad.info, 2, verbose);
    if (ibs > 0) {
        PrintAndLogEx(SUCCESS, "Card publisher sector " _MAGENTA_("0x%02X"), ibs);
    } else {
        PrintAndLogEx(WARNING, "Card publisher " _RED_("not") " present " _YELLOW_("0x%02x"), ibs);
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "---------------- " _CYAN_("Listing") " ----------------");

    PrintAndLogEx(INFO, " 16 MAD v2");

    uint32_t prev_aid = 0xFFFFFFFF;
    for (int i = 0; i < MAD2_NUM_AIDS; i++) {
        int sector_no = i + 17;
        uint16_t aid = madGetAID(sector->mad.aid[i], swapmad);
        if (aid <= MAD_AID_ADMIN_MAX) {
            PrintAndLogEx(INFO,
                          (ibs == sector_no) ? _MAGENTA_(" %02d [%04X] %s") : " %02d [" _GREEN_("%04X") "] %s",
                          sector_no,
                          aid,
                          aid_admin[aid]
                         );
        } else if (prev_aid == aid) {
            PrintAndLogEx(INFO,
                          (ibs == sector_no) ? _MAGENTA_(" %02d [%04X] continuation") : " %02d [" _YELLOW_("%04X") "] continuation",
                          sector_no,
                          aid
                         );
        } else {
            json_t *elm = mad_lookup_aid(mad_known_aids, aid);
            const char *desc = elm ? mad_aid_description(elm) : " (unknown)";
            PrintAndLogEx(INFO,
                          (ibs == sector_no) ? _MAGENTA_(" %02d [%04X]%s") : " %02d [" _GREEN_("%04X") "]%s",
                          sector_no,
                          aid,
                          desc
                         );
            if (verbose && elm) {
                mad_print_aid_verbose(elm);
            }
            prev_aid = aid;
        }
    }
    close_mad_file(mad_known_aids);

    return PM3_SUCCESS;
}

int MADDFDecodeAndPrint(uint32_t short_aid, bool verbose) {
    if (open_mad_file(&mad_known_aids, false) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Could not load MAD JSON, AID names will not be resolved");
    }

    json_t *elm = mad_lookup_aid(mad_known_aids, short_aid);
    const char *desc = elm ? mad_aid_description(elm) : " (unknown)";
    PrintAndLogEx(INFO, "   MAD AID Function 0x%04X... " _YELLOW_("%s"), short_aid, desc);
    if (verbose && elm) {
        mad_print_aid_verbose(elm);
    }
    close_mad_file(mad_known_aids);
    return PM3_SUCCESS;
}

bool HasMADKey(const mad1_sector_t *s0) {
    if (s0 == NULL)
        return false;
    return (memcmp(s0->trailer.key_a, g_mifare_mad_key, sizeof(g_mifare_mad_key)) == 0);
}

int DetectHID(const mad1_sector_t *s0, uint16_t manufacture) {
    if (s0 == NULL)
        return -1;
    for (int i = 0; i < MAD1_NUM_AIDS; i++) {
        if (madGetAID(s0->mad.aid[i], false) == manufacture)
            return i + 1;
    }
    return -1;
}

int convert_mad_to_arr(const mad1_sector_t *s0, const mad2_sector_t *s16,
                       size_t dump_len,
                       uint8_t *out, size_t omax, size_t *olen, bool override) {
    if (s0 == NULL || out == NULL || olen == NULL || dump_len < sizeof(mad1_sector_t) || omax == 0)
        return PM3_EINVARG;

    *olen = 0;

    if (HasMADKey(s0) == false) {
        PrintAndLogEx(FAILED, "No MAD key was detected in the dump file");
        return PM3_ESOFT;
    }

    mad_entry_list_t mad_list = {0};
    if (MADDecode(s0, s16, &mad_list, false, override)) {
        PrintAndLogEx(ERR, "can't decode MAD");
        return PM3_ESOFT;
    }

    const uint8_t *dump = (const uint8_t *)s0;
    uint16_t ndef_aid = 0xE103;
    for (size_t i = 0; i < mad_list.len; i++) {
        if (ndef_aid != mad_list.entries[i].aid)
            continue;

        uint8_t sector_no = mad_list.entries[i].sector;
        size_t offset = mfFirstBlockOfSector(sector_no) * MFBLOCK_SIZE;
        size_t sector_size = mfNumBlocksPerSector(sector_no) * MFBLOCK_SIZE;
        size_t data_size = sector_size - MFBLOCK_SIZE;

        if (offset + sector_size > dump_len)
            break;

        if (*olen + data_size > omax) {
            PrintAndLogEx(WARNING, "NDEF output buffer full");
            return PM3_EOVFLOW;
        }

        memcpy(out + *olen, dump + offset, data_size);
        *olen += data_size;
    }
    return PM3_SUCCESS;
}

static int mad_read_directory(const mad_ops_t *ops, bool swapmad, bool override,
                              mad_entry_list_t *mad_list) {
    mad1_sector_t sector0 = {0};
    int res = ops->read_sector(MF_MAD1_SECTOR, ops->mad_key_type,
                               ops->mad_key, (uint8_t *)&sector0, ops->verbose);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "error reading MAD1 sector 0");
        return res;
    }

    mad2_sector_t mad2 = {0};
    const mad2_sector_t *pmad2 = NULL;
    res = ops->read_sector(MF_MAD2_SECTOR, ops->mad_key_type,
                           ops->mad_key, (uint8_t *)&mad2, ops->verbose);
    if (res == PM3_SUCCESS) {
        pmad2 = &mad2;
    } else if (ops->verbose) {
        PrintAndLogEx(INFO, "MAD2 sector not available, skipping");
    }

    return MADDecode(&sector0, pmad2, mad_list, swapmad, override);
}

int mad_app_read(const mad_ops_t *ops, uint16_t aid, bool swapmad, bool override,
                 uint8_t *out, size_t max_len, size_t *out_len) {
    *out_len = 0;

    mad_entry_list_t mad_list = {0};
    int res = mad_read_directory(ops, swapmad, override, &mad_list);
    if (res != PM3_SUCCESS)
        return res;

    for (size_t i = 0; i < mad_list.len; i++) {
        if (mad_list.entries[i].aid != aid)
            continue;

        uint8_t sno = mad_list.entries[i].sector;
        uint8_t sector_buf[MFBLOCK_SIZE * 16] = {0};
        res = ops->read_sector(sno, ops->app_key_type,
                               ops->app_key, sector_buf, ops->verbose);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "error reading sector %u", sno);
            return res;
        }

        uint8_t num_data_blocks = mfNumBlocksPerSector(sno) - 1;
        size_t nbytes = num_data_blocks * MFBLOCK_SIZE;

        if (*out_len + nbytes > max_len) {
            PrintAndLogEx(ERR, "output buffer too small");
            return PM3_EOVFLOW;
        }

        memcpy(out + *out_len, sector_buf, nbytes);
        *out_len += nbytes;

        if (ops->verbose)
            PrintAndLogEx(INFO, "read sector %u, %zu data bytes", sno, nbytes);
    }

    if (*out_len == 0 && ops->verbose)
        PrintAndLogEx(WARNING, "no sectors found for AID 0x%04X", aid);

    return PM3_SUCCESS;
}

int mad_app_write(const mad_ops_t *ops, uint16_t aid, bool swapmad, bool override,
                  const uint8_t *data, size_t data_len) {
    mad_entry_list_t mad_list = {0};
    int res = mad_read_directory(ops, swapmad, override, &mad_list);
    if (res != PM3_SUCCESS)
        return res;

    size_t capacity = 0;
    for (size_t i = 0; i < mad_list.len; i++) {
        if (mad_list.entries[i].aid == aid)
            capacity += (mfNumBlocksPerSector(mad_list.entries[i].sector) - 1) * MFBLOCK_SIZE;
    }

    if (data_len > capacity) {
        if (ops->verbose)
            PrintAndLogEx(ERR, "data (%zu bytes) exceeds capacity (%zu bytes) for AID 0x%04X",
                          data_len, capacity, aid);
        return PM3_EINVARG;
    }

    size_t offset = 0;
    for (size_t i = 0; i < mad_list.len; i++) {
        if (mad_list.entries[i].aid != aid)
            continue;
        if (offset >= data_len)
            break;

        uint8_t sno = mad_list.entries[i].sector;
        uint8_t num_data_blocks = mfNumBlocksPerSector(sno) - 1;
        size_t sector_data_size = num_data_blocks * MFBLOCK_SIZE;

        uint8_t sector_data[MFBLOCK_SIZE * 15] = {0};
        size_t to_copy = sector_data_size;
        if (data_len - offset < to_copy)
            to_copy = data_len - offset;
        memcpy(sector_data, data + offset, to_copy);

        res = ops->write_sector_data(sno, ops->app_key_type,
                                     ops->app_key, sector_data, ops->verbose);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "error writing sector %u", sno);
            return res;
        }

        if (ops->verbose)
            PrintAndLogEx(INFO, "wrote sector %u, %zu bytes", sno, to_copy);

        offset += sector_data_size;
    }

    PrintAndLogEx(SUCCESS, "wrote %zu bytes to AID 0x%04X", data_len, aid);
    return PM3_SUCCESS;
}

int mad_app_verify(const mad_ops_t *ops, uint16_t aid, bool swapmad, bool override,
                   const uint8_t *expected, size_t expected_len) {
    uint8_t readback[MIFARE_4K_MAX_BYTES];
    size_t readback_len = 0;

    int res = mad_app_read(ops, aid, swapmad, override,
                           readback, sizeof(readback), &readback_len);
    if (res != PM3_SUCCESS)
        return res;

    size_t cmp_len = readback_len < expected_len ? readback_len : expected_len;
    if (memcmp(expected, readback, cmp_len) != 0) {
        if (ops->verbose) {
            PrintAndLogEx(ERR, "Verify " _RED_("FAILED") ": data mismatch");
            for (size_t j = 0; j < cmp_len; j++) {
                if (expected[j] != readback[j]) {
                    PrintAndLogEx(ERR, "first difference at offset %zu: expected %02X, got %02X",
                                  j, expected[j], readback[j]);
                    break;
                }
            }
        }
        return PM3_ESOFT;
    }

    if (expected_len != readback_len) {
        PrintAndLogEx(WARNING, "length mismatch: expected %zu, read %zu (data matches up to shorter)",
                      expected_len, readback_len);
    }

    PrintAndLogEx(SUCCESS, "Verify " _GREEN_("OK") " (%zu bytes)", cmp_len);
    return PM3_SUCCESS;
}
