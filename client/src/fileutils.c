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

// this define is needed for scandir/alphasort to work
#define _GNU_SOURCE
#include "fileutils.h"
#include "preferences.h"

#include <dirent.h>
#include <ctype.h>

#include "pm3_cmd.h"
#include "commonutil.h"
#include "proxmark3.h"
#include "util.h"
#include "cmdhficlass.h"  // pagemap
#include "iclass_cmd.h"
#include "iso15.h"

#ifdef _WIN32
#include "scandir.h"
#include <direct.h>
#endif

#define PATH_MAX_LENGTH 200

struct wave_info_t {
    char signature[4];
    uint32_t filesize;
    char type[4];
    struct {
        char tag[4];
        uint32_t size;
        uint16_t codec;
        uint16_t nb_channel;
        uint32_t sample_per_sec;
        uint32_t byte_per_sec;
        uint16_t block_align;
        uint16_t bit_per_sample;
    } PACKED format;
    struct {
        char tag[4];
        uint32_t size;
    } PACKED audio_data;
} PACKED;

/**
 * @brief detects if file is of a supported filetype based on extension
 * @param filename
 * @return o
 */
DumpFileType_t get_filetype(const char *filename) {
    // assume unknown file is BINARY
    DumpFileType_t o = BIN;
    if (filename == NULL) {
        return o;
    }

    size_t len = strlen(filename);
    if (len > 4) {
        //  check if valid file extension and attempt to load data
        char s[FILE_PATH_SIZE];
        memset(s, 0, sizeof(s));
        memcpy(s, filename, len);
        str_lower(s);

        if (str_endswith(s, "bin")) {
            o = BIN;
        } else if (str_endswith(s, "eml")) {
            o = EML;
        } else if (str_endswith(s, "json")) {
            o = JSON;
        } else if (str_endswith(s, "dic")) {
            o = DICTIONARY;
        } else if (str_endswith(s, "mct")) {
            o = MCT;
        } else if (str_endswith(s, "nfc")) {
            o = FLIPPER;
        } else if (str_endswith(s, "picopass")) {
            o = FLIPPER;
        } else {
            // mfd, trc, trace is binary
            o = BIN;
            // log is text
            // .pm3 is text values of signal data
        }
    }
    return o;
}

/**
 * @brief checks if a file exists
 * @param filename
 * @return
 */
int fileExists(const char *filename) {

#ifdef _WIN32
    struct _stat st;
    int result = _stat(filename, &st);
#else
    struct stat st;
    int result = stat(filename, &st);
#endif
    return result == 0;
}

/**
 * @brief checks if path is directory.
 * @param filename
 * @return
 */
static bool is_directory(const char *filename) {
#ifdef _WIN32
    struct _stat st;
    if (_stat(filename, &st) == -1)
        return false;
#else
    struct stat st;
//    stat(filename, &st);
    if (lstat(filename, &st) == -1)
        return false;
#endif
    return S_ISDIR(st.st_mode) != 0;
}

bool setDefaultPath(savePaths_t pathIndex, const char *path) {

    if (pathIndex < spItemCount) {

        if ((path == NULL) && (g_session.defaultPaths[pathIndex] != NULL)) {
            free(g_session.defaultPaths[pathIndex]);
            g_session.defaultPaths[pathIndex] = NULL;
        }

        if (path == NULL) {
            return false;
        }

        size_t len = strlen(path);

        g_session.defaultPaths[pathIndex] = (char *)realloc(g_session.defaultPaths[pathIndex], len + 1);
        strcpy(g_session.defaultPaths[pathIndex], path);
        return true;
    }
    return false;
}

static char *filenamemcopy(const char *preferredName, const char *suffix) {
    if (preferredName == NULL) return NULL;
    if (suffix == NULL) return NULL;

    char *fileName = (char *) calloc(strlen(preferredName) + strlen(suffix) + 1, sizeof(uint8_t));
    if (fileName == NULL) {
        return NULL;
    }

    strcpy(fileName, preferredName);
    if (str_endswith(fileName, suffix)) {
        return fileName;
    }

    strcat(fileName, suffix);
    return fileName;
}

static size_t path_size(savePaths_t a) {
    if (a >= spItemCount) {
        return 0;
    }
    return strlen(g_session.defaultPaths[a]);
}

char *newfilenamemcopy(const char *preferredName, const char *suffix) {
    return newfilenamemcopyEx(preferredName, suffix, spDefault);
}

char *newfilenamemcopyEx(const char *preferredName, const char *suffix, savePaths_t e_save_path) {
    if (preferredName == NULL || suffix == NULL) {
        return NULL;
    }

    // 1: null terminator
    // 16: room for filenum to ensure new filename
    // save_path_len + strlen(PATHSEP):  the user preference save paths
    //const size_t len = p_namelen + strlen(suffix) + 1 + 16 + save_path_len + strlen(PATHSEP);
    size_t len = FILE_PATH_SIZE;

    char *fileName = (char *) calloc(len, sizeof(uint8_t));
    if (fileName == NULL) {
        return NULL;
    }

    char *pfn = fileName;

    // if given path is not an absolute path
    if ((preferredName[0] !=  '/') && (preferredName[0] !=  '\\')) {
        // user preference save paths
        size_t save_path_len = path_size(e_save_path);
        if (save_path_len && save_path_len < (FILE_PATH_SIZE - strlen(PATHSEP))) {
            snprintf(pfn, len, "%s%s", g_session.defaultPaths[e_save_path], PATHSEP);
            pfn += save_path_len + strlen(PATHSEP);
            len -= save_path_len + strlen(PATHSEP);
        }
    }

    // remove file extension if exist in name
    size_t p_namelen = strlen(preferredName);
    if (str_endswith(preferredName, suffix)) {
        p_namelen -= strlen(suffix);
    }

    len -= strlen(suffix) + 1;
    len -= p_namelen;

    // modify filename
    snprintf(pfn, len, "%.*s%s", (int)p_namelen, preferredName, suffix);

    // "-001"
    len -= 4;

    int num = 1;
    // check complete path/filename if exists
    while (fileExists(fileName)) {
        // modify filename
        snprintf(pfn, len, "%.*s-%03d%s", (int)p_namelen, preferredName, num, suffix);
        num++;
    }

    return fileName;
}

// trunacate down a filename to LEN size
void truncate_filename(char *fn, uint16_t maxlen) {
    if (fn == NULL || maxlen < 5) {
        return;
    }

    // Check if the filename is already shorter than or equal to the desired length
    if (strlen(fn) <= maxlen) {
        return;
    }

    // If there's no extension or it's too long, just truncate the filename
    fn[maxlen - 3] = '\0';
    strcat(fn, "...");
}

// --------- SAVE FILES
int saveFile(const char *preferredName, const char *suffix, const void *data, size_t datalen) {
    return saveFileEx(preferredName, suffix, data, datalen, spDefault);
}
int saveFileEx(const char *preferredName, const char *suffix, const void *data, size_t datalen, savePaths_t e_save_path) {
    if (data == NULL || datalen == 0) {
        return PM3_EINVARG;
    }

    char *fileName = newfilenamemcopyEx(preferredName, suffix, e_save_path);
    if (fileName == NULL) {
        return PM3_EMALLOC;
    }

    // We should have a valid filename now, e.g. dumpdata-3.bin

    // Opening file for writing in binary mode
    FILE *f = fopen(fileName, "wb");
    if (!f) {
        PrintAndLogEx(WARNING, "file not found or locked `" _YELLOW_("%s") "`", fileName);
        free(fileName);
        return PM3_EFILE;
    }
    fwrite(data, 1, datalen, f);
    fflush(f);
    fclose(f);
    PrintAndLogEx(SUCCESS, "Saved " _YELLOW_("%zu") " bytes to binary file `" _YELLOW_("%s") "`", datalen, fileName);
    free(fileName);
    return PM3_SUCCESS;
}

int prepareJSON(json_t *root, JSONFileType ftype, uint8_t *data, size_t datalen, bool verbose, void (*callback)(json_t *)) {
    if (ftype != jsfCustom) {
        if (data == NULL || datalen == 0) {
            return PM3_EINVARG;
        }
    }

    char path[PATH_MAX_LENGTH] = {0};

    JsonSaveStr(root, "Created", "proxmark3");
    switch (ftype) {
        case jsfRaw: {
            JsonSaveStr(root, "FileType", "raw");
            JsonSaveBufAsHexCompact(root, "raw", data, datalen);
            break;
        }
        case jsfMfc_v2: {

            iso14a_mf_extdump_t xdump;
            memcpy(&xdump, data, sizeof(iso14a_mf_extdump_t));

            JsonSaveStr(root, "FileType", "mfc v2");
            JsonSaveBufAsHexCompact(root, "$.Card.UID", xdump.card_info.uid, xdump.card_info.uidlen);
            JsonSaveBufAsHexCompact(root, "$.Card.ATQA", xdump.card_info.atqa, 2);
            JsonSaveBufAsHexCompact(root, "$.Card.SAK", &(xdump.card_info.sak), 1);
            for (size_t i = 0; i < (xdump.dumplen / MFBLOCK_SIZE); i++) {

                snprintf(path, sizeof(path), "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, &xdump.dump[i * MFBLOCK_SIZE], MFBLOCK_SIZE);
                if (mfIsSectorTrailer(i)) {
                    snprintf(path, sizeof(path), "$.SectorKeys.%d.KeyA", mfSectorNum(i));
                    JsonSaveBufAsHexCompact(root, path, &xdump.dump[i * MFBLOCK_SIZE], 6);

                    snprintf(path, sizeof(path), "$.SectorKeys.%d.KeyB", mfSectorNum(i));
                    JsonSaveBufAsHexCompact(root, path, &xdump.dump[i * MFBLOCK_SIZE + 10], 6);

                    uint8_t *adata = &xdump.dump[i * MFBLOCK_SIZE + 6];
                    snprintf(path, sizeof(path), "$.SectorKeys.%d.AccessConditions", mfSectorNum(i));
                    JsonSaveBufAsHexCompact(root, path, &xdump.dump[i * MFBLOCK_SIZE + 6], 4);

                    snprintf(path, sizeof(path), "$.SectorKeys.%d.AccessConditionsText.block%zu", mfSectorNum(i), i - 3);
                    JsonSaveStr(root, path, mfGetAccessConditionsDesc(0, adata));

                    snprintf(path, sizeof(path), "$.SectorKeys.%d.AccessConditionsText.block%zu", mfSectorNum(i), i - 2);
                    JsonSaveStr(root, path, mfGetAccessConditionsDesc(1, adata));

                    snprintf(path, sizeof(path), "$.SectorKeys.%d.AccessConditionsText.block%zu", mfSectorNum(i), i - 1);
                    JsonSaveStr(root, path, mfGetAccessConditionsDesc(2, adata));

                    snprintf(path, sizeof(path), "$.SectorKeys.%d.AccessConditionsText.block%zu", mfSectorNum(i), i);
                    JsonSaveStr(root, path, mfGetAccessConditionsDesc(3, adata));

                    snprintf(path, sizeof(path), "$.SectorKeys.%d.AccessConditionsText.UserData", mfSectorNum(i));
                    JsonSaveBufAsHexCompact(root, path, &adata[3], 1);
                }
            }
            break;
        }
        case jsfMfc_v3: {

            iso14a_mf_dump_ev1_t xdump;
            memcpy(&xdump, data, sizeof(iso14a_mf_dump_ev1_t));

            JsonSaveStr(root, "FileType", "mfc v3");
            JsonSaveBufAsHexCompact(root, "$.Card.UID", xdump.card.ev1.uid, xdump.card.ev1.uidlen);
            JsonSaveBufAsHexCompact(root, "$.Card.ATQA", xdump.card.ev1.atqa, 2);
            JsonSaveBufAsHexCompact(root, "$.Card.SAK", &(xdump.card.ev1.sak), 1);
            JsonSaveBufAsHexCompact(root, "$.Card.ATS", xdump.card.ev1.ats, sizeof(xdump.card.ev1.ats_len));
            JsonSaveBufAsHexCompact(root, "$.Card.SIGNATURE", xdump.card.ev1.signature, sizeof(xdump.card.ev1.signature));

            for (size_t i = 0; i < (xdump.dumplen / MFBLOCK_SIZE); i++) {

                snprintf(path, sizeof(path), "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, &xdump.dump[i * MFBLOCK_SIZE], MFBLOCK_SIZE);
                if (mfIsSectorTrailer(i)) {
                    snprintf(path, sizeof(path), "$.SectorKeys.%d.KeyA", mfSectorNum(i));
                    JsonSaveBufAsHexCompact(root, path, &xdump.dump[i * MFBLOCK_SIZE], 6);

                    snprintf(path, sizeof(path), "$.SectorKeys.%d.KeyB", mfSectorNum(i));
                    JsonSaveBufAsHexCompact(root, path, &xdump.dump[i * MFBLOCK_SIZE + 10], 6);

                    uint8_t *adata = &xdump.dump[i * MFBLOCK_SIZE + 6];
                    snprintf(path, sizeof(path), "$.SectorKeys.%d.AccessConditions", mfSectorNum(i));
                    JsonSaveBufAsHexCompact(root, path, &xdump.dump[i * MFBLOCK_SIZE + 6], 4);

                    snprintf(path, sizeof(path), "$.SectorKeys.%d.AccessConditionsText.block%zu", mfSectorNum(i), i - 3);
                    JsonSaveStr(root, path, mfGetAccessConditionsDesc(0, adata));

                    snprintf(path, sizeof(path), "$.SectorKeys.%d.AccessConditionsText.block%zu", mfSectorNum(i), i - 2);
                    JsonSaveStr(root, path, mfGetAccessConditionsDesc(1, adata));

                    snprintf(path, sizeof(path), "$.SectorKeys.%d.AccessConditionsText.block%zu", mfSectorNum(i), i - 1);
                    JsonSaveStr(root, path, mfGetAccessConditionsDesc(2, adata));

                    snprintf(path, sizeof(path), "$.SectorKeys.%d.AccessConditionsText.block%zu", mfSectorNum(i), i);
                    JsonSaveStr(root, path, mfGetAccessConditionsDesc(3, adata));

                    snprintf(path, sizeof(path), "$.SectorKeys.%d.AccessConditionsText.UserData", mfSectorNum(i));
                    JsonSaveBufAsHexCompact(root, path, &adata[3], 1);
                }
            }
            break;
        }
        case jsfFudan: {
            iso14a_mf_extdump_t xdump;
            memcpy(&xdump, data, sizeof(iso14a_mf_extdump_t));

            JsonSaveStr(root, "FileType", "fudan");
            JsonSaveBufAsHexCompact(root, "$.Card.UID", xdump.card_info.uid, xdump.card_info.uidlen);
            JsonSaveBufAsHexCompact(root, "$.Card.ATQA", xdump.card_info.atqa, 2);
            JsonSaveBufAsHexCompact(root, "$.Card.SAK", &(xdump.card_info.sak), 1);
            for (size_t i = 0; i < (xdump.dumplen / 4); i++) {

                snprintf(path, sizeof(path), "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, &xdump.dump[i * 4], 4);
            }
            break;
        }
        case jsfMfuMemory: {
            mfu_dump_t tmp;
            memcpy(&tmp, data, sizeof(mfu_dump_t));

            uint8_t uid[7] = {0};
            memcpy(uid, tmp.data, 3);
            memcpy(uid + 3, tmp.data + 4, 4);

            JsonSaveStr(root, "FileType", "mfu");
            JsonSaveBufAsHexCompact(root, "$.Card.UID", uid, sizeof(uid));
            JsonSaveBufAsHexCompact(root, "$.Card.Version", tmp.version, sizeof(tmp.version));
            JsonSaveBufAsHexCompact(root, "$.Card.TBO_0", tmp.tbo, sizeof(tmp.tbo));
            JsonSaveBufAsHexCompact(root, "$.Card.TBO_1", tmp.tbo1, sizeof(tmp.tbo1));
            JsonSaveBufAsHexCompact(root, "$.Card.Signature", tmp.signature, sizeof(tmp.signature));
            for (uint8_t i = 0; i < 3; i ++) {
                snprintf(path, sizeof(path), "$.Card.Counter%d", i);
                JsonSaveBufAsHexCompact(root, path, tmp.counter_tearing[i], 3);
                snprintf(path, sizeof(path), "$.Card.Tearing%d", i);
                JsonSaveBufAsHexCompact(root, path, tmp.counter_tearing[i] + 3, 1);
            }

            // size of header 56b

            size_t len = (datalen - MFU_DUMP_PREFIX_LENGTH) / MFU_BLOCK_SIZE;

            for (size_t i = 0; i < len; i++) {
                snprintf(path, sizeof(path), "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, tmp.data + (i * MFU_BLOCK_SIZE), MFU_BLOCK_SIZE);
            }
            break;
        }
        case jsfHitag: {
            uint8_t uid[4] = {0};
            memcpy(uid, data, 4);
            JsonSaveStr(root, "FileType", "hitag");
            JsonSaveBufAsHexCompact(root, "$.Card.UID", uid, sizeof(uid));

            for (size_t i = 0; i < (datalen / 4); i++) {
                snprintf(path, sizeof(path), "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, data + (i * 4), 4);
            }
            break;
        }
        case jsfIclass: {

            picopass_hdr_t hdr;
            memcpy(&hdr, data, sizeof(picopass_hdr_t));

            JsonSaveStr(root, "FileType", "iclass");
            JsonSaveBufAsHexCompact(root, "$.Card.CSN", hdr.csn, sizeof(hdr.csn));
            JsonSaveBufAsHexCompact(root, "$.Card.Configuration", (uint8_t *)&hdr.conf, sizeof(hdr.conf));

            uint8_t pagemap = get_pagemap(&hdr);
            if (pagemap == PICOPASS_NON_SECURE_PAGEMODE) {
                picopass_ns_hdr_t ns_hdr;
                memcpy(&ns_hdr, data, sizeof(picopass_ns_hdr_t));
                JsonSaveBufAsHexCompact(root, "$.Card.AIA", ns_hdr.app_issuer_area, sizeof(ns_hdr.app_issuer_area));
            } else {
                JsonSaveBufAsHexCompact(root, "$.Card.Epurse", hdr.epurse, sizeof(hdr.epurse));
                JsonSaveBufAsHexCompact(root, "$.Card.Kd", hdr.key_d, sizeof(hdr.key_d));
                JsonSaveBufAsHexCompact(root, "$.Card.Kc", hdr.key_c, sizeof(hdr.key_c));
                JsonSaveBufAsHexCompact(root, "$.Card.AIA", hdr.app_issuer_area, sizeof(hdr.app_issuer_area));
            }

            for (size_t i = 0; i < (datalen / PICOPASS_BLOCK_SIZE); i++) {
                snprintf(path, sizeof(path), "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, data + (i * PICOPASS_BLOCK_SIZE), PICOPASS_BLOCK_SIZE);
            }

            break;
        }
        case jsfT55x7: {
            JsonSaveStr(root, "FileType", "t55x7");
            uint8_t conf[4] = {0};
            memcpy(conf, data, 4);
            JsonSaveBufAsHexCompact(root, "$.Card.ConfigBlock", conf, sizeof(conf));

            for (size_t i = 0; i < (datalen / 4); i++) {
                snprintf(path, sizeof(path), "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, data + (i * 4), 4);
            }
            break;
        }
        case jsf14b_v2: {
            JsonSaveStr(root, "FileType", "14b v2");
            for (size_t i = 0; i < datalen / 4; i++) {
                snprintf(path, sizeof(path), "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, &data[i * 4], 4);
            }
            break;
        }
        // handles ISO15693 in iso15_tag_t format
        case jsf15_v4: {
            JsonSaveStr(root, "FileType", "15693 v4");
            iso15_tag_t *tag = (iso15_tag_t *)data;
            JsonSaveBufAsHexCompact(root, "$.Card.uid", tag->uid, sizeof(tag->uid));
            JsonSaveBufAsHexCompact(root, "$.Card.dsfid", &tag->dsfid, 1);
            JsonSaveBufAsHexCompact(root, "$.Card.dsfidlock", (uint8_t *)&tag->dsfidLock, 1);
            JsonSaveBufAsHexCompact(root, "$.Card.afi", &tag->afi, 1);
            JsonSaveBufAsHexCompact(root, "$.Card.afilock", (uint8_t *)&tag->afiLock, 1);
            JsonSaveBufAsHexCompact(root, "$.Card.bytesperpage", &tag->bytesPerPage, 1);
            JsonSaveBufAsHexCompact(root, "$.Card.pagescount", &tag->pagesCount, 1);
            JsonSaveBufAsHexCompact(root, "$.Card.ic", &tag->ic, 1);
            JsonSaveBufAsHexCompact(root, "$.Card.locks", tag->locks, tag->pagesCount);
            JsonSaveBufAsHexCompact(root, "$.Card.random", tag->random, 2);
            JsonSaveBufAsHexCompact(root, "$.Card.privacypasswd", tag->privacyPasswd, sizeof(tag->privacyPasswd));
            JsonSaveBufAsHexCompact(root, "$.Card.state", (uint8_t *)&tag->state, 1);

            for (uint8_t i = 0 ; i < tag->pagesCount ; i++) {

                if (((i + 1) * tag->bytesPerPage) > ISO15693_TAG_MAX_SIZE) {
                    break;
                }

                snprintf(path, sizeof(path), "$.blocks.%u", i);
                JsonSaveBufAsHexCompact(root
                                        , path
                                        , &tag->data[i * tag->bytesPerPage]
                                        , tag->bytesPerPage
                                       );
            }
            break;
        }
        case jsfLegic_v2: {
            JsonSaveStr(root, "FileType", "legic v2");
            JsonSaveBufAsHexCompact(root, "$.Card.UID", data, 4);
            size_t i = 0;
            for (; i < datalen / 16; i++) {
                snprintf(path, sizeof(path), "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, &data[i * 16], 16);
            }
            if (datalen % 16) {
                snprintf(path, sizeof(path), "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, &data[i * 16], (datalen % 16));
            }
            break;
        }
        case jsfT5555: {
            JsonSaveStr(root, "FileType", "t5555");
            uint8_t conf[4] = {0};
            memcpy(conf, data, 4);
            JsonSaveBufAsHexCompact(root, "$.Card.ConfigBlock", conf, sizeof(conf));

            for (size_t i = 0; i < (datalen / 4); i++) {
                snprintf(path, sizeof(path), "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, data + (i * 4), 4);
            }
            break;
        }
        case jsfEM4x05: {
            JsonSaveStr(root, "FileType", "EM4205/EM4305");
            JsonSaveBufAsHexCompact(root, "$.Card.UID", data + (1 * 4), 4);
            JsonSaveBufAsHexCompact(root, "$.Card.Config", data + (4 * 4), 4);
            JsonSaveBufAsHexCompact(root, "$.Card.Protection1", data + (14 * 4), 4);
            JsonSaveBufAsHexCompact(root, "$.Card.Protection2", data + (15 * 4), 4);

            for (size_t i = 0; i < (datalen / 4); i++) {
                snprintf(path, sizeof(path), "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, data + (i * 4), 4);
            }
            break;
        }
        case jsfEM4x69: {
            JsonSaveStr(root, "FileType", "EM4469/EM4569");
            JsonSaveBufAsHexCompact(root, "$.Card.UID", data + (1 * 4), 4);
            JsonSaveBufAsHexCompact(root, "$.Card.Protection", data + (3 * 4), 4);
            JsonSaveBufAsHexCompact(root, "$.Card.Config", data + (4 * 4), 4);

            for (size_t i = 0; i < (datalen / 4); i++) {
                snprintf(path, sizeof(path), "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, data + (i * 4), 4);
            }
            break;
        }
        case jsfEM4x50: {
            JsonSaveStr(root, "FileType", "EM4X50");
            JsonSaveBufAsHexCompact(root, "$.Card.Protection", data + (1 * 4), 4);
            JsonSaveBufAsHexCompact(root, "$.Card.Config", data + (2 * 4), 4);
            JsonSaveBufAsHexCompact(root, "$.Card.Serial", data + (32 * 4), 4);
            JsonSaveBufAsHexCompact(root, "$.Card.UID", data + (33 * 4), 4);

            for (size_t i = 0; i < (datalen / 4); i++) {
                snprintf(path, sizeof(path), "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, data + (i * 4), 4);
            }
            break;
        }
        case jsfMfPlusKeys: {
            JsonSaveStr(root, "FileType", "mfpkeys");
            JsonSaveBufAsHexCompact(root, "$.Card.UID", &data[0], 7);
            JsonSaveBufAsHexCompact(root, "$.Card.SAK", &data[10], 1);
            JsonSaveBufAsHexCompact(root, "$.Card.ATQA", &data[11], 2);
            uint8_t atslen = data[13];
            if (atslen > 0) {
                JsonSaveBufAsHexCompact(root, "$.Card.ATS", &data[14], atslen);
            }

            uint8_t vdata[2][64][17] = {{{0}}};
            memcpy(vdata, data + (14 + atslen), 2 * 64 * 17);

            for (size_t i = 0; i < datalen; i++) {
                if (vdata[0][i][0]) {
                    snprintf(path, sizeof(path), "$.SectorKeys.%zu.KeyA", i);
                    JsonSaveBufAsHexCompact(root, path, &vdata[0][i][1], AES_KEY_LEN);
                }

                if (vdata[1][i][0]) {
                    snprintf(path, sizeof(path), "$.SectorKeys.%zu.KeyB", i);
                    JsonSaveBufAsHexCompact(root, path, &vdata[1][i][1], AES_KEY_LEN);
                }
            }
            break;
        }
        case jsfMfDesfireKeys: {
            JsonSaveStr(root, "FileType", "mfdes");
            JsonSaveBufAsHexCompact(root, "$.Card.UID", &data[0], 7);
            JsonSaveBufAsHexCompact(root, "$.Card.SAK", &data[10], 1);
            JsonSaveBufAsHexCompact(root, "$.Card.ATQA", &data[11], 2);
            uint8_t datslen = data[13];
            if (datslen > 0)
                JsonSaveBufAsHexCompact(root, "$.Card.ATS", &data[14], datslen);

            uint8_t dvdata[4][0xE][24 + 1] = {{{0}}};
            memcpy(dvdata, &data[14 + datslen], 4 * 0xE * (24 + 1));

            for (int i = 0; i < (int)datalen; i++) {

                if (dvdata[0][i][0]) {
                    snprintf(path, sizeof(path), "$.DES.%d.Key", i);
                    JsonSaveBufAsHexCompact(root, path, &dvdata[0][i][1], DES_KEY_LEN);
                }

                if (dvdata[1][i][0]) {
                    snprintf(path, sizeof(path), "$.3DES.%d.Key", i);
                    JsonSaveBufAsHexCompact(root, path, &dvdata[1][i][1], T2DES_KEY_LEN);
                }
                if (dvdata[2][i][0]) {
                    snprintf(path, sizeof(path), "$.AES.%d.Key", i);
                    JsonSaveBufAsHexCompact(root, path, &dvdata[2][i][1], AES_KEY_LEN);
                }
                if (dvdata[3][i][0]) {
                    snprintf(path, sizeof(path), "$.K3KDES.%d.Key", i);
                    JsonSaveBufAsHexCompact(root, path, &dvdata[3][i][1], T3DES_KEY_LEN);
                }
            }
            break;
        }
        case jsfCustom: {
            (*callback)(root);
            break;
        }
        case jsfTopaz: {
            topaz_tag_t *tag = (topaz_tag_t *)(void *) data;
            JsonSaveStr(root, "FileType", "topaz");
            JsonSaveBufAsHexCompact(root, "$.Card.UID", tag->uid, sizeof(tag->uid));
            JsonSaveBufAsHexCompact(root, "$.Card.H0R1", tag->HR01, sizeof(tag->HR01));
            JsonSaveBufAsHexCompact(root, "$.Card.Size", (uint8_t *) & (tag->size), 2);

            for (size_t i = 0; i < TOPAZ_STATIC_MEMORY / 8; i++) {
                snprintf(path, sizeof(path), "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, &tag->data_blocks[i][0], TOPAZ_BLOCK_SIZE);
            }

            // ICEMAN todo:  add dynamic memory.
            // uint16_z Size
            // uint8_t *dynamic_memory;

            break;
        }
        case jsfLto: {
            JsonSaveStr(root, "FileType", "lto");
            for (size_t i = 0; i < datalen / 32; i++) {
                snprintf(path, sizeof(path), "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, &data[i * 32], 32);
            }
            break;
        }
        case jsfCryptorf: {
            JsonSaveStr(root, "FileType", "cryptorf");
            for (size_t i = 0; i < datalen / 8; i++) {
                snprintf(path, sizeof(path), "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, &data[i * 8], 8);
            }
            break;
        }
        case jsfNDEF: {
            JsonSaveStr(root, "FileType", "ndef");
            JsonSaveInt(root, "Ndef.Size", datalen);
            size_t i = 0;
            for (; i < datalen / 16; i++) {
                snprintf(path, sizeof(path), "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, &data[i * 16], 16);
            }
            if (datalen % 16) {
                snprintf(path, sizeof(path), "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, &data[i * 16], (datalen % 16));
            }
            break;
        }
        case jsfFM11RF08SNonces:
        case jsfFM11RF08SNoncesWithData: {
            if (datalen != sizeof(iso14a_fm11rf08s_nonces_with_data_t)) {
                return PM3_EINVARG;
            }
            iso14a_fm11rf08s_nonces_with_data_t *p = (iso14a_fm11rf08s_nonces_with_data_t *)data;
            if (ftype == jsfFM11RF08SNoncesWithData) {
                JsonSaveStr(root, "FileType", "fm11rf08s_nonces_with_data");
            } else {
                JsonSaveStr(root, "FileType", "fm11rf08s_nonces");
            }
            for (uint16_t sec = 0; sec < MIFARE_1K_MAXSECTOR + 1; sec++) {
                uint8_t par2[2];
                uint8_t par;
                uint16_t real_sec = sec;
                if (sec == MIFARE_1K_MAXSECTOR) {
                    real_sec = 32; // advanced verification method block
                }
                snprintf(path, sizeof(path), "$.nt.%u.a", real_sec);
                JsonSaveBufAsHexCompact(root, path, p->nt[sec][0], 4);
                snprintf(path, sizeof(path), "$.nt.%u.b", real_sec);
                JsonSaveBufAsHexCompact(root, path, p->nt[sec][1], 4);
                snprintf(path, sizeof(path), "$.nt_enc.%u.a", real_sec);
                JsonSaveBufAsHexCompact(root, path, p->nt_enc[sec][0], 4);
                snprintf(path, sizeof(path), "$.nt_enc.%u.b", real_sec);
                JsonSaveBufAsHexCompact(root, path, p->nt_enc[sec][1], 4);

                snprintf(path, sizeof(path), "$.par_err.%u.a", real_sec);
                par = p->par_err[sec][0];
                par2[0] = (((par >> 3) & 1) << 4) | ((par >> 2) & 1);
                par2[1] = (((par >> 1) & 1) << 4) | ((par >> 0) & 1);
                JsonSaveBufAsHexCompact(root, path, par2, 2);
                snprintf(path, sizeof(path), "$.par_err.%u.b", real_sec);
                par = p->par_err[sec][1];
                par2[0] = (((par >> 3) & 1) << 4) | ((par >> 2) & 1);
                par2[1] = (((par >> 1) & 1) << 4) | ((par >> 0) & 1);
                JsonSaveBufAsHexCompact(root, path, par2, 2);
            }
            if (ftype == jsfFM11RF08SNoncesWithData) {
                for (uint16_t blk = 0; blk < MIFARE_1K_MAXBLOCK; blk++) {
                    snprintf(path, sizeof(path), "$.blocks.%u", blk);
                    JsonSaveBufAsHexCompact(root, path, p->blocks[blk], MFBLOCK_SIZE);
                }
            }
            break;
        }
        // no action
        case jsfFido:
            break;
        // depricated
        case jsfCardMemory:
        case jsf14b:
        case jsf15:
        case jsf15_v2:
        case jsf15_v3:
        case jsfLegic:
        default:
            break;
    }
    return PM3_SUCCESS;
}

// dump file (normally,  we also got preference file, etc)
int saveFileJSON(const char *preferredName, JSONFileType ftype, uint8_t *data, size_t datalen, void (*callback)(json_t *)) {
    return saveFileJSONex(preferredName, ftype, data, datalen, true, callback, spDump);
}

int saveFileJSONex(const char *preferredName, JSONFileType ftype, uint8_t *data, size_t datalen, bool verbose, void (*callback)(json_t *), savePaths_t e_save_path) {

    int retval = PM3_SUCCESS;

    json_t *root = json_object();
    retval = prepareJSON(root, ftype, data, datalen, verbose, callback);
    if (retval != PM3_SUCCESS) {
        return retval;
    }
    retval = saveFileJSONrootEx(preferredName, root, JSON_INDENT(2), verbose, false, e_save_path);
    json_decref(root);
    return retval;
}

int saveFileJSONroot(const char *preferredName, void *root, size_t flags, bool verbose) {
    return saveFileJSONrootEx(preferredName, root, flags, verbose, false, spDump);
}

int saveFileJSONrootEx(const char *preferredName, const void *root, size_t flags, bool verbose, bool overwrite, savePaths_t e_save_path) {
    if (root == NULL)
        return PM3_EINVARG;

    char *filename = NULL;
    if (overwrite)
        filename = filenamemcopy(preferredName, ".json");
    else
        filename = newfilenamemcopyEx(preferredName, ".json", e_save_path);

    if (filename == NULL)
        return PM3_EMALLOC;

    int res = json_dump_file(root, filename, flags);

    if (res == 0) {
        if (verbose) {
            PrintAndLogEx(SUCCESS, "Saved to json file `" _YELLOW_("%s") "`", filename);
        }
        free(filename);
        return PM3_SUCCESS;
    } else {
        PrintAndLogEx(FAILED, "error, can't save the file `" _YELLOW_("%s") "`", filename);
    }
    free(filename);
    return PM3_EFILE;
}

char *sprintJSON(JSONFileType ftype, uint8_t *data, size_t datalen, bool verbose, void (*callback)(json_t *)) {

    json_t *root = json_object();
    if (prepareJSON(root, ftype, data, datalen, verbose, callback) != PM3_SUCCESS) {
        return NULL;
    }
    char *s = json_dumps(root, JSON_INDENT(2));
    json_decref(root);
    return s;
}

// wave file of trace,
int saveFileWAVE(const char *preferredName, const int *data, size_t datalen) {

    if (data == NULL || datalen == 0) {
        return PM3_EINVARG;
    }

    char *fileName = newfilenamemcopyEx(preferredName, ".wav", spTrace);
    if (fileName == NULL) {
        return PM3_EMALLOC;
    }

    int retval = PM3_SUCCESS;

    struct wave_info_t wave_info = {
        .signature = "RIFF",
        .filesize = sizeof(wave_info) - sizeof(wave_info.signature) - sizeof(wave_info.filesize) + datalen,
        .type = "WAVE",
        .format.tag = "fmt ",
        .format.size = sizeof(wave_info.format) - sizeof(wave_info.format.tag) - sizeof(wave_info.format.size),
        .format.codec = 1, // PCM
        .format.nb_channel = 1,
        .format.sample_per_sec = 125000,  // TODO update for other tag types
        .format.byte_per_sec = 125000,    // TODO update for other tag types
        .format.block_align = 1,
        .format.bit_per_sample = 8,
        .audio_data.tag = "data",
        .audio_data.size = datalen,
    };

    FILE *wave_file = fopen(fileName, "wb");
    if (!wave_file) {
        PrintAndLogEx(WARNING, "file not found or locked `" _YELLOW_("%s") "`", fileName);
        retval = PM3_EFILE;
        goto out;
    }

    fwrite(&wave_info, sizeof(wave_info), 1, wave_file);

    for (int i = 0; i < datalen; i++) {
        uint8_t sample = data[i] + 128;
        fwrite(&sample, 1, 1, wave_file);
    }

    fclose(wave_file);

    PrintAndLogEx(SUCCESS, "Saved " _YELLOW_("%zu") " bytes to wave file `" _YELLOW_("%s") "`", 2 * datalen, fileName);

out:
    free(fileName);
    return retval;
}

// Signal trace file, PM3
int saveFilePM3(const char *preferredName, int *data, size_t datalen) {

    if (data == NULL || datalen == 0) {
        return PM3_EINVARG;
    }

    char *fileName = newfilenamemcopyEx(preferredName, ".pm3", spTrace);
    if (fileName == NULL) {
        return PM3_EMALLOC;
    }

    int retval = PM3_SUCCESS;

    FILE *f = fopen(fileName, "w");
    if (!f) {
        PrintAndLogEx(WARNING, "file not found or locked `" _YELLOW_("%s") "`", fileName);
        retval = PM3_EFILE;
        goto out;
    }

    for (uint32_t i = 0; i < datalen; i++) {
        fprintf(f, "%d\n", data[i]);
    }

    fflush(f);
    fclose(f);
    PrintAndLogEx(SUCCESS, "Saved " _YELLOW_("%zu") " bytes to PM3 file `" _YELLOW_("%s") "`", datalen, fileName);

out:
    free(fileName);
    return retval;
}

// key file dump
int createMfcKeyDump(const char *preferredName, uint8_t sectorsCnt, const sector_t *e_sector) {

    if (e_sector == NULL) return PM3_EINVARG;

    char *fileName = newfilenamemcopyEx(preferredName, ".bin", spDump);
    if (fileName == NULL) return PM3_EMALLOC;

    FILE *f = fopen(fileName, "wb");
    if (f == NULL) {
        PrintAndLogEx(WARNING, "could not create file `" _YELLOW_("%s") "`", fileName);
        free(fileName);
        return PM3_EFILE;
    }
    PrintAndLogEx(SUCCESS, "Generating binary key file");

    uint8_t empty[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t tmp[6] = {0, 0, 0, 0, 0, 0};

    for (int i = 0; i < sectorsCnt; i++) {
        if (e_sector[i].foundKey[0])
            num_to_bytes(e_sector[i].Key[0], sizeof(tmp), tmp);
        else
            memcpy(tmp, empty, sizeof(tmp));
        fwrite(tmp, 1, sizeof(tmp), f);
    }

    for (int i = 0; i < sectorsCnt; i++) {
        if (e_sector[i].foundKey[0])
            num_to_bytes(e_sector[i].Key[1], sizeof(tmp), tmp);
        else
            memcpy(tmp, empty, sizeof(tmp));
        fwrite(tmp, 1, sizeof(tmp), f);
    }

    fflush(f);
    fclose(f);
    PrintAndLogEx(SUCCESS, "Found keys have been dumped to `" _YELLOW_("%s") "`", fileName);
    PrintAndLogEx(INFO, "--[ " _YELLOW_("FFFFFFFFFFFF") " ]-- has been inserted for unknown keys where " _YELLOW_("res") " is " _RED_("0"));
    free(fileName);
    return PM3_SUCCESS;
}

// --------- LOAD FILES
int loadFile_safe(const char *preferredName, const char *suffix, void **pdata, size_t *datalen) {
    return loadFile_safeEx(preferredName, suffix, pdata, datalen, true);
}
int loadFile_safeEx(const char *preferredName, const char *suffix, void **pdata, size_t *datalen, bool verbose) {

    char *path;
    int res = searchFile(&path, RESOURCES_SUBDIR, preferredName, suffix, false);
    if (res != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        PrintAndLogEx(WARNING, "file not found or locked `" _YELLOW_("%s") "`", path);
        free(path);
        return PM3_EFILE;
    }
    free(path);

    // get filesize in order to malloc memory
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0) {
        PrintAndLogEx(FAILED, "error, when getting filesize");
        fclose(f);
        return PM3_EFILE;
    }

    *pdata = calloc(fsize, sizeof(uint8_t));
    if (!*pdata) {
        PrintAndLogEx(FAILED, "error, cannot allocate memory");
        fclose(f);
        return PM3_EMALLOC;
    }

    size_t bytes_read = fread(*pdata, 1, fsize, f);

    fclose(f);

    if (bytes_read != fsize) {
        PrintAndLogEx(FAILED, "error, bytes read mismatch file size");
        free(*pdata);
        return PM3_EFILE;
    }

    *datalen = bytes_read;

    if (verbose) {
        PrintAndLogEx(SUCCESS, "Loaded " _YELLOW_("%zu") " bytes from binary file `" _YELLOW_("%s") "`", bytes_read, preferredName);
    }
    return PM3_SUCCESS;
}

int loadFileEML_safe(const char *preferredName, void **pdata, size_t *datalen) {
    char *path;
    int res = searchFile(&path, RESOURCES_SUBDIR, preferredName, "", false);
    if (res != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    FILE *f = fopen(path, "r");
    if (!f) {
        PrintAndLogEx(WARNING, "file not found or locked `" _YELLOW_("%s") "`", path);
        free(path);
        return PM3_EFILE;
    }
    free(path);

    // get filesize in order to malloc memory
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0) {
        PrintAndLogEx(FAILED, "error, when getting filesize");
        fclose(f);
        return PM3_EFILE;
    }

    *pdata = calloc(fsize, sizeof(uint8_t));
    if (!*pdata) {
        PrintAndLogEx(FAILED, "error, cannot allocate memory");
        fclose(f);
        return PM3_EMALLOC;
    }

    // 128 + 2 newline chars + 1 null terminator
    char line[131];
    memset(line, 0, sizeof(line));
    uint8_t buf[64] = {0x00};
    size_t counter = 0;
    int retval = PM3_SUCCESS, hexlen = 0;

    uint8_t *tmp = (uint8_t *)*pdata;

    while (!feof(f)) {

        memset(line, 0, sizeof(line));

        if (fgets(line, sizeof(line), f) == NULL) {
            if (feof(f))
                break;

            fclose(f);
            PrintAndLogEx(FAILED, "file reading error");
            return PM3_EFILE;
        }

        if (line[0] == '#')
            continue;

        str_cleanrn(line, sizeof(line));

        res = param_gethex_to_eol(line, 0, buf, sizeof(buf), &hexlen);
        if (res == 0) {
            memcpy(tmp + counter, buf, hexlen);
            counter += hexlen;
        } else {
            retval = PM3_ESOFT;
        }
    }
    fclose(f);
    PrintAndLogEx(SUCCESS, "Loaded " _YELLOW_("%zu") " bytes from text file `" _YELLOW_("%s") "`", counter, preferredName);


    uint8_t *newdump = realloc(*pdata, counter);
    if (newdump == NULL) {
        free(*pdata);
        return PM3_EMALLOC;
    } else {
        *pdata = newdump;
    }

    if (datalen)
        *datalen = counter;

    return retval;
}

int loadFileNFC_safe(const char *preferredName, void *data, size_t maxdatalen, size_t *datalen, nfc_df_e ft) {

    if (data == NULL) return PM3_EINVARG;

    *datalen = 0;
    int retval = PM3_SUCCESS;

    char *path;
    int res = searchFile(&path, RESOURCES_SUBDIR, preferredName, "", false);
    if (res != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    FILE *f = fopen(path, "r");
    if (!f) {
        PrintAndLogEx(WARNING, "file not found or locked `" _YELLOW_("%s") "`", path);
        free(path);
        return PM3_EFILE;
    }
    free(path);

    // 256 + 2 newline chars + 1 null terminator
    char line[256 + 2 + 1];
    memset(line, 0, sizeof(line));

    udata_t udata = (udata_t)data;
    int n = 0;
    uint32_t counter = 0;

    while (!feof(f)) {

        memset(line, 0, sizeof(line));

        if (fgets(line, sizeof(line), f) == NULL) {
            if (feof(f))
                break;

            fclose(f);
            PrintAndLogEx(FAILED, "file reading error");
            return PM3_EFILE;
        }

        if (line[0] == '#')
            continue;

        str_cleanrn(line, sizeof(line));
        str_lower(line);

        if (str_startswith(line, "uid:")) {
            if (ft == NFC_DF_MFC) {
//                param_gethex_to_eol(line + 4, 0, udata.mfc->card_info.uid, sizeof(udata.mfc->card_info.uid), &n);
            }
            continue;
        }

        if (str_startswith(line, "atqa:")) {
            if (ft == NFC_DF_MFC) {
//                param_gethex_to_eol(line + 5, 0, udata.mfc->card_info.atqa, sizeof(udata.mfc->card_info.atqa), &n);
            }
            continue;
        }

        if (str_startswith(line, "sak:")) {
            if (ft == NFC_DF_MFC) {
                int sak = 0;
                sscanf(line, "sak: %d", &sak);
//                udata.mfc->card_info.sak = sak & 0xFF;
            }
            continue;
        }

        if (str_startswith(line, "signature:")) {
            if (ft == NFC_DF_MFC) {
            } else if (ft == NFC_DF_MFU) {
                param_gethex_to_eol(line + 11, 0, udata.mfu->signature, sizeof(udata.mfu->signature), &n);
            }
            continue;
        }

        if (str_startswith(line, "mifare version:")) {
            if (ft == NFC_DF_MFC) {
            } else if (ft == NFC_DF_MFU) {
                param_gethex_to_eol(line + 16, 0, udata.mfu->version, sizeof(udata.mfu->version), &n);
            }
            continue;
        }

        if (str_startswith(line, "counter 0:")) {
            int no = 0;
            sscanf(line, "counter 0: %d", &no);
            if (ft == NFC_DF_MFC) {
            } else if (ft == NFC_DF_MFU) {
                udata.mfu->counter_tearing[0][0] = no & 0xFF;
                udata.mfu->counter_tearing[0][1] = no & 0xFF;
                udata.mfu->counter_tearing[0][2] = no & 0xFF;
            }
            continue;
        }

        if (str_startswith(line, "tearing 0:")) {
            if (ft == NFC_DF_MFC) {
            } else if (ft == NFC_DF_MFU) {
                uint32_t b = 0;
                sscanf(line, "tearing 0: %02x", &b);
                udata.mfu->counter_tearing[0][3] = b & 0xFF;
            }
            continue;
        }

        if (str_startswith(line, "counter 1:")) {
            int no = 0;
            sscanf(line, "counter 1: %d", &no);
            if (ft == NFC_DF_MFC) {
            } else if (ft == NFC_DF_MFU) {
                udata.mfu->counter_tearing[1][0] = no & 0xFF;
                udata.mfu->counter_tearing[1][1] = no & 0xFF;
                udata.mfu->counter_tearing[1][2] = no & 0xFF;
            }
            continue;
        }

        if (str_startswith(line, "tearing 1:")) {
            if (ft == NFC_DF_MFC) {
            } else if (ft == NFC_DF_MFU) {
                uint32_t b = 0;
                sscanf(line, "tearing 1: %02x", &b);
                udata.mfu->counter_tearing[1][3] = b & 0xFF;
            }
            continue;
        }

        if (str_startswith(line, "counter 2:")) {
            int no = 0;
            sscanf(line, "counter 2: %d", &no);
            if (ft == NFC_DF_MFC) {
            } else if (ft == NFC_DF_MFU) {
                udata.mfu->counter_tearing[2][0] = no & 0xFF;
                udata.mfu->counter_tearing[2][1] = no & 0xFF;
                udata.mfu->counter_tearing[2][2] = no & 0xFF;
            }
            continue;
        }

        if (str_startswith(line, "tearing 2:")) {
            if (ft == NFC_DF_MFC) {
            } else if (ft == NFC_DF_MFU) {
                uint32_t b = 0;
                sscanf(line, "tearing 2: %02x", &b);
                udata.mfu->counter_tearing[2][3] = b & 0xFF;
            }
            continue;
        }

        if (str_startswith(line, "pages total:")) {
            sscanf(line, "pages total: %d", &n);
            if (ft == NFC_DF_MFC) {
            } else if (ft == NFC_DF_MFU) {
                udata.mfu->pages = n;
            }
            continue;
        }

        // Page 0: 04 10 56 CA
        if (str_startswith(line, "page ")) {
            int pageno = 0;
            sscanf(line, "page %d:", &pageno);

            if (strcmp(line, "??") == 0) {
                PrintAndLogEx(INFO, "missing data detected in page %i,  skipping...", pageno);
                continue;
            }

            if (((pageno * MFU_BLOCK_SIZE) + MFU_BLOCK_SIZE) > maxdatalen) {
                continue;
            }

            char *p = line;
            while (*p++ != ':') {};
            p++;

            if (ft == NFC_DF_MFU) {
                n = 0;
                param_gethex_to_eol(p, 0, udata.mfu->data + (pageno * MFU_BLOCK_SIZE), MFU_BLOCK_SIZE, &n);
                *datalen += MFU_BLOCK_SIZE;
            }
            continue;
        }

        // Block 0: 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
        if (str_startswith(line, "block ")) {
            int blockno = 0;
            sscanf(line, "block %d:", &blockno);

            if (strcmp(line, "??") == 0) {
                PrintAndLogEx(INFO, "missing data detected in block %i,  skipping...", blockno);
                continue;
            }

            if (((blockno * MFBLOCK_SIZE) + MFBLOCK_SIZE) > maxdatalen) {
                continue;
            }

            char *p = line;
            while (*p++ != ':') {};
            p++;

            if (ft == NFC_DF_MFC) {
                uint8_t block[MFBLOCK_SIZE] = {0};
                param_gethex_to_eol(p, 0, block, MFBLOCK_SIZE, &n);
                memcpy(&udata.bytes[(blockno * MFBLOCK_SIZE)], block, MFBLOCK_SIZE);
                counter += MFBLOCK_SIZE;
            } else if (ft == NFC_DF_PICOPASS) {
                uint8_t block[PICOPASS_BLOCK_SIZE] = {0};
                param_gethex_to_eol(p, 0, block, PICOPASS_BLOCK_SIZE, &n);
                memcpy(&udata.bytes[(blockno * PICOPASS_BLOCK_SIZE)], block, PICOPASS_BLOCK_SIZE);
                counter += PICOPASS_BLOCK_SIZE;
            }
            continue;
        }
    }

    // add header length
    if (ft == NFC_DF_MFC || ft == NFC_DF_PICOPASS) {
        *datalen = counter;
    } else if (ft == NFC_DF_MFU) {
        *datalen += MFU_DUMP_PREFIX_LENGTH;
    }

    fclose(f);
    PrintAndLogEx(SUCCESS, "Loaded " _YELLOW_("%zu") " bytes from NFC file `" _YELLOW_("%s") "`", *datalen, preferredName);
    return retval;
}

int loadFileMCT_safe(const char *preferredName, void **pdata, size_t *datalen) {
    char *path;
    int res = searchFile(&path, RESOURCES_SUBDIR, preferredName, "", false);
    if (res != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    FILE *f = fopen(path, "r");
    if (!f) {
        PrintAndLogEx(WARNING, "file not found or locked `" _YELLOW_("%s") "`", path);
        free(path);
        return PM3_EFILE;
    }
    free(path);

    // get filesize in order to malloc memory
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0) {
        PrintAndLogEx(FAILED, "error, when getting filesize");
        fclose(f);
        return PM3_EFILE;
    }

    *pdata = calloc(fsize, sizeof(uint8_t));
    if (!*pdata) {
        PrintAndLogEx(FAILED, "error, cannot allocate memory");
        fclose(f);
        return PM3_EMALLOC;
    }

    // 128 + 2 newline chars + 1 null terminator
    char line[131];
    memset(line, 0, sizeof(line));
    uint8_t buf[64] = {0x00};
    size_t counter = 0;
    int retval = PM3_SUCCESS, hexlen = 0;

    uint8_t *tmp = (uint8_t *)*pdata;

    while (!feof(f)) {

        memset(line, 0, sizeof(line));

        if (fgets(line, sizeof(line), f) == NULL) {
            if (feof(f))
                break;

            fclose(f);
            PrintAndLogEx(FAILED, "file reading error");
            return PM3_EFILE;
        }

        // skip lines like "+Sector:"
        if (line[0] == '+')
            continue;

        str_cleanrn(line, sizeof(line));

        res = param_gethex_to_eol(line, 0, buf, sizeof(buf), &hexlen);
        if (res == 0) {
            memcpy(tmp + counter, buf, hexlen);
            counter += hexlen;
        } else {
            retval = PM3_ESOFT;
        }
    }
    fclose(f);
    PrintAndLogEx(SUCCESS, "Loaded " _YELLOW_("%zu") " bytes from MCT file `" _YELLOW_("%s") "`", counter, preferredName);


    uint8_t *newdump = realloc(*pdata, counter);
    if (newdump == NULL) {
        free(*pdata);
        return PM3_EMALLOC;
    } else {
        *pdata = newdump;
    }

    if (datalen)
        *datalen = counter;

    return retval;
}

static int load_file_sanity(char *s, uint32_t datalen, int i, size_t len) {
    if (len == 0) {
        PrintAndLogEx(DEBUG, "WARNING: json %s block %d has zero-length data", s, i);
        PrintAndLogEx(DEBUG, "File parsing stopped");
        return false;
    } else if (len != datalen) {
        PrintAndLogEx(WARNING, "WARNING: json %s block %d only has %zu bytes", s, i, len);
        PrintAndLogEx(INFO, "Expected %d - padding with zeros", datalen);
    }
    return true;
}

int loadFileJSON(const char *preferredName, void *data, size_t maxdatalen, size_t *datalen, void (*callback)(json_t *)) {
    return loadFileJSONex(preferredName, data, maxdatalen, datalen, true, callback);
}
int loadFileJSONex(const char *preferredName, void *data, size_t maxdatalen, size_t *datalen, bool verbose, void (*callback)(json_t *)) {

    if (data == NULL) return PM3_EINVARG;

    *datalen = 0;
    int retval = PM3_SUCCESS;

    char *path;
    int res = searchFile(&path, RESOURCES_SUBDIR, preferredName, ".json", false);
    if (res != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    json_error_t error;
    json_t *root = json_load_file(path, 0, &error);
    if (verbose) {
        PrintAndLogEx(SUCCESS, "loaded `" _YELLOW_("%s") "`", path);
    }

    free(path);

    if (!root) {
        PrintAndLogEx(ERR, "error, json " _YELLOW_("%s") " error on line %d: %s", preferredName, error.line, error.text);
        retval = PM3_ESOFT;
        goto out;
    }

    if (!json_is_object(root)) {
        PrintAndLogEx(ERR, "error, invalid json " _YELLOW_("%s") " format. root must be an object.", preferredName);
        retval = PM3_ESOFT;
        goto out;
    }

    char ctype[100] = {0};
    JsonLoadStr(root, "$.FileType", ctype);

    // Proxmark3 settings file.  Nothing to do except call the callback function
    if (!strcmp(ctype, "settings")) {
        goto out;
    }

    udata_t udata = (udata_t)data;

    size_t len = 0;
    char blocks[PATH_MAX_LENGTH] = {0};

    if (!strcmp(ctype, "raw")) {
        JsonLoadBufAsHex(root, "$.raw", udata.bytes, maxdatalen, datalen);
        goto out;
    }

    // depricated mfcard
    if (!strcmp(ctype, "mfcard") || !strcmp(ctype, "mfc v2")) {
        size_t sptr = 0;
        // load blocks (i) from 0..N, but check sptr against total data length, not `i`
        for (int i = 0; sptr < maxdatalen; i++) {
            if (sptr + MFBLOCK_SIZE > maxdatalen) {
                PrintAndLogEx(ERR, "loadFileJSONex: maxdatalen=%zu (%04zx)   block (i)=%4d (%04x)   sptr=%zu (%04zx) -- exceeded maxdatalen", maxdatalen, maxdatalen, i, i, sptr, sptr);
                retval = PM3_EMALLOC;
                goto out;
            }

            snprintf(blocks, sizeof(blocks), "$.blocks.%d", i);
            uint8_t block[MFBLOCK_SIZE] = {0}; // ensure zero-filled when partial block of data read
            JsonLoadBufAsHex(root, blocks, block, MFBLOCK_SIZE, &len);
            if (load_file_sanity(ctype, MFBLOCK_SIZE, i, len) == false) {
                break;
            }

            memcpy(&udata.bytes[sptr], block, MFBLOCK_SIZE);
            sptr += MFBLOCK_SIZE; // always increment pointer by the full block size, even if only partial data read from dump file
        }

        *datalen = sptr;
        goto out;
    }

    if (!strcmp(ctype, "mfc v3")) {

        JsonLoadBufAsHex(root, "$.Card.UID", udata.mfc_ev1->card.ev1.uid, udata.mfc_ev1->card.ev1.uidlen, datalen);
        JsonLoadBufAsHex(root, "$.Card.ATQA", udata.mfc_ev1->card.ev1.atqa, 2, datalen);
        JsonLoadBufAsHex(root, "$.Card.SAK", &(udata.mfc_ev1->card.ev1.sak), 1, datalen);
        JsonLoadBufAsHex(root, "$.Card.ATS", udata.mfc_ev1->card.ev1.ats, sizeof(udata.mfc_ev1->card.ev1.ats_len), datalen);
        JsonLoadBufAsHex(root, "$.Card.SIGNATURE", udata.mfc_ev1->card.ev1.signature, sizeof(udata.mfc_ev1->card.ev1.signature), datalen);

        *datalen = MFU_DUMP_PREFIX_LENGTH;

        size_t sptr = 0;
        // load blocks (i) from 0..N, but check sptr against total data length, not `i`
        for (int i = 0; sptr < maxdatalen; i++) {
            if (sptr + MFBLOCK_SIZE > maxdatalen) {
                PrintAndLogEx(ERR, "loadFileJSONex: maxdatalen=%zu (%04zx)   block (i)=%4d (%04x)   sptr=%zu (%04zx) -- exceeded maxdatalen", maxdatalen, maxdatalen, i, i, sptr, sptr);
                retval = PM3_EMALLOC;
                goto out;
            }

            snprintf(blocks, sizeof(blocks), "$.blocks.%d", i);
            uint8_t block[MFBLOCK_SIZE] = {0}; // ensure zero-filled when partial block of data read
            JsonLoadBufAsHex(root, blocks, block, MFBLOCK_SIZE, &len);

            if (load_file_sanity(ctype, MFBLOCK_SIZE, i, len) == false) {
                break;
            }

            memcpy(&udata.bytes[sptr], block, MFBLOCK_SIZE);
            sptr += MFBLOCK_SIZE; // always increment pointer by the full block size, even if only partial data read from dump file
        }

        *datalen = sptr;
        goto out;
    }

    if (!strcmp(ctype, "fudan")) {
        size_t sptr = 0;
        for (int i = 0; i < maxdatalen; i++) {
            if (sptr + 4 > maxdatalen) {
                PrintAndLogEx(ERR, "loadFileJSONex: maxdatalen=%zu (%04zx)   block (i)=%4d (%04x)   sptr=%zu (%04zx) -- exceeded maxdatalen", maxdatalen, maxdatalen, i, i, sptr, sptr);
                retval = PM3_EMALLOC;
                goto out;
            }

            snprintf(blocks, sizeof(blocks), "$.blocks.%d", i);
            JsonLoadBufAsHex(root, blocks, &udata.bytes[sptr], 4, &len);

            if (load_file_sanity(ctype, 4, i, len) == false) {
                break;
            }
            sptr += len;
        }

        *datalen = sptr;
        goto out;
    }

    if (!strcmp(ctype, "mfu")) {

        JsonLoadBufAsHex(root, "$.Card.Version", udata.mfu->version, sizeof(udata.mfu->version), datalen);
        JsonLoadBufAsHex(root, "$.Card.TBO_0", udata.mfu->tbo, sizeof(udata.mfu->tbo), datalen);
        JsonLoadBufAsHex(root, "$.Card.TBO_1", udata.mfu->tbo1, sizeof(udata.mfu->tbo1), datalen);
        JsonLoadBufAsHex(root, "$.Card.Signature", udata.mfu->signature, sizeof(udata.mfu->signature), datalen);
        JsonLoadBufAsHex(root, "$.Card.Counter0", &udata.mfu->counter_tearing[0][0], 3, datalen);
        JsonLoadBufAsHex(root, "$.Card.Tearing0", &udata.mfu->counter_tearing[0][3], 1, datalen);
        JsonLoadBufAsHex(root, "$.Card.Counter1", &udata.mfu->counter_tearing[1][0], 3, datalen);
        JsonLoadBufAsHex(root, "$.Card.Tearing1", &udata.mfu->counter_tearing[1][3], 1, datalen);
        JsonLoadBufAsHex(root, "$.Card.Counter2", &udata.mfu->counter_tearing[2][0], 3, datalen);
        JsonLoadBufAsHex(root, "$.Card.Tearing2", &udata.mfu->counter_tearing[2][3], 1, datalen);
        *datalen = MFU_DUMP_PREFIX_LENGTH;

        size_t sptr = 0;
        for (int i = 0; i < 256; i++) {
            if (sptr + 4 > maxdatalen) {
                PrintAndLogEx(ERR, "loadFileJSONex: maxdatalen=%zu (%04zx)   block (i)=%4d (%04x)   sptr=%zu (%04zx) -- exceeded maxdatalen", maxdatalen, maxdatalen, i, i, sptr, sptr);
                retval = PM3_EMALLOC;
                goto out;
            }

            snprintf(blocks, sizeof(blocks), "$.blocks.%d", i);
            JsonLoadBufAsHex(root, blocks, &udata.mfu->data[sptr], MFU_BLOCK_SIZE, &len);

            if (load_file_sanity(ctype, MFU_BLOCK_SIZE, i, len) == false) {
                break;
            }

            sptr += len;
            udata.mfu->pages++;
        }
        // remove one, since pages indicates a index rather than number of available pages
        --udata.mfu->pages;

        *datalen += sptr;
        goto out;
    }

    if (!strcmp(ctype, "hitag")) {
        size_t sptr = 0;
        for (int i = 0; i < (maxdatalen / 4); i++) {
            if (sptr + 4 > maxdatalen) {
                PrintAndLogEx(ERR, "loadFileJSONex: maxdatalen=%zu (%04zx)   block (i)=%4d (%04x)   sptr=%zu (%04zx) -- exceeded maxdatalen", maxdatalen, maxdatalen, i, i, sptr, sptr);
                retval = PM3_EMALLOC;
                goto out;
            }

            snprintf(blocks, sizeof(blocks), "$.blocks.%d", i);
            JsonLoadBufAsHex(root, blocks, &udata.bytes[sptr], 4, &len);
            if (load_file_sanity(ctype, 4, i, len) == false) {
                break;
            }

            sptr += len;
        }

        *datalen = sptr;
        goto out;
    }

    if (!strcmp(ctype, "iclass")) {
        size_t sptr = 0;
        for (int i = 0; i < (maxdatalen / PICOPASS_BLOCK_SIZE); i++) {
            if (sptr + PICOPASS_BLOCK_SIZE > maxdatalen) {
                PrintAndLogEx(ERR, "loadFileJSONex: maxdatalen=%zu (%04zx)   block (i)=%4d (%04x)   sptr=%zu (%04zx) -- exceeded maxdatalen", maxdatalen, maxdatalen, i, i, sptr, sptr);
                retval = PM3_EMALLOC;
                goto out;
            }

            snprintf(blocks, sizeof(blocks), "$.blocks.%d", i);
            JsonLoadBufAsHex(root, blocks, &udata.bytes[sptr], PICOPASS_BLOCK_SIZE, &len);
            if (load_file_sanity(ctype, PICOPASS_BLOCK_SIZE, i, len) == false) {
                break;
            }

            sptr += len;
        }
        *datalen = sptr;
        goto out;
    }

    if (!strcmp(ctype, "t55x7")) {
        size_t sptr = 0;
        for (int i = 0; i < (maxdatalen / 4); i++) {
            if (sptr + 4 > maxdatalen) {
                PrintAndLogEx(ERR, "loadFileJSONex: maxdatalen=%zu (%04zx)   block (i)=%4d (%04x)   sptr=%zu (%04zx) -- exceeded maxdatalen", maxdatalen, maxdatalen, i, i, sptr, sptr);
                retval = PM3_EMALLOC;
                goto out;
            }

            snprintf(blocks, sizeof(blocks), "$.blocks.%d", i);
            JsonLoadBufAsHex(root, blocks, &udata.bytes[sptr], 4, &len);
            if (load_file_sanity(ctype, 4, i, len) == false) {
                break;
            }

            sptr += len;
        }
        *datalen = sptr;
        goto out;
    }

    if (!strcmp(ctype, "EM4205/EM4305")) {
        size_t sptr = 0;
        for (int i = 0; i < (maxdatalen / 4); i++) {
            if (sptr + 4 > maxdatalen) {
                PrintAndLogEx(ERR, "loadFileJSONex: maxdatalen=%zu (%04zx)   block (i)=%4d (%04x)   sptr=%zu (%04zx) -- exceeded maxdatalen", maxdatalen, maxdatalen, i, i, sptr, sptr);
                retval = PM3_EMALLOC;
                goto out;
            }

            snprintf(blocks, sizeof(blocks), "$.blocks.%d", i);
            JsonLoadBufAsHex(root, blocks, &udata.bytes[sptr], 4, &len);
            if (load_file_sanity(ctype, 4, i, len) == false) {
                break;
            }

            sptr += len;
        }
        *datalen = sptr;
        goto out;
    }

    if (!strcmp(ctype, "EM4469/EM4569")) {
        size_t sptr = 0;
        for (int i = 0; i < (maxdatalen / 4); i++) {
            if (sptr + 4 > maxdatalen) {
                PrintAndLogEx(ERR, "loadFileJSONex: maxdatalen=%zu (%04zx)   block (i)=%4d (%04x)   sptr=%zu (%04zx) -- exceeded maxdatalen", maxdatalen, maxdatalen, i, i, sptr, sptr);
                retval = PM3_EMALLOC;
                goto out;
            }

            snprintf(blocks, sizeof(blocks), "$.blocks.%d", i);
            JsonLoadBufAsHex(root, blocks, &udata.bytes[sptr], 4, &len);
            if (load_file_sanity(ctype, 4, i, len) == false) {
                break;
            }

            sptr += len;
        }
        *datalen = sptr;
        goto out;
    }

    if (!strcmp(ctype, "EM4X50")) {
        size_t sptr = 0;
        for (int i = 0; i < (maxdatalen / 4); i++) {
            if (sptr + 4 > maxdatalen) {
                PrintAndLogEx(ERR, "loadFileJSONex: maxdatalen=%zu (%04zx)   block (i)=%4d (%04x)   sptr=%zu (%04zx) -- exceeded maxdatalen", maxdatalen, maxdatalen, i, i, sptr, sptr);
                retval = PM3_EMALLOC;
                goto out;
            }

            snprintf(blocks, sizeof(blocks), "$.blocks.%d", i);
            JsonLoadBufAsHex(root, blocks, &udata.bytes[sptr], 4, &len);
            if (load_file_sanity(ctype, 4, i, len) == false) {
                break;
            }

            sptr += len;
        }
        *datalen = sptr;
        goto out;
    }

    // depricated
    if (!strcmp(ctype, "15693")) {
        PrintAndLogEx(WARNING, "loadFileJSONex: loading deprecated 15693 format");
        // will set every metadata to 0 except 1st UID byte to E0 and memory layout
        iso15_tag_t *tag = (iso15_tag_t *)udata.bytes;
        tag->uid[7] = 0xE0;
        tag->bytesPerPage = 4;
        JsonLoadBufAsHex(root, "$.raw", tag->data
                         , MIN(maxdatalen, ISO15693_TAG_MAX_SIZE)
                         , datalen
                        );

        if (*datalen > ISO15693_TAG_MAX_SIZE) {
            PrintAndLogEx(ERR, "loadFileJSONex: maxdatalen=%zu (%04zx)   sptr=%zu (%04zx) -- exceeded maxdatalen"
                          , ISO15693_TAG_MAX_SIZE
                          , ISO15693_TAG_MAX_SIZE
                          , *datalen
                          , *datalen
                         );
            retval = PM3_EMALLOC;
            goto out;
        }
        tag->pagesCount = *datalen / 4;
        if (tag->pagesCount > ISO15693_TAG_MAX_PAGES) {
            PrintAndLogEx(ERR, "loadFileJSONex: maxpagecount=%zu (%04zx)   pagecount=%u (%04x) -- exceeded maxpagecount"
                          , ISO15693_TAG_MAX_PAGES
                          , ISO15693_TAG_MAX_PAGES
                          , tag->pagesCount
                          , tag->pagesCount
                         );
            retval = PM3_EMALLOC;
            goto out;
        }
        *datalen = sizeof(iso15_tag_t);
        goto out;
    }

    // depricated: handles ISO15693 w blocksize of 4 bytes.
    if (!strcmp(ctype, "15693 v2")) {
        PrintAndLogEx(WARNING, "loadFileJSONex: loading deprecated 15693 v2 format");
        // will set every metadata to 0 except 1st UID byte to E0 and memory layout
        iso15_tag_t *tag = (iso15_tag_t *)udata.bytes;
        tag->uid[7] = 0xE0;
        tag->bytesPerPage = 4;
        size_t sptr = 0;

        for (uint32_t i = 0; i < (maxdatalen / 4) ; i++) {
            if (((i + 1) * 4) > ISO15693_TAG_MAX_SIZE) {
                PrintAndLogEx(ERR, "loadFileJSONex: maxdatalen=%zu (%04zx)   block (i)=%4d (%04x)   sptr=%zu (%04zx) -- exceeded maxdatalen"
                              , maxdatalen
                              , maxdatalen
                              , i
                              , i
                              , sptr
                              , sptr
                             );

                retval = PM3_EMALLOC;
                goto out;
            }

            snprintf(blocks, sizeof(blocks), "$.blocks.%u", i);
            JsonLoadBufAsHex(root, blocks, &tag->data[sptr], 4, &len);
            if (load_file_sanity(ctype, tag->bytesPerPage, i, len) == false) {
                break;
            }
            sptr += len;
        }

        tag->pagesCount = sptr / 4;
        if (tag->pagesCount > ISO15693_TAG_MAX_PAGES) {
            PrintAndLogEx(ERR, "loadFileJSONex: maxpagecount=%zu (%04zx)   pagecount=%u (%04x) -- exceeded maxpagecount"
                          , ISO15693_TAG_MAX_PAGES
                          , ISO15693_TAG_MAX_PAGES
                          , tag->pagesCount
                          , tag->pagesCount
                         );
            retval = PM3_EMALLOC;
            goto out;
        }

        *datalen = sizeof(iso15_tag_t);
        goto out;
    }
    // depricated: handles ISO15693 w blocksize of 8 bytes.
    if (!strcmp(ctype, "15693 v3")) {
        PrintAndLogEx(WARNING, "loadFileJSONex: loading deprecated 15693 v3 format");
        // will set every metadata to 0 except 1st UID byte to E0 and memory layout
        iso15_tag_t *tag = (iso15_tag_t *)udata.bytes;
        tag->uid[7] = 0xE0;
        tag->bytesPerPage = 8;
        size_t sptr = 0;

        for (uint32_t i = 0; i < (maxdatalen / 8) ; i++) {
            if (((i + 1) * 8) > ISO15693_TAG_MAX_SIZE) {
                PrintAndLogEx(ERR, "loadFileJSONex: maxdatalen=%zu (%04zx)   block (i)=%4d (%04x)   sptr=%zu (%04zx) -- exceeded maxdatalen"
                              , maxdatalen
                              , maxdatalen
                              , i
                              , i
                              , sptr
                              , sptr
                             );

                retval = PM3_EMALLOC;
                goto out;
            }

            snprintf(blocks, sizeof(blocks), "$.blocks.%u", i);
            JsonLoadBufAsHex(root, blocks, &tag->data[sptr], 8, &len);
            if (load_file_sanity(ctype, tag->bytesPerPage, i, len) == false) {
                break;
            }
            sptr += len;
        }

        tag->pagesCount = sptr / 8;
        if (tag->pagesCount > ISO15693_TAG_MAX_PAGES) {
            PrintAndLogEx(ERR, "loadFileJSONex: maxpagecount=%zu (%04zx)   pagecount=%u (%04x) -- exceeded maxpagecount"
                          , ISO15693_TAG_MAX_PAGES
                          , ISO15693_TAG_MAX_PAGES
                          , tag->pagesCount
                          , tag->pagesCount
                         );
            retval = PM3_EMALLOC;
            goto out;
        }

        *datalen = sizeof(iso15_tag_t);
        goto out;
    }

    if (!strcmp(ctype, "15693 v4")) {
        iso15_tag_t *tag = (iso15_tag_t *)udata.bytes;
        JsonLoadBufAsHex(root, "$.Card.uid", tag->uid, 8, datalen);
        JsonLoadBufAsHex(root, "$.Card.dsfid", &tag->dsfid, 1, datalen);
        JsonLoadBufAsHex(root, "$.Card.dsfidlock", (uint8_t *)&tag->dsfidLock, 1, datalen);
        JsonLoadBufAsHex(root, "$.Card.afi", &tag->afi, 1, datalen);
        JsonLoadBufAsHex(root, "$.Card.afilock", (uint8_t *)&tag->afiLock, 1, datalen);
        JsonLoadBufAsHex(root, "$.Card.bytesperpage", &tag->bytesPerPage, 1, datalen);
        JsonLoadBufAsHex(root, "$.Card.pagescount", &tag->pagesCount, 1, datalen);

        if ((tag->pagesCount > ISO15693_TAG_MAX_PAGES) ||
                ((tag->pagesCount * tag->bytesPerPage) > ISO15693_TAG_MAX_SIZE) ||
                (tag->pagesCount == 0) ||
                (tag->bytesPerPage == 0)) {
            PrintAndLogEx(ERR, "loadFileJSONex: pagesCount=%u (%04x)    bytesPerPage=%u (%04x) -- invalid tag memory layout"
                          , tag->pagesCount
                          , tag->pagesCount
                          , tag->bytesPerPage
                          , tag->bytesPerPage
                         );
            retval = PM3_EMALLOC;
            goto out;
        }

        JsonLoadBufAsHex(root, "$.Card.ic", &tag->ic, 1, datalen);
        JsonLoadBufAsHex(root, "$.Card.locks", tag->locks, tag->pagesCount, datalen);
        JsonLoadBufAsHex(root, "$.Card.random", tag->random, 2, datalen);
        JsonLoadBufAsHex(root, "$.Card.privacypasswd", tag->privacyPasswd, 4, datalen);
        JsonLoadBufAsHex(root, "$.Card.state", (uint8_t *)&tag->state, 1, datalen);

        size_t sptr = 0;
        for (uint8_t i = 0; i < tag->pagesCount ; i++) {

            if (((i + 1) * tag->bytesPerPage) > ISO15693_TAG_MAX_SIZE) {
                PrintAndLogEx(ERR, "loadFileJSONex: maxdatalen=%zu (%04zx)   block (i)=%4d (%04x)   sptr=%zu (%04zx) -- exceeded maxdatalen"
                              , maxdatalen
                              , maxdatalen
                              , i
                              , i
                              , sptr
                              , sptr
                             );

                retval = PM3_EMALLOC;
                goto out;
            }

            snprintf(blocks, sizeof(blocks), "$.blocks.%d", i);
            JsonLoadBufAsHex(root, blocks, &tag->data[sptr], tag->bytesPerPage, &len);
            if (load_file_sanity(ctype, tag->bytesPerPage, i, len) == false) {
                break;
            }
            sptr += len;
        }

        *datalen = sizeof(iso15_tag_t);
        goto out;
    }

    if (!strcmp(ctype, "legic v2")) {
        size_t sptr = 0;
        for (int i = 0; i < 64; i++) {
            if (sptr + 16 > maxdatalen) {
                PrintAndLogEx(ERR, "loadFileJSONex: maxdatalen=%zu (%04zx)   block (i)=%4d (%04x)   sptr=%zu (%04zx) -- exceeded maxdatalen", maxdatalen, maxdatalen, i, i, sptr, sptr);
                retval = PM3_EMALLOC;
                goto out;
            }

            snprintf(blocks, sizeof(blocks), "$.blocks.%d", i);
            JsonLoadBufAsHex(root, blocks, &udata.bytes[sptr], 16, &len);
            if (load_file_sanity(ctype, 16, i, len) == false) {
                break;
            }
            sptr += len;
        }

        *datalen = sptr;
        goto out;
    }

    // depricated
    if (!strcmp(ctype, "legic")) {
        JsonLoadBufAsHex(root, "$.raw", udata.bytes, maxdatalen, datalen);
        goto out;
    }

    if (!strcmp(ctype, "topaz")) {

        JsonLoadBufAsHex(root, "$.Card.UID", udata.topaz->uid, sizeof(udata.topaz->uid), datalen);
        JsonLoadBufAsHex(root, "$.Card.HR01", udata.topaz->HR01, sizeof(udata.topaz->HR01), datalen);
        JsonLoadBufAsHex(root, "$.Card.Size", (uint8_t *) & (udata.topaz->size), 2, datalen);

        size_t sptr = 0;
        for (int i = 0; i < (TOPAZ_STATIC_MEMORY / 8); i++) {

            if (sptr + TOPAZ_BLOCK_SIZE > maxdatalen) {
                PrintAndLogEx(ERR, "loadFileJSONex: maxdatalen=%zu (%04zx)   block (i)=%4d (%04x)   sptr=%zu (%04zx) -- exceeded maxdatalen", maxdatalen, maxdatalen, i, i, sptr, sptr);
                retval = PM3_EMALLOC;
                goto out;
            }

            snprintf(blocks, sizeof(blocks), "$.blocks.%d", i);
            JsonLoadBufAsHex(root, blocks, &udata.topaz->data_blocks[sptr][0], TOPAZ_BLOCK_SIZE, &len);
            if (load_file_sanity(ctype, TOPAZ_BLOCK_SIZE, i, len) == false) {
                break;
            }

            sptr += len;
            // ICEMAN todo:  add dynamic memory.
            // uint16_z Size
            // uint8_t *dynamic_memory;
        }

        *datalen += sptr;
        goto out;
    }

    if (!strcmp(ctype, "mfpkeys")) {

        JsonLoadBufAsHex(root, "$.Card.UID", udata.bytes, 7, datalen);
        JsonLoadBufAsHex(root, "$.Card.SAK", udata.bytes + 10, 1, datalen);
        JsonLoadBufAsHex(root, "$.Card.ATQA", udata.bytes + 11, 2, datalen);
        uint8_t atslen = udata.bytes[13];
        if (atslen > 0) {
            JsonLoadBufAsHex(root, "$.Card.ATS", udata.bytes + 14, atslen, datalen);
        }

        size_t sptr = (14 + atslen);

        // memcpy(vdata, udata.bytes + (14 + atslen), 2 * 64 * 17);
        for (int i = 0; i < 64; i++) {

            if ((sptr + (AES_KEY_LEN * 2)) > maxdatalen) {
                PrintAndLogEx(ERR, "loadFileJSONex: maxdatalen=%zu (%04zx)   block (i)=%4d (%04x)   sptr=%zu (%04zx) -- exceeded maxdatalen", maxdatalen, maxdatalen, i, i, sptr, sptr);
                break;
            }

            size_t offset = (14 + atslen) + (i * 2 * AES_KEY_LEN);

            snprintf(blocks, sizeof(blocks), "$.SectorKeys.%d.KeyA", i);
            JsonLoadBufAsHex(root, blocks, udata.bytes + offset, AES_KEY_LEN, datalen);

            snprintf(blocks, sizeof(blocks), "$.SectorKeys.%d.KeyB", i);
            JsonLoadBufAsHex(root, blocks, udata.bytes + offset + AES_KEY_LEN, AES_KEY_LEN, datalen);

            sptr += (2 * AES_KEY_LEN);
        }
        *datalen += sptr;
        goto out;
    }

    if (!strcmp(ctype, "mfdes")) {
        JsonLoadBufAsHex(root, "$.Card.UID", udata.bytes, 7, datalen);
        JsonLoadBufAsHex(root, "$.Card.SAK", udata.bytes + 10, 1, datalen);
        JsonLoadBufAsHex(root, "$.Card.ATQA", udata.bytes + 11, 2, datalen);
        uint8_t atslen = udata.bytes[13];
        if (atslen > 0) {
            JsonLoadBufAsHex(root, "$.Card.ATS", udata.bytes + 14, atslen, datalen);
        }

//        size_t sptr = (14 + atslen);
//         uint8_t dvdata[4][0xE][24 + 1] = {{{0}}};

        /*
        for (int i = 0; i < (int)datalen; i++) {
            char path[PATH_MAX_LENGTH] = {0};

            if (dvdata[0][i][0]) {
                snprintf(path, sizeof(path), "$.DES.%d.Key", i);
                JsonSaveBufAsHexCompact(root, path, &dvdata[0][i][1], DES_KEY_LEN);
            }

            if (dvdata[1][i][0]) {
                snprintf(path, sizeof(path), "$.3DES.%d.Key", i);
                JsonSaveBufAsHexCompact(root, path, &dvdata[1][i][1], T2DES_KEY_LEN);
            }
            if (dvdata[2][i][0]) {
                snprintf(path, sizeof(path), "$.AES.%d.Key", i);
                JsonSaveBufAsHexCompact(root, path, &dvdata[2][i][1], AES_KEY_LEN);
            }
            if (dvdata[3][i][0]) {
                snprintf(path, sizeof(path), "$.K3KDES.%d.Key", i);
                JsonSaveBufAsHexCompact(root, path, &dvdata[3][i][1], T3DES_KEY_LEN);
            }
        }
        */
//        memcpy(&data[14 + atslen], dvdata, 4 * 0xE * (24 + 1));

        goto out;
    }

    if (!strcmp(ctype, "14b v2")) {
        size_t sptr = 0;
        for (int i = 0; i < (maxdatalen / 4); i++) {
            if (sptr + 4 > maxdatalen) {
                PrintAndLogEx(ERR, "loadFileJSONex: maxdatalen=%zu (%04zx)   block (i)=%4d (%04x)   sptr=%zu (%04zx) -- exceeded maxdatalen", maxdatalen, maxdatalen, i, i, sptr, sptr);
                retval = PM3_EMALLOC;
                goto out;
            }

            snprintf(blocks, sizeof(blocks), "$.blocks.%d", i);
            JsonLoadBufAsHex(root, blocks, &udata.bytes[sptr], 4, &len);
            if (load_file_sanity(ctype, 4, i, len) == false) {
                break;
            }
            sptr += len;
        }

        *datalen = sptr;
        goto out;
    }

    if (!strcmp(ctype, "lto")) {
        size_t sptr = 0;
        for (int i = 0; i < (maxdatalen / 32); i++) {
            if (sptr + 32 > maxdatalen) {
                PrintAndLogEx(ERR, "loadFileJSONex: maxdatalen=%zu (%04zx)   block (i)=%4d (%04x)   sptr=%zu (%04zx) -- exceeded maxdatalen", maxdatalen, maxdatalen, i, i, sptr, sptr);
                retval = PM3_EMALLOC;
                goto out;
            }

            snprintf(blocks, sizeof(blocks), "$.blocks.%d", i);
            JsonLoadBufAsHex(root, blocks, &udata.bytes[sptr], 32, &len);
            if (load_file_sanity(ctype, 32, i, len) == false) {
                break;
            }
            sptr += len;
        }

        *datalen = sptr;
        goto out;
    }

    if (!strcmp(ctype, "cryptorf")) {
        size_t sptr = 0;
        for (int i = 0; i < (maxdatalen / 8); i++) {
            if (sptr + 8 > maxdatalen) {
                PrintAndLogEx(ERR, "loadFileJSONex: maxdatalen=%zu (%04zx)   block (i)=%4d (%04x)   sptr=%zu (%04zx) -- exceeded maxdatalen", maxdatalen, maxdatalen, i, i, sptr, sptr);
                retval = PM3_EMALLOC;
                goto out;
            }

            snprintf(blocks, sizeof(blocks), "$.blocks.%d", i);
            JsonLoadBufAsHex(root, blocks, &udata.bytes[sptr], 8, &len);
            if (load_file_sanity(ctype, 8, i, len) == false) {
                break;
            }
            sptr += len;
        }

        *datalen = sptr;
        goto out;
    }

    if (!strcmp(ctype, "ndef")) {

        /*
        // when we will read and return extra values from NDEF json
        json_error_t up_error = {0};
        int i1 = 0;
        size_t ndefsize = 0;
        if (json_unpack_ex(root, &up_error, 0, "{s:i}", "Ndef.Size", &i1) == 0) {
            ndefsize = i1;
        }
        */

        size_t sptr = 0;
        for (int i = 0; i < (maxdatalen / 16); i++) {
            if (sptr + 16 > maxdatalen) {
                PrintAndLogEx(ERR, "loadFileJSONex: maxdatalen=%zu (%04zx)   block (i)=%4d (%04x)   sptr=%zu (%04zx) -- exceeded maxdatalen", maxdatalen, maxdatalen, i, i, sptr, sptr);
                retval = PM3_EMALLOC;
                goto out;
            }

            snprintf(blocks, sizeof(blocks), "$.blocks.%d", i);
            JsonLoadBufAsHex(root, blocks, &udata.bytes[sptr], 16, &len);
            if (load_file_sanity(ctype, 16, i, len) == false) {
                break;
            }

            sptr += len;
        }

        *datalen = sptr;
        goto out;
    }

out:
    if (callback != NULL) {
        (*callback)(root);
    }

    json_decref(root);
    return retval;
}

int loadFileJSONroot(const char *preferredName, void **proot, bool verbose) {
    char *path;
    int res = searchFile(&path, RESOURCES_SUBDIR, preferredName, ".json", false);
    if (res != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    json_error_t error;
    json_t *root = json_load_file(path, 0, &error);
    if (verbose) {
        PrintAndLogEx(SUCCESS, "Loaded " _YELLOW_("%s"), path);
    }

    free(path);

    int retval = PM3_SUCCESS;
    if (root == NULL) {
        PrintAndLogEx(ERR, "ERROR: json " _YELLOW_("%s") " error on line %d: %s", preferredName, error.line, error.text);
        retval = PM3_ESOFT;
    }

    if (json_is_object(root) == false) {
        PrintAndLogEx(ERR, "ERROR: Invalid json " _YELLOW_("%s") " format. root must be an object.", preferredName);
        retval = PM3_ESOFT;
    }

    if (retval == PM3_ESOFT)
        json_decref(root);
    else
        *proot = root;

    return retval;
}

// iceman:  todo - move all unsafe functions like this from client source.
int loadFileDICTIONARY(const char *preferredName, void *data, size_t *datalen, uint8_t keylen, uint32_t *keycnt) {
    // t5577 == 4 bytes
    // mifare == 6 bytes
    // mf plus == 16 bytes
    // mf desfire == 3des3k 24 bytes
    // iclass == 8 bytes
    // default to 6 bytes.
    if (keylen != 4 && keylen != 6 && keylen != 8 && keylen != 16 && keylen != 24) {
        keylen = 6;
    }

    return loadFileDICTIONARYEx(preferredName, data, 0, datalen, keylen, keycnt, 0, NULL, true);
}

int loadFileDICTIONARYEx(const char *preferredName, void *data, size_t maxdatalen, size_t *datalen, uint8_t keylen, uint32_t *keycnt,
                         size_t startFilePosition, size_t *endFilePosition, bool verbose) {

    if (data == NULL) {
        return PM3_EINVARG;
    }

    if (endFilePosition) {
        *endFilePosition = 0;
    }

    char *path;
    if (searchFile(&path, DICTIONARIES_SUBDIR, preferredName, ".dic", false) != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    // double up since its chars
    keylen <<= 1;

    char line[255];
    uint32_t vkeycnt = 0;
    size_t counter = 0;
    int retval = PM3_SUCCESS;

    FILE *f = fopen(path, "r");
    if (!f) {
        PrintAndLogEx(WARNING, "file not found or locked `" _YELLOW_("%s") "`", path);
        retval = PM3_EFILE;
        goto out;
    }

    if (startFilePosition) {
        if (fseek(f, startFilePosition, SEEK_SET) < 0) {
            fclose(f);
            retval = PM3_EFILE;
            goto out;
        }
    }

    uint8_t *udata = (uint8_t *)data;

    // read file
    while (!feof(f)) {
        long filepos = ftell(f);

        if (!fgets(line, sizeof(line), f)) {
            if (endFilePosition) {
                *endFilePosition = 0;
            }
            break;
        }

        // add null terminator
        line[keylen] = 0;

        // smaller keys than expected is skipped
        if (strlen(line) < keylen) {
            continue;
        }

        // The line start with # is comment, skip
        if (line[0] == '#') {
            continue;
        }

        if (!CheckStringIsHEXValue(line)) {
            continue;
        }

        // cant store more data
        if (maxdatalen && (counter + (keylen >> 1) > maxdatalen)) {
            retval = 1;
            if (endFilePosition) {
                *endFilePosition = filepos;
            }
            break;
        }

        if (hex_to_bytes(line, udata + counter, keylen >> 1) != (keylen >> 1)) {
            continue;
        }

        vkeycnt++;
        memset(line, 0, sizeof(line));
        counter += (keylen >> 1);
    }

    fclose(f);

    if (verbose) {
        PrintAndLogEx(SUCCESS, "Loaded " _GREEN_("%2d") " keys from dictionary file `" _YELLOW_("%s") "`", vkeycnt, path);
    }

    if (datalen) {
        *datalen = counter;
    }

    if (keycnt) {
        *keycnt = vkeycnt;
    }
out:
    free(path);
    return retval;
}


int loadFileDICTIONARY_safe(const char *preferredName, void **pdata, uint8_t keylen, uint32_t *keycnt) {
    return loadFileDICTIONARY_safe_ex(preferredName, ".dic", pdata, keylen, keycnt, true);
}

int loadFileDICTIONARY_safe_ex(const char *preferredName, const char *suffix, void **pdata, uint8_t keylen, uint32_t *keycnt, bool verbose) {

    int retval = PM3_SUCCESS;

    char *path;
    if (searchFile(&path, DICTIONARIES_SUBDIR, preferredName, suffix, false) != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    // t5577 == 4bytes
    // mifare == 6 bytes
    // mf plus == 16 bytes
    // mf desfire == 3des3k 24 bytes
    // iclass == 8 bytes
    // default to 6 bytes.
    if (keylen != 4 && keylen != 5 && keylen != 6 && keylen != 8 && keylen != 16 && keylen != 24) {
        keylen = 6;
    }

    size_t mem_size;
    size_t block_size = 10 * keylen;

    // double up since its chars
    keylen <<= 1;

    char line[255];

    // allocate some space for the dictionary
    *pdata = calloc(block_size, sizeof(uint8_t));
    if (*pdata == NULL) {
        free(path);
        return PM3_EFILE;
    }
    mem_size = block_size;

    FILE *f = fopen(path, "r");
    if (!f) {
        PrintAndLogEx(WARNING, "file not found or locked `" _YELLOW_("%s") "`", path);
        retval = PM3_EFILE;
        goto out;
    }

    // read file
    while (fgets(line, sizeof(line), f)) {

        // check if we have enough space (if not allocate more)
        if ((*keycnt * (keylen >> 1)) >= mem_size) {

            mem_size += block_size;
            *pdata = realloc(*pdata, mem_size);

            if (*pdata == NULL) {
                retval = PM3_EFILE;
                fclose(f);
                goto out;
            } else {
                memset((uint8_t *)*pdata + (mem_size - block_size), 0, block_size);
            }
        }

        // add null terminator
        line[keylen] = 0;

        // smaller keys than expected is skipped
        if (strlen(line) < keylen) {
            continue;
        }

        // The line start with # is comment, skip
        if (line[0] == '#') {
            continue;
        }

        if (CheckStringIsHEXValue(line) == false) {
            continue;
        }

        if (hex_to_bytes(
                    line,
                    (uint8_t *)*pdata + (*keycnt * (keylen >> 1)),
                    keylen >> 1) != (keylen >> 1)) {
            continue;
        }

        (*keycnt)++;

        memset(line, 0, sizeof(line));
    }
    fclose(f);

    if (verbose) {
        PrintAndLogEx(SUCCESS, "Loaded " _GREEN_("%2d") " keys from dictionary file `" _YELLOW_("%s") "`", *keycnt, path);
    }

out:
    free(path);
    return retval;
}

int loadFileBinaryKey(const char *preferredName, const char *suffix, void **keya, void **keyb, size_t *alen, size_t *blen) {

    char *path;
    int res = searchFile(&path, RESOURCES_SUBDIR, preferredName, suffix, false);
    if (res != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        PrintAndLogEx(WARNING, "file not found or locked `" _YELLOW_("%s") "`", path);
        free(path);
        return PM3_EFILE;
    }

    // get filesize in order to malloc memory
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0) {
        PrintAndLogEx(FAILED, "error, when getting filesize");
        fclose(f);
        free(path);
        return PM3_EFILE;
    }

    // Half is KEY A,  half is KEY B
    fsize /= 2;

    *keya = calloc(fsize, sizeof(uint8_t));
    if (*keya == NULL) {
        PrintAndLogEx(FAILED, "error, cannot allocate memory");
        fclose(f);
        free(path);
        return PM3_EMALLOC;
    }

    *alen = fread(*keya, 1, fsize, f);

    *keyb = calloc(fsize, sizeof(uint8_t));
    if (*keyb == NULL) {
        PrintAndLogEx(FAILED, "error, cannot allocate memory");
        fclose(f);
        free(*keya);
        free(path);
        return PM3_EMALLOC;
    }

    *blen = fread(*keyb, 1, fsize, f);
    fclose(f);

    PrintAndLogEx(SUCCESS, "Loaded binary key file `" _YELLOW_("%s") "`", path);
    free(path);
    return PM3_SUCCESS;
}

mfu_df_e detect_mfu_dump_format(uint8_t **dump, bool verbose) {

    mfu_df_e retval = MFU_DF_UNKNOWN;
    uint8_t bcc0, bcc1;
    uint8_t ct = 0x88;

    // detect new
    mfu_dump_t *new = (mfu_dump_t *)*dump;
    bcc0 = ct ^ new->data[0] ^ new->data[1] ^ new->data[2];
    bcc1 = new->data[4] ^ new->data[5] ^ new->data[6] ^ new->data[7];
    if (bcc0 == new->data[3] && bcc1 == new->data[8]) {
        retval = MFU_DF_NEWBIN;
    }

    // Memory layout is different for NTAG I2C 1K/2K plus
    // Sak 00, atqa 44 00
    if (0 ==  new->data[7] &&  0x44 == new->data[8] &&  0x00 == new->data[9]) {
        retval = MFU_DF_NEWBIN;
    }

    // detect old
    if (retval == MFU_DF_UNKNOWN) {
        old_mfu_dump_t *old = (old_mfu_dump_t *)*dump;
        bcc0 = ct ^ old->data[0] ^ old->data[1] ^ old->data[2];
        bcc1 = old->data[4] ^ old->data[5] ^ old->data[6] ^ old->data[7];
        if (bcc0 == old->data[3] && bcc1 == old->data[8]) {
            retval = MFU_DF_OLDBIN;
        }
    }

    // detect plain
    if (retval == MFU_DF_UNKNOWN) {
        const uint8_t *plain = *dump;
        bcc0 = ct ^ plain[0] ^ plain[1] ^ plain[2];
        bcc1 = plain[4] ^ plain[5] ^ plain[6] ^ plain[7];
        if ((bcc0 == plain[3]) && (bcc1 == plain[8])) {
            retval = MFU_DF_PLAINBIN;
        }
    }

    if (verbose) {
        switch (retval) {
            case MFU_DF_NEWBIN:
                PrintAndLogEx(INFO, "Detected " _GREEN_("new") " mfu dump format");
                break;
            case MFU_DF_OLDBIN:
                PrintAndLogEx(INFO, "Detected " _GREEN_("old") " mfu dump format");
                break;
            case MFU_DF_PLAINBIN:
                PrintAndLogEx(INFO, "Detected " _GREEN_("plain") " mfu dump format");
                break;
            case MFU_DF_UNKNOWN:
                PrintAndLogEx(WARNING, "Failed to detected mfu dump format");
                break;
        }
    }
    return retval;
}

int detect_nfc_dump_format(const char *preferredName, nfc_df_e *dump_type, bool verbose) {

    *dump_type = NFC_DF_UNKNOWN;

    char *path;
    int res = searchFile(&path, RESOURCES_SUBDIR, preferredName, "", false);
    if (res != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    FILE *f = fopen(path, "r");
    if (!f) {
        PrintAndLogEx(WARNING, "file not found or locked `" _YELLOW_("%s") "`", path);
        free(path);
        return PM3_EFILE;
    }
    free(path);

    char line[256];
    memset(line, 0, sizeof(line));

    while (!feof(f)) {

        memset(line, 0, sizeof(line));

        if (fgets(line, sizeof(line), f) == NULL) {
            if (feof(f)) {
                break;
            }

            fclose(f);
            PrintAndLogEx(FAILED, "file reading error");
            return PM3_EFILE;
        }

        str_cleanrn(line, sizeof(line));
        str_lower(line);

        if (str_startswith(line, "device type: ntag")) {
            *dump_type = NFC_DF_MFU;
            break;
        }
        if (str_startswith(line, "device type: mifare classic")) {
            *dump_type = NFC_DF_MFC;
            break;
        }
        if (str_startswith(line, "device type: mifare desfire")) {
            *dump_type = NFC_DF_MFDES;
            break;
        }
        if (str_startswith(line, "device type: iso14443-3a")) {
            *dump_type = NFC_DF_14_3A;
            break;
        }
        if (str_startswith(line, "device type: iso14443-3b")) {
            *dump_type = NFC_DF_14_3B;
            break;
        }
        if (str_startswith(line, "device type: iso14443-4a")) {
            *dump_type = NFC_DF_14_4A;
            break;
        }
        if (str_startswith(line, "filetype: flipper picopass device")) {
            *dump_type = NFC_DF_PICOPASS;
            break;
        }

    }
    fclose(f);

    if (verbose) {
        switch (*dump_type) {
            case NFC_DF_MFU:
                PrintAndLogEx(INFO, "Detected MIFARE Ultralight / NTAG based dump format");
                break;
            case NFC_DF_MFC:
                PrintAndLogEx(INFO, "Detected MIFARE Classic based dump format");
                break;
            case NFC_DF_MFDES:
                PrintAndLogEx(INFO, "Detected MIFARE DESFire based dump format");
                break;
            case NFC_DF_14_3A:
                PrintAndLogEx(INFO, "Detected ISO14443-3A based dump format. No data available");
                break;
            case NFC_DF_14_3B:
                PrintAndLogEx(INFO, "Detected ISO14443-3B based dump format. No data available");
                break;
            case NFC_DF_14_4A:
                PrintAndLogEx(INFO, "Detected ISO14443-4A based dump format. No data available");
                break;
            case NFC_DF_PICOPASS:
                PrintAndLogEx(INFO, "Detected PICOPASS based dump format");
                break;
            case NFC_DF_UNKNOWN:
                PrintAndLogEx(WARNING, "Failed to detected dump format");
                break;
        }
    }
    return PM3_SUCCESS;
}

static int convert_plain_mfu_dump(uint8_t **dump, size_t *dumplen, bool verbose) {

    mfu_dump_t *mfu = (mfu_dump_t *) calloc(sizeof(mfu_dump_t), sizeof(uint8_t));
    if (mfu == NULL) {
        return PM3_EMALLOC;
    }

    memcpy(mfu->data, *dump, *dumplen);

    mfu->pages = *dumplen / 4 - 1;

    if (verbose) {
        PrintAndLogEx(SUCCESS, "Plain mfu dump format was converted to " _GREEN_("%d") " blocks", mfu->pages + 1);
    }

    *dump = (uint8_t *)mfu;
    *dumplen += MFU_DUMP_PREFIX_LENGTH ;
    return PM3_SUCCESS;
}

static int convert_old_mfu_dump(uint8_t **dump, size_t *dumplen, bool verbose) {
    /*  For reference
    typedef struct {
        uint8_t version[8];
        uint8_t tbo[2];
        uint8_t tearing[3];
        uint8_t pack[2];
        uint8_t tbo1[1];
        uint8_t signature[32];
        uint8_t data[1024];
    } PACKED old_mfu_dump_t;
    */

    // convert old format
    old_mfu_dump_t *old_mfu_dump = (old_mfu_dump_t *)*dump;

    size_t old_data_len = *dumplen - OLD_MFU_DUMP_PREFIX_LENGTH;
    size_t new_dump_len = old_data_len + MFU_DUMP_PREFIX_LENGTH;

    mfu_dump_t *mfu_dump = (mfu_dump_t *) calloc(sizeof(mfu_dump_t), sizeof(uint8_t));
    if (mfu_dump == NULL) {
        return PM3_EMALLOC;
    }

    memcpy(mfu_dump->version, old_mfu_dump->version, sizeof(mfu_dump->version));
    memcpy(mfu_dump->tbo, old_mfu_dump->tbo, sizeof(mfu_dump->tbo));
    memcpy(mfu_dump->signature, old_mfu_dump->signature, sizeof(mfu_dump->signature));

    mfu_dump->tbo1[0] = old_mfu_dump->tbo1[0];

    for (int i = 0; i < 3; i++) {
        mfu_dump->counter_tearing[i][3] = old_mfu_dump->tearing[i];
    }

    memcpy(mfu_dump->data, old_mfu_dump->data, sizeof(mfu_dump->data));
    mfu_dump->pages = old_data_len / 4 - 1;

    // Add PACK to last block of memory.
    memcpy(mfu_dump->data + (mfu_dump->pages * 4 + MFU_DUMP_PREFIX_LENGTH), old_mfu_dump->pack, 2);

    if (verbose) {
        PrintAndLogEx(SUCCESS, "Old mfu dump format was converted to " _GREEN_("%d") " blocks", mfu_dump->pages + 1);
    }

    free(*dump);
    *dump = (uint8_t *)mfu_dump;
    *dumplen = new_dump_len;
    return PM3_SUCCESS;
}

int convert_mfu_dump_format(uint8_t **dump, size_t *dumplen, bool verbose) {

    if (!dump || !dumplen || *dumplen < OLD_MFU_DUMP_PREFIX_LENGTH) {
        return PM3_EINVARG;
    }

    mfu_df_e res = detect_mfu_dump_format(dump, verbose);

    switch (res) {
        case MFU_DF_NEWBIN:
            return PM3_SUCCESS;
        case MFU_DF_OLDBIN:
            return convert_old_mfu_dump(dump, dumplen, verbose);
        case MFU_DF_PLAINBIN:
            return convert_plain_mfu_dump(dump, dumplen, verbose);
        case MFU_DF_UNKNOWN:
        default:
            return PM3_ESOFT;
    }
}

static int filelist(const char *path, const char *ext, uint8_t last, bool tentative, uint8_t indent, uint16_t strip) {
    struct dirent **namelist;
    int n;

    n = scandir(path, &namelist, NULL, alphasort);
    if (n == -1) {

        if (tentative == false) {

            for (uint8_t j = 0; j < indent; j++) {
                PrintAndLogEx(NORMAL, "%s   " NOLF, ((last >> j) & 1) ? " " : "│");
            }
            PrintAndLogEx(NORMAL, "%s── "_GREEN_("%s"), last ? "└" : "├", &path[strip]);
        }
        return PM3_EFILE;
    }

    for (uint8_t j = 0; j < indent; j++) {
        PrintAndLogEx(NORMAL, "%s   " NOLF, ((last >> j) & 1) ? " " : "│");
    }

    PrintAndLogEx(NORMAL, "%s── "_GREEN_("%s"), last ? "└" : "├", &path[strip]);

    for (int i = 0; i < n; i++) {

        char tmp_fullpath[1024] = {0};
        strncat(tmp_fullpath, path, sizeof(tmp_fullpath) - 1);
        tmp_fullpath[1023] = 0x00;
        strncat(tmp_fullpath, namelist[i]->d_name, strlen(tmp_fullpath) - 1);

        if (is_directory(tmp_fullpath)) {

            char newpath[1024];
            if (strcmp(namelist[i]->d_name, ".") == 0 || strcmp(namelist[i]->d_name, "..") == 0)
                continue;

            snprintf(newpath, sizeof(newpath), "%s", path);
            strncat(newpath, namelist[i]->d_name, sizeof(newpath) - strlen(newpath) - 1);
            strncat(newpath, "/", sizeof(newpath) - strlen(newpath) - 1);

            filelist(newpath, ext, last + ((i == n - 1) << (indent + 1)), tentative, indent + 1, strlen(path));
        } else {

            if ((ext == NULL) || ((str_endswith(namelist[i]->d_name, ext)))) {

                for (uint8_t j = 0; j < indent + 1; j++) {
                    PrintAndLogEx(NORMAL, "%s   " NOLF, ((last >> j) & 1) ? " " : "│");
                }
                PrintAndLogEx(NORMAL, "%s── %-21s", i == n - 1 ? "└" : "├", namelist[i]->d_name);
            }
        }
        free(namelist[i]);
    }
    free(namelist);
    return PM3_SUCCESS;
}

int searchAndList(const char *pm3dir, const char *ext) {
    // display in same order as searched by searchFile
    // try pm3 dirs in current workdir (dev mode)
    if (get_my_executable_directory() != NULL) {
        char script_directory_path[strlen(get_my_executable_directory()) + strlen(pm3dir) + 1];
        strcpy(script_directory_path, get_my_executable_directory());
        strcat(script_directory_path, pm3dir);
        filelist(script_directory_path, ext, false, true, 0, 0);
    }
    // try pm3 dirs in user .proxmark3 (user mode)
    const char *user_path = get_my_user_directory();
    if (user_path != NULL) {
        char script_directory_path[strlen(user_path) + strlen(PM3_USER_DIRECTORY) + strlen(pm3dir) + 1];
        strcpy(script_directory_path, user_path);
        strcat(script_directory_path, PM3_USER_DIRECTORY);
        strcat(script_directory_path, pm3dir);
        filelist(script_directory_path, ext, false, false, 0, 0);
    }
    // try pm3 dirs in pm3 installation dir (install mode)
    const char *exec_path = get_my_executable_directory();
    if (exec_path != NULL) {
        char script_directory_path[strlen(exec_path) + strlen(PM3_SHARE_RELPATH) + strlen(pm3dir) + 1];
        strcpy(script_directory_path, exec_path);
        strcat(script_directory_path, PM3_SHARE_RELPATH);
        strcat(script_directory_path, pm3dir);
        filelist(script_directory_path, ext, true, false, 0, 0);
    }
    return PM3_SUCCESS;
}

static int searchFinalFile(char **foundpath, const char *pm3dir, const char *searchname, bool silent) {

    if ((foundpath == NULL) || (pm3dir == NULL) || (searchname == NULL)) {
        return PM3_ESOFT;
    }

    // explicit absolute (/) or relative path (./) => try only to match it directly
    char *filename = calloc(strlen(searchname) + 1, sizeof(char));
    if (filename == NULL) {
        return PM3_EMALLOC;
    }

    strcpy(filename, searchname);
    if ((g_debugMode == 2) && (!silent)) {
        PrintAndLogEx(INFO, "pm3dir...... %s", pm3dir);
        PrintAndLogEx(INFO, "Searching... %s", filename);
    }

    // try implicit relative path
    PrintAndLogEx(DEBUG, "Searching implicit relative paths");
    if (fileExists(filename)) {
        *foundpath = filename;
        if ((g_debugMode == 2) && (!silent)) {
            PrintAndLogEx(INFO, "Found %s", *foundpath);
        }
        return PM3_SUCCESS;
    }

    if (((strlen(filename) > 1) && (filename[0] == '/')) ||
            ((strlen(filename) > 2) && (filename[0] == '.') && (filename[1] == '/'))) {
        goto out;
    }

    // try the session paths
    PrintAndLogEx(DEBUG, "Searching preferences paths");
    for (int i = 0; i < spItemCount; i++) {

        size_t sn = strlen(g_session.defaultPaths[i]) + strlen(filename) + strlen(PATHSEP) + 1;
        char *default_path = calloc(sn, sizeof(char));
        if (default_path == NULL) {
            goto out;
        }

        snprintf(default_path, sn, "%s%s%s", g_session.defaultPaths[i], PATHSEP, filename);

        if ((g_debugMode == 2) && (!silent)) {
            PrintAndLogEx(INFO, "Searching %s", default_path);
        }

        if (fileExists(default_path)) {
            free(filename);
            *foundpath = default_path;
            if ((g_debugMode == 2) && (!silent)) {
                PrintAndLogEx(INFO, "Found %s", *foundpath);
            }
            return PM3_SUCCESS;
        } else {
            free(default_path);
        }
    }

    // try pm3 dirs in user .proxmark3 (user mode)
    PrintAndLogEx(DEBUG, "Searching user .proxmark3 paths");
    const char *user_path = get_my_user_directory();
    if (user_path != NULL) {
        char *path = calloc(strlen(user_path) + strlen(PM3_USER_DIRECTORY) + strlen(pm3dir) + strlen(filename) + 1, sizeof(char));
        if (path == NULL) {
            goto out;
        }

        strcpy(path, user_path);
        strcat(path, PM3_USER_DIRECTORY);
        strcat(path, pm3dir);
        strcat(path, filename);

        if ((g_debugMode == 2) && (!silent)) {
            PrintAndLogEx(INFO, "Searching %s", path);
        }

        if (fileExists(path)) {
            free(filename);
            *foundpath = path;
            if ((g_debugMode == 2) && (!silent)) {
                PrintAndLogEx(INFO, "Found %s", *foundpath);
            }
            return PM3_SUCCESS;
        } else {
            free(path);
        }
    }

    // try pm3 dirs in current client workdir (dev mode)
    PrintAndLogEx(DEBUG, "Searching current workdir paths");
    const char *exec_path = get_my_executable_directory();
    if ((exec_path != NULL) &&
            ((strcmp(DICTIONARIES_SUBDIR, pm3dir) == 0) ||
             (strcmp(LUA_LIBRARIES_SUBDIR, pm3dir) == 0) ||
             (strcmp(LUA_SCRIPTS_SUBDIR, pm3dir) == 0) ||
             (strcmp(CMD_SCRIPTS_SUBDIR, pm3dir) == 0) ||
             (strcmp(PYTHON_SCRIPTS_SUBDIR, pm3dir) == 0) ||
             (strcmp(RESOURCES_SUBDIR, pm3dir) == 0))) {
        char *path = calloc(strlen(exec_path) + strlen(pm3dir) + strlen(filename) + 1, sizeof(char));
        if (path == NULL) {
            goto out;
        }

        strcpy(path, exec_path);
        strcat(path, pm3dir);
        strcat(path, filename);

        if ((g_debugMode == 2) && (!silent)) {
            PrintAndLogEx(INFO, "Searching %s", path);
        }

        if (fileExists(path)) {
            free(filename);
            *foundpath = path;
            if ((g_debugMode == 2) && (!silent)) {
                PrintAndLogEx(INFO, "Found %s", *foundpath);
            }
            return PM3_SUCCESS;
        } else {
            free(path);
        }
    }

    // try pm3 dirs in current repo workdir (dev mode)
    PrintAndLogEx(DEBUG, "Searching PM3 dirs in current workdir");
    if ((exec_path != NULL) &&
            ((strcmp(TRACES_SUBDIR, pm3dir) == 0) ||
             (strcmp(FIRMWARES_SUBDIR, pm3dir) == 0) ||
             (strcmp(BOOTROM_SUBDIR, pm3dir) == 0) ||
             (strcmp(FULLIMAGE_SUBDIR, pm3dir) == 0))) {
        char *path = calloc(strlen(exec_path) + strlen(ABOVE) + strlen(pm3dir) + strlen(filename) + 1, sizeof(char));
        if (path == NULL) {
            goto out;
        }

        strcpy(path, exec_path);
        strcat(path, ABOVE);
        strcat(path, pm3dir);
        strcat(path, filename);

        if ((g_debugMode == 2) && (!silent)) {
            PrintAndLogEx(INFO, "Searching %s", path);
        }

        if (fileExists(path)) {
            free(filename);
            *foundpath = path;
            if ((g_debugMode == 2) && (!silent)) {
                PrintAndLogEx(INFO, "Found %s", *foundpath);
            }
            return PM3_SUCCESS;
        } else {
            free(path);
        }
    }

    // try pm3 dirs in pm3 installation dir (install mode)
    PrintAndLogEx(DEBUG, "Searching PM3 installation dir paths");
    if (exec_path != NULL) {
        char *path = calloc(strlen(exec_path) + strlen(PM3_SHARE_RELPATH) + strlen(pm3dir) + strlen(filename) + 1, sizeof(char));
        if (path == NULL) {
            goto out;
        }

        strcpy(path, exec_path);
        strcat(path, PM3_SHARE_RELPATH);
        strcat(path, pm3dir);
        strcat(path, filename);

        if ((g_debugMode == 2) && (!silent)) {
            PrintAndLogEx(INFO, "Searching %s", path);
        }

        if (fileExists(path)) {
            free(filename);
            *foundpath = path;
            if ((g_debugMode == 2) && (!silent)) {
                PrintAndLogEx(INFO, "Found %s", *foundpath);
            }
            return PM3_SUCCESS;
        } else {
            free(path);
        }
    }
out:
    free(filename);
    return PM3_EFILE;
}

int searchFile(char **foundpath, const char *pm3dir, const char *searchname, const char *suffix, bool silent) {

    if (foundpath == NULL)
        return PM3_EINVARG;

    if (searchname == NULL || strlen(searchname) == 0)
        return PM3_EINVARG;

    if (is_directory(searchname))
        return PM3_EINVARG;

    char *filename = filenamemcopy(searchname, suffix);
    if (filename == NULL)
        return PM3_EMALLOC;

    if (strlen(filename) == 0) {
        free(filename);
        return PM3_EFILE;
    }

    int res = searchFinalFile(foundpath, pm3dir, filename, silent);
    if (res != PM3_SUCCESS) {
        if ((res == PM3_EFILE) && (!silent)) {
            PrintAndLogEx(FAILED, "Error - can't find `" _YELLOW_("%s") "`", filename);
        }
    }
    free(filename);
    return res;
}

int pm3_load_dump(const char *fn, void **pdump, size_t *dumplen, size_t maxdumplen) {

    int res = PM3_SUCCESS;
    DumpFileType_t dt = get_filetype(fn);
    switch (dt) {
        case BIN: {
            res = loadFile_safe(fn, ".bin", pdump, dumplen);
            break;
        }
        case EML: {
            res = loadFileEML_safe(fn, pdump, dumplen);
            break;
        }
        case JSON: {
            *pdump = calloc(maxdumplen, sizeof(uint8_t));
            if (*pdump == NULL) {
                PrintAndLogEx(WARNING, "fail, cannot allocate memory");
                return PM3_EMALLOC;
            }
            res = loadFileJSON(fn, *pdump, maxdumplen, dumplen, NULL);
            if (res == PM3_SUCCESS) {
                return res;
            }

            free(*pdump);

            if (res == PM3_ESOFT) {
                PrintAndLogEx(WARNING, "JSON objects failed to load");
            } else if (res == PM3_EMALLOC) {
                PrintAndLogEx(WARNING, "Wrong size of allocated memory. Check your parameters");
            }
            break;
        }
        case DICTIONARY: {
            PrintAndLogEx(ERR, "Only <BIN|EML|JSON|MCT|NFC formats allowed");
            return PM3_EINVARG;
        }
        case MCT: {
            res = loadFileMCT_safe(fn, pdump, dumplen);
            break;
        }
        case FLIPPER: {
            nfc_df_e dumptype;
            res = detect_nfc_dump_format(fn, &dumptype, true);
            if (res != PM3_SUCCESS) {
                break;
            }

            if (dumptype == NFC_DF_MFC || dumptype == NFC_DF_MFU || dumptype == NFC_DF_PICOPASS) {

                *pdump = calloc(maxdumplen, sizeof(uint8_t));
                if (*pdump == NULL) {
                    PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
                    return PM3_EMALLOC;
                }
                res = loadFileNFC_safe(fn, *pdump, maxdumplen, dumplen, dumptype);
                if (res == PM3_SUCCESS) {
                    return res;
                }

                free(*pdump);

                if (res == PM3_ESOFT) {
                    PrintAndLogEx(WARNING, "NFC objects failed to load");
                } else if (res == PM3_EMALLOC) {
                    PrintAndLogEx(WARNING, "wrong size of allocated memory. Check your parameters");
                }
            } else {
                // unknown dump file type
                res = PM3_ESOFT;
            }
            break;
        }
    }
    return res;
}

int pm3_save_dump(const char *fn, uint8_t *d, size_t n, JSONFileType jsft) {
    if (fn == NULL || strlen(fn) == 0) {
        return PM3_EINVARG;
    }
    if (d == NULL || n == 0) {
        PrintAndLogEx(INFO, "No data to save, skipping...");
        return PM3_EINVARG;
    }
    saveFile(fn, ".bin", d, n);
    saveFileJSON(fn, jsft, d, n, NULL);
    return PM3_SUCCESS;
}

int pm3_save_mf_dump(const char *fn, uint8_t *d, size_t n, JSONFileType jsft) {

    if (fn == NULL || d == NULL || n == 0) {
        PrintAndLogEx(INFO, "No data to save, skipping...");
        return PM3_EINVARG;
    }
    saveFileEx(fn, ".bin", d, n, spDump);

    iso14a_mf_extdump_t jd = {0};
    jd.card_info.ats_len = 0;

    // Check for 4 bytes uid: bcc corrected and single size uid bits in ATQA
    if ((d[0] ^ d[1] ^ d[2] ^ d[3]) == d[4] && (d[6] & 0xC0) == 0) {
        jd.card_info.uidlen = 4;
        memcpy(jd.card_info.uid, d, jd.card_info.uidlen);
        jd.card_info.sak = d[5];
        memcpy(jd.card_info.atqa, &d[6], sizeof(jd.card_info.atqa));
    }
    // Check for 7 bytes UID: double size uid bits in ATQA
    else if ((d[8] & 0xC0) == 0x40) {
        jd.card_info.uidlen = 7;
        memcpy(jd.card_info.uid, d, jd.card_info.uidlen);
        jd.card_info.sak = d[7];
        memcpy(jd.card_info.atqa, &d[8], sizeof(jd.card_info.atqa));
    } else {
        PrintAndLogEx(WARNING, "Invalid dump. UID/SAK/ATQA not found");
    }
    jd.dump = d;
    jd.dumplen = n;
    saveFileJSON(fn, jsfMfc_v2, (uint8_t *)&jd, sizeof(jd), NULL);
    return PM3_SUCCESS;
}

int pm3_save_fm11rf08s_nonces(const char *fn, iso14a_fm11rf08s_nonces_with_data_t *d, bool with_data) {

    if (fn == NULL || d == NULL) {
        PrintAndLogEx(INFO, "No data to save, skipping...");
        return PM3_EINVARG;
    }

    if (with_data) {
        saveFileJSON(fn, jsfFM11RF08SNoncesWithData, (uint8_t *)d, sizeof(*d), NULL);
    } else {
        saveFileJSON(fn, jsfFM11RF08SNonces, (uint8_t *)d, sizeof(*d), NULL);
    }
    return PM3_SUCCESS;
}

