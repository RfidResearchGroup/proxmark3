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
#include "protocols.h"    // iclass defines

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
DumpFileType_t getfiletype(const char *filename) {
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
 * @brief checks if path is file.
 * @param filename
 * @return
 */
/*
static bool is_regular_file(const char *filename) {
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
    return S_ISREG(st.st_mode) != 0;
}
*/

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

/**
 * @brief create a new directory.
 * @param dirname
 * @return
 */
// Not used...
/*
#ifdef _WIN32
#define make_dir(a) _mkdir(a)
#else
#define make_dir(a) mkdir(a,0755) //note 0755 MUST have leading 0 for octal linux file permissions
#endif
bool create_path(const char *dirname) {

    if (dirname == NULL) // nothing to do
        return false;

    if ((strlen(dirname) == 1) && (dirname[0] == '/'))
        return true;

    if ((strlen(dirname) == 2) && (dirname[1] == ':'))
        return true;

    if (fileExists(dirname) == 0) {

        char *bs = strrchr(dirname, '\\');
        char *fs = strrchr(dirname, '/');

        if ((bs == NULL) && (fs != NULL)) {
            *fs = 0x00;
            create_path (dirname);
            *fs = '/';
        }

        if ((bs != NULL) && (fs == NULL)) {
            *bs = 0x00;
            create_path (dirname);
            *bs = '\\';
        }

        if ((bs != NULL) && (fs != NULL)) {
            if (strlen (bs) > strlen (fs)) {
                *fs = 0x00; // No slash
                create_path (dirname);
                *fs = '/';
            } else {
                *bs = 0x00;
                create_path (dirname);
                *bs = '\\';
            }

        }

        if (make_dir(dirname) != 0) {
           PrintAndLogEx(ERR, "could not create directory.... "_RED_("%s"),dirname);
           return false;
        }
    }
    return true;
}
*/

bool setDefaultPath(savePaths_t pathIndex, const char *Path) {

    if (pathIndex < spItemCount) {
        if ((Path == NULL) && (g_session.defaultPaths[pathIndex] != NULL)) {
            free(g_session.defaultPaths[pathIndex]);
            g_session.defaultPaths[pathIndex] = NULL;
        }

        if (Path != NULL) {
            g_session.defaultPaths[pathIndex] = (char *)realloc(g_session.defaultPaths[pathIndex], strlen(Path) + 1);
            strcpy(g_session.defaultPaths[pathIndex], Path);
        }
        return true;
    }
    return false;
}

static char *filenamemcopy(const char *preferredName, const char *suffix) {
    if (preferredName == NULL) return NULL;
    if (suffix == NULL) return NULL;
    char *fileName = (char *) calloc(strlen(preferredName) + strlen(suffix) + 1, sizeof(uint8_t));
    if (fileName == NULL)
        return NULL;
    strcpy(fileName, preferredName);
    if (str_endswith(fileName, suffix))
        return fileName;
    strcat(fileName, suffix);
    return fileName;
}

char *newfilenamemcopy(const char *preferredName, const char *suffix) {
    if (preferredName == NULL) return NULL;
    if (suffix == NULL) return NULL;

    uint16_t p_namelen = strlen(preferredName);
    if (str_endswith(preferredName, suffix))
        p_namelen -= strlen(suffix);

    char *fileName = (char *) calloc(p_namelen + strlen(suffix) + 1 + 10, sizeof(uint8_t)); // 10: room for filenum to ensure new filename
    if (fileName == NULL) {
        return NULL;
    }

    int num = 1;
    sprintf(fileName, "%.*s%s", p_namelen, preferredName, suffix);
    while (fileExists(fileName)) {
        sprintf(fileName, "%.*s-%d%s", p_namelen, preferredName, num, suffix);
        num++;
    }
    return fileName;
}

int saveFile(const char *preferredName, const char *suffix, const void *data, size_t datalen) {

    if (data == NULL) return PM3_EINVARG;
    char *fileName = newfilenamemcopy(preferredName, suffix);
    if (fileName == NULL) return PM3_EMALLOC;

    /* We should have a valid filename now, e.g. dumpdata-3.bin */

    /*Opening file for writing in binary mode*/
    FILE *f = fopen(fileName, "wb");
    if (!f) {
        PrintAndLogEx(WARNING, "file not found or locked. '" _YELLOW_("%s")"'", fileName);
        free(fileName);
        return PM3_EFILE;
    }
    fwrite(data, 1, datalen, f);
    fflush(f);
    fclose(f);
    PrintAndLogEx(SUCCESS, "saved " _YELLOW_("%zu") " bytes to binary file " _YELLOW_("%s"), datalen, fileName);
    free(fileName);
    return PM3_SUCCESS;
}

int saveFileEML(const char *preferredName, uint8_t *data, size_t datalen, size_t blocksize) {

    if (data == NULL) return PM3_EINVARG;
    char *fileName = newfilenamemcopy(preferredName, ".eml");
    if (fileName == NULL) return PM3_EMALLOC;

    int retval = PM3_SUCCESS;
    int blocks = datalen / blocksize;
    uint16_t currblock = 1;

    /* We should have a valid filename now, e.g. dumpdata-3.bin */

    /*Opening file for writing in text mode*/
    FILE *f = fopen(fileName, "w+");
    if (!f) {
        PrintAndLogEx(WARNING, "file not found or locked. '" _YELLOW_("%s")"'", fileName);
        retval = PM3_EFILE;
        goto out;
    }

    for (size_t i = 0; i < datalen; i++) {
        fprintf(f, "%02X", data[i]);

        // no extra line in the end
        if ((i + 1) % blocksize == 0 && currblock != blocks) {
            fprintf(f, "\n");
            currblock++;
        }
    }
    // left overs
    if (datalen % blocksize != 0) {
        int index = blocks * blocksize;
        for (size_t j = 0; j < datalen % blocksize; j++) {
            fprintf(f, "%02X", data[index + j]);
        }
    }
    fflush(f);
    fclose(f);
    PrintAndLogEx(SUCCESS, "saved " _YELLOW_("%" PRId32) " blocks to text file " _YELLOW_("%s"), blocks, fileName);

out:
    free(fileName);
    return retval;
}

int saveFileJSON(const char *preferredName, JSONFileType ftype, uint8_t *data, size_t datalen, void (*callback)(json_t *)) {
    return saveFileJSONex(preferredName, ftype, data, datalen, true, callback);
}
int saveFileJSONex(const char *preferredName, JSONFileType ftype, uint8_t *data, size_t datalen, bool verbose, void (*callback)(json_t *)) {

    if (data == NULL) return PM3_EINVARG;

    char *fileName = newfilenamemcopy(preferredName, ".json");
    if (fileName == NULL) return PM3_EMALLOC;

    int retval = PM3_SUCCESS;

    json_t *root = json_object();
    JsonSaveStr(root, "Created", "proxmark3");
    switch (ftype) {
        case jsfRaw: {
            JsonSaveStr(root, "FileType", "raw");
            JsonSaveBufAsHexCompact(root, "raw", data, datalen);
            break;
        }
        case jsfCardMemory: {
            iso14a_mf_extdump_t *xdump = (iso14a_mf_extdump_t *)(void *) data;
            JsonSaveStr(root, "FileType", "mfcard");
            JsonSaveBufAsHexCompact(root, "$.Card.UID", xdump->card_info.uid, xdump->card_info.uidlen);
            JsonSaveBufAsHexCompact(root, "$.Card.ATQA", xdump->card_info.atqa, 2);
            JsonSaveBufAsHexCompact(root, "$.Card.SAK", &(xdump->card_info.sak), 1);
            for (size_t i = 0; i < (xdump->dumplen / 16); i++) {
                char path[PATH_MAX_LENGTH] = {0};
                sprintf(path, "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, &xdump->dump[i * 16], 16);
                if (mfIsSectorTrailer(i)) {
                    snprintf(path, sizeof(path), "$.SectorKeys.%d.KeyA", mfSectorNum(i));
                    JsonSaveBufAsHexCompact(root, path, &xdump->dump[i * 16], 6);

                    snprintf(path, sizeof(path), "$.SectorKeys.%d.KeyB", mfSectorNum(i));
                    JsonSaveBufAsHexCompact(root, path, &xdump->dump[i * 16 + 10], 6);

                    uint8_t *adata = &xdump->dump[i * 16 + 6];
                    snprintf(path, sizeof(path), "$.SectorKeys.%d.AccessConditions", mfSectorNum(i));
                    JsonSaveBufAsHexCompact(root, path, &xdump->dump[i * 16 + 6], 4);

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
        case jsfMfuMemory: {
            JsonSaveStr(root, "FileType", "mfu");

            mfu_dump_t *tmp = (mfu_dump_t *)data;

            uint8_t uid[7] = {0};
            memcpy(uid, tmp->data, 3);
            memcpy(uid + 3, tmp->data + 4, 4);

            char path[PATH_MAX_LENGTH] = {0};

            JsonSaveBufAsHexCompact(root, "$.Card.UID", uid, sizeof(uid));
            JsonSaveBufAsHexCompact(root, "$.Card.Version", tmp->version, sizeof(tmp->version));
            JsonSaveBufAsHexCompact(root, "$.Card.TBO_0", tmp->tbo, sizeof(tmp->tbo));
            JsonSaveBufAsHexCompact(root, "$.Card.TBO_1", tmp->tbo1, sizeof(tmp->tbo1));
            JsonSaveBufAsHexCompact(root, "$.Card.Signature", tmp->signature, sizeof(tmp->signature));
            for (uint8_t i = 0; i < 3; i ++) {
                sprintf(path, "$.Card.Counter%d", i);
                JsonSaveBufAsHexCompact(root, path, tmp->counter_tearing[i], 3);
                sprintf(path, "$.Card.Tearing%d", i);
                JsonSaveBufAsHexCompact(root, path, tmp->counter_tearing[i] + 3, 1);
            }

            // size of header 56b
            size_t len = (datalen - MFU_DUMP_PREFIX_LENGTH) / 4;

            for (size_t i = 0; i < len; i++) {
                sprintf(path, "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, tmp->data + (i * 4), 4);
            }
            break;
        }
        case jsfHitag: {
            JsonSaveStr(root, "FileType", "hitag");
            uint8_t uid[4] = {0};
            memcpy(uid, data, 4);

            JsonSaveBufAsHexCompact(root, "$.Card.UID", uid, sizeof(uid));

            for (size_t i = 0; i < (datalen / 4); i++) {
                char path[PATH_MAX_LENGTH] = {0};
                sprintf(path, "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, data + (i * 4), 4);
            }
            break;
        }
        case jsfIclass: {
            JsonSaveStr(root, "FileType", "iclass");

            picopass_hdr_t *hdr = (picopass_hdr_t *)data;
            JsonSaveBufAsHexCompact(root, "$.Card.CSN", hdr->csn, sizeof(hdr->csn));
            JsonSaveBufAsHexCompact(root, "$.Card.Configuration", (uint8_t *)&hdr->conf, sizeof(hdr->conf));

            uint8_t pagemap = get_pagemap(hdr);
            if (pagemap == PICOPASS_NON_SECURE_PAGEMODE) {
                picopass_ns_hdr_t *ns_hdr = (picopass_ns_hdr_t *)data;
                JsonSaveBufAsHexCompact(root, "$.Card.AIA", ns_hdr->app_issuer_area, sizeof(ns_hdr->app_issuer_area));
            } else {
                JsonSaveBufAsHexCompact(root, "$.Card.Epurse", hdr->epurse, sizeof(hdr->epurse));
                JsonSaveBufAsHexCompact(root, "$.Card.Kd", hdr->key_d, sizeof(hdr->key_d));
                JsonSaveBufAsHexCompact(root, "$.Card.Kc", hdr->key_c, sizeof(hdr->key_c));
                JsonSaveBufAsHexCompact(root, "$.Card.AIA", hdr->app_issuer_area, sizeof(hdr->app_issuer_area));
            }

            for (size_t i = 0; i < (datalen / 8); i++) {
                char path[PATH_MAX_LENGTH] = {0};
                sprintf(path, "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, data + (i * 8), 8);
            }

            break;
        }
        case jsfT55x7: {
            JsonSaveStr(root, "FileType", "t55x7");
            uint8_t conf[4] = {0};
            memcpy(conf, data, 4);
            JsonSaveBufAsHexCompact(root, "$.Card.ConfigBlock", conf, sizeof(conf));

            for (size_t i = 0; i < (datalen / 4); i++) {
                char path[PATH_MAX_LENGTH] = {0};
                sprintf(path, "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, data + (i * 4), 4);
            }
            break;
        }
        case jsf14b: {
            JsonSaveStr(root, "FileType", "14b");
            JsonSaveBufAsHexCompact(root, "raw", data, datalen);
            break;
        }
        case jsf15: {
            JsonSaveStr(root, "FileType", "15693");
            JsonSaveBufAsHexCompact(root, "raw", data, datalen);
            break;
        }
        case jsfLegic: {
            JsonSaveStr(root, "FileType", "legic");
            JsonSaveBufAsHexCompact(root, "raw", data, datalen);
            break;
        }
        case jsfT5555: {
            JsonSaveStr(root, "FileType", "t5555");
            uint8_t conf[4] = {0};
            memcpy(conf, data, 4);
            JsonSaveBufAsHexCompact(root, "$.Card.ConfigBlock", conf, sizeof(conf));

            for (size_t i = 0; i < (datalen / 4); i++) {
                char path[PATH_MAX_LENGTH] = {0};
                sprintf(path, "$.blocks.%zu", i);
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
                char path[PATH_MAX_LENGTH] = {0};
                sprintf(path, "$.blocks.%zu", i);
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
                char path[PATH_MAX_LENGTH] = {0};
                sprintf(path, "$.blocks.%zu", i);
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
                char path[PATH_MAX_LENGTH] = {0};
                sprintf(path, "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, data + (i * 4), 4);
            }
            break;
        }
        case jsfMfPlusKeys: {
            JsonSaveStr(root, "FileType", "mfp");
            JsonSaveBufAsHexCompact(root, "$.Card.UID", &data[0], 7);
            JsonSaveBufAsHexCompact(root, "$.Card.SAK", &data[10], 1);
            JsonSaveBufAsHexCompact(root, "$.Card.ATQA", &data[11], 2);
            uint8_t atslen = data[13];
            if (atslen > 0)
                JsonSaveBufAsHexCompact(root, "$.Card.ATS", &data[14], atslen);

            uint8_t vdata[2][64][16 + 1] = {{{0}}};
            memcpy(vdata, &data[14 + atslen], 2 * 64 * 17);

            for (size_t i = 0; i < datalen; i++) {
                char path[PATH_MAX_LENGTH] = {0};

                if (vdata[0][i][0]) {
                    memset(path, 0x00, sizeof(path));
                    sprintf(path, "$.SectorKeys.%d.KeyA", mfSectorNum(i));
                    JsonSaveBufAsHexCompact(root, path, &vdata[0][i][1], 16);
                }

                if (vdata[1][i][0]) {
                    memset(path, 0x00, sizeof(path));
                    sprintf(path, "$.SectorKeys.%d.KeyB", mfSectorNum(i));
                    JsonSaveBufAsHexCompact(root, path, &vdata[1][i][1], 16);
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
                char path[PATH_MAX_LENGTH] = {0};

                if (dvdata[0][i][0]) {
                    memset(path, 0x00, sizeof(path));
                    sprintf(path, "$.DES.%d.Key", i);
                    JsonSaveBufAsHexCompact(root, path, &dvdata[0][i][1], 8);
                }

                if (dvdata[1][i][0]) {
                    memset(path, 0x00, sizeof(path));
                    sprintf(path, "$.3DES.%d.Key", i);
                    JsonSaveBufAsHexCompact(root, path, &dvdata[1][i][1], 16);
                }
                if (dvdata[2][i][0]) {
                    memset(path, 0x00, sizeof(path));
                    sprintf(path, "$.AES.%d.Key", i);
                    JsonSaveBufAsHexCompact(root, path, &dvdata[2][i][1], 16);
                }
                if (dvdata[3][i][0]) {
                    memset(path, 0x00, sizeof(path));
                    sprintf(path, "$.K3KDES.%d.Key", i);
                    JsonSaveBufAsHexCompact(root, path, &dvdata[3][i][1], 24);
                }
            }
            break;
        }
        case jsfFido: {
            break;
        }
        case jsfCustom: {
            (*callback)(root);
            break;
        }
        default:
            break;
    }

    int res = json_dump_file(root, fileName, JSON_INDENT(2));
    if (res) {
        PrintAndLogEx(FAILED, "error: can't save the file: " _YELLOW_("%s"), fileName);
        retval = 200;
        goto out;
    }

    if (verbose) {
        PrintAndLogEx(SUCCESS, "saved to json file " _YELLOW_("%s"), fileName);
    }

out:
    json_decref(root);
    free(fileName);
    return retval;
}
int saveFileJSONroot(const char *preferredName, void *root, size_t flags, bool verbose) {
    return saveFileJSONrootEx(preferredName, root, flags, verbose, false);
}
int saveFileJSONrootEx(const char *preferredName, void *root, size_t flags, bool verbose, bool overwrite) {
    if (root == NULL)
        return PM3_EINVARG;

    char *filename = NULL;
    if (overwrite)
        filename = filenamemcopy(preferredName, ".json");
    else
        filename = newfilenamemcopy(preferredName, ".json");

    if (filename == NULL)
        return PM3_EMALLOC;

    int res = json_dump_file(root, filename, flags);

    if (res == 0) {
        if (verbose) {
            PrintAndLogEx(SUCCESS, "saved to json file " _YELLOW_("%s"), filename);
        }
        free(filename);
        return PM3_SUCCESS;
    } else {
        PrintAndLogEx(FAILED, "error: can't save the file: " _YELLOW_("%s"), filename);
    }
    free(filename);
    return PM3_EFILE;
}

int saveFileWAVE(const char *preferredName, const int *data, size_t datalen) {

    if (data == NULL) return PM3_EINVARG;
    char *fileName = newfilenamemcopy(preferredName, ".wav");
    if (fileName == NULL) return PM3_EMALLOC;
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
        PrintAndLogEx(WARNING, "file not found or locked. "_YELLOW_("'%s'"), fileName);
        retval = PM3_EFILE;
        goto out;
    }
    fwrite(&wave_info, sizeof(wave_info), 1, wave_file);
    for (int i = 0; i < datalen; i++) {
        uint8_t sample = data[i] + 128;
        fwrite(&sample, 1, 1, wave_file);
    }
    fclose(wave_file);

    PrintAndLogEx(SUCCESS, "saved " _YELLOW_("%zu") " bytes to wave file " _YELLOW_("'%s'"), 2 * datalen, fileName);

out:
    free(fileName);
    return retval;
}

int saveFilePM3(const char *preferredName, int *data, size_t datalen) {

    if (data == NULL) return PM3_EINVARG;
    char *fileName = newfilenamemcopy(preferredName, ".pm3");
    if (fileName == NULL) return PM3_EMALLOC;

    int retval = PM3_SUCCESS;

    FILE *f = fopen(fileName, "w");
    if (!f) {
        PrintAndLogEx(WARNING, "file not found or locked. "_YELLOW_("'%s'"), fileName);
        retval = PM3_EFILE;
        goto out;
    }

    for (uint32_t i = 0; i < datalen; i++)
        fprintf(f, "%d\n", data[i]);

    fflush(f);
    fclose(f);
    PrintAndLogEx(SUCCESS, "saved " _YELLOW_("%zu") " bytes to PM3 file " _YELLOW_("'%s'"), datalen, fileName);

out:
    free(fileName);
    return retval;
}

int createMfcKeyDump(const char *preferredName, uint8_t sectorsCnt, sector_t *e_sector) {

    if (e_sector == NULL) return PM3_EINVARG;

    char *fileName = newfilenamemcopy(preferredName, ".bin");
    if (fileName == NULL) return PM3_EMALLOC;

    FILE *f = fopen(fileName, "wb");
    if (f == NULL) {
        PrintAndLogEx(WARNING, "Could not create file " _YELLOW_("%s"), fileName);
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
    PrintAndLogEx(SUCCESS, "Found keys have been dumped to " _YELLOW_("%s"), fileName);
    PrintAndLogEx(INFO, "FYI! --> " _YELLOW_("0xFFFFFFFFFFFF") " <-- has been inserted for unknown keys where " _YELLOW_("res") " is " _YELLOW_("0"));
    free(fileName);
    return PM3_SUCCESS;
}

int loadFile(const char *preferredName, const char *suffix, void *data, size_t maxdatalen, size_t *datalen) {

    if (data == NULL) return 1;
    char *fileName = filenamemcopy(preferredName, suffix);
    if (fileName == NULL) return PM3_EINVARG;

    int retval = PM3_SUCCESS;

    FILE *f = fopen(fileName, "rb");
    if (!f) {
        PrintAndLogEx(WARNING, "file not found or locked. '" _YELLOW_("%s")"'", fileName);
        free(fileName);
        return PM3_EFILE;
    }

    // get filesize in order to malloc memory
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0) {
        PrintAndLogEx(FAILED, "error, when getting filesize");
        retval = PM3_EFILE;
        goto out;
    }

    uint8_t *dump = calloc(fsize, sizeof(uint8_t));
    if (!dump) {
        PrintAndLogEx(FAILED, "error, cannot allocate memory");
        retval = PM3_EMALLOC;
        goto out;
    }

    size_t bytes_read = fread(dump, 1, fsize, f);

    if (bytes_read != fsize) {
        PrintAndLogEx(FAILED, "error, bytes read mismatch file size");
        free(dump);
        retval = PM3_EFILE;
        goto out;
    }

    if (bytes_read > maxdatalen) {
        PrintAndLogEx(WARNING, "Warning, bytes read exceed calling array limit. Max bytes is %zu bytes", maxdatalen);
        bytes_read = maxdatalen;
    }

    memcpy((data), dump, bytes_read);
    free(dump);

    PrintAndLogEx(SUCCESS, "loaded " _YELLOW_("%zu") " bytes from binary file " _YELLOW_("%s"), bytes_read, fileName);

    *datalen = bytes_read;

out:
    fclose(f);
    free(fileName);
    return retval;
}

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
        PrintAndLogEx(WARNING, "file not found or locked. '" _YELLOW_("%s")"'", path);
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

    if (verbose)
        PrintAndLogEx(SUCCESS, "loaded " _YELLOW_("%zu") " bytes from binary file " _YELLOW_("%s"), bytes_read, preferredName);
    return PM3_SUCCESS;
}

int loadFileEML(const char *preferredName, void *data, size_t *datalen) {

    if (data == NULL) return PM3_EINVARG;

    char *fileName = filenamemcopy(preferredName, ".eml");
    if (fileName == NULL) return PM3_EMALLOC;

    size_t counter = 0;
    int retval = PM3_SUCCESS, hexlen = 0;

    FILE *f = fopen(fileName, "r");
    if (!f) {
        PrintAndLogEx(WARNING, "file not found or locked. '" _YELLOW_("%s")"'", fileName);
        retval = PM3_EFILE;
        goto out;
    }

    // 128 + 2 newline chars + 1 null terminator
    char line[131];
    memset(line, 0, sizeof(line));
    uint8_t buf[64] = {0x00};

    uint8_t *udata = (uint8_t *)data;

    while (!feof(f)) {

        memset(line, 0, sizeof(line));

        if (fgets(line, sizeof(line), f) == NULL) {
            if (feof(f))
                break;

            fclose(f);
            PrintAndLogEx(FAILED, "File reading error.");
            retval = PM3_EFILE;
            goto out;
        }

        if (line[0] == '#')
            continue;

        strcleanrn(line, sizeof(line));

        int res = param_gethex_to_eol(line, 0, buf, sizeof(buf), &hexlen);
        if (res == 0) {
            memcpy(udata + counter, buf, hexlen);
            counter += hexlen;
        } else {
            retval = PM3_ESOFT;
        }
    }
    fclose(f);
    PrintAndLogEx(SUCCESS, "loaded " _YELLOW_("%zu") " bytes from text file " _YELLOW_("%s"), counter, fileName);

    if (datalen)
        *datalen = counter;

out:
    free(fileName);
    return retval;
}
int loadFileEML_safe(const char *preferredName, void **pdata, size_t *datalen) {
    char *path;
    int res = searchFile(&path, RESOURCES_SUBDIR, preferredName, "", false);
    if (res != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    FILE *f = fopen(path, "r");
    if (!f) {
        PrintAndLogEx(WARNING, "file not found or locked. '" _YELLOW_("%s")"'", path);
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
            PrintAndLogEx(FAILED, "File reading error.");
            return PM3_EFILE;
        }

        if (line[0] == '#')
            continue;

        strcleanrn(line, sizeof(line));

        res = param_gethex_to_eol(line, 0, buf, sizeof(buf), &hexlen);
        if (res == 0) {
            memcpy(tmp + counter, buf, hexlen);
            counter += hexlen;
        } else {
            retval = PM3_ESOFT;
        }
    }
    fclose(f);
    PrintAndLogEx(SUCCESS, "loaded " _YELLOW_("%zu") " bytes from text file " _YELLOW_("%s"), counter, preferredName);


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
    if (verbose)
        PrintAndLogEx(SUCCESS, "loaded from JSON file " _YELLOW_("%s"), path);

    free(path);

    if (!root) {
        PrintAndLogEx(ERR, "ERROR: json " _YELLOW_("%s") " error on line %d: %s", preferredName, error.line, error.text);
        retval = PM3_ESOFT;
        goto out;
    }

    if (!json_is_object(root)) {
        PrintAndLogEx(ERR, "ERROR: Invalid json " _YELLOW_("%s") " format. root must be an object.", preferredName);
        retval = PM3_ESOFT;
        goto out;
    }

    uint8_t *udata = (uint8_t *)data;
    char ctype[100] = {0};
    JsonLoadStr(root, "$.FileType", ctype);

    if (!strcmp(ctype, "raw")) {
        JsonLoadBufAsHex(root, "$.raw", udata, maxdatalen, datalen);
    }

    if (!strcmp(ctype, "mfcard")) {
        size_t sptr = 0;
        for (int i = 0; i < 256; i++) {
            if (sptr + 16 > maxdatalen) {
                retval = PM3_EMALLOC;
                goto out;
            }

            char blocks[30] = {0};
            sprintf(blocks, "$.blocks.%d", i);

            size_t len = 0;
            JsonLoadBufAsHex(root, blocks, &udata[sptr], 16, &len);
            if (!len)
                break;

            sptr += len;
        }

        *datalen = sptr;
    }

    if (!strcmp(ctype, "mfu")) {
        size_t sptr = 0;
        for (int i = 0; i < 256; i++) {
            if (sptr + 4 > maxdatalen) {
                retval = PM3_EMALLOC;
                goto out;
            }

            char blocks[30] = {0};
            sprintf(blocks, "$.blocks.%d", i);

            size_t len = 0;
            JsonLoadBufAsHex(root, blocks, &udata[sptr], 4, &len);
            if (!len)
                break;

            sptr += len;
        }

        *datalen = sptr;
    }

    if (!strcmp(ctype, "hitag")) {
        size_t sptr = 0;
        for (size_t i = 0; i < (maxdatalen / 4); i++) {
            if (sptr + 4 > maxdatalen) {
                retval = PM3_EMALLOC;
                goto out;
            }

            char blocks[30] = {0};
            sprintf(blocks, "$.blocks.%zu", i);

            size_t len = 0;
            JsonLoadBufAsHex(root, blocks, &udata[sptr], 4, &len);
            if (!len)
                break;

            sptr += len;
        }

        *datalen = sptr;
    }

    if (!strcmp(ctype, "iclass")) {
        size_t sptr = 0;
        for (size_t i = 0; i < (maxdatalen / 8); i++) {
            if (sptr + 8 > maxdatalen) {
                retval = PM3_EMALLOC;
                goto out;
            }

            char blocks[30] = {0};
            sprintf(blocks, "$.blocks.%zu", i);

            size_t len = 0;
            JsonLoadBufAsHex(root, blocks, &udata[sptr], 8, &len);
            if (!len)
                break;

            sptr += len;
        }
        *datalen = sptr;
    }

    if (!strcmp(ctype, "t55x7")) {
        size_t sptr = 0;
        for (size_t i = 0; i < (maxdatalen / 4); i++) {
            if (sptr + 4 > maxdatalen) {
                retval = PM3_EMALLOC;
                goto out;
            }

            char blocks[30] = {0};
            sprintf(blocks, "$.blocks.%zu", i);

            size_t len = 0;
            JsonLoadBufAsHex(root, blocks, &udata[sptr], 4, &len);
            if (!len)
                break;

            sptr += len;
        }
        *datalen = sptr;
    }

    if (!strcmp(ctype, "EM4X50")) {
        size_t sptr = 0;
        for (size_t i = 0; i < (maxdatalen / 4); i++) {
            if (sptr + 4 > maxdatalen) {
                retval = PM3_EMALLOC;
                goto out;
            }

            char blocks[30] = {0};
            sprintf(blocks, "$.blocks.%zu", i);

            size_t len = 0;
            JsonLoadBufAsHex(root, blocks, &udata[sptr], 4, &len);
            if (!len)
                break;

            sptr += len;
        }
        *datalen = sptr;
    }

    if (!strcmp(ctype, "15693")) {
        JsonLoadBufAsHex(root, "$.raw", udata, maxdatalen, datalen);
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
    if (verbose)
        PrintAndLogEx(SUCCESS, "loaded from JSON file " _YELLOW_("%s"), path);

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

    if (data == NULL) return PM3_EINVARG;

    if (endFilePosition)
        *endFilePosition = 0;

    char *path;
    if (searchFile(&path, DICTIONARIES_SUBDIR, preferredName, ".dic", false) != PM3_SUCCESS)
        return PM3_EFILE;

    // double up since its chars
    keylen <<= 1;

    char line[255];
    uint32_t vkeycnt = 0;
    size_t counter = 0;
    int retval = PM3_SUCCESS;

    FILE *f = fopen(path, "r");
    if (!f) {
        PrintAndLogEx(WARNING, "file not found or locked. '" _YELLOW_("%s")"'", path);
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
            if (endFilePosition)
                *endFilePosition = 0;
            break;
        }

        // add null terminator
        line[keylen] = 0;

        // smaller keys than expected is skipped
        if (strlen(line) < keylen)
            continue;

        // The line start with # is comment, skip
        if (line[0] == '#')
            continue;

        if (!CheckStringIsHEXValue(line))
            continue;

        // cant store more data
        if (maxdatalen && (counter + (keylen >> 1) > maxdatalen)) {
            retval = 1;
            if (endFilePosition)
                *endFilePosition = filepos;
            break;
        }

        if (hex_to_bytes(line, udata + counter, keylen >> 1) != (keylen >> 1))
            continue;

        vkeycnt++;
        memset(line, 0, sizeof(line));
        counter += (keylen >> 1);
    }
    fclose(f);
    if (verbose)
        PrintAndLogEx(SUCCESS, "loaded " _GREEN_("%2d") " keys from dictionary file " _YELLOW_("%s"), vkeycnt, path);

    if (datalen)
        *datalen = counter;
    if (keycnt)
        *keycnt = vkeycnt;
out:
    free(path);
    return retval;
}

int loadFileDICTIONARY_safe(const char *preferredName, void **pdata, uint8_t keylen, uint32_t *keycnt) {

    int retval = PM3_SUCCESS;

    char *path;
    if (searchFile(&path, DICTIONARIES_SUBDIR, preferredName, ".dic", false) != PM3_SUCCESS)
        return PM3_EFILE;

    // t5577 == 4bytes
    // mifare == 6 bytes
    // mf plus == 16 bytes
    // mf desfire == 3des3k 24 bytes
    // iclass == 8 bytes
    // default to 6 bytes.
    if (keylen != 4 && keylen != 6 && keylen != 8 && keylen != 16 && keylen != 24) {
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
        PrintAndLogEx(WARNING, "file not found or locked. '" _YELLOW_("%s")"'", path);
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
        if (strlen(line) < keylen)
            continue;

        // The line start with # is comment, skip
        if (line[0] == '#')
            continue;

        if (!CheckStringIsHEXValue(line))
            continue;

        uint64_t key = strtoull(line, NULL, 16);

        num_to_bytes(key, keylen >> 1, (uint8_t *)*pdata + (*keycnt * (keylen >> 1)));

        (*keycnt)++;

        memset(line, 0, sizeof(line));
    }
    fclose(f);
    PrintAndLogEx(SUCCESS, "loaded " _GREEN_("%2d") " keys from dictionary file " _YELLOW_("%s"), *keycnt, path);

out:
    free(path);
    return retval;
}

mfu_df_e detect_mfu_dump_format(uint8_t **dump, size_t *dumplen, bool verbose) {

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
        uint8_t *plain = *dump;
        bcc0 = ct ^ plain[0] ^ plain[1] ^ plain[2];
        bcc1 = plain[4] ^ plain[5] ^ plain[6] ^ plain[7];
        if ((bcc0 == plain[3]) && (bcc1 == plain[8])) {
            retval = MFU_DF_PLAINBIN;
        }
    }

    if (verbose) {
        switch (retval) {
            case MFU_DF_NEWBIN:
                PrintAndLogEx(INFO, "detected " _GREEN_("new") " mfu dump format");
                break;
            case MFU_DF_OLDBIN:
                PrintAndLogEx(INFO, "detected " _GREEN_("old") " mfu dump format");
                break;
            case MFU_DF_PLAINBIN:
                PrintAndLogEx(INFO, "detected " _GREEN_("plain") " mfu dump format");
                break;
            case MFU_DF_UNKNOWN:
                PrintAndLogEx(WARNING, "failed to detected mfu dump format");
                break;
        }
    }
    return retval;
}

static int convert_plain_mfu_dump(uint8_t **dump, size_t *dumplen, bool verbose) {

    mfu_dump_t *mfu = (mfu_dump_t *) calloc(sizeof(mfu_dump_t), sizeof(uint8_t));
    if (mfu == NULL) {
        return PM3_EMALLOC;
    }

    memcpy(mfu->data, *dump, *dumplen);

    mfu->pages = *dumplen / 4 - 1;

    if (verbose) {
        PrintAndLogEx(SUCCESS, "plain mfu dump format was converted to " _GREEN_("%d") " blocks", mfu->pages + 1);
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
        PrintAndLogEx(SUCCESS, "old mfu dump format was converted to " _GREEN_("%d") " blocks", mfu_dump->pages + 1);
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

    mfu_df_e res = detect_mfu_dump_format(dump, dumplen, verbose);

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

    for (uint16_t i = 0; i < n; i++) {

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
    if ((foundpath == NULL) || (pm3dir == NULL) || (searchname == NULL)) return PM3_ESOFT;
    // explicit absolute (/) or relative path (./) => try only to match it directly
    char *filename = calloc(strlen(searchname) + 1, sizeof(char));
    if (filename == NULL) return PM3_EMALLOC;
    strcpy(filename, searchname);
    if ((g_debugMode == 2) && (!silent)) {
        PrintAndLogEx(INFO, "Searching %s", filename);
    }
    if (((strlen(filename) > 1) && (filename[0] == '/')) ||
            ((strlen(filename) > 2) && (filename[0] == '.') && (filename[1] == '/'))) {
        if (fileExists(filename)) {
            *foundpath = filename;
            if ((g_debugMode == 2) && (!silent)) {
                PrintAndLogEx(INFO, "Found %s", *foundpath);
            }
            return PM3_SUCCESS;
        } else {
            goto out;
        }
    }
    // else

    // try implicit relative path
    {
        if (fileExists(filename)) {
            *foundpath = filename;
            if ((g_debugMode == 2) && (!silent)) {
                PrintAndLogEx(INFO, "Found %s", *foundpath);
            }
            return PM3_SUCCESS;
        }
    }
    // try pm3 dirs in user .proxmark3 (user mode)
    const char *user_path = get_my_user_directory();
    if (user_path != NULL) {
        char *path = calloc(strlen(user_path) + strlen(PM3_USER_DIRECTORY) + strlen(pm3dir) + strlen(filename) + 1, sizeof(char));
        if (path == NULL)
            goto out;
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
    const char *exec_path = get_my_executable_directory();
    if ((exec_path != NULL) &&
            ((strcmp(DICTIONARIES_SUBDIR, pm3dir) == 0) ||
             (strcmp(LUA_LIBRARIES_SUBDIR, pm3dir) == 0) ||
             (strcmp(LUA_SCRIPTS_SUBDIR, pm3dir) == 0) ||
             (strcmp(CMD_SCRIPTS_SUBDIR, pm3dir) == 0) ||
             (strcmp(PYTHON_SCRIPTS_SUBDIR, pm3dir) == 0) ||
             (strcmp(RESOURCES_SUBDIR, pm3dir) == 0))) {
        char *path = calloc(strlen(exec_path) + strlen(pm3dir) + strlen(filename) + 1, sizeof(char));
        if (path == NULL)
            goto out;
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
    if ((exec_path != NULL) &&
            ((strcmp(TRACES_SUBDIR, pm3dir) == 0) ||
             (strcmp(FIRMWARES_SUBDIR, pm3dir) == 0) ||
             (strcmp(BOOTROM_SUBDIR, pm3dir) == 0) ||
             (strcmp(FULLIMAGE_SUBDIR, pm3dir) == 0))) {
        const char *above = "../";
        char *path = calloc(strlen(exec_path) + strlen(above) + strlen(pm3dir) + strlen(filename) + 1, sizeof(char));
        if (path == NULL)
            goto out;
        strcpy(path, exec_path);
        strcat(path, above);
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
    if (exec_path != NULL) {
        char *path = calloc(strlen(exec_path) + strlen(PM3_SHARE_RELPATH) + strlen(pm3dir) + strlen(filename) + 1, sizeof(char));
        if (path == NULL)
            goto out;
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
        if ((res == PM3_EFILE) && (!silent))
            PrintAndLogEx(FAILED, "Error - can't find `" _YELLOW_("%s") "`", filename);
        free(filename);
        return res;
    }
    free(filename);
    return PM3_SUCCESS;
}
