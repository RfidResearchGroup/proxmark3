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
#include "hitag.h"

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
        char *s = str_dup(filename);
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
        } else if (str_endswith(s, "xml")) {
            o = TAGINFO;
        } else if (str_endswith(s, "rfid")) {
            o = BRUCE;
        } else {
            // mfd, trc, trace is binary
            o = BIN;
            // log is text
            // .pm3 is text values of signal data
        }

        free(s);
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
bool path_is_directory(const char *path) {
    if (path == NULL) {
        return false;
    }
#ifdef _WIN32
    struct _stat st;
    if (_stat(path, &st) == -1)
        return false;
#else
    struct stat st;
//    stat(filename, &st);
    if (lstat(path, &st) == -1)
        return false;
#endif
    return S_ISDIR(st.st_mode) != 0;
}

bool path_is_regular_file(const char *path) {
    if (path == NULL) {
        return false;
    }
#ifdef _WIN32
    struct _stat st;
    if (_stat(path, &st) == -1)
        return false;
#else
    struct stat st;
    if (stat(path, &st) == -1)
        return false;
#endif
    return S_ISREG(st.st_mode) != 0;
}

/**
 * @brief checks if path is an absolute path.
 * @param path
 * @return
 */
bool path_is_absolute(const char *path) {
    if (path == NULL || path[0] == '\0') {
        return false;
    }

    if ((path[0] == '/') || (path[0] == '\\')) {
        return true;
    }

#ifdef _WIN32
    // drive letter,  "C:/..." or "C:\..."
    if (isalpha((unsigned char)path[0]) && (path[1] == ':') && ((path[2] == '/') || (path[2] == '\\'))) {
        return true;
    }
#endif
    return false;
}

/**
 * @brief expands a leading "~" into the user home directory.
 *
 * The pm3 prompt is not a shell, so nobody expands "~" for us and it wouldotherwise be taken as a directory named "~". 
 * 
 * "~user/..." is not supported and is returned unchanged.
 *
 * @param path
 * @return newly allocated string, caller must free.  NULL on failure
 */
char *path_expand_homedir(const char *path) {
    if (path == NULL) {
        return NULL;
    }

    // only a leading "~", "~/" or "~\" is expanded
    if ((path[0] != '~') || ((path[1] != '\0') && (path[1] != '/') && (path[1] != '\\'))) {
        return str_dup(path);
    }

    const char *user_path = get_my_user_directory();
    if (user_path == NULL) {
        return str_dup(path);
    }

    // skip the "~" and the path separators directly after it
    const char *tail = path + 1;
    while ((*tail == '/') || (*tail == '\\')) {
        tail++;
    }

    bool sep = ((*tail != '\0') &&
                (str_endswith(user_path, "/") == false) &&
                (str_endswith(user_path, "\\") == false));

    size_t n = strlen(user_path) + (sep ? strlen(PATHSEP) : 0) + strlen(tail) + 1;
    char *res = (char *)calloc(n, sizeof(uint8_t));
    if (res == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return NULL;
    }

    snprintf(res, n, "%s%s%s", user_path, sep ? PATHSEP : "", tail);
    return res;
}

const char *path_basename(const char *path) {
    if (path == NULL) {
        return "";
    }

    const char *base = strrchr(path, '/');
    const char *base_win = strrchr(path, '\\');
    if (base == NULL || (base_win != NULL && base_win > base)) {
        base = base_win;
    }
    return (base == NULL) ? path : (base + 1);
}

void path_basename_without_ext(const char *path, char *out, size_t out_len) {
    if (out == NULL || out_len == 0) {
        return;
    }
    out[0] = '\0';

    const char *base = path_basename(path);
    if (base[0] == '\0') {
        return;
    }

    snprintf(out, out_len, "%s", base);
    char *dot = strrchr(out, '.');
    if (dot != NULL && dot != out) {
        *dot = '\0';
    }
}

static int qsort_path_cmp(const void *a, const void *b) {
    const char *pa = (const char *)a;
    const char *pb = (const char *)b;
    return strcmp(pa, pb);
}

static char *path_list_slot(char *paths, size_t path_len, size_t index) {
    return paths + (index * path_len);
}

int collect_file_paths_recursive(const char *dirpath, char *paths, size_t path_len,
                                 size_t max_paths, size_t *count, bool include_hidden, size_t max_depth) {
    if (dirpath == NULL || paths == NULL || path_len == 0 || count == NULL) {
        return PM3_EINVARG;
    }

    DIR *dir = opendir(dirpath);
    if (dir == NULL) {
        return PM3_EFILE;
    }

    struct dirent *entry = NULL;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 ||
                (include_hidden == false && entry->d_name[0] == '.')) {
            continue;
        }

        char *fullpath = calloc(path_len, sizeof(char));
        if (fullpath == NULL) {
            closedir(dir);
            return PM3_EMALLOC;
        }
        const char *sep = "";
        size_t dir_len = strlen(dirpath);
        if (dir_len > 0 && dirpath[dir_len - 1] != '/' && dirpath[dir_len - 1] != '\\') {
            sep = PATHSEP;
        }
        if (snprintf(fullpath, path_len, "%s%s%s", dirpath, sep, entry->d_name) >= (int)path_len) {
            free(fullpath);
            continue;
        }

        if (path_is_directory(fullpath)) {
            if (max_depth == 0) {
                free(fullpath);
                continue;
            }
            int res = collect_file_paths_recursive(fullpath, paths, path_len, max_paths, count, include_hidden, max_depth - 1);
            free(fullpath);
            if (res != PM3_SUCCESS) {
                closedir(dir);
                return res;
            }
            continue;
        }

        if (!path_is_regular_file(fullpath)) {
            free(fullpath);
            continue;
        }
        if (*count >= max_paths) {
            free(fullpath);
            closedir(dir);
            return PM3_EOVFLOW;
        }
        if (snprintf(path_list_slot(paths, path_len, *count), path_len, "%s", fullpath) >= (int)path_len) {
            free(fullpath);
            continue;
        }
        free(fullpath);
        (*count)++;
    }

    closedir(dir);
    return PM3_SUCCESS;
}

int collect_resource_file_paths(const char *resource_dir, char *paths, size_t path_len,
                                size_t max_paths, size_t *count, bool include_hidden, size_t max_depth) {
    if (resource_dir == NULL || resource_dir[0] == '\0' || paths == NULL || path_len == 0 || count == NULL) {
        return PM3_EINVARG;
    }

    char *rootdir = NULL;
    int res = searchFile(&rootdir, RESOURCES_SUBDIR, resource_dir, "", true);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (!path_is_directory(rootdir)) {
        free(rootdir);
        return PM3_EFILE;
    }

    *count = 0;
    res = collect_file_paths_recursive(rootdir, paths, path_len, max_paths, count, include_hidden, max_depth);
    free(rootdir);
    if (res != PM3_SUCCESS) {
        return res;
    }

    qsort(paths, *count, path_len, qsort_path_cmp);
    return PM3_SUCCESS;
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

    char *expanded = path_expand_homedir(preferredName);
    if (expanded == NULL) {
        return NULL;
    }

    char *fileName = (char *) calloc(strlen(expanded) + strlen(suffix) + 1, sizeof(uint8_t));
    if (fileName == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        free(expanded);
        return NULL;
    }

    strcpy(fileName, expanded);
    free(expanded);

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

    char *expanded = path_expand_homedir(preferredName);
    if (expanded == NULL) {
        return NULL;
    }

    // 1: null terminator
    // 16: room for filenum to ensure new filename
    // save_path_len + strlen(PATHSEP):  the user preference save paths
    //const size_t len = p_namelen + strlen(suffix) + 1 + 16 + save_path_len + strlen(PATHSEP);
    size_t len = FILE_PATH_SIZE;

    char *fileName = (char *) calloc(len, sizeof(uint8_t));
    if (fileName == NULL) {
        free(expanded);
        return NULL;
    }

    char *pfn = fileName;

    // if given path is not an absolute path
    if (path_is_absolute(expanded) == false) {
        // user preference save paths
        size_t save_path_len = path_size(e_save_path);
        if (save_path_len && save_path_len < (FILE_PATH_SIZE - strlen(PATHSEP))) {
            snprintf(pfn, len, "%s%s", g_session.defaultPaths[e_save_path], PATHSEP);
            pfn += save_path_len + strlen(PATHSEP);
            len -= save_path_len + strlen(PATHSEP);
        }
    }

    // remove file extension if exist in name
    size_t p_namelen = strlen(expanded);
    if (str_endswith(expanded, suffix)) {
        p_namelen -= strlen(suffix);
    }

    len -= strlen(suffix) + 1;
    len -= p_namelen;

    // modify filename
    snprintf(pfn, len, "%.*s%s", (int)p_namelen, expanded, suffix);

    // "-001"
    len -= 4;

    int num = 1;
    // check complete path/filename if exists
    while (fileExists(fileName)) {
        // modify filename
        snprintf(pfn, len, "%.*s-%03d%s", (int)p_namelen, expanded, num, suffix);
        num++;
    }

    free(expanded);
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
    if (f == NULL) {
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

int saveFileTXT(const char *preferredName, const char *suffix, const void *data, size_t datalen, savePaths_t e_save_path) {
    if (data == NULL || datalen == 0) {
        return PM3_EINVARG;
    }

    char *fileName = newfilenamemcopyEx(preferredName, suffix, e_save_path);
    if (fileName == NULL) {
        return PM3_EMALLOC;
    }

    // We should have a valid filename now, e.g. dumpdata-3.txt

    // Opening file for writing in text mode
    FILE *f = fopen(fileName, "w");
    if (f == NULL) {
        PrintAndLogEx(WARNING, "file not found or locked `" _YELLOW_("%s") "`", fileName);
        free(fileName);
        return PM3_EFILE;
    }
    fwrite(data, 1, datalen, f);
    fflush(f);
    fclose(f);
    PrintAndLogEx(SUCCESS, "Saved " _YELLOW_("%zu") " bytes to text file `" _YELLOW_("%s") "`", datalen, fileName);
    free(fileName);
    return PM3_SUCCESS;
}

// Writes the iso15_tag_t body of a `15693 v4` or `15693 v5` JSON.
//
// The two revisions differ in exactly one field: v4 stored pagesCount in a byte,
// v5 in two, once 0xA0 pages stopped being enough for an SLIX2. Everything else
// is identical, so the width is a parameter rather than a second copy.
//
// pagesCount is serialized little endian, byte for byte what an x86 client
// writes out of the struct, so dumps stay readable across hosts.
static void json15_save_tag(json_t *root, const iso15_tag_t *tag, size_t pagescount_len) {

    char path[PATH_MAX_LENGTH] = {0};
    uint8_t pagescount[2] = { tag->pagesCount & 0xFF, (tag->pagesCount >> 8) & 0xFF };

    JsonSaveBufAsHexCompact(root, "$.Card.uid", (uint8_t *)tag->uid, sizeof(tag->uid));
    JsonSaveBufAsHexCompact(root, "$.Card.dsfid", (uint8_t *)&tag->dsfid, 1);
    JsonSaveBufAsHexCompact(root, "$.Card.dsfidlock", (uint8_t *)&tag->dsfidLock, 1);
    JsonSaveBufAsHexCompact(root, "$.Card.afi", (uint8_t *)&tag->afi, 1);
    JsonSaveBufAsHexCompact(root, "$.Card.afilock", (uint8_t *)&tag->afiLock, 1);
    JsonSaveBufAsHexCompact(root, "$.Card.bytesperpage", (uint8_t *)&tag->bytesPerPage, 1);
    JsonSaveBufAsHexCompact(root, "$.Card.pagescount", pagescount, pagescount_len);
    JsonSaveBufAsHexCompact(root, "$.Card.ic", (uint8_t *)&tag->ic, 1);
    JsonSaveBufAsHexCompact(root, "$.Card.locks", (uint8_t *)tag->locks, tag->pagesCount);
    JsonSaveBufAsHexCompact(root, "$.Card.random", (uint8_t *)tag->random, sizeof(tag->random));
    JsonSaveBufAsHexCompact(root, "$.Card.privacypasswd", (uint8_t *)tag->privacyPasswd, sizeof(tag->privacyPasswd));
    JsonSaveBufAsHexCompact(root, "$.Card.state", (uint8_t *)&tag->state, 1);

    for (uint16_t i = 0 ; i < tag->pagesCount ; i++) {

        if (((i + 1) * tag->bytesPerPage) > ISO15693_TAG_MAX_SIZE) {
            break;
        }

        snprintf(path, sizeof(path), "$.blocks.%u", i);
        JsonSaveBufAsHexCompact(root
                                , path
                                , (uint8_t *)&tag->data[i * tag->bytesPerPage]
                                , tag->bytesPerPage
                               );
    }
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
        // Hitag 1 and Hitag 2 both start with the UID in block 0.  Hitag 2 also
        // carries its configuration in block 3, so record it when the dump is
        // long enough to hold one.
        case jsfHitag1:
        case jsfHitag2: {
            JsonSaveStr(root, "FileType", (ftype == jsfHitag1) ? "hitag1" : "hitag2");
            JsonSaveBufAsHexCompact(root, "$.Card.UID", data, HITAG_UID_SIZE);

            if ((ftype == jsfHitag2) && (datalen >= 16)) {
                JsonSaveBufAsHexCompact(root, "$.Card.Config", data + 12, HITAG_BLOCK_SIZE);
            }

            JsonSaveInt(root, "$.Card.Blocks", (int)(datalen / HITAG_BLOCK_SIZE));

            for (size_t i = 0; i < (datalen / HITAG_BLOCK_SIZE); i++) {
                snprintf(path, sizeof(path), "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, data + (i * HITAG_BLOCK_SIZE), HITAG_BLOCK_SIZE);
            }
            break;
        }
        // Hitag S keeps the UID in page 0 and the configuration in page 1
        case jsfHitagS: {
            JsonSaveStr(root, "FileType", "hitags");
            JsonSaveBufAsHexCompact(root, "$.Card.UID", data + (HITAGS_UID_PADR * HITAGS_PAGE_SIZE), HITAG_UID_SIZE);

            if (datalen >= ((HITAGS_CONFIG_PADR + 1) * HITAGS_PAGE_SIZE)) {
                JsonSaveBufAsHexCompact(root, "$.Card.Config", data + (HITAGS_CONFIG_PADR * HITAGS_PAGE_SIZE), HITAGS_PAGE_SIZE);
            }

            JsonSaveInt(root, "$.Card.Blocks", (int)(datalen / HITAGS_PAGE_SIZE));

            for (size_t i = 0; i < (datalen / HITAGS_PAGE_SIZE); i++) {
                snprintf(path, sizeof(path), "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, data + (i * HITAGS_PAGE_SIZE), HITAGS_PAGE_SIZE);
            }
            break;
        }
        // Hitag u has a 6 byte UID and an ICR that the tag reports separately from
        // its pages, so neither can be recovered from `data`.  The caller supplies
        // them through the save callback, see pm3_save_dump_cb().
        case jsfHitagU: {
            JsonSaveStr(root, "FileType", "hitagu");
            JsonSaveInt(root, "$.Card.Blocks", (int)(datalen / HITAGU_BLOCK_SIZE));

            for (size_t i = 0; i < (datalen / HITAGU_BLOCK_SIZE); i++) {
                snprintf(path, sizeof(path), "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, data + (i * HITAGU_BLOCK_SIZE), HITAGU_BLOCK_SIZE);
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
        case jsf15_v4:
        case jsf15_v5: {
            JsonSaveStr(root, "FileType", (ftype == jsf15_v5) ? "15693 v5" : "15693 v4");
            json15_save_tag(root, (iso15_tag_t *)data, (ftype == jsf15_v5) ? 2 : 1);
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
    if (root == NULL) {
        return PM3_EINVARG;
    }

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
            PrintAndLogEx(SUCCESS, "Saved to json file " _YELLOW_("%s"), filename);
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
        if (e_sector[i].foundKey[1])
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
    if (f == NULL) {
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
    if (*pdata == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
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

int loadFile_TXTsafe(const char *preferredName, const char *suffix, void **pdata, size_t *datalen, bool verbose) {

    char *path;
    int res = searchFile(&path, RESOURCES_SUBDIR, preferredName, suffix, false);
    if (res != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    FILE *f = fopen(path, "r");
    if (f == NULL) {
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
    if (*pdata == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
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
        PrintAndLogEx(SUCCESS, "Loaded " _YELLOW_("%zu") " bytes from text file `" _YELLOW_("%s") "`", bytes_read, preferredName);
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
    if (*pdata == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
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
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        free(*pdata);
        return PM3_EMALLOC;
    } else {
        *pdata = newdump;
    }

    if (datalen)
        *datalen = counter;

    return retval;
}

// Convert a run of "XX XX XX ..." hex text into bytes.
//
// `head` is the part of the line the caller already has, `more` says whether the
// line continued past the caller's buffer, in which case the rest is pulled from
// `f` one character at a time and converted as it goes.  That keeps the caller's
// line buffer small: an ISO15693 "Data Content" line carries the whole tag and
// runs to several thousand characters.
//
// Returns the number of bytes the text held, which may be larger than `destlen`.
// Only the first `destlen` bytes are stored, so the caller can spot an overflow.
static size_t hexstream_to_bytes(FILE *f, const char *head, bool more, uint8_t *dest, size_t destlen) {

    size_t cnt = 0;
    int hi = -1;

    for (;;) {

        int c;
        if (*head) {
            c = (unsigned char) * head++;
        } else if (more) {
            c = fgetc(f);
        } else {
            break;
        }

        if ((c == EOF) || (c == '\n') || (c == '\r')) {
            break;
        }

        if (isxdigit(c) == 0) {
            // separator
            continue;
        }

        int v = (c <= '9') ? (c - '0') : ((c | 0x20) - 'a' + 10);

        if (hi < 0) {
            hi = v;
            continue;
        }

        if (cnt < destlen) {
            dest[cnt] = (hi << 4) | v;
        }
        cnt++;
        hi = -1;
    }

    return cnt;
}

int loadFileNFC_safe(const char *preferredName, void *data, size_t maxdatalen, size_t *datalen, nfc_df_e ft) {

    if (data == NULL) {
        return PM3_EINVARG;
    }

    *datalen = 0;
    int retval = PM3_SUCCESS;

    char *path;
    int res = searchFile(&path, RESOURCES_SUBDIR, preferredName, "", false);
    if (res != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    FILE *f = fopen(path, "r");
    if (f == NULL) {
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
    size_t iso15_datalen = 0;

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

        if (line[0] == '#') {
            continue;
        }

        // did this fgets reach the end of the line, or is the line longer than
        // the buffer?  ISO15693 puts a whole tag on its "Data Content" line.
        bool line_truncated = ((strchr(line, '\n') == NULL) && (feof(f) == false));

        str_cleanrn(line, sizeof(line));
        str_lower(line);

        if (str_startswith(line, "uid:")) {
            if (ft == NFC_DF_MFC) {
//                param_gethex_to_eol(line + 4, 0, udata.mfc->card_info.uid, sizeof(udata.mfc->card_info.uid), &n);
            } else if (ft == NFC_DF_15) {
                // iso15_tag_t keeps the UID in transmission order (LSB first),
                // Flipper writes it the way it is displayed (MSB first).
                param_gethex_to_eol(line + 4, 0, udata.iso15->uid, sizeof(udata.iso15->uid), &n);
                reverse_array(udata.iso15->uid, sizeof(udata.iso15->uid));
            }
            continue;
        }

        if (ft == NFC_DF_15) {

            if (str_startswith(line, "dsfid:")) {
                uint8_t v = 0;
                param_gethex_to_eol(line + 6, 0, &v, sizeof(v), &n);
                udata.iso15->dsfid = v;
                continue;
            }

            if (str_startswith(line, "afi:")) {
                uint8_t v = 0;
                param_gethex_to_eol(line + 4, 0, &v, sizeof(v), &n);
                udata.iso15->afi = v;
                continue;
            }

            if (str_startswith(line, "ic reference:")) {
                uint8_t v = 0;
                param_gethex_to_eol(line + 13, 0, &v, sizeof(v), &n);
                udata.iso15->ic = v;
                continue;
            }

            // Flipper writes the block count in decimal but the block size in hex
            if (str_startswith(line, "block count:")) {
                int v = 0;
                sscanf(line, "block count: %d", &v);
                udata.iso15->pagesCount = v;
                continue;
            }

            if (str_startswith(line, "block size:")) {
                uint8_t v = 0;
                param_gethex_to_eol(line + 11, 0, &v, sizeof(v), &n);
                udata.iso15->bytesPerPage = v;
                continue;
            }

            if (str_startswith(line, "data content:")) {
                iso15_datalen = hexstream_to_bytes(f, line + 13, line_truncated
                                                   , udata.iso15->data
                                                   , sizeof(udata.iso15->data));
                continue;
            }

            if (str_startswith(line, "password privacy:")) {
                param_gethex_to_eol(line + 17, 0, udata.iso15->privacyPasswd, sizeof(udata.iso15->privacyPasswd), &n);
                continue;
            }
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
    } else if (ft == NFC_DF_15) {

        if ((udata.iso15->pagesCount == 0) || (udata.iso15->bytesPerPage == 0)) {
            fclose(f);
            PrintAndLogEx(FAILED, "missing block count / block size in `" _YELLOW_("%s") "`", preferredName);
            return PM3_ESOFT;
        }

        if (udata.iso15->pagesCount > ISO15693_TAG_MAX_PAGES) {
            fclose(f);
            PrintAndLogEx(FAILED, "block count ( %u ) exceeds max ( %u )"
                          , udata.iso15->pagesCount
                          , ISO15693_TAG_MAX_PAGES);
            return PM3_ESOFT;
        }

        uint32_t expected = (uint32_t)udata.iso15->pagesCount * udata.iso15->bytesPerPage;
        if (expected > ISO15693_TAG_MAX_SIZE) {
            fclose(f);
            PrintAndLogEx(FAILED, "tag memory ( %u bytes ) exceeds max ( %u bytes )"
                          , expected
                          , ISO15693_TAG_MAX_SIZE);
            return PM3_ESOFT;
        }

        if (iso15_datalen > sizeof(udata.iso15->data)) {
            fclose(f);
            PrintAndLogEx(FAILED, "data content ( %zu bytes ) exceeds max ( %zu bytes )"
                          , iso15_datalen
                          , sizeof(udata.iso15->data));
            return PM3_ESOFT;
        }

        if (iso15_datalen != expected) {
            PrintAndLogEx(WARNING, "data content is %zu bytes, header says %u x %u = %u bytes"
                          , iso15_datalen
                          , udata.iso15->pagesCount
                          , udata.iso15->bytesPerPage
                          , expected);
        }

        *datalen = sizeof(iso15_tag_t);
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
    if (*pdata == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
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
        PrintAndLogEx(WARNING, "Failed to allocate memory");
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
// Loads one metadata field of an iso15_tag_t.
//
// JsonLoadBufAsHex writes whatever it managed to parse *before* it bails, so a
// caller that discards the return value keeps a half-written field. Dumps in the
// wild carry a two byte `pagescount` from when that member was a uint16_t; the
// old code took the first byte of it ("0001" -> 0) and then tripped over its own
// layout check with a message that pointed nowhere near the real problem.
//
// A malformed value is always fatal. A missing key is only fatal for the fields
// the memory layout is computed from.
static int json15_load_field(json_t *root, const char *path, uint8_t *dst, size_t len, size_t *datalen, bool required) {

    int res = JsonLoadBufAsHex(root, path, dst, len, datalen);
    if (res == 0) {
        return PM3_SUCCESS;
    }

    // do not leave a partial value behind
    memset(dst, 0, len);

    if (res == 1) {
        if (required == false) {
            return PM3_SUCCESS;
        }
        PrintAndLogEx(ERR, "loadFileJSONex: `" _YELLOW_("%s") "` is missing", path);
    } else {
        PrintAndLogEx(ERR, "loadFileJSONex: `" _YELLOW_("%s") "` is not a %zu byte hex value", path, len);
    }
    return PM3_EFILE;
}

int loadFileJSONex(const char *preferredName, void *data, size_t maxdatalen, size_t *datalen, bool verbose, void (*callback)(json_t *)) {

    if (data == NULL) {
        return PM3_EINVARG;
    }

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

    // The four Hitag flavours share one block layout on disk and differ only in
    // how many blocks they carry, so one reader serves all of them.  A file
    // written before the per-flavour types existed says only "hitag" and cannot
    // say which tag it came from - treat those as Hitag 2 and tell the user.
    if (!strcmp(ctype, "hitag")) {
        PrintAndLogEx(WARNING, "`" _YELLOW_("hitag") "` is the legacy dump type and does not record which tag it came from");
        PrintAndLogEx(INFO, "Reading it as " _YELLOW_("Hitag 2") ", re-dump the tag to get a versioned file");
    }

    if (!strcmp(ctype, "hitag") ||
            !strcmp(ctype, "hitag1") ||
            !strcmp(ctype, "hitag2") ||
            !strcmp(ctype, "hitags") ||
            !strcmp(ctype, "hitagu")) {
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

    if (!strcmp(ctype, "15693 v4") || !strcmp(ctype, "15693 v5")) {

        bool is_v5 = (strcmp(ctype, "15693 v5") == 0);
        if (is_v5 == false) {
            PrintAndLogEx(WARNING, "loadFileJSONex: loading deprecated 15693 v4 format");
        }

        if (maxdatalen < sizeof(iso15_tag_t)) {
            PrintAndLogEx(ERR, "loadFileJSONex: maxdatalen=%zu, need %zu for an iso15_tag_t"
                          , maxdatalen
                          , sizeof(iso15_tag_t)
                         );
            retval = PM3_EMALLOC;
            goto out;
        }

        iso15_tag_t *tag = (iso15_tag_t *)udata.bytes;

        // pagesCount is the only field the two revisions disagree on: one byte
        // in v4, two in v5, little endian. The width belongs to the format, so
        // it is taken from the FileType and a value of the wrong width is an
        // error, not something to accommodate. Read into a scratch buffer and
        // assemble, so a v4 file cannot leave the high byte of a uint16_t
        // member holding whatever the caller's buffer had in it.
        uint8_t pagescount[2] = {0};

        const struct {
            const char *path;
            uint8_t *dst;
            size_t len;
            bool required;
        } hdr[] = {
            { "$.Card.uid",          tag->uid,                          sizeof(tag->uid), true  },
            { "$.Card.dsfid",        &tag->dsfid,                       1,                false },
            { "$.Card.dsfidlock", (uint8_t *) &tag->dsfidLock,        1,                false },
            { "$.Card.afi",          &tag->afi,                         1,                false },
            { "$.Card.afilock", (uint8_t *) &tag->afiLock,          1,                false },
            { "$.Card.bytesperpage", &tag->bytesPerPage,                1,                true  },
            { "$.Card.pagescount",   pagescount,                        is_v5 ? 2 : 1,    true  },
        };

        for (size_t n = 0; n < ARRAYLEN(hdr); n++) {
            retval = json15_load_field(root, hdr[n].path, hdr[n].dst, hdr[n].len, datalen, hdr[n].required);
            if (retval != PM3_SUCCESS) {
                goto out;
            }
        }

        tag->pagesCount = pagescount[0] | (pagescount[1] << 8);

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

        const struct {
            const char *path;
            uint8_t *dst;
            size_t len;
        } rest[] = {
            { "$.Card.ic",            &tag->ic,                   1                          },
            { "$.Card.locks",         tag->locks,                 tag->pagesCount            },
            { "$.Card.random",        tag->random,                sizeof(tag->random)        },
            { "$.Card.privacypasswd", tag->privacyPasswd,         sizeof(tag->privacyPasswd) },
            { "$.Card.state", (uint8_t *) &tag->state,     1                          },
        };

        for (size_t n = 0; n < ARRAYLEN(rest); n++) {
            retval = json15_load_field(root, rest[n].path, rest[n].dst, rest[n].len, datalen, false);
            if (retval != PM3_SUCCESS) {
                goto out;
            }
        }

        size_t sptr = 0;
        for (uint16_t i = 0; i < tag->pagesCount ; i++) {

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

    // Nothing above claimed this file. Falling through to `out` used to return
    // PM3_SUCCESS with datalen 0, which reads to the caller as "loaded, empty".
    PrintAndLogEx(ERR, "loadFileJSONex: unsupported FileType `" _YELLOW_("%s") "`", ctype);
    PrintAndLogEx(HINT, "Hint: the file may have been written by a newer client version");
    retval = PM3_EFILE;

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

// this function handles exceptional large dictionaries,
// using start position and end position parameters.
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
    if (f == NULL) {
        PrintAndLogEx(WARNING, "file not found or locked `" _YELLOW_("%s") "`", path);
        free(path);
        return PM3_EFILE;
    }

    if (startFilePosition) {
        if (fseek(f, startFilePosition, SEEK_SET) < 0) {
            fclose(f);
            free(path);
            return PM3_EFILE;
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
    if (keylen != 4 && keylen != 5 && keylen != 6 && keylen != 8 && keylen != 12 && keylen != 16 && keylen != 24) {
        keylen = 6;
    }

    size_t block_size = 1000 * keylen;

    // double up since its chars
    keylen <<= 1;

    char line[255];

    // allocate some space for the dictionary
    *pdata = calloc(block_size, sizeof(uint8_t));
    if (*pdata == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        free(path);
        return PM3_EFILE;
    }
    size_t mem_size = block_size;

    FILE *f = fopen(path, "r");
    if (f == NULL) {
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
                PrintAndLogEx(WARNING, "Failed to allocate memory");
                retval = PM3_EFILE;
                fclose(f);
                goto out;
            } else {
                memset((uint8_t *)*pdata + (mem_size - block_size), 0, block_size);
            }
        }

        // The line start with # is comment, skip
        if (line[0] == '#') {
            continue;
        }

        // remove newline/linefeed
        str_cleanrn(line, strlen(line));
        str_trim(line);

        // smaller keys than expected is skipped
        if (strlen(line) < keylen) {
            continue;
        }

        char *pos = strstr(line, "#");
        if (pos) {
            // we found a inline comment,  add a null terminator, until we hit hexadecimal char
            while (isxdigit(pos[0]) == 0) {
                pos[0] = 0x00;
                --pos;
            }
        }

        // larger keys than expected is skipped
        if (strlen(line) > keylen) {
            PrintAndLogEx(INFO, "too long line (%zu) ... %s", strlen(line), line);
            continue;
        }

        if (CheckStringIsHEXValue(line) == false) {
            continue;
        }

        int ret = hex_to_bytes(line, (uint8_t *)*pdata + (*keycnt * (keylen >> 1)),  keylen >> 1);
        if (ret != (keylen >> 1)) {
            PrintAndLogEx(INFO, "hex to bytes wrong  %i", ret);
            continue;
        }

        (*keycnt)++;

        memset(line, 0, sizeof(line));
    }
    fclose(f);

    if (verbose) {
        PrintAndLogEx(SUCCESS, "Loaded " _GREEN_("%d") " keys from dictionary file `" _YELLOW_("%s") "`", *keycnt, path);
    }

out:
    free(path);
    return retval;
}

int loadFileBinaryKey(const char *preferredName, const char *suffix, void **keya, void **keyb, size_t *alen, size_t *blen, bool verbose) {

    char *path;
    int res = searchFile(&path, RESOURCES_SUBDIR, preferredName, suffix, false);
    if (res != PM3_SUCCESS) {
        return PM3_ENOFILE;
    }

    FILE *f = fopen(path, "rb");
    if (f == NULL) {
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
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        fclose(f);
        free(path);
        return PM3_EMALLOC;
    }

    *alen = fread(*keya, 1, fsize, f);

    *keyb = calloc(fsize, sizeof(uint8_t));
    if (*keyb == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        fclose(f);
        free(*keya);
        free(path);
        return PM3_EMALLOC;
    }

    *blen = fread(*keyb, 1, fsize, f);
    fclose(f);

    if (verbose) {
        PrintAndLogEx(SUCCESS, "Loaded binary key file `" _YELLOW_("%s") "`", path);
    }
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
    if (f == NULL) {
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

        // older Flipper files name the exact chip, the current format writes
        // the family name instead
        if (str_startswith(line, "device type: ntag") ||
                str_startswith(line, "device type: mifare ultralight")) {
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
        if (str_startswith(line, "device type: iso15693")) {
            *dump_type = NFC_DF_15;
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
            case NFC_DF_15:
                PrintAndLogEx(INFO, "Detected ISO15693 based dump format");
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
        PrintAndLogEx(WARNING, "Failed to allocate memory");
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
        PrintAndLogEx(WARNING, "Failed to allocate memory");
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

// Every iso15_tag_t revision carries the same fields in the same order and
// differs only in the width of pagesCount and the length of locks[]. A .bin has
// no version field, so its length is its version -- and a conversion is a matter
// of reading the fields at the right offsets, not one struct type per revision.
//
//    bytes   pagesCount   locks[]   note
//    2139    u8           0x40
//    2235    u8           0xA0      ISO15_V4_DUMP_LENGTH, iso15_tag_v4_t
//    2236    u16          0xA0      pagesCount widened first
//    2331    u16          0xFF      then locks[], briefly to 0xFF
//    2332    u16          0x100     ISO15_V5_DUMP_LENGTH, the current struct
//
// The two lengths that have a struct to compare against are asserted below, so a
// future edit to iso15_tag_t cannot drift away from this table unnoticed.
_Static_assert(sizeof(iso15_tag_t) == ISO15_V5_DUMP_LENGTH, "iso15_tag_t is not ISO15_V5_DUMP_LENGTH bytes");
_Static_assert(sizeof(iso15_tag_v4_t) == ISO15_V4_DUMP_LENGTH, "iso15_tag_v4_t is not ISO15_V4_DUMP_LENGTH bytes");

static const struct {
    size_t len;
    uint8_t pagescount_sz;
    uint16_t locks_sz;
} g_iso15_layouts[] = {
    { 2139,                 1, 0x40  },
    { ISO15_V4_DUMP_LENGTH, 1, 0xA0  },
    { 2236,                 2, 0xA0  },
    { 2331,                 2, 0xFF  },
    { ISO15_V5_DUMP_LENGTH, 2, 0x100 },
};

// Upgrades a raw iso15_tag_t dump to the current struct revision. A dump that
// already is the current revision passes through untouched, so this is safe to
// call on any buffer that came out of pm3_load_dump().
int convert_15_dump_format(uint8_t **dump, size_t *dumplen, bool verbose) {

    if ((dump == NULL) || (*dump == NULL) || (dumplen == NULL)) {
        return PM3_EINVARG;
    }

    if (*dumplen == ISO15_V5_DUMP_LENGTH) {
        return PM3_SUCCESS;
    }

    size_t n = 0;
    for (; n < ARRAYLEN(g_iso15_layouts); n++) {
        if (g_iso15_layouts[n].len == *dumplen) {
            break;
        }
    }

    if (n == ARRAYLEN(g_iso15_layouts)) {
        PrintAndLogEx(FAILED, "Unsupported ISO15693 dump length ( %zu bytes )", *dumplen);
        PrintAndLogEx(HINT, "Hint: known lengths are 2139, %d, 2236, 2331 and %d bytes"
                      , ISO15_V4_DUMP_LENGTH
                      , ISO15_V5_DUMP_LENGTH
                     );
        return PM3_ESOFT;
    }

    uint8_t pagescount_sz = g_iso15_layouts[n].pagescount_sz;
    uint16_t locks_sz = g_iso15_layouts[n].locks_sz;

    iso15_tag_t *tag = (iso15_tag_t *)calloc(1, sizeof(iso15_tag_t));
    if (tag == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    const uint8_t *old = *dump;
    size_t o = 0;

    memcpy(tag->uid, old + o, sizeof(tag->uid));
    o += sizeof(tag->uid);

    tag->dsfid = old[o++];
    tag->dsfidLock = (old[o++] != 0);
    tag->afi = old[o++];
    tag->afiLock = (old[o++] != 0);
    tag->bytesPerPage = old[o++];

    tag->pagesCount = old[o];
    if (pagescount_sz == 2) {
        tag->pagesCount |= (old[o + 1] << 8);
    }
    o += pagescount_sz;

    tag->ic = old[o++];

    // a shorter locks[] leaves the tail of the current one zeroed
    memcpy(tag->locks, old + o, MIN(locks_sz, sizeof(tag->locks)));
    o += locks_sz;

    memcpy(tag->data, old + o, sizeof(tag->data));
    o += sizeof(tag->data);
    memcpy(tag->random, old + o, sizeof(tag->random));
    o += sizeof(tag->random);
    memcpy(tag->privacyPasswd, old + o, sizeof(tag->privacyPasswd));
    o += sizeof(tag->privacyPasswd);

    // the state enumerators have never been renumbered, so the value carries over
    memcpy(&tag->state, old + o, sizeof(tag->state));
    o += sizeof(tag->state);

    tag->expectFast = (old[o++] != 0);
    tag->expectFsk = (old[o++] != 0);

    free(*dump);
    *dump = (uint8_t *)tag;
    *dumplen = ISO15_V5_DUMP_LENGTH;

    if (verbose) {
        PrintAndLogEx(SUCCESS, "Converted ISO15693 dump, " _YELLOW_("%zu") " byte layout -> " _GREEN_("v5")
                      "  ( pagesCount u%u, locks[0x%X] )"
                      , g_iso15_layouts[n].len
                      , pagescount_sz * 8
                      , locks_sz
                     );
    }

    return PM3_SUCCESS;
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
        snprintf(tmp_fullpath, sizeof(tmp_fullpath), "%s%s", path, namelist[i]->d_name);

        if (path_is_directory(tmp_fullpath)) {

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
        PrintAndLogEx(WARNING, "Failed to allocate memory");
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

    if (foundpath == NULL) {
        return PM3_EINVARG;
    }

    if (searchname == NULL || strlen(searchname) == 0) {
        return PM3_EINVARG;
    }

    char *filename = filenamemcopy(searchname, suffix);
    if (filename == NULL) {
        return PM3_EMALLOC;
    }

    if (strlen(filename) == 0) {
        free(filename);
        return PM3_EFILE;
    }

    if (path_is_directory(filename)) {
        free(filename);
        return PM3_EINVARG;
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

/**
 * Inserts a line into a text file only if it does not already exist.
 * Returns PM3_SUCCES or, PM3_EFILE;
 *
 * @param filepath Path to the file.
 * @param keystr     Line to insert (should not contain a trailing newline).
 */
int insert_line_if_not_exists(const char *preferredName, const char *keystr) {

    char *path;
    int res = searchFile(&path, DICTIONARIES_SUBDIR, preferredName, ".dic", false);
    if (res != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        PrintAndLogEx(WARNING, "file not found or locked `" _YELLOW_("%s") "`", path);
        free(path);
        return PM3_EFILE;
    }

    // Maximum line length we assume (adjust as necessary for your use case)
    char line[255];
    bool key_exists = false;

    char *keystrdup = str_dup(keystr);
    str_upper(keystrdup);

    // First pass: check if the line exists
    while (fgets(line, sizeof(line), f)) {

        // The line start with # is comment, skip
        if (line[0] == '#') {
            continue;
        }

        // Remove trailing newline for comparison
        line[strcspn(line, "\n")] = '\0';

        // UPPER CASE
        str_upper(line);

        key_exists = str_startswith(line, keystrdup);
        if (key_exists) {
            fclose(f);
            free(path);
            PrintAndLogEx(INFO, "already in there...");
            return PM3_SUCCESS;
        }
    }

    fclose(f);


    // Reopen for appending if line doesn't exist
    f = fopen(path, "a");
    if (f == NULL) {
        PrintAndLogEx(WARNING, "file not found or locked `" _YELLOW_("%s") "`", path);
        free(path);
        return PM3_EFILE;
    }

    free(path);

    // Append the line with a newline
    if (fprintf(f, "%s\n", keystrdup) < 0) {
        PrintAndLogEx(WARNING, "error writing to file");
        fclose(f);
        return PM3_EFILE;
    }

    fclose(f);
    return PM3_SUCCESS;
}

static int load_dump_check_len(const char *fn, void **pdump, size_t *dumplen, size_t maxdumplen) {
    if (*dumplen <= maxdumplen) {
        return PM3_SUCCESS;
    }

    PrintAndLogEx(FAILED, "`" _YELLOW_("%s") "` is %zu bytes, expected at most %zu"
                  , fn
                  , *dumplen
                  , maxdumplen
                 );
    PrintAndLogEx(HINT, "Hint: the file may come from a different client version, or not be a dump of this tag type");

    free(*pdump);
    *pdump = NULL;
    *dumplen = 0;
    return PM3_EFILE;
}

int pm3_load_dump(const char *fn, void **pdump, size_t *dumplen, size_t maxdumplen) {

    int res = PM3_SUCCESS;
    DumpFileType_t dt = get_filetype(fn);
    switch (dt) {
        case BIN: {
            res = loadFile_safe(fn, ".bin", pdump, dumplen);
            if (res == PM3_SUCCESS) {
                res = load_dump_check_len(fn, pdump, dumplen, maxdumplen);
            }
            break;
        }
        case EML: {
            res = loadFileEML_safe(fn, pdump, dumplen);
            if (res == PM3_SUCCESS) {
                res = load_dump_check_len(fn, pdump, dumplen, maxdumplen);
            }
            break;
        }
        case JSON: {
            *pdump = calloc(maxdumplen, sizeof(uint8_t));
            if (*pdump == NULL) {
                PrintAndLogEx(WARNING, "Failed to allocate memory");
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
            if (res == PM3_SUCCESS) {
                res = load_dump_check_len(fn, pdump, dumplen, maxdumplen);
            }
            break;
        }
        case BRUCE:
        case FLIPPER: {
            nfc_df_e dumptype = NFC_DF_UNKNOWN;
            res = detect_nfc_dump_format(fn, &dumptype, true);
            if (res != PM3_SUCCESS) {
                break;
            }

            if (dumptype == NFC_DF_MFC || dumptype == NFC_DF_MFU || dumptype == NFC_DF_PICOPASS || dumptype == NFC_DF_15) {

                *pdump = calloc(maxdumplen, sizeof(uint8_t));
                if (*pdump == NULL) {
                    PrintAndLogEx(WARNING, "Failed to allocate memory");
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
        case TAGINFO: {
            //res = loadFileXML_safe(fn, ".xml", pdump, dumplen);
            break;
        }
    }
    return res;
}

// Saves a dump as JSON only, no .bin alongside.
//
// For ISO15693 the .bin is the raw iso15_tag_t, and its only identity on disk is
// its length. Nothing in the file says which struct revision wrote it or what
// the block size is -- you have to already know the layout to find the field
// that tells you. Every past change to the struct therefore turned older .bin
// files into silently misparsed ones. The JSON names every field, so it survives
// the next change. Reading .bin stays supported, writing it does not.
int pm3_save_dump_json(const char *fn, uint8_t *d, size_t n, JSONFileType jsft) {
    if (fn == NULL || strlen(fn) == 0) {
        return PM3_EINVARG;
    }
    if (d == NULL || n == 0) {
        PrintAndLogEx(INFO, "No data to save, skipping...");
        return PM3_EINVARG;
    }

    saveFileJSON(fn, jsft, d, n, NULL);
    return PM3_SUCCESS;
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

int pm3_save_dump_cb(const char *fn, uint8_t *d, size_t n, JSONFileType jsft, void (*callback)(json_t *)) {
    if (fn == NULL || strlen(fn) == 0) {
        return PM3_EINVARG;
    }
    if (d == NULL || n == 0) {
        PrintAndLogEx(INFO, "No data to save, skipping...");
        return PM3_EINVARG;
    }

    saveFile(fn, ".bin", d, n);
    saveFileJSON(fn, jsft, d, n, callback);
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
