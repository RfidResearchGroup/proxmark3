/*****************************************************************************
 * WARNING
 *
 * THIS CODE IS CREATED FOR EXPERIMENTATION AND EDUCATIONAL USE ONLY.
 *
 * USAGE OF THIS CODE IN OTHER WAYS MAY INFRINGE UPON THE INTELLECTUAL
 * PROPERTY OF OTHER PARTIES, SUCH AS INSIDE SECURE AND HID GLOBAL,
 * AND MAY EXPOSE YOU TO AN INFRINGEMENT ACTION FROM THOSE PARTIES.
 *
 * THIS CODE SHOULD NEVER BE USED TO INFRINGE PATENTS OR INTELLECTUAL PROPERTY RIGHTS.
 *
 *****************************************************************************
 *
 * This file is part of loclass. It is a reconstructon of the cipher engine
 * used in iClass, and RFID techology.
 *
 * The implementation is based on the work performed by
 * Flavio D. Garcia, Gerhard de Koning Gans, Roel Verdult and
 * Milosch Meriac in the paper "Dismantling IClass".
 *
 * Copyright (C) 2014 Martin Holst Swende
 *
 * This is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, or, at your option, any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with loclass.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 ****************************************************************************/

// this define is needed for scandir/alphasort to work
#define _GNU_SOURCE
#include "fileutils.h"

#include <dirent.h>
#include <ctype.h>

#include "pm3_cmd.h"
#include "commonutil.h"
#include "proxmark3.h"
#include "util.h"
#ifdef _WIN32
#include "scandir.h"
#endif

#define PATH_MAX_LENGTH 100

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

static char *newfilenamemcopy(const char *preferredName, const char *suffix) {
    if (preferredName == NULL) return NULL;
    if (suffix == NULL) return NULL;
    uint16_t preferredNameLen = strlen(preferredName);
    if (str_endswith(preferredName, suffix))
        preferredNameLen -= strlen(suffix);
    char *fileName = (char *) calloc(preferredNameLen + strlen(suffix) + 1 + 10, sizeof(uint8_t)); // 10: room for filenum to ensure new filename
    if (fileName == NULL) {
        return NULL;
    }
    int num = 1;
    sprintf(fileName, "%.*s%s", preferredNameLen, preferredName, suffix);
    while (fileExists(fileName)) {
        sprintf(fileName, "%.*s-%d%s", preferredNameLen, preferredName, num, suffix);
        num++;
    }
    return fileName;
}

int saveFile(const char *preferredName, const char *suffix, const void *data, size_t datalen) {

    if (data == NULL) return 1;
    char *fileName = newfilenamemcopy(preferredName, suffix);
    if (fileName == NULL) return 1;

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
    PrintAndLogEx(SUCCESS, "saved %u bytes to binary file " _YELLOW_("%s"), datalen, fileName);
    free(fileName);
    return PM3_SUCCESS;
}

int saveFileEML(const char *preferredName, uint8_t *data, size_t datalen, size_t blocksize) {

    if (data == NULL) return 1;
    char *fileName = newfilenamemcopy(preferredName, ".eml");
    if (fileName == NULL) return 1;

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
    PrintAndLogEx(SUCCESS, "saved %d blocks to text file " _YELLOW_("%s"), blocks, fileName);

out:
    free(fileName);
    return retval;
}

int saveFileJSON(const char *preferredName, JSONFileType ftype, uint8_t *data, size_t datalen) {

    if (data == NULL) return 1;
    char *fileName = newfilenamemcopy(preferredName, ".json");
    if (fileName == NULL) return 1;

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
            JsonSaveStr(root, "FileType", "mfcard");
            for (size_t i = 0; i < (datalen / 16); i++) {
                char path[PATH_MAX_LENGTH] = {0};
                sprintf(path, "$.blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, &data[i * 16], 16);

                if (i == 0) {
                    JsonSaveBufAsHexCompact(root, "$.Card.UID", &data[0], 4);
                    JsonSaveBufAsHexCompact(root, "$.Card.SAK", &data[5], 1);
                    JsonSaveBufAsHexCompact(root, "$.Card.ATQA", &data[6], 2);
                }

                if (mfIsSectorTrailer(i)) {
                    memset(path, 0x00, sizeof(path));
                    sprintf(path, "$.SectorKeys.%d.KeyA", mfSectorNum(i));
                    JsonSaveBufAsHexCompact(root, path, &data[i * 16], 6);

                    memset(path, 0x00, sizeof(path));
                    sprintf(path, "$.SectorKeys.%d.KeyB", mfSectorNum(i));
                    JsonSaveBufAsHexCompact(root, path, &data[i * 16 + 10], 6);

                    memset(path, 0x00, sizeof(path));
                    uint8_t *adata = &data[i * 16 + 6];
                    sprintf(path, "$.SectorKeys.%d.AccessConditions", mfSectorNum(i));
                    JsonSaveBufAsHexCompact(root, path, &data[i * 16 + 6], 4);

                    memset(path, 0x00, sizeof(path));
                    sprintf(path, "$.SectorKeys.%d.AccessConditionsText.block%zu", mfSectorNum(i), i - 3);
                    JsonSaveStr(root, path, mfGetAccessConditionsDesc(0, adata));

                    memset(path, 0x00, sizeof(path));
                    sprintf(path, "$.SectorKeys.%d.AccessConditionsText.block%zu", mfSectorNum(i), i - 2);
                    JsonSaveStr(root, path, mfGetAccessConditionsDesc(1, adata));

                    memset(path, 0x00, sizeof(path));
                    sprintf(path, "$.SectorKeys.%d.AccessConditionsText.block%zu", mfSectorNum(i), i - 1);
                    JsonSaveStr(root, path, mfGetAccessConditionsDesc(2, adata));

                    memset(path, 0x00, sizeof(path));
                    sprintf(path, "$.SectorKeys.%d.AccessConditionsText.block%zu", mfSectorNum(i), i);
                    JsonSaveStr(root, path, mfGetAccessConditionsDesc(3, adata));

                    memset(path, 0x00, sizeof(path));
                    sprintf(path, "$.SectorKeys.%d.AccessConditionsText.UserData", mfSectorNum(i));
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
            uint8_t uid[8] = {0};
            memcpy(uid, data, 8);
            JsonSaveBufAsHexCompact(root, "$.Card.UID", uid, sizeof(uid));

            for (size_t i = 0; i < (datalen / 8); i++) {
                char path[PATH_MAX_LENGTH] = {0};
                sprintf(path, "$blocks.%zu", i);
                JsonSaveBufAsHexCompact(root, path, data + (i * 8), 8);
            }
            break;
        }
    }

    int res = json_dump_file(root, fileName, JSON_INDENT(2));
    if (res) {
        PrintAndLogEx(FAILED, "error: can't save the file: " _YELLOW_("%s"), fileName);
        json_decref(root);
        retval = 200;
        goto out;
    }
    PrintAndLogEx(SUCCESS, "saved to json file " _YELLOW_("%s"), fileName);
    json_decref(root);

out:
    free(fileName);
    return retval;
}

int createMfcKeyDump(uint8_t sectorsCnt, sector_t *e_sector, char *fptr) {
    uint8_t tmpKey[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    int i;

    if (fptr == NULL) {
        return 1;
    }

    FILE *fkeys = fopen(fptr, "wb");
    if (fkeys == NULL) {
        PrintAndLogEx(WARNING, "Could not create file " _YELLOW_("%s"), fptr);
        return 1;
    }
    PrintAndLogEx(SUCCESS, "Printing keys to binary file " _YELLOW_("%s")"...", fptr);

    for (i = 0; i < sectorsCnt; i++) {
        num_to_bytes(e_sector[i].Key[0], 6, tmpKey);
        fwrite(tmpKey, 1, 6, fkeys);
    }

    for (i = 0; i < sectorsCnt; i++) {
        num_to_bytes(e_sector[i].Key[1], 6, tmpKey);
        fwrite(tmpKey, 1, 6, fkeys);
    }

    fclose(fkeys);
    PrintAndLogEx(SUCCESS, "Found keys have been dumped to " _YELLOW_("%s")" --> 0xffffffffffff has been inserted for unknown keys.", fptr);
    return 0;
}

int loadFile(const char *preferredName, const char *suffix, void *data, size_t maxdatalen, size_t *datalen) {

    if (data == NULL) return 1;
    char *fileName = filenamemcopy(preferredName, suffix);
    if (fileName == NULL) return 1;

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
        retval = 1;
        goto out;
    }

    uint8_t *dump = calloc(fsize, sizeof(uint8_t));
    if (!dump) {
        PrintAndLogEx(FAILED, "error, cannot allocate memory");
        retval = 2;
        goto out;
    }

    size_t bytes_read = fread(dump, 1, fsize, f);

    if (bytes_read != fsize) {
        PrintAndLogEx(FAILED, "error, bytes read mismatch file size");
        free(dump);
        retval = 3;
        goto out;
    }

    if (bytes_read > maxdatalen) {
        PrintAndLogEx(WARNING, "Warning, bytes read exceed calling array limit. Max bytes is %d bytes", maxdatalen);
        bytes_read = maxdatalen;
    }

    memcpy((data), dump, bytes_read);
    free(dump);

    PrintAndLogEx(SUCCESS, "loaded %d bytes from binary file " _YELLOW_("%s"), bytes_read, fileName);

    *datalen = bytes_read;

out:
    fclose(f);
    free(fileName);

    return retval;
}

int loadFileEML(const char *preferredName, void *data, size_t *datalen) {

    if (data == NULL) return 1;
    char *fileName = filenamemcopy(preferredName, ".eml");
    if (fileName == NULL) return 1;

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

    while (!feof(f)) {

        memset(line, 0, sizeof(line));

        if (fgets(line, sizeof(line), f) == NULL) {
            if (feof(f))
                break;
            fclose(f);
            PrintAndLogEx(FAILED, "File reading error.");
            retval = 2;
            goto out;
        }

        if (line[0] == '#')
            continue;

        int res = param_gethex_to_eol(line, 0, buf, sizeof(buf), &hexlen);
        if (res == 0 || res == 1) {
            memcpy(data + counter, buf, hexlen);
            counter += hexlen;
        }
    }
    fclose(f);
    PrintAndLogEx(SUCCESS, "loaded %d bytes from text file " _YELLOW_("%s"), counter, fileName);

    if (datalen)
        *datalen = counter;

out:
    free(fileName);
    return retval;
}

int loadFileJSON(const char *preferredName, void *data, size_t maxdatalen, size_t *datalen) {

    if (data == NULL) return 1;
    char *fileName = filenamemcopy(preferredName, ".json");
    if (fileName == NULL) return 1;

    *datalen = 0;
    json_t *root;
    json_error_t error;

    int retval = PM3_SUCCESS;

    root = json_load_file(fileName, 0, &error);
    if (!root) {
        PrintAndLogEx(ERR, "ERROR: json " _YELLOW_("%s") " error on line %d: %s", fileName, error.line, error.text);
        retval = 2;
        goto out;
    }

    if (!json_is_object(root)) {
        PrintAndLogEx(ERR, "ERROR: Invalid json " _YELLOW_("%s") " format. root must be an object.", fileName);
        retval = 3;
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
                retval = 5;
                goto out;
            }

            char path[30] = {0};
            sprintf(path, "$.blocks.%d", i);

            size_t len = 0;
            JsonLoadBufAsHex(root, path, &udata[sptr], 16, &len);
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
                retval = 5;
                goto out;
            }

            char path[30] = {0};
            sprintf(path, "$.blocks.%d", i);

            size_t len = 0;
            JsonLoadBufAsHex(root, path, &udata[sptr], 4, &len);
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
                retval = 5;
                goto out;
            }

            char path[30] = {0};
            sprintf(path, "$.blocks.%zu", i);

            size_t len = 0;
            JsonLoadBufAsHex(root, path, &udata[sptr], 4, &len);
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
                retval = 5;
                goto out;
            }

            char path[30] = {0};
            sprintf(path, "$.blocks.%zu", i);

            size_t len = 0;
            JsonLoadBufAsHex(root, path, &udata[sptr], 8, &len);
            if (!len)
                break;

            sptr += len;
        }
        *datalen = sptr;
    }

    PrintAndLogEx(SUCCESS, "loaded from JSON file " _YELLOW_("%s"), fileName);
out:
    json_decref(root);
    free(fileName);
    return retval;
}

int loadFileDICTIONARY(const char *preferredName, void *data, size_t *datalen, uint8_t keylen, uint16_t *keycnt) {

    if (data == NULL) return PM3_ESOFT;
    char *path;
    if (searchFile(&path, DICTIONARIES_SUBDIR, preferredName, ".dic") != PM3_SUCCESS)
        return PM3_EFILE;

    // t5577 == 4bytes
    // mifare == 6 bytes
    // iclass == 8 bytes
    // default to 6 bytes.
    if (keylen != 4 && keylen != 6 && keylen != 8) {
        keylen = 6;
    }

    // double up since its chars
    keylen <<= 1;

    char line[255];

    size_t counter = 0;
    int retval = PM3_SUCCESS;

    FILE *f = fopen(path, "r");
    if (!f) {
        PrintAndLogEx(WARNING, "file not found or locked. '" _YELLOW_("%s")"'", path);
        retval = PM3_EFILE;
        goto out;
    }

    // read file
    while (fgets(line, sizeof(line), f)) {

        // add null terminator
        line[keylen] = 0;

        // smaller keys than expected is skipped
        if (strlen(line) < keylen)
            continue;

        // The line start with # is comment, skip
        if (line[0] == '#')
            continue;

        if (!isxdigit(line[0])) {
            PrintAndLogEx(FAILED, "file content error. '%s' must include " _BLUE_("%2d") "HEX symbols", line, keylen);
            continue;
        }

        uint64_t key = strtoull(line, NULL, 16);

        num_to_bytes(key, keylen >> 1, data + counter);
        (*keycnt)++;
        memset(line, 0, sizeof(line));
        counter += (keylen >> 1);
    }
    fclose(f);
    PrintAndLogEx(SUCCESS, "loaded " _GREEN_("%2d") "keys from dictionary file " _YELLOW_("%s"), *keycnt, path);

    if (datalen)
        *datalen = counter;
out:
    free(path);
    return retval;
}

int loadFileDICTIONARY_safe(const char *preferredName, void **pdata, uint8_t keylen, uint16_t *keycnt) {

    int block_size = 512;
    int allocation_size = block_size;
    size_t counter = 0;
    int retval = PM3_SUCCESS;
    char *path;
    if (searchFile(&path, DICTIONARIES_SUBDIR, preferredName, ".dic") != PM3_SUCCESS)
        return PM3_EFILE;

    // t5577 == 4bytes
    // mifare == 6 bytes
    // iclass == 8 bytes
    // default to 6 bytes.
    if (keylen != 4 && keylen != 6 && keylen != 8) {
        keylen = 6;
    }

    // double up since its chars
    keylen <<= 1;

    char line[255];

    // allocate some space for the dictionary
    *pdata = calloc(keylen * allocation_size, sizeof(uint8_t));
    if (*pdata == NULL) return PM3_EFILE;

    FILE *f = fopen(path, "r");
    if (!f) {
        PrintAndLogEx(WARNING, "file not found or locked. '" _YELLOW_("%s")"'", path);
        retval = PM3_EFILE;
        goto out;    }

    // read file
    while (fgets(line, sizeof(line), f)) {
        // check if we have enough space (if not allocate more)
        if ((*keycnt) >= allocation_size) {
            allocation_size += block_size;
            *pdata = realloc(*pdata, keylen * allocation_size * sizeof(uint8_t));
            if (*pdata == NULL) {
                return PM3_EFILE;
            } else {
                // zero the new memory (safety first)
                memset(*pdata + allocation_size - block_size, 0, block_size);
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

        if (!isxdigit(line[0])) {
            PrintAndLogEx(FAILED, "file content error. '%s' must include " _BLUE_("%2d") "HEX symbols", line, keylen);
            continue;
        }

        uint64_t key = strtoull(line, NULL, 16);

        num_to_bytes(key, keylen >> 1, *pdata + counter);
        (*keycnt)++;
        memset(line, 0, sizeof(line));
        counter += (keylen >> 1);
    }
    fclose(f);
    PrintAndLogEx(SUCCESS, "loaded " _GREEN_("%2d") "keys from dictionary file " _YELLOW_("%s"), *keycnt, path);

out:
    free(path);
    return retval;
}

int convertOldMfuDump(uint8_t **dump, size_t *dumplen) {
    if (!dump || !dumplen || *dumplen < OLD_MFU_DUMP_PREFIX_LENGTH)
        return 1;
    // try to check new file format
    mfu_dump_t *mfu_dump = (mfu_dump_t *) *dump;
    if ((*dumplen - MFU_DUMP_PREFIX_LENGTH) / 4 - 1 == mfu_dump->pages)
        return 0;
    // convert old format
    old_mfu_dump_t *old_mfu_dump = (old_mfu_dump_t *) *dump;

    size_t old_data_len = *dumplen - OLD_MFU_DUMP_PREFIX_LENGTH;
    size_t new_dump_len = old_data_len + MFU_DUMP_PREFIX_LENGTH;

    mfu_dump = (mfu_dump_t *) calloc(new_dump_len, sizeof(uint8_t));

    memcpy(mfu_dump->version, old_mfu_dump->version, 8);
    memcpy(mfu_dump->tbo, old_mfu_dump->tbo, 2);
    mfu_dump->tbo1[0] = old_mfu_dump->tbo1[0];
    memcpy(mfu_dump->signature, old_mfu_dump->signature, 32);
    for (int i = 0; i < 3; i++)
        mfu_dump->counter_tearing[i][3] = old_mfu_dump->tearing[i];

    memcpy(mfu_dump->data, old_mfu_dump->data, old_data_len);
    mfu_dump->pages = old_data_len / 4 - 1;
    // free old buffer, return new buffer
    *dumplen = new_dump_len;
    free(*dump);
    *dump = (uint8_t *) mfu_dump;
    PrintAndLogEx(SUCCESS, "old mfu dump format, was converted on load to " _GREEN_("%d") " pages", mfu_dump->pages + 1);
    return PM3_SUCCESS;
}

static int filelist(const char *path, const char *ext, bool last) {
    struct dirent **namelist;
    int n;

    n = scandir(path, &namelist, NULL, alphasort);
    if (n == -1) {
        PrintAndLogEx(NORMAL, "%s── %s => NOT FOUND", last ? "└" : "├", path);
        return PM3_EFILE;
    }

    PrintAndLogEx(NORMAL, "%s── %s", last ? "└" : "├", path);
    for (uint16_t i = 0; i < n; i++) {
        if (((ext == NULL) && (namelist[i]->d_name[0] != '.')) || (str_endswith(namelist[i]->d_name, ext))) {
            PrintAndLogEx(NORMAL, "%s   %s── %-21s", last ? " " : "│", i == n - 1 ? "└" : "├", namelist[i]->d_name);
        }
        free(namelist[i]);
    }
    free(namelist);
    return PM3_SUCCESS;
}

int searchAndList(const char *pm3dir, const char *ext) {
    if (get_my_executable_directory() != NULL) {
        char script_directory_path[strlen(get_my_executable_directory()) + strlen(pm3dir) + 1];
        strcpy(script_directory_path, get_my_executable_directory());
        strcat(script_directory_path, pm3dir);
        filelist(script_directory_path, ext, false);
    }
    char *userpath = getenv("HOME");
    if (userpath != NULL) {
        char script_directory_path[strlen(userpath) + strlen(PM3_USER_DIRECTORY) + strlen(pm3dir) + 1];
        strcpy(script_directory_path, userpath);
        strcat(script_directory_path, PM3_USER_DIRECTORY);
        strcat(script_directory_path, pm3dir);
        filelist(script_directory_path, ext, false);
    }
    {
        char script_directory_path[strlen(PM3_SHARE_PATH) + strlen(pm3dir) + 1];
        strcpy(script_directory_path, PM3_SHARE_PATH);
        strcat(script_directory_path, pm3dir);
        filelist(script_directory_path, ext, true);
    }
    return PM3_SUCCESS;
}

static int searchFinalFile(char **foundpath, const char *pm3dir, const char *searchname) {
    if ((foundpath == NULL) || (pm3dir == NULL) || (searchname == NULL)) return PM3_ESOFT;
    // explicit absolute (/) or relative path (./) => try only to match it directly
    char *filename = calloc(strlen(searchname) + 1, sizeof(char));
    if (filename == NULL) return PM3_EMALLOC;
    strcpy(filename, searchname);
    if (((strlen(filename) > 1) && (filename[0] == '/')) ||
            ((strlen(filename) > 2) && (filename[0] == '.') && (filename[1] == '/'))) {
        if (fileExists(filename)) {
            *foundpath = filename;
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
            return PM3_SUCCESS;
        }
    }
    // try pm3 dirs in current workdir (dev mode)
    const char *exec_path = get_my_executable_directory();
    if (exec_path != NULL) {
        char *path = calloc(strlen(exec_path) + strlen(pm3dir) + strlen(filename) + 1, sizeof(char));
        if (path == NULL)
            goto out;
        strcpy(path, exec_path);
        strcat(path, pm3dir);
        strcat(path, filename);
        if (fileExists(path)) {
            free(filename);
            *foundpath = path;
            return PM3_SUCCESS;
        } else {
            free(path);
        }
    }
    // try pm3 dirs in user .proxmark3 (user mode)
    char *user_path = getenv("HOME");
    if (user_path != NULL) {
        char *path = calloc(strlen(user_path) + strlen(PM3_USER_DIRECTORY) + strlen(pm3dir) + strlen(filename) + 1, sizeof(char));
        if (path == NULL)
            goto out;
        strcpy(path, user_path);
        strcat(path, PM3_USER_DIRECTORY);
        strcat(path, pm3dir);
        strcat(path, filename);
        if (fileExists(path)) {
            free(filename);
            *foundpath = path;
            return PM3_SUCCESS;
        } else {
            free(path);
        }
    }
    // try pm3 dirs in pm3 installation dir (install mode)
    {
        char *path = calloc(strlen(PM3_SHARE_PATH) + strlen(pm3dir) + strlen(filename) + 1, sizeof(char));
        if (path == NULL)
            goto out;
        strcpy(path, PM3_SHARE_PATH);
        strcat(path, pm3dir);
        strcat(path, filename);
        if (fileExists(path)) {
            free(filename);
            *foundpath = path;
            return PM3_SUCCESS;
        } else {
            free(path);
        }
    }
out:
    free(filename);
    return PM3_EFILE;
}

int searchFile(char **foundpath, const char *pm3dir, const char *searchname, const char *suffix) {
    char *filename = filenamemcopy(searchname, suffix);
    if (filename == NULL) return PM3_EMALLOC;
    int res = searchFinalFile(foundpath, pm3dir, filename);
    if (res != PM3_SUCCESS) {
        if (res == PM3_EFILE)
            PrintAndLogEx(FAILED, "Error - can't find %s", filename);
        free(filename);
        return res;
    }
    free(filename);
    return PM3_SUCCESS;
}
