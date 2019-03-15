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
#include "fileutils.h"

#ifndef ON_DEVICE

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

int saveFile(const char *preferredName, const char *suffix, const void *data, size_t datalen) {
    int size = sizeof(char) * (strlen(preferredName) + strlen(suffix) + 10);
    char *fileName = calloc(size, sizeof(char));
    int num = 1;
    sprintf(fileName, "%s.%s", preferredName, suffix);
    while (fileExists(fileName)) {
        sprintf(fileName, "%s-%d.%s", preferredName, num, suffix);
        num++;
    }
    /* We should have a valid filename now, e.g. dumpdata-3.bin */

    /*Opening file for writing in binary mode*/
    FILE *f = fopen(fileName, "wb");
    if (!f) {
        PrintAndLogDevice(WARNING, "file not found or locked. '" _YELLOW_("%s")"'", fileName);
        free(fileName);
        return 1;
    }
    fwrite(data, 1, datalen, f);
    fflush(f);
    fclose(f);
    PrintAndLogDevice(SUCCESS, "saved %u bytes to binary file " _YELLOW_("%s"), datalen, fileName);
    free(fileName);
    return 0;
}

int saveFileEML(const char *preferredName, const char *suffix, uint8_t *data, size_t datalen, size_t blocksize) {

    if (preferredName == NULL) return 1;
    if (suffix == NULL) return 1;
    if (data == NULL) return 1;

    int retval = 0;
    int blocks = datalen / blocksize;
    uint16_t currblock = 1;
    int i, j;
    int size = sizeof(char) * (strlen(preferredName) + strlen(suffix) + 10);
    char *fileName = calloc(size, sizeof(char));
    int num = 1;
    sprintf(fileName, "%s.%s", preferredName, suffix);
    while (fileExists(fileName)) {
        sprintf(fileName, "%s-%d.%s", preferredName, num, suffix);
        num++;
    }

    /* We should have a valid filename now, e.g. dumpdata-3.bin */

    /*Opening file for writing in text mode*/
    FILE *f = fopen(fileName, "w+");
    if (!f) {
        PrintAndLogDevice(WARNING, "file not found or locked. '" _YELLOW_("%s")"'", fileName);
        retval =  1;
        goto out;
    }

    for (i = 0; i < datalen; i++) {
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
        for (j = 0; j < datalen % blocksize; j++) {
            fprintf(f, "%02X", data[index + j]);
        }
    }
    fflush(f);
    fclose(f);
    PrintAndLogDevice(SUCCESS, "saved %d blocks to text file " _YELLOW_("%s"), blocks, fileName);

out:
    free(fileName);
    return retval;
}

int saveFileJSON(const char *preferredName, const char *suffix, JSONFileType ftype, uint8_t *data, size_t datalen) {
    if (preferredName == NULL) return 1;
    if (suffix == NULL) return 1;
    if (data == NULL) return 1;

    int retval = 0;
    int size = sizeof(char) * (strlen(preferredName) + strlen(suffix) + 10);
    char *fileName = calloc(size, sizeof(char));
    int num = 1;
    sprintf(fileName, "%s.%s", preferredName, suffix);
    while (fileExists(fileName)) {
        sprintf(fileName, "%s-%d.%s", preferredName, num, suffix);
        num++;
    }

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
            for (int i = 0; i < (datalen / 16); i++) {
                char path[PATH_MAX_LENGTH] = {0};
                sprintf(path, "$.blocks.%d", i);
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
                    sprintf(path, "$.SectorKeys.%d.AccessConditionsText.block%d", mfSectorNum(i), i - 3);
                    JsonSaveStr(root, path, mfGetAccessConditionsDesc(0, adata));

                    memset(path, 0x00, sizeof(path));
                    sprintf(path, "$.SectorKeys.%d.AccessConditionsText.block%d", mfSectorNum(i), i - 2);
                    JsonSaveStr(root, path, mfGetAccessConditionsDesc(1, adata));

                    memset(path, 0x00, sizeof(path));
                    sprintf(path, "$.SectorKeys.%d.AccessConditionsText.block%d", mfSectorNum(i), i - 1);
                    JsonSaveStr(root, path, mfGetAccessConditionsDesc(2, adata));

                    memset(path, 0x00, sizeof(path));
                    sprintf(path, "$.SectorKeys.%d.AccessConditionsText.block%d", mfSectorNum(i), i);
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

            JsonSaveBufAsHexCompact(root, "$.Card.UID", uid, sizeof(uid));
            JsonSaveBufAsHexCompact(root, "$.Card.Version", tmp->version, sizeof(tmp->version));
            JsonSaveBufAsHexCompact(root, "$.Card.TBO_0", tmp->tbo, sizeof(tmp->tbo));
            JsonSaveBufAsHexCompact(root, "$.Card.Tearing", tmp->tearing, sizeof(tmp->tearing));
            JsonSaveBufAsHexCompact(root, "$.Card.Pack",  tmp->pack, sizeof(tmp->pack));
            JsonSaveBufAsHexCompact(root, "$.Card.TBO_1", tmp->tbo1, sizeof(tmp->tbo1));
            JsonSaveBufAsHexCompact(root, "$.Card.Signature", tmp->signature, sizeof(tmp->signature));
            JsonSaveStr(root, "$.Card.Counter", "N/A");

            // size of header 48b
            size_t len = (datalen - DUMP_PREFIX_LENGTH) / 4;

            for (int i = 0; i < len; i++) {
                char path[PATH_MAX_LENGTH] = {0};
                sprintf(path, "$.blocks.%d", i);
                JsonSaveBufAsHexCompact(root, path, tmp->data + (i * 4), 4);
            }
            break;
        }
        case jsfHitag: {
            JsonSaveStr(root, "FileType", "hitag");
            uint8_t uid[4] = {0};
            memcpy(uid, data, 4);

            JsonSaveBufAsHexCompact(root, "$.Card.UID", uid, sizeof(uid));

            for (int i = 0; i < (datalen / 4); i++) {
                char path[PATH_MAX_LENGTH] = {0};
                sprintf(path, "$.blocks.%d", i);
                JsonSaveBufAsHexCompact(root, path, data + (i * 4), 4);
            }
            break;
        }
    }

    int res = json_dump_file(root, fileName, JSON_INDENT(2));
    if (res) {
        PrintAndLogDevice(FAILED, "error: can't save the file: " _YELLOW_("%s"), fileName);
        json_decref(root);
        retval = 200;
        goto out;
    }
    PrintAndLogDevice(SUCCESS, "saved to json file " _YELLOW_("%s"), fileName);
    json_decref(root);

out:
    free(fileName);
    return retval;
}

int loadFile(const char *preferredName, const char *suffix, void *data, size_t maxdatalen, size_t *datalen) {

    if (preferredName == NULL) return 1;
    if (suffix == NULL) return 1;
    if (data == NULL) return 1;

    int retval = 0;
    int size = sizeof(char) * (strlen(preferredName) + strlen(suffix) + 10);
    char *fileName = calloc(size, sizeof(char));
    sprintf(fileName, "%s.%s", preferredName, suffix);

    FILE *f = fopen(fileName, "rb");
    if (!f) {
        PrintAndLogDevice(WARNING, "file not found or locked. '" _YELLOW_("%s")"'", fileName);
        free(fileName);
        return 1;
    }

    // get filesize in order to malloc memory
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize < 0) {
        PrintAndLogDevice(FAILED, "error, when getting filesize");
        retval = 1;
        goto out;
    }

    uint8_t *dump = calloc(fsize, sizeof(uint8_t));
    if (!dump) {
        PrintAndLogDevice(FAILED, "error, cannot allocate memory");
        retval = 2;
        goto out;
    }

    size_t bytes_read = fread(dump, 1, fsize, f);

    if (bytes_read != fsize) {
        PrintAndLogDevice(FAILED, "error, bytes read mismatch file size");
        free(dump);
        retval = 3;
        goto out;
    }

    if (bytes_read != maxdatalen) {
        PrintAndLogDevice(WARNING, "Warning, bytes read exeed calling array limit. Max bytes is %d bytes", maxdatalen);
        bytes_read = maxdatalen;
    }

    memcpy((data), dump, bytes_read);
    free(dump);

    PrintAndLogDevice(SUCCESS, "loaded %d bytes from binary file " _YELLOW_("%s"), bytes_read, fileName);

    *datalen = bytes_read;

out:
    fclose(f);
    free(fileName);

    return retval;
}

int loadFileEML(const char *preferredName, const char *suffix, void *data, size_t *datalen) {

    if (preferredName == NULL) return 1;
    if (suffix == NULL) return 1;
    if (data == NULL) return 1;

    size_t counter = 0;
    int retval = 0, hexlen = 0;
    int size = sizeof(char) * (strlen(preferredName) + strlen(suffix) + 10);
    char *fileName = calloc(size, sizeof(char));
    sprintf(fileName, "%s.%s", preferredName, suffix);

    FILE *f = fopen(fileName, "r");
    if (!f) {
        PrintAndLogDevice(WARNING, "file not found or locked. '" _YELLOW_("%s")"'", fileName);
        retval = 1;
        goto out;
    }

    // 128 + 2 newline chars + 1 null terminator
    char line[131];
    memset(line, 0, sizeof(line));
    uint8_t buf[64] = {0x00};

    while (!feof(f)) {

        memset(line, 0, sizeof(line));

        if (fgets(line, sizeof(line), f) == NULL) {
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
    PrintAndLogDevice(SUCCESS, "loaded %d bytes from text file " _YELLOW_("%s"), counter, fileName);

    if (datalen)
        *datalen = counter;

out:
    free(fileName);
    return retval;
}

int loadFileJSON(const char *preferredName, const char *suffix, void *data, size_t maxdatalen, size_t *datalen) {

    if (preferredName == NULL) return 1;
    if (suffix == NULL) return 1;
    if (data == NULL) return 1;

    *datalen = 0;
    json_t *root;
    json_error_t error;

    int retval = 0;
    int size = sizeof(char) * (strlen(preferredName) + strlen(suffix) + 10);
    char *fileName = calloc(size, sizeof(char));
    sprintf(fileName, "%s.%s", preferredName, suffix);

    root = json_load_file(fileName, 0, &error);
    if (!root) {
        PrintAndLog("ERROR: json " _YELLOW_("%s") " error on line %d: %s", fileName, error.line, error.text);
        retval = 2;
        goto out;
    }

    if (!json_is_object(root)) {
        PrintAndLog("ERROR: Invalid json " _YELLOW_("%s") " format. root must be an object.", fileName);
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
        for (int i = 0; i < (maxdatalen / 4); i++) {
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

    PrintAndLogEx(SUCCESS, "loaded from JSON file " _YELLOW_("%s"), fileName);
out:
    json_decref(root);
    free(fileName);
    return retval;
}

int loadFileDICTIONARY(const char *preferredName, const char *suffix, void *data, size_t *datalen, uint8_t keylen, uint16_t *keycnt) {

    if (preferredName == NULL) return 1;
    if (suffix == NULL) return 1;
    if (data == NULL) return 1;

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
    int retval = 0;
    int size = sizeof(char) * (strlen(preferredName) + strlen(suffix) + 10);
    char *fileName = calloc(size, sizeof(char));
    sprintf(fileName, "%s.%s", preferredName, suffix);

    FILE *f = fopen(fileName, "r");
    if (!f) {
        PrintAndLogDevice(WARNING, "file not found or locked. '" _YELLOW_("%s")"'", fileName);
        retval = 1;
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
    PrintAndLogDevice(SUCCESS, "loaded " _GREEN_("%2d") "keys from dictionary file " _YELLOW_("%s"), *keycnt, fileName);

    if (datalen)
        *datalen = counter;
out:
    free(fileName);
    return retval;
}

#else //if we're on ARM

#endif
