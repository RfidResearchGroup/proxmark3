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

#ifndef FILEUTILS_H
#define FILEUTILS_H

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdarg.h>
#include "ui.h"
#include "emv/emvjson.h"
#include "mifare/mifare4.h"
#include "mifare/mifarehost.h"
#include "cmdhfmfu.h"

typedef enum {
    jsfRaw,
    jsfCardMemory,
    jsfMfuMemory,
    jsfHitag,
    jsfIclass,
    jsf14b,
    jsf15,
    jsfLegic,
    jsfT55x7,
    jsfT5555,
    jsfMfPlusKeys,
    jsfCustom,
    jsfMfDesfireKeys,
    jsfEM4x05,
    jsfEM4x69,
    jsfEM4x50,
    jsfFido,
    jsfFudan,
    jsfTopaz,
} JSONFileType;

typedef enum {
    BIN = 0,
    EML,
    JSON,
    DICTIONARY,
    MCT,
} DumpFileType_t;

int fileExists(const char *filename);

// set a path in the path list g_session.defaultPaths
bool setDefaultPath(savePaths_t pathIndex, const char *path);

char *newfilenamemcopy(const char *preferredName, const char *suffix);
char *newfilenamemcopyEx(const char *preferredName, const char *suffix, savePaths_t save_path);

/**
 * @brief Utility function to save data to a binary file. This method takes a preferred name, but if that
 * file already exists, it tries with another name until it finds something suitable.
 * E.g. dumpdata-15.txt
 *
 * @param preferredName
 * @param suffix the file suffix. Including the ".".
 * @param data The binary data to write to the file
 * @param datalen the length of the data
 * @return 0 for ok, 1 for failz
 */
int saveFile(const char *preferredName, const char *suffix, const void *data, size_t datalen);

/**
 * @brief Utility function to save data to a textfile (EML). This method takes a preferred name, but if that
 * file already exists, it tries with another name until it finds something suitable.
 * E.g. dumpdata-15.txt
 *
 * @param preferredName
 * @param data The binary data to write to the file
 * @param datalen the length of the data
 * @param blocksize the length of one row
 * @return 0 for ok, 1 for failz
*/
int saveFileEML(const char *preferredName, uint8_t *data, size_t datalen, size_t blocksize);

/** STUB
 * @brief Utility function to save JSON data to a file. This method takes a preferred name, but if that
 * file already exists, it tries with another name until it finds something suitable.
 * E.g. dumpdata-15.json
 *
 * @param preferredName
 * @param ftype type of file.
 * @param data The binary data to write to the file
 * @param datalen the length of the data
 * @return 0 for ok, 1 for failz
 */
int saveFileJSON(const char *preferredName, JSONFileType ftype, uint8_t *data, size_t datalen, void (*callback)(json_t *));
int saveFileJSONex(const char *preferredName, JSONFileType ftype, uint8_t *data, size_t datalen, bool verbose, void (*callback)(json_t *), savePaths_t e_save_path);
int saveFileJSONroot(const char *preferredName, void *root, size_t flags, bool verbose);
int saveFileJSONrootEx(const char *preferredName, void *root, size_t flags, bool verbose, bool overwrite);
/** STUB
 * @brief Utility function to save WAVE data to a file. This method takes a preferred name, but if that
 * file already exists, it tries with another name until it finds something suitable.
 * E.g. dumpdata-15.wav
 *
 * @param preferredName
 * @param data The binary data to write to the file
 * @param datalen the length of the data
 * @return 0 for ok
 */
int saveFileWAVE(const char *preferredName, const int *data, size_t datalen);

/** STUB
 * @brief Utility function to save PM3 data to a file. This method takes a preferred name, but if that
 * file already exists, it tries with another name until it finds something suitable.
 * E.g. dump_trace.pm3
 *
 * @param preferredName
 * @param data The binary data to write to the file
 * @param datalen the length of the data
 * @return 0 for ok
 */
int saveFilePM3(const char *preferredName, int *data, size_t datalen);

/**
 * @brief Utility function to save a keydump into a binary file.
 *
 * @param preferredName
 * @param sectorsCnt the used sectors
 * @param e_sector the keys in question
 * @return 0 for ok, 1 for failz
 */
int createMfcKeyDump(const char *preferredName, uint8_t sectorsCnt, sector_t *e_sector);

/**
 * @brief Utility function to load data from a binary file. This method takes a preferred name.
 * E.g. dumpdata-15.bin,  tries to search for it,  and allocated memory.
 *
 * @param preferredName
 * @param suffix the file suffix. Including the ".".
 * @param data The data array to store the loaded bytes from file
 * @param datalen the number of bytes loaded from file
 * @return PM3_SUCCESS for ok, PM3_E* for failz
*/
int loadFile_safe(const char *preferredName, const char *suffix, void **pdata, size_t *datalen);
int loadFile_safeEx(const char *preferredName, const char *suffix, void **pdata, size_t *datalen, bool verbose);
/**
 * @brief  Utility function to load data from a textfile (EML). This method takes a preferred name.
 * E.g. dumpdata-15.txt
 *
 * @param preferredName
 * @param data The data array to store the loaded bytes from file
 * @param datalen the number of bytes loaded from file
 * @return 0 for ok, 1 for failz
*/
int loadFileEML_safe(const char *preferredName, void **pdata, size_t *datalen);

/**
 * @brief  Utility function to load data from a textfile (MCT). This method takes a preferred name.
 * E.g. dumpdata-15.mct
 *
 * @param preferredName
 * @param data The data array to store the loaded bytes from file
 * @param datalen the number of bytes loaded from file
 * @return 0 for ok, 1 for failz
*/
int loadFileMCT_safe(const char *preferredName, void **pdata, size_t *datalen);

/**
 * @brief  Utility function to load data from a JSON textfile. This method takes a preferred name.
 * E.g. dumpdata-15.json
 *
 * @param preferredName
 * @param data The data array to store the loaded bytes from file
 * @param maxdatalen maximum size of data array in bytes
 * @param datalen the number of bytes loaded from file
 * @return 0 for ok, 1 for failz
*/
int loadFileJSON(const char *preferredName, void *data, size_t maxdatalen, size_t *datalen, void (*callback)(json_t *));
int loadFileJSONex(const char *preferredName, void *data, size_t maxdatalen, size_t *datalen, bool verbose, void (*callback)(json_t *));
int loadFileJSONroot(const char *preferredName, void **proot, bool verbose);

/**
 * @brief  Utility function to load data from a DICTIONARY textfile. This method takes a preferred name.
 * E.g. mfc_default_keys.dic
 *
 * @param preferredName
 * @param data The data array to store the loaded bytes from file
 * @param datalen the number of bytes loaded from file. may be NULL
 * @param keylen  the number of bytes a key per row is
 * @param keycnt key count that lays in data. may be NULL
 * @return 0 for ok, 1 for failz
*/
int loadFileDICTIONARY(const char *preferredName, void *data, size_t *datalen, uint8_t keylen, uint32_t *keycnt);

/**
 * @brief  Utility function to load data from a DICTIONARY textfile. This method takes a preferred name.
 * E.g. mfc_default_keys.dic
 * can be executed several times for big dictionaries and checks length of buffer
 *
 * @param preferredName
 * @param data The data array to store the loaded bytes from file
 * @param maxdatalen maximum size of data array in bytes
 * @param datalen the number of bytes loaded from file. may be NULL
 * @param keylen  the number of bytes a key per row is
 * @param keycnt key count that lays in data. may be NULL
 * @param startFilePosition  start position in dictionary file. used for big dictionaries.
 * @param endFilePosition in case we have keys in file and maxdatalen reached it returns current key position in file. may be NULL
 * @param verbose print messages if true
 * @return 0 for ok, 1 for failz
*/
int loadFileDICTIONARYEx(const char *preferredName, void *data, size_t maxdatalen, size_t *datalen, uint8_t keylen, uint32_t *keycnt,
                         size_t startFilePosition, size_t *endFilePosition, bool verbose);

/**
 * @brief  Utility function to load data safely from a DICTIONARY textfile. This method takes a preferred name.
 * E.g. mfc_default_keys.dic
 *
 * @param preferredName
 * @param pdata A pointer to a pointer  (for reverencing the loaded dictionary)
 * @param keylen  the number of bytes a key per row is
 * @return 0 for ok, 1 for failz
*/
int loadFileDICTIONARY_safe(const char *preferredName, void **pdata, uint8_t keylen, uint32_t *keycnt);

int loadFileBinaryKey(const char *preferredName, const char *suffix, void **keya, void **keyb, size_t *alen, size_t *blen);

typedef enum {
    MFU_DF_UNKNOWN,
    MFU_DF_PLAINBIN,
    MFU_DF_OLDBIN,
    MFU_DF_NEWBIN
} mfu_df_e;
/**
 * @brief  Utility function to check and convert plain mfu dump format to new mfu binary format.
 * plain dumps doesn't have any extra data, like version, signature etc.
 * @param dump pointer to loaded dump to check and convert format
 * @param dumplen the number of bytes loaded dump and converted
 * @param verbose - extra debug output
 * @return PM3_SUCCESS for ok, PM3_ESOFT for fails
*/
int convert_mfu_dump_format(uint8_t **dump, size_t *dumplen, bool verbose);
mfu_df_e detect_mfu_dump_format(uint8_t **dump, size_t *dumplen, bool verbose);

int searchAndList(const char *pm3dir, const char *ext);
int searchFile(char **foundpath, const char *pm3dir, const char *searchname, const char *suffix, bool silent);


/**
 * @brief detects if file is of a supported filetype based on extension
 * @param filename
 * @return
 */
DumpFileType_t getfiletype(const char *filename);


/**
 * @brief load dump file into a data array dynamically allocated
 * @param fn
 * @param pdump pointer to loaded dump
 * @param dumplen the number of bytes loaded from dump file
 * @param maxdumplen maximum size of data array in bytes (JSON files)
 * @return PM3_SUCCESS if OK
 */
int pm3_load_dump(const char *fn, void **pdump, size_t *dumplen, size_t maxdumplen);


/** STUB
 * @brief Utility function to save data to three file files (BIN/EML/JSON).
 * It also tries to save according to user preferences set dump folder paths.
 * E.g. dumpdata.bin
 * E.g. dumpdata.eml
 * E.g. dumpdata.json

 * @param fn
 * @param d The binary data to write to the file
 * @param n the length of the data
 * @param jsft json format type for the different memory cards (MFC, MFUL, LEGIC, 14B, 15, ICLASS etc)
 * @param blocksize
 * @return PM3_SUCCESS if OK
 */
int pm3_save_dump(const char *fn, uint8_t *d, size_t n, JSONFileType jsft, size_t blocksize);
#endif // FILEUTILS_H
