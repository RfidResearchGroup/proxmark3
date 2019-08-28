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
//    jsf14b,
//    jsf15,
//    jsfLegic,
//    jsfT55xx,
} JSONFileType;

int fileExists(const char *filename);

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
int saveFileJSON(const char *preferredName, JSONFileType ftype, uint8_t *data, size_t datalen);

/**
 * @brief Utility function to save a keydump.
 *
 * @param sectorsCnt the used sectors
 * @param e_sector the keys in question
 * @param fptr string pointer to the filename
 * @return 0 for ok, 1 for failz
 */
int createMfcKeyDump(uint8_t sectorsCnt, sector_t *e_sector, char *fptr);

/** STUB
 * @brief Utility function to load data from a binary file. This method takes a preferred name.
 * E.g. dumpdata-15.bin
 *
 * @param preferredName
 * @param suffix the file suffix. Including the ".".
 * @param data The data array to store the loaded bytes from file
 * @param maxdatalen the number of bytes that your data array has
 * @param datalen the number of bytes loaded from file
 * @return 0 for ok, 1 for failz
*/
int loadFile(const char *preferredName, const char *suffix, void *data, size_t maxdatalen, size_t *datalen);

/**
 * @brief  Utility function to load data from a textfile (EML). This method takes a preferred name.
 * E.g. dumpdata-15.txt
 *
 * @param preferredName
 * @param data The data array to store the loaded bytes from file
 * @param datalen the number of bytes loaded from file
 * @return 0 for ok, 1 for failz
*/
int loadFileEML(const char *preferredName, void *data, size_t *datalen);

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
int loadFileJSON(const char *preferredName, void *data, size_t maxdatalen, size_t *datalen);

/**
 * @brief  Utility function to load data from a DICTIONARY textfile. This method takes a preferred name.
 * E.g. mfc_default_keys.dic
 *
 * @param preferredName
 * @param data The data array to store the loaded bytes from file
 * @param maxdatalen maximum size of data array in bytes
 * @param datalen the number of bytes loaded from file
 * @param keylen  the number of bytes a key per row is
 * @return 0 for ok, 1 for failz
*/
int loadFileDICTIONARY(const char *preferredName, void *data, size_t *datalen, uint8_t keylen, uint16_t *keycnt);

/**
 * @brief  Utility function to load data safely from a DICTIONARY textfile. This method takes a preferred name.
 * E.g. mfc_default_keys.dic
 *
 * @param preferredName
 * @param pdata A pointer to a pointer  (for reverencing the loaded dictionary)
 * @param keylen  the number of bytes a key per row is
 * @return 0 for ok, 1 for failz
*/
int loadFileDICTIONARY_safe(const char *preferredName, void **pdata, uint8_t keylen, uint16_t *keycnt);

/**
 * @brief  Utility function to check and convert old mfu dump format to new
 *
 * @param dump pointer to loaded dump to check and convert format
 * @param dumplen the number of bytes loaded dump and converted
 * @return 0 for ok, 1 for fails
*/
int convertOldMfuDump(uint8_t **dump, size_t *dumplen);

int searchAndList(const char *pm3dir, const char *ext);
int searchFile(char **foundpath, const char *pm3dir, const char *searchname, const char *suffix);

#endif // FILEUTILS_H
