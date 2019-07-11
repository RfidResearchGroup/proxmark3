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

#ifndef ON_DEVICE

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdarg.h>
#include "../ui.h"
#include "../emv/emvjson.h"
#include "mifare/mifare4.h"
#include "cmdhfmfu.h"

typedef enum {
    jsfRaw,
    jsfCardMemory,
    jsfMfuMemory,
    jsfHitag,
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
 * E.g. default_keys.dic
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
 * @brief  Utility function to check and convert old mfu dump format to new
 *
 * @param dump pointer to loaded dump to check and convert format
 * @param dumplen the number of bytes loaded dump and converted
 * @return 0 for ok, 1 for fails
*/
int convertOldMfuDump(uint8_t **dump, size_t *dumplen);

#define PrintAndLogDevice(level, format, args...)  PrintAndLogEx(level, format , ## args)
#else

/**
* Utility function to print to console. This is used consistently within the library instead
* of printf, but it actually only calls printf. The reason to have this method is to
*make it simple to plug this library into proxmark, which has this function already to
* write also to a logfile. When doing so, just point this function to use PrintAndLog
* @param fmt
*/
#define PrintAndLogDevice(level, format, args...) { }



#endif //ON_DEVICE

#endif // FILEUTILS_H
