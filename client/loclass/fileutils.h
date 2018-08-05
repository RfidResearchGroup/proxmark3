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

/**
 * @brief Utility function to save data to a binary file. This method takes a preferred name, but if that
 * file already exists, it tries with another name until it finds something suitable.
 * E.g. dumpdata-15.txt
 * @param preferredName
 * @param suffix the file suffix. Leave out the ".".
 * @param data The binary data to write to the file
 * @param datalen the length of the data
 * @return 0 for ok, 1 for failz
 */
extern int saveFile(const char *preferredName, const char *suffix, const void* data, size_t datalen);

/**
 * @brief Utility function to save data to a textfile. This method takes a preferred name, but if that
 * file already exists, it tries with another name until it finds something suitable.
 * E.g. dumpdata-15.txt
 * @param preferredName
 * @param suffix the file suffix. Leave out the ".".
 * @param data The binary data to write to the file
 * @param datalen the length of the data
 * @param blocksize the length of one row
 * @return 0 for ok, 1 for failz
*/
extern int saveFileEML(const char *preferredName, const char *suffix, uint8_t* data, size_t datalen, size_t blocksize);
/**
 * @brief Utility function to save load binary data from a a file. This method takes a filename,
 * Should only be used for fixed-size binary files
 * @param fileName the name of the file
 * @param data a buffer to place data in
 * @param datalen the length of the data/data.
 * @return
 */

int fileExists(const char *filename);

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


//void PrintAndLogDevice(logLevel_t level, char *fmt, ...);

#endif // FILEUTILS_H
