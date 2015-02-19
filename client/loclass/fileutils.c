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
 * by the Free Software Foundation.
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
 * 
 ****************************************************************************/
#ifndef ON_DEVICE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdarg.h>
#include "fileutils.h"
#include "ui.h"
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

int saveFile(const char *preferredName, const char *suffix, const void* data, size_t datalen)
{
	int size = sizeof(char) * (strlen(preferredName)+strlen(suffix)+10);
	char * fileName = malloc(size);

	memset(fileName,0,size);
	int num = 1;
	sprintf(fileName,"%s.%s", preferredName, suffix);
	while(fileExists(fileName))
	{
		sprintf(fileName,"%s-%d.%s", preferredName, num, suffix);
		num++;
	}
	/* We should have a valid filename now, e.g. dumpdata-3.bin */

	/*Opening file for writing in binary mode*/
	FILE *fileHandle=fopen(fileName,"wb");
	if(!fileHandle) {
		prnlog("Failed to write to file '%s'", fileName);
		free(fileName);
		return 1;
	}
	fwrite(data, 1,	datalen, fileHandle);
	fclose(fileHandle);
	prnlog("Saved data to '%s'", fileName);
	free(fileName);

	return 0;
}

/**
 * Utility function to print to console. This is used consistently within the library instead
 * of printf, but it actually only calls printf (and adds a linebreak).
 * The reason to have this method is to
 * make it simple to plug this library into proxmark, which has this function already to
 * write also to a logfile. When doing so, just delete this function.
 * @param fmt
 */
void prnlog(char *fmt, ...)
{
	char buffer[2048] = {0};
	va_list args;
	va_start(args,fmt);
	vsprintf (buffer,fmt, args);
	va_end(args);
	PrintAndLog(buffer);

}
#else //if we're on ARM
void prnlog(char *fmt,...)
{
	return;
}

#endif
