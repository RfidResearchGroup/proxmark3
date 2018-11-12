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

int saveFile(const char *preferredName, const char *suffix, const void* data, size_t datalen) {
	int size = sizeof(char) * (strlen(preferredName) + strlen(suffix) + 10);
	char * fileName = calloc(size, sizeof(char));
	int num = 1;
	sprintf(fileName,"%s.%s", preferredName, suffix);
	while (fileExists(fileName)) {
		sprintf(fileName,"%s-%d.%s", preferredName, num, suffix);
		num++;
	}
	/* We should have a valid filename now, e.g. dumpdata-3.bin */

	/*Opening file for writing in binary mode*/
	FILE *f = fopen(fileName, "wb");
	if (!f) {
		PrintAndLogDevice(WARNING, "file not found or locked. '%s'", fileName);
		free(fileName);
		return 1;
	}
	fwrite(data, 1,	datalen, f);
	fflush(f);
	fclose(f);
	PrintAndLogDevice(SUCCESS, "saved %u bytes to binary file %s", datalen, fileName);
	free(fileName);
	return 0;
}

int saveFileEML(const char *preferredName, const char *suffix, uint8_t* data, size_t datalen, size_t blocksize) {

	if ( preferredName == NULL ) return 1;
	if ( suffix == NULL ) return 1;
	if ( data == NULL ) return 1;

	int retval = 0;
	int blocks = datalen/blocksize;
	uint16_t currblock = 1;
	int i,j;
	int size = sizeof(char) * (strlen(preferredName) + strlen(suffix) + 10);
	char * fileName = calloc(size, sizeof(char));
	int num = 1;
	sprintf(fileName,"%s.%s", preferredName, suffix);
	while (fileExists(fileName)) {
		sprintf(fileName,"%s-%d.%s", preferredName, num, suffix);
		num++;
	}
	
	/* We should have a valid filename now, e.g. dumpdata-3.bin */

	/*Opening file for writing in text mode*/
	FILE *f = fopen(fileName, "w+");
	if (!f) {
		PrintAndLogDevice(WARNING, "file not found or locked. '%s'", fileName);
		retval =  1;
		goto out;
	}

	for (i = 0; i < datalen; i++) {
		fprintf(f, "%02X", data[i] );
		
		// no extra line in the end
		if ( (i+1) % blocksize == 0 && currblock != blocks ) {
			fprintf(f, "\n");
			currblock++;
		}
	}
	// left overs
	if ( datalen % blocksize != 0) {
		int index = blocks * blocksize;
		for (j = 0; j < datalen % blocksize; j++) {
			fprintf(f, "%02X", data[index + j] );
		}
	}
	fflush(f);
	fclose(f);
	PrintAndLogDevice(SUCCESS, "saved %d blocks to text file %s", blocks, fileName);
	
out:	
	free(fileName);
	return retval;
}

int saveFileJSON(const char *preferredName, const char *suffix, uint8_t* data, size_t datalen) {
	//stub - for merlokk ;)
	return 1;
}

int loadFile(const char *preferredName, const char *suffix, void* data, size_t* datalen) {

	if ( preferredName == NULL ) return 1;
	if ( suffix == NULL ) return 1;

	int retval = 0;
	int size = sizeof(char) * (strlen(preferredName) + strlen(suffix) + 10);
	char * fileName = calloc(size, sizeof(char));
	sprintf(fileName,"%s.%s", preferredName, suffix);

	FILE *f = fopen(fileName, "rb");
	if ( !f ) {
		PrintAndLogDevice(FAILED, "file: %s: not found or locked.", fileName);
		retval = 1;
		goto out;
	}
	
	// get filesize in order to malloc memory
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	if ( fsize < 0 ) 	{
		PrintAndLogDevice(FAILED, "error, when getting filesize");
		retval = 1;
		goto out;
	}
	
	uint8_t *dump = calloc(fsize, sizeof(uint8_t));
	if ( !dump ) {
		PrintAndLogDevice(FAILED, "error, cannot allocate memory");
		retval = 2;
		goto out;
	}
	
	size_t bytes_read = fread(dump, 1, fsize, f);

	if ( bytes_read != fsize ) {
		PrintAndLogDevice(FAILED, "error, bytes read mismatch file size");
		free(dump);
		retval = 3;
		goto out;		
	}
	
	if ( (data) == NULL) {
		(data) = calloc( bytes_read, sizeof(uint8_t));
	}
	
	memcpy( (data), dump, bytes_read);
	free(dump);
	
	PrintAndLogDevice(SUCCESS, "loaded %d bytes from binary file %s", bytes_read, fileName);
	
	*datalen = bytes_read;

out:	
	fclose(f);
	free(fileName);
	return retval;
}

int loadFileEML(const char *preferredName, const char *suffix, void* data, size_t* datalen) {

	if ( preferredName == NULL ) return 1;
	if ( suffix == NULL ) return 1;

    size_t counter = 0;
	int retval = 0, hexlen = 0;
	int size = sizeof(char) * (strlen(preferredName) + strlen(suffix) + 10);
	char * fileName = calloc(size, sizeof(char));
	sprintf(fileName,"%s.%s", preferredName, suffix);

	FILE *f = fopen(fileName, "r");
	if ( !f ) {
		PrintAndLogDevice(FAILED, "file: %s: not found or locked.", fileName);
		retval = 1;
		goto out;
	}
	
	// 128 + 2 newline chars + 1 null terminator	
	char line[131];
	memset(line, 0, sizeof(line));
	uint8_t buf[64] = {0x00};
	
	while ( !feof(f) ) {

		memset(line, 0, sizeof(line));

		if (fgets(line, sizeof(line), f) == NULL){
			fclose(f);
			PrintAndLogEx(FAILED, "File reading error.");
			retval = 2;
			goto out;
		}
	
		if ( line[0] == '#' )
			continue;
		
		int res = param_gethex_to_eol(line, 0, buf, sizeof(buf), &hexlen);
		if (res == 0 || res == 1) {
			memcpy(data + counter, buf, hexlen);
			counter += hexlen;
		}
	}
	fclose(f);
	PrintAndLogDevice(SUCCESS, "loaded %d bytes from text file %s", counter, fileName);
	*datalen = counter;
		
out:	
	free(fileName);
	return retval;
}

int loadFileJSON(const char *preferredName, const char *suffix, void* data, size_t* datalen) {
	//stub - for merlokk ;)
	datalen = 0;
	return 1;
}

#else //if we're on ARM

#endif
