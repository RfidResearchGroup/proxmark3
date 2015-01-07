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
	struct stat st;
	int result = stat(filename, &st);
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
		PrintAndLog("Failed to write to file '%s'", fileName);
		free(fileName);
		return 1;
	}
	fwrite(data, 1,	datalen, fileHandle);
	fclose(fileHandle);
	PrintAndLog("Saved data to '%s'", fileName);

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
