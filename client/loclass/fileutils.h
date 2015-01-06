#ifndef FILEUTILS_H
#define FILEUTILS_H
/**
 * @brief Utility function to save data to a file. This method takes a preferred name, but if that
 * file already exists, it tries with another name until it finds something suitable.
 * E.g. dumpdata-15.txt
 * @param preferredName
 * @param suffix the file suffix. Leave out the ".".
 * @param data The binary data to write to the file
 * @param datalen the length of the data
 * @return 0 for ok, 1 for failz
 */
int saveFile(const char *preferredName, const char *suffix, const void* data, size_t datalen);


/**
 * Utility function to print to console. This is used consistently within the library instead
 * of printf, but it actually only calls printf. The reason to have this method is to
 *make it simple to plug this library into proxmark, which has this function already to
 * write also to a logfile. When doing so, just point this function to use PrintAndLog
 * @param fmt
 */
void prnlog(char *fmt, ...);
int fileExists(const char *filename);
#endif // FILEUTILS_H
