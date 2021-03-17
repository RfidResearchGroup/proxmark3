//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// utilities
//-----------------------------------------------------------------------------
#ifndef __UTIL_H_
#define __UTIL_H_

#include "common.h"

#ifdef ANDROID
#include <endian.h>
#endif

// used for save/load files
#ifndef FILE_PATH_SIZE
# define FILE_PATH_SIZE 1000
#endif

extern uint8_t g_debugMode;
extern uint8_t g_printAndLog;
typedef int (*print_cb_t)(char *s);
extern print_cb_t g_printCallback;
extern bool g_pendingPrompt;

#define PRINTANDLOG_PRINT 1
#define PRINTANDLOG_LOG   2

int kbd_enter_pressed(void);
void FillFileNameByUID(char *filenamePrefix, const uint8_t *uid, const char *ext, const int uidlen);
// fill buffer from structure [{uint8_t data, size_t length},...]
int FillBuffer(uint8_t *data, size_t maxDataLength, size_t *dataLength, ...);

bool CheckStringIsHEXValue(const char *value);
void hex_to_buffer(const uint8_t *buf, const uint8_t *hex_data, const size_t hex_len,
                   const size_t hex_max_len, const size_t min_str_len, const size_t spaces_between,
                   bool uppercase);

void print_hex(const uint8_t *data, const size_t len);
void print_hex_break(const uint8_t *data, const size_t len, const uint8_t breaks);
char *sprint_hex(const uint8_t *data, const size_t len);
char *sprint_hex_inrow(const uint8_t *data, const size_t len);
char *sprint_hex_inrow_ex(const uint8_t *data, const size_t len, const size_t min_str_len);
char *sprint_hex_inrow_spaces(const uint8_t *data, const size_t len, size_t spaces_between);
char *sprint_bin(const uint8_t *data, const size_t len);
char *sprint_bin_break(const uint8_t *data, const size_t len, const uint8_t breaks);
char *sprint_hex_ascii(const uint8_t *data, const size_t len);
char *sprint_ascii(const uint8_t *data, const size_t len);
char *sprint_ascii_ex(const uint8_t *data, const size_t len, const size_t min_str_len);

void print_buffer(const uint8_t *data, const size_t len, int level);
void print_blocks(uint32_t *data, size_t len);

int hex_to_bytes(const char *hexValue, uint8_t *bytesValue, size_t maxBytesValueLen);
void num_to_bytebits(uint64_t n, size_t len, uint8_t *dest);
void num_to_bytebitsLSBF(uint64_t n, size_t len, uint8_t *dest);
void bytes_to_bytebits(void *src, size_t srclen, void *dest);

// Swap endian on arrays up to 64bytes.
uint8_t *SwapEndian64(const uint8_t *src, const size_t len, const uint8_t blockSize);
void SwapEndian64ex(const uint8_t *src, const size_t len, const uint8_t blockSize, uint8_t *dest);

// parameter helper functions
int param_getlength(const char *line, int paramnum);
char param_getchar(const char *line, int paramnum);
char param_getchar_indx(const char *line, int indx, int paramnum);
int param_getptr(const char *line, int *bg, int *en, int paramnum);
uint8_t param_get8(const char *line, int paramnum);
uint8_t param_get8ex(const char *line, int paramnum, int deflt, int base);
uint32_t param_get32ex(const char *line, int paramnum, int deflt, int base);
uint64_t param_get64ex(const char *line, int paramnum, int deflt, int base);
float param_getfloat(const char *line, int paramnum, float deflt);
uint8_t param_getdec(const char *line, int paramnum, uint8_t *destination);
uint8_t param_isdec(const char *line, int paramnum);
int param_gethex(const char *line, int paramnum, uint8_t *data, int hexcnt);
int param_gethex_ex(const char *line, int paramnum, uint8_t *data, int *hexcnt);
int param_gethex_to_eol(const char *line, int paramnum, uint8_t *data, int maxdatalen, int *datalen);
int param_getstr(const char *line, int paramnum, char *str, size_t buffersize);

int hextobinarray(char *target, char *source);
int hextobinstring(char *target, char *source);
int binarraytohex(char *target, const size_t targetlen, char *source, size_t srclen);
void binarraytobinstring(char *target,  char *source, int length);
int binstring2binarray(uint8_t* target, char *source, int length);

uint8_t GetParity(uint8_t *bits, uint8_t type, int length);
void wiegand_add_parity(uint8_t *target, uint8_t *source, uint8_t length);
void wiegand_add_parity_swapped(uint8_t *target, uint8_t *source, uint8_t length);

//void xor(unsigned char *dst, unsigned char *src, size_t len);

uint32_t PackBits(uint8_t start, uint8_t len, uint8_t *bits);
uint64_t HornerScheme(uint64_t num, uint64_t divider, uint64_t factor);

int num_CPUs(void); // number of logical CPUs

void str_lower(char *s); // converts string to lower case
bool str_startswith(const char *s,  const char *pre);  // check for prefix in string
bool str_endswith(const char *s,  const char *suffix);    // check for suffix in string
void clean_ascii(unsigned char *buf, size_t len);
void strcleanrn(char *buf, size_t len);
void strcreplace(char *buf, size_t len, char from, char to);
char *str_dup(const char *src);
char *str_ndup(const char *src, size_t len);
int hexstring_to_u96(uint32_t *hi2, uint32_t *hi, uint32_t *lo, const char *str);

uint32_t bitcount32(uint32_t a);
uint64_t bitcount64(uint64_t a);
uint32_t leadingzeros32(uint32_t a);
uint64_t leadingzeros64(uint64_t a);

#endif
