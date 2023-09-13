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
extern bool g_pendingPrompt;
extern int g_numCPUs;

#define PRINTANDLOG_PRINT 1
#define PRINTANDLOG_LOG   2

// Return error
#define PM3_RET_ERR(err, ...)  { \
    PrintAndLogEx(ERR, __VA_ARGS__); \
    return err; \
}

#define PM3_RET_ERR_FREE(err, ...)  { \
    CLIParserFree(ctx); \
    PrintAndLogEx(ERR, __VA_ARGS__); \
    return err; \
}

// RETurn IF ERRor
#define PM3_RET_IF_ERR(res)                          if (res != PM3_SUCCESS) {                                               return res; }
#define PM3_RET_IF_ERR_WITH_MSG(res, ...)            if (res != PM3_SUCCESS) {              PrintAndLogEx(ERR, __VA_ARGS__); return res; }
#define PM3_RET_IF_ERR_MAYBE_MSG(res, verbose, ...)  if (res != PM3_SUCCESS) { if (verbose) PrintAndLogEx(ERR, __VA_ARGS__); return res; }

int kbd_enter_pressed(void);
void FillFileNameByUID(char *filenamePrefix, const uint8_t *uid, const char *ext, const int uidlen);
// fill buffer from structure [{uint8_t data, size_t length},...]
int FillBuffer(uint8_t *data, size_t maxDataLength, size_t *dataLength, ...);

bool CheckStringIsHEXValue(const char *value);
void ascii_to_buffer(uint8_t *buf, const uint8_t *hex_data, const size_t hex_len,
                     const size_t hex_max_len, const size_t min_str_len);
void hex_to_buffer(uint8_t *buf, const uint8_t *hex_data, const size_t hex_len,
                   const size_t hex_max_len, const size_t min_str_len, const size_t spaces_between,
                   bool uppercase);

void print_hex(const uint8_t *data, const size_t len);
void print_hex_break(const uint8_t *data, const size_t len, const uint8_t breaks);
void print_hex_noascii_break(const uint8_t *data, const size_t len, uint8_t breaks);

char *sprint_hex(const uint8_t *data, const size_t len);
char *sprint_hex_inrow(const uint8_t *data, const size_t len);
char *sprint_hex_inrow_ex(const uint8_t *data, const size_t len, const size_t min_str_len);
char *sprint_hex_inrow_spaces(const uint8_t *data, const size_t len, size_t spaces_between);
char *sprint_bin(const uint8_t *data, const size_t len);
char *sprint_bytebits_bin(const uint8_t *data, const size_t len);
char *sprint_bytebits_bin_break(const uint8_t *data, const size_t len, const uint8_t breaks);
char *sprint_hex_ascii(const uint8_t *data, const size_t len);
char *sprint_ascii(const uint8_t *data, const size_t len);
char *sprint_ascii_ex(const uint8_t *data, const size_t len, const size_t min_str_len);

void print_buffer_with_offset(const uint8_t *data, const size_t len, int offset, bool print_header);
void print_buffer(const uint8_t *data, const size_t len, int level);
void print_blocks(uint32_t *data, size_t len);

int hex_to_bytes(const char *hexValue, uint8_t *bytesValue, size_t maxBytesValueLen);
void num_to_bytebits(uint64_t n, size_t len, uint8_t *dest);
void num_to_bytebitsLSBF(uint64_t n, size_t len, uint8_t *dest);
void bytes_to_bytebits(const void *src, const size_t srclen, void *dest);

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
int param_getbin_to_eol(const char *line, int paramnum, uint8_t *data, int maxdatalen, int *datalen);
int param_getstr(const char *line, int paramnum, char *str, size_t buffersize);

int hextobinarray(char *target, char *source);
int hextobinarray_n(char *target, char *source, int sourcelen);

int hextobinstring(char *target, char *source);
int hextobinstring_n(char *target, char *source, int sourcelen);

int binarraytohex(char *target, const size_t targetlen, const char *source, size_t srclen);
void binarraytobinstring(char *target,  char *source, int length);
int binstring2binarray(uint8_t *target, char *source, int length);

uint8_t GetParity(const uint8_t *bits, uint8_t type, int length);
void wiegand_add_parity(uint8_t *target, uint8_t *source, uint8_t length);
void wiegand_add_parity_swapped(uint8_t *target, uint8_t *source, uint8_t length);

//void xor(unsigned char *dst, unsigned char *src, size_t len);

uint32_t PackBits(uint8_t start, uint8_t len, const uint8_t *bits);
uint64_t HornerScheme(uint64_t num, uint64_t divider, uint64_t factor);

int num_CPUs(void);
int detect_num_CPUs(void); // number of logical CPUs

void str_lower(char *s); // converts string to lower case
void str_upper(char *s); // converts string to UPPER case
void strn_upper(char *s, size_t n);

bool str_startswith(const char *s,  const char *pre);  // check for prefix in string
bool str_endswith(const char *s,  const char *suffix);    // check for suffix in string
void clean_ascii(unsigned char *buf, size_t len);
void strcleanrn(char *buf, size_t len);
void strcreplace(char *buf, size_t len, char from, char to);
char *str_dup(const char *src);
char *str_ndup(const char *src, size_t len);
int hexstring_to_u96(uint32_t *hi2, uint32_t *hi, uint32_t *lo, const char *str);
int binstring_to_u96(uint32_t *hi2, uint32_t *hi, uint32_t *lo, const char *str);
int binarray_to_u96(uint32_t *hi2, uint32_t *hi, uint32_t *lo, const uint8_t *arr, int arrlen);

uint32_t bitcount32(uint32_t a);
uint64_t bitcount64(uint64_t a);
uint32_t leadingzeros32(uint32_t a);
uint64_t leadingzeros64(uint64_t a);

int byte_strstr(const uint8_t *src, size_t srclen, const uint8_t *pattern, size_t plen);
int byte_strrstr(const uint8_t *src, size_t srclen, const uint8_t *pattern, size_t plen);

struct smartbuf {
    char *ptr;
    size_t size;
    size_t idx;
} typedef smartbuf;
void sb_append_char(smartbuf *sb, unsigned char c);
#endif
