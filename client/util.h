//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// utilities
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include "data.h"

#ifndef MIN
# define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
# define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif
#define TRUE                        1
#define FALSE                       0
#define EVEN                        0
#define ODD                         1

int ukbhit(void);

void AddLogLine(char *fileName, char *extData, char *c);
void AddLogHex(char *fileName, char *extData, const uint8_t * data, const size_t len);
void AddLogUint64(char *fileName, char *extData, const uint64_t data);
void AddLogCurrentDT(char *fileName);
void FillFileNameByUID(char *fileName, uint8_t * uid, char *ext, int byteCount);

void print_hex(const uint8_t * data, const size_t len);
char * sprint_hex(const uint8_t * data, const size_t len);
char * sprint_bin(const uint8_t * data, const size_t len);
char * sprint_bin_break(const uint8_t *data, const size_t len, const uint8_t breaks);

void num_to_bytes(uint64_t n, size_t len, uint8_t* dest);
uint64_t bytes_to_num(uint8_t* src, size_t len);
char * printBits(size_t const size, void const * const ptr);
uint8_t *SwapEndian64(const uint8_t *src, const size_t len, const uint8_t blockSize);

char param_getchar(const char *line, int paramnum);
uint8_t param_get8(const char *line, int paramnum);
uint8_t param_get8ex(const char *line, int paramnum, int deflt, int base);
uint32_t param_get32ex(const char *line, int paramnum, int deflt, int base);
uint64_t param_get64ex(const char *line, int paramnum, int deflt, int base);
uint8_t param_getdec(const char *line, int paramnum, uint8_t *destination);
uint8_t param_isdec(const char *line, int paramnum);
int param_gethex(const char *line, int paramnum, uint8_t * data, int hexcnt);
int param_getstr(const char *line, int paramnum, char * str);

 int hextobinarray( char *target,  char *source);
 int hextobinstring( char *target,  char *source);
 int binarraytohex( char *target,  char *source,  int length);
void binarraytobinstring(char *target,  char *source,  int length);
uint8_t GetParity( char *string, uint8_t type,  int length);
void wiegand_add_parity(char *target, char *source, char length);

void xor(unsigned char *dst, unsigned char *src, size_t len);
int32_t le24toh(uint8_t data[3]);
