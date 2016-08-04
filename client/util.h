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
#include <stdint.h>		//included in data.h
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <math.h>		// math.pow
#include "data.h"		// for FILE_PATH_SIZE
#include "proxmark3.h"

#ifndef BITMASK
# define BITMASK(X) (1 << (X))
#endif
#ifndef ROTR
# define ROTR(x,n) (((uintmax_t)(x) >> (n)) | ((uintmax_t)(x) << ((sizeof(x) * 8) - (n))))
#endif

#ifndef MIN
# define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
# define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

// Byte swapping
#ifndef BSWAP_32
# define BSWAP_32(x) \
     ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) | \
      (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))
#endif
#ifndef BSWAP_16
# define BSWAP_16(x) ((( ((x) & 0xFF00 ) >> 8))| ( (((x) & 0x00FF) << 8)))
#endif

// Boolean
#define TRUE                        1
#define FALSE                       0
#define EVEN                        0
#define ODD                         1

// Nibble logic
#ifndef NIBBLE_HIGH
# define NIBBLE_HIGH(b) ( (b & 0xF0) >> 4 )
#endif
#ifndef NIBBLE_LOW
# define NIBBLE_LOW(b)  ( b & 0x0F )
#endif
#ifndef CRUMB
# define CRUMB(b,p)    (((b & (0x3 << p) ) >> p ) & 0xF)
#endif
#ifndef SWAP_NIBBLE
# define SWAP_NIBBLE(b)  ( (NIBBLE_LOW(b)<< 4) | NIBBLE_HIGH(b))
#endif

// Binary Encoded Digit
#ifndef BCD2DEC
# define BCD2DEC(bcd) HornerScheme(bcd, 0x10, 10)
#endif
#ifndef DEC2BCD
# define DEC2BCD(dec) HornerScheme(dec, 10, 0x10)
#endif

// used for save/load files
#ifndef FILE_PATH_SIZE
# define FILE_PATH_SIZE 1000
#endif

#ifndef ARRAYLEN
# define ARRAYLEN(x) (sizeof(x)/sizeof((x)[0]))
#endif

int ukbhit(void);

void AddLogLine(char *fileName, char *extData, char *c);
void AddLogHex(char *fileName, char *extData, const uint8_t * data, const size_t len);
void AddLogUint64(char *fileName, char *extData, const uint64_t data);
void AddLogCurrentDT(char *fileName);
void FillFileNameByUID(char *fileName, uint8_t * uid, char *ext, int byteCount);

void print_hex(const uint8_t * data, const size_t len);
void print_hex_break(const uint8_t *data, const size_t len, const uint8_t breaks);
char *sprint_hex(const uint8_t * data, const size_t len);
char *sprint_bin(const uint8_t * data, const size_t len);
char *sprint_bin_break(const uint8_t *data, const size_t len, const uint8_t breaks);
char *sprint_hex_ascii(const uint8_t *data, const size_t len);

void num_to_bytes(uint64_t n, size_t len, uint8_t* dest);
uint64_t bytes_to_num(uint8_t* src, size_t len);
void num_to_bytebits(uint64_t n, size_t len, uint8_t *dest);
void num_to_bytebitsLSBF(uint64_t n, size_t len, uint8_t *dest);
uint8_t *SwapEndian64(const uint8_t *src, const size_t len, const uint8_t blockSize);
void SwapEndian64ex(const uint8_t *src, const size_t len, const uint8_t blockSize, uint8_t *dest);

char param_getchar(const char *line, int paramnum);
int param_getptr(const char *line, int *bg, int *en, int paramnum);
uint8_t param_get8(const char *line, int paramnum);
uint8_t param_get8ex(const char *line, int paramnum, int deflt, int base);
uint32_t param_get32ex(const char *line, int paramnum, int deflt, int base);
uint64_t param_get64ex(const char *line, int paramnum, int deflt, int base);
uint8_t param_getdec(const char *line, int paramnum, uint8_t *destination);
uint8_t param_isdec(const char *line, int paramnum);
int param_gethex(const char *line, int paramnum, uint8_t * data, int hexcnt);
int param_gethex_ex(const char *line, int paramnum, uint8_t * data, int *hexcnt);
int param_getstr(const char *line, int paramnum, char * str);

int hextobinarray( char *target,  char *source);
int hextobinstring( char *target,  char *source);
int binarraytohex( char *target,  char *source,  int length);
void binarraytobinstring(char *target,  char *source,  int length);
uint8_t GetParity( uint8_t *string, uint8_t type,  int length);
void wiegand_add_parity(uint8_t *target, uint8_t *source, uint8_t length);

void xor(unsigned char * dst, unsigned char * src, size_t len);
int32_t le24toh (uint8_t data[3]);
uint32_t le32toh (uint8_t *data);
uint32_t PackBits(uint8_t start, uint8_t len, uint8_t* bits);
void rol(uint8_t *data, const size_t len);
uint32_t SwapBits(uint32_t value, int nrbits);
uint32_t reflect(uint32_t v, int b);
uint64_t HornerScheme(uint64_t num, uint64_t divider, uint64_t factor);