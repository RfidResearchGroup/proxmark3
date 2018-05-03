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

#include <stdint.h>		//included in data.h
#include <stddef.h>
#include <inttypes.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "ui.h"			// PrintAndLog

#ifdef ANDROID
  #include <endian.h>
#endif

#ifndef BITMASK
# define BITMASK(X) (1 << (X))
#endif
#ifndef ROTR
# define ROTR(x,n) (((uintmax_t)(x) >> (n)) | ((uintmax_t)(x) << ((sizeof(x) * 8) - (n))))
#endif
#ifndef ROTL
# define ROTL(x,n) (((uintmax_t)(x) << (n)) | ((uintmax_t)(x) >> ((sizeof(x) * 8) - (n))))
#endif

#ifndef MIN
# define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
# define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

// endian change for 64bit
#ifdef __GNUC__
	#ifndef BSWAP_64
		#define BSWAP_64(x) __builtin_bswap64(x)
	#endif
#else
	#ifdef _MSC_VER
		#ifndef BSWAP_64
			#define BSWAP_64(x) _byteswap_uint64(x)
		#endif
	#else
	#ifndef BSWAP_64
		#define	BSWAP_64(x) \
			(((uint64_t)(x) << 56) | \
			(((uint64_t)(x) << 40) & 0xff000000000000ULL) | \
			(((uint64_t)(x) << 24) & 0xff0000000000ULL) | \
			(((uint64_t)(x) << 8)  & 0xff00000000ULL) | \
			(((uint64_t)(x) >> 8)  & 0xff000000ULL) | \
			(((uint64_t)(x) >> 24) & 0xff0000ULL) | \
			(((uint64_t)(x) >> 40) & 0xff00ULL) | \
			((uint64_t)(x)  >> 56))
		#endif
	#endif
#endif

// endian change for 32bit
#ifdef __GNUC__
	#ifndef BSWAP_32
		#define BSWAP_32(x) __builtin_bswap32(x)
	#endif
#else
	#ifdef _MSC_VER
		#ifndef BSWAP_32
			#define BSWAP_32(x) _byteswap_ulong(x)
		#endif
	#else
		#ifndef BSWAP_32
			# define BSWAP_32(x) \
			 ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) | \
			  (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))
		#endif
	#endif
#endif

// endian change for 16bit
#ifdef __GNUC__
	#ifndef BSWAP_16
		#define BSWAP_16(x) __builtin_bswap16(x)
	#endif
#else
	#ifdef _MSC_VER
		#ifndef BSWAP_16
			#define BSWAP_16(x) _byteswap_ushort(x)
		#endif
	#else
		#ifndef BSWAP_16
			# define BSWAP_16(x) ((( ((x) & 0xFF00 ) >> 8))| ( (((x) & 0x00FF) << 8)))
		#endif
	#endif
#endif

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

#if defined(__linux__)	|| (__APPLE__)
# define _BLUE_(s) "\x1b[34m" #s "\x1b[0m "
#else
# define _BLUE_(s) #s " "
#endif

#if defined(__linux__)	|| (__APPLE__)
# define _RED_(s) "\x1b[31m" #s "\x1b[0m "
#else
# define _RED_(s) #s " "
#endif

#if defined(__linux__)	|| (__APPLE__)
# define _GREEN_(s) "\x1b[32m" #s "\x1b[0m "
#else
# define _GREEN_(s) #s " "
#endif

#if defined(__linux__)	|| (__APPLE__)
# define _YELLOW_(s) "\x1b[33m" #s "\x1b[0m "
#else
# define _YELLOW_(s) #s " "
#endif

#if defined(__linux__)	|| (__APPLE__)
# define _MAGENTA_(s) "\x1b[35m" #s "\x1b[0m "
#else
# define _MAGENTA_(s) #s " "
#endif

#if defined(__linux__)	|| (__APPLE__)
# define _CYAN_(s) "\x1b[36m" #s "\x1b[0m "
#else
# define _CYAN_(s) #s " "
#endif

#ifndef DropField
#define DropField() { \
	UsbCommand c = {CMD_READER_ISO_14443a, {0,0,0}}; clearCommandBuffer(); SendCommand(&c); \
}
#endif

extern uint8_t g_debugMode;

extern int ukbhit(void);
extern void AddLogLine(char *fileName, char *extData, char *c);
extern void AddLogHex(char *fileName, char *extData, const uint8_t * data, const size_t len);
extern void AddLogUint64(char *fileName, char *extData, const uint64_t data);
extern void AddLogCurrentDT(char *fileName);
extern void FillFileNameByUID(char *filenamePrefix, uint8_t * uid, const char *ext, int uidlen);

extern void hex_to_buffer(const uint8_t *buf, const uint8_t *hex_data, const size_t hex_len, 
						  const size_t hex_max_len, const size_t min_str_len, const size_t spaces_between,
						  bool uppercase);

extern void print_hex(const uint8_t * data, const size_t len);
extern void print_hex_break(const uint8_t *data, const size_t len, const uint8_t breaks);
extern char *sprint_hex(const uint8_t * data, const size_t len);
extern char *sprint_hex_inrow(const uint8_t *data, const size_t len);
extern char *sprint_hex_inrow_ex(const uint8_t *data, const size_t len, const size_t min_str_len);
extern char *sprint_hex_inrow_spaces(const uint8_t *data, const size_t len, size_t spaces_between);
extern char *sprint_bin(const uint8_t * data, const size_t len);
extern char *sprint_bin_break(const uint8_t *data, const size_t len, const uint8_t breaks);
extern char *sprint_hex_ascii(const uint8_t *data, const size_t len);
extern char *sprint_ascii(const uint8_t *data, const size_t len);
extern char *sprint_ascii_ex(const uint8_t *data, const size_t len, const size_t min_str_len);

extern void print_blocks(uint32_t *data, size_t len);

extern void num_to_bytes(uint64_t n, size_t len, uint8_t* dest);
extern uint64_t bytes_to_num(uint8_t* src, size_t len);
extern void num_to_bytebits(uint64_t n, size_t len, uint8_t *dest);
extern void num_to_bytebitsLSBF(uint64_t n, size_t len, uint8_t *dest);
extern uint8_t *SwapEndian64(const uint8_t *src, const size_t len, const uint8_t blockSize);
extern void SwapEndian64ex(const uint8_t *src, const size_t len, const uint8_t blockSize, uint8_t *dest);

extern int param_getlength(const char *line, int paramnum);
extern char param_getchar(const char *line, int paramnum);
extern char param_getchar_indx(const char *line, int indx, int paramnum);
extern int param_getptr(const char *line, int *bg, int *en, int paramnum);
extern uint8_t param_get8(const char *line, int paramnum);
extern uint8_t param_get8ex(const char *line, int paramnum, int deflt, int base);
extern uint32_t param_get32ex(const char *line, int paramnum, int deflt, int base);
extern uint64_t param_get64ex(const char *line, int paramnum, int deflt, int base);
extern uint8_t param_getdec(const char *line, int paramnum, uint8_t *destination);
extern uint8_t param_isdec(const char *line, int paramnum);
extern int param_gethex(const char *line, int paramnum, uint8_t * data, int hexcnt);
extern int param_gethex_ex(const char *line, int paramnum, uint8_t * data, int *hexcnt);
extern int param_gethex_to_eol(const char *line, int paramnum, uint8_t * data, int maxdatalen, int *datalen);
extern int param_getstr(const char *line, int paramnum, char * str, size_t buffersize);

extern int hextobinarray( char *target,  char *source);
extern int hextobinstring( char *target,  char *source);
extern int binarraytohex( char *target,  char *source,  int length);
extern void binarraytobinstring(char *target,  char *source,  int length);
extern uint8_t GetParity( uint8_t *string, uint8_t type,  int length);
extern void wiegand_add_parity(uint8_t *target, uint8_t *source, uint8_t length);

extern void xor(unsigned char * dst, unsigned char * src, size_t len);
extern int32_t le24toh (uint8_t data[3]);

extern uint32_t PackBits(uint8_t start, uint8_t len, uint8_t* bits);
extern void rol(uint8_t *data, const size_t len);
extern uint32_t reflect(uint32_t v, int b);
extern uint8_t reflect8(uint8_t b);		// dedicated 8bit reversal
extern uint16_t reflect16(uint16_t b);	// dedicated 16bit reversal
extern uint64_t HornerScheme(uint64_t num, uint64_t divider, uint64_t factor);

extern int num_CPUs(void);			// number of logical CPUs

extern void str_lower(char* s);	 // converts string to lower case
extern void strcleanrn(char *buf, size_t len);
extern void strcreplace(char *buf, size_t len, char from, char to);
extern char *strmcopy(char *buf);
#endif 