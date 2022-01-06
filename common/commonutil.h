//-----------------------------------------------------------------------------
// Jonathan Westhues, Aug 2005
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Utility functions used in many places, not specific to any piece of code.
//-----------------------------------------------------------------------------

#ifndef __COMMONUTIL_H
#define __COMMONUTIL_H

#include "common.h"

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

#ifndef BITMASK
# define BITMASK(X) (1 << (X))
#endif
#ifndef ARRAYLEN
# define ARRAYLEN(x) (sizeof(x)/sizeof((x)[0]))
#endif

#ifndef NTIME
# define NTIME(n) for (int _index = 0; _index < n; _index++)
#endif

extern struct version_information_t g_version_information;
void FormatVersionInformation(char *dst, int len, const char *prefix, void *version_info);

uint32_t reflect(uint32_t v, int b); // used in crc.c ...
uint8_t reflect8(uint8_t b);         // dedicated 8bit reversal
uint16_t reflect16(uint16_t b);      // dedicated 16bit reversal
uint32_t reflect32(uint32_t b);      // dedicated 32bit reversal

void num_to_bytes(uint64_t n, size_t len, uint8_t *dest);
uint64_t bytes_to_num(uint8_t *src, size_t len);

// LE and BE to/from memory
uint16_t MemLeToUint2byte(uint8_t *data);
uint32_t MemLeToUint3byte(uint8_t *data);
uint32_t MemLeToUint4byte(uint8_t *data);
uint16_t MemBeToUint2byte(uint8_t *data);
uint32_t MemBeToUint3byte(uint8_t *data);
uint32_t MemBeToUint4byte(uint8_t *data);
void Uint2byteToMemLe(uint8_t *data, uint16_t value);
void Uint3byteToMemLe(uint8_t *data, uint32_t value);
void Uint4byteToMemLe(uint8_t *data, uint32_t value);
void Uint2byteToMemBe(uint8_t *data, uint16_t value);
void Uint3byteToMemBe(uint8_t *data, uint32_t value);
void Uint4byteToMemBe(uint8_t *data, uint32_t value);

// rotate left byte array
void rol(uint8_t *data, const size_t len);
void lsl(uint8_t *data, size_t len);
uint32_t le24toh(uint8_t data[3]);
void htole24(uint32_t val, uint8_t data[3]);

// rol on a u32
uint32_t rotl(uint32_t a, uint8_t n);
uint32_t rotr(uint32_t a, uint8_t n);

uint16_t get_sw(const uint8_t *d, uint8_t n);
#endif
