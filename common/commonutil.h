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

#ifndef REV8
#define REV8(x) ((((x)>>7)&1)+((((x)>>6)&1)<<1)+((((x)>>5)&1)<<2)+((((x)>>4)&1)<<3)+((((x)>>3)&1)<<4)+((((x)>>2)&1)<<5)+((((x)>>1)&1)<<6)+(((x)&1)<<7))
#endif

#ifndef REV16
#define REV16(x)        (REV8(x) + (REV8 ((x) >> 8) << 8))
#endif

#ifndef REV32
#define REV32(x)        (REV16(x) + (REV16((x) >> 16) << 16))
#endif

#ifndef REV64
#define REV64(x)        (REV32(x) + ((uint64_t)(REV32((x) >> 32) << 32)))
#endif


extern struct version_information_t g_version_information;
void FormatVersionInformation(char *dst, int len, const char *prefix, const void *version_info);
void format_version_information_short(char *dst, int len, const void *version_info);

uint32_t reflect(uint32_t v, int b); // used in crc.c ...
uint8_t reflect8(uint8_t b);         // dedicated 8bit reversal
uint16_t reflect16(uint16_t b);      // dedicated 16bit reversal
uint32_t reflect32(uint32_t b);      // dedicated 32bit reversal
uint64_t reflect64(uint64_t b);      // dedicated 64bit reversal

void num_to_bytes(uint64_t n, size_t len, uint8_t *dest);
uint64_t bytes_to_num(const uint8_t *src, size_t len);

// LE and BE to/from memory
uint16_t MemLeToUint2byte(const uint8_t *data);
uint32_t MemLeToUint3byte(const uint8_t *data);
uint32_t MemLeToUint4byte(const uint8_t *data);
uint64_t MemLeToUint5byte(const uint8_t *data);
uint64_t MemLeToUint6byte(const uint8_t *data);
uint64_t MemLeToUint7byte(const uint8_t *data);
uint64_t MemLeToUint8byte(const uint8_t *data);

uint16_t MemBeToUint2byte(const uint8_t *data);
uint32_t MemBeToUint3byte(const uint8_t *data);
uint32_t MemBeToUint4byte(const uint8_t *data);
uint64_t MemBeToUint5byte(const uint8_t *data);
uint64_t MemBeToUint6byte(const uint8_t *data);
uint64_t MemBeToUint7byte(const uint8_t *data);
uint64_t MemBeToUint8byte(const uint8_t *data);

void Uint2byteToMemLe(uint8_t *data, uint16_t value);
void Uint3byteToMemLe(uint8_t *data, uint32_t value);
void Uint4byteToMemLe(uint8_t *data, uint32_t value);
void Uint5byteToMemLe(uint8_t *data, uint64_t value);
void Uint6byteToMemLe(uint8_t *data, uint64_t value);
void Uint7byteToMemLe(uint8_t *data, uint64_t value);
void Uint8byteToMemLe(uint8_t *data, uint64_t value);

void Uint2byteToMemBe(uint8_t *data, uint16_t value);
void Uint3byteToMemBe(uint8_t *data, uint32_t value);
void Uint4byteToMemBe(uint8_t *data, uint32_t value);
void Uint5byteToMemBe(uint8_t *data, uint64_t value);
void Uint6byteToMemBe(uint8_t *data, uint64_t value);
void Uint7byteToMemBe(uint8_t *data, uint64_t value);
void Uint8byteToMemBe(uint8_t *data, uint64_t value);

// rotate left byte array
void rol(uint8_t *data, const size_t len);
void ror(uint8_t *data, const size_t len);

void lsl(uint8_t *data, size_t len);
uint32_t le24toh(const uint8_t data[3]);
void htole24(uint32_t val, uint8_t data[3]);

// rol on a u32
uint32_t rotl(uint32_t a, uint8_t n);
uint32_t rotr(uint32_t a, uint8_t n);

uint16_t get_sw(const uint8_t *d, uint16_t n);

void reverse_array(uint8_t *d, size_t n);
void reverse_array_copy(const uint8_t *src, int src_len, uint8_t *dest);

bool hexstr_to_byte_array(const char *hexstr, uint8_t *d, size_t *n);

void reverse_arraybytes(uint8_t *arr, size_t len);
void reverse_arraybytes_copy(uint8_t *arr, uint8_t *dest, size_t len);
#endif
