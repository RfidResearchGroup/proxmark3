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

#include <stddef.h>
#include <inttypes.h>
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

uint32_t reflect(uint32_t v, int b); // used in crc.c ...
uint8_t reflect8(uint8_t b);         // dedicated 8bit reversal
uint16_t reflect16(uint16_t b);      // dedicated 16bit reversal

void num_to_bytes(uint64_t n, size_t len, uint8_t *dest);
uint64_t bytes_to_num(uint8_t *src, size_t len);

void rol(uint8_t *data, const size_t len);
void lsl(uint8_t *data, size_t len);
int32_t le24toh(uint8_t data[3]);
void htole24(uint32_t val, uint8_t data[3]);

# define _BLUE_(s) "\x1b[34m" s "\x1b[0m "
# define _RED_(s) "\x1b[31m" s "\x1b[0m "
# define _GREEN_(s) "\x1b[32m" s "\x1b[0m "
# define _YELLOW_(s) "\x1b[33m" s "\x1b[0m "
# define _MAGENTA_(s) "\x1b[35m" s "\x1b[0m "
# define _CYAN_(s) "\x1b[36m" s "\x1b[0m "

#endif
