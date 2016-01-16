//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Generic CRC calculation code.
//-----------------------------------------------------------------------------

#ifndef __PARITY_H
#define __PARITY_H

#include <stdint.h>

extern const uint8_t OddByteParity[256];

static inline uint8_t oddparity8(uint8_t bt)
{
	return OddByteParity[bt];
}


extern const uint8_t EvenByteParity[256];

static inline uint8_t evenparity8(const uint8_t bt)
{
	return EvenByteParity[bt];
}


static inline uint8_t evenparity32(uint32_t x) 
{
	x ^= x >> 16;
	x ^= x >> 8;
	return EvenByteParity[x & 0xff];
}


#endif /* __PARITY_H */
