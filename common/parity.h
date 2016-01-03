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

#define oddparity8(x) (OddByteParity[(x)])


extern const uint8_t EvenByteParity[256];

static inline bool /*__attribute__((always_inline))*/ evenparity8(const uint8_t x) {
#if !defined __i386__ || !defined __GNUC__
	return EvenByteParity[x];
#else
	uint8_t y;
        __asm(	"testb $255, %1\n"
                "setpo %0\n" : "=r"(y) : "r"(x): );
	return y;
#endif
}


static inline uint8_t evenparity32(uint32_t x) 
{
	x ^= x >> 16;
	x ^= x >> 8;
	return EvenByteParity[x & 0xff];
}


#endif /* __PARITY_H */
