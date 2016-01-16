/*  crapto1.h

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
    MA  02110-1301, US$

    Copyright (C) 2008-2014 bla <blapost@gmail.com>
*/
#ifndef CRAPTO1_INCLUDED
#define CRAPTO1_INCLUDED
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

struct Crypto1State {uint32_t odd, even;};
struct Crypto1State* crypto1_create(uint64_t);
void crypto1_destroy(struct Crypto1State*);
void crypto1_get_lfsr(struct Crypto1State*, uint64_t*);
uint8_t crypto1_bit(struct Crypto1State*, uint8_t, int);
uint8_t crypto1_byte(struct Crypto1State*, uint8_t, int);
uint32_t crypto1_word(struct Crypto1State*, uint32_t, int);
uint32_t prng_successor(uint32_t x, uint32_t n);

struct Crypto1State* lfsr_recovery32(uint32_t ks2, uint32_t in);
struct Crypto1State* lfsr_recovery64(uint32_t ks2, uint32_t ks3);
uint32_t *lfsr_prefix_ks(uint8_t ks[8], int isodd);
struct Crypto1State*
lfsr_common_prefix(uint32_t pfx, uint32_t rr, uint8_t ks[8], uint8_t par[8][8]);

uint8_t lfsr_rollback_bit(struct Crypto1State* s, uint32_t in, int fb);
uint8_t lfsr_rollback_byte(struct Crypto1State* s, uint32_t in, int fb);
uint32_t lfsr_rollback_word(struct Crypto1State* s, uint32_t in, int fb);
int nonce_distance(uint32_t from, uint32_t to);
#define FOREACH_VALID_NONCE(N, FILTER, FSIZE)\
	uint32_t __n = 0,__M = 0, N = 0;\
	int __i;\
	for(; __n < 1 << 16; N = prng_successor(__M = ++__n, 16))\
		for(__i = FSIZE - 1; __i >= 0; __i--)\
			if(BIT(FILTER, __i) ^ parity(__M & 0xFF01))\
				break;\
			else if(__i)\
				__M = prng_successor(__M, (__i == 7) ? 48 : 8);\
			else 

#define LF_POLY_ODD (0x29CE5C)
#define LF_POLY_EVEN (0x870804)
#define BIT(x, n) ((x) >> (n) & 1)
#define BEBIT(x, n) BIT(x, (n) ^ 24)
static inline int parity(uint32_t x)
{
#if !defined __i386__ || !defined __GNUC__
	x ^= x >> 16;
	x ^= x >> 8;
	x ^= x >> 4;
	return BIT(0x6996, x & 0xf);
#else
        asm(    "movl %1, %%eax\n"
		"mov %%ax, %%cx\n"
		"shrl $0x10, %%eax\n"
		"xor %%ax, %%cx\n"
                "xor %%ch, %%cl\n"
                "setpo %%al\n"
                "movzx %%al, %0\n": "=r"(x) : "r"(x): "eax","ecx");
	return x;
#endif
}
static inline int filter(uint32_t const x)
{
	uint32_t f;

	f  = 0xf22c0 >> (x       & 0xf) & 16;
	f |= 0x6c9c0 >> (x >>  4 & 0xf) &  8;
	f |= 0x3c8b0 >> (x >>  8 & 0xf) &  4;
	f |= 0x1e458 >> (x >> 12 & 0xf) &  2;
	f |= 0x0d938 >> (x >> 16 & 0xf) &  1;
	return BIT(0xEC57E80A, f);
}
#ifdef __cplusplus
}
#endif
#endif
