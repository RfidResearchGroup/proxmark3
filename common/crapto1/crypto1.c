/*  crypto1.c

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
	MA  02110-1301, US

	Copyright (C) 2008-2008 bla <blapost@gmail.com>
*/
#include "crapto1.h"

#include <stdlib.h>
#include "parity.h"

#define SWAPENDIAN(x)\
	(x = (x >> 8 & 0xff00ff) | (x & 0xff00ff) << 8, x = x >> 16 | x << 16)

#if defined(__arm__) && !defined(__linux__) && !defined(_WIN32) && !defined(__APPLE__)		// bare metal ARM Proxmark lacks malloc()/free()
void crypto1_create(struct Crypto1State *s, uint64_t key)
{
	int i;

	for(i = 47;s && i > 0; i -= 2) {
		s->odd  = s->odd  << 1 | BIT(key, (i - 1) ^ 7);
		s->even = s->even << 1 | BIT(key, i ^ 7);
	}
	return;
}
void crypto1_destroy(struct Crypto1State *state)
{
	state->odd = 0;
	state->even = 0;
}
#else
struct Crypto1State * crypto1_create(uint64_t key)
{
	struct Crypto1State *s = malloc(sizeof(*s));
	if ( !s ) return NULL;

	s->odd = s->even = 0;
	
	int i;
	//for(i = 47;s && i > 0; i -= 2) {
	for(i = 47; i > 0; i -= 2) {
		s->odd  = s->odd  << 1 | BIT(key, (i - 1) ^ 7);
		s->even = s->even << 1 | BIT(key, i ^ 7);
	}
	return s;
}
void crypto1_destroy(struct Crypto1State *state)
{
	free(state);
}
#endif
void crypto1_get_lfsr(struct Crypto1State *state, uint64_t *lfsr)
{
	int i;
	for(*lfsr = 0, i = 23; i >= 0; --i) {
		*lfsr = *lfsr << 1 | BIT(state->odd, i ^ 3);
		*lfsr = *lfsr << 1 | BIT(state->even, i ^ 3);
	}
}
uint8_t crypto1_bit(struct Crypto1State *s, uint8_t in, int is_encrypted)
{
	uint32_t feedin, t;
	uint8_t ret = filter(s->odd);

	feedin  = ret & !!is_encrypted;
	feedin ^= !!in;
	feedin ^= LF_POLY_ODD & s->odd;
	feedin ^= LF_POLY_EVEN & s->even;
	s->even = s->even << 1 | evenparity32(feedin);

	t = s->odd;
	s->odd = s->even;
	s->even = t;

	return ret;
}
uint8_t crypto1_byte(struct Crypto1State *s, uint8_t in, int is_encrypted)
{
	/*
	uint8_t i, ret = 0;

	for (i = 0; i < 8; ++i)
		ret |= crypto1_bit(s, BIT(in, i), is_encrypted) << i;
	*/
// unfold loop 20161012
	uint8_t ret = 0;
	ret |= crypto1_bit(s, BIT(in, 0), is_encrypted) << 0;
	ret |= crypto1_bit(s, BIT(in, 1), is_encrypted) << 1;
	ret |= crypto1_bit(s, BIT(in, 2), is_encrypted) << 2;
	ret |= crypto1_bit(s, BIT(in, 3), is_encrypted) << 3;
	ret |= crypto1_bit(s, BIT(in, 4), is_encrypted) << 4;
	ret |= crypto1_bit(s, BIT(in, 5), is_encrypted) << 5;
	ret |= crypto1_bit(s, BIT(in, 6), is_encrypted) << 6;
	ret |= crypto1_bit(s, BIT(in, 7), is_encrypted) << 7;
	return ret;
}
uint32_t crypto1_word(struct Crypto1State *s, uint32_t in, int is_encrypted)
{
	/*
	uint32_t i, ret = 0;

	for (i = 0; i < 32; ++i)
		ret |= crypto1_bit(s, BEBIT(in, i), is_encrypted) << (i ^ 24);
*/
//unfold loop 2016012
	uint32_t ret = 0;
	ret |= crypto1_bit(s, BEBIT(in, 0), is_encrypted) << (0 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 1), is_encrypted) << (1 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 2), is_encrypted) << (2 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 3), is_encrypted) << (3 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 4), is_encrypted) << (4 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 5), is_encrypted) << (5 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 6), is_encrypted) << (6 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 7), is_encrypted) << (7 ^ 24);
	
	ret |= crypto1_bit(s, BEBIT(in, 8), is_encrypted) << (8 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 9), is_encrypted) << (9 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 10), is_encrypted) << (10 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 11), is_encrypted) << (11 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 12), is_encrypted) << (12 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 13), is_encrypted) << (13 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 14), is_encrypted) << (14 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 15), is_encrypted) << (15 ^ 24);

	ret |= crypto1_bit(s, BEBIT(in, 16), is_encrypted) << (16 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 17), is_encrypted) << (17 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 18), is_encrypted) << (18 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 19), is_encrypted) << (19 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 20), is_encrypted) << (20 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 21), is_encrypted) << (21 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 22), is_encrypted) << (22 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 23), is_encrypted) << (23 ^ 24);

	ret |= crypto1_bit(s, BEBIT(in, 24), is_encrypted) << (24 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 25), is_encrypted) << (25 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 26), is_encrypted) << (26 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 27), is_encrypted) << (27 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 28), is_encrypted) << (28 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 29), is_encrypted) << (29 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 30), is_encrypted) << (30 ^ 24);
	ret |= crypto1_bit(s, BEBIT(in, 31), is_encrypted) << (31 ^ 24);
	return ret;
}

/* prng_successor
 * helper used to obscure the keystream during authentication
 */
uint32_t prng_successor(uint32_t x, uint32_t n)
{
	SWAPENDIAN(x);
	while(n--)
		x = x >> 1 | (x >> 16 ^ x >> 18 ^ x >> 19 ^ x >> 21) << 31;

	return SWAPENDIAN(x);
}
