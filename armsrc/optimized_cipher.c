/*****************************************************************************
 * WARNING
 *
 * THIS CODE IS CREATED FOR EXPERIMENTATION AND EDUCATIONAL USE ONLY. 
 * 
 * USAGE OF THIS CODE IN OTHER WAYS MAY INFRINGE UPON THE INTELLECTUAL 
 * PROPERTY OF OTHER PARTIES, SUCH AS INSIDE SECURE AND HID GLOBAL, 
 * AND MAY EXPOSE YOU TO AN INFRINGEMENT ACTION FROM THOSE PARTIES. 
 * 
 * THIS CODE SHOULD NEVER BE USED TO INFRINGE PATENTS OR INTELLECTUAL PROPERTY RIGHTS. 
 *
 *****************************************************************************
 *
 * This file is part of loclass. It is a reconstructon of the cipher engine
 * used in iClass, and RFID techology.
 *
 * The implementation is based on the work performed by
 * Flavio D. Garcia, Gerhard de Koning Gans, Roel Verdult and
 * Milosch Meriac in the paper "Dismantling IClass".
 *
 * Copyright (C) 2014 Martin Holst Swende
 *
 * This is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with loclass.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * 
 * 
 ****************************************************************************/

/**

  This file contains an optimized version of the MAC-calculation algorithm. Some measurements on
  a std laptop showed it runs in about 1/3 of the time:

	Std: 0.428962
	Opt: 0.151609

  Additionally, it is self-reliant, not requiring e.g. bitstreams from the cipherutils, thus can
  be easily dropped into a code base.

  The optimizations have been performed in the following steps:
  * Parameters passed by reference instead of by value.
  * Iteration instead of recursion, un-nesting recursive loops into for-loops.
  * Handling of bytes instead of individual bits, for less shuffling and masking
  * Less creation of "objects", structs, and instead reuse of alloc:ed memory
  * Inlining some functions via #define:s

  As a consequence, this implementation is less generic. Also, I haven't bothered documenting this.
  For a thorough documentation, check out the MAC-calculation within cipher.c instead.

  -- MHS 2015
**/

#include "optimized_cipher.h"
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>


#define opt_T(s) (0x1 & ((s->t >> 15) ^ (s->t >> 14)^ (s->t >> 10)^ (s->t >> 8)^ (s->t >> 5)^ (s->t >> 4)^ (s->t >> 1)^ s->t))

#define opt_B(s) (((s->b >> 6) ^ (s->b >> 5) ^ (s->b >> 4) ^ (s->b)) & 0x1)

#define opt__select(x,y,r)  (4 & (((r & (r << 2)) >> 5) ^ ((r & ~(r << 2)) >> 4) ^ ( (r | r << 2) >> 3)))\
	|(2 & (((r | r << 2) >> 6) ^ ( (r | r << 2) >> 1) ^ (r >> 5) ^ r ^ ((x^y) << 1)))\
	|(1 & (((r & ~(r << 2)) >> 4) ^ ((r & (r << 2)) >> 3) ^ r ^ x))

/*
 * Some background on the expression above can be found here...
uint8_t xopt__select(bool x, bool y, uint8_t r)
{
	uint8_t r_ls2 = r << 2;
	uint8_t r_and_ls2 = r & r_ls2;
	uint8_t r_or_ls2  = r | r_ls2;

	//r:      r0 r1 r2 r3 r4 r5 r6 r7
	//r_ls2:  r2 r3 r4 r5 r6 r7  0  0
	//                       z0
	//                          z1

//	uint8_t z0 = (r0 & r2) ^ (r1 & ~r3) ^ (r2 | r4); // <-- original
	uint8_t z0 = (r_and_ls2 >> 5) ^ ((r & ~r_ls2) >> 4) ^ ( r_or_ls2 >> 3);

//	uint8_t z1 = (r0 | r2) ^ ( r5 | r7) ^ r1 ^ r6 ^ x ^ y;  // <-- original
	uint8_t z1 = (r_or_ls2 >> 6) ^ ( r_or_ls2 >> 1) ^ (r >> 5) ^ r ^ ((x^y) << 1);

//	uint8_t z2 = (r3 & ~r5) ^ (r4 & r6 ) ^ r7 ^ x;  // <-- original
	uint8_t z2 = ((r & ~r_ls2) >> 4) ^ (r_and_ls2 >> 3) ^ r ^ x;

	return (z0 & 4) | (z1 & 2) | (z2 & 1);
}
*/

void opt_successor(const uint8_t* k, State *s, bool y, State* successor)
{

	uint8_t Tt = 1 & opt_T(s);

	successor->t = (s->t >> 1);
	successor->t |= (Tt ^ (s->r >> 7 & 0x1) ^ (s->r >> 3 & 0x1)) << 15;

	successor->b = s->b >> 1;
	successor->b |= (opt_B(s) ^ (s->r & 0x1)) << 7;

	successor->r = (k[opt__select(Tt,y,s->r)] ^ successor->b) + s->l ;
	successor->l = successor->r+s->r;

}

void opt_suc(const uint8_t* k,State* s, uint8_t *in, uint8_t length, bool add32Zeroes)
{
	State x2;
	int i;
	uint8_t head = 0;
	for(i =0 ; i < length  ; i++)
	{
		head = 1 & (in[i] >> 7);
		opt_successor(k,s,head,&x2);

		head = 1 & (in[i] >> 6);
		opt_successor(k,&x2,head,s);

		head = 1 & (in[i] >> 5);
		opt_successor(k,s,head,&x2);

		head = 1 & (in[i] >> 4);
		opt_successor(k,&x2,head,s);

		head = 1 & (in[i] >> 3);
		opt_successor(k,s,head,&x2);

		head = 1 & (in[i] >> 2);
		opt_successor(k,&x2,head,s);

		head = 1 & (in[i] >> 1);
		opt_successor(k,s,head,&x2);

		head = 1 & in[i];
		opt_successor(k,&x2,head,s);

	}
	//For tag MAC, an additional 32 zeroes
	if(add32Zeroes)
		for(i =0 ; i < 16 ; i++)
		{
			opt_successor(k,s,0,&x2);
			opt_successor(k,&x2,0,s);
		}
}

void opt_output(const uint8_t* k,State* s,  uint8_t *buffer)
{
	uint8_t times = 0;
	uint8_t bout = 0;
	State temp = {0,0,0,0};
	for( ; times < 4 ; times++)
	{
		bout =0;
		bout |= (s->r & 0x4) << 5;
		opt_successor(k,s,0,&temp);
		bout |= (temp.r & 0x4) << 4;
		opt_successor(k,&temp,0,s);
		bout |= (s->r & 0x4) << 3;
		opt_successor(k,s,0,&temp);
		bout |= (temp.r & 0x4) << 2;
		opt_successor(k,&temp,0,s);
		bout |= (s->r & 0x4) << 1;
		opt_successor(k,s,0,&temp);
		bout |= (temp.r & 0x4) ;
		opt_successor(k,&temp,0,s);
		bout |= (s->r & 0x4) >> 1;
		opt_successor(k,s,0,&temp);
		bout |= (temp.r & 0x4) >> 2;
		opt_successor(k,&temp,0,s);
		buffer[times] = bout;
	}

}

void opt_MAC(uint8_t* k, uint8_t* input, uint8_t* out)
{
	State _init  =  {
			((k[0] ^ 0x4c) + 0xEC) & 0xFF,// l
			((k[0] ^ 0x4c) + 0x21) & 0xFF,// r
			0x4c, // b
			0xE012 // t
			};

	opt_suc(k,&_init,input,12, false);
	//printf("\noutp ");
	opt_output(k,&_init, out);
}
uint8_t rev_byte(uint8_t b) {
	b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
	b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
	b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
   return b;
}
void opt_reverse_arraybytecpy(uint8_t* dest, uint8_t *src, size_t len)
{
	uint8_t i;
	for( i =0; i< len ; i++)
		dest[i] = rev_byte(src[i]);
}

void opt_doReaderMAC(uint8_t *cc_nr_p, uint8_t *div_key_p, uint8_t mac[4])
{
	static uint8_t cc_nr[12];

	opt_reverse_arraybytecpy(cc_nr, cc_nr_p,12);
	uint8_t dest []= {0,0,0,0,0,0,0,0};
	opt_MAC(div_key_p,cc_nr, dest);
	//The output MAC must also be reversed
	opt_reverse_arraybytecpy(mac, dest,4);
	return;
}
void opt_doTagMAC(uint8_t *cc_p, const uint8_t *div_key_p, uint8_t mac[4])
{
	static uint8_t cc_nr[8+4+4];
	opt_reverse_arraybytecpy(cc_nr, cc_p,12);
	State _init  =  {
			((div_key_p[0] ^ 0x4c) + 0xEC) & 0xFF,// l
			((div_key_p[0] ^ 0x4c) + 0x21) & 0xFF,// r
			0x4c, // b
			0xE012 // t
			};
	opt_suc(div_key_p,&_init,cc_nr, 12,true);
	uint8_t dest []= {0,0,0,0};
	opt_output(div_key_p,&_init, dest);
	//The output MAC must also be reversed
	opt_reverse_arraybytecpy(mac, dest,4);
	return;

}
/**
 * The tag MAC can be divided (both can, but no point in dividing the reader mac) into
 * two functions, since the first 8 bytes are known, we can pre-calculate the state
 * reached after feeding CC to the cipher.
 * @param cc_p
 * @param div_key_p
 * @return the cipher state
 */
State opt_doTagMAC_1(uint8_t *cc_p, const uint8_t *div_key_p)
{
	static uint8_t cc_nr[8];
	opt_reverse_arraybytecpy(cc_nr, cc_p,8);
	State _init  =  {
			((div_key_p[0] ^ 0x4c) + 0xEC) & 0xFF,// l
			((div_key_p[0] ^ 0x4c) + 0x21) & 0xFF,// r
			0x4c, // b
			0xE012 // t
			};
	opt_suc(div_key_p,&_init,cc_nr, 8,false);
	return _init;
}
/**
 * The second part of the tag MAC calculation, since the CC is already calculated into the state,
 * this function is fed only the NR, and internally feeds the remaining 32 0-bits to generate the tag
 * MAC response.
 * @param _init - precalculated cipher state
 * @param nr - the reader challenge
 * @param mac - where to store the MAC
 * @param div_key_p - the key to use
 */
void opt_doTagMAC_2(State _init,  uint8_t* nr, uint8_t mac[4], const uint8_t* div_key_p)
{
	static uint8_t _nr [4];
	opt_reverse_arraybytecpy(_nr, nr, 4);
	opt_suc(div_key_p,&_init,_nr, 4, true);
	//opt_suc(div_key_p,&_init,nr, 4, false);
	uint8_t dest []= {0,0,0,0};
	opt_output(div_key_p,&_init, dest);
	//The output MAC must also be reversed
	opt_reverse_arraybytecpy(mac, dest,4);
	return;
}
