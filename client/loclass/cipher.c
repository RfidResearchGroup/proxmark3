/*****************************************************************************
 * This file is part of iClassCipher. It is a reconstructon of the cipher engine
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
 * along with IClassCipher.  If not, see <http://www.gnu.org/licenses/>.
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include "loclass/cipher.h"
#include "loclass/cipherutils.h"
#include "loclass/ikeys.h"

uint8_t keytable[] = { 0,0,0,0,0,0,0,0};

/**
*	Definition 2. The feedback function for the top register T : F 16/2 → F 2
*	is defined as
*	T (x 0 x 1 . . . . . . x 15 ) = x 0 ⊕ x 1 ⊕ x 5 ⊕ x 7 ⊕ x 10 ⊕ x 11 ⊕ x 14 ⊕ x 15 .
**/
bool T(State state)
{
	bool x0 = state.t & 0x8000;
	bool x1 = state.t & 0x4000;
	bool x5 = state.t & 0x0400;
	bool x7 = state.t & 0x0100;
	bool x10 = state.t & 0x0020;
	bool x11 = state.t & 0x0010;
	bool x14 = state.t & 0x0002;
	bool x15 = state.t & 0x0001;
	return x0 ^ x1 ^ x5 ^ x7 ^ x10 ^ x11 ^ x14 ^ x15;
}
/**
*	Similarly, the feedback function for the bottom register B : F 8/2 → F 2 is defined as
*	B(x 0 x 1 . . . x 7 ) = x 1 ⊕ x 2 ⊕ x 3 ⊕ x 7 .
**/
bool B(State state)
{
	bool x1 = state.b & 0x40;
	bool x2 = state.b & 0x20;
	bool x3 = state.b & 0x10;
	bool x7 = state.b & 0x01;

	return x1 ^ x2 ^ x3 ^ x7;

}


/**
*	Definition 3 (Selection function). The selection function select : F 2 × F 2 ×
*	F 8/2 → F 3/2 is defined as select(x, y, r) = z 0 z 1 z 2 where
*	z 0 = (r 0 ∧ r 2 ) ⊕ (r 1 ∧ r 3 ) ⊕ (r 2 ∨ r 4 )
*	z 1 = (r 0 ∨ r 2 ) ⊕ (r 5 ∨ r 7 ) ⊕ r 1 ⊕ r 6 ⊕ x ⊕ y
*	z 2 = (r 3 ∧ r 5 ) ⊕ (r 4 ∧ r 6 ) ⊕ r 7 ⊕ x
**/
uint8_t _select(bool x, bool y, uint8_t r)
{
	bool r0 = r >> 7 & 0x1;
	bool r1 = r >> 6 & 0x1;
	bool r2 = r >> 5 & 0x1;
	bool r3 = r >> 4 & 0x1;
	bool r4 = r >> 3 & 0x1;
	bool r5 = r >> 2 & 0x1;
	bool r6 = r >> 1 & 0x1;
	bool r7 = r & 0x1;

	bool z0 = (r0 & r2) ^ (r1 & ~r3) ^ (r2 | r4);
	bool z1 = (r0 | r2) ^ ( r5 | r7) ^ r1 ^ r6 ^ x ^ y;
	bool z2 = (r3 & ~r5) ^ (r4 & r6 ) ^ r7 ^ x;

	// The three bitz z0.. z1 are packed into a uint8_t:
	// 00000ZZZ
	//Return value is a uint8_t
	uint8_t retval = 0;
	retval |= (z0 << 2) & 4;
	retval |= (z1 << 1) & 2;
	retval |= z2 & 1;

	// Return value 0 <= retval <= 7
	return retval;
}

/**
*	Definition 4 (Successor state). Let s = l, r, t, b be a cipher state, k ∈ (F 82 ) 8
*	be a key and y ∈ F 2 be the input bit. Then, the successor cipher state s ′ =
*	l ′ , r ′ , t ′ , b ′ is defined as
*	t ′ := (T (t) ⊕ r 0 ⊕ r 4 )t 0 . . . t 14 l ′ := (k [select(T (t),y,r)] ⊕ b ′ ) ⊞ l ⊞ r
*	b ′ := (B(b) ⊕ r 7 )b 0 . . . b 6 r ′ := (k [select(T (t),y,r)] ⊕ b ′ ) ⊞ l
*
* @param s - state
* @param k - array containing 8 bytes
**/
State successor(uint8_t* k, State s, bool y)
{
	bool r0 = s.r >> 7 & 0x1;
	bool r4 = s.r >> 3 & 0x1;
	bool r7 = s.r & 0x1;

	State successor = {0,0,0,0};

	successor.t = s.t >> 1;
	successor.t |= (T(s) ^ r0 ^ r4) << 15;

	successor.b = s.b >> 1;
	successor.b |= (B(s) ^ r7) << 7;

	bool Tt = T(s);

	successor.l = ((k[_select(Tt,y,s.r)] ^ successor.b) + s.l+s.r ) & 0xFF;
	successor.r = ((k[_select(Tt,y,s.r)] ^ successor.b) + s.l ) & 0xFF;

	return successor;
}
/**
*	We define the successor function suc which takes a key k ∈ (F 82 ) 8 , a state s and
*	an input y ∈ F 2 and outputs the successor state s ′ . We overload the function suc
*	to multiple bit input x ∈ F n 2 which we define as
* @param k - array containing 8 bytes
**/
State suc(uint8_t* k,State s, BitstreamIn *bitstream)
{
	if(bitsLeft(bitstream) == 0)
	{
		return s;
	}
	bool lastbit = tailBit(bitstream);
	return successor(k,suc(k,s,bitstream), lastbit);
}

/**
*	Definition 5 (Output). Define the function output which takes an internal
*	state s =< l, r, t, b > and returns the bit r 5 . We also define the function output
*	on multiple bits input which takes a key k, a state s and an input x ∈ F n 2 as
*	output(k, s, ǫ) = ǫ
*	output(k, s, x 0 . . . x n ) = output(s) · output(k, s ′ , x 1 . . . x n )
*	where s ′ = suc(k, s, x 0 ).
**/
void output(uint8_t* k,State s, BitstreamIn* in,  BitstreamOut* out)
{
	if(bitsLeft(in) == 0)
	{
		return;
	}
	//printf("bitsleft %d" , bitsLeft(in));
	//printf(" %0d", s.r >> 2 & 1);
	pushBit(out,(s.r >> 2) & 1);
	//Remove first bit
	uint8_t x0 = headBit(in);
	State ss = successor(k,s,x0);
	output(k,ss,in, out);
}

/**
* Definition 6 (Initial state). Define the function init which takes as input a
* key k ∈ (F 82 ) 8 and outputs the initial cipher state s =< l, r, t, b >
**/

State init(uint8_t* k)
{
	State s = {
	((k[0] ^ 0x4c) + 0xEC) & 0xFF,// l
	((k[0] ^ 0x4c) + 0x21) & 0xFF,// r
	0x4c, // b
	0xE012 // t
	};
	return s;
}
void MAC(uint8_t* k, BitstreamIn input, BitstreamOut out)
{
	uint8_t zeroes_32[] = {0,0,0,0};
	BitstreamIn input_32_zeroes = {zeroes_32,sizeof(zeroes_32)*8,0};
	State initState = suc(k,init(k),&input);
	output(k,initState,&input_32_zeroes,&out);

}


void printarr(char * name, uint8_t* arr, int len)
{
	int i ;
	printf("uint8_t %s[] = {", name);
	for(i =0 ;  i< len ; i++)
	{
		printf("0x%02x,",*(arr+i));
	}
	printf("};\n");
}

int testMAC()
{

	//From the "dismantling.IClass" paper:
	uint8_t cc_nr[] = {0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0,0,0,0};
	// But actually, that must be reversed, it's "on-the-wire" data
	reverse_arraybytes(cc_nr,sizeof(cc_nr));

	//From the paper
	uint8_t div_key[] = {0xE0,0x33,0xCA,0x41,0x9A,0xEE,0x43,0xF9};
	uint8_t correct_MAC[] = {0x1d,0x49,0xC9,0xDA};

	BitstreamIn bitstream = {cc_nr,sizeof(cc_nr) * 8,0};
	uint8_t dest []= {0,0,0,0,0,0,0,0};
	BitstreamOut out = { dest, sizeof(dest)*8, 0 };
	MAC(div_key,bitstream, out);
	//The output MAC must also be reversed
	reverse_arraybytes(dest, sizeof(dest));

	if(false && memcmp(dest, correct_MAC,4) == 0)
	{
		printf("MAC calculation OK!\n");

	}else
	{
		printf("MAC calculation failed\n");
		printarr("Calculated_MAC", dest, 4);
		printarr("Correct_MAC   ", correct_MAC, 4);
		return 1;
	}
	return 0;
}

int calc_iclass_mac(uint8_t *cc_nr_p, int length, uint8_t *div_key_p, uint8_t *mac)
{
    uint8_t *cc_nr;
    uint8_t div_key[8];
    cc_nr=(uint8_t*)malloc(length+1);
    memcpy(cc_nr,cc_nr_p,length);
    memcpy(div_key,div_key_p,8);
    
	reverse_arraybytes(cc_nr,length);
	BitstreamIn bitstream = {cc_nr,length * 8,0};
	uint8_t dest []= {0,0,0,0,0,0,0,0};
	BitstreamOut out = { dest, sizeof(dest)*8, 0 };
	MAC(div_key,bitstream, out);
	//The output MAC must also be reversed
	reverse_arraybytes(dest, sizeof(dest));
	
	printf("Calculated_MAC\t%02x%02x%02x%02x\n", dest[0],dest[1],dest[2],dest[3]);
	memcpy(mac,dest,4);
	free(cc_nr);
	return 1;
}