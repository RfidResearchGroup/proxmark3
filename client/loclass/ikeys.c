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
/**
From "Dismantling iclass":
	This section describes in detail the built-in key diversification algorithm of iClass.
	Besides the obvious purpose of deriving a card key from a master key, this
	algorithm intends to circumvent weaknesses in the cipher by preventing the
	usage of certain ‘weak’ keys. In order to compute a diversified key, the iClass
	reader first encrypts the card identity id with the master key K, using single
	DES. The resulting ciphertext is then input to a function called hash0 which
	outputs the diversified key k.

	k = hash0(DES enc (id, K))

	Here the DES encryption of id with master key K outputs a cryptogram c
	of 64 bits. These 64 bits are divided as c = x, y, z [0] , . . . , z [7] ∈ F 82 × F 82 × (F 62 ) 8
	which is used as input to the hash0 function. This function introduces some
	obfuscation by performing a number of permutations, complement and modulo
	operations, see Figure 2.5. Besides that, it checks for and removes patterns like
	similar key bytes, which could produce a strong bias in the cipher. Finally, the
	output of hash0 is the diversified card key k = k [0] , . . . , k [7] ∈ (F 82 ) 8 .


**/


#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "cipherutils.h"
#include "cipher.h"
#include "../util.h"
#include <stdio.h>
#include "des.h"
#include <inttypes.h>

uint8_t pi[35] = {0x0F,0x17,0x1B,0x1D,0x1E,0x27,0x2B,0x2D,0x2E,0x33,0x35,0x39,0x36,0x3A,0x3C,0x47,0x4B,0x4D,0x4E,0x53,0x55,0x56,0x59,0x5A,0x5C,0x63,0x65,0x66,0x69,0x6A,0x6C,0x71,0x72,0x74,0x78};

static des_context ctx_enc = {DES_ENCRYPT,{0}};
static des_context ctx_dec = {DES_DECRYPT,{0}};

static bool debug_print = false;

/**
 * @brief The key diversification algorithm uses 6-bit bytes.
 * This implementation uses 64 bit uint to pack seven of them into one
 * variable. When they are there, they are placed as follows:
 * XXXX XXXX N0 .... N7, occupying the lsat 48 bits.
 *
 * This function picks out one from such a collection
 * @param all
 * @param n bitnumber
 * @return
 */
uint8_t getSixBitByte(uint64_t c, int n)
{
	return (c >> (42-6*n)) & 0x3F;
	//return (c >> n*6) & 0x3f;
}

/**
 * @brief Puts back a six-bit 'byte' into a uint64_t.
 * @param c buffer
 * @param z the value to place there
 * @param n bitnumber.
 */
void pushbackSixBitByte(uint64_t *c, uint8_t z, int n)
{
	//0x XXXX YYYY ZZZZ ZZZZ ZZZZ
	//             ^z0         ^z7
	//z0:  1111 1100 0000 0000

	uint64_t masked = z & 0x3F;
	uint64_t eraser = 0x3F;
	masked <<= 42-6*n;
	eraser <<= 42-6*n;

	//masked <<= 6*n;
	//eraser <<= 6*n;

	eraser = ~eraser;
	(*c) &= eraser;
	(*c) |= masked;

}

uint64_t swapZvalues(uint64_t c)
{
	uint64_t newz = 0;
	pushbackSixBitByte(&newz, getSixBitByte(c,0),7);
	pushbackSixBitByte(&newz, getSixBitByte(c,1),6);
	pushbackSixBitByte(&newz, getSixBitByte(c,2),5);
	pushbackSixBitByte(&newz, getSixBitByte(c,3),4);
	pushbackSixBitByte(&newz, getSixBitByte(c,4),3);
	pushbackSixBitByte(&newz, getSixBitByte(c,5),2);
	pushbackSixBitByte(&newz, getSixBitByte(c,6),1);
	pushbackSixBitByte(&newz, getSixBitByte(c,7),0);
	newz |= (c & 0xFFFF000000000000);
	return newz;
}

/**
* @return 4 six-bit bytes chunked into a uint64_t,as 00..00a0a1a2a3
*/
uint64_t ck(int i, int j, uint64_t z)
{

//	printf("ck( i=%d, j=%d), zi=[%d],zj=[%d] \n",i,j,getSixBitByte(z,i),getSixBitByte(z,j) );

	if(i == 1 && j == -1)
	{
		// ck(1, −1, z [0] . . . z [3] ) = z [0] . . . z [3]
		return z;

	}else if( j == -1)
	{
		// ck(i, −1, z [0] . . . z [3] ) = ck(i − 1, i − 2, z [0] . . . z [3] )
		return ck(i-1,i-2, z);
	}

	if(getSixBitByte(z,i) == getSixBitByte(z,j))
	{
		// TODO, I dont know what they mean here in the paper
		//ck(i, j − 1, z [0] . . . z [i] ← j . . . z [3] )
		uint64_t newz = 0;
		int c;
		//printf("z[i]=z[i] (0x%02x), i=%d, j=%d\n",getSixBitByte(z,i),i,j );
		for(c = 0; c < 4 ;c++)
		{
			uint8_t val = getSixBitByte(z,c);
			if(c == i)
			{
				//printf("oops\n");
				pushbackSixBitByte(&newz, j, c);
			}else
			{
				pushbackSixBitByte(&newz, val, c);
			}
		}
		return ck(i,j-1,newz);
	}else
	{
		return ck(i,j-1,z);
	}

}
/**

	Definition 8.
	Let the function check : (F 62 ) 8 → (F 62 ) 8 be defined as
	check(z [0] . . . z [7] ) = ck(3, 2, z [0] . . . z [3] ) · ck(3, 2, z [4] . . . z [7] )

	where ck : N × N × (F 62 ) 4 → (F 62 ) 4 is defined as

		ck(1, −1, z [0] . . . z [3] ) = z [0] . . . z [3]
		ck(i, −1, z [0] . . . z [3] ) = ck(i − 1, i − 2, z [0] . . . z [3] )
		ck(i, j, z [0] . . . z [3] ) =
		ck(i, j − 1, z [0] . . . z [i] ← j . . . z [3] ),  if z [i] = z [j] ;
		ck(i, j − 1, z [0] . . . z [3] ), otherwise

	otherwise.
**/

uint64_t check(uint64_t z)
{
	//These 64 bits are divided as c = x, y, z [0] , . . . , z [7]

	// ck(3, 2, z [0] . . . z [3] )
	uint64_t ck1 = ck(3,2, z );

	// ck(3, 2, z [4] . . . z [7] )
	uint64_t ck2 = ck(3,2, z << 24);
	ck1 &= 0x00000000FFFFFF000000;
	ck2 &= 0x00000000FFFFFF000000;

	return ck1 | ck2 >> 24;

}

void permute(BitstreamIn *p_in, uint64_t z,int l,int r, BitstreamOut* out)
{
	if(bitsLeft(p_in) == 0)
	{
		return;
	}
	bool pn = tailBit(p_in);
	if( pn ) // pn = 1
	{
		uint8_t zl = getSixBitByte(z,l);
		//printf("permute pushing, zl=0x%02x, zl+1=0x%02x\n", zl, zl+1);
		push6bits(out, zl+1);
		permute(p_in, z, l+1,r, out);
	}else // otherwise
	{
		uint8_t zr = getSixBitByte(z,r);
		//printf("permute pushing, zr=0x%02x\n", zr);
		push6bits(out, zr);
		permute(p_in,z,l,r+1,out);
	}
}
void testPermute()
{

	uint64_t x = 0;
	pushbackSixBitByte(&x,0x00,0);
	pushbackSixBitByte(&x,0x01,1);
	pushbackSixBitByte(&x,0x02,2);
	pushbackSixBitByte(&x,0x03,3);
	pushbackSixBitByte(&x,0x04,4);
	pushbackSixBitByte(&x,0x05,5);
	pushbackSixBitByte(&x,0x06,6);
	pushbackSixBitByte(&x,0x07,7);

	uint8_t mres[8] = { getSixBitByte(x, 0),
						getSixBitByte(x, 1),
						getSixBitByte(x, 2),
						getSixBitByte(x, 3),
						getSixBitByte(x, 4),
						getSixBitByte(x, 5),
						getSixBitByte(x, 6),
						getSixBitByte(x, 7)};
	printarr("input_perm", mres,8);

	uint8_t p = ~pi[0];
	BitstreamIn p_in = { &p, 8,0 };
	uint8_t outbuffer[] = {0,0,0,0,0,0,0,0};
	BitstreamOut out = {outbuffer,0,0};

	permute(&p_in, x,0,4, &out);

	uint64_t permuted = bytes_to_num(outbuffer,8);
	//printf("zTilde 0x%"PRIX64"\n", zTilde);
	permuted >>= 16;

	uint8_t res[8] = { getSixBitByte(permuted, 0),
						getSixBitByte(permuted, 1),
						getSixBitByte(permuted, 2),
						getSixBitByte(permuted, 3),
						getSixBitByte(permuted, 4),
						getSixBitByte(permuted, 5),
						getSixBitByte(permuted, 6),
						getSixBitByte(permuted, 7)};
	printarr("permuted", res, 8);
}
void printbegin()
{
	if(! debug_print)
		return;

	printf("          | x| y|z0|z1|z2|z3|z4|z5|z6|z7|\n");
}

void printState(char* desc, int x,int y, uint64_t c)
{
	if(! debug_print)
		return;

	printf("%s : ", desc);
	//uint8_t x = 	(c & 0xFF00000000000000 ) >> 56;
	//uint8_t y = 	(c & 0x00FF000000000000 ) >> 48;
	printf("  %02x %02x", x,y);
	int i ;
	for(i =0 ; i < 8 ; i++)
	{
		printf(" %02x", getSixBitByte(c,i));
	}
	printf("\n");
}

/**
 * @brief
 *Definition 11. Let the function hash0 : F 82 × F 82 × (F 62 ) 8 → (F 82 ) 8 be defined as
 *	hash0(x, y, z [0] . . . z [7] ) = k [0] . . . k [7] where
 * z'[i] = (z[i] mod (63-i)) + i	i =  0...3
 * z'[i+4] = (z[i+4] mod (64-i)) + i	i =  0...3
 * ẑ = check(z');
 * @param c
 * @param k this is where the diversified key is put (should be 8 bytes)
 * @return
 */
void hash0(uint64_t c, uint8_t *k)
{
	printbegin();
	//These 64 bits are divided as c = x, y, z [0] , . . . , z [7]
	// x = 8 bits
	// y = 8 bits
	// z0-z7 6 bits each : 48 bits
	uint8_t x = 	(c & 0xFF00000000000000 ) >> 56;
	uint8_t y = 	(c & 0x00FF000000000000 ) >> 48;
	printState("origin",x,y,c);
	int n;
	uint8_t zn, zn4, _zn, _zn4;
	uint64_t zP = 0;

	for(n = 0;  n < 4 ; n++)
	{
		zn = getSixBitByte(c,n);
		zn4 = getSixBitByte(c,n+4);

		_zn = (zn % (63-n)) + n;
		_zn4 = (zn4 % (64-n)) + n;

		pushbackSixBitByte(&zP, _zn,n);
		pushbackSixBitByte(&zP, _zn4,n+4);

	}
	printState("x|y|z'",x,y,zP);

	uint64_t zCaret = check(zP);
	printState("x|y|z^",x,y,zP);


	uint8_t p = pi[x % 35];

	if(x & 1) //Check if x7 is 1
	{
		p = ~p;
	}
    printState("p|y|z^",p,y,zP);
	//if(debug_print) printf("p:%02x\n", p);

	BitstreamIn p_in = { &p, 8,0 };
	uint8_t outbuffer[] = {0,0,0,0,0,0,0,0};
	BitstreamOut out = {outbuffer,0,0};
	permute(&p_in,zCaret,0,4,&out);//returns 48 bits? or 6 8-bytes

	//Out is now a buffer containing six-bit bytes, should be 48 bits
	// if all went well
	//printf("Permute output is %d num bits (48?)\n", out.numbits);
	//Shift z-values down onto the lower segment

	uint64_t zTilde = bytes_to_num(outbuffer,8);

	//printf("zTilde 0x%"PRIX64"\n", zTilde);
	zTilde >>= 16;
	//printf("z~ 0x%"PRIX64"\n", zTilde);
	printState("p|y|z~", p,y,zTilde);

	int i;
	int zerocounter =0 ;
	for(i =0 ; i < 8  ; i++)
	{

		// the key on index i is first a bit from y
		// then six bits from z,
		// then a bit from p

		// Init with zeroes
		k[i] = 0;
		// First, place yi leftmost in k
		//k[i] |= (y  << i) & 0x80 ;

		// First, place y(7-i) leftmost in k
		k[i] |= (y  << (7-i)) & 0x80 ;

		//printf("y%d = %d\n",i,(y  << i) & 0x80);

		uint8_t zTilde_i = getSixBitByte(zTilde, i);
		//printf("zTilde_%d 0x%02x (should be <= 0x3F)\n",i, zTilde_i);
		// zTildeI is now on the form 00XXXXXX
		// with one leftshift, it'll be
		// 0XXXXXX0
		// So after leftshift, we can OR it into k
		// However, when doing complement, we need to
		// again MASK 0XXXXXX0 (0x7E)
		zTilde_i <<= 1;

		//Finally, add bit from p or p-mod
		//Shift bit i into rightmost location (mask only after complement)
		uint8_t p_i = p >> i & 0x1;

		if( k[i] )// yi = 1
		{
			//printf("k[%d] +1\n", i);
			k[i] |= ~zTilde_i & 0x7E;
			k[i] |= p_i & 1;
			k[i] += 1;

		}else // otherwise
		{
			k[i] |= zTilde_i & 0x7E;
			k[i] |= (~p_i) & 1;
		}
		if((k[i]  & 1 )== 0)
		{
			zerocounter ++;
		}
	}
	//printf("zerocounter=%d (should be 4)\n",zerocounter);
	//printf("permute fin, y:0x%02x, x: 0x%02x\n", y, x);

	//return k;
}

void reorder(uint8_t arr[8])
{
	uint8_t tmp[4] = {arr[3],arr[2],arr[1], arr[0]};
	arr[0] = arr[7];
	arr[1] = arr[6];
	arr[2] = arr[5];
	arr[3] = arr[4];
	arr[4] = tmp[0];//arr[3];
	arr[5] = tmp[1];//arr[2];
	arr[6] = tmp[2];//arr[3];
	arr[7] = tmp[3];//arr[1]
}

//extern void printarr(char * name, uint8_t* arr, int len);

bool des_getParityBitFromKey(uint8_t key)
{//The top 7 bits is used
	bool parity = ((key & 0x80) >> 7)
			^ ((key & 0x40) >> 6) ^ ((key & 0x20) >> 5)
			^ ((key & 0x10) >> 4) ^ ((key & 0x08) >> 3)
			^ ((key & 0x04) >> 2) ^ ((key & 0x02) >> 1);
	return !parity;
}
void des_checkParity(uint8_t* key)
{
	int i;
	int fails =0;
	for(i =0 ; i < 8 ; i++)
	{
		bool parity = des_getParityBitFromKey(key[i]);
		if(parity != (key[i] & 0x1))
		{
			fails++;
			printf("parity1 fail, byte %d [%02x] was %d, should be %d\n",i,key[i],(key[i] & 0x1),parity);
		}
	}
	if(fails)
	{
		printf("parity fails: %d\n", fails);
	}else
	{
		printf("Key syntax is with parity bits inside each byte\n");
	}
}

void printarr2(char * name, uint8_t* arr, int len)
{
	int i ;
	printf("%s :", name);
	for(i =0 ;  i< len ; i++)
	{
		printf("%02x",*(arr+i));
	}
	printf("\n");
}
