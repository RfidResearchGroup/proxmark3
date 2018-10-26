/*
 *  AES-CMAC from NIST Special Publication 800-38B — Recommendation for block cipher modes of operation: The CMAC mode for authentication.
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *  Copyright (C) 2014, Anargyros Plemenos
 *  Tests added Merkok, 2018
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  Reference : https://polarssl.org/discussions/generic/authentication-token
 *  NIST Special Publication 800-38B — Recommendation for block cipher modes of operation: The CMAC mode for authentication.
 *  Tests here:
 *  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
*/

#include "polarssl/aes_cmac128.h"
#include <stdio.h>

#define MIN(a,b)           ((a)<(b)?(a):(b))
#define _MSB(x)            (((x)[0] & 0x80)?1:0)

#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl_config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_AES_C)
#include "aes.h"
#endif

#if defined(POLARSSL_PLATFORM_C)
#include "polarssl/platform.h"
#else
#define polarssl_printf printf
#endif


/** 
 * zero a structure 
 */
#define ZERO_STRUCT(x)      memset((char *)&(x), 0, sizeof(x))

/** 
 * zero a structure given a pointer to the structure 
 */
#define ZERO_STRUCTP(x)     do{ if((x) != NULL) memset((char *)(x), 0, sizeof(*(x)));} while(0)


/* For CMAC Calculation */
static unsigned char const_Rb[16] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87
};
static unsigned char const_Zero[16] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static inline void aes_cmac_128_left_shift_1(const uint8_t in[16], uint8_t out[16])
{
	uint8_t overflow = 0;
	int8_t i;

	for (i = 15; i >= 0; i--) {
		out[i] = in[i] << 1;
		out[i] |= overflow;
		overflow = _MSB(&in[i]);
	 } 
}

static inline void aes_cmac_128_xor(const uint8_t in1[16], const uint8_t in2[16], 
										uint8_t out[16])
{
	uint8_t i;

	for (i = 0; i < 16; i++) {
		out[i] = in1[i] ^ in2[i];
	}
}

/*
 * AES-CMAC-128 context setup
 */
void aes_cmac128_starts(aes_cmac128_context *ctx, const uint8_t K[16])
{
	uint8_t L[16];

	/* Zero struct of aes_context */
	ZERO_STRUCTP(ctx);
	/* Initialize aes_context */
	aes_setkey_enc(&ctx->aes_key, K, 128);

	/* step 1 - generate subkeys k1 and k2 */
	aes_crypt_ecb(&ctx->aes_key, AES_ENCRYPT, const_Zero, L);

	if (_MSB(L) == 0) {
		aes_cmac_128_left_shift_1(L, ctx->K1);
	} else {
		uint8_t tmp_block[16];

		aes_cmac_128_left_shift_1(L, tmp_block);
		aes_cmac_128_xor(tmp_block, const_Rb, ctx->K1);
		ZERO_STRUCT(tmp_block);
	}

	if (_MSB(ctx->K1) == 0) {
		aes_cmac_128_left_shift_1(ctx->K1, ctx->K2);
	} else {
		uint8_t tmp_block[16];

		aes_cmac_128_left_shift_1(ctx->K1, tmp_block);
		aes_cmac_128_xor(tmp_block, const_Rb, ctx->K2);
		ZERO_STRUCT(tmp_block);
   }

	ZERO_STRUCT(L);
}

/*
 * AES-CMAC-128 process message
 */
void aes_cmac128_update(aes_cmac128_context *ctx, const uint8_t *_msg, size_t _msg_len)
{
	uint8_t tmp_block[16];
	uint8_t Y[16];
	const uint8_t *msg = _msg;
	size_t msg_len = _msg_len;

	/*
	 * copy the remembered last block
	 */
	ZERO_STRUCT(tmp_block);
	if (ctx->last_len) {
		memcpy(tmp_block, ctx->last, ctx->last_len);
	}

	/*
	 * check if we expand the block
	 */
	if (ctx->last_len < 16) {
		size_t len = MIN(16 - ctx->last_len, msg_len);

		memcpy(&tmp_block[ctx->last_len], msg, len);
		memcpy(ctx->last, tmp_block, 16);
		msg += len;
		msg_len -= len;
		ctx->last_len += len;
	}

	if (msg_len == 0) {
		/* if it is still the last block, we are done */
		ZERO_STRUCT(tmp_block);
		return;
	}

	/*
	 * It is not the last block anymore
	 */
	ZERO_STRUCT(ctx->last);
	ctx->last_len = 0;

	/*
	 * now checksum everything but the last block
	 */
	aes_cmac_128_xor(ctx->X, tmp_block, Y);
	aes_crypt_ecb(&ctx->aes_key, AES_ENCRYPT, Y, ctx->X);

	while (msg_len > 16) {
		memcpy(tmp_block, msg, 16);
		msg += 16;
		msg_len -= 16;

		aes_cmac_128_xor(ctx->X, tmp_block, Y);
		aes_crypt_ecb(&ctx->aes_key, AES_ENCRYPT, Y, ctx->X);
	}

	/*
	 * copy the last block, it will be processed in
	 * aes_cmac128_final().
	 */
	 memcpy(ctx->last, msg, msg_len);
	 ctx->last_len = msg_len;

	ZERO_STRUCT(tmp_block);
	ZERO_STRUCT(Y);
}

/*
 * AES-CMAC-128 compute T
 */
void aes_cmac128_final(aes_cmac128_context *ctx, uint8_t T[16])
{
	uint8_t tmp_block[16];
	uint8_t Y[16];

	if (ctx->last_len < 16) {
		ctx->last[ctx->last_len] = 0x80;
		aes_cmac_128_xor(ctx->last, ctx->K2, tmp_block);
	} else {
		aes_cmac_128_xor(ctx->last, ctx->K1, tmp_block);
	}

	aes_cmac_128_xor(tmp_block, ctx->X, Y);
	aes_crypt_ecb(&ctx->aes_key, AES_ENCRYPT, Y, T);

	ZERO_STRUCT(tmp_block);
	ZERO_STRUCT(Y);
	ZERO_STRUCTP(ctx);
}

/*
 * Checkup routine
 * 
 * https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
 */
int aes_cmac_self_test( int verbose )
{
	unsigned char key[16] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
	unsigned char mac[16] = {0};
	aes_cmac128_context ctx;
	int ret;

	// check Example1:
	if( verbose != 0 )
		polarssl_printf( "  AES-CMAC-128 zero length data: " );
	unsigned char ex1data[16] = {0};
	aes_cmac128_starts(&ctx, key);
	aes_cmac128_update(&ctx, ex1data, 0);
	aes_cmac128_final(&ctx, mac);
	unsigned char ex1res[16] = {0xBB, 0x1D, 0x69, 0x29, 0xE9, 0x59, 0x37, 0x28, 0x7F, 0xA3, 0x7D, 0x12, 0x9B, 0x75, 0x67, 0x46};
	if(!memcmp(mac, ex1res, 16)) {
		if( verbose != 0 )
			polarssl_printf( "passed\n" );
	} else {
		polarssl_printf( "failed\n" );
		ret = 1;
		goto exit;
	}

	// check Example2:
	if( verbose != 0 )    
		polarssl_printf( "  AES-CMAC-128 one block data  : " );
	unsigned char ex2data[16] = {0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A};
	aes_cmac128_starts(&ctx, key);
	aes_cmac128_update(&ctx, ex2data, sizeof(ex2data));
	aes_cmac128_final(&ctx, mac);
	unsigned char ex2res[16] = {0x07, 0x0A, 0x16, 0xB4, 0x6B, 0x4D, 0x41, 0x44, 0xF7, 0x9B, 0xDD, 0x9D, 0xD0, 0x4A, 0x28, 0x7C};
	if(!memcmp(mac, ex2res, 16)) {
		if( verbose != 0 )
			polarssl_printf( "passed\n" );
	} else {
		polarssl_printf( "failed\n" );
		ret = 1;
		goto exit;
	}
	
	// check Example3:
	if( verbose != 0 )
		polarssl_printf( "  AES-CMAC-128 20 bytes of data: " );
	unsigned char ex3data[20] = {0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A, 
								 0xAE, 0x2D, 0x8A, 0x57};
	aes_cmac128_starts(&ctx, key);
	aes_cmac128_update(&ctx, ex3data, sizeof(ex3data));
	aes_cmac128_final(&ctx, mac);
	unsigned char ex3res[16] = {0x7D, 0x85, 0x44, 0x9E, 0xA6, 0xEA, 0x19, 0xC8, 0x23, 0xA7, 0xBF, 0x78, 0x83, 0x7D, 0xFA, 0xDE};
	if(!memcmp(mac, ex3res, 16)) {
		if( verbose != 0 )
			polarssl_printf( "passed\n" );
	} else {
		polarssl_printf( "failed\n" );
		ret = 1;
		goto exit;
	}

	// check Example4:
	if( verbose != 0 )
		polarssl_printf( "  AES-CMAC-128 4 blocks of data: " );
	unsigned char ex4data[64] = {0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
								 0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
								 0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
								 0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10};
	aes_cmac128_starts(&ctx, key);
	aes_cmac128_update(&ctx, ex4data, sizeof(ex4data));
	aes_cmac128_final(&ctx, mac);
	unsigned char ex4res[16] = {0x51, 0xF0, 0xBE, 0xBF, 0x7E, 0x3B, 0x9D, 0x92, 0xFC, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3C, 0xFE};
	if(!memcmp(mac, ex4res, 16)) {
		if( verbose != 0 )
			polarssl_printf( "passed\n" );
	} else {
		polarssl_printf( "failed\n" );
		ret = 1;
		goto exit;
	}

	if( verbose != 0 )
		polarssl_printf( "\n" );

	ret = 0;

exit:
	return( ret );
}

