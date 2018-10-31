//-----------------------------------------------------------------------------
// Copyright (C) 2018 Merlok
// Copyright (C) 2018 drHatson
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// crypto commands
//-----------------------------------------------------------------------------

#include "polarssl/libpcrypto.h"
#include <polarssl/aes.h>
#include <polarssl/aes_cmac128.h>

// NIST Special Publication 800-38A — Recommendation for block cipher modes of operation: methods and techniques, 2001.
int aes_encode(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *output, int length){
	uint8_t iiv[16] = {0};
	if (iv)
		memcpy(iiv, iv, 16);
	
	aes_context aes;
	aes_init(&aes);
	if (aes_setkey_enc(&aes, key, 128))
		return 1;
	if (aes_crypt_cbc(&aes, AES_ENCRYPT, length, iiv, input, output))
		return 2;
	aes_free(&aes);

	return 0;
}

int aes_decode(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *output, int length){
	uint8_t iiv[16] = {0};
	if (iv)
		memcpy(iiv, iv, 16);
	
	aes_context aes;
	aes_init(&aes);
	if (aes_setkey_dec(&aes, key, 128))
		return 1;
	if (aes_crypt_cbc(&aes, AES_DECRYPT, length, iiv, input, output))
		return 2;
	aes_free(&aes);

	return 0;
}

//  NIST Special Publication 800-38B — Recommendation for block cipher modes of operation: The CMAC mode for authentication.
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
int aes_cmac(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *mac, int length) {
	memset(mac, 0x00, 16);
	uint8_t iiv[16] = {0};
	if (iv)
		memcpy(iiv, iv, 16);
	
	//  NIST 800-38B 
	aes_cmac128_context ctx;
	aes_cmac128_starts(&ctx, key);
	aes_cmac128_update(&ctx, input, length);
	aes_cmac128_final(&ctx, mac);

	return 0;
}

int aes_cmac8(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *mac, int length) {
	uint8_t cmac[16] = {0};
	memset(mac, 0x00, 8);
	
	int res = aes_cmac(iv, key, input, cmac, length);
	if (res)
		return res;
	
	for(int i = 0; i < 8; i++) 
		mac[i] = cmac[i * 2 + 1];

	return 0;
}
