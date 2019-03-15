//-----------------------------------------------------------------------------
// Copyright (C) 2018 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// crypto commands
//-----------------------------------------------------------------------------

#ifndef LIBPCRYPTO_H
#define LIBPCRYPTO_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <mbedtls/pk.h>

extern int aes_encode(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *output, int length);
extern int aes_decode(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *output, int length);
extern int aes_cmac(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *mac, int length);
extern int aes_cmac8(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *mac, int length);

extern int sha256hash(uint8_t *input, int length, uint8_t *hash);
extern int sha512hash(uint8_t *input, int length, uint8_t *hash);

extern int ecdsa_key_create(uint8_t *key_d, uint8_t *key_xy);
extern int ecdsa_public_key_from_pk(mbedtls_pk_context *pk, uint8_t *key, size_t keylen);
extern int ecdsa_signature_create(uint8_t *key_d, uint8_t *key_xy, uint8_t *input, int length, uint8_t *signature, size_t *signaturelen);
extern int ecdsa_signature_verify(uint8_t *key_xy, uint8_t *input, int length, uint8_t *signature, size_t signaturelen);
extern char *ecdsa_get_error(int ret);

extern int ecdsa_nist_test(bool verbose);

#endif /* libpcrypto.h */
