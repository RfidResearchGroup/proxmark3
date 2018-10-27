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
#include <stddef.h>

extern int aes_encode(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *output, int length);
extern int aes_decode(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *output, int length);
extern int aes_cmac(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *mac, int length);
extern int aes_cmac8(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *mac, int length);

#endif /* libpcrypto.h */
