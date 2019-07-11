/* des.h */
/*
    This file is part of the ARM-Crypto-Lib.
    Copyright (C) 2008  Daniel Otte (daniel.otte@rub.de)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
/**
 * \file    des.h
 * \author  Daniel Otte
 * \date    2007-06-16
 * \brief   des and tdes declarations
 * \license GPLv3 or later
 *
 */
#ifndef __DES_H_
#define __DES_H_

#include <stdint.h>
#include <string.h>

/* the FIPS 46-3 (1999-10-25) name for triple DES is triple data encryption algorithm so TDEA.
 * Also we only implement the three key mode  */

/** \def tdea_enc
 * \brief defining an alias for void tdes_enc(void* out, const void* in, const void* key)
 */

/** \def tdea_dec
 * \brief defining an alias for void tdes_dec(void* out, const void* in, const void* key)
 */

#define tdea_enc tdes_enc
#define tdea_dec tdes_dec

/** \fn void des_enc(void* out, const void* in, const void* key)
 * \brief encrypt a block with DES
 *
 * This function encrypts a block of 64 bits (8 bytes) with the DES algorithm.
 * Key expansion is done automatically. The key is 64 bits long, but note that
 * only 56 bits are used (the LSB of each byte is dropped). The input and output
 * blocks may overlap.
 *
 * \param out pointer to the block (64 bit = 8 byte) where the ciphertext is written to
 * \param in  pointer to the block (64 bit = 8 byte) where the plaintext is read from
 * \param key pointer to the key (64 bit = 8 byte)
 */
void des_enc(void *out, const void *in, const void *key);

/** \fn void des_dec(void* out, const void* in, const void* key)
 * \brief decrypt a block with DES
 *
 * This function decrypts a block of 64 bits (8 bytes) with the DES algorithm.
 * Key expansion is done automatically. The key is 64 bits long, but note that
 * only 56 bits are used (the LSB of each byte is dropped). The input and output
 * blocks may overlap.
 *
 * \param out pointer to the block (64 bit = 8 byte) where the plaintext is written to
 * \param in  pointer to the block (64 bit = 8 byte) where the ciphertext is read from
 * \param key pointer to the key (64 bit = 8 byte)
 */
//void des_dec(void* out, const void* in, const void* key);
void des_dec(void *out, const void *in, const uint8_t *key);

/** \fn void tdes_enc(void* out, const void* in, const void* key)
 * \brief encrypt a block with Tripple-DES
 *
 * This function encrypts a block of 64 bits (8 bytes) with the Tripple-DES (EDE)
 * algorithm. Key expansion is done automatically. The key is 192 bits long, but
 * note that only 178 bits are used (the LSB of each byte is dropped). The input
 * and output blocks may overlap.
 *
 * \param out pointer to the block (64 bit = 8 byte) where the ciphertext is written to
 * \param in  pointer to the block (64 bit = 8 byte) where the plaintext is read from
 * \param key pointer to the key (192 bit = 24 byte)
 */
//void tdes_enc(void* out, const void* in, const void* key);
void tdes_enc(void *out, void *in, const void *key);

/** \fn void tdes_dec(void* out, const void* in, const void* key)
 * \brief decrypt a block with Tripple-DES
 *
 * This function decrypts a block of 64 bits (8 bytes) with the Tripple-DES (EDE)
 * algorithm. Key expansion is done automatically. The key is 192 bits long, but
 * note that only 178 bits are used (the LSB of each byte is dropped). The input
 * and output blocks may overlap.
 *
 * \param out pointer to the block (64 bit = 8 byte) where the plaintext is written to
 * \param in  pointer to the block (64 bit = 8 byte) where the ciphertext is read from
 * \param key pointer to the key (192 bit = 24 byte)
 */
//void tdes_dec(void* out, const void* in, const void* key);
void tdes_dec(void *out, void *in, const uint8_t *key);

void tdes_2key_enc(void *out, const void *in, size_t length, const void *key, unsigned char iv[8]);
void tdes_2key_dec(void *out, const void *in, size_t length, const void *key, unsigned char iv[8]);

// Copied from des.h in desfire imp.
typedef unsigned long DES_KS[16][2];   /* Single-key DES key schedule */
typedef unsigned long DES3_KS[48][2];  /* Triple-DES key schedule */

extern int Asmversion; /* 1 if we're linked with an asm version, 0 if C */

#endif /*DES_H_*/
