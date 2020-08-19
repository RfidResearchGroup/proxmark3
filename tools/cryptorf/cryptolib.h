/*
 * 
 * SecureMemory, CryptoMemory and CryptoRF library
 *
 * Copyright (C) 2010, Flavio D. Garcia, Peter van Rossum, Roel Verdult
 * and Ronny Wichers Schreur. Radboud University Nijmegen   
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */

#ifndef _CRYPTOLIB_H_
#define _CRYPTOLIB_H_

#include "defines.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// A nibble is actually only 4 bits, but there is no such type ;)
typedef byte_t nibble;

typedef struct {
  uint64_t l;
    uint64_t m;
    uint64_t r;
    nibble b0;
    nibble b1;
    nibble b1l;
    nibble b1r;
    nibble b1s;
}crypto_state_t;
typedef crypto_state_t* crypto_state;

void print_crypto_state(const char* text,crypto_state s);
void sm_auth(const byte_t* Gc, const byte_t* Ci, const byte_t* Q, byte_t* Ch, byte_t* Ci_1, crypto_state s);
void cm_auth(const byte_t* Gc, const byte_t* Ci, const byte_t* Q, byte_t* Ch, byte_t* Ci_1, byte_t* Ci_2, crypto_state s);
void cm_encrypt(const byte_t offset, const byte_t len, const byte_t* pt, byte_t* ct, crypto_state s);
void cm_decrypt(const byte_t offset, const byte_t len, const byte_t* ct, byte_t* pt, crypto_state s);
void cm_grind_read_system_zone(const byte_t offset, const byte_t len, const byte_t* pt, crypto_state s);
void cm_grind_set_user_zone(const byte_t zone, crypto_state s);
void cm_mac(byte_t* mac, crypto_state s);
void cm_password(const byte_t* pt, byte_t* ct, crypto_state s);

#endif // _CRYPTOLIB_H_
