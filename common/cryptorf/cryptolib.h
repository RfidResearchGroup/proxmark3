//-----------------------------------------------------------------------------
// Copyright (C) 2010, Flavio D. Garcia, Peter van Rossum, Roel Verdult
// and Ronny Wichers Schreur. Radboud University Nijmegen
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// SecureMemory, CryptoMemory and CryptoRF library
//-----------------------------------------------------------------------------

#ifndef _CRYPTOLIB_H_
#define _CRYPTOLIB_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

// A nibble is actually only 4 bits, but there is no such type ;)
typedef uint8_t nibble;

typedef struct {
    uint64_t l;
    uint64_t m;
    uint64_t r;
    nibble b0;
    nibble b1;
    nibble b1l;
    nibble b1r;
    nibble b1s;
} crypto_state_t;
typedef crypto_state_t *crypto_state;

void print_crypto_state(const char *text, crypto_state s);
void sm_auth(const uint8_t *Gc, const uint8_t *Ci, const uint8_t *Q, uint8_t *Ch, uint8_t *Ci_1, crypto_state s);
void cm_auth(const uint8_t *Gc, const uint8_t *Ci, const uint8_t *Q, uint8_t *Ch, uint8_t *Ci_1, uint8_t *Ci_2, crypto_state s);
void cm_encrypt(const uint8_t offset, const uint8_t len, const uint8_t *pt, uint8_t *ct, crypto_state s);
void cm_decrypt(const uint8_t offset, const uint8_t len, const uint8_t *ct, uint8_t *pt, crypto_state s);
void cm_grind_read_system_zone(const uint8_t offset, const uint8_t len, const uint8_t *pt, crypto_state s);
void cm_grind_set_user_zone(const uint8_t zone, crypto_state s);
void cm_mac(uint8_t *mac, crypto_state s);
void cm_password(const uint8_t *pt, uint8_t *ct, crypto_state s);

#ifdef __cplusplus
}
#endif
#endif // _CRYPTOLIB_H_
