//-----------------------------------------------------------------------------
// Borrowed initially from https://github.com/lumag/emv-tools/
// Copyright (C) 2012, 2015 Dmitry Eremin-Solenikov
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
// libopenemv - a library to work with EMV family of smart cards
//-----------------------------------------------------------------------------

#ifndef CRYPTO_H
#define CRYPTO_H

#include "common.h"

enum crypto_algo_hash {
    HASH_INVALID,
    HASH_SHA_1,
};

struct crypto_hash *crypto_hash_open(enum crypto_algo_hash hash);
void crypto_hash_close(struct crypto_hash *ch);
void crypto_hash_write(struct crypto_hash *ch, const unsigned char *buf, size_t len);
unsigned char *crypto_hash_read(struct crypto_hash *ch);
size_t crypto_hash_get_size(const struct crypto_hash *ch);

enum crypto_algo_pk {
    PK_INVALID,
    PK_RSA,
};

struct crypto_pk *crypto_pk_open(enum crypto_algo_pk pk, ...);
struct crypto_pk *crypto_pk_open_priv(enum crypto_algo_pk pk, ...);
struct crypto_pk *crypto_pk_genkey(enum crypto_algo_pk pk, ...);
void crypto_pk_close(struct crypto_pk *cp);
unsigned char *crypto_pk_encrypt(const struct crypto_pk *cp, const unsigned char *buf, size_t len, size_t *clen);
unsigned char *crypto_pk_decrypt(const struct crypto_pk *cp, const unsigned char *buf, size_t len, size_t *clen);
enum crypto_algo_pk crypto_pk_get_algo(const struct crypto_pk *cp);
size_t crypto_pk_get_nbits(const struct crypto_pk *cp);
unsigned char *crypto_pk_get_parameter(const struct crypto_pk *cp, unsigned param, size_t *plen);

#endif
