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

#ifndef CRYPTO_BACKEND_H
#define CRYPTO_BACKEND_H

#include "crypto.h"

#include <stdarg.h>  // va_list

struct crypto_hash {
    enum crypto_algo_hash algo;
    void (*write)(struct crypto_hash *ch, const unsigned char *buf, size_t len);
    unsigned char *(*read)(struct crypto_hash *ch);
    void (*close)(struct crypto_hash *ch);
    size_t (*get_size)(const struct crypto_hash *ch);
};

struct crypto_pk {
    enum crypto_algo_pk algo;
    unsigned char *(*encrypt)(const struct crypto_pk *cp, const unsigned char *buf, size_t len, size_t *clen);
    unsigned char *(*decrypt)(const struct crypto_pk *cp, const unsigned char *buf, size_t len, size_t *clen);
    unsigned char *(*get_parameter)(const struct crypto_pk *cp, unsigned param, size_t *plen);
    size_t (*get_nbits)(const struct crypto_pk *cp);
    void (*close)(struct crypto_pk *cp);
};

struct crypto_backend {
    struct crypto_hash *(*hash_open)(enum crypto_algo_hash hash);
    struct crypto_pk *(*pk_open)(enum crypto_algo_pk pk, va_list vl);
    struct crypto_pk *(*pk_open_priv)(enum crypto_algo_pk pk, va_list vl);
    struct crypto_pk *(*pk_genkey)(enum crypto_algo_pk pk, va_list vl);
};

struct crypto_backend *crypto_polarssl_init(void);

#endif
