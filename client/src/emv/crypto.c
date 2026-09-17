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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "crypto.h"
#include "crypto_backend.h"

static struct crypto_backend *crypto_backend;

static bool crypto_init(void) {
    if (crypto_backend)
        return true;

    crypto_backend = crypto_polarssl_init();

    if (!crypto_backend)
        return false;

    return true;
}

struct crypto_hash *crypto_hash_open(enum crypto_algo_hash hash) {
    struct crypto_hash *ch;

    if (!crypto_init())
        return NULL;

    ch = crypto_backend->hash_open(hash);
    if (ch)
        ch->algo = hash;

    return ch;
}

void crypto_hash_close(struct crypto_hash *ch) {
    ch->close(ch);
}

void crypto_hash_write(struct crypto_hash *ch, const unsigned char *buf, size_t len) {
    ch->write(ch, buf, len);
}

unsigned char *crypto_hash_read(struct crypto_hash *ch) {
    return ch->read(ch);
}

size_t crypto_hash_get_size(const struct crypto_hash *ch) {
    return ch->get_size(ch);
}

struct crypto_pk *crypto_pk_open(enum crypto_algo_pk pk, ...) {
    struct crypto_pk *cp;
    va_list vl;

    if (!crypto_init())
        return NULL;

    va_start(vl, pk);
    cp = crypto_backend->pk_open(pk, vl);
    va_end(vl);

    if (cp)
        cp->algo = pk;

    return cp;
}

struct crypto_pk *crypto_pk_open_priv(enum crypto_algo_pk pk, ...) {
    struct crypto_pk *cp;
    va_list vl;

    if (!crypto_init())
        return NULL;

    if (!crypto_backend->pk_open_priv)
        return NULL;

    va_start(vl, pk);
    cp = crypto_backend->pk_open_priv(pk, vl);
    va_end(vl);

    if (cp)
        cp->algo = pk;

    return cp;
}

struct crypto_pk *crypto_pk_genkey(enum crypto_algo_pk pk, ...) {
    struct crypto_pk *cp;
    va_list vl;

    if (!crypto_init())
        return NULL;

    if (!crypto_backend->pk_genkey)
        return NULL;

    va_start(vl, pk);
    cp = crypto_backend->pk_genkey(pk, vl);
    va_end(vl);

    if (cp)
        cp->algo = pk;

    return cp;
}

void crypto_pk_close(struct crypto_pk *cp) {
    cp->close(cp);
}

unsigned char *crypto_pk_encrypt(const struct crypto_pk *cp, const unsigned char *buf, size_t len, size_t *clen) {
    return cp->encrypt(cp, buf, len, clen);
}

unsigned char *crypto_pk_decrypt(const struct crypto_pk *cp, const unsigned char *buf, size_t len, size_t *clen) {
    if (!cp->decrypt) {
        *clen = 0;

        return NULL;
    }

    return cp->decrypt(cp, buf, len, clen);
}

enum crypto_algo_pk crypto_pk_get_algo(const struct crypto_pk *cp) {
    if (!cp)
        return PK_INVALID;

    return cp->algo;
}

size_t crypto_pk_get_nbits(const struct crypto_pk *cp) {
    if (!cp->get_nbits)
        return 0;

    return cp->get_nbits(cp);
}

unsigned char *crypto_pk_get_parameter(const struct crypto_pk *cp, unsigned param, size_t *plen) {
    *plen = 0;

    if (!cp->get_parameter)
        return NULL;

    return cp->get_parameter(cp, param, plen);
}
