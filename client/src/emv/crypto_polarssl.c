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

#include "crypto_backend.h"

#include <stdlib.h>   // malloc
#include <string.h>   // memset

#include "rsa.h"
#include "sha1.h"
#include "ui.h"         // printandlog

struct crypto_hash_polarssl {
    struct crypto_hash ch;
    mbedtls_sha1_context ctx;
};

static void crypto_hash_polarssl_close(struct crypto_hash *_ch) {
    struct crypto_hash_polarssl *ch = (struct crypto_hash_polarssl *)_ch;
    free(ch);
}

static void crypto_hash_polarssl_write(struct crypto_hash *_ch, const unsigned char *buf, size_t len) {
    struct crypto_hash_polarssl *ch = (struct crypto_hash_polarssl *)_ch;
    mbedtls_sha1_update(&(ch->ctx), buf, len);
}

static unsigned char *crypto_hash_polarssl_read(struct crypto_hash *_ch) {
    struct crypto_hash_polarssl *ch = (struct crypto_hash_polarssl *)_ch;
    static unsigned char sha1sum[20];
    mbedtls_sha1_finish(&(ch->ctx), sha1sum);
    return sha1sum;
}

static size_t crypto_hash_polarssl_get_size(const struct crypto_hash *ch) {
    if (ch->algo == HASH_SHA_1)
        return 20;
    return 0;
}

static struct crypto_hash *crypto_hash_polarssl_open(enum crypto_algo_hash hash) {
    if (hash != HASH_SHA_1)
        return NULL;

    struct crypto_hash_polarssl *ch = calloc(1, sizeof(*ch));

    mbedtls_sha1_starts(&(ch->ctx));

    ch->ch.write = crypto_hash_polarssl_write;
    ch->ch.read = crypto_hash_polarssl_read;
    ch->ch.close = crypto_hash_polarssl_close;
    ch->ch.get_size = crypto_hash_polarssl_get_size;

    return &ch->ch;
}

struct crypto_pk_polarssl {
    struct crypto_pk cp;
    mbedtls_rsa_context ctx;
};

static struct crypto_pk *crypto_pk_polarssl_open_rsa(va_list vl) {
    struct crypto_pk_polarssl *cp = calloc(1, sizeof(*cp));
    memset(cp, 0x00, sizeof(*cp));

    char *mod = va_arg(vl, char *); // N
    int modlen = va_arg(vl, size_t);
    char *exp = va_arg(vl, char *); // E
    int explen = va_arg(vl, size_t);

    mbedtls_rsa_init(&cp->ctx, MBEDTLS_RSA_PKCS_V15, 0);

    cp->ctx.len = modlen; // size(N) in bytes
    mbedtls_mpi_read_binary(&cp->ctx.N, (const unsigned char *)mod, modlen);
    mbedtls_mpi_read_binary(&cp->ctx.E, (const unsigned char *)exp, explen);

    int res = mbedtls_rsa_check_pubkey(&cp->ctx);
    if (res != 0) {
        PrintAndLogEx(WARNING, "PolarSSL public key error res=%x exp=%d mod=%d", res * -1, explen, modlen);
        free(cp);
        return NULL;
    }

    return &cp->cp;
}

static struct crypto_pk *crypto_pk_polarssl_open_priv_rsa(va_list vl) {
    struct crypto_pk_polarssl *cp = calloc(1, sizeof(*cp));
    memset(cp, 0x00, sizeof(*cp));
    char *mod = va_arg(vl, char *);
    int modlen = va_arg(vl, size_t);
    char *exp = va_arg(vl, char *);
    int explen = va_arg(vl, size_t);
    char *d = va_arg(vl, char *);
    int dlen = va_arg(vl, size_t);
    char *p = va_arg(vl, char *);
    int plen = va_arg(vl, size_t);
    char *q = va_arg(vl, char *);
    int qlen = va_arg(vl, size_t);
    char *dp = va_arg(vl, char *);
    int dplen = va_arg(vl, size_t);
    char *dq = va_arg(vl, char *);
    int dqlen = va_arg(vl, size_t);
    // calc QP via Q and P
// char *inv = va_arg(vl, char *);
// int invlen = va_arg(vl, size_t);

    mbedtls_rsa_init(&cp->ctx, MBEDTLS_RSA_PKCS_V15, 0);

    cp->ctx.len = modlen; // size(N) in bytes
    mbedtls_mpi_read_binary(&cp->ctx.N, (const unsigned char *)mod, modlen);
    mbedtls_mpi_read_binary(&cp->ctx.E, (const unsigned char *)exp, explen);

    mbedtls_mpi_read_binary(&cp->ctx.D, (const unsigned char *)d, dlen);
    mbedtls_mpi_read_binary(&cp->ctx.P, (const unsigned char *)p, plen);
    mbedtls_mpi_read_binary(&cp->ctx.Q, (const unsigned char *)q, qlen);
    mbedtls_mpi_read_binary(&cp->ctx.DP, (const unsigned char *)dp, dplen);
    mbedtls_mpi_read_binary(&cp->ctx.DQ, (const unsigned char *)dq, dqlen);

    int res = mbedtls_mpi_inv_mod(&cp->ctx.QP, &cp->ctx.Q, &cp->ctx.P);
    if (res != 0) {
        PrintAndLogEx(WARNING, "PolarSSL private key error res=%x exp=%d mod=%d", res * -1, explen, modlen);
        free(cp);
        return NULL;
    }

    res = mbedtls_rsa_check_privkey(&cp->ctx);
    if (res != 0) {
        PrintAndLogEx(WARNING, "PolarSSL private key error res=%x exp=%d mod=%d", res * -1, explen, modlen);
        free(cp);
        return NULL;
    }

    return &cp->cp;
}

static int myrand(void *rng_state, unsigned char *output, size_t len) {
    size_t i;
    (void)rng_state;

    for (i = 0; i < len; ++i)
        output[i] = rand();

    return 0;
}

static struct crypto_pk *crypto_pk_polarssl_genkey_rsa(va_list vl) {
    struct crypto_pk_polarssl *cp = calloc(1, sizeof(*cp));
    memset(cp, 0x00, sizeof(*cp));

    int transient = va_arg(vl, int);
    unsigned int nbits = va_arg(vl, unsigned int);
    unsigned int exp = va_arg(vl, unsigned int);

    if (transient) {
    }

    int res = mbedtls_rsa_gen_key(&cp->ctx, &myrand, NULL, nbits, exp);
    if (res) {
        PrintAndLogEx(WARNING, "PolarSSL private key generation error res=%x exp=%u nbits=%u", res * -1, exp, nbits);
        free(cp);
        return NULL;
    }

    return &cp->cp;
}

static void crypto_pk_polarssl_close(struct crypto_pk *_cp) {
    struct crypto_pk_polarssl *cp = (struct crypto_pk_polarssl *)_cp;

    mbedtls_rsa_free(&cp->ctx);
    free(cp);
}

static unsigned char *crypto_pk_polarssl_encrypt(const struct crypto_pk *_cp, const unsigned char *buf, size_t len, size_t *clen) {
    struct crypto_pk_polarssl *cp = (struct crypto_pk_polarssl *)_cp;
    *clen = 0;
    size_t keylen = mbedtls_mpi_size(&cp->ctx.N);

    unsigned char *result = calloc(1, keylen);
    if (!result) {
        PrintAndLogEx(WARNING, "RSA encrypt failed. Can't allocate result memory");
        return NULL;
    }

    int res = mbedtls_rsa_public(&cp->ctx, buf, result);
    if (res) {
        PrintAndLogEx(WARNING, "RSA encrypt failed. Error: %x data len: %zu key len: %zu", res * -1, len, keylen);
        free(result);
        return NULL;
    }

    *clen = keylen;
    return result;
}

static unsigned char *crypto_pk_polarssl_decrypt(const struct crypto_pk *_cp, const unsigned char *buf, size_t len, size_t *clen) {
    struct crypto_pk_polarssl *cp = (struct crypto_pk_polarssl *)_cp;
    *clen = 0;
    size_t keylen = mbedtls_mpi_size(&cp->ctx.N);

    unsigned char *result = calloc(1, keylen);
    if (!result) {
        PrintAndLogEx(WARNING, "RSA encrypt failed. Can't allocate result memory");
        return NULL;
    }

    int res = mbedtls_rsa_private(&cp->ctx, NULL, NULL, buf, result); // CHECK???
    if (res) {
        PrintAndLogEx(WARNING, "RSA decrypt failed. Error: %x data len: %zu key len: %zu", res * -1, len, keylen);
        free(result);
        return NULL;
    }

    *clen = keylen;
    return result;
}

static size_t crypto_pk_polarssl_get_nbits(const struct crypto_pk *_cp) {
    struct crypto_pk_polarssl *cp = (struct crypto_pk_polarssl *)_cp;
    return cp->ctx.len * 8;
}

static unsigned char *crypto_pk_polarssl_get_parameter(const struct crypto_pk *_cp, unsigned param, size_t *plen) {
    struct crypto_pk_polarssl *cp = (struct crypto_pk_polarssl *)_cp;
    unsigned char *result = NULL;
    int res;
    switch (param) {
        // mod
        case 0:
            *plen = mbedtls_mpi_size(&cp->ctx.N);
            result = calloc(1, *plen);
            memset(result, 0x00, *plen);
            res = mbedtls_mpi_write_binary(&cp->ctx.N, result, *plen);
            if (res < 0) {
                PrintAndLogEx(WARNING, "Error write_binary");
                free(result);
                result = 0;
            }
            break;
        // exp
        case 1:
            *plen = mbedtls_mpi_size(&cp->ctx.E);
            result = calloc(1, *plen);
            memset(result, 0x00, *plen);
            res = mbedtls_mpi_write_binary(&cp->ctx.E, result, *plen);
            if (res < 0) {
                PrintAndLogEx(WARNING, "Error write_binary");
                free(result);
                result = 0;
            }
            break;
        default:
            PrintAndLogEx(WARNING, "Error get parameter. Param = %u", param);
            break;
    }
    return result;
}

static struct crypto_pk *crypto_pk_polarssl_open(enum crypto_algo_pk pk, va_list vl) {
    struct crypto_pk *cp;

    if (pk == PK_RSA)
        cp = crypto_pk_polarssl_open_rsa(vl);
    else
        return NULL;

    cp->close = crypto_pk_polarssl_close;
    cp->encrypt = crypto_pk_polarssl_encrypt;
    cp->get_parameter = crypto_pk_polarssl_get_parameter;
    cp->get_nbits = crypto_pk_polarssl_get_nbits;

    return cp;
}

static struct crypto_pk *crypto_pk_polarssl_open_priv(enum crypto_algo_pk pk, va_list vl) {
    struct crypto_pk *cp;

    if (pk == PK_RSA)
        cp = crypto_pk_polarssl_open_priv_rsa(vl);
    else
        return NULL;

    cp->close = crypto_pk_polarssl_close;
    cp->encrypt = crypto_pk_polarssl_encrypt;
    cp->decrypt = crypto_pk_polarssl_decrypt;
    cp->get_parameter = crypto_pk_polarssl_get_parameter;
    cp->get_nbits = crypto_pk_polarssl_get_nbits;

    return cp;
}

static struct crypto_pk *crypto_pk_polarssl_genkey(enum crypto_algo_pk pk, va_list vl) {
    struct crypto_pk *cp;

    if (pk == PK_RSA)
        cp = crypto_pk_polarssl_genkey_rsa(vl);
    else
        return NULL;

    cp->close = crypto_pk_polarssl_close;
    cp->encrypt = crypto_pk_polarssl_encrypt;
    cp->decrypt = crypto_pk_polarssl_decrypt;
    cp->get_parameter = crypto_pk_polarssl_get_parameter;
    cp->get_nbits = crypto_pk_polarssl_get_nbits;

    return cp;
}

static struct crypto_backend crypto_polarssl_backend = {
    .hash_open = crypto_hash_polarssl_open,
    .pk_open = crypto_pk_polarssl_open,
    .pk_open_priv = crypto_pk_polarssl_open_priv,
    .pk_genkey = crypto_pk_polarssl_genkey,
};

struct crypto_backend *crypto_polarssl_init(void) {
    return &crypto_polarssl_backend;
}
