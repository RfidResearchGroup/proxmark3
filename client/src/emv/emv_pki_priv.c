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

#include "emv_pki_priv.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

struct emv_pk *emv_pki_make_ca(const struct crypto_pk *cp,
                               const unsigned char *rid, unsigned char index,
                               unsigned int expire, enum crypto_algo_hash hash_algo) {
    size_t modlen, explen;
    unsigned char *mod, *exp;

    if (!rid)
        return NULL;

    mod = crypto_pk_get_parameter(cp, 0, &modlen);
    exp = crypto_pk_get_parameter(cp, 1, &explen);

    if (!mod || !modlen || !exp || !explen) {
        free(mod);
        free(exp);

        return NULL;
    }

    struct emv_pk *pk = emv_pk_new(modlen, explen);
    memcpy(pk->rid, rid, 5);
    pk->index = index;
    pk->expire = expire;
    pk->pk_algo = crypto_pk_get_algo(cp);
    pk->hash_algo = hash_algo;
    memcpy(pk->modulus, mod, modlen);
    memcpy(pk->exp, exp, explen);

    free(mod);
    free(exp);

    struct crypto_hash *ch = crypto_hash_open(pk->hash_algo);
    if (!ch) {
        emv_pk_free(pk);
        return NULL;
    }

    crypto_hash_write(ch, pk->rid, sizeof(pk->rid));
    crypto_hash_write(ch, &pk->index, 1);
    crypto_hash_write(ch, pk->modulus, pk->mlen);
    crypto_hash_write(ch, pk->exp, pk->elen);

    unsigned char *h = crypto_hash_read(ch);
    if (!h) {
        crypto_hash_close(ch);
        emv_pk_free(pk);

        return NULL;
    }

    memcpy(pk->hash, h, crypto_hash_get_size(ch));
    crypto_hash_close(ch);

    return pk;
}

static struct tlvdb *emv_pki_sign_message(const struct crypto_pk *cp,
                                          tlv_tag_t cert_tag, tlv_tag_t rem_tag,
                                          const unsigned char *msg, size_t msg_len,
                                          ... /* A list of tlv pointers, end with NULL */
                                         ) {
    size_t tmp_len = (crypto_pk_get_nbits(cp) + 7) / 8;
    unsigned char *tmp = calloc(1, tmp_len);
    if (!tmp) {
        return NULL;
    }

    // XXX
    struct crypto_hash *ch = crypto_hash_open(HASH_SHA_1);
    if (!ch) {
        free(tmp);
        return NULL;
    }

    tmp[0] = 0x6a;
    tmp[tmp_len - 1] = 0xbc;

    const unsigned char *rem;
    size_t rem_len;
    size_t hash_len = crypto_hash_get_size(ch);
    size_t part_len = tmp_len - 2 - hash_len;
    if (part_len < msg_len) {
        memcpy(tmp + 1, msg, part_len);
        rem = msg + part_len;
        rem_len = msg_len - part_len;
    } else {
        memcpy(tmp + 1, msg, msg_len);
        memset(tmp + 1 + msg_len, 0xbb, part_len - msg_len);
        rem = NULL;
        rem_len = 0;
    }
    crypto_hash_write(ch, tmp + 1, part_len);
    crypto_hash_write(ch, rem, rem_len);

    va_list vl;
    va_start(vl, msg_len);
    while (true) {
        const struct tlv *add_tlv = va_arg(vl, const struct tlv *);
        if (!add_tlv)
            break;

        crypto_hash_write(ch, add_tlv->value, add_tlv->len);
    }
    va_end(vl);

    unsigned char *h = crypto_hash_read(ch);
    if (!h) {
        crypto_hash_close(ch);
        free(tmp);

        return NULL;
    }

    memcpy(tmp + 1 + part_len, h, hash_len);
    crypto_hash_close(ch);

    size_t cert_len;
    unsigned char *cert = crypto_pk_decrypt(cp, tmp, tmp_len, &cert_len);
    free(tmp);

    if (!cert)
        return NULL;

    struct tlvdb *db = tlvdb_fixed(cert_tag, cert_len, cert);
    free(cert);
    if (!db)
        return NULL;

    if (rem) {
        struct tlvdb *rdb = tlvdb_fixed(rem_tag, rem_len, rem);
        if (!rdb) {
            tlvdb_free(db);

            return NULL;
        }
        tlvdb_add(db, rdb);
    }

    return db;
}

static struct tlvdb *emv_pki_sign_key(const struct crypto_pk *cp,
                                      struct emv_pk *ipk,
                                      unsigned char msgtype,
                                      size_t pan_len,
                                      tlv_tag_t cert_tag,
                                      tlv_tag_t exp_tag,
                                      tlv_tag_t rem_tag,
                                      const struct tlv *add_tlv
                                     ) {
    unsigned pos = 0;
    unsigned char *msg = calloc(1, 1 + pan_len + 2 + 3 + 1 + 1 + 1 + 1 + ipk->mlen);

    if (!msg)
        return NULL;

    msg[pos++] = msgtype;
    memcpy(msg + pos, ipk->pan, pan_len);
    pos += pan_len;
    msg[pos++] = (ipk->expire >> 8) & 0xff;
    msg[pos++] = (ipk->expire >> 16) & 0xff;
    memcpy(msg + pos, ipk->serial, 3);
    pos += 3;
    msg[pos++] = ipk->hash_algo;
    msg[pos++] = ipk->pk_algo;
    msg[pos++] = ipk->mlen;
    msg[pos++] = ipk->elen;
    memcpy(msg + pos, ipk->modulus, ipk->mlen);
    pos += ipk->mlen;

    struct tlvdb *exp_db = tlvdb_fixed(exp_tag, ipk->elen, ipk->exp);
    if (!exp_db) {
        free(msg);
        return NULL;
    }

    struct tlvdb *db = emv_pki_sign_message(cp,
                                            cert_tag, rem_tag,
                                            msg, pos,
                                            tlvdb_get(exp_db, exp_tag, NULL),
                                            add_tlv,
                                            (uint8_t *)NULL);
    free(msg);
    if (!db) {
        free(exp_db);
        return NULL;
    }

    tlvdb_add(db, exp_db);

    return db;
}

struct tlvdb *emv_pki_sign_issuer_cert(const struct crypto_pk *cp, struct emv_pk *issuer_pk) {
    return emv_pki_sign_key(cp, issuer_pk, 2, 4, 0x90, 0x9f32, 0x92, NULL);
}

struct tlvdb *emv_pki_sign_icc_cert(const struct crypto_pk *cp, struct emv_pk *icc_pk, const struct tlv *sda_tlv) {
    return emv_pki_sign_key(cp, icc_pk, 4, 10, 0x9f46, 0x9f47, 0x9f48, sda_tlv);
}

struct tlvdb *emv_pki_sign_icc_pe_cert(const struct crypto_pk *cp, struct emv_pk *icc_pe_pk) {
    return emv_pki_sign_key(cp, icc_pe_pk, 4, 10, 0x9f2d, 0x9f2e, 0x9f2f, NULL);
}

struct tlvdb *emv_pki_sign_dac(const struct crypto_pk *cp, const struct tlv *dac_tlv, const struct tlv *sda_tlv) {
    unsigned pos = 0;
    unsigned char *msg = calloc(1, 1 + 1 + dac_tlv->len);

    if (!msg)
        return NULL;

    msg[pos++] = 3;
    msg[pos++] = HASH_SHA_1;
    memcpy(msg + pos, dac_tlv->value, dac_tlv->len);
    pos += dac_tlv->len;

    struct tlvdb *db = emv_pki_sign_message(cp,
                                            0x93, 0,
                                            msg, pos,
                                            sda_tlv,
                                            (uint8_t *)NULL);

    free(msg);

    return db;
}

struct tlvdb *emv_pki_sign_idn(const struct crypto_pk *cp, const struct tlv *idn_tlv, const struct tlv *dyn_tlv) {
    unsigned pos = 0;
    unsigned char *msg = calloc(1, 1 + 1 + 1 + 1 + idn_tlv->len);

    if (!msg)
        return NULL;

    msg[pos++] = 5;
    msg[pos++] = HASH_SHA_1;
    msg[pos++] = idn_tlv->len + 1;
    msg[pos++] = idn_tlv->len;
    memcpy(msg + pos, idn_tlv->value, idn_tlv->len);
    pos += idn_tlv->len;

    struct tlvdb *db = emv_pki_sign_message(cp,
                                            0x9f4b, 0,
                                            msg, pos,
                                            dyn_tlv,
                                            (uint8_t *)NULL);

    free(msg);

    return db;
}
