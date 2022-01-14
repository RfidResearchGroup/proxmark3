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

#include "emv_pki.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "crypto.h"
#include "util.h"
#include "ui.h"

static bool strictExecution = true;
void PKISetStrictExecution(bool se) {
    strictExecution = se;
}

static const unsigned char empty_tlv_value[] = {};
static const struct tlv empty_tlv = {.tag = 0x0, .len = 0, .value = empty_tlv_value};

static size_t emv_pki_hash_psn[256] = { 0, 0, 11, 2, 17, 2, };

static unsigned char *emv_pki_decode_message(const struct emv_pk *enc_pk,
                                             uint8_t msgtype,
                                             size_t *len,
                                             const struct tlv *cert_tlv,
                                             int tlv_count,
                                             ... /* A list of tlv pointers */
                                            ) {
    struct crypto_pk *kcp;
    unsigned char *data;
    size_t data_len;
    va_list vl;

    if (!enc_pk)
        return NULL;

    if (!cert_tlv) {
        PrintAndLogEx(WARNING, "ERROR: Can't find certificate");
        return NULL;
    }

    if (cert_tlv->len != enc_pk->mlen) {
        PrintAndLogEx(WARNING, "ERROR: Certificate length (%zu) not equal key length (%zu)", cert_tlv->len, enc_pk->mlen);
        return NULL;
    }
    kcp = crypto_pk_open(enc_pk->pk_algo,
                         enc_pk->modulus, enc_pk->mlen,
                         enc_pk->exp, enc_pk->elen);
    if (!kcp)
        return NULL;

    data = crypto_pk_encrypt(kcp, cert_tlv->value, cert_tlv->len, &data_len);
    crypto_pk_close(kcp);

    /*  if (true){
            PrintAndLogEx(SUCCESS, "Recovered data:\n");
            print_buffer(data, data_len, 1);
        }*/

    if (data[data_len - 1] != 0xbc || data[0] != 0x6a || data[1] != msgtype) {
        PrintAndLogEx(WARNING, "ERROR: Certificate format");
        free(data);
        return NULL;
    }

    size_t hash_pos = emv_pki_hash_psn[msgtype];
    if (hash_pos == 0 || hash_pos > data_len) {
        PrintAndLogEx(WARNING, "ERROR: Cant get hash position in the certificate");
        free(data);
        return NULL;
    }

    struct crypto_hash *ch;
    ch = crypto_hash_open(data[hash_pos]);
    if (!ch) {
        PrintAndLogEx(WARNING, "ERROR: Cant do hash");
        free(data);
        return NULL;
    }

    size_t hash_len = crypto_hash_get_size(ch);
    crypto_hash_write(ch, data + 1, data_len - 2 - hash_len);

    va_start(vl, tlv_count);
    for (int i = 0; i < tlv_count; i++) {
        const struct tlv *add_tlv = va_arg(vl, const struct tlv *);
        if (!add_tlv)
            continue;

        crypto_hash_write(ch, add_tlv->value, add_tlv->len);
    }
    va_end(vl);

    uint8_t hash[hash_len];
    memset(hash, 0, hash_len);
    memcpy(hash, crypto_hash_read(ch), hash_len);
    if (memcmp(data + data_len - 1 - hash_len, hash, hash_len)) {
        PrintAndLogEx(WARNING, "ERROR: Calculated wrong hash");
        PrintAndLogEx(WARNING, "decoded:    " _YELLOW_("%s"), sprint_hex(data + data_len - 1 - hash_len, hash_len));
        PrintAndLogEx(WARNING, "calculated: " _YELLOW_("%s"), sprint_hex(hash, hash_len));

        if (strictExecution) {
            crypto_hash_close(ch);
            free(data);
            return NULL;
        }
    }

    crypto_hash_close(ch);
    *len = data_len - hash_len - 1;
    return data;
}

static unsigned emv_cn_length(const struct tlv *tlv) {
    for (int i = 0; i < tlv->len; i++) {
        unsigned char c = tlv->value[i];

        if (c >> 4 == 0xf)
            return 2 * i;

        if ((c & 0xf) == 0xf)
            return 2 * i + 1;
    }
    return 2 * tlv->len;
}

static unsigned char emv_cn_get(const struct tlv *tlv, unsigned pos) {
    if (pos > tlv->len * 2)
        return 0xf;

    unsigned char c = tlv->value[pos / 2];

    if (pos % 2)
        return c & 0xf;
    else
        return c >> 4;
}

static struct emv_pk *emv_pki_decode_key_ex(const struct emv_pk *enc_pk,
                                            unsigned char msgtype,
                                            const struct tlv *pan_tlv,
                                            const struct tlv *cert_tlv,
                                            const struct tlv *exp_tlv,
                                            const struct tlv *rem_tlv,
                                            const struct tlv *add_tlv,
                                            const struct tlv *sdatl_tlv,
                                            bool showData
                                           ) {
    size_t pan_length;
    unsigned char *data;
    size_t data_len;
    size_t pk_len;

    if (!cert_tlv || !exp_tlv || !pan_tlv)
        return NULL;

    if (!rem_tlv)
        rem_tlv = &empty_tlv;

    if (msgtype == 2)
        pan_length = 4;
    else if (msgtype == 4)
        pan_length = 10;
    else {
        PrintAndLogEx(WARNING, "ERROR: Message type must be 2 or 4");
        return NULL;
    }

    data = emv_pki_decode_message(enc_pk, msgtype, &data_len,
                                  cert_tlv,
                                  5,
                                  rem_tlv,
                                  exp_tlv,
                                  add_tlv,
                                  sdatl_tlv,
                                  (uint8_t *)NULL);
    if (!data || data_len < 11 + pan_length) {
        PrintAndLogEx(WARNING, "ERROR: Can't decode message");
        return NULL;
    }

    if (showData) {
        PrintAndLogEx(SUCCESS, "Recovered data:");
        print_buffer(data, data_len, 1);
    }

    /* Perform the rest of checks here */

    struct tlv pan2_tlv = {
        .tag = 0x5a,
        .len = pan_length,
        .value = &data[2],
    };
    unsigned pan_len = emv_cn_length(pan_tlv);
    unsigned pan2_len = emv_cn_length(&pan2_tlv);

    if (((msgtype == 2) && (pan2_len < 4 || pan2_len > pan_len)) ||
            ((msgtype == 4) && (pan2_len != pan_len))) {
        PrintAndLogEx(WARNING, "ERROR: Invalid PAN lengths");
        free(data);

        return NULL;
    }

    unsigned i;
    for (i = 0; i < pan2_len; i++)
        if (emv_cn_get(pan_tlv, i) != emv_cn_get(&pan2_tlv, i)) {
            PrintAndLogEx(WARNING, "ERROR: PAN data mismatch");
            PrintAndLogEx(WARNING, "tlv  pan " _YELLOW_("%s"), sprint_hex(pan_tlv->value, pan_tlv->len));
            PrintAndLogEx(WARNING, "cert pan " _YELLOW_("%s"), sprint_hex(pan2_tlv.value, pan2_tlv.len));
            free(data);

            return NULL;
        }

    pk_len = data[9 + pan_length];
    if (pk_len > data_len - 11 - pan_length + rem_tlv->len) {
        PrintAndLogEx(WARNING, "ERROR: Invalid pk length");
        free(data);
        return NULL;
    }

    if (exp_tlv->len != data[10 + pan_length]) {
        free(data);
        return NULL;
    }

    struct emv_pk *pk = emv_pk_new(pk_len, exp_tlv->len);

    memcpy(pk->rid, enc_pk->rid, 5);
    pk->index = enc_pk->index;

    pk->hash_algo = data[7 + pan_length];
    pk->pk_algo = data[8 + pan_length];
    pk->expire = (data[3 + pan_length] << 16) | (data[2 + pan_length] << 8) | 0x31;
    memcpy(pk->serial, data + 4 + pan_length, 3);
    memcpy(pk->pan, data + 2, pan_length);
    memset(pk->pan + pan_length, 0xff, 10 - pan_length);

    memcpy(pk->modulus, data + 11 + pan_length,
           pk_len < data_len - (11 + pan_length) ?
           pk_len :
           data_len - (11 + pan_length));
    memcpy(pk->modulus + data_len - (11 + pan_length), rem_tlv->value, rem_tlv->len);
    memcpy(pk->exp, exp_tlv->value, exp_tlv->len);

    free(data);
    return pk;
}

static struct emv_pk *emv_pki_decode_key(const struct emv_pk *enc_pk,
                                         unsigned char msgtype,
                                         const struct tlv *pan_tlv,
                                         const struct tlv *cert_tlv,
                                         const struct tlv *exp_tlv,
                                         const struct tlv *rem_tlv,
                                         const struct tlv *add_tlv,
                                         const struct tlv *sdatl_tlv
                                        ) {
    return emv_pki_decode_key_ex(enc_pk, msgtype, pan_tlv, cert_tlv, exp_tlv, rem_tlv, add_tlv, sdatl_tlv, false);
}

struct emv_pk *emv_pki_recover_issuer_cert(const struct emv_pk *pk, struct tlvdb *db) {
    return emv_pki_decode_key(pk, 2,
                              tlvdb_get(db, 0x5a, NULL),
                              tlvdb_get(db, 0x90, NULL),
                              tlvdb_get(db, 0x9f32, NULL),
                              tlvdb_get(db, 0x92, NULL),
                              NULL,
                              NULL);
}

struct emv_pk *emv_pki_recover_icc_cert(const struct emv_pk *pk, struct tlvdb *db, const struct tlv *sda_tlv) {
    size_t sdatl_len;
    unsigned char *sdatl = emv_pki_sdatl_fill(db, &sdatl_len);
    struct tlv sda_tdata = {
        .tag = 0x00,        // dummy tag
        .len = sdatl_len,
        .value = sdatl
    };

    struct emv_pk *res = emv_pki_decode_key(pk, 4,
                                            tlvdb_get(db, 0x5a, NULL),
                                            tlvdb_get(db, 0x9f46, NULL),
                                            tlvdb_get(db, 0x9f47, NULL),
                                            tlvdb_get(db, 0x9f48, NULL),
                                            sda_tlv,
                                            &sda_tdata);

    free(sdatl); // calloc here: emv_pki_sdatl_fill
    return res;
}

struct emv_pk *emv_pki_recover_icc_pe_cert(const struct emv_pk *pk, struct tlvdb *db) {
    return emv_pki_decode_key(pk, 4,
                              tlvdb_get(db, 0x5a, NULL),
                              tlvdb_get(db, 0x9f2d, NULL),
                              tlvdb_get(db, 0x9f2e, NULL),
                              tlvdb_get(db, 0x9f2f, NULL),
                              NULL,
                              NULL);
}

unsigned char *emv_pki_sdatl_fill(const struct tlvdb *db, size_t *sdatl_len) {
    uint8_t buf[2048] = {0};
    size_t len = 0;

    *sdatl_len = 0;

    const struct tlv *sda_tl = tlvdb_get(db, 0x9f4a, NULL);
    if (!sda_tl || sda_tl->len == 0)
        return NULL;

    for (int i = 0; i < sda_tl->len; i++) {
        uint32_t tag = sda_tl->value[i]; // here may be multibyte, but now not
        const struct tlv *elm = tlvdb_get(db, tag, NULL);
        if (elm) {
            memcpy(&buf[len], elm->value, elm->len);
            len += elm->len;
        }
    }

    if (len) {
        *sdatl_len = len;
        unsigned char *value = calloc(1, len);
        memcpy(value, buf, len);
        return value;
    }

    return NULL;
}

struct tlvdb *emv_pki_recover_dac_ex(const struct emv_pk *enc_pk, const struct tlvdb *db, const struct tlv *sda_tlv, bool showData) {
    size_t data_len = 0;

    // Static Data Authentication Tag List
    size_t sdatl_len;
    unsigned char *sdatl = emv_pki_sdatl_fill(db, &sdatl_len);
    struct tlv sda_tdata = {
        .tag = 0x00,        // dummy tag
        .len = sdatl_len,
        .value = sdatl
    };

    unsigned char *data = emv_pki_decode_message(enc_pk, 3, &data_len,
                                                 tlvdb_get(db, 0x93, NULL),
                                                 3,
                                                 sda_tlv,
                                                 &sda_tdata,
                                                 (uint8_t *)NULL);

    free(sdatl); // calloc here: emv_pki_sdatl_fill

    if (!data || data_len < 5)
        return NULL;

    if (showData) {
        PrintAndLogEx(SUCCESS, "Recovered data:");
        print_buffer(data, data_len, 1);
    }

    struct tlvdb *dac_db = tlvdb_fixed(0x9f45, 2, data + 3);
    free(data);
    return dac_db;
}

struct tlvdb *emv_pki_recover_dac(const struct emv_pk *enc_pk, const struct tlvdb *db, const struct tlv *sda_tlv) {
    return emv_pki_recover_dac_ex(enc_pk, db, sda_tlv, false);
}

struct tlvdb *emv_pki_recover_idn(const struct emv_pk *enc_pk, const struct tlvdb *db, const struct tlv *dyn_tlv) {
    return emv_pki_recover_idn_ex(enc_pk, db, dyn_tlv, false);
}

struct tlvdb *emv_pki_recover_idn_ex(const struct emv_pk *enc_pk, const struct tlvdb *db, const struct tlv *dyn_tlv, bool showData) {
    size_t data_len;
    unsigned char *data = emv_pki_decode_message(enc_pk, 5, &data_len,
                                                 tlvdb_get(db, 0x9f4b, NULL),
                                                 2,
                                                 dyn_tlv,
                                                 (uint8_t *)NULL);

    if (!data || data_len < 3)
        return NULL;

    if (data[3] < 2 || data[3] > data_len - 3) {
        free(data);
        return NULL;
    }

    if (showData) {
        PrintAndLogEx(SUCCESS, "Recovered data:");
        print_buffer(data, data_len, 1);
    }

    size_t idn_len = data[4];
    if (idn_len > data[3] - 1) {
        free(data);
        return NULL;
    }

    // 9f4c ICC Dynamic Number
    struct tlvdb *idn_db = tlvdb_fixed(0x9f4c, idn_len, data + 5);
    free(data);
    return idn_db;
}

struct tlvdb *emv_pki_recover_atc_ex(const struct emv_pk *enc_pk, const struct tlvdb *db, bool showData) {
    size_t data_len;
    unsigned char *data = emv_pki_decode_message(enc_pk, 5, &data_len,
                                                 tlvdb_get(db, 0x9f4b, NULL),
                                                 5,
                                                 tlvdb_get(db, 0x9f37, NULL),
                                                 tlvdb_get(db, 0x9f02, NULL),
                                                 tlvdb_get(db, 0x5f2a, NULL),
                                                 tlvdb_get(db, 0x9f69, NULL),
                                                 (uint8_t *)NULL);

    if (!data || data_len < 3)
        return NULL;

    if (data[3] < 2 || data[3] > data_len - 3) {
        free(data);
        return NULL;
    }

    if (showData) {
        PrintAndLogEx(SUCCESS, "Recovered data:");
        print_buffer(data, data_len, 1);
    }

    size_t idn_len = data[4];
    if (idn_len > data[3] - 1) {
        free(data);
        return NULL;
    }

    // 9f36 Application Transaction Counter (ATC)
    struct tlvdb *atc_db = tlvdb_fixed(0x9f36, idn_len, data + 5);

    free(data);

    return atc_db;
}

static void tlv_hash(void *data, const struct tlv *tlv, int level, bool is_leaf) {
    struct crypto_hash *ch = data;
    size_t tag_len;
    unsigned char *tag;

    if (tlv_is_constructed(tlv))
        return;

    if (tlv->tag == 0x9f4b)
        return;

    tag = tlv_encode(tlv, &tag_len);
    crypto_hash_write(ch, tag, tag_len);
    free(tag);
}

struct tlvdb *emv_pki_perform_cda(const struct emv_pk *enc_pk, const struct tlvdb *db,
                                  const struct tlvdb *this_db,
                                  const struct tlv *pdol_data_tlv,
                                  const struct tlv *crm1_tlv,
                                  const struct tlv *crm2_tlv) {
    return emv_pki_perform_cda_ex(enc_pk, db, this_db, pdol_data_tlv, crm1_tlv, crm2_tlv, false);
}

struct tlvdb *emv_pki_perform_cda_ex(const struct emv_pk *enc_pk, const struct tlvdb *db,
                                     const struct tlvdb *this_db,     // AC TLV result
                                     const struct tlv *pdol_data_tlv, // PDOL
                                     const struct tlv *crm1_tlv,      // CDOL1
                                     const struct tlv *crm2_tlv,      // CDOL2
                                     bool showData) {
    const struct tlv *un_tlv = tlvdb_get(db, 0x9f37, NULL);
    const struct tlv *cid_tlv = tlvdb_get(this_db, 0x9f27, NULL);

    if (!un_tlv || !cid_tlv)
        return NULL;

    size_t data_len = 0;
    unsigned char *data = emv_pki_decode_message(enc_pk, 5, &data_len,
                                                 tlvdb_get(this_db, 0x9f4b, NULL),
                                                 2,
                                                 un_tlv,
                                                 (uint8_t *)NULL);
    if (!data || data_len < 3) {
        PrintAndLogEx(WARNING, "ERROR: can't decode message. [%zu bytes]", data_len);
        return NULL;
    }

    if (showData) {
        PrintAndLogEx(SUCCESS, "Recovered data:");
        print_buffer(data, data_len, 1);
    }

    if (data[3] < 30 || data[3] > data_len - 4) {
        PrintAndLogEx(WARNING, "ERROR: Invalid data length");
        free(data);
        return NULL;
    }

    if (!cid_tlv || cid_tlv->len != 1 || cid_tlv->value[0] != data[5 + data[4]]) {
        PrintAndLogEx(WARNING, "ERROR: CID mismatch");
        free(data);
        return NULL;
    }

    struct crypto_hash *ch;
    ch = crypto_hash_open(enc_pk->hash_algo);
    if (!ch) {
        PrintAndLogEx(WARNING, "ERROR: can't create hash");
        free(data);
        return NULL;
    }

    if (pdol_data_tlv)
        crypto_hash_write(ch, pdol_data_tlv->value, pdol_data_tlv->len);
    if (crm1_tlv)
        crypto_hash_write(ch, crm1_tlv->value, crm1_tlv->len);
    if (crm2_tlv)
        crypto_hash_write(ch, crm2_tlv->value, crm2_tlv->len);

    tlvdb_visit(this_db, tlv_hash, ch, 0);

    if (memcmp(data + 5 + data[4] + 1 + 8, crypto_hash_read(ch), 20)) {
        PrintAndLogEx(WARNING, "ERROR: calculated hash error");
        crypto_hash_close(ch);
        free(data);
        return NULL;
    }
    crypto_hash_close(ch);

    size_t idn_len = data[4];
    if (idn_len > data[3] - 1) {
        PrintAndLogEx(WARNING, "ERROR: Invalid IDN length");
        free(data);
        return NULL;
    }

    struct tlvdb *idn_db = tlvdb_fixed(0x9f4c, idn_len, data + 5);
    free(data);

    return idn_db;
}
