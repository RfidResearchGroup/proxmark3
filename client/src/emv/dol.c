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

#include "emv/dol.h"
#include "emv/tlv.h"

#include <stdlib.h>
#include <string.h>

static size_t dol_calculate_len(const struct tlv *tlv, size_t data_len) {
    if (!tlv)
        return 0;

    const unsigned char *buf = tlv->value;
    size_t left = tlv->len;
    size_t count = 0;

    while (left) {
        struct tlv cur_tlv;
        if (!tlv_parse_tl(&buf, &left, &cur_tlv))
            return 0;

        count += cur_tlv.len;

        /* Last tag can be of variable length */
        if (cur_tlv.len == 0 && left == 0)
            count = data_len;
    }

    return count;
}

struct tlv *dol_process(const struct tlv *tlv, const struct tlvdb *tlvdb, tlv_tag_t tag) {
    size_t res_len;
    if (!tlv || !(res_len = dol_calculate_len(tlv, 0))) {
        struct tlv *res_tlv = calloc(1, sizeof(*res_tlv));

        res_tlv->tag = tag;
        res_tlv->len = 0;
        res_tlv->value = NULL;

        return res_tlv;
    }

    struct tlv *res_tlv = calloc(1, sizeof(*res_tlv) + res_len);
    if (!res_tlv)
        return NULL;

    const unsigned char *buf = tlv->value;
    size_t left = tlv->len;
    unsigned char *res = (unsigned char *)(res_tlv + 1);
    size_t pos = 0;

    while (left) {
        struct tlv cur_tlv;
        if (!tlv_parse_tl(&buf, &left, &cur_tlv) || pos + cur_tlv.len > res_len) {
            free(res_tlv);

            return NULL;
        }

        const struct tlv *tag_tlv = tlvdb_get(tlvdb, cur_tlv.tag, NULL);
        if (!tag_tlv) {
            memset(res + pos, 0, cur_tlv.len);
        } else if (tag_tlv->len > cur_tlv.len) {
            memcpy(res + pos, tag_tlv->value, cur_tlv.len);
        } else {
            // FIXME: cn data should be padded with 0xFF !!!
            memcpy(res + pos, tag_tlv->value, tag_tlv->len);
            memset(res + pos + tag_tlv->len, 0, cur_tlv.len - tag_tlv->len);
        }
        pos += cur_tlv.len;
    }

    res_tlv->tag = tag;
    res_tlv->len = res_len;
    res_tlv->value = res;

    return res_tlv;
}

struct tlvdb *dol_parse(const struct tlv *tlv, const unsigned char *data, size_t data_len) {
    if (!tlv)
        return NULL;

    const unsigned char *buf = tlv->value;
    size_t left = tlv->len;
    size_t res_len = dol_calculate_len(tlv, data_len);
    size_t pos = 0;
    struct tlvdb *db = NULL;

    if (res_len != data_len)
        return NULL;

    while (left) {
        struct tlv cur_tlv;
        if (!tlv_parse_tl(&buf, &left, &cur_tlv) || pos + cur_tlv.len > res_len) {
            tlvdb_free(db);
            return NULL;
        }

        /* Last tag can be of variable length */
        if (cur_tlv.len == 0 && left == 0)
            cur_tlv.len = res_len - pos;

        struct tlvdb *tag_db = tlvdb_fixed(cur_tlv.tag, cur_tlv.len, data + pos);
        if (!db)
            db = tag_db;
        else
            tlvdb_add(db, tag_db);

        pos += cur_tlv.len;
    }

    return db;
}
