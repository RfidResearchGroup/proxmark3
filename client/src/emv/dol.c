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

typedef enum {
    DOL_FORMAT_OTHER,
    DOL_FORMAT_NUMERIC,
    DOL_FORMAT_COMPRESSED_NUMERIC,
} dol_data_format_t;

/*
 * DOL values are already encoded, but EMV still defines how a terminal must
 * resize them.  Keep this list local to DOL construction so display decoders
 * cannot accidentally change data sent to a card.
 */
static dol_data_format_t dol_data_format(tlv_tag_t tag) {
    switch (tag) {
        case 0x5a:   /* Application PAN */
        case 0x9f20: /* Track 2 Discretionary Data */
            return DOL_FORMAT_COMPRESSED_NUMERIC;

        case 0x5f24: case 0x5f25: case 0x5f28: case 0x5f2a:
        case 0x5f30: case 0x5f34: case 0x5f36:
        case 0x9a: case 0x9c:
        case 0x9f01: case 0x9f02: case 0x9f03: case 0x9f11:
        case 0x9f15: case 0x9f1a: case 0x9f21: case 0x9f35:
        case 0x9f39: case 0x9f3b: case 0x9f3c: case 0x9f3d:
        case 0x9f41: case 0x9f42: case 0x9f43: case 0x9f44:
        case 0x9f6a:
            return DOL_FORMAT_NUMERIC;

        default:
            return DOL_FORMAT_OTHER;
    }
}

bool dol_parse_tl(const unsigned char **buf, size_t *len, struct tlv *tlv) {
    if (!tlv)
        return false;
    memset(tlv, 0, sizeof(*tlv));
    tlv->tag = tlv_parse_tag(buf, len);
    if (!tlv->tag || !*len)
        return false;
    // Book 3 section 5.4: a DOL length is one byte, not a BER length.
    tlv->len = *(*buf)++;
    (*len)--;
    return true;
}

static bool dol_calculate_len(const struct tlv *tlv, size_t data_len, bool variable, size_t *length) {
    if (!tlv || (tlv->len && !tlv->value))
        return false;

    const unsigned char *buf = tlv->value;
    size_t left = tlv->len;
    size_t count = 0;

    while (left) {
        struct tlv cur_tlv;
        if (!dol_parse_tl(&buf, &left, &cur_tlv))
            return false;

        if (cur_tlv.len > SIZE_MAX - count)
            return false;
        count += cur_tlv.len;

        /* Last tag can be of variable length */
        if (variable && cur_tlv.len == 0 && left == 0)
            count = data_len;
    }

    *length = count;
    return true;
}

struct tlv *dol_process(const struct tlv *tlv, const struct tlvdb *tlvdb, tlv_tag_t tag) {
    size_t res_len = 0;
    if (tlv && !dol_calculate_len(tlv, 0, false, &res_len))
        return NULL;
    if (!tlv || res_len == 0) {
        struct tlv *res_tlv = calloc(1, sizeof(*res_tlv));
        if (!res_tlv)
            return NULL;

        res_tlv->tag = tag;
        res_tlv->len = 0;
        res_tlv->value = NULL;

        return res_tlv;
    }

    if (res_len > SIZE_MAX - sizeof(struct tlv))
        return NULL;
    struct tlv *res_tlv = calloc(1, sizeof(*res_tlv) + res_len);
    if (!res_tlv)
        return NULL;

    const unsigned char *buf = tlv->value;
    size_t left = tlv->len;
    unsigned char *res = (unsigned char *)(res_tlv + 1);
    size_t pos = 0;

    while (left) {
        struct tlv cur_tlv;
        if (!dol_parse_tl(&buf, &left, &cur_tlv) || pos > res_len || cur_tlv.len > res_len - pos) {
            free(res_tlv);

            return NULL;
        }

        const struct tlv *tag_tlv = tlv_is_constructed(&cur_tlv) ? NULL : tlvdb_get(tlvdb, cur_tlv.tag, NULL);
        dol_data_format_t format = dol_data_format(cur_tlv.tag);
        if (!tag_tlv) {
            memset(res + pos, 0, cur_tlv.len);
        } else if (tag_tlv->len && !tag_tlv->value) {
            free(res_tlv);
            return NULL;
        } else if (format == DOL_FORMAT_NUMERIC) {
            size_t copied = tag_tlv->len < cur_tlv.len ? tag_tlv->len : cur_tlv.len;
            size_t source_offset = tag_tlv->len - copied;
            size_t destination_offset = cur_tlv.len - copied;
            memset(res + pos, 0, destination_offset);
            if (copied)
                memcpy(res + pos + destination_offset, tag_tlv->value + source_offset, copied);
        } else {
            size_t copied = tag_tlv->len < cur_tlv.len ? tag_tlv->len : cur_tlv.len;
            if (copied)
                memcpy(res + pos, tag_tlv->value, copied);
            memset(res + pos + copied,
                   format == DOL_FORMAT_COMPRESSED_NUMERIC ? 0xff : 0x00,
                   cur_tlv.len - copied);
        }
        pos += cur_tlv.len;
    }

    res_tlv->tag = tag;
    res_tlv->len = res_len;
    res_tlv->value = res;

    return res_tlv;
}

struct tlvdb *dol_parse(const struct tlv *tlv, const unsigned char *data, size_t data_len) {
    if (!tlv || (tlv->len && !tlv->value) || (data_len && !data))
        return NULL;

    const unsigned char *buf = tlv->value;
    size_t left = tlv->len;
    size_t res_len;
    if (!dol_calculate_len(tlv, data_len, true, &res_len))
        return NULL;
    size_t pos = 0;
    struct tlvdb *db = NULL;

    if (res_len != data_len)
        return NULL;

    while (left) {
        struct tlv cur_tlv;
        if (!dol_parse_tl(&buf, &left, &cur_tlv) || pos > res_len || cur_tlv.len > res_len - pos) {
            tlvdb_free(db);
            return NULL;
        }

        /* Last tag can be of variable length */
        if (cur_tlv.len == 0 && left == 0)
            cur_tlv.len = res_len - pos;

        const unsigned char *value = cur_tlv.len ? data + pos : NULL;
        struct tlvdb *tag_db = tlvdb_fixed(cur_tlv.tag, cur_tlv.len, value);
        if (!tag_db) {
            tlvdb_free(db);
            return NULL;
        }
        if (!db)
            db = tag_db;
        else
            tlvdb_add(db, tag_db);

        pos += cur_tlv.len;
    }

    return db;
}
