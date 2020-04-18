/*
 * libopenemv - a library to work with EMV family of smart cards
 * Copyright (C) 2012, 2015 Dmitry Eremin-Solenikov
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * https://github.com/lumag/emv-tools/blob/master/lib/include/openemv/tlv.h
 */

#ifndef TLV_H
#define TLV_H

#include "common.h"

typedef uint32_t tlv_tag_t;

struct tlv {
    tlv_tag_t tag;
    size_t len;
    const unsigned char *value;
};

struct tlvdb;
typedef bool (*tlv_cb)(void *data, const struct tlv *tlv, int level, bool is_leaf);

struct tlvdb *tlvdb_fixed(tlv_tag_t tag, size_t len, const unsigned char *value);
struct tlvdb *tlvdb_external(tlv_tag_t tag, size_t len, const unsigned char *value);
struct tlvdb *tlvdb_parse(const unsigned char *buf, size_t len);
struct tlvdb *tlvdb_parse_multi(const unsigned char *buf, size_t len);
void tlvdb_free(struct tlvdb *tlvdb);

struct tlvdb *tlvdb_elm_get_next(struct tlvdb *tlvdb);
struct tlvdb *tlvdb_elm_get_children(struct tlvdb *tlvdb);
struct tlvdb *tlvdb_elm_get_parent(struct tlvdb *tlvdb);

struct tlvdb *tlvdb_find_full(struct tlvdb *tlvdb, tlv_tag_t tag); // search also in childrens
struct tlvdb *tlvdb_find(struct tlvdb *tlvdb, tlv_tag_t tag);
struct tlvdb *tlvdb_find_next(struct tlvdb *tlvdb, tlv_tag_t tag);
struct tlvdb *tlvdb_find_path(struct tlvdb *tlvdb, tlv_tag_t tag[]);

void tlvdb_add(struct tlvdb *tlvdb, struct tlvdb *other);
void tlvdb_change_or_add_node(struct tlvdb *tlvdb, tlv_tag_t tag, size_t len, const unsigned char *value);
void tlvdb_change_or_add_node_ex(struct tlvdb *tlvdb, tlv_tag_t tag, size_t len, const unsigned char *value, struct tlvdb **tlvdb_elm);

void tlvdb_visit(const struct tlvdb *tlvdb, tlv_cb cb, void *data, int level);
const struct tlv *tlvdb_get(const struct tlvdb *tlvdb, tlv_tag_t tag, const struct tlv *prev);
const struct tlv *tlvdb_get_inchild(const struct tlvdb *tlvdb, tlv_tag_t tag, const struct tlv *prev);
const struct tlv *tlvdb_get_tlv(const struct tlvdb *tlvdb);

bool tlv_parse_tl(const unsigned char **buf, size_t *len, struct tlv *tlv);
unsigned char *tlv_encode(const struct tlv *tlv, size_t *len);
bool tlv_is_constructed(const struct tlv *tlv);
bool tlv_equal(const struct tlv *a, const struct tlv *b);

bool tlv_get_uint8(const struct tlv *etlv, uint8_t *value);
bool tlv_get_int(const struct tlv *etlv, int *value);

bool tlvdb_get_uint8(struct tlvdb *tlvRoot, tlv_tag_t tag, uint8_t *value);

#endif
