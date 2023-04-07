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

#ifndef TLV_H
#define TLV_H

#include "common.h"

typedef uint32_t tlv_tag_t;

struct tlv {
    tlv_tag_t tag;
    size_t len;
    const unsigned char *value;
};

struct tlvdb {
    struct tlv tag;
    struct tlvdb *next;
    struct tlvdb *parent;
    struct tlvdb *children;
};

struct tlvdb_root {
    struct tlvdb db;
    size_t len;
    unsigned char buf[0];
};

typedef void (*tlv_cb)(void *data, const struct tlv *tlv, int level, bool is_leaf);

struct tlvdb *tlvdb_fixed(tlv_tag_t tag, size_t len, const unsigned char *value);
struct tlvdb *tlvdb_external(tlv_tag_t tag, size_t len, const unsigned char *value);
struct tlvdb *tlvdb_parse(const unsigned char *buf, size_t len);
struct tlvdb *tlvdb_parse_multi(const unsigned char *buf, size_t len);

bool tlvdb_parse_root(struct tlvdb_root *root);
bool tlvdb_parse_root_multi(struct tlvdb_root *root);

void tlvdb_free(struct tlvdb *tlvdb);
void tlvdb_root_free(struct tlvdb_root *root);

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
