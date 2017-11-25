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
 * https://github.com/lumag/emv-tools/blob/master/lib/tlv.c
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "tlv.h"

#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#define TLV_TAG_CLASS_MASK	0xc0
#define TLV_TAG_COMPLEX		0x20
#define TLV_TAG_VALUE_MASK	0x1f
#define TLV_TAG_VALUE_CONT	0x1f
#define TLV_TAG_INVALID		0

#define TLV_LEN_LONG		0x80
#define TLV_LEN_MASK		0x7f
#define TLV_LEN_INVALID		(~0)

// http://radek.io/2012/11/10/magical-container_of-macro/
//#define container_of(ptr, type, member) ({			       
//	const typeof( ((type *)0)->member ) *__mptr = (ptr);	
//        (type *)( (char *)__mptr - offsetof(type,member) );})

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

static tlv_tag_t tlv_parse_tag(const unsigned char **buf, size_t *len)
{
	tlv_tag_t tag;

	if (*len == 0)
		return TLV_TAG_INVALID;
	tag = **buf;
	--*len;
	++*buf;
	if ((tag & TLV_TAG_VALUE_MASK) != TLV_TAG_VALUE_CONT)
		return tag;

	if (*len == 0)
		return TLV_TAG_INVALID;

	tag <<= 8;
	tag |= **buf;
	--*len;
	++*buf;

	return tag;
}

static size_t tlv_parse_len(const unsigned char **buf, size_t *len)
{
	size_t l;

	if (*len == 0)
		return TLV_LEN_INVALID;

	l = **buf;
	--*len;
	++*buf;

	if (!(l & TLV_LEN_LONG))
		return l;

	size_t ll = l &~ TLV_LEN_LONG;
	if (*len < ll)
		return TLV_LEN_INVALID;

	/* FIXME */
	if (ll != 1)
		return TLV_LEN_INVALID;

	l = **buf;
	--*len;
	++*buf;

	return l;
}

bool tlv_parse_tl(const unsigned char **buf, size_t *len, struct tlv *tlv)
{
	tlv->value = 0;

	tlv->tag = tlv_parse_tag(buf, len);
	if (tlv->tag == TLV_TAG_INVALID)
		return false;

	tlv->len = tlv_parse_len(buf, len);
	if (tlv->len == TLV_LEN_INVALID)
		return false;

	return true;
}

static struct tlvdb *tlvdb_parse_children(struct tlvdb *parent);

static bool tlvdb_parse_one(struct tlvdb *tlvdb,
		struct tlvdb *parent,
		const unsigned char **tmp,
		size_t *left)
{
	tlvdb->next = tlvdb->children = NULL;
	tlvdb->parent = parent;

	tlvdb->tag.tag = tlv_parse_tag(tmp, left);
	if (tlvdb->tag.tag == TLV_TAG_INVALID)
		goto err;

	tlvdb->tag.len = tlv_parse_len(tmp, left);
	if (tlvdb->tag.len == TLV_LEN_INVALID)
		goto err;

	if (tlvdb->tag.len > *left)
		goto err;

	tlvdb->tag.value = *tmp;

	*tmp += tlvdb->tag.len;
	*left -= tlvdb->tag.len;

	if (tlv_is_constructed(&tlvdb->tag) && (tlvdb->tag.len != 0)) {
		tlvdb->children = tlvdb_parse_children(tlvdb);
		if (!tlvdb->children)
			goto err;
	} else {
		tlvdb->children = NULL;
	}

	return true;

err:
	return false;
}

static struct tlvdb *tlvdb_parse_children(struct tlvdb *parent)
{
	const unsigned char *tmp = parent->tag.value;
	size_t left = parent->tag.len;
	struct tlvdb *tlvdb, *first = NULL, *prev = NULL;

	while (left != 0) {
		tlvdb = malloc(sizeof(*tlvdb));
		if (prev)
			prev->next = tlvdb;
		else
			first = tlvdb;
		prev = tlvdb;

		if (!tlvdb_parse_one(tlvdb, parent, &tmp, &left))
			goto err;

		tlvdb->parent = parent;
	}

	return first;

err:
	tlvdb_free(first);

	return NULL;
}

struct tlvdb *tlvdb_parse(const unsigned char *buf, size_t len)
{
	struct tlvdb_root *root;
	const unsigned char *tmp;
	size_t left;

	if (!len || !buf)
		return NULL;

	root = malloc(sizeof(*root) + len);
	root->len = len;
	memcpy(root->buf, buf, len);

	tmp = root->buf;
	left = len;

	if (!tlvdb_parse_one(&root->db, NULL, &tmp, &left))
		goto err;

	if (left)
		goto err;

	return &root->db;

err:
	tlvdb_free(&root->db);

	return NULL;
}

struct tlvdb *tlvdb_parse_multi(const unsigned char *buf, size_t len)
{
	struct tlvdb_root *root;
	const unsigned char *tmp;
	size_t left;

	if (!len || !buf)
		return NULL;

	root = malloc(sizeof(*root) + len);
	root->len = len;
	memcpy(root->buf, buf, len);

	tmp = root->buf;
	left = len;

	if (!tlvdb_parse_one(&root->db, NULL, &tmp, &left))
		goto err;

	while (left != 0) {
		struct tlvdb *db = malloc(sizeof(*db));
		if (!tlvdb_parse_one(db, NULL, &tmp, &left)) {
			free (db);
			goto err;
		}

		tlvdb_add(&root->db, db);
	}

	return &root->db;

err:
	tlvdb_free(&root->db);

	return NULL;
}

struct tlvdb *tlvdb_fixed(tlv_tag_t tag, size_t len, const unsigned char *value)
{
	struct tlvdb_root *root = malloc(sizeof(*root) + len);

	root->len = len;
	memcpy(root->buf, value, len);

	root->db.parent = root->db.next = root->db.children = NULL;
	root->db.tag.tag = tag;
	root->db.tag.len = len;
	root->db.tag.value = root->buf;

	return &root->db;
}

struct tlvdb *tlvdb_external(tlv_tag_t tag, size_t len, const unsigned char *value)
{
	struct tlvdb_root *root = malloc(sizeof(*root));

	root->len = 0;

	root->db.parent = root->db.next = root->db.children = NULL;
	root->db.tag.tag = tag;
	root->db.tag.len = len;
	root->db.tag.value = value;

	return &root->db;
}

void tlvdb_free(struct tlvdb *tlvdb)
{
	struct tlvdb *next = NULL;

	if (!tlvdb)
		return;

	for (; tlvdb; tlvdb = next) {
		next = tlvdb->next;
		tlvdb_free(tlvdb->children);
		free(tlvdb);
	}
}

struct tlvdb *tlvdb_find_next(struct tlvdb *tlvdb, tlv_tag_t tag) {
	if (!tlvdb)
		return NULL;
	
	return tlvdb_find(tlvdb->next, tag);
}

struct tlvdb *tlvdb_find(struct tlvdb *tlvdb, tlv_tag_t tag) {
	if (!tlvdb)
		return NULL;
	
	for (; tlvdb; tlvdb = tlvdb->next) {
		if (tlvdb->tag.tag == tag)
			return tlvdb;
	}

	return NULL;
}

struct tlvdb *tlvdb_find_path(struct tlvdb *tlvdb, tlv_tag_t tag[]) {
	int i = 0;
	struct tlvdb *tnext = tlvdb;
	
	while (tnext && tag[i]) {
		tnext = tlvdb_find(tnext, tag[i]);
		i++;
		if (tag[i] && tnext) {
			tnext = tnext->children;
		}
	}
	
	return tnext;
}

void tlvdb_add(struct tlvdb *tlvdb, struct tlvdb *other)
{
	while (tlvdb->next) {
		tlvdb = tlvdb->next;
	}

	tlvdb->next = other;
}

void tlvdb_visit(const struct tlvdb *tlvdb, tlv_cb cb, void *data, int level)
{
	struct tlvdb *next = NULL;

	if (!tlvdb)
		return;

	for (; tlvdb; tlvdb = next) {
		next = tlvdb->next;
		cb(data, &tlvdb->tag, level, (tlvdb->children == NULL));
		tlvdb_visit(tlvdb->children, cb, data, level + 1);
	}
}

static const struct tlvdb *tlvdb_next(const struct tlvdb *tlvdb)
{
	if (tlvdb->children)
		return tlvdb->children;

	while (tlvdb) {
		if (tlvdb->next)
			return tlvdb->next;

		tlvdb = tlvdb->parent;
	}

	return NULL;
}

const struct tlv *tlvdb_get(const struct tlvdb *tlvdb, tlv_tag_t tag, const struct tlv *prev)
{
	if (prev) {
//		tlvdb = tlvdb_next(container_of(prev, struct tlvdb, tag));
		tlvdb = tlvdb_next((struct tlvdb *)prev);
	}


	while (tlvdb) {
		if (tlvdb->tag.tag == tag)
			return &tlvdb->tag;

		tlvdb = tlvdb_next(tlvdb);
	}

	return NULL;
}

const struct tlv *tlvdb_get_inchild(const struct tlvdb *tlvdb, tlv_tag_t tag, const struct tlv *prev) {
	tlvdb = tlvdb->children;
	return tlvdb_get(tlvdb, tag, prev);
}

unsigned char *tlv_encode(const struct tlv *tlv, size_t *len)
{
	size_t size = tlv->len;
	unsigned char *data;
	size_t pos;

	if (tlv->tag > 0x100)
		size += 2;
	else
		size += 1;

	if (tlv->len > 0x7f)
		size += 2;
	else
		size += 1;

	data = malloc(size);
	if (!data) {
		*len = 0;
		return NULL;
	}

	pos = 0;

	if (tlv->tag > 0x100) {
		data[pos++] = tlv->tag >> 8;
		data[pos++] = tlv->tag & 0xff;
	} else
		data[pos++] = tlv->tag;

	if (tlv->len > 0x7f) {
		data[pos++] = 0x81;
		data[pos++] = tlv->len;
	} else
		data[pos++] = tlv->len;

	memcpy(data + pos, tlv->value, tlv->len);
	pos += tlv->len;

	*len = pos;
	return data;
}

bool tlv_is_constructed(const struct tlv *tlv)
{
	return (tlv->tag < 0x100 ? tlv->tag : tlv->tag >> 8) & TLV_TAG_COMPLEX;
}

bool tlv_equal(const struct tlv *a, const struct tlv *b)
{
	if (!a && !b)
		return true;

	if (!a || !b)
		return false;

	return a->tag == b->tag && a->len == b->len && !memcmp(a->value, b->value, a->len);
}
