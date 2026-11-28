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

#include "tlv.h"
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>


#define TLV_TAG_CLASS_MASK  0xC0
#define TLV_TAG_COMPLEX     0x20
#define TLV_TAG_VALUE_MASK  0x1F
#define TLV_TAG_VALUE_CONT  0x1F
#define TLV_TAG_INVALID     0

#define TLV_LEN_LONG        0x80
#define TLV_LEN_MASK        0x7F
#define TLV_LEN_INVALID     SIZE_MAX

// http://radek.io/2012/11/10/magical-container_of-macro/
//#define container_of(ptr, type, member) ({
//  const typeof( ((type *)0)->member ) *__mptr = (ptr);
//        (type *)( (char *)__mptr - offsetof(type,member) );})

tlv_tag_t tlv_parse_tag(const unsigned char **buf, size_t *len) {
    if (!buf || !*buf || !len || *len == 0)
        return TLV_TAG_INVALID;

    tlv_tag_t tag = **buf;
    --*len;
    ++*buf;
    if (tag == TLV_TAG_INVALID)
        return TLV_TAG_INVALID;
    if ((tag & TLV_TAG_VALUE_MASK) != TLV_TAG_VALUE_CONT)
        return tag;

    // EMV BER-TLV tags are at most three bytes. In high-tag-number form,
    // bit 8 indicates another tag byte follows and the first base-128 group
    // must not be zero.
    for (size_t tag_len = 1; tag_len < 3; tag_len++) {
        if (*len == 0)
            return TLV_TAG_INVALID;
        uint8_t next = **buf;
        --*len;
        ++*buf;
        if (tag_len == 1 && (next & 0x7f) == 0)
            return TLV_TAG_INVALID;
        tag = (tag << 8) | next;
        if (!(next & 0x80))
            return tag;
    }

    return TLV_TAG_INVALID;
}

static size_t tlv_parse_len(const unsigned char **buf, size_t *len) {
    size_t l;

    if (*len == 0)
        return TLV_LEN_INVALID;

    l = **buf;
    --*len;
    ++*buf;

    if (!(l & TLV_LEN_LONG))
        return l;

    size_t ll = l & ~TLV_LEN_LONG;
    if (ll == 0 || ll > sizeof(size_t))
        return TLV_LEN_INVALID;
    // Long-form lengths must have all declared length bytes available.
    if (*len < ll)
        return TLV_LEN_INVALID;

    l = 0;
    for (size_t i = 0; i < ll; i++) {
        l = (l << 8) + **buf;
        --*len;
        ++*buf;
    }

    return l;
}

bool tlv_parse_tl(const unsigned char **buf, size_t *len, struct tlv *tlv) {
    if (tlv == NULL) {
        return false;
    }
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

static void tlv_skip_padding(const unsigned char **buf, size_t *left) {
    while (*left && **buf == 0) {
        (*buf)++;
        (*left)--;
    }
}

static bool tlvdb_parse_one(struct tlvdb *tlvdb,
                            struct tlvdb *parent,
                            const unsigned char **tmp,
                            size_t *left) {
    if (tlvdb == NULL) {
        return false;
    }
    tlvdb->next = tlvdb->children = NULL;
    tlvdb->parent = parent;

    size_t depth = 0;
    for (const struct tlvdb *ancestor = parent; ancestor; ancestor = ancestor->parent)
        if (++depth >= 32)
            goto err;
    tlv_skip_padding(tmp, left);

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
        const unsigned char *content = tlvdb->tag.value;
        size_t content_len = tlvdb->tag.len;
        tlv_skip_padding(&content, &content_len);
        if (content_len) {
            tlvdb->children = tlvdb_parse_children(tlvdb);
            if (!tlvdb->children)
                goto err;
        }
    } else {
        tlvdb->children = NULL;
    }

    return true;

err:
    return false;
}

static struct tlvdb *tlvdb_parse_children(struct tlvdb *parent) {
    if (parent == NULL) {
        return NULL;
    }
    const unsigned char *tmp = parent->tag.value;
    size_t left = parent->tag.len;
    struct tlvdb *tlvdb, *first = NULL, *prev = NULL;

    while (left != 0) {
        tlv_skip_padding(&tmp, &left);
        if (!left)
            break;
        tlvdb = calloc(1, sizeof(*tlvdb));
        if (tlvdb == NULL) {
            goto err;
        }
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

struct tlvdb *tlvdb_parse(const unsigned char *buf, size_t len) {
    struct tlvdb_root *root;
    const unsigned char *tmp;
    size_t left;

    if (!len || !buf || len > SIZE_MAX - sizeof(*root))
        return NULL;

    root = calloc(1, sizeof(*root) + len);
    if (root == NULL) {
        return NULL;
    }
    root->len = len;
    memcpy(root->buf, buf, len);

    tmp = root->buf;
    left = len;

    if (!tlvdb_parse_one(&root->db, NULL, &tmp, &left))
        goto err;

    if (left)
        tlv_skip_padding(&tmp, &left);
    if (left)
        goto err;

    return &root->db;

err:
    tlvdb_root_free(root);
    return NULL;
}

struct tlvdb *tlvdb_parse_multi(const unsigned char *buf, size_t len) {
    struct tlvdb_root *root;
    const unsigned char *tmp;
    size_t left;

    if (len == 0 || buf == NULL || len > SIZE_MAX - sizeof(*root)) {
        return NULL;
    }

    root = calloc(1, sizeof(*root) + len);
    if (root == NULL) {
        return NULL;
    }

    root->len = len;
    memcpy(root->buf, buf, len);

    tmp = root->buf;
    left = len;

    if (tlvdb_parse_one(&root->db, NULL, &tmp, &left) == false) {
        goto err;
    }

    while (left != 0) {
        tlv_skip_padding(&tmp, &left);
        if (!left)
            break;
        struct tlvdb *db = calloc(1, sizeof(*db));
        if (db == NULL) {
            goto err;
        }

        if (tlvdb_parse_one(db, NULL, &tmp, &left) == false) {
            free(db);
            goto err;
        }

        tlvdb_add(&root->db, db);
    }

    return &root->db;

err:
    tlvdb_root_free(root);
    return NULL;
}

bool tlvdb_parse_root(struct tlvdb_root *root) {
    if (root == NULL || root->len == 0) {
        return false;
    }

    const uint8_t *tmp;
    size_t left;

    tmp = root->buf;
    left = root->len;
    if (tlvdb_parse_one(&root->db, NULL, &tmp, &left) == true) {
        tlv_skip_padding(&tmp, &left);
        if (left == 0) {
            return true;
        }
    }
    return false;
}

bool tlvdb_parse_root_multi(struct tlvdb_root *root) {
    if (root == NULL || root->len == 0) {
        return false;
    }

    const uint8_t *tmp;
    size_t left;

    tmp = root->buf;
    left = root->len;
    if (tlvdb_parse_one(&root->db, NULL, &tmp, &left) == true) {
        while (left > 0) {
            tlv_skip_padding(&tmp, &left);
            if (!left)
                break;
            struct tlvdb *db = calloc(1, sizeof(*db));
            if (db == NULL) {
                return false;
            }
            if (tlvdb_parse_one(db, NULL, &tmp, &left) == true) {
                tlvdb_add(&root->db, db);
            } else {
                free(db);
                return false;
            }
        }
        return true;
    }
    return false;
}

struct tlvdb *tlvdb_fixed(tlv_tag_t tag, size_t len, const unsigned char *value) {
    if (tag == TLV_TAG_INVALID || (len && !value) || len > SIZE_MAX - sizeof(struct tlvdb_root))
        return NULL;
    struct tlvdb_root *root = calloc(1, sizeof(*root) + len);
    if (root == NULL) {
        return NULL;
    }

    root->len = len;
    if (len)
        memcpy(root->buf, value, len);

    root->db.parent = root->db.next = root->db.children = NULL;
    root->db.tag.tag = tag;
    root->db.tag.len = len;
    root->db.tag.value = root->buf;

    return &root->db;
}

struct tlvdb *tlvdb_external(tlv_tag_t tag, size_t len, const unsigned char *value) {
    if (tag == TLV_TAG_INVALID || (len && !value))
        return NULL;
    struct tlvdb_root *root = calloc(1, sizeof(*root));
    if (root == NULL) {
        return NULL;
    }

    root->len = 0;

    root->db.parent = root->db.next = root->db.children = NULL;
    root->db.tag.tag = tag;
    root->db.tag.len = len;
    root->db.tag.value = value;

    return &root->db;
}

void tlvdb_free(struct tlvdb *tlvdb) {
    struct tlvdb *next = NULL;

    if (tlvdb == NULL) {
        return;
    }

    for (; tlvdb; tlvdb = next) {
        next = tlvdb->next;
        tlvdb_free(tlvdb->children);
        free(tlvdb);
    }
}

void tlvdb_root_free(struct tlvdb_root *root) {
    if (root == NULL) {
        return;
    }
    if (root->db.children) {
        tlvdb_free(root->db.children);
        root->db.children = NULL;
    }
    if (root->db.next) {
        tlvdb_free(root->db.next);
        root->db.next = NULL;
    }
    free(root);
}

struct tlvdb *tlvdb_find_next(struct tlvdb *tlvdb, tlv_tag_t tag) {
    if (tlvdb == NULL) {
        return NULL;
    }

    return tlvdb_find(tlvdb->next, tag);
}

struct tlvdb *tlvdb_find(struct tlvdb *tlvdb, tlv_tag_t tag) {
    if (tlvdb == NULL) {
        return NULL;
    }

    for (; tlvdb; tlvdb = tlvdb->next) {
        if (tlvdb->tag.tag == tag) {
            return tlvdb;
        }
    }

    return NULL;
}

struct tlvdb *tlvdb_find_full(struct tlvdb *tlvdb, tlv_tag_t tag) {
    if (tlvdb == NULL) {
        return NULL;
    }

    for (; tlvdb; tlvdb = tlvdb->next) {
        if (tlvdb->tag.tag == tag) {
            return tlvdb;
        }

        if (tlvdb->children) {
            struct tlvdb *ch = tlvdb_find_full(tlvdb->children, tag);
            if (ch) {
                return ch;
            }
        }
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

void tlvdb_add(struct tlvdb *tlvdb, struct tlvdb *other) {
    if (!tlvdb || !other || tlvdb == other) {
        return;
    }

    while (tlvdb->next) {
        if (tlvdb->next == other) {
            return;
        }

        tlvdb = tlvdb->next;
    }

    tlvdb->next = other;
}

void tlvdb_change_or_add_node_ex(struct tlvdb *tlvdb, tlv_tag_t tag, size_t len, const unsigned char *value, struct tlvdb **tlvdb_elm) {
    if (tlvdb_elm)
        *tlvdb_elm = NULL;
    if (!tlvdb || tag == TLV_TAG_INVALID || (len && !value))
        return;

    struct tlvdb *telm = tlvdb_find_full(tlvdb, tag);
    if (telm == NULL) {
        // new tlv element
        struct tlvdb *elm = tlvdb_fixed(tag, len, value);
        if (!elm)
            return;
        tlvdb_add(tlvdb, elm);
        if (tlvdb_elm) {
            *tlvdb_elm = elm;
        }

    } else {
        // the same tlv structure
        if (telm->tag.tag == tag && telm->tag.len == len &&
                (len == 0 || !memcmp(telm->tag.value, value, len))) {
            return;
        }

        // replace tlv element
        struct tlvdb *tnewelm = tlvdb_fixed(tag, len, value);
        if (!tnewelm)
            return;
        bool tnewelm_linked = false;
        tnewelm->next = telm->next;
        tnewelm->parent = telm->parent;

        // if telm stayed first in children chain
        if (telm->parent && telm->parent->children == telm) {
            telm->parent->children = tnewelm;
            tnewelm_linked = true;
        }

        // if telm have previous element
        if (telm != tlvdb) {
            // elm in root
            struct tlvdb *celm = tlvdb;
            // elm in child list of node
            if (telm->parent && telm->parent->children) {
                celm = telm->parent->children;
            }

            // find previous element
            for (; celm; celm = celm->next) {
                if (celm->next == telm) {
                    celm->next = tnewelm;
                    tnewelm_linked = true;
                    break;
                }
            }
        }

        // free old element with childrens
        telm->next = NULL;
        tlvdb_free(telm);

        if (tlvdb_elm) {
            *tlvdb_elm = tnewelm;
            tnewelm_linked = true;
        }

        if (!tnewelm_linked) {
            tlvdb_free(tnewelm);
        }
    }

    return;
}

void tlvdb_change_or_add_node(struct tlvdb *tlvdb, tlv_tag_t tag, size_t len, const unsigned char *value) {
    tlvdb_change_or_add_node_ex(tlvdb, tag, len, value, NULL);
}

void tlvdb_visit(const struct tlvdb *tlvdb, tlv_cb cb, void *data, int level) {
    struct tlvdb *next = NULL;

    if (tlvdb == NULL) {
        return;
    }

    for (; tlvdb; tlvdb = next) {
        next = tlvdb->next;
        cb(data, &tlvdb->tag, level, (tlvdb->children == NULL));
        tlvdb_visit(tlvdb->children, cb, data, level + 1);
    }
}

static const struct tlvdb *tlvdb_next(const struct tlvdb *tlvdb) {
    if (tlvdb->children) {
        return tlvdb->children;
    }

    while (tlvdb) {
        if (tlvdb->next) {
            return tlvdb->next;
        }

        tlvdb = tlvdb->parent;
    }

    return NULL;
}

const struct tlv *tlvdb_get(const struct tlvdb *tlvdb, tlv_tag_t tag, const struct tlv *prev) {
    if (prev) {
// tlvdb = tlvdb_next(container_of(prev, struct tlvdb, tag));
        tlvdb = tlvdb_next((struct tlvdb *)prev);
    }


    while (tlvdb) {
        if (tlvdb->tag.tag == tag) {
            return &tlvdb->tag;
        }

        tlvdb = tlvdb_next(tlvdb);
    }

    return NULL;
}

const struct tlv *tlvdb_get_inchild(const struct tlvdb *tlvdb, tlv_tag_t tag, const struct tlv *prev) {
    if (!tlvdb)
        return NULL;
    tlvdb = tlvdb->children;
    return tlvdb_get(tlvdb, tag, prev);
}

const struct tlv *tlvdb_get_tlv(const struct tlvdb *tlvdb) {
    if (tlvdb)
        return &tlvdb->tag;
    else
        return NULL;
}

unsigned char *tlv_encode(const struct tlv *tlv, size_t *len) {
    if (!len)
        return NULL;
    *len = 0;
    if (!tlv || tlv->tag == TLV_TAG_INVALID || tlv->tag > 0xffffff ||
            (tlv->len && !tlv->value))
        return NULL;

    size_t tag_len = tlv->tag > 0xffff ? 3 : (tlv->tag > 0xff ? 2 : 1);
    size_t length_bytes = 0;
    for (size_t value_len = tlv->len; value_len; value_len >>= 8)
        length_bytes++;
    size_t length_len = tlv->len > 0x7f ? 1 + length_bytes : 1;
    if (tlv->len > SIZE_MAX - tag_len - length_len)
        return NULL;
    size_t size = tlv->len + tag_len + length_len;

    unsigned char *data = calloc(1, size);
    if (!data) {
        return NULL;
    }

    size_t pos = 0;
    for (size_t i = tag_len; i > 0; i--)
        data[pos++] = (tlv->tag >> ((i - 1) * 8)) & 0xff;

    if (tlv->len > 0x7f) {
        data[pos++] = 0x80 | length_bytes;
        for (size_t i = length_bytes; i > 0; i--)
            data[pos++] = (tlv->len >> ((i - 1) * 8)) & 0xff;
    } else {
        data[pos++] = tlv->len;
    }

    if (tlv->len)
        memcpy(data + pos, tlv->value, tlv->len);
    pos += tlv->len;

    *len = pos;
    return data;
}

bool tlv_is_constructed(const struct tlv *tlv) {
    if (!tlv)
        return false;
    tlv_tag_t first = tlv->tag;
    while (first > 0xff)
        first >>= 8;
    return (first & TLV_TAG_COMPLEX) == TLV_TAG_COMPLEX;
}

bool tlv_equal(const struct tlv *a, const struct tlv *b) {
    if (a == NULL && b == NULL) {
        return true;
    }

    if (a == NULL || b == NULL) {
        return false;
    }

    return a->tag == b->tag && a->len == b->len &&
           (a->len == 0 || !memcmp(a->value, b->value, a->len));
}

struct tlvdb *tlvdb_elm_get_next(const struct tlvdb *tlvdb) {
    return tlvdb ? tlvdb->next : NULL;
}

struct tlvdb *tlvdb_elm_get_children(const struct tlvdb *tlvdb) {
    return tlvdb ? tlvdb->children : NULL;
}

struct tlvdb *tlvdb_elm_get_parent(const struct tlvdb *tlvdb) {
    return tlvdb ? tlvdb->parent : NULL;
}

bool tlvdb_get_uint8(const struct tlvdb *tlvRoot, tlv_tag_t tag, uint8_t *value) {
    const struct tlv *tlvelm = tlvdb_get(tlvRoot, tag, NULL);
    return tlv_get_uint8(tlvelm, value);
}

bool tlv_get_uint8(const struct tlv *etlv, uint8_t *value) {
    *value = 0;
    if (etlv) {
        if (etlv->len == 0) {
            return true;
        }

        if (etlv->len == 1) {
            *value = etlv->value[0];
            return true;
        }
    }
    return false;
}

bool tlv_get_int(const struct tlv *etlv, int *value) {
    *value = 0;
    if (etlv) {
        if (etlv->len == 0) {
            return true;
        }

        if (etlv->len <= 4) {
            for (size_t i = 0; i < etlv->len; i++) {
                *value += etlv->value[i] * (1 << (i * 8));
            }
            return true;
        }
    }
    return false;
}
