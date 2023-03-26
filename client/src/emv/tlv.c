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
#define TLV_LEN_INVALID     (~0)

// http://radek.io/2012/11/10/magical-container_of-macro/
//#define container_of(ptr, type, member) ({
//  const typeof( ((type *)0)->member ) *__mptr = (ptr);
//        (type *)( (char *)__mptr - offsetof(type,member) );})

static tlv_tag_t tlv_parse_tag(const unsigned char **buf, size_t *len) {
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

static size_t tlv_parse_len(const unsigned char **buf, size_t *len) {
    size_t l;

    if (*len == 0)
        return TLV_LEN_INVALID;

    l = **buf;
    --*len;
    ++*buf;

    if (!(l & TLV_LEN_LONG))
        return l;

    size_t ll = l & ~ TLV_LEN_LONG;
    if (ll > 5)
        return TLV_LEN_INVALID;

    l = 0;
    for (int i = 1; i <= ll; i++) {
        l = (l << 8) + **buf;
        --*len;
        ++*buf;
    }

    return l;
}

bool tlv_parse_tl(const unsigned char **buf, size_t *len, struct tlv *tlv) {
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
                            size_t *left) {
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

static struct tlvdb *tlvdb_parse_children(struct tlvdb *parent) {
    const unsigned char *tmp = parent->tag.value;
    size_t left = parent->tag.len;
    struct tlvdb *tlvdb, *first = NULL, *prev = NULL;

    while (left != 0) {
        tlvdb = calloc(1, sizeof(*tlvdb));
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

    if (!len || !buf)
        return NULL;

    root = calloc(1, sizeof(*root) + len);
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
    tlvdb_root_free(root);
    return NULL;
}

struct tlvdb *tlvdb_parse_multi(const unsigned char *buf, size_t len) {
    struct tlvdb_root *root;
    const unsigned char *tmp;
    size_t left;

    if (len == 0 || buf == NULL) {
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
            struct tlvdb *db = calloc(1, sizeof(*db));
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
    struct tlvdb_root *root = calloc(1, sizeof(*root) + len);

    root->len = len;
    memcpy(root->buf, value, len);

    root->db.parent = root->db.next = root->db.children = NULL;
    root->db.tag.tag = tag;
    root->db.tag.len = len;
    root->db.tag.value = root->buf;

    return &root->db;
}

struct tlvdb *tlvdb_external(tlv_tag_t tag, size_t len, const unsigned char *value) {
    struct tlvdb_root *root = calloc(1, sizeof(*root));

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
    if (tlvdb == other) {
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

    struct tlvdb *telm = tlvdb_find_full(tlvdb, tag);
    if (telm == NULL) {
        // new tlv element
        struct tlvdb *elm = tlvdb_fixed(tag, len, value);
        tlvdb_add(tlvdb, elm);
        if (tlvdb_elm) {
            *tlvdb_elm = elm;
        }

    } else {
        // the same tlv structure
        if (telm->tag.tag == tag && telm->tag.len == len && !memcmp(telm->tag.value, value, len)) {
            return;
        }

        // replace tlv element
        struct tlvdb *tnewelm = tlvdb_fixed(tag, len, value);
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

    data = calloc(1, size);
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

bool tlv_is_constructed(const struct tlv *tlv) {
    return (((tlv->tag < 0x100 ? tlv->tag : tlv->tag >> 8) & TLV_TAG_COMPLEX) == TLV_TAG_COMPLEX);
}

bool tlv_equal(const struct tlv *a, const struct tlv *b) {
    if (a == NULL && b == NULL) {
        return true;
    }

    if (a == NULL || b == NULL) {
        return false;
    }

    return a->tag == b->tag && a->len == b->len && !memcmp(a->value, b->value, a->len);
}

struct tlvdb *tlvdb_elm_get_next(struct tlvdb *tlvdb) {
    return tlvdb->next;
}

struct tlvdb *tlvdb_elm_get_children(struct tlvdb *tlvdb) {
    return tlvdb->children;
}

struct tlvdb *tlvdb_elm_get_parent(struct tlvdb *tlvdb) {
    return tlvdb->parent;
}

bool tlvdb_get_uint8(struct tlvdb *tlvRoot, tlv_tag_t tag, uint8_t *value) {
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
            for (int i = 0; i < etlv->len; i++) {
                *value += etlv->value[i] * (1 << (i * 8));
            }
            return true;
        }
    }
    return false;
}
