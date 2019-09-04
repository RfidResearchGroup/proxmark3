//-----------------------------------------------------------------------------
// Copyright (C) 2018 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// asn.1 dumping
//-----------------------------------------------------------------------------
#define _POSIX_C_SOURCE 200809L                 // need for strnlen()
#include "asn1dump.h"

#include "commonutil.h"  // ARRAYLEN

#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <jansson.h>
#include <mbedtls/asn1.h>
#include <mbedtls/oid.h>
#include "emv/emv_tags.h"
#include "emv/dump.h"
#include "emv/emvjson.h"
#include "util.h"
#include "proxmark3.h"
#include "fileutils.h"
#include "pm3_cmd.h"

#ifndef PRINT_INDENT
# define PRINT_INDENT(level) {for (int myi = 0; myi < (level); myi++) fprintf(f, "   ");}
#endif

enum asn1_tag_t {
    ASN1_TAG_GENERIC,
    ASN1_TAG_BOOLEAN,
    ASN1_TAG_INTEGER,
    ASN1_TAG_STRING,
    ASN1_TAG_OCTET_STRING,
    ASN1_TAG_UTC_TIME,
    ASN1_TAG_STR_TIME,
    ASN1_TAG_OBJECT_ID,
};

struct asn1_tag {
    tlv_tag_t tag;
    const char *name;
    enum asn1_tag_t type;
//    const void *data;
};

static const struct asn1_tag asn1_tags[] = {
    // internal
    { 0x00, "Unknown ???",       ASN1_TAG_GENERIC      },

    // ASN.1
    { 0x01, "BOOLEAN",           ASN1_TAG_BOOLEAN      },
    { 0x02, "INTEGER",           ASN1_TAG_INTEGER      },
    { 0x03, "BIT STRING",        ASN1_TAG_GENERIC      },
    { 0x04, "OCTET STRING",      ASN1_TAG_OCTET_STRING },
    { 0x05, "NULL",              ASN1_TAG_GENERIC      },
    { 0x06, "OBJECT IDENTIFIER", ASN1_TAG_OBJECT_ID    },
    { 0x07, "OBJECT DESCRIPTOR", ASN1_TAG_GENERIC      },
    { 0x08, "EXTERNAL",          ASN1_TAG_GENERIC      },
    { 0x09, "REAL",              ASN1_TAG_GENERIC      },
    { 0x0A, "ENUMERATED",        ASN1_TAG_GENERIC      },
    { 0x0B, "EMBEDDED_PDV",      ASN1_TAG_GENERIC      },
    { 0x0C, "UTF8String",        ASN1_TAG_STRING       },
    { 0x10, "SEQUENCE",          ASN1_TAG_GENERIC      },
    { 0x11, "SET",               ASN1_TAG_GENERIC      },
    { 0x12, "NumericString",     ASN1_TAG_STRING       },
    { 0x13, "PrintableString",   ASN1_TAG_STRING       },
    { 0x14, "T61String",         ASN1_TAG_GENERIC      },
    { 0x15, "VideotexString",    ASN1_TAG_GENERIC      },
    { 0x16, "IA5String",         ASN1_TAG_GENERIC      },
    { 0x17, "UTCTime",           ASN1_TAG_UTC_TIME     },
    { 0x18, "GeneralizedTime",   ASN1_TAG_STR_TIME     },
    { 0x19, "GraphicString",     ASN1_TAG_GENERIC      },
    { 0x1A, "VisibleString",     ASN1_TAG_STRING       },
    { 0x1B, "GeneralString",     ASN1_TAG_STRING       },
    { 0x1C, "UniversalString",   ASN1_TAG_STRING       },
    { 0x1E, "BMPString",         ASN1_TAG_GENERIC      },
    { 0x30, "SEQUENCE",          ASN1_TAG_GENERIC      },
    { 0x31, "SET",               ASN1_TAG_GENERIC      },
    { 0xa0, "[0]",               ASN1_TAG_GENERIC      },
    { 0xa1, "[1]",               ASN1_TAG_GENERIC      },
    { 0xa2, "[2]",               ASN1_TAG_GENERIC      },
    { 0xa3, "[3]",               ASN1_TAG_GENERIC      },
    { 0xa4, "[4]",               ASN1_TAG_GENERIC      },
    { 0xa5, "[5]",               ASN1_TAG_GENERIC      },
};

static int asn1_sort_tag(tlv_tag_t tag) {
    return (int)(tag >= 0x100 ? tag : tag << 8);
}

static int asn1_tlv_compare(const void *a, const void *b) {
    const struct tlv *tlv = a;
    const struct asn1_tag *tag = b;

    return asn1_sort_tag(tlv->tag) - (asn1_sort_tag(tag->tag));
}

static const struct asn1_tag *asn1_get_tag(const struct tlv *tlv) {
    struct asn1_tag *tag = bsearch(tlv, asn1_tags, ARRAYLEN(asn1_tags),
                                   sizeof(asn1_tags[0]), asn1_tlv_compare);

    return tag ? tag : &asn1_tags[0];
}

static void asn1_tag_dump_str_time(const struct tlv *tlv, const struct asn1_tag *tag, FILE *f, int level, bool longyear, bool *needdump) {
    int len = tlv->len;
    *needdump = false;

    int startindx = longyear ? 4 : 2;

    if (len > 4) {
        fprintf(f, "\tvalue: '");
        while (true) {
            // year
            if (!longyear)
                fprintf(f, "20");
            fwrite(tlv->value, 1, longyear ? 4 : 2, f);
            fprintf(f, "-");
            if (len < startindx + 2)
                break;
            // month
            fwrite(&tlv->value[startindx], 1, 2, f);
            fprintf(f, "-");
            if (len < startindx + 4)
                break;
            // day
            fwrite(&tlv->value[startindx + 2], 1, 2, f);
            fprintf(f, " ");
            if (len < startindx + 6)
                break;
            // hour
            fwrite(&tlv->value[startindx + 4], 1, 2, f);
            fprintf(f, ":");
            if (len < startindx + 8)
                break;
            // min
            fwrite(&tlv->value[startindx + 6], 1, 2, f);
            fprintf(f, ":");
            if (len < startindx + 10)
                break;
            // sec
            fwrite(&tlv->value[startindx + 8], 1, 2, f);
            if (len < startindx + 11)
                break;
            // time zone
            fprintf(f, " zone: %.*s", len - 10 - (longyear ? 4 : 2), &tlv->value[startindx + 10]);

            break;
        }
        fprintf(f, "'\n");
    } else {
        fprintf(f, "\n");
        *needdump = true;
    }
}

static void asn1_tag_dump_string(const struct tlv *tlv, const struct asn1_tag *tag, FILE *f, int level) {
    fprintf(f, "\tvalue: '");
    fwrite(tlv->value, 1, tlv->len, f);
    fprintf(f, "'\n");
}

static void asn1_tag_dump_octet_string(const struct tlv *tlv, const struct asn1_tag *tag, FILE *f, int level, bool *needdump) {
    *needdump = false;
    for (size_t i = 0; i < tlv->len; i++)
        if (!isspace(tlv->value[i]) && !isprint(tlv->value[i])) {
            *needdump = true;
            break;
        }

    if (*needdump) {
        fprintf(f, "'\n");
    } else {
        fprintf(f, "\t\t");
        asn1_tag_dump_string(tlv, tag, f, level);
    }
}

static unsigned long asn1_value_integer(const struct tlv *tlv, unsigned start, unsigned end) {
    unsigned long ret = 0;
    unsigned i;

    if (end > tlv->len * 2)
        return ret;
    if (start >= end)
        return ret;

    if (start & 1) {
        ret += tlv->value[start / 2] & 0xf;
        i = start + 1;
    } else
        i = start;

    for (; i < end - 1; i += 2) {
        ret *= 10;
        ret += tlv->value[i / 2] >> 4;
        ret *= 10;
        ret += tlv->value[i / 2] & 0xf;
    }

    if (end & 1) {
        ret *= 10;
        ret += tlv->value[end / 2] >> 4;
    }

    return ret;
}

static void asn1_tag_dump_boolean(const struct tlv *tlv, const struct asn1_tag *tag, FILE *f, int level) {
    PRINT_INDENT(level);
    if (tlv->len > 0) {
        fprintf(f, "\tvalue: %s\n", tlv->value[0] ? "true" : "false");
    } else {
        fprintf(f, "n/a\n");
    }
}

static void asn1_tag_dump_integer(const struct tlv *tlv, const struct asn1_tag *tag, FILE *f, int level) {
    PRINT_INDENT(level);
    if (tlv->len == 4) {
        int32_t val = 0;
        for (size_t i = 0; i < tlv->len; i++)
            val = (val << 8) + tlv->value[i];
        fprintf(f, "\tvalue4b: %d\n", val);
        return;
    }
    fprintf(f, "\tvalue: %lu\n", asn1_value_integer(tlv, 0, tlv->len * 2));
}

static char *asn1_oid_description(const char *oid, bool with_group_desc) {
    json_error_t error;
    json_t *root = NULL;
    static char res[300];
    memset(res, 0x00, sizeof(res));

    char *path;
    if (searchFile(&path, RESOURCES_SUBDIR, "oids", ".json", false) != PM3_SUCCESS) {
        return NULL;
    }

    // load `oids.json`
    root = json_load_file(path, 0, &error);
    free(path);

    if (!root || !json_is_object(root)) {
        goto error;
    }

    json_t *elm = json_object_get(root, oid);
    if (!elm) {
        goto error;
    }

    if (JsonLoadStr(elm, "$.d", res))
        goto error;

    char strext[300] = {0};
    if (!JsonLoadStr(elm, "$.c", strext)) {
        strcat(res, " (");
        strcat(res, strext);
        strcat(res, ")");
    }

    json_decref(root);
    return res;

error:
    if (root)
        json_decref(root);
    return NULL;
}

static void asn1_tag_dump_object_id(const struct tlv *tlv, const struct asn1_tag *tag, FILE *f, int level) {
    PRINT_INDENT(level);
    mbedtls_asn1_buf asn1_buf;
    asn1_buf.len = tlv->len;
    asn1_buf.p = (uint8_t *)tlv->value;
    char pstr[300];
    mbedtls_oid_get_numeric_string(pstr, sizeof(pstr), &asn1_buf);
    fprintf(f, " %s", pstr);

    char *jsondesc = asn1_oid_description(pstr, true);
    if (jsondesc) {
        fprintf(f, " -  %s", jsondesc);
    } else {
        const char *ppstr;
        mbedtls_oid_get_attr_short_name(&asn1_buf, &ppstr);
        if (ppstr && strnlen(ppstr, 1)) {
            fprintf(f, " (%s)\n", ppstr);
            return;
        }
        mbedtls_oid_get_sig_alg_desc(&asn1_buf, &ppstr);
        if (ppstr && strnlen(ppstr, 1)) {
            fprintf(f, " (%s)\n", ppstr);
            return;
        }
        mbedtls_oid_get_extended_key_usage(&asn1_buf, &ppstr);
        if (ppstr && strnlen(ppstr, 1)) {
            fprintf(f, " (%s)\n", ppstr);
            return;
        }
    }
    fprintf(f, "\n");
}

bool asn1_tag_dump(const struct tlv *tlv, FILE *f, int level, bool *candump) {
    if (!tlv) {
        fprintf(f, "NULL\n");
        return false;
    }

    const struct asn1_tag *tag = asn1_get_tag(tlv);

    PRINT_INDENT(level);
    fprintf(f, "--%2x[%02zx] '%s':", tlv->tag, tlv->len, tag->name);

    switch (tag->type) {
        case ASN1_TAG_GENERIC:
            fprintf(f, "\n");
            break;
        case ASN1_TAG_STRING:
            asn1_tag_dump_string(tlv, tag, f, level);
            *candump = false;
            break;
        case ASN1_TAG_OCTET_STRING:
            asn1_tag_dump_octet_string(tlv, tag, f, level, candump);
            break;
        case ASN1_TAG_BOOLEAN:
            asn1_tag_dump_boolean(tlv, tag, f, level);
            *candump = false;
            break;
        case ASN1_TAG_INTEGER:
            asn1_tag_dump_integer(tlv, tag, f, level);
            *candump = false;
            break;
        case ASN1_TAG_UTC_TIME:
            asn1_tag_dump_str_time(tlv, tag, f, level, false, candump);
            break;
        case ASN1_TAG_STR_TIME:
            asn1_tag_dump_str_time(tlv, tag, f, level, true, candump);
            break;
        case ASN1_TAG_OBJECT_ID:
            asn1_tag_dump_object_id(tlv, tag, f, level);
            *candump = false;
            break;
    };

    return true;
}
