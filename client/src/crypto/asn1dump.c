//-----------------------------------------------------------------------------
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
// asn.1 dumping
//-----------------------------------------------------------------------------
#define _POSIX_C_SOURCE 200809L                 // need for strnlen()
#include "asn1dump.h"

#include "commonutil.h"  // ARRAYLEN

#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <jansson.h>
#include <mbedtls/asn1.h>
#include "mbedtls/bignum.h"      // big num
#include <mbedtls/oid.h>
#include "emv/emv_tags.h"
#include "emv/emvjson.h"
#include "util.h"
#include "proxmark3.h"
#include "fileutils.h"
#include "pm3_cmd.h"

enum asn1_tag_t {
    ASN1_TAG_GENERIC,
    ASN1_TAG_BOOLEAN,
    ASN1_TAG_INTEGER,
    ASN1_TAG_STRING,
    ASN1_TAG_OCTET_STRING,
    ASN1_TAG_UTC_TIME,
    ASN1_TAG_STR_TIME,
    ASN1_TAG_OBJECT_ID,
    ASN1_TAG_HEX,
    ASN1_TAG_BIT_STRING,
};

struct asn1_tag {
    tlv_tag_t tag;
    const char *name;
    enum asn1_tag_t type;
//    const void *data;
};

static const struct asn1_tag asn1_tags[] = {
    // internal
    { 0x00, "elem",              ASN1_TAG_GENERIC      },  // PRIMITIVE
    { 0x20, "CONSTRUCTED",       ASN1_TAG_GENERIC      },  // CONSTRUCTED,  the sequence has multiple elements
    { 0x80, "CONTEXT SPECIFIC",  ASN1_TAG_GENERIC      },

    // ASN.1
    { 0x01, "BOOLEAN",           ASN1_TAG_BOOLEAN      },
    { 0x02, "INTEGER",           ASN1_TAG_INTEGER      },
    { 0x03, "BIT STRING",        ASN1_TAG_BIT_STRING   },
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
    struct asn1_tag *tag = bsearch(tlv, asn1_tags, ARRAYLEN(asn1_tags), sizeof(asn1_tags[0]), asn1_tlv_compare);
    return tag ? tag : &asn1_tags[0];
}

static void asn1_tag_dump_str_time(const struct tlv *tlv, const struct asn1_tag *tag, int level, bool longyear, bool *needdump) {
    int len = tlv->len;
    *needdump = false;

    int startidx = longyear ? 4 : 2;

    if (len > 4) {
        PrintAndLogEx(NORMAL, "    value: '" NOLF);
        while (true) {

            // year
            if (longyear == false) {
                int short_year = (tlv->value[0] - '0') * 10 + (tlv->value[1] - '0');
                if (short_year >= 0 && short_year <= 99) {
                    if (short_year > 50) {
                        PrintAndLogEx(NORMAL, "19" NOLF);
                    } else {
                        PrintAndLogEx(NORMAL, "20" NOLF);
                    }
                }
            }

            PrintAndLogEx(NORMAL, "%.*s-" NOLF, startidx, tlv->value);
            if (len < startidx + 2)
                break;

            // month
            PrintAndLogEx(NORMAL, "%.*s-" NOLF, 2, tlv->value + startidx);
            if (len < startidx + 4)
                break;

            // day
            PrintAndLogEx(NORMAL, "%.*s " NOLF, 2, tlv->value + startidx + 2);
            if (len < startidx + 6)
                break;

            // hour
            PrintAndLogEx(NORMAL, "%.*s:" NOLF, 2, tlv->value + startidx + 4);
            if (len < startidx + 8)
                break;

            // min
            PrintAndLogEx(NORMAL, "%.*s:" NOLF, 2, tlv->value + startidx + 6);
            if (len < startidx + 10)
                break;

            // sec
            PrintAndLogEx(NORMAL, "%.*s" NOLF, 2, tlv->value + startidx + 8);
            if (len < startidx + 12)
                break;

            // time zone
            PrintAndLogEx(NORMAL, " zone: UTC %.*s" NOLF, len - startidx - 10, tlv->value + startidx + 10);
            break;
        }
        PrintAndLogEx(NORMAL, "'");
    } else {
        PrintAndLogEx(NORMAL, "");
        *needdump = true;
    }
}

static void asn1_tag_dump_string(const struct tlv *tlv, const struct asn1_tag *tag, int level) {
    PrintAndLogEx(NORMAL, "    value: '" _GREEN_("%.*s") "' hex: '%s'", (int)tlv->len, tlv->value, sprint_hex(tlv->value, tlv->len));
}

static void asn1_tag_dump_bitstring(const struct tlv *tlv, const struct asn1_tag *tag, int level) {

    size_t len = tlv->len;
    size_t n = (len * 8);
    bool skip = false;

    if (tlv->value[0] == 0) {
        n -= 8;
        len--;
        skip = true;
    }

    uint8_t *d = calloc(n, sizeof(uint8_t));
    if (d == NULL) {
        return;
    }

    if (skip)
        bytes_to_bytebits(tlv->value + 1, len, d);
    else
        bytes_to_bytebits(tlv->value, len, d);

    level++;
    PrintAndLogEx(NORMAL, "  (%zu bit)", n);
    PrintAndLogEx(INFO, "%*s" NOLF, 1 + (level * 4), "");

    for (int i = 0; i < n; i++) {

        char c = d[i];
        if (c < 2) {
            c += '0';
        } else {
            goto out;
        }

        PrintAndLogEx(NORMAL, "%c" NOLF, c);

        if (((i + 1) % 64) == 0) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, "%*s" NOLF, 1 + (level * 4), "");
        }
    }

out:
    free(d);
    PrintAndLogEx(NORMAL, "");
}

static void asn1_tag_dump_hex(const struct tlv *tlv, const struct asn1_tag *tag, int level) {
    PrintAndLogEx(NORMAL, "    value: '%s'", sprint_hex_inrow(tlv->value, tlv->len));
}

static void asn1_tag_dump_octet_string(const struct tlv *tlv, const struct asn1_tag *tag, int level) {
    /*
        for (size_t i = 0; i < tlv->len; i++) {
            if (!isspace(tlv->value[i]) && !isprint(tlv->value[i])) {
                *needdump = true;
                break;
            }
        }
        */
    PrintAndLogEx(NORMAL, "        " NOLF);
    asn1_tag_dump_string(tlv, tag, level);
}

static void asn1_tag_dump_boolean(const struct tlv *tlv, const struct asn1_tag *tag, int level) {
    PrintAndLogEx(NORMAL, "%*s" NOLF, (level * 4), " ");
    if (tlv->len > 0) {
        PrintAndLogEx(NORMAL, "    value: %s", tlv->value[0] ? "true" : "false");
    } else {
        PrintAndLogEx(NORMAL, "n/a");
    }
}

static void asn1_tag_dump_integer(const struct tlv *tlv, const struct asn1_tag *tag, int level) {

    size_t n = (tlv->len * 2);
    char *hex = calloc(n + 1, sizeof(uint8_t));
    if (hex == NULL) {
        return;
    }

    hex_to_buffer((uint8_t *)hex, tlv->value, tlv->len, tlv->len, 0, 0, false);

    // results for MPI actions
    bool ret = false;

    // container of big number
    mbedtls_mpi N;
    mbedtls_mpi_init(&N);

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&N, 16, hex));

    char s[600] = {0};
    size_t slen = 0;
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_string(&N, 10, s, sizeof(s), &slen));
    if (slen > 0) {
        PrintAndLogEx(NORMAL, "%*s value: %s", (level), "", s);
    }

cleanup:
    mbedtls_mpi_free(&N);
    free(hex);
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

static void asn1_tag_dump_object_id(const struct tlv *tlv, const struct asn1_tag *tag, int level) {

    mbedtls_asn1_buf asn1_buf;
    asn1_buf.len = tlv->len;
    asn1_buf.p = (uint8_t *)tlv->value;
    char pstr[300];
    mbedtls_oid_get_numeric_string(pstr, sizeof(pstr), &asn1_buf);

    PrintAndLogEx(NORMAL, "%*s %s" NOLF, (level), " ", pstr);

    char *jsondesc = asn1_oid_description(pstr, true);
    if (jsondesc) {
        PrintAndLogEx(NORMAL, " -  %s" NOLF, jsondesc);
    } else {
        const char *ppstr = NULL;
        mbedtls_oid_get_attr_short_name(&asn1_buf, &ppstr);
        if (ppstr && strnlen(ppstr, 1)) {
            PrintAndLogEx(NORMAL, " (%s)", ppstr);
            return;
        }
        mbedtls_oid_get_sig_alg_desc(&asn1_buf, &ppstr);
        if (ppstr && strnlen(ppstr, 1)) {
            PrintAndLogEx(NORMAL, " (%s)", ppstr);
            return;
        }
        mbedtls_oid_get_extended_key_usage(&asn1_buf, &ppstr);
        if (ppstr && strnlen(ppstr, 1)) {
            PrintAndLogEx(NORMAL, " (%s)", ppstr);
            return;
        }
    }
    PrintAndLogEx(NORMAL, "");
}

bool asn1_tag_dump(const struct tlv *tlv, int level, bool *candump) {
    if (tlv == NULL) {
        PrintAndLogEx(FAILED, "NULL\n");
        return false;
    }

    const struct asn1_tag *tag = asn1_get_tag(tlv);

    /*
        if ((tlv->tag & 0x20) == 0x20 ) {
        } else if ((tlv->tag & 0x80) == 0x80 ) {
        } else {
        }
    */

    PrintAndLogEx(INFO,
                  "%*s-- %02X [%02zX] '"_YELLOW_("%s") "'" NOLF
                  , (level * 4)
                  , " "
                  , tlv->tag
                  , tlv->len
                  , tag->name
                 );

    switch (tag->type) {
        case ASN1_TAG_GENERIC:
            PrintAndLogEx(NORMAL, "");
            // maybe print number of elements?
            break;
        case ASN1_TAG_STRING:
            asn1_tag_dump_string(tlv, tag, level);
            *candump = false;
            break;
        case ASN1_TAG_OCTET_STRING:
            asn1_tag_dump_octet_string(tlv, tag, level);
            *candump = false;
            break;
        case ASN1_TAG_BOOLEAN:
            asn1_tag_dump_boolean(tlv, tag, level);
            *candump = false;
            break;
        case ASN1_TAG_INTEGER:
            asn1_tag_dump_integer(tlv, tag, level);
            *candump = false;
            break;
        case ASN1_TAG_UTC_TIME:
            asn1_tag_dump_str_time(tlv, tag, level, false, candump);
            break;
        case ASN1_TAG_STR_TIME:
            asn1_tag_dump_str_time(tlv, tag, level, true, candump);
            break;
        case ASN1_TAG_OBJECT_ID:
            asn1_tag_dump_object_id(tlv, tag, level);
            *candump = false;
            break;
        case ASN1_TAG_HEX:
            asn1_tag_dump_hex(tlv, tag, level);
            *candump = false;
            break;
        case ASN1_TAG_BIT_STRING:
            asn1_tag_dump_bitstring(tlv, tag, level);
            *candump = false;
            break;
    };

    return true;
}
