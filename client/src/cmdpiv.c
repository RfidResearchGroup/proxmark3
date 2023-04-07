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
// PIV commands
//-----------------------------------------------------------------------------

#include "cmdpiv.h"

#include "comms.h" // DropField
#include "cmdsmartcard.h" // smart_select
#include "cmdtrace.h"
#include "cliparser.h"
#include "cmdparser.h"
#include "commonutil.h"  // Mem[LB]eToUintXByte
#include "emv/tlv.h"
#include "proxmark3.h"
#include "cmdhf14a.h"
#include "fileutils.h"
#include "crypto/asn1utils.h"
#include "protocols.h"

static int CmdHelp(const char *Cmd);

static uint8_t PIV_APPLET[9] = "\xA0\x00\x00\x03\x08\x00\x00\x10\x00";

enum piv_condition_t {
    PIV_MANDATORY,
    PIV_CONDITIONAL,
    PIV_OPTIONAL,
    PIV_INVALID = 0xff,
};

struct piv_container {
    uint32_t id;
    const uint8_t *tlv_tag;  // tag is between 1 and 3 bytes.
    size_t len;  // length of the hex-form if the tag (i.e. twice the byte size) for pretty printing
    enum piv_condition_t cond;
    const char *name;
};

#define PIV_TAG_ID(x) ((const uint8_t *)(x))
#define PIV_CONTAINER_FINISH { (~0), NULL, 0, PIV_INVALID, NULL }

// Source: SP800-73-4, Annex A
// https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-73-4.pdf
static const struct piv_container PIV_CONTAINERS[] = {
    {0xDB00, PIV_TAG_ID("\x5F\xC1\x07"), 3, PIV_MANDATORY,   "Card Capability Container"},
    {0x3000, PIV_TAG_ID("\x5F\xC1\x02"), 3, PIV_MANDATORY,   "Card Holder Unique Identifier"},
    {0x0101, PIV_TAG_ID("\x5F\xC1\x05"), 3, PIV_MANDATORY,   "X.509 Certificate for PIV Authentication (key ref 9A)"},
    {0x6010, PIV_TAG_ID("\x5F\xC1\x03"), 3, PIV_MANDATORY,   "Cardholder Fingerprints"},
    {0x9000, PIV_TAG_ID("\x5F\xC1\x06"), 3, PIV_MANDATORY,   "Security Object"},
    {0x6030, PIV_TAG_ID("\x5F\xC1\x08"), 3, PIV_MANDATORY,   "Cardholder Facial Image"},
    {0x0500, PIV_TAG_ID("\x5F\xC1\x01"), 3, PIV_MANDATORY,   "X.509 Certificate for Card Authentication (key ref 9E)"},
    {0x0100, PIV_TAG_ID("\x5F\xC1\x0A"), 3, PIV_CONDITIONAL, "X.509 Certificate for Digital Signature (key ref 9C)"},
    {0x0102, PIV_TAG_ID("\x5F\xC1\x0B"), 3, PIV_CONDITIONAL, "X.509 Certificate for Key Management (key ref 9D)"},
    {0x3001, PIV_TAG_ID("\x5F\xC1\x09"), 3, PIV_OPTIONAL,    "Printed Information"},
    {0x6050, PIV_TAG_ID("\x7E"), 1, PIV_OPTIONAL,    "Discovery Object"},
    {0x6060, PIV_TAG_ID("\x5F\xC1\x0C"), 3, PIV_OPTIONAL,    "Key History Object"},
    {0x1001, PIV_TAG_ID("\x5F\xC1\x0D"), 3, PIV_OPTIONAL,    "Retired X.509 Certificate for Key Management 1 (key ref 82)"},
    {0x1002, PIV_TAG_ID("\x5F\xC1\x0E"), 3, PIV_OPTIONAL,    "Retired X.509 Certificate for Key Management 2 (key ref 83)"},
    {0x1003, PIV_TAG_ID("\x5F\xC1\x0F"), 3, PIV_OPTIONAL,    "Retired X.509 Certificate for Key Management 3 (key ref 84)"},
    {0x1004, PIV_TAG_ID("\x5F\xC1\x10"), 3, PIV_OPTIONAL,    "Retired X.509 Certificate for Key Management 4 (key ref 85)"},
    {0x1005, PIV_TAG_ID("\x5F\xC1\x11"), 3, PIV_OPTIONAL,    "Retired X.509 Certificate for Key Management 5 (key ref 86)"},
    {0x1006, PIV_TAG_ID("\x5F\xC1\x12"), 3, PIV_OPTIONAL,    "Retired X.509 Certificate for Key Management 6 (key ref 87)"},
    {0x1007, PIV_TAG_ID("\x5F\xC1\x13"), 3, PIV_OPTIONAL,    "Retired X.509 Certificate for Key Management 7 (key ref 88)"},
    {0x1008, PIV_TAG_ID("\x5F\xC1\x14"), 3, PIV_OPTIONAL,    "Retired X.509 Certificate for Key Management 8 (key ref 89)"},
    {0x1009, PIV_TAG_ID("\x5F\xC1\x15"), 3, PIV_OPTIONAL,    "Retired X.509 Certificate for Key Management 9 (key ref 8A)"},
    {0x100A, PIV_TAG_ID("\x5F\xC1\x16"), 3, PIV_OPTIONAL,    "Retired X.509 Certificate for Key Management 10 (key ref 8B)"},
    {0x100B, PIV_TAG_ID("\x5F\xC1\x17"), 3, PIV_OPTIONAL,    "Retired X.509 Certificate for Key Management 11 (key ref 8C)"},
    {0x100C, PIV_TAG_ID("\x5F\xC1\x18"), 3, PIV_OPTIONAL,    "Retired X.509 Certificate for Key Management 12 (key ref 8D)"},
    {0x100D, PIV_TAG_ID("\x5F\xC1\x19"), 3, PIV_OPTIONAL,    "Retired X.509 Certificate for Key Management 13 (key ref 8E)"},
    {0x100E, PIV_TAG_ID("\x5F\xC1\x1A"), 3, PIV_OPTIONAL,    "Retired X.509 Certificate for Key Management 14 (key ref 8F)"},
    {0x100F, PIV_TAG_ID("\x5F\xC1\x1B"), 3, PIV_OPTIONAL,    "Retired X.509 Certificate for Key Management 15 (key ref 90)"},
    {0x1010, PIV_TAG_ID("\x5F\xC1\x1C"), 3, PIV_OPTIONAL,    "Retired X.509 Certificate for Key Management 16 (key ref 91)"},
    {0x1011, PIV_TAG_ID("\x5F\xC1\x1D"), 3, PIV_OPTIONAL,    "Retired X.509 Certificate for Key Management 17 (key ref 92)"},
    {0x1012, PIV_TAG_ID("\x5F\xC1\x1E"), 3, PIV_OPTIONAL,    "Retired X.509 Certificate for Key Management 18 (key ref 93)"},
    {0x1013, PIV_TAG_ID("\x5F\xC1\x1F"), 3, PIV_OPTIONAL,    "Retired X.509 Certificate for Key Management 19 (key ref 94)"},
    {0x1014, PIV_TAG_ID("\x5F\xC1\x20"), 3, PIV_OPTIONAL,    "Retired X.509 Certificate for Key Management 20 (key ref 95)"},
    {0x1015, PIV_TAG_ID("\x5F\xC1\x21"), 3, PIV_OPTIONAL,    "Cardholder Iris Images"},
    {0x1016, PIV_TAG_ID("\x7F\x61"), 2, PIV_OPTIONAL,    "Biometric Information Templates Group Template"},
    {0x1017, PIV_TAG_ID("\x5F\xC1\x22"), 3, PIV_OPTIONAL,    "Secure Messaging Certificate Signer"},
    {0x1018, PIV_TAG_ID("\x5F\xC1\x23"), 3, PIV_OPTIONAL,    "Pairing Code Reference Data Container"},
    PIV_CONTAINER_FINISH,
};

enum piv_tag_t {
    PIV_TAG_GENERIC,
    PIV_TAG_HEXDUMP,
    PIV_TAG_STRING,
    PIV_TAG_PRINTSTR,
    PIV_TAG_NUMERIC,
    PIV_TAG_YYYYMMDD,
    PIV_TAG_ENUM,
    PIV_TAG_TLV,
    PIV_TAG_GUID,
    PIV_TAG_CERT,
    PIV_TAG_FASCN,
};

struct piv_tag {
    tlv_tag_t tag;
    const char *name;
    enum piv_tag_t type;
    const void *data;
};

struct piv_tag_enum {
    unsigned long value;
    const char *name;
};

#define PIV_ENUM_FINISH { (~0), NULL }

// From table 6-2 in SP800-78 specification
static const struct piv_tag_enum PIV_CRYPTO_ALG[] = {
    {0x00, "3 Key 3DES - ECB"},
    {0x03, "3 Key 3DES - ECB"}, // Not a typo, 2 identifiers for the same algorithm
    {0x06, "RSA 1024 bit"},
    {0x07, "RSA 2048 bit"},
    {0x08, "AES-128 ECB"},
    {0x0A, "AES-192 ECB"},
    {0x0C, "AES-256 ECB"},
    {0x11, "ECC P-256"},
    {0x14, "ECC P-384"},
    {0x27, "Cipher Suite 2"},
    {0x2E, "Cipher Suite 7"},
    PIV_ENUM_FINISH,
};

static const struct piv_tag_enum PIV_CERT_INFO[] = {
    {0x00, "Uncompressed"},
    {0x01, "GZIP Compressed"},
    PIV_ENUM_FINISH,
};

static const struct piv_tag piv_tags[] = {
    { 0x00,     "Unknown ???",                                                 PIV_TAG_HEXDUMP,  NULL },
    { 0x01,     "Name",                                                        PIV_TAG_PRINTSTR, NULL },
    { 0x02,     "Employee Affiliation",                                        PIV_TAG_PRINTSTR, NULL },
    { 0x04,     "Expiry Date",                                                 PIV_TAG_PRINTSTR, NULL },
    { 0x05,     "Agency Card Serial Number",                                   PIV_TAG_PRINTSTR, NULL },
    { 0x06,     "Issuer identification",                                       PIV_TAG_PRINTSTR, NULL },
    { 0x07,     "Organization Affiliation (Line 1)",                           PIV_TAG_PRINTSTR, NULL },
    { 0x08,     "Organization Affiliation (Line 2)",                           PIV_TAG_PRINTSTR, NULL },

    { 0x30,     "FASC-N",                                                      PIV_TAG_FASCN,    NULL },
    { 0x32,     "Organizational Identifier [deprecated]",                      PIV_TAG_HEXDUMP,  NULL },
    { 0x33,     "DUNS [deprecated]",                                           PIV_TAG_HEXDUMP,  NULL },
    { 0x34,     "GUID",                                                        PIV_TAG_GUID,     NULL },
    { 0x35,     "Expiry Date",                                                 PIV_TAG_YYYYMMDD, NULL },
    { 0x36,     "Cardholder UUID",                                             PIV_TAG_GUID,     NULL },
    { 0x3d,     "Authentication Key Map",                                      PIV_TAG_HEXDUMP,  NULL },
    { 0x3e,     "Issuer Asymmetric Signature",                                 PIV_TAG_CERT,     NULL },

    { 0x4f,     "Application Identifier (AID)",                                PIV_TAG_STRING,   NULL },

    { 0x50,     "Application Label",                                           PIV_TAG_PRINTSTR, NULL },
    { 0x53,     "Discretionary data (or template)",                            PIV_TAG_TLV,      NULL },
    { 0x5f2f,   "PIN Usage Policy",                                            PIV_TAG_HEXDUMP,  NULL },
    { 0x5f50,   "Issuer URL",                                                  PIV_TAG_PRINTSTR, NULL },

    { 0x61,     "Application Property Template",                               PIV_TAG_GENERIC,  NULL },

    { 0x70,     "Certificate",                                                 PIV_TAG_CERT,     NULL },
    { 0x71,     "CertInfo",                                                    PIV_TAG_ENUM,     PIV_CERT_INFO },
    { 0x72,     "MSCUID [deprecated]",                                         PIV_TAG_HEXDUMP,  NULL },
    { 0x79,     "Coexistent tag allocation authority",                         PIV_TAG_HEXDUMP,  NULL },
    { 0x7f21,   "Intermediate CVC",                                            PIV_TAG_HEXDUMP,  NULL },
    { 0x7f60,   "Biometric Information Template",                              PIV_TAG_GENERIC,  NULL },

    { 0x80,     "Cryptographic algorithm identifier",                          PIV_TAG_ENUM,     PIV_CRYPTO_ALG },

    { 0x99,     "Pairing Code",                                                PIV_TAG_PRINTSTR, NULL },

    { 0xac,     "Cryptographic algorithms supported",                          PIV_TAG_GENERIC,  NULL },

    { 0xb4,     "Security Object Buffer (deprecated)",                         PIV_TAG_GENERIC,  NULL },
    { 0xba,     "Mapping of DG to Container ID",                               PIV_TAG_HEXDUMP,  NULL },
    { 0xbb,     "Security Object",                                             PIV_TAG_CERT,     NULL },
    { 0xbc,     "Fingerprint I & II or Image for Visual Verification",         PIV_TAG_GENERIC,  NULL },

    { 0xc1,     "keysWithOnCardCerts",                                         PIV_TAG_NUMERIC,  NULL },
    { 0xc2,     "keysWithOffCardCerts",                                        PIV_TAG_NUMERIC,  NULL },

    { 0xe3,     "Extended Application CardURL [deprecated]",                   PIV_TAG_GENERIC,  NULL },
    { 0xee,     "Buffer Length [deprecated]",                                  PIV_TAG_NUMERIC,  NULL },

    { 0xf0,     "Card Identifier",                                             PIV_TAG_STRING,   NULL },
    { 0xf1,     "Capability Container version number",                         PIV_TAG_NUMERIC,  NULL },
    { 0xf2,     "Capability Grammar version number",                           PIV_TAG_NUMERIC,  NULL },
    { 0xf3,     "Application Card URL",                                        PIV_TAG_PRINTSTR, NULL },
    { 0xf4,     "PKCS#15",                                                     PIV_TAG_NUMERIC,  NULL },
    { 0xf5,     "Registered Data Model Number",                                PIV_TAG_NUMERIC,  NULL },
    { 0xf6,     "Access Control Rule Table",                                   PIV_TAG_HEXDUMP,  NULL },
    { 0xf7,     "Card APDUs",                                                  PIV_TAG_GENERIC,  NULL },
    { 0xfa,     "Redirection Tag",                                             PIV_TAG_GENERIC,  NULL },
    { 0xfb,     "Capability Tuples (CT)",                                      PIV_TAG_GENERIC,  NULL },
    { 0xfc,     "Status Tuples (ST)",                                          PIV_TAG_GENERIC,  NULL },
    { 0xfd,     "Next CCC",                                                    PIV_TAG_GENERIC,  NULL },
    { 0xfe,     "Error Detection Code",                                        PIV_TAG_GENERIC,  NULL },
};

struct guid {
    uint32_t part1;
    uint16_t part2;
    uint16_t part3;
    uint8_t data[8];
};

static void parse_guid(const uint8_t *data, struct guid *guid) {
    if (guid == NULL) {
        return;
    }
    size_t ofs = 0;
    guid->part1 = MemBeToUint4byte(&data[ofs]);
    ofs += sizeof(uint32_t);
    guid->part2 = MemBeToUint2byte(&data[ofs]);
    ofs += sizeof(uint16_t);
    guid->part3 = MemBeToUint2byte(&data[ofs]);
    ofs += sizeof(uint16_t);
    for (size_t i = 0; i < sizeof(guid->data); i++) {
        guid->data[i] = data[ofs + i];
    }
}

static void piv_print_cb(void *data, const struct tlv *tlv, int level, bool is_leaf);
static bool piv_tag_dump(const struct tlv *tlv, int level);

static void PrintChannel(Iso7816CommandChannel channel) {
    switch (channel) {
        case CC_CONTACTLESS:
            PrintAndLogEx(INFO, "Selected channel... " _GREEN_("CONTACTLESS (T=CL)"));
            break;
        case CC_CONTACT:
            PrintAndLogEx(INFO, "Selected channel... " _GREEN_("CONTACT"));
            break;
    }
}

static int piv_sort_tag(tlv_tag_t tag) {
    return (int)(tag >= 0x100 ? tag : tag << 8);
}

static int piv_tlv_compare(const void *a, const void *b) {
    const struct tlv *tlv = a;
    const struct piv_tag *tag = b;

    return piv_sort_tag(tlv->tag) - (piv_sort_tag(tag->tag));
}

static const struct piv_tag *piv_get_tag(const struct tlv *tlv) {
    const struct piv_tag *tag = bsearch(tlv, piv_tags, ARRAYLEN(piv_tags),
                                        sizeof(piv_tags[0]), piv_tlv_compare);
    return tag != NULL ? tag : &piv_tags[0];
}

static unsigned long piv_value_numeric(const struct tlv *tlv, unsigned start, unsigned end) {
    unsigned long ret = 0;
    int i;

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

static void piv_tag_dump_yyyymmdd(const struct tlv *tlv, const struct piv_tag *tag, int level) {
    bool is_printable = true;
    for (size_t i = 0; i < tlv->len; i++) {
        if ((tlv->value[i] < 0x30) || (tlv->value[i] > 0x39)) {
            is_printable = false;
            break;
        }
    }
    if (is_printable) {
        PrintAndLogEx(NORMAL, " " _YELLOW_("%c%c%c%c.%c%c.%c%c"),
                      tlv->value[0], tlv->value[1], tlv->value[2], tlv->value[3],
                      tlv->value[4], tlv->value[5],
                      tlv->value[6], tlv->value[7]
                     );
    } else {
        PrintAndLogEx(NORMAL, " " _YELLOW_("%04lu.%02lu.%02lu"),
                      piv_value_numeric(tlv, 0, 4),
                      piv_value_numeric(tlv, 4, 6),
                      piv_value_numeric(tlv, 6, 8)
                     );
    }
}

static void piv_tag_dump_enum(const struct tlv *tlv, const struct piv_tag *tag, int level) {
    const struct piv_tag_enum *values = tag->data;
    for (size_t i = 0; values[i].name != NULL; i++) {
        if (values[i].value == tlv->value[0]) {
            PrintAndLogEx(NORMAL, " %u - '" _YELLOW_("%s")"'",
                          tlv->value[0], values[i].name);
            return;
        }
    }
    PrintAndLogEx(NORMAL, " %u - " _RED_("Unknown??"), tlv->value[0]);
}

static void piv_tag_dump_tlv(const struct tlv *tlv, const struct piv_tag *tag, int level) {
    // We don't use parsing methods because we need to discard constructed tags
    const unsigned char *buf = tlv->value;
    size_t left = tlv->len;

    while (left) {
        struct tlv sub_tlv;
        //const struct piv_tag *sub_tag;

        if (!tlv_parse_tl(&buf, &left, &sub_tlv)) {
            PrintAndLogEx(INFO, "%*sInvalid Tag-Len", (level * 4), " ");
            continue;
        }
        sub_tlv.value = buf;
        piv_tag_dump(&sub_tlv, level + 1);
        buf += sub_tlv.len;
        left -= sub_tlv.len;
    }

}

static void piv_print_cert(const uint8_t *buf, const size_t len, int level) {
    char prefix[256] = {0};
    PrintAndLogEx(NORMAL, "");
    snprintf(prefix, sizeof(prefix), "%*s", 4 * level, " ");
    // TODO: when mbedTLS has a new release with the PCKS7 parser, we can replace the generic ASN.1 print
    // The pull request has been merged end of Nov 2022.
    asn1_print((uint8_t *) buf, len, prefix);
}

static void piv_print_fascn(const uint8_t *buf, const size_t len, int level) {
    const char *encoded[32] = {
        _RED_("?"),       // 0b00000
        "0",              // 0b00001
        "8",              // 0b00010
        _RED_("?"),       // 0b00011
        "4",              // 0b00100
        _RED_("?"),       // 0b00101
        _RED_("?"),       // 0b00110
        _RED_("?"),       // 0b00111
        "2",              // 0b01000
        _RED_("?"),       // 0b01001
        _RED_("?"),       // 0b01010
        _RED_("?"),       // 0b01011
        _RED_("?"),       // 0b01100
        "6",              // 0b01101
        _RED_("?"),       // 0b01110
        _RED_("?"),       // 0b01111
        "1",              // 0b10000
        _RED_("?"),       // 0b10001
        _RED_("?"),       // 0b10010
        "9",              // 0b10011
        _RED_("?"),       // 0b10100
        "5",              // 0b10101
        _GREEN_(" FS "),  // 0b10110
        _RED_("?"),       // 0b10111
        _RED_("?"),       // 0b11000
        "3",              // 0b11001
        _YELLOW_("SS "),  // 0b11010
        _RED_("?"),       // 0b11011
        "7",              // 0b11100
        _RED_("?"),       // 0b11101
        _RED_("?"),       // 0b11110
        _YELLOW_(" ES"),  // 0b11111
    };
    const uint8_t cycle[8] = {5, 2, 7, 4, 1, 6, 3, 8};

    PrintAndLogEx(INFO, "%*s" NOLF, 4 * level, " ");
    // Buffer is 40 bytes but last byte is LRC that we process separately
    for (int i = 0; i < 39; i++) {
        uint8_t tmp = buf[(5 * i) >> 3];
        uint8_t rot = cycle[i & 7];
        // rotate left to get the bits in place
        tmp = (tmp << rot) | (tmp >> (8 - rot));
        // append bits from next byte if needed
        if (rot < 5) {
            uint8_t tmp2 = buf[(5 * (i + 1)) >> 3];
            tmp2 = (tmp2 << rot) | (tmp2 >> (8 - rot));
            tmp &= 0x1f << rot;
            tmp |= tmp2 & ((1 << rot) - 1);
        }
        PrintAndLogEx(NORMAL, "%s" NOLF, encoded[tmp & 0x1f]);
    }
    uint8_t lrc = buf[24] & 0x1f;
    PrintAndLogEx(NORMAL, " LRC=[" _YELLOW_("%02x") "]", lrc);
}

static bool piv_tag_dump(const struct tlv *tlv, int level) {
    if (tlv == NULL) {
        PrintAndLogEx(FAILED, "NULL");
        return false;
    }

    const struct piv_tag *tag = piv_get_tag(tlv);

    PrintAndLogEx(INFO, "%*s--%2x[%02zx] '%s':" NOLF, (level * 4), " ", tlv->tag, tlv->len, tag->name);

    switch (tag->type) {
        case PIV_TAG_GENERIC:
            PrintAndLogEx(NORMAL, "");
            break;
        case PIV_TAG_HEXDUMP:
            PrintAndLogEx(NORMAL, "");
            print_buffer(tlv->value, tlv->len, level + 1);
            break;
        case PIV_TAG_STRING:
            PrintAndLogEx(NORMAL, " '" _YELLOW_("%s")"'", sprint_hex_inrow(tlv->value, tlv->len));
            break;
        case PIV_TAG_NUMERIC:
            PrintAndLogEx(NORMAL, " " _YELLOW_("%lu"), piv_value_numeric(tlv, 0, tlv->len * 2));
            break;
        case PIV_TAG_YYYYMMDD:
            piv_tag_dump_yyyymmdd(tlv, tag, level);
            break;
        case PIV_TAG_ENUM:
            piv_tag_dump_enum(tlv, tag, level + 1);
            break;
        case PIV_TAG_TLV:
            PrintAndLogEx(NORMAL, "");
            piv_tag_dump_tlv(tlv, tag, level);
            break;
        case PIV_TAG_PRINTSTR:
            PrintAndLogEx(NORMAL, " '" NOLF);
            for (size_t i = 0; i < tlv->len; i++) {
                PrintAndLogEx(NORMAL, _YELLOW_("%c") NOLF, tlv->value[i]);
            }
            PrintAndLogEx(NORMAL, "'");
            break;
        case PIV_TAG_GUID:
            if (tlv->len != 16) {
                PrintAndLogEx(NORMAL, _RED_("<Invalid>"));
            } else {
                struct guid guid = {0};
                parse_guid(tlv->value, &guid);
                PrintAndLogEx(NORMAL, " " _YELLOW_("{%08x-%04x-%04x-") NOLF, guid.part1, guid.part2, guid.part3);
                for (size_t i = 0; i < 8; i++) {
                    PrintAndLogEx(NORMAL, _YELLOW_("%02x") NOLF, guid.data[i]);
                }
                PrintAndLogEx(NORMAL, _YELLOW_("}"));
            }
            break;
        case PIV_TAG_CERT:
            piv_print_cert(tlv->value, tlv->len, level + 2);
            break;
        case PIV_TAG_FASCN:
            PrintAndLogEx(NORMAL, " '" _YELLOW_("%s")"'", sprint_hex_inrow(tlv->value, tlv->len));
            if (tlv->len == 25) {
                piv_print_fascn(tlv->value, tlv->len, level + 2);
            }
            break;
    };

    return true;
}

static void piv_print_cb(void *data, const struct tlv *tlv, int level, bool is_leaf) {
    piv_tag_dump(tlv, level);
    if (is_leaf) {
        print_buffer(tlv->value, tlv->len, level);
    }
}

static void PrintTLV(const struct tlvdb *tlvdb) {
    if (tlvdb) {
        tlvdb_visit(tlvdb, piv_print_cb, NULL, 0);
    }
}

static void PrintTLVFromBuffer(const uint8_t *buf, size_t len) {
    if (buf == NULL || len == 0) {
        return;
    }
    struct tlvdb_root *root = calloc(1, sizeof(*root) + len);
    if (root == NULL) {
        return;
    }
    root->len = len;
    memcpy(root->buf, buf, len);
    if (tlvdb_parse_root_multi(root) == true) {
        PrintTLV(&(root->db));
    } else {
        PrintAndLogEx(WARNING, "TLV ERROR: Can't parse buffer as TLV tree.");
    }
    tlvdb_root_free(root);
}

static int PivGetData(Iso7816CommandChannel channel, const uint8_t tag[], size_t tag_len, bool verbose, struct tlvdb_root **result, uint16_t *sw) {
    uint8_t apdu_data[5] = {0x5c, 0x00};

    *result = NULL;
    *sw = 0;

    if (tag_len < 1 || tag_len > 3) {
        return PM3_EINVARG;
    }

    apdu_data[1] = tag_len;
    memcpy(&apdu_data[2], tag, tag_len);

    sAPDU_t apdu = {
        .CLA = 0x00,
        .INS = 0xCB,
        .P1 = 0x3F,
        .P2 = 0xFF,
        .Lc = tag_len + 2,
        .data = apdu_data
    };

    // Answer can be chained. Let's use a dynamically allocated buffer.
    size_t capacity = PM3_CMD_DATA_SIZE;
    struct tlvdb_root *root = calloc(1, sizeof(*root) + capacity);

    if (root == NULL) {
        return PM3_EMALLOC;
    }
    root->len = 0;

    size_t more_data = 0;
    do {
        size_t received = 0;
        int res = Iso7816ExchangeEx(channel, false, true, apdu, (more_data != 0), more_data, &(root->buf[root->len]), capacity - root->len, &received, sw);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Sending APDU failed with code %d", res);
            free(root);
            return res;
        }
        root->len += received;
        if (((*sw) & 0xff00) == 0x6100) {
            // More data
            more_data = (*sw) & 0xff;
            if (more_data == 0x00 || more_data > MAX_APDU_SIZE) {
                more_data = MAX_APDU_SIZE;
            }
            apdu.CLA = 0x00;
            apdu.INS = 0xC0;
            apdu.P1 = 0x00;
            apdu.P2 = 0x00;
            apdu.Lc = 0;
            apdu.data = NULL;
            if ((capacity - root->len) < PM3_CMD_DATA_SIZE) {
                PrintAndLogEx(DEBUG, "Adding more capacity to buffer...");
                capacity += PM3_CMD_DATA_SIZE;
                struct tlvdb_root *new_root = realloc(root, sizeof(*root) + capacity);
                if (new_root == NULL) {
                    PrintAndLogEx(FAILED, "Running out of memory while re-allocating buffer");
                    //free(root);
                    tlvdb_root_free(root);
                    return PM3_EMALLOC;
                }
                root = new_root;
            }
        }
        if ((*sw) == ISO7816_OK) {
            more_data = 0;
        }
    } while (more_data > 0);

    // Now we can try parse the TLV and return it
    *result = root;
    if (*sw == ISO7816_OK && tlvdb_parse_root(root) == true) {
        return PM3_SUCCESS;
    }
    if (verbose == true) {
        PrintAndLogEx(WARNING, "Couldn't parse TLV answer.");
    }
    return PM3_SUCCESS;
}

static int PivGetDataByCidAndPrint(Iso7816CommandChannel channel, const struct piv_container *cid, bool decodeTLV, bool verbose) {
    struct tlvdb_root *root = NULL;

    if (cid == NULL) {
        return PM3_SUCCESS;
    }

    PrintAndLogEx(INFO, "Getting %s [" _GREEN_("%s") "]", cid->name, sprint_hex_inrow(cid->tlv_tag, cid->len));

    uint16_t sw = 0;

    if (PivGetData(channel, cid->tlv_tag, cid->len, verbose, &root, &sw) == PM3_SUCCESS) {
        switch (sw) {
            case ISO7816_OK:
                if (decodeTLV == true) {
                    PrintTLV(&(root->db));
                } else {
                    print_buffer(root->buf, root->len, 0);
                }
                break;
            case ISO7816_FILE_NOT_FOUND:
                PrintAndLogEx(FAILED, "Container not found.");
                break;
            case ISO7816_SECURITY_STATUS_NOT_SATISFIED:
                PrintAndLogEx(WARNING, "Security conditions not met.");
                break;
            default:
                if (verbose == true) {
                    PrintAndLogEx(INFO, "APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
                }
                break;
        }
        tlvdb_root_free(root);
    }
    return PM3_SUCCESS;
}

static int PivGetDataByTagAndPrint(Iso7816CommandChannel channel, const uint8_t tag[], size_t tag_len, bool decodeTLV, bool verbose) {
    int idx = 0;

    for (; PIV_CONTAINERS[idx].len != 0; idx++) {
        if ((tag_len == PIV_CONTAINERS[idx].len) && (memcmp(tag, PIV_CONTAINERS[idx].tlv_tag, tag_len) == 0)) {
            break;
        }
    }
    if (PIV_CONTAINERS[idx].len == 0) {
        struct piv_container cid = {0x00, tag, tag_len, PIV_OPTIONAL, "Getting unknown contained ID"};
        return PivGetDataByCidAndPrint(channel, &cid, decodeTLV, verbose);
    }
    return PivGetDataByCidAndPrint(channel, &(PIV_CONTAINERS[idx]), decodeTLV, verbose);
}

static int PivAuthenticateSign(Iso7816CommandChannel channel, uint8_t alg_id, uint8_t key_id, uint8_t nonce[], size_t nonce_len, void **result, bool decodeTLV, bool verbose) {
    const size_t MAX_NONCE_LEN = 0x7a;
    if (nonce_len > MAX_NONCE_LEN) {
        if (verbose == true) {
            PrintAndLogEx(WARNING, "Nonce cannot exceed %zu bytes. Got %zu bytes.", MAX_NONCE_LEN, nonce_len);
        }
        return PM3_EINVARG;
    }
    uint8_t apdu_buf[APDU_RES_LEN] = {0x7c, nonce_len + 4, 0x82, 0x00, 0x81, nonce_len};
    memcpy(&apdu_buf[6], nonce, nonce_len);
    sAPDU_t apdu = {
        0x00, 0x87, alg_id, key_id,
        6 + nonce_len, apdu_buf
    };

    uint16_t sw = 0;
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    int res = Iso7816ExchangeEx(channel, false, true, apdu, false, 0, buf, APDU_RES_LEN, &len, &sw);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Sending APDU failed with code %d", res);
        return res;
    }
    if (sw != ISO7816_OK) {
        if (verbose == true) {
            PrintAndLogEx(INFO, "Unexpected APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        }
        return PM3_EFAILED;
    }
    if (verbose == true) {
        if (decodeTLV == true) {
            PrintTLVFromBuffer(buf, len);
        } else {
            print_buffer(buf, len, 0);
        }
    }
    return PM3_SUCCESS;
}

static int PivSelect(Iso7816CommandChannel channel, bool activateField, bool leaveFieldOn, bool decodeTLV, bool silent, uint8_t applet[], size_t appletLen) {
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    int res = Iso7816Select(channel, activateField, leaveFieldOn, applet, appletLen, buf, sizeof(buf), &len, &sw);
    if ((sw != 0) && (silent == false)) {
        PrintAndLogEx(INFO, "APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
    }

    if (res != PM3_SUCCESS || sw != ISO7816_OK) {
        PrintAndLogEx(FAILED, "Applet selection failed. Card is not a PIV card.");
        return res;
    }

    if (silent == false) {
        if (decodeTLV == true) {
            PrintTLVFromBuffer(buf, len);
        } else {
            print_buffer(buf, len, 0);
        }
    }
    return PM3_SUCCESS;
}

static int CmdPIVSelect(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "piv select",
                  "Executes select applet command",
                  "piv select -s   -> select card, select applet\n"
                  "piv select -st --aid a00000030800001000   -> select card, select applet a00000030800001000, show result in TLV\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("sS",  "select",  "Activate field and select applet"),
        arg_lit0("kK",  "keep",    "Keep field for next command"),
        arg_lit0("aA",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("tT",  "tlv",     "TLV decode results"),
        arg_lit0("wW",  "wired",   "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_str0(NULL,  "aid", "<hex>", "Applet ID to select. By default A0000003080000100 will be used"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool activateField = arg_get_lit(ctx, 1);
    bool leaveSignalON = arg_get_lit(ctx, 2);
    bool APDULogging = arg_get_lit(ctx, 3);
    bool decodeTLV = arg_get_lit(ctx, 4);
    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 5)) {
        channel = CC_CONTACT;
    }

    PrintChannel(channel);

    uint8_t applet_id[APDU_AID_LEN] = {0};
    int aid_len = 0;
    CLIGetHexWithReturn(ctx, 6, applet_id, &aid_len);
    if (aid_len == 0) {
        memcpy(applet_id, PIV_APPLET, sizeof(PIV_APPLET));
        aid_len = sizeof(PIV_APPLET);
    }

    CLIParserFree(ctx);

    SetAPDULogging(APDULogging);

    return PivSelect(channel, activateField, leaveSignalON, decodeTLV, false, applet_id, aid_len);
}

static int CmdPIVGetData(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "piv getdata",
                  "Get a data container of a given tag",
                  "piv getdata -s 5fc102   -> select card, select applet, get card holder unique identifer\n"
                  "piv getdata -st 5fc102   -> select card, select applet, get card holder unique identifer, show result in TLV\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("sS",  "select",  "Activate field and select applet"),
        arg_lit0("kK",  "keep",    "Keep field for next command"),
        arg_lit0("aA",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("tT",  "tlv",     "TLV decode results"),
        arg_lit0("wW",  "wired",   "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_str0(NULL,  "aid", "<hex>", "Applet ID to select. By default A0000003080000100 will be used"),
        arg_str1(NULL, NULL, "<hex>", "Tag ID to read, between 1 and 3 bytes."),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool activateField = arg_get_lit(ctx, 1);
    bool leaveSignalON = arg_get_lit(ctx, 2);
    bool APDULogging = arg_get_lit(ctx, 3);
    bool decodeTLV = arg_get_lit(ctx, 4);
    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 5))
        channel = CC_CONTACT;
    PrintChannel(channel);

    uint8_t applet_id[APDU_AID_LEN] = {0};
    int aid_len = 0;
    CLIGetHexWithReturn(ctx, 6, applet_id, &aid_len);
    if (aid_len == 0) {
        memcpy(applet_id, PIV_APPLET, sizeof(PIV_APPLET));
        aid_len = sizeof(PIV_APPLET);
    }

    uint8_t tag[4] = {0};
    int tag_len = 0;
    CLIGetHexWithReturn(ctx, 7, tag, &tag_len);

    CLIParserFree(ctx);

    if ((tag_len < 1) || (tag_len > 3)) {
        PrintAndLogEx(WARNING, "Tag should be between 1 and 3 bytes. Got %i", tag_len);
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);

    int res = 0;
    if (activateField == true) {
        res = PivSelect(channel, activateField, true, decodeTLV, true, applet_id, aid_len);
        if (res != PM3_SUCCESS) {
            if (leaveSignalON == false) {
                DropFieldEx(channel);
            }
            return res;
        }
    }
    res = PivGetDataByTagAndPrint(channel, tag, tag_len, decodeTLV, false);
    if (leaveSignalON == false) {
        DropFieldEx(channel);
    }
    return res;
}

static int CmdPIVAuthenticateSign(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "piv sign",
                  "Send a nonce and ask the PIV card to sign it",
                  "piv sign -sk   -> select card, select applet, sign a NULL nonce\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("sS",  "select",  "Activate field and select applet"),
        arg_lit0("kK",  "keep",    "Keep field for next command"),
        arg_lit0("aA",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("tT",  "tlv",     "TLV decode results"),
        arg_lit0("wW",  "wired",   "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_str0(NULL,  "aid", "<hex>", "Applet ID to select. By default A0000003080000100 will be used"),
        arg_str1(NULL,  "nonce", "<hex>", "Nonce to sign."),
        arg_int0(NULL,  "slot", "<dec id>", "Slot number. Default will be 0x9E (card auth cert)."),
        arg_int0(NULL,  "alg", "<dec>", "Algorithm to use to sign. Example values: 06=RSA-1024, 07=RSA-2048, 11=ECC-P256 (default), 14=ECC-P384"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool activateField = arg_get_lit(ctx, 1);
    bool leaveSignalON = arg_get_lit(ctx, 2);
    bool APDULogging = arg_get_lit(ctx, 3);
    bool decodeTLV = arg_get_lit(ctx, 4);
    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 5))
        channel = CC_CONTACT;
    PrintChannel(channel);

    uint8_t applet_id[APDU_AID_LEN] = {0};
    int aid_len = 0;
    CLIGetHexWithReturn(ctx, 6, applet_id, &aid_len);
    if (aid_len == 0) {
        memcpy(applet_id, PIV_APPLET, sizeof(PIV_APPLET));
        aid_len = sizeof(PIV_APPLET);
    }

    uint8_t nonce[APDU_RES_LEN] = {0};
    int nonce_len = 0;
    CLIGetHexWithReturn(ctx, 7, nonce, &nonce_len);

    int key_slot = arg_get_int_def(ctx, 8, 0x9e);
    int alg_id = arg_get_int_def(ctx, 9, 0x11);

    CLIParserFree(ctx);

    if (key_slot > 0xff) {
        PrintAndLogEx(FAILED, "Key slot must fit on 1 byte.");
        return PM3_EINVARG;
    }
    if (alg_id > 0xff) {
        PrintAndLogEx(FAILED, "Algorithm ID must fit on 1 byte");
        return PM3_EINVARG;
    }

    SetAPDULogging(APDULogging);

    int res = 0;
    if (activateField == true) {
        res = PivSelect(channel, activateField, true, decodeTLV, true, applet_id, aid_len);
        if (res != PM3_SUCCESS) {
            if (leaveSignalON == false) {
                DropFieldEx(channel);
            }
            return res;
        }
    }
    res = PivAuthenticateSign(channel, (uint8_t)(alg_id & 0xff), (uint8_t)(key_slot & 0xff), nonce, nonce_len, NULL, decodeTLV, true);
    if (leaveSignalON == false) {
        DropFieldEx(channel);
    }
    return res;
}

static int CmdPIVScan(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "piv scan",
                  "Scan a PIV card for known containers",
                  "piv scan -s   -> select card, select applet and run scan\n"
                  "piv scan -st --aid a00000030800001000   -> select card, select applet a00000030800001000, show result of the scan in TLV\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("sS",  "select",  "Activate field and select applet"),
        arg_lit0("kK",  "keep",    "Keep field for next command"),
        arg_lit0("aA",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("tT",  "tlv",     "TLV decode results"),
        arg_lit0("wW",  "wired",   "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_str0(NULL,  "aid", "<hex>", "Applet ID to select. By default A0000003080000100 will be used"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool activateField = arg_get_lit(ctx, 1);
    bool leaveSignalON = arg_get_lit(ctx, 2);
    bool APDULogging = arg_get_lit(ctx, 3);
    bool decodeTLV = arg_get_lit(ctx, 4);
    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 5))
        channel = CC_CONTACT;
    PrintChannel(channel);

    uint8_t applet_id[APDU_AID_LEN] = {0};
    int aid_len = 0;
    CLIGetHexWithReturn(ctx, 6, applet_id, &aid_len);
    if (aid_len == 0) {
        memcpy(applet_id, PIV_APPLET, sizeof(PIV_APPLET));
        aid_len = sizeof(PIV_APPLET);
    }

    CLIParserFree(ctx);

    SetAPDULogging(APDULogging);
    if (aid_len == 0) {
        memcpy(applet_id, PIV_APPLET, sizeof(PIV_APPLET));
        aid_len = sizeof(PIV_APPLET);
    }
    if (activateField == true) {
        int res = PivSelect(channel, activateField, true, decodeTLV, true, applet_id, aid_len);
        if (res != PM3_SUCCESS) {
            if (leaveSignalON == false) {
                DropFieldEx(channel);
            }
            return res;
        }
    }

    for (int i = 0; PIV_CONTAINERS[i].len != 0; i++) {
        PivGetDataByCidAndPrint(channel, &(PIV_CONTAINERS[i]), decodeTLV, false);
        PrintAndLogEx(NORMAL, "");
    }
    if (leaveSignalON == false) {
        DropFieldEx(channel);
    }
    return PM3_SUCCESS;
}

static int CmdPIVList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "piv", "7816");
}

static command_t CommandTable[] =  {
    {"help",        CmdHelp,                        AlwaysAvailable, "This help"},
    {"select",      CmdPIVSelect,                   IfPm3Iso14443,   "Select the PIV applet"},
    {"getdata",     CmdPIVGetData,                  IfPm3Iso14443,   "Gets a container on a PIV card"},
    {"authsign",    CmdPIVAuthenticateSign,         IfPm3Iso14443,   "Authenticate with the card"},
    {"scan",        CmdPIVScan,                     IfPm3Iso14443,   "Scan PIV card for known containers"},
    {"list",        CmdPIVList,                     AlwaysAvailable, "List ISO7816 history"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdPIV(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

