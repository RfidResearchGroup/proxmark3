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
// EMV commands
//-----------------------------------------------------------------------------

#include "cmdemv.h"
#include <string.h>
#include "comms.h"          // DropField
#include "cmdsmartcard.h"   // smart_select
#include "cmdtrace.h"
#include "emvjson.h"
#include "test/cryptotest.h"
#include "cliparser.h"
#include "cmdparser.h"
#include "proxmark3.h"
#include "emv_roca.h"
#include "emvcore.h"
#include "cmdhf14a.h"
#include "dol.h"
#include "ui.h"
#include "emv_tags.h"
#include "fileutils.h"
#include "protocols.h"      // ISO7816 APDU return codes
#include "commonutil.h"     // MemBeToUint2byte
#include "util_posix.h"     // msleep
#include <mbedtls/des.h>    // DES
#include "crypto/libpcrypto.h"
#include "iso4217.h"        // currency lookup
#include <limits.h>
#include <stdarg.h>
#include <time.h>

static int CmdHelp(const char *Cmd);
static int CmdEMVReader(const char *Cmd);

#define TLV_ADD(tag, value)( tlvdb_change_or_add_node(tlvRoot, tag, sizeof(value) - 1, (const unsigned char *)value) )
static bool emv_numeric_un(uint32_t sample, uint8_t value[4]) {
    // Reject the incomplete range to keep all eight-digit values equally likely.
    if (sample >= 4200000000UL)
        return false;
    sample %= 100000000UL;
    for (int i = 3; i >= 0; i--) {
        unsigned pair = sample % 100;
        value[i] = ((pair / 10) << 4) | (pair % 10);
        sample /= 100;
    }
    return true;
}

static bool ParamLoadDefaults(struct tlvdb *tlvRoot) {
    // 9F02:(Amount, authorized (Numeric)) len:6
    TLV_ADD(0x9F02, "\x00\x00\x00\x00\x01\x00");
    // 9F1A:(Terminal Country Code) len:2
    TLV_ADD(0x9F1A, "\x06\x43"); // Russian Federation, ISO 3166 numeric 643
    // 5F2A:(Transaction Currency Code) len:2
    // USD 840, EUR 978, RUR 810, RUB 643, RUR 810(old), UAH 980, AZN 031, n/a 999
    TLV_ADD(0x5F2A, "\x09\x78"); // EUR, ISO 4217 numeric 978
    // 9A:(Transaction Date) len:3
    time_t now = time(NULL);
    struct tm *local = localtime(&now);
    if (local) {
        uint8_t date[3] = {
            ((local->tm_year % 100) / 10 << 4) | ((local->tm_year % 100) % 10),
            (((local->tm_mon + 1) / 10) << 4) | ((local->tm_mon + 1) % 10),
            ((local->tm_mday / 10) << 4) | (local->tm_mday % 10),
        };
        tlvdb_change_or_add_node(tlvRoot, 0x9A, sizeof(date), date);
    } else {
        TLV_ADD(0x9A, "\x00\x00\x00");
        PrintAndLogEx(WARNING, "Could not determine local transaction date");
    }
    // 9C:(Transaction Type) len:1
    //     | 00 => Goods and Service
    //     | 01 => Cash
    TLV_ADD(0x9C,   "\x00");
    // 9F37 Unpredictable Number (UN) len:4
    uint8_t unpredictable[4] = {0};
    if (pcrypto_rng_fill_oneshot(unpredictable, sizeof(unpredictable), "proxmark3-emv-un") != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Secure unpredictable-number generation failed");
        return false;
    }
    tlvdb_change_or_add_node(tlvRoot, 0x9F37, sizeof(unpredictable), unpredictable);
    // 9F6A Unpredictable Number (MSD for UDOL) len:4
    uint8_t numeric[4];
    bool generated = false;
    for (size_t attempt = 0; attempt < 16; attempt++) {
        uint8_t sample[4];
        if (pcrypto_rng_fill_oneshot(sample, sizeof(sample), "proxmark3-emv-msd-un") != PM3_SUCCESS)
            break;
        if (emv_numeric_un(MemBeToUint4byte(sample), numeric)) {
            generated = true;
            break;
        }
    }
    if (!generated) {
        PrintAndLogEx(ERR, "Secure numeric unpredictable-number generation failed");
        return false;
    }
    tlvdb_change_or_add_node(tlvRoot, 0x9F6A, sizeof(numeric), numeric);
    // 9F66:(Terminal Transaction Qualifiers (TTQ)) len:4
    TLV_ADD(0x9F66, "\x26\x00\x00\x00"); // qVSDC
    // 95:(Terminal Verification Results) len:5
    // all OK TVR
    TLV_ADD(0x95,   "\x00\x00\x00\x00\x00");
    TLV_ADD(0x9B,   "\x00\x00");
    TLV_ADD(0x9F33, "\x20\x08\xC0"); // ICC input, SDA/DDA, no PIN/signature entry
    TLV_ADD(0x9F34, "\x3F\x00\x00");
    TLV_ADD(0x9F35, "\x22"); // attended, online-capable
    TLV_ADD(0x9F03, "\x00\x00\x00\x00\x00\x00");
    // 9F4E Merchant Name and Location len:x
    TLV_ADD(0x9F4E, "proxmark3rdv4\x00");
    return true;
}

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

static void PrintEMVAPDUHint(Iso7816CommandChannel channel, int result, uint16_t sw) {
    if (result == PM3_SUCCESS)
        return;
    if (channel == CC_CONTACTLESS && sw == 0) {
        PrintAndLogEx(HINT, "Hint: Hold one ISO 14443-4 card steadily on the antenna; EMV will probe both Type A and Type B automatically");
        PrintAndLogEx(HINT, "Hint: Add `-a` to show APDUs and use `hf tune` if cards are repeatedly not detected");
    } else if (sw == 0x6985 || sw == 0x6999) {
        PrintAndLogEx(HINT, "Hint: Keep transaction state with `-k`; SELECT the AID, then run GPO before application-state commands");
    } else if (sw == 0x6a82) {
        PrintAndLogEx(HINT, "Hint: The selected AID/file was not found; try `emv pse -kt` or `emv search -t`");
    }
}

typedef struct {
    size_t objects;
    size_t warnings;
    size_t errors;
} emv_analysis_result_t;

static void emv_analysis_finding(emv_analysis_result_t *result, bool error, const char *fmt, ...) {
    char message[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);
    if (error) {
        result->errors++;
        PrintAndLogEx(ERR, "[error] %s", message);
    } else {
        result->warnings++;
        PrintAndLogEx(WARNING, "[warn]  %s", message);
    }
}

static void emv_analysis_count_cb(void *data, const struct tlv *tlv, int level, bool is_leaf) {
    (void)tlv;
    (void)level;
    (void)is_leaf;
    ((emv_analysis_result_t *)data)->objects++;
}

static bool emv_analysis_is_dol(tlv_tag_t tag) {
    static const tlv_tag_t tags[] = {0x8c, 0x8d, 0x97, 0x9f38, 0x9f49, 0x9f4f};
    for (size_t i = 0; i < ARRAYLEN(tags); i++)
        if (tag == tags[i]) return true;
    return false;
}

static void emv_analysis_dol(const struct tlv *dol, emv_analysis_result_t *result) {
    const uint8_t *p = dol->value;
    size_t left = dol->len;
    size_t total = 0;
    size_t count = 0;
    while (left) {
        const uint8_t *item_start = p;
        struct tlv item;
        if (!dol_parse_tl(&p, &left, &item)) {
            emv_analysis_finding(result, true, "%s (%X) is not a valid tag-length list",
                                 emv_get_tag_name(dol), dol->tag);
            return;
        }
        count++;
        if (item.len == 0 && !(dol->tag == 0x9f4f && left == 0))
            emv_analysis_finding(result, true, "%s requests zero bytes for tag %X",
                                 emv_get_tag_name(dol), item.tag);
        if (tlv_is_constructed(&item))
            emv_analysis_finding(result, false, "%s requests constructed tag %X",
                                 emv_get_tag_name(dol), item.tag);
        const uint8_t *prior = dol->value;
        size_t prior_left = (size_t)(item_start - dol->value);
        while (prior_left) {
            struct tlv previous;
            if (!dol_parse_tl(&prior, &prior_left, &previous))
                break;
            if (previous.tag == item.tag) {
                emv_analysis_finding(result, false, "%s requests tag %X more than once",
                                     emv_get_tag_name(dol), item.tag);
                break;
            }
        }
        if (item.len > 252 || total > 252 - item.len)
            emv_analysis_finding(result, true, "%s requests more than 252 bytes",
                                 emv_get_tag_name(dol));
        else
            total += item.len;
    }
    PrintAndLogEx(INFO, "%s: %zu object(s), %zu data byte(s)",
                  emv_get_tag_name(dol), count, total);
}

typedef struct {
    emv_analysis_result_t *result;
    bool mastercard;
    bool visa;
    bool dump_tlv;
} emv_analysis_visit_t;

static void emv_analysis_visit_cb(void *data, const struct tlv *tlv, int level, bool is_leaf) {
    (void)level;
    (void)is_leaf;
    emv_analysis_visit_t *visit = data;
    if (emv_analysis_is_dol(tlv->tag))
        emv_analysis_dol(tlv, visit->result);
    if (tlv->tag == 0x9f66) {
        const struct tlvdb *parent = tlvdb_elm_get_parent((const struct tlvdb *)tlv);
        bool card_record = parent && parent->tag.tag == 0x70;
        if (visit->visa && tlv->len != 4)
            emv_analysis_finding(visit->result, true, "Visa TTQ (9F66) must contain four bytes");
        else if (visit->mastercard && card_record && tlv->len != 2)
            emv_analysis_finding(visit->result, true, "Mastercard PUNATC Track2 (9F66) must contain two bytes");
    }
    if ((visit->visa || visit->mastercard) && tlv->tag == 0x9f6c && tlv->len != 2)
        emv_analysis_finding(visit->result, true, "Visa CTQ / Mastercard mag-stripe version (9F6C) must contain two bytes");
    if (visit->visa && visit->dump_tlv && (tlv->tag == 0x9f66 || tlv->tag == 0x9f6c))
        emv_tag_dump_visa_qualifiers(tlv, level);
    if (tlv->tag == 0x9f69) {
        if (visit->mastercard)
            emv_analysis_dol(tlv, visit->result);
        else if (visit->visa) {
            if (tlv->len < 5 || tlv->len > 16)
                emv_analysis_finding(visit->result, true, "Visa Card Authentication Related Data (9F69) length must be 5..16 bytes");
        } else
            PrintAndLogEx(INFO, "9F69 needs a selected AID (84) to distinguish Card Authentication Related Data from UDOL");
    }
}

static void emv_analysis_fixed_len(const struct tlvdb *db, tlv_tag_t tag, size_t expected,
                                   emv_analysis_result_t *result) {
    const struct tlv *tlv = NULL;
    while ((tlv = tlvdb_get(db, tag, tlv)) != NULL) {
        if (tlv->len != expected)
            emv_analysis_finding(result, true, "tag %X (%s) has length %zu; expected %zu",
                                 tag, emv_get_tag_name(tlv), tlv->len, expected);
    }
}

static void emv_analysis_lengths(const struct tlvdb *db, emv_analysis_result_t *result) {
    static const struct {
        tlv_tag_t tag;
        size_t len;
    } fixed[] = {
        {0x82, 2}, {0x8f, 1}, {0x95, 5}, {0x9a, 3}, {0x9b, 2},
        {0x9f07, 2}, {0x9f08, 2}, {0x9f09, 2}, {0x9f0d, 5}, {0x9f0e, 5}, {0x9f0f, 5},
        {0x9f13, 2}, {0x9f17, 1}, {0x9f18, 4}, {0x9f26, 8}, {0x9f27, 1},
        {0x9f33, 3}, {0x9f34, 3}, {0x9f35, 1}, {0x9f36, 2}, {0x9f37, 4},
        {0x9f40, 5}, {0x9f4d, 2}, {0x9f6a, 4},
        {0x5f24, 3}, {0x5f25, 3}, {0x5f28, 2}, {0x9f1a, 2}, {0x9c, 1}, {0x9f03, 6},
    };
    for (size_t i = 0; i < ARRAYLEN(fixed); i++)
        emv_analysis_fixed_len(db, fixed[i].tag, fixed[i].len, result);

    static const tlv_tag_t aid_tags[] = {0x4f, 0x84};
    for (size_t i = 0; i < ARRAYLEN(aid_tags); i++) {
        const struct tlv *aid = NULL;
        while ((aid = tlvdb_get(db, aid_tags[i], aid)) != NULL) {
            if (aid->len < 5 || aid->len > 16)
                emv_analysis_finding(result, true, "tag %X AID length %zu is outside 5..16 bytes",
                                     aid_tags[i], aid->len);
        }
    }
}

static uint32_t emv_analysis_uint32(const uint8_t *value) {
    return ((uint32_t)value[0] << 24) | ((uint32_t)value[1] << 16) |
           ((uint32_t)value[2] << 8) | value[3];
}

static unsigned emv_analysis_popcount32(uint32_t value) {
    unsigned count = 0;
    while (value) {
        count += value & 1U;
        value >>= 1;
    }
    return count;
}

static void emv_analysis_unpredictable_numbers(const struct tlvdb *db,
                                               emv_analysis_result_t *result) {
    static const tlv_tag_t tags[] = {0x9f37, 0x9f6a};
    for (size_t tag_index = 0; tag_index < ARRAYLEN(tags); tag_index++) {
        const struct tlv *sample = NULL;
        size_t count = 0;
        uint32_t first = 0;
        uint32_t previous = 0;
        uint32_t first_delta = 0;
        uint32_t variation = 0;
        bool duplicate = false;
        bool all_zero = true;
        bool constant_delta = true;
        bool bcd_valid = true;

        while ((sample = tlvdb_get(db, tags[tag_index], sample)) != NULL) {
            if (sample->len != 4 || !sample->value)
                continue;
            uint32_t value = emv_analysis_uint32(sample->value);
            const struct tlv *prior = NULL;
            while ((prior = tlvdb_get(db, tags[tag_index], prior)) != NULL && prior != sample) {
                if (prior->len == 4 && prior->value && !memcmp(prior->value, sample->value, 4)) {
                    duplicate = true;
                    break;
                }
            }
            if (tags[tag_index] == 0x9f6a) {
                for (size_t i = 0; i < 4; i++)
                    if ((sample->value[i] >> 4) > 9 || (sample->value[i] & 0x0f) > 9)
                        bcd_valid = false;
            }
            if (count == 0) {
                first = value;
            } else {
                uint32_t delta = value - previous;
                if (count == 1)
                    first_delta = delta;
                else if (delta != first_delta)
                    constant_delta = false;
            }
            variation |= value ^ first;
            previous = value;
            all_zero &= value == 0;
            count++;
        }

        if (!count)
            continue;
        PrintAndLogEx(INFO, "Pre-play screen for tag %X: %zu sample(s), %u varying bit(s)",
                      tags[tag_index], count, emv_analysis_popcount32(variation));
        if (all_zero)
            emv_analysis_finding(result, false, "tag %X unpredictable-number samples are all zero",
                                 tags[tag_index]);
        if (duplicate)
            emv_analysis_finding(result, false, "tag %X contains a repeated unpredictable number",
                                 tags[tag_index]);
        if (count >= 4 && constant_delta && first_delta != 0)
            emv_analysis_finding(result, false, "tag %X follows a constant-delta sequence (counter-like RNG)",
                                 tags[tag_index]);
        if (count >= 8 && emv_analysis_popcount32(variation) < 8)
            emv_analysis_finding(result, false, "tag %X varies in fewer than 8 of 32 bits",
                                 tags[tag_index]);
        if (!bcd_valid)
            emv_analysis_finding(result, true, "tag 9F6A contains non-BCD digits");
        if (count == 1)
            PrintAndLogEx(HINT, "Hint: one sample cannot establish unpredictability; concatenate repeated 9F37/9F6A TLVs in capture order");
    }
}

static void emv_analysis_afl(const struct tlv *afl, emv_analysis_result_t *result) {
    if (!afl) return;
    if (afl->len % 4) {
        emv_analysis_finding(result, true, "AFL length %zu is not a multiple of four", afl->len);
        return;
    }
    if (afl->len == 0) {
        PrintAndLogEx(INFO, "AFL contains no record entries");
        return;
    }
    PrintAndLogEx(INFO, "AFL record plan:");
    for (size_t i = 0; i < afl->len; i += 4) {
        uint8_t sfi = afl->value[i] >> 3;
        uint8_t first = afl->value[i + 1];
        uint8_t last = afl->value[i + 2];
        uint8_t oda = afl->value[i + 3];
        PrintAndLogEx(INFO, "  SFI %u, records %u..%u, ODA records %u", sfi, first, last, oda);
        if (afl->value[i] & 0x07)
            emv_analysis_finding(result, true, "AFL entry %zu has non-zero RFU bits", i / 4 + 1);
        if (sfi == 0 || sfi == 31)
            emv_analysis_finding(result, true, "AFL entry %zu uses invalid SFI %u", i / 4 + 1, sfi);
        if (first == 0 || last < first)
            emv_analysis_finding(result, true, "AFL entry %zu has invalid range %u..%u", i / 4 + 1, first, last);
        else if (oda > last - first + 1)
            emv_analysis_finding(result, true, "AFL entry %zu authenticates more records than it contains", i / 4 + 1);
        for (size_t j = 0; j < i; j += 4) {
            if (sfi == (afl->value[j] >> 3) && first <= afl->value[j + 2] && afl->value[j + 1] <= last)
                emv_analysis_finding(result, false, "AFL entries %zu and %zu overlap for SFI %u",
                                     j / 4 + 1, i / 4 + 1, sfi);
        }
    }
}

static const char *emv_analysis_cvm_name(uint8_t method) {
    switch (method & 0x3f) {
        case 0x00: return "fail processing";
        case 0x01: return "plaintext PIN by ICC";
        case 0x02: return "online enciphered PIN";
        case 0x03: return "plaintext PIN by ICC + signature";
        case 0x04: return "enciphered PIN by ICC";
        case 0x05: return "enciphered PIN by ICC + signature";
        case 0x06: return "offline facial biometric";
        case 0x07: return "online facial biometric";
        case 0x08: return "offline finger biometric";
        case 0x09: return "online finger biometric";
        case 0x0a: return "offline palm biometric";
        case 0x0b: return "online palm biometric";
        case 0x0c: return "offline iris biometric";
        case 0x0d: return "online iris biometric";
        case 0x0e: return "offline voice biometric";
        case 0x0f: return "online voice biometric";
        case 0x1e: return "signature";
        case 0x1f: return "no CVM required";
        case 0x3f: return "not available";
        default: return "reserved/proprietary";
    }
}

static void emv_analysis_cvm(const struct tlv *cvm, emv_analysis_result_t *result) {
    if (!cvm) return;
    if (cvm->len == 0 || cvm->len == 8) return;
    if (cvm->len < 10 || (cvm->len & 1)) {
        emv_analysis_finding(result, true, "CVM List length %zu must be at least 10 and even", cvm->len);
        return;
    }
    uint32_t x = MemBeToUint4byte(cvm->value);
    uint32_t y = MemBeToUint4byte(cvm->value + 4);
    PrintAndLogEx(INFO, "CVM policy: X=%u, Y=%u", x, y);
    for (size_t i = 8; i < cvm->len; i += 2) {
        PrintAndLogEx(INFO, "  %zu. %s, condition %02x, on failure %s",
                      (i - 8) / 2 + 1, emv_analysis_cvm_name(cvm->value[i]), cvm->value[i + 1],
                      (cvm->value[i] & 0x40) ? "continue" : "fail");
        if (cvm->value[i] & 0x80)
            emv_analysis_finding(result, true, "CVM rule %zu has RFU bit 8 set", (i - 8) / 2 + 1);
        if (cvm->value[i + 1] >= 0x0a && cvm->value[i + 1] < 0x80)
            emv_analysis_finding(result, false, "CVM rule %zu uses reserved condition %02x",
                                 (i - 8) / 2 + 1, cvm->value[i + 1]);
    }
}

static bool emv_analysis_cvm_contains(const struct tlv *cvm, uint8_t method, uint8_t condition) {
    if (!cvm || cvm->len < 10 || (cvm->len & 1) || !cvm->value)
        return false;
    for (size_t i = 8; i < cvm->len; i += 2)
        if ((cvm->value[i] & 0x3f) == (method & 0x3f) && cvm->value[i + 1] == condition)
            return true;
    return false;
}

typedef struct {
    uint8_t result[3];
    uint8_t tvr[5];
    uint8_t tsi[2];
    bool pending;
    size_t rule;
} emv_cvm_result_t;

static bool emv_bcd_amount(const struct tlv *tlv, uint64_t *amount) {
    if (!tlv || tlv->len != 6)
        return false;
    *amount = 0;
    for (size_t i = 0; i < tlv->len; i++) {
        if ((tlv->value[i] >> 4) > 9 || (tlv->value[i] & 15) > 9)
            return false;
        *amount = *amount * 100 + (tlv->value[i] >> 4) * 10 + (tlv->value[i] & 15);
    }
    return true;
}

static bool emv_cvm_supported(uint8_t method, uint8_t capability) {
    switch (method) {
        case 0: return true;
        case 1: return capability & 0x80;
        case 2: return capability & 0x40;
        case 3: return (capability & 0xa0) == 0xa0;
        case 4: return capability & 0x10;
        case 5: return (capability & 0x30) == 0x30;
        case 0x1e: return capability & 0x20;
        case 0x1f: return capability & 0x08;
        default: return false;
    }
}

static bool emv_cvm_condition(const struct tlvdb *db, uint8_t condition, bool supported,
                                uint32_t x, uint32_t y) {
    if (condition == 0) return true;
    if (condition == 3) return supported;
    if (condition >= 6 && condition <= 9) {
        const struct tlv *currency = tlvdb_get(db, 0x5f2a, NULL);
        const struct tlv *application = tlvdb_get(db, 0x9f42, NULL);
        uint64_t amount;
        if (!currency || !application || currency->len != 2 || application->len != 2 ||
                memcmp(currency->value, application->value, 2) ||
                !emv_bcd_amount(tlvdb_get(db, 0x9f02, NULL), &amount))
            return false;
        uint32_t threshold = condition < 8 ? x : y;
        return (condition & 1) ? amount > threshold : amount < threshold;
    }
    const struct tlv *type = tlvdb_get(db, 0x9c, NULL);
    const struct tlv *terminal = tlvdb_get(db, 0x9f35, NULL);
    if (!type || type->len != 1 || !terminal || terminal->len != 1)
        return false;
    uint8_t t = terminal->value[0];
    bool unattended = (t & 0x0f) >= 4 && (t & 0x0f) <= 6;
    bool cash = type->value[0] == 1;
    uint64_t other = 0;
    bool cashback = type->value[0] == 9 ||
                    (emv_bcd_amount(tlvdb_get(db, 0x9f03, NULL), &other) && other != 0);
    switch (condition) {
        case 1: return cash && unattended;
        case 2: return !cash && !cashback;
        case 4: return cash && !unattended;
        case 5: return cashback;
        default: return false;
    }
}

static int emv_cvm_evaluate(const struct tlvdb *db, emv_cvm_result_t *out) {
    memset(out, 0, sizeof(*out));
    out->result[0] = 0x3f;
    const struct tlv *aip = tlvdb_get(db, 0x82, NULL);
    if (aip && aip->len == 2 && !(aip->value[0] & 0x10))
        return PM3_SUCCESS;
    const struct tlv *list = tlvdb_get(db, 0x8e, NULL);
    if (!list || list->len == 8 || list->len == 0)
        return PM3_SUCCESS;
    if (list->len < 10 || (list->len & 1))
        return PM3_EINVARG;
    const struct tlv *capability = tlvdb_get(db, 0x9f33, NULL);
    if (!capability || capability->len != 3)
        return PM3_EINVARG;
    uint8_t cap = capability->value[1];
    uint32_t x = MemBeToUint4byte(list->value), y = MemBeToUint4byte(list->value + 4);
    const struct tlv *observed = tlvdb_get(db, 0x9f34, NULL);
    if (observed && (observed->len != 3 || observed->value[2] > 2))
        return PM3_EINVARG;
    for (size_t i = 8; i < list->len; i += 2) {
        uint8_t code = list->value[i], method = code & 0x3f, condition = list->value[i + 1];
        if (code & 0x80)
            return PM3_EINVARG;
        bool recognised = method <= 0x0f || method == 0x1e || method == 0x1f;
        bool supported = emv_cvm_supported(method, cap);
        if (!emv_cvm_condition(db, condition, supported, x, y))
            continue;
        out->rule = (i - 8) / 2 + 1;
        if (!recognised)
            out->tvr[2] |= 0x40;
        if (!supported && method >= 1 && method <= 5 &&
                (method == 2 || !(cap & 0x90)))
            out->tvr[2] |= 0x10;
        if (method >= 6 && method <= 0x0f)
            out->tvr[3] |= 0x02;
        if (supported) {
            out->result[0] = code;
            out->result[1] = condition;
            out->result[2] = 1;
            if (method == 0) {
                out->tvr[2] |= 0x80;
                out->tsi[0] |= 0x40;
                return PM3_SUCCESS;
            }
            if (method == 0x1f)
                out->result[2] = 2;
            else if (method == 0x1e)
                out->result[2] = 0;
            else if (observed && observed->len == 3 && observed->value[0] == code &&
                     observed->value[1] == condition && observed->value[2] <= 2)
                out->result[2] = observed->value[2];
            else {
                out->result[2] = 0;
                out->pending = true;
                return PM3_SUCCESS;
            }
            if ((method == 1 || method == 4) && out->result[2] == 0) {
                out->pending = true;
                return PM3_SUCCESS;
            }
            if ((method == 2 || method == 3 || method == 5) && out->result[2] == 2)
                return PM3_EINVARG;
            if (method == 2 && out->result[2] == 0)
                out->tvr[2] |= 0x04;
            if (out->result[2] == 2 || ((method == 2 || method == 3 || method == 5 || method == 0x1e) && out->result[2] == 0)) {
                out->tsi[0] |= 0x40;
                return PM3_SUCCESS;
            }
        }
        if (!(code & 0x40))
            break;
    }
    out->tvr[2] |= 0x80;
    out->tsi[0] |= 0x40;
    out->result[2] = 1;
    return PM3_SUCCESS;
}

static int CmdEMVCVM(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv cvm", "Evaluate Book 3 CVM rules offline; no PIN or biometric commands are sent.\n"
                  "Supply CVM List (8E), Terminal Capabilities (9F33), and transaction context.\n"
                  "Captured CVM Results (9F34) can supply the outcome of PIN verification.\n",
                  "emv cvm 8e0a00000000000000001f009f3303000800\n");
    void *argtable[] = {arg_param_begin, arg_strx1(NULL, NULL, "<hex>", "EMV context in BER-TLV format"), arg_param_end};
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint8_t data[4096];
    int len = 0;
    CLIGetHexWithReturn(ctx, 1, data, &len);
    CLIParserFree(ctx);
    struct tlvdb *db = tlvdb_parse_multi(data, len);
    if (!db) return PM3_EINVARG;
    emv_cvm_result_t result;
    int res = emv_cvm_evaluate(db, &result);
    tlvdb_free(db);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "CVM context is malformed or is missing Terminal Capabilities (9F33)");
        return res;
    }
    PrintAndLogEx(INFO, "CVM rule %zu: %s", result.rule, emv_analysis_cvm_name(result.result[0]));
    PrintAndLogEx(INFO, "CVM Results (9F34): %s", sprint_hex_inrow(result.result, 3));
    PrintAndLogEx(INFO, "TVR additions: %s", sprint_hex_inrow(result.tvr, 5));
    PrintAndLogEx(INFO, "TSI additions: %s", sprint_hex_inrow(result.tsi, 2));
    PrintAndLogEx(INFO, "%s", result.pending ? "Verification outcome required; no success has been assumed" :
                  result.tvr[2] & 0x80 ? "Cardholder verification unsuccessful" : "CVM evaluation complete");
    return PM3_SUCCESS;
}

static bool emv_analysis_mask_intersects(const struct tlv *a, const struct tlv *b) {
    if (!a || !b || a->len != 5 || b->len != 5) return false;
    for (size_t i = 0; i < 5; i++)
        if (a->value[i] & b->value[i]) return true;
    return false;
}

static bool emv_analysis_all_zero(const struct tlv *tlv, size_t expected_len) {
    if (!tlv || !tlv->value || tlv->len != expected_len)
        return false;
    for (size_t i = 0; i < expected_len; i++)
        if (tlv->value[i])
            return false;
    return true;
}

static bool emv_analysis_bcd_date(const struct tlv *date) {
    if (!date || date->len != 3) return false;
    for (size_t i = 0; i < 3; i++)
        if ((date->value[i] >> 4) > 9 || (date->value[i] & 0x0f) > 9) return false;
    unsigned month = (date->value[1] >> 4) * 10 + (date->value[1] & 0x0f);
    unsigned day = (date->value[2] >> 4) * 10 + (date->value[2] & 0x0f);
    if (month < 1 || month > 12 || day == 0)
        return false;
    static const unsigned days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    unsigned year = (date->value[0] >> 4) * 10 + (date->value[0] & 0x0f);
    unsigned max_day = days[month - 1] + (month == 2 && year % 4 == 0);
    return day <= max_day;
}

typedef enum {
    EMV_BRAND_UNKNOWN,
    EMV_BRAND_VISA,
    EMV_BRAND_MASTERCARD,
    EMV_BRAND_AMEX,
    EMV_BRAND_DISCOVER,
    EMV_BRAND_JCB,
    EMV_BRAND_UNIONPAY,
} emv_analysis_brand_t;

static const char *emv_analysis_brand_name(emv_analysis_brand_t brand) {
    switch (brand) {
        case EMV_BRAND_UNKNOWN: return "unknown";
        case EMV_BRAND_VISA: return "Visa";
        case EMV_BRAND_MASTERCARD: return "Mastercard";
        case EMV_BRAND_AMEX: return "American Express";
        case EMV_BRAND_DISCOVER: return "Discover";
        case EMV_BRAND_JCB: return "JCB";
        case EMV_BRAND_UNIONPAY: return "UnionPay";
    }
    return "unknown";
}

static emv_analysis_brand_t emv_analysis_aid_brand(const struct tlv *aid) {
    static const struct {
        uint8_t rid[5];
        emv_analysis_brand_t brand;
    } networks[] = {
        {{0xa0, 0x00, 0x00, 0x00, 0x03}, EMV_BRAND_VISA},
        {{0xa0, 0x00, 0x00, 0x00, 0x04}, EMV_BRAND_MASTERCARD},
        {{0xa0, 0x00, 0x00, 0x00, 0x25}, EMV_BRAND_AMEX},
        {{0xa0, 0x00, 0x00, 0x01, 0x52}, EMV_BRAND_DISCOVER},
        {{0xa0, 0x00, 0x00, 0x00, 0x65}, EMV_BRAND_JCB},
        {{0xa0, 0x00, 0x00, 0x03, 0x33}, EMV_BRAND_UNIONPAY},
    };
    if (!aid || !aid->value || aid->len < 5)
        return EMV_BRAND_UNKNOWN;
    for (size_t i = 0; i < ARRAYLEN(networks); i++)
        if (!memcmp(aid->value, networks[i].rid, sizeof(networks[i].rid)))
            return networks[i].brand;
    return EMV_BRAND_UNKNOWN;
}

static bool emv_analysis_pan_prefix(const struct tlv *pan, uint8_t prefix[4]) {
    if (!pan || !pan->value || pan->len < 2 || !prefix)
        return false;
    prefix[0] = pan->value[0] >> 4;
    prefix[1] = pan->value[0] & 0x0f;
    prefix[2] = pan->value[1] >> 4;
    prefix[3] = pan->value[1] & 0x0f;
    for (size_t i = 0; i < 4; i++)
        if (prefix[i] > 9)
            return false;
    return true;
}

static emv_analysis_brand_t emv_analysis_pan_brand(const uint8_t prefix[4]) {
    unsigned two = prefix[0] * 10U + prefix[1];
    unsigned three = two * 10U + prefix[2];
    unsigned four = three * 10U + prefix[3];
    if (prefix[0] == 4)
        return EMV_BRAND_VISA;
    if ((two >= 51 && two <= 55) || (four >= 2221 && four <= 2720))
        return EMV_BRAND_MASTERCARD;
    if (two == 34 || two == 37)
        return EMV_BRAND_AMEX;
    if (four == 6011 || two == 65 || (three >= 644 && three <= 649))
        return EMV_BRAND_DISCOVER;
    if (four >= 3528 && four <= 3589)
        return EMV_BRAND_JCB;
    /* 62 overlaps historical Discover ranges, so leave it unclassified. */
    return EMV_BRAND_UNKNOWN;
}

static void emv_analysis_brand_mixup(const struct tlvdb *db, emv_analysis_result_t *result) {
    emv_analysis_brand_t aid_brand = EMV_BRAND_UNKNOWN;
    const struct tlv *aid = NULL;
    while ((aid = tlvdb_get(db, 0x84, aid)) != NULL) {
        emv_analysis_brand_t current = emv_analysis_aid_brand(aid);
        if (current == EMV_BRAND_UNKNOWN)
            continue;
        if (aid_brand != EMV_BRAND_UNKNOWN && aid_brand != current) {
            PrintAndLogEx(HINT, "Hint: multiple payment-network DF Names are present; isolate the selected application to screen for brand mixup");
            return;
        }
        aid_brand = current;
    }
    if (aid_brand == EMV_BRAND_UNKNOWN)
        return;

    uint8_t prefix[4] = {0};
    const struct tlv *pan = tlvdb_get(db, 0x5a, NULL);
    if (!emv_analysis_pan_prefix(pan, prefix))
        if (!emv_analysis_pan_prefix(tlvdb_get(db, 0x57, NULL), prefix))
            return;
    emv_analysis_brand_t pan_brand = emv_analysis_pan_brand(prefix);
    if (pan_brand != EMV_BRAND_UNKNOWN && pan_brand != aid_brand)
        emv_analysis_finding(result, false,
                             "selected AID network (%s) differs from apparent PAN network (%s); review card-brand mixup or legitimate co-badging",
                             emv_analysis_brand_name(aid_brand), emv_analysis_brand_name(pan_brand));
}

static void emv_analysis_restriction(const struct tlvdb *db, uint8_t mask, const char *reason,
                                      emv_analysis_result_t *result) {
    emv_analysis_finding(result, false, "%s; expected TVR byte 2 mask %02X", reason, mask);
    const struct tlv *tvr = tlvdb_get(db, 0x95, NULL);
    if (tvr && tvr->len == 5 && !(tvr->value[1] & mask))
        emv_analysis_finding(result, true, "TVR does not record the processing restriction: %s", reason);
}

static void emv_analysis_restrictions(const struct tlvdb *db, bool contact,
                                       emv_analysis_result_t *result) {
    const struct tlv *effective = tlvdb_get(db, 0x5f25, NULL);
    const struct tlv *txdate = tlvdb_get(db, 0x9a, NULL);
    if (emv_analysis_bcd_date(effective) && emv_analysis_bcd_date(txdate) &&
            memcmp(txdate->value, effective->value, 3) < 0) {
        if (contact)
            emv_analysis_restriction(db, 0x20, "application is not yet effective", result);
        else
            emv_analysis_finding(result, false, "Transaction Date is before Application Effective Date");
    }
    // Book 3 contact rules differ from individual contactless kernels.
    if (!contact)
        return;
    const struct tlv *card_version = tlvdb_get(db, 0x9f08, NULL);
    const struct tlv *terminal_version = tlvdb_get(db, 0x9f09, NULL);
    if (card_version && card_version->len == 2 && terminal_version && terminal_version->len == 2 &&
            memcmp(card_version->value, terminal_version->value, 2))
        emv_analysis_restriction(db, 0x80, "ICC and terminal have different application versions", result);

    const struct tlv *auc = tlvdb_get(db, 0x9f07, NULL);
    if (!auc || auc->len != 2)
        return;
    const struct tlv *terminal_type = tlvdb_get(db, 0x9f35, NULL);
    const struct tlv *capabilities = tlvdb_get(db, 0x9f40, NULL);
    if (terminal_type && terminal_type->len == 1) {
        uint8_t type = terminal_type->value[0];
        bool unattended_bank = type == 0x14 || type == 0x15 || type == 0x16;
        if (!unattended_bank || (capabilities && capabilities->len == 5)) {
            bool atm = unattended_bank && (capabilities->value[0] & 0x80);
            if (!(auc->value[0] & (atm ? 0x02 : 0x01)))
                emv_analysis_restriction(db, 0x10, atm ? "AUC disallows use at ATMs" :
                                         "AUC disallows use at terminals other than ATMs", result);
        } else
            PrintAndLogEx(INFO, "AUC terminal-environment check needs Additional Terminal Capabilities (9F40)");
    }
    const struct tlv *issuer_country = tlvdb_get(db, 0x5f28, NULL);
    const struct tlv *terminal_country = tlvdb_get(db, 0x9f1a, NULL);
    const struct tlv *transaction_type = tlvdb_get(db, 0x9c, NULL);
    if (!issuer_country || issuer_country->len != 2 || !terminal_country || terminal_country->len != 2 ||
            !transaction_type || transaction_type->len != 1)
        return;
    bool domestic = !memcmp(issuer_country->value, terminal_country->value, 2);
    uint8_t type = transaction_type->value[0];
    if (type == 0x01 && !(auc->value[0] & (domestic ? 0x80 : 0x40)))
        emv_analysis_restriction(db, 0x10, domestic ? "AUC disallows domestic cash" :
                                 "AUC disallows international cash", result);
    if ((type == 0x00 || type == 0x09) && !(auc->value[0] & (domestic ? 0x28 : 0x14)))
        emv_analysis_restriction(db, 0x10, domestic ? "AUC disallows domestic goods/services" :
                                 "AUC disallows international goods/services", result);
    const struct tlv *cashback = tlvdb_get(db, 0x9f03, NULL);
    bool has_cashback = false;
    if (cashback && cashback->len == 6) {
        for (size_t i = 0; i < cashback->len; i++)
            has_cashback |= cashback->value[i] != 0;
    }
    if (has_cashback && !(auc->value[1] & (domestic ? 0x80 : 0x40)))
        emv_analysis_restriction(db, 0x10, domestic ? "AUC disallows domestic cashback" :
                                 "AUC disallows international cashback", result);
}

static void emv_analysis_correlate(const struct tlvdb *db, emv_analysis_result_t *result) {
    const struct tlv *aip = tlvdb_get(db, 0x82, NULL);
    if (aip && aip->len == 2) {
        PrintAndLogEx(INFO, "Capabilities: XDA=%s SDA=%s DDA=%s CVM=%s risk=%s issuer-auth=%s CDA=%s",
                      (aip->value[0] & 0x80) ? "yes" : "no", (aip->value[0] & 0x40) ? "yes" : "no",
                      (aip->value[0] & 0x20) ? "yes" : "no", (aip->value[0] & 0x10) ? "yes" : "no",
                      (aip->value[0] & 0x08) ? "yes" : "no", (aip->value[0] & 0x04) ? "yes" : "no",
                      (aip->value[0] & 0x01) ? "yes" : "no");
        if ((aip->value[0] & 0x10) && !tlvdb_get(db, 0x8e, NULL))
            emv_analysis_finding(result, false, "AIP advertises CVM but this data set has no CVM List");
        if ((aip->value[0] & 0x40) && !(aip->value[0] & (0x80 | 0x20 | 0x01)))
            emv_analysis_finding(result, false, "SDA-only profile has no dynamic offline card authentication");
        if (aip->value[1] & 0x80)
            emv_analysis_finding(result, false, "card profile supports legacy MSD; review pre-play/downgrade exposure");
    }
    bool visa = emv_analysis_aid_brand(tlvdb_get(db, 0x84, NULL)) == EMV_BRAND_VISA;
    const struct tlv *ttq = visa ? tlvdb_get(db, 0x9f66, NULL) : NULL;
    if (ttq && ttq->len == 4 && (ttq->value[0] & 0x80))
        emv_analysis_finding(result, false, "terminal TTQ offers MSD; review contactless downgrade exposure");
    const struct tlv *ctq = visa ? tlvdb_get(db, 0x9f6c, NULL) : NULL;
    if (ctq && ctq->len == 2 && (ctq->value[1] & 0x80) &&
            ttq && ttq->len == 4 && !(ttq->value[2] & 0x40))
        emv_analysis_finding(result, true,
                             "CTQ reports Consumer Device CVM performed but TTQ does not support Consumer Device CVM");

    const struct tlv *tvr = tlvdb_get(db, 0x95, NULL);
    const struct tlv *iac_denial = tlvdb_get(db, 0x9f0e, NULL);
    if (emv_analysis_all_zero(iac_denial, 5))
        emv_analysis_finding(result, false,
                             "IAC-Denial is all zero; verify TAC-Denial covers ODA and CVM failures");
    if (emv_analysis_mask_intersects(tvr, iac_denial))
        PrintAndLogEx(WARNING, "Action analysis: TVR intersects IAC-Denial (AAC path)");
    else if (emv_analysis_mask_intersects(tvr, tlvdb_get(db, 0x9f0f, NULL)))
        PrintAndLogEx(INFO, "Action analysis: TVR intersects IAC-Online (ARQC path)");
    if (emv_analysis_mask_intersects(tvr, tlvdb_get(db, 0x9f0d, NULL)))
        PrintAndLogEx(INFO, "Action analysis: TVR intersects IAC-Default (AAC if online unavailable)");

    const struct tlv *cid = tlvdb_get(db, 0x9f27, NULL);
    if (tvr && tvr->len == 5 && cid && cid->len == 1) {
        bool oda_failed = (tvr->value[0] & (0x40 | 0x10 | 0x08)) != 0;
        uint8_t cryptogram_type = cid->value[0] & EMVAC_AC_MASK;
        if (oda_failed && cryptogram_type == EMVAC_TC)
            emv_analysis_finding(result, true, "offline approval (TC) is present despite an ODA failure in TVR");
        else if (oda_failed && cryptogram_type == EMVAC_ARQC)
            emv_analysis_finding(result, false, "online fallback (ARQC) follows an ODA failure; verify that all decision data is issuer-authenticated");
    }

    const struct tlv *effective = tlvdb_get(db, 0x5f25, NULL);
    const struct tlv *expiry = tlvdb_get(db, 0x5f24, NULL);
    const struct tlv *txdate = tlvdb_get(db, 0x9a, NULL);
    if (effective && !emv_analysis_bcd_date(effective)) emv_analysis_finding(result, true, "invalid Application Effective Date");
    if (expiry && !emv_analysis_bcd_date(expiry)) emv_analysis_finding(result, true, "invalid Application Expiration Date");
    if (txdate && !emv_analysis_bcd_date(txdate)) emv_analysis_finding(result, true, "invalid Transaction Date");
    if (effective && expiry && emv_analysis_bcd_date(effective) && emv_analysis_bcd_date(expiry) &&
            memcmp(effective->value, expiry->value, 3) > 0)
        emv_analysis_finding(result, true, "Application Effective Date is after Expiration Date");
    bool expired = txdate && expiry && emv_analysis_bcd_date(txdate) &&
                   emv_analysis_bcd_date(expiry) && memcmp(txdate->value, expiry->value, 3) > 0;
    if (expired)
        emv_analysis_finding(result, false, "Transaction Date is after Application Expiration Date");
    if (expired && tvr && tvr->len == 5 && !(tvr->value[1] & 0x40))
        emv_analysis_finding(result, true, "expired application is not marked in TVR");
    if (expired && cid && cid->len == 1 && (cid->value[0] & EMVAC_AC_MASK) == EMVAC_TC)
        emv_analysis_finding(result, true, "expired application produced an offline approval (TC)");
    else if (expired && cid && cid->len == 1 && (cid->value[0] & EMVAC_AC_MASK) == EMVAC_ARQC)
        emv_analysis_finding(result, false, "expired application produced an online request (ARQC); issuer acceptance is not visible in this capture");

    const struct tlv *cvm_result = tlvdb_get(db, 0x9f34, NULL);
    if (cvm_result && cvm_result->len == 3) {
        if (cvm_result->value[2] > 2)
            emv_analysis_finding(result, true, "CVM Results byte 3 has RFU value %02x", cvm_result->value[2]);
        const struct tlv *cvm = tlvdb_get(db, 0x8e, NULL);
        uint8_t method = cvm_result->value[0] & 0x3f;
        if (cvm && method != 0x3f &&
                !emv_analysis_cvm_contains(cvm, cvm_result->value[0], cvm_result->value[1]))
            emv_analysis_finding(result, false, "CVM Results method/condition does not occur in the captured CVM List");
        if (cvm_result->value[2] == 2 && (method == 0x01 || method == 0x03))
            emv_analysis_finding(result, false, "successful plaintext offline PIN result requires trace-level MITM review");
        if (cvm_result->value[2] == 2 && method == 0x1f &&
                ttq && ttq->len == 4 && (ttq->value[1] & 0x40))
            emv_analysis_finding(result, true,
                                 "terminal TTQ requires a CVM but CVM Results reports successful no-CVM processing");
        if (cvm_result->value[2] == 2 && tvr && tvr->len == 5 && (tvr->value[2] & 0x80))
            emv_analysis_finding(result, true, "CVM Results reports success while TVR reports unsuccessful cardholder verification");
    }
    emv_analysis_brand_mixup(db, result);
}

static void emv_analysis_scripts(const struct tlvdb *db, emv_analysis_result_t *result) {
    static const tlv_tag_t tags[] = {0x71, 0x72};
    for (size_t i = 0; i < ARRAYLEN(tags); i++) {
        const struct tlv *script_tlv = NULL;
        while ((script_tlv = tlvdb_get(db, tags[i], script_tlv)) != NULL) {
            const struct tlvdb *script = (const struct tlvdb *)script_tlv;
            PrintAndLogEx(INFO, "Issuer Script %X (%s final GENERATE AC)", tags[i], tags[i] == 0x71 ? "before" : "after");
            size_t count = 0;
            size_t identifiers = 0;
            bool command_seen = false;
            const struct tlvdb *child = tlvdb_elm_get_children(script);
            while (child) {
                const struct tlv *cmd = tlvdb_get_tlv(child);
                if (cmd && cmd->tag == 0x9f18) {
                    identifiers++;
                    if (command_seen)
                        emv_analysis_finding(result, false, "Issuer Script Identifier follows a command");
                } else if (cmd && cmd->tag == 0x86) {
                    count++;
                    command_seen = true;
                    PrintAndLogEx(INFO, "  command %zu: %s", count,
                                  cmd->len ? sprint_hex_inrow(cmd->value, cmd->len) : "<empty>");
                    if (cmd->len < 4) {
                        emv_analysis_finding(result, true, "Issuer Script command %zu is shorter than an APDU header", count);
                    } else if (cmd->len > INT_MAX) {
                        emv_analysis_finding(result, true, "Issuer Script command %zu is too long to decode", count);
                    } else {
                        APDU_t apdu;
                        if (APDUDecode((uint8_t *)cmd->value, (int)cmd->len, &apdu))
                            emv_analysis_finding(result, true, "Issuer Script command %zu has inconsistent Lc/Le", count);
                        else if (apdu.extended_apdu)
                            emv_analysis_finding(result, false, "Issuer Script command %zu uses extended length", count);
                    }
                } else if (cmd) {
                    emv_analysis_finding(result, false, "Issuer Script %X contains unexpected tag %X",
                                         tags[i], cmd->tag);
                }
                child = tlvdb_elm_get_next(child);
            }
            if (identifiers > 1)
                emv_analysis_finding(result, true, "Issuer Script %X has more than one Script Identifier", tags[i]);
            if (!count) emv_analysis_finding(result, false, "Issuer Script %X contains no tag 86 command", tags[i]);
        }
    }
}

static bool emv_analysis_add(struct tlvdb *db, tlv_tag_t tag, size_t len,
                             const uint8_t *value, emv_analysis_result_t *result) {
    struct tlvdb *item = tlvdb_fixed(tag, len, value);
    if (!item) {
        emv_analysis_finding(result, true, "out of memory while expanding tag %X", tag);
        return false;
    }
    tlvdb_add(db, item);
    return true;
}

typedef enum {
    EMV_FORMAT_AUTO,
    EMV_FORMAT_GPO,
    EMV_FORMAT_AC,
} emv_format_hint_t;

static const struct tlv *emv_analysis_response_field(const struct tlvdb *response, tlv_tag_t tag,
                                                     size_t length, bool required,
                                                     emv_analysis_result_t *result) {
    const struct tlv *field = NULL;
    size_t count = 0;
    for (const struct tlvdb *child = tlvdb_elm_get_children(response); child;
            child = tlvdb_elm_get_next(child)) {
        const struct tlv *candidate = tlvdb_get_tlv(child);
        if (candidate->tag == tag) {
            count++;
            field = candidate;
        }
    }
    if (required && !count)
        emv_analysis_finding(result, true, "response template 77 is missing mandatory tag %X", tag);
    if (count > 1)
        emv_analysis_finding(result, true, "response template 77 contains duplicate tag %X", tag);
    if (field && length != SIZE_MAX && field->len != length)
        emv_analysis_finding(result, true, "response tag %X has length %zu; expected %zu", tag, field->len, length);
    return field;
}

static void emv_analysis_responses(struct tlvdb *db, emv_format_hint_t hint, bool contact,
                                    emv_analysis_result_t *result) {
    if (hint != EMV_FORMAT_AUTO &&
            (tlvdb_elm_get_next(db) || (db->tag.tag != 0x80 && db->tag.tag != 0x77))) {
        emv_analysis_finding(result, true, "--gpo/--ac requires one response template (80 or 77)");
        return;
    }
    for (const struct tlvdb *response = db; response; response = tlvdb_elm_get_next(response)) {
        if (response->tag.tag != 0x77)
            continue;
        const struct tlvdb *children = tlvdb_elm_get_children(response);
        bool gpo = hint == EMV_FORMAT_GPO;
        bool ac = hint == EMV_FORMAT_AC;
        if (hint == EMV_FORMAT_AUTO) {
            for (const struct tlvdb *child = children; child; child = tlvdb_elm_get_next(child)) {
                tlv_tag_t tag = child->tag.tag;
                gpo |= tag == 0x82 || tag == 0x94;
                ac |= tag == 0x9f27 || tag == 0x9f26 || tag == 0x9f4b;
            }
            // Contactless GPO responses may also contain cryptogram data.
            if (gpo)
                ac = false;
        }
        if (gpo) {
            emv_analysis_response_field(response, 0x82, 2, true, result);
            const struct tlv *afl = emv_analysis_response_field(response, 0x94, SIZE_MAX, contact, result);
            if (!afl && !contact)
                PrintAndLogEx(INFO, "GPO has no AFL; its presence depends on the contactless kernel");
            if (afl && (afl->len > 252 || afl->len % 4))
                emv_analysis_finding(result, true, "GPO AFL length must be a multiple of four, at most 252 bytes");
        }
        if (ac) {
            const struct tlv *cid = emv_analysis_response_field(response, 0x9f27, 1, true, result);
            emv_analysis_response_field(response, 0x9f36, 2, true, result);
            const struct tlv *cryptogram = emv_analysis_response_field(response, 0x9f26, 8, false, result);
            const struct tlv *signature = emv_analysis_response_field(response, 0x9f4b, SIZE_MAX, false, result);
            if (!cryptogram && !signature)
                emv_analysis_finding(result, true, "GENERATE AC response has neither an application cryptogram nor signed dynamic data");
            if (signature && signature->len == 0)
                emv_analysis_finding(result, true, "GENERATE AC response contains empty signed dynamic data");
            if (cid && cid->len == 1 && (cid->value[0] & EMVAC_AC_MASK) == EMVAC_AC_MASK)
                emv_analysis_finding(result, true, "GENERATE AC response uses an RFU cryptogram type");
        }
    }
}

static void emv_analysis_expand_format1(struct tlvdb *db, emv_analysis_result_t *result,
                                        emv_format_hint_t hint) {
    const struct tlv *outer = tlvdb_get(db, 0x80, NULL);
    if (!outer) return;
    bool gpo_shape = outer->len >= 2 && outer->len <= 254 && (outer->len - 2) % 4 == 0;
    bool ac_shape = outer->len >= 11;
    if (hint == EMV_FORMAT_AUTO && gpo_shape && ac_shape) {
        emv_analysis_finding(result, false, "tag 80 is ambiguous; use --gpo or --ac to identify the response");
        return;
    }
    if ((hint == EMV_FORMAT_GPO || (hint == EMV_FORMAT_AUTO && gpo_shape)) && gpo_shape) {
        PrintAndLogEx(INFO, "Recognized Format 1 GPO response");
        emv_analysis_add(db, 0x82, 2, outer->value, result);
        emv_analysis_add(db, 0x94, outer->len - 2, outer->value + 2, result);
    } else if ((hint == EMV_FORMAT_AC || hint == EMV_FORMAT_AUTO) && ac_shape) {
        PrintAndLogEx(INFO, "Recognized Format 1 GENERATE AC response");
        if ((outer->value[0] & EMVAC_AC_MASK) == EMVAC_AC_MASK)
            emv_analysis_finding(result, true, "GENERATE AC response uses an RFU cryptogram type");
        emv_analysis_add(db, 0x9f27, 1, outer->value, result);
        emv_analysis_add(db, 0x9f36, 2, outer->value + 1, result);
        emv_analysis_add(db, 0x9f26, 8, outer->value + 3, result);
        if (outer->len > 11) emv_analysis_add(db, 0x9f10, outer->len - 11, outer->value + 11, result);
    } else if (hint == EMV_FORMAT_GPO)
        emv_analysis_finding(result, true, "tag 80 is not a valid Format 1 GPO response");
    else if (hint == EMV_FORMAT_AC)
        emv_analysis_finding(result, true, "tag 80 is not a valid Format 1 GENERATE AC response");
    else
        emv_analysis_finding(result, true, "tag 80 is not a valid Format 1 GPO or GENERATE AC response");
}

static bool emv_analyze_tlvdb(struct tlvdb *db, bool dump_tlv,
                              emv_format_hint_t hint, bool contact, emv_analysis_result_t *result) {
    if (!db || !result)
        return false;
    memset(result, 0, sizeof(*result));
    emv_analysis_responses(db, hint, contact, result);
    emv_analysis_expand_format1(db, result, hint);
    tlvdb_visit(db, emv_analysis_count_cb, result, 0);
    if (dump_tlv) {
        PrintAndLogEx(INFO, "-------------------- decoded input --------------------");
        TLVPrintFromTLV(db);
    }
    PrintAndLogEx(INFO, "-------------------- EMV analysis --------------------");
    emv_analysis_lengths(db, result);
    emv_analysis_unpredictable_numbers(db, result);
    emv_analysis_afl(tlvdb_get(db, 0x94, NULL), result);
    emv_analysis_cvm(tlvdb_get(db, 0x8e, NULL), result);
    emv_analysis_brand_t brand = emv_analysis_aid_brand(tlvdb_get(db, 0x84, NULL));
    emv_analysis_visit_t visit = {
        .result = result,
        .mastercard = brand == EMV_BRAND_MASTERCARD,
        .visa = brand == EMV_BRAND_VISA,
        .dump_tlv = dump_tlv,
    };
    tlvdb_visit(db, emv_analysis_visit_cb, &visit, 0);
    emv_analysis_scripts(db, result);
    emv_analysis_correlate(db, result);
    emv_analysis_restrictions(db, contact, result);
    PrintAndLogEx(result->errors ? WARNING : SUCCESS,
                  "Analysis summary: %zu objects, %zu warning(s), %zu error(s)",
                  result->objects, result->warnings, result->errors);
    return result->errors == 0;
}

static bool emv_analyze_data(const uint8_t *data, size_t len, bool dump_tlv,
                             emv_format_hint_t hint, bool contact, emv_analysis_result_t *result) {
    if (!data || !len || !result)
        return false;
    struct tlvdb *db = tlvdb_parse_multi(data, len);
    if (!db) {
        memset(result, 0, sizeof(*result));
        emv_analysis_finding(result, true, "input is not well-formed BER-TLV data");
        return false;
    }
    bool valid = emv_analyze_tlvdb(db, dump_tlv, hint, contact, result);
    tlvdb_free(db);
    return valid;
}

/*
static int emv_calc_cvv(const uint8_t *pan, size_t panlen, const uint8_t *expiry, const uint8_t *servicecode, const uint8_t *atc) {

    uint8_t key[16] = {0};
    memset(key, 0x30, sizeof(key));

    uint8_t d[32] = {0};
    uint8_t *pd = d;

    memcpy(pd, pan, panlen);
    pd += panlen;
    memcpy(pd, expiry, 4);
    pd += 4;

    // cvv/cvc
    memcpy(pd, servicecode, 3);
    pd += 3;

    // atc
    memcpy(pd, atc, 4);

    uint8_t encrypted[16] = {0};

    // zero padding?!?

    mbedtls_des_context ctx;
    mbedtls_des_setkey_enc(&ctx, key);
    mbedtls_des_crypt_ecb(&ctx, d, encrypted);
    mbedtls_des_crypt_ecb(&ctx, d + 6, encrypted + 6);

    // xor
    for (size_t i = 16; i < 32; i++) {
        d[i] ^= encrypted[i - 16];
    }

    mbedtls_des_free(&ctx);

    PrintAndLogEx(INFO, "key... %s", sprint_hex_inrow(key, sizeof(key)));
    PrintAndLogEx(INFO, "d..... %s", sprint_hex_inrow(d, sizeof(d)));


    mbedtls_des3_context ctx3;
    mbedtls_des3_init(&ctx3);
    mbedtls_des3_set2key_enc(&ctx3, key);
    mbedtls_des3_set2key_dec(&ctx3, key);
    mbedtls_des3_crypt_ecb(&ctx3, d, encrypted);
    mbedtls_des3_free(&ctx3);

    PrintAndLogEx(INFO, "enc... %s", sprint_hex_inrow(encrypted, sizeof(encrypted)));

    memset(encrypted, 0, sizeof(encrypted));
    des3_encrypt(encrypted, d, key, 2);
    PrintAndLogEx(INFO, "enc... %s", sprint_hex_inrow(encrypted, sizeof(encrypted)));

    return PM3_SUCCESS;
}
*/

static int CmdEMVAnalyze(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv analyze",
                  "Collect and analyze a complete EMV card profile, or decode supplied BER-TLV data offline.\n"
                  "Checks standard lengths, AFL and CVM structure, DOLs, dates, issuer scripts,\n"
                  "action-code/security correlations, repeated unpredictable numbers, and expands\n"
                  "Format 1 GPO/GENERATE AC responses. Concatenate trace TLVs to correlate them.\n"
                  "With no hex input it activates a card, runs the reader workflow, reads AFL records\n"
                  "and transaction metadata, then performs the full analysis automatically.\n"
                  "Use --gpo or --ac to validate one complete response, and -w to apply\n"
                  "Book 3 contact processing restrictions to offline data. Include selected AID\n"
                  "tag 84 to interpret scheme-specific data such as 9F69.\n",
                  "emv analyze\n"
                  "emv analyze -a -w\n"
                  "emv analyze 770a82020000940408010100\n"
                  "emv analyze -v --gpo 8006000008010100\n"
                  "emv analyze 9f3704000000019f3704000000029f3704000000039f370400000004\n");
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "Print the complete decoded TLV tree before analysis"),
        arg_lit0("a", "apdu", "Show APDU requests and responses during automatic card collection"),
        arg_lit0("w", "wired", "Use the contact interface, or contact processing rules for offline data"),
        arg_lit0(NULL, "gpo", "Validate one GPO response (template 80 or 77)"),
        arg_lit0(NULL, "ac", "Validate one GENERATE AC response (template 80 or 77)"),
        arg_strx0(NULL, NULL, "<hex>", "Optional BER-TLV encoded EMV data"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t data[4096] = {0};
    int data_len = 0;
    bool verbose = arg_get_lit(ctx, 1);
    bool show_apdu = arg_get_lit(ctx, 2);
    bool wired = arg_get_lit(ctx, 3);
    bool force_gpo = arg_get_lit(ctx, 4);
    bool force_ac = arg_get_lit(ctx, 5);
    CLIGetHexWithReturn(ctx, 6, data, &data_len);
    CLIParserFree(ctx);
    if (force_gpo && force_ac) {
        PrintAndLogEx(ERR, "Choose only one of --gpo and --ac");
        return PM3_EINVARG;
    }
    if (data_len <= 0) {
        if (force_gpo || force_ac) {
            PrintAndLogEx(ERR, "--gpo/--ac requires an offline response");
            return PM3_EINVARG;
        }
        char reader_args[64] = "--analyze";
        if (verbose)
            strcat(reader_args, " --verbose");
        if (show_apdu)
            strcat(reader_args, " --apdu");
        if (wired)
            strcat(reader_args, " --wired");
        PrintAndLogEx(INFO, "No offline TLV supplied; starting automatic card collection and analysis");
        return CmdEMVReader(reader_args);
    }

    emv_analysis_result_t result;
    emv_format_hint_t hint = force_gpo ? EMV_FORMAT_GPO : (force_ac ? EMV_FORMAT_AC : EMV_FORMAT_AUTO);
    return emv_analyze_data(data, data_len, verbose, hint, wired, &result) ? PM3_SUCCESS : PM3_ESOFT;
}

static bool emv_action_matches(const uint8_t masks[7][5], size_t issuer, size_t terminal,
                                uint8_t matched[5]) {
    bool any = false;
    for (size_t i = 0; i < 5; i++) {
        matched[i] = masks[0][i] & (masks[issuer][i] | masks[terminal][i]);
        any |= matched[i] != 0;
    }
    return any;
}

static uint8_t emv_action_decision(const uint8_t masks[7][5], bool unavailable, bool offline_only,
                                   uint8_t matched[5], const char **stage) {
    *stage = "Denial";
    if (emv_action_matches(masks, 1, 4, matched))
        return EMVAC_AAC;
    *stage = "Online";
    bool online = emv_action_matches(masks, 2, 5, matched);
    if (!offline_only && online && !unavailable)
        return EMVAC_ARQC;
    if (offline_only || (online && unavailable)) {
        *stage = "Default";
        return emv_action_matches(masks, 3, 6, matched) ? EMVAC_AAC : EMVAC_TC;
    }
    *stage = "No action-code match";
    return EMVAC_TC;
}

static int CmdEMVAction(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv action",
                  "Explain Book 3 terminal action analysis offline; no APDUs are sent.\n"
                  "Defaults: IAC-Denial and all TACs are zero; IAC-Online/Default are FF.\n"
                  "The result is the terminal's cryptogram request, not issuer approval.\n",
                  "emv action --tvr 8000000000\n"
                  "emv action --tvr 8000000000 --tac-denial 8000000000\n"
                  "emv action --tvr 8000000000 --unavailable --iac-default 0000000000\n");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "tvr", "<hex>", "Terminal Verification Results (5 bytes)"),
        arg_str0(NULL, "iac-denial", "<hex>", "Issuer Action Code - Denial (5 bytes)"),
        arg_str0(NULL, "iac-online", "<hex>", "Issuer Action Code - Online (5 bytes)"),
        arg_str0(NULL, "iac-default", "<hex>", "Issuer Action Code - Default (5 bytes)"),
        arg_str0(NULL, "tac-denial", "<hex>", "Terminal Action Code - Denial (5 bytes)"),
        arg_str0(NULL, "tac-online", "<hex>", "Terminal Action Code - Online (5 bytes)"),
        arg_str0(NULL, "tac-default", "<hex>", "Terminal Action Code - Default (5 bytes)"),
        arg_lit0(NULL, "unavailable", "Online-capable terminal could not obtain an online response"),
        arg_lit0(NULL, "offline-only", "Offline-only terminal; evaluate Default after Denial"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint8_t masks[7][5] = {{0}};
    memset(masks[2], 0xff, 5);
    memset(masks[3], 0xff, 5);
    for (size_t i = 0; i < ARRAYLEN(masks); i++) {
        int len = 0;
        CLIGetHexWithReturn(ctx, i + 1, masks[i], &len);
        if ((i == 0 || arg_get_str_len(ctx, i + 1)) && len != 5) {
            CLIParserFree(ctx);
            PrintAndLogEx(ERR, "Every supplied TVR/action code must contain exactly five bytes");
            return PM3_EINVARG;
        }
    }
    bool unavailable = arg_get_lit(ctx, 8);
    bool offline_only = arg_get_lit(ctx, 9);
    CLIParserFree(ctx);
    if (unavailable && offline_only) {
        PrintAndLogEx(ERR, "Choose either --unavailable or --offline-only");
        return PM3_EINVARG;
    }
    static const char *names[] = {"TVR", "IAC-Denial", "IAC-Online", "IAC-Default", "TAC-Denial", "TAC-Online", "TAC-Default"};
    for (size_t i = 0; i < ARRAYLEN(masks); i++)
        PrintAndLogEx(INFO, "%s: %s", names[i], sprint_hex_inrow(masks[i], 5));
    uint8_t matched[5];
    const char *stage;
    uint8_t decision = emv_action_decision(masks, unavailable, offline_only, matched, &stage);
    PrintAndLogEx(INFO, "Decision stage: %s; matching TVR bits: %s", stage, sprint_hex_inrow(matched, 5));
    PrintAndLogEx(SUCCESS, "Terminal request: %s", decision == EMVAC_AAC ? "AAC (decline)" :
                  decision == EMVAC_ARQC ? "ARQC (online authorisation requested)" : "TC (offline approval requested)");
    return PM3_SUCCESS;
}

static const struct tlvdb *emv_diff_occurrence(const struct tlvdb *db, tlv_tag_t tag, size_t occurrence) {
    for (; db; db = tlvdb_elm_get_next(db)) {
        if (db->tag.tag == tag && --occurrence == 0)
            return db;
    }
    return NULL;
}

static void emv_diff_report(const char *kind, const char *path, const struct tlv *left,
                             const struct tlv *right, bool verbose, bool report) {
    if (!report)
        return;
    PrintAndLogEx(INFO, "%s %s (left %zu bytes, right %zu bytes)", kind, path,
                  left ? left->len : 0, right ? right->len : 0);
    if (verbose) {
        if (left) PrintAndLogEx(INFO, "  left:  %s", sprint_hex_inrow(left->value, left->len));
        if (right) PrintAndLogEx(INFO, "  right: %s", sprint_hex_inrow(right->value, right->len));
    }
}

static int emv_diff_trees(const struct tlvdb *left, const struct tlvdb *right, const char *path,
                           bool verbose, bool report, size_t *changes) {
    for (const struct tlvdb *node = left; node; node = tlvdb_elm_get_next(node)) {
        size_t occurrence = 1;
        for (const struct tlvdb *prior = left; prior != node; prior = tlvdb_elm_get_next(prior))
            occurrence += prior->tag.tag == node->tag.tag;
        char child_path[256];
        int n = snprintf(child_path, sizeof(child_path), "%s/%X[%zu]", path, node->tag.tag, occurrence);
        if (n < 0 || (size_t)n >= sizeof(child_path))
            return PM3_EOVFLOW;
        const struct tlvdb *peer = emv_diff_occurrence(right, node->tag.tag, occurrence);
        if (!peer) {
            (*changes)++;
            emv_diff_report("Removed", child_path, &node->tag, NULL, verbose, report);
        } else if (tlv_is_constructed(&node->tag)) {
            int res = emv_diff_trees(tlvdb_elm_get_children(node), tlvdb_elm_get_children(peer),
                                     child_path, verbose, report, changes);
            if (res != PM3_SUCCESS)
                return res;
        } else if (!tlv_equal(&node->tag, &peer->tag)) {
            (*changes)++;
            emv_diff_report("Changed", child_path, &node->tag, &peer->tag, verbose, report);
        }
    }
    for (const struct tlvdb *node = right; node; node = tlvdb_elm_get_next(node)) {
        size_t occurrence = 1;
        for (const struct tlvdb *prior = right; prior != node; prior = tlvdb_elm_get_next(prior))
            occurrence += prior->tag.tag == node->tag.tag;
        if (emv_diff_occurrence(left, node->tag.tag, occurrence))
            continue;
        char child_path[256];
        int n = snprintf(child_path, sizeof(child_path), "%s/%X[%zu]", path, node->tag.tag, occurrence);
        if (n < 0 || (size_t)n >= sizeof(child_path))
            return PM3_EOVFLOW;
        (*changes)++;
        emv_diff_report("Added", child_path, NULL, &node->tag, verbose, report);
    }
    return PM3_SUCCESS;
}

static int CmdEMVDiff(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv diff",
                  "Compare two BER-TLV captures offline by tag path and occurrence.\n"
                  "Unique-tag ordering is ignored; repeated tags retain their occurrence order.\n"
                  "Values are shown only with --verbose. No APDUs are sent.\n",
                  "emv diff --left 9f36020001 --right 9f36020002\n"
                  "emv diff -v --left 9f36020001 --right 9f36020002\n");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "left", "<hex>", "First BER-TLV capture"),
        arg_str1(NULL, "right", "<hex>", "Second BER-TLV capture"),
        arg_lit0("v", "verbose", "Show changed, added and removed values"),
        arg_lit0(NULL, "fail-on-change", "Return an error when captures differ"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint8_t left[4096], right[4096];
    int left_len = 0, right_len = 0;
    CLIGetHexWithReturn(ctx, 1, left, &left_len);
    CLIGetHexWithReturn(ctx, 2, right, &right_len);
    bool verbose = arg_get_lit(ctx, 3);
    bool fail_on_change = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);
    struct tlvdb *left_db = tlvdb_parse_multi(left, left_len);
    struct tlvdb *right_db = tlvdb_parse_multi(right, right_len);
    if (!left_db || !right_db) {
        tlvdb_free(left_db);
        tlvdb_free(right_db);
        PrintAndLogEx(ERR, "Both captures must contain well-formed, nonempty BER-TLV data");
        return PM3_EINVARG;
    }
    size_t changes = 0;
    int res = emv_diff_trees(left_db, right_db, "", verbose, true, &changes);
    tlvdb_free(left_db);
    tlvdb_free(right_db);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "TLV path exceeds the comparison depth limit");
        return res;
    }
    PrintAndLogEx(SUCCESS, "EMV diff: %zu changed object(s)", changes);
    return fail_on_change && changes ? PM3_ESOFT : PM3_SUCCESS;
}

static int CmdEMVGetData(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv getdata",
                  "Execute the EMV GET DATA command for the currently selected application.\n"
                  "Book 3 defines 9F36, 9F13, 9F17, 9F4F, BF4C, and BF4D.\n",
                  "emv getdata -t 9f36\n"
                  "emv getdata -kt bf4c\n");
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k", "keep", "Keep the field on for the next command"),
        arg_lit0("a", "apdu", "Show APDU requests and responses"),
        arg_lit0("t", "tlv", "Decode successful response as TLV"),
        arg_lit0("w", "wired", "Use the contact ISO 7816 interface"),
        arg_str1(NULL, NULL, "<tag>", "One- or two-byte data object tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool keep = arg_get_lit(ctx, 1);
    bool show_apdu = arg_get_lit(ctx, 2);
    bool decode_tlv = arg_get_lit(ctx, 3);
    Iso7816CommandChannel channel = arg_get_lit(ctx, 4) ? CC_CONTACT : CC_CONTACTLESS;
    uint8_t tag_data[2] = {0};
    int tag_len = 0;
    CLIGetHexWithReturn(ctx, 5, tag_data, &tag_len);
    CLIParserFree(ctx);
    if (tag_len < 1 || tag_len > 2) {
        PrintAndLogEx(ERR, "GET DATA requires a one- or two-byte tag");
        return PM3_EINVARG;
    }
    uint16_t tag = tag_len == 1 ? tag_data[0] : ((uint16_t)tag_data[0] << 8) | tag_data[1];

    PrintChannel(channel);
    SetAPDULogging(show_apdu);
    uint8_t response[APDU_RES_LEN] = {0};
    size_t response_len = 0;
    uint16_t sw = 0;
    int res = EMVGetData(channel, keep, tag, response, sizeof(response), &response_len, &sw, NULL);
    PrintAndLogEx(sw == ISO7816_OK ? SUCCESS : WARNING, "APDU status: %04x - %s",
                  sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
    if (res == PM3_SUCCESS && sw == ISO7816_OK) {
        PrintAndLogEx(INFO, "Data: %s", sprint_hex_inrow(response, response_len));
        if (decode_tlv) TLVPrintFromBuffer(response, response_len);
    }
    PrintEMVAPDUHint(channel, res, sw);
    SetAPDULogging(false);
    return res;
}

static int CmdEMVExternalAuthenticate(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv extauth",
                  "Execute EXTERNAL AUTHENTICATE with issuer authentication data (tag 91 value).\n"
                  "The application must already be selected and processing initiated.\n",
                  "emv extauth -ka 1122334455667788\n");
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k", "keep", "Keep the field on for the next command"),
        arg_lit0("a", "apdu", "Show APDU requests and responses"),
        arg_lit0("w", "wired", "Use the contact ISO 7816 interface"),
        arg_strx1(NULL, NULL, "<hex>", "Issuer Authentication Data, 8 to 16 bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool keep = arg_get_lit(ctx, 1);
    bool show_apdu = arg_get_lit(ctx, 2);
    Iso7816CommandChannel channel = arg_get_lit(ctx, 3) ? CC_CONTACT : CC_CONTACTLESS;
    uint8_t auth_data[16] = {0};
    int auth_len = 0;
    CLIGetHexWithReturn(ctx, 4, auth_data, &auth_len);
    CLIParserFree(ctx);
    if (auth_len < 8 || auth_len > 16) {
        PrintAndLogEx(ERR, "Issuer Authentication Data must be 8 to 16 bytes");
        return PM3_EINVARG;
    }

    PrintChannel(channel);
    SetAPDULogging(show_apdu);
    uint8_t response[APDU_RES_LEN] = {0};
    size_t response_len = 0;
    uint16_t sw = 0;
    int res = EMVExternalAuthenticate(channel, keep, auth_data, auth_len,
                                      response, sizeof(response), &response_len, &sw);
    PrintAndLogEx(sw == ISO7816_OK ? SUCCESS : WARNING, "APDU status: %04x - %s",
                  sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
    PrintEMVAPDUHint(channel, res, sw);
    SetAPDULogging(false);
    return res;
}


static struct tlvdb *emv_logtemplate_parse(const struct tlv *tlv) {
    if (!tlv || (!tlv->value && tlv->len))
        return NULL;

    const unsigned char *buf = tlv->value;
    size_t left = tlv->len;
    struct tlvdb *db = NULL;

    while (left) {
        struct tlv cur_tlv;
        if (!dol_parse_tl(&buf, &left, &cur_tlv)) {
            tlvdb_free(db);
            return NULL;
        }

        // The log template is a DOL (tag + expected length), not a log
        // record. Build a shape-only TLV tree; emv_parse_log applies those
        // lengths to each record read later.
        uint8_t *placeholder = cur_tlv.len ? calloc(cur_tlv.len, 1) : NULL;
        if (cur_tlv.len && !placeholder) {
            tlvdb_free(db);
            return NULL;
        }
        struct tlvdb *tag_db = tlvdb_fixed(cur_tlv.tag, cur_tlv.len, placeholder);
        free(placeholder);
        if (!tag_db) {
            tlvdb_free(db);
            return NULL;
        }
        if (!db)
            db = tag_db;
        else
            tlvdb_add(db, tag_db);
    }

    return db;
}

static int emv_parse_log(struct tlvdb *ttdb, const uint8_t *d, size_t n) {
    /*
        The Log Format (9F4F) is a list in tag and length format (i.e., "TL" instead of TLV) See description in Table 33 on page 141.

        In your example, "9F 27 01 9F 02 06 5F 2A 02 9A 03 9F 36 02 9F 52 06 DF 3E 01 9F 21 03 9F 7C 14" means:

        9F27 01 (Cryptogram Information Data)
        9F02 06 (Amount, Authorised)
        5F2A 02 (Transaction Currency Code)
        9A 03 (Transaction Date)
        9F36 02 (Application Transaction Counter)
        9F52 06 (Terminal Compatibility Indicator)
        DF3E 01
        9F21 03 (Transaction Time)
        9F7C 14 (Visa Customer Exclusive Data)

    */
    if (!ttdb || (!d && n))
        return PM3_EINVARG;

    size_t pos = 0;
    struct tlvdb *tp = ttdb;
    while (tp) {
        const struct tlv *tpitem = tlvdb_get_tlv(tp);
        if (!tpitem || pos > n || tpitem->len > n - pos) {
            PrintAndLogEx(ERR, "Log record is shorter than its Log Format");
            return PM3_EOVFLOW;
        }

        const char *s = emv_get_tag_name(tpitem);

        switch (tpitem->tag) {
            case 0x5F2A:
                if (tpitem->len == 2) {

                    char tmp[5] = {0};
                    snprintf(tmp, sizeof(tmp), "%x%02x", d[pos], d[pos + 1]);
                    const char *cn = getCurrencyInfo(tmp);
                    PrintAndLogEx(INFO, "%-30s... " _YELLOW_("%s") " ( %x%02x )", s, cn, d[pos], d[pos + 1]);
                }
                break;
            case 0x9A:
                if (tpitem->len == 3) {
                    PrintAndLogEx(INFO, "%-30s... " _YELLOW_("20%02x-%02x-%02x"), s, d[pos], d[pos + 1], d[pos + 2]);
                }
                break;
            case 0x9F21:
                if (tpitem->len == 3) {
                    PrintAndLogEx(INFO, "%-30s... " _YELLOW_("%02x:%02x:%02x"), s, d[pos], d[pos + 1], d[pos + 2]);
                }
                break;
            default:
                PrintAndLogEx(INFO, "%-30s... " _YELLOW_("%s"), s, sprint_hex_inrow(d + pos, tpitem->len));
                break;
        }

        pos += tpitem->len;

        tp = tlvdb_elm_get_next(tp);
    }
    if (pos != n)
        PrintAndLogEx(WARNING, "Log record has %zu trailing byte(s)", n - pos);
    return PM3_SUCCESS;
}

static int emv_extract_log_info(uint8_t *response, size_t reslen, uint8_t *lid,  uint8_t *lrecs) {
    if (!response || !reslen || !lid || !lrecs)
        return PM3_EINVARG;

    struct tlvdb *t = tlvdb_parse_multi(response, reslen);
    if (t == NULL) {
        PrintAndLogEx(INFO, "root null");
        return PM3_EINVARG;
    }

    int res = PM3_ESOFT;
    struct tlvdb *logs = tlvdb_find_full(t, 0x9F4D);
    if (logs != NULL) {
        const struct tlv *tlv = tlvdb_get_tlv(logs);
        if (tlv->len == 2) {
            *lid = tlv->value[0];
            *lrecs = tlv->value[1];
            PrintAndLogEx(DEBUG, "Logs EMV...  SFI %u Records # %u", *lid, *lrecs);
            res = PM3_SUCCESS;
        }
    }

    tlvdb_free(t);
    return res;
}

static bool emv_format_pan(const char *pan, size_t pan_len, char *formatted, size_t formatted_size) {
    if (!pan || pan_len < 8 || pan_len > 19 || !formatted || formatted_size < pan_len + 1)
        return false;
    size_t out = 0;
    for (size_t i = 0; i < pan_len; i++) {
        if (pan[i] < '0' || pan[i] > '9')
            return false;
        if (i && i % 4 == 0) {
            if (out + 1 >= formatted_size)
                return false;
            formatted[out++] = ' ';
        }
        if (out + 1 >= formatted_size)
            return false;
        formatted[out++] = pan[i];
    }
    formatted[out] = '\0';
    return true;
}

static int emv_parse_track1(const uint8_t *d, size_t n, bool verbose) {
    if (d == NULL || n < 10) {
        return PM3_EINVARG;
    }
    if (verbose == false) {
        return PM3_SUCCESS;
    }

    // sanity checks
    if (d[0] != 'B') {
        return PM3_EINVARG;
    }

    // decoder
    char *tmp = str_ndup((const char *)d, n);
    if (!tmp)
        return PM3_EMALLOC;
    uint8_t i = 0;
    const char delim[2] = "^";
    char *token = strtok(tmp, delim);
    while (token != NULL) {

        switch (i) {
            case 0: {
                size_t a = strlen(token);
                char pan[24] = {0};
                if (a < 2 || token[0] != 'B' || !emv_format_pan(token + 1, a - 1, pan, sizeof(pan))) {
                    free(tmp);
                    return PM3_EINVARG;
                }
                PrintAndLogEx(INFO, "PAN...................... " _GREEN_("%s"), pan);
                break;
            }
            case 1:
                PrintAndLogEx(INFO, "CardHolder............... %s", token);
                break;
            case 2:
                if (strlen(token) < 14) {
                    break;
                }
                PrintAndLogEx(INFO, "Expiry date.............. %.*s ( %c%c/%c%c )", 4, token, token[2], token[3], token[0], token[1]);
                token += 4;

                PrintAndLogEx(INFO, "Service code............. %.*s", 3, token);
                token += 3;

                PrintAndLogEx(INFO, "Unknown.................. %.*s", 4, token);
                token += 4;

                PrintAndLogEx(INFO, "CVV / iCvv............... %.*s", 3, token);
                token += 3;

                PrintAndLogEx(INFO, "Trailing................. %s", token);
                break;
            default:
                break;
        }
        token = strtok(0, delim);
        i++;
    }
    free(tmp);
    return PM3_SUCCESS;
}

static int emv_parse_track2(const uint8_t *d, size_t n, bool verbose) {
    if (d == NULL || n < 8 || n > 39) {
        return PM3_EINVARG;
    }
    if (verbose == false) {
        return PM3_SUCCESS;
    }

    // decoder
    uint8_t s[80] = {0};
    hex_to_buffer(s, d, n, n, 0, 0, true);
    char *separator = strchr((char *)s, 'D');
    if (!separator)
        return PM3_EINVARG;
    size_t pan_len = separator - (char *)s;
    char pan[24] = {0};
    if (!emv_format_pan((char *)s, pan_len, pan, sizeof(pan)))
        return PM3_EINVARG;
    char *discretionary = separator + 1;
    size_t remaining = strlen(discretionary);
    if (remaining < 7)
        return PM3_EINVARG;

    PrintAndLogEx(INFO, "PAN...................... " _GREEN_("%s"), pan);
    PrintAndLogEx(INFO, "Expiry date.............. %.*s ( %c%c/%c%c )", 4, discretionary,
                  discretionary[2], discretionary[3], discretionary[0], discretionary[1]);
    discretionary += 4;
    remaining -= 4;
    PrintAndLogEx(INFO, "Service code............. %.*s", 3, discretionary);
    discretionary += 3;
    remaining -= 3;

    if (remaining >= 4) {
        PrintAndLogEx(INFO, "Pin verification value... %.*s", 4, discretionary);
        discretionary += 4;
        remaining -= 4;
    }
    if (remaining >= 3) {
        PrintAndLogEx(INFO, "CVV / iCvv............... %.*s", 3, discretionary);
        discretionary += 3;
        remaining -= 3;
    }
    if (remaining && discretionary[remaining - 1] == 'F')
        remaining--;
    PrintAndLogEx(INFO, "Trailing................. %.*s", (int)remaining, discretionary);

    return PM3_SUCCESS;
}

static int emv_parse_card_details(uint8_t *response, size_t reslen, bool verbose) {

    struct tlvdb *root = tlvdb_parse_multi(response, reslen);
    if (root == NULL) {
        return PM3_EINVARG;
    }

    // extract application preferred name
    struct tlvdb *prefname_full = tlvdb_find_full(root, 0x9F12);
    if (prefname_full != NULL) {
        const struct tlv *prefname_tlv = tlvdb_get_tlv(prefname_full);
        if (prefname_tlv->len) {
            char name[64] = {0};
            size_t n = MIN(sizeof(name) - 1, prefname_tlv->len);
            memcpy(name, prefname_tlv->value, n);
            PrintAndLogEx(INFO, "Application.......... " _YELLOW_("%s"), name);
        }
    }

    // extract application label
    struct tlvdb *alabel = tlvdb_find_full(root, 0x50);
    if (alabel != NULL) {
        const struct tlv *alabel_tlv = tlvdb_get_tlv(alabel);
        if (alabel_tlv->len) {
            char name[64] = {0};
            size_t n = MIN(sizeof(name) - 1, alabel_tlv->len);
            memcpy(name, alabel_tlv->value, n);
            PrintAndLogEx(INFO, "Label................ " _YELLOW_("%s"), name);
        }
    }

    // extract language preference
    struct tlvdb *lang_full = tlvdb_find_full(root, 0x5F2D);
    if (lang_full != NULL) {
        const struct tlv *lang_tlv = tlvdb_get_tlv(lang_full);
        if (lang_tlv->len) {
            char lang[16] = {0};
            size_t n = MIN(sizeof(lang) - 1, lang_tlv->len);
            memcpy(lang, lang_tlv->value, n);
            PrintAndLogEx(INFO, "Language............. " _YELLOW_("%s"), lang);
        }
    }

    // Application Currency Code
    struct tlvdb *acc_full = tlvdb_find_full(root, 0x9F42);
    if (acc_full != NULL) {
        const struct tlv *acc_tlv = tlvdb_get_tlv(acc_full);
        if (acc_tlv->len == 2) {
            uint16_t acc = MemBeToUint2byte((const uint8_t *)acc_tlv->value);

            char tmp[5] = {0};
            snprintf(tmp, sizeof(tmp), "%x%02x", acc_tlv->value[0], acc_tlv->value[1]);
            const char *cn = getCurrencyInfo(tmp);

            PrintAndLogEx(INFO, "Currency Code........ " _YELLOW_("%s") " ( %x )", cn, acc);
        }
    }

    // Application Effective Date
    struct tlvdb *aeffect_full = tlvdb_find_full(root, 0x5F25);
    if (aeffect_full != NULL) {
        const struct tlv *aaeffect_tlv = tlvdb_get_tlv(aeffect_full);
        if (aaeffect_tlv->len == 3) {
            PrintAndLogEx(INFO, "Effective date....... " _YELLOW_("20%02x-%02x-%02x"),
                          aaeffect_tlv->value[0],
                          aaeffect_tlv->value[1],
                          aaeffect_tlv->value[2]
                         );
        }
    }

    // Application Expiration Date
    struct tlvdb *aexd_full = tlvdb_find_full(root, 0x5F24);
    if (aexd_full != NULL) {
        const struct tlv *aexd_tlv = tlvdb_get_tlv(aexd_full);
        if (aexd_tlv->len == 3) {
            PrintAndLogEx(INFO, "Expiration date...... " _YELLOW_("20%02x-%02x-%02x"),
                          aexd_tlv->value[0],
                          aexd_tlv->value[1],
                          aexd_tlv->value[2]
                         );
        }
    }

    // Application Primary Account Number (PAN)
    struct tlvdb *apan_full = tlvdb_find_full(root, 0x5A);
    if (apan_full != NULL) {
        const struct tlv *apan_tlv = tlvdb_get_tlv(apan_full);
        if (apan_tlv->len == 8) {
            PrintAndLogEx(INFO, "PAN.................. " _GREEN_("%02x%02x %02x%02x %02x%02x %02x%02x"),
                          apan_tlv->value[0],
                          apan_tlv->value[1],
                          apan_tlv->value[2],
                          apan_tlv->value[3],
                          apan_tlv->value[4],
                          apan_tlv->value[5],
                          apan_tlv->value[6],
                          apan_tlv->value[7]
                         );
        }
    }

    // Application Primary Account Number (PAN) sequence number
    struct tlvdb *apansq_full = tlvdb_find_full(root, 0x5F34);
    if (apansq_full != NULL) {
        const struct tlv *apansq_tlv = tlvdb_get_tlv(apansq_full);
        if (apansq_tlv->len == 1) {
            PrintAndLogEx(INFO, "PAN Sequence......... " _YELLOW_("%u"), apansq_tlv->value[0]);
        }
    }

    // Cardholder Name
    struct tlvdb *chm_full = tlvdb_find_full(root, 0x5F20);
    if (chm_full != NULL) {
        const struct tlv *chm_tlv = tlvdb_get_tlv(chm_full);
        if (chm_tlv->len) {
            PrintAndLogEx(INFO, "Cardhold Name........ " _YELLOW_("%s"), sprint_ascii(chm_tlv->value, chm_tlv->len));
        }
    }

    // Track 1 Data
    struct tlvdb *track1_full = tlvdb_find_full(root, 0x56);
    if (track1_full != NULL) {
        const struct tlv *track1_tlv = tlvdb_get_tlv(track1_full);
        if (track1_tlv->len) {
            PrintAndLogEx(INFO, "Track 1.............. " _YELLOW_("%s"), sprint_ascii(track1_tlv->value, track1_tlv->len));
            emv_parse_track1(track1_tlv->value, track1_tlv->len, verbose);
        }
    }

    // Track 2 Data
    struct tlvdb *track2_full = tlvdb_find_full(root, 0x9F6B);
    if (track2_full != NULL) {
        const struct tlv *track2_tlv = tlvdb_get_tlv(track2_full);
        if (track2_tlv->len) {
            PrintAndLogEx(INFO, "Track 2.............. " _YELLOW_("%s"), sprint_hex_inrow(track2_tlv->value, track2_tlv->len));
            emv_parse_track2(track2_tlv->value, track2_tlv->len, verbose);
        }
    }

    // Track 2 Equivalent Data
    struct tlvdb *track2_eq_full = tlvdb_find_full(root, 0x57);
    if (track2_eq_full != NULL) {
        const struct tlv *track2_eq_tlv = tlvdb_get_tlv(track2_eq_full);
        if (track2_eq_tlv->len) {
            PrintAndLogEx(INFO, "Track 2 equivalent... " _YELLOW_("%s"), sprint_hex_inrow(track2_eq_tlv->value, track2_eq_tlv->len));
            emv_parse_track2(track2_eq_tlv->value, track2_eq_tlv->len, verbose);
        }
    }

    // Track 3 Data
    // to be impl.

    // Unpredicable Number (UN)
    struct tlvdb *un1_full = tlvdb_find_full(root, 0x9f37);
    if (un1_full != NULL) {
        const struct tlv *un1_tlv = tlvdb_get_tlv(un1_full);
        if (un1_tlv->len) {
            PrintAndLogEx(INFO, "9F37 Unpredicable Number... " _YELLOW_("%s"), sprint_hex_inrow(un1_tlv->value, un1_tlv->len));
        }
    }

    // Unpredicable Number (UN)
    struct tlvdb *un_full = tlvdb_find_full(root, 0x9f6a);
    if (un_full != NULL) {
        const struct tlv *un_tlv = tlvdb_get_tlv(un_full);
        if (un_tlv->len) {
            PrintAndLogEx(INFO, "9F6A Unpredicable Number... " _YELLOW_("%s"), sprint_hex_inrow(un_tlv->value, un_tlv->len));
            emv_parse_track2(un_tlv->value, un_tlv->len, verbose);
        }
    }

    struct tlvdb *merch_full = tlvdb_find_full(root, 0x9f4e);
    if (merch_full != NULL) {
        const struct tlv *merch_tlv = tlvdb_get_tlv(merch_full);
        if (merch_tlv->len) {
            PrintAndLogEx(INFO, "Merchant Name and Location... " _YELLOW_("%s"), sprint_hex_inrow(merch_tlv->value, merch_tlv->len));
        }
    }

    tlvdb_free(root);
    return PM3_SUCCESS;
}

static int CmdEMVSelect(const char *Cmd) {
    uint8_t data[APDU_AID_LEN] = {0};
    int datalen = 0;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv select",
                  "Executes select applet command. An inactive contactless field is activated automatically.",
                  "emv select a00000000101       -> activate if needed, select applet\n"
                  "emv select -kt a00000000101   -> select applet, keep field on, show result in TLV\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("s",  "select",  "Activate field and select card"),
        arg_lit0("k",  "keep",    "Keep field for next command"),
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("t",  "tlv",     "TLV decode results"),
        arg_lit0("w",  "wired",   "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_str1(NULL, NULL, "<hex>", "Applet AID"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool activateField = arg_get_lit(ctx, 1);
    bool leaveSignalON = arg_get_lit(ctx, 2);
    bool show_apdu = arg_get_lit(ctx, 3);
    bool decodeTLV = arg_get_lit(ctx, 4);
    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 5))
        channel = CC_CONTACT;
    PrintChannel(channel);
    CLIGetHexWithReturn(ctx, 6, data, &datalen);
    CLIParserFree(ctx);

    SetAPDULogging(show_apdu);

    // exec
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = EMVSelect(channel, activateField, leaveSignalON, data, datalen, buf, sizeof(buf), &len, &sw, NULL);

    if (sw)
        PrintAndLogEx(INFO, "APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));

    PrintEMVAPDUHint(channel, res, sw);

    if (res) {
        SetAPDULogging(false);
        return res;
    }

    if (decodeTLV)
        TLVPrintFromBuffer(buf, len);

    SetAPDULogging(false);
    return PM3_SUCCESS;
}

static int CmdEMVSmartToNFC(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv smart2nfc",
                  "Executes ISO14443a payment, TX using ISO7816 interface for authentication",
                  "emv smart2nfc -t     -> test that the attached card is working (must be VISA)\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("t",  "test",    "test that the attached card is working (must be VISA)"),
        arg_str0("u", "uid", "<hex>", "optional 7 hex bytes UID"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int uidlen = 0;
    uint8_t uid[7] = {0};
    CLIGetHexWithReturn(ctx, 2, uid, &uidlen);

    if (uidlen == 0) {
        PrintAndLogEx(SUCCESS, "No UID provided, using default.");
        uint8_t default_uid[7] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
        memcpy(uid, default_uid, sizeof(default_uid));
        uidlen = sizeof(default_uid);
    } else if (uidlen != 7) {
        PrintAndLogEx(FAILED, "UID must be 7 bytes long.");
        return PM3_EINVARG;
    }

    PrintAndLogEx(SUCCESS, "UID length is %d", uidlen);

    bool testMode = arg_get_lit(ctx, 1);
    bool show_apdu = true;

    if (testMode) {
        PrintAndLogEx(SUCCESS, "Test mode enabled.");
    } else {
        PrintAndLogEx(SUCCESS, "Test mode disabled.");
    }

    CLIParserFree(ctx);

    // todo for PR: check this is relevant for us.
    SetAPDULogging(show_apdu);

    struct {
        uint16_t flags;
        uint8_t exitAfter;
        uint8_t uid[7];
        uint16_t atqa;
        uint8_t sak;
    } PACKED payload;

    memcpy(payload.uid, uid, uidlen);

    // Set up the flags for 2K mifare sim with RATS
    uint16_t flags = 0;

    FLAG_SET_UID_IN_DATA(flags, uidlen);
    if (IS_FLAG_UID_IN_EMUL(flags)) {
        PrintAndLogEx(WARNING, "Invalid parameter for UID");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    FLAG_SET_MF_SIZE(flags, MIFARE_2K_MAX_BYTES);

    flags |= FLAG_ATQA_IN_DATA;
    flags |= FLAG_SAK_IN_DATA;

    payload.flags = flags;
    payload.exitAfter = 0x1;
    payload.atqa = 0x0;
    payload.sak = 0x20;

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443A_EMV_SIMULATE, (uint8_t *)&payload, sizeof(payload));

    PrintAndLogEx(INFO, "Press " _GREEN_("pm3 button") " to abort simulation");

    SetAPDULogging(false);
    return PM3_SUCCESS;
}

static int CmdEMVSearch(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv search",
                  "Tries to select all applets from applet list\n",
                  "emv search -s   -> select card and search\n"
                  "emv search -st  -> select card, search and show result in TLV\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("s",  "select",  "Activate field and select card"),
        arg_lit0("k",  "keep",    "Keep field ON for next command"),
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("t",  "tlv",     "TLV decode results of selected applets"),
        arg_lit0("w",  "wired",   "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool activateField = arg_get_lit(ctx, 1);
    bool leaveSignalON = arg_get_lit(ctx, 2);
    bool show_apdu = arg_get_lit(ctx, 3);
    bool decodeTLV = arg_get_lit(ctx, 4);

    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 5)) {
        channel = CC_CONTACT;
    }

    PrintChannel(channel);
    CLIParserFree(ctx);

    SetAPDULogging(show_apdu);

    const char *al = "Applets list";
    struct tlvdb *t = tlvdb_fixed(1, strlen(al), (const unsigned char *)al);

    if (EMVSearch(channel, activateField, leaveSignalON, decodeTLV, t, false)) {
        tlvdb_free(t);
        SetAPDULogging(false);
        return PM3_ERFTRANS;
    }

    PrintAndLogEx(SUCCESS, "Search completed.");

    // print list here
    if (decodeTLV == false) {
        TLVPrintAIDlistFromSelectTLV(t);
    }

    tlvdb_free(t);

    SetAPDULogging(false);
    return PM3_SUCCESS;
}

static int CmdEMVPPSE(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv pse",
                  "Executes PSE/PPSE select command. It returns list of applet on the card:\n",
                  "emv pse -s1   -> select, get pse\n"
                  "emv pse -st2  -> select, get ppse, show result in TLV\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("s",  "select",  "Activate field and select card"),
        arg_lit0("k",  "keep",    "Keep field ON for next command"),
        arg_lit0("1",  "pse",     "PSE (1PAY.SYS.DDF01) mode"),
        arg_lit0("2",  "ppse",    "PPSE (2PAY.SYS.DDF01) mode (def)"),
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("t",  "tlv",     "TLV decode results of selected applets"),
        arg_lit0("w",  "wired",   "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool activateField = arg_get_lit(ctx, 1);
    bool leaveSignalON = arg_get_lit(ctx, 2);
    uint8_t PSENum = 2;
    if (arg_get_lit(ctx, 3)) {
        PSENum = 1;
    }
    if (arg_get_lit(ctx, 4)) {
        PSENum = 2;
    }
    bool show_apdu = arg_get_lit(ctx, 5);
    bool decodeTLV = arg_get_lit(ctx, 6);

    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 7)) {
        channel = CC_CONTACT;
    }
    PrintChannel(channel);
    CLIParserFree(ctx);

    SetAPDULogging(show_apdu);

    // exec
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = EMVSelectPSE(channel, activateField, leaveSignalON, PSENum, buf, sizeof(buf), &len, &sw);

    if (sw)
        PrintAndLogEx(sw == ISO7816_OK ? SUCCESS : WARNING,
                      "APDU response status: %04x - %s", sw,
                      GetAPDUCodeDescription(sw >> 8, sw & 0xff));

    if (res) {
        PrintEMVAPDUHint(channel, res, sw);
        SetAPDULogging(false);
        return res;
    }

    const char *directory = PSENum == 1 ? "PSE (1PAY.SYS.DDF01)" : "PPSE (2PAY.SYS.DDF01)";
    PrintAndLogEx(SUCCESS, "%s selected; received %zu data byte(s)", directory, len);
    if (len == 0) {
        PrintAndLogEx(WARNING, "The card returned no FCI data for the selected payment directory");
    } else {
        PrintAndLogEx(INFO, "Payment directory FCI:");
        if (!TLVPrintFromBuffer(buf, len))
            PrintAndLogEx(INFO, "Raw response: %s", sprint_hex_inrow(buf, len));
        emv_parse_card_details(buf, len, decodeTLV);
    }

    SetAPDULogging(false);
    return PM3_SUCCESS;
}

static int CmdEMVGPO(const char *Cmd) {
    uint8_t data[APDU_RES_LEN] = {0};
    int datalen = 0;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv gpo",
                  "Executes Get Processing Options command. It returns data in TLV format (0x77 - format2)\n"
                  "or plain format (0x80 - format1). Needs a EMV applet to be selected.",
                  "emv gpo -k              -> execute GPO\n"
                  "emv gpo -t 01020304     -> execute GPO with 4-byte PDOL data, show result in TLV\n"
                  "emv gpo -pmt 9F 37 04   -> load params from file, make PDOL data from PDOL, execute GPO with PDOL, show result in TLV\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k",  "keep",    "Keep field ON for next command"),
        arg_lit0("p",  "params",  "Load parameters from `emv_defparams.json` file for PDOLdata making from PDOL and parameters"),
        arg_lit0("m",  "make",    "Make PDOLdata from PDOL (tag 9F38) and parameters (def: uses default parameters)"),
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("t",  "tlv",     "TLV decode results of selected applets"),
        arg_lit0("w",  "wired",   "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_strx0(NULL,  NULL,    "<hex>", "PDOLdata/PDOL"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool leaveSignalON = arg_get_lit(ctx, 1);
    bool paramsLoadFromFile = arg_get_lit(ctx, 2);
    bool dataMakeFromPDOL = arg_get_lit(ctx, 3);
    bool show_apdu = arg_get_lit(ctx, 4);
    bool decodeTLV = arg_get_lit(ctx, 5);
    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 6)) {
        channel = CC_CONTACT;
    }
    PrintChannel(channel);
    CLIGetHexWithReturn(ctx, 7, data, &datalen);
    CLIParserFree(ctx);

    SetAPDULogging(show_apdu);

    // Init TLV tree
    const char *alr = "Root terminal TLV tree";
    struct tlvdb *tlvRoot = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);

    // calc PDOL
    struct tlv *pdol_data_tlv = NULL;
    struct tlvdb *tmp_ext = NULL;
    struct tlv data_tlv = {
        .tag = 0x83,
        .len = datalen,
        .value = (uint8_t *)data,
    };
    if (dataMakeFromPDOL) {
        if (!ParamLoadDefaults(tlvRoot)) {
            tlvdb_free(tlvRoot);
            SetAPDULogging(false);
            return PM3_ESOFT;
        }

        if (paramsLoadFromFile) {
            PrintAndLogEx(INFO, "Params loading from file...");
            ParamLoadFromJson(tlvRoot);
        };

        tmp_ext = tlvdb_external(0x9f38, datalen, data);
        pdol_data_tlv = dol_process((const struct tlv *)tmp_ext, tlvRoot, 0x83);
        if (!pdol_data_tlv) {
            PrintAndLogEx(ERR, "Can't create PDOL TLV.");
            tlvdb_free(tmp_ext);
            tlvdb_free(tlvRoot);
            SetAPDULogging(false);
            return PM3_ESOFT;
        }
    } else {
        if (paramsLoadFromFile) {
            PrintAndLogEx(WARNING, "Don't need to load parameters. Sending plain PDOL data...");
        }
        pdol_data_tlv = &data_tlv;
    }

    size_t pdol_data_tlv_data_len = 0;
    unsigned char *pdol_data_tlv_data = tlv_encode(pdol_data_tlv, &pdol_data_tlv_data_len);
    if (!pdol_data_tlv_data) {
        PrintAndLogEx(ERR, "Can't create PDOL data.");
        tlvdb_free(tmp_ext);
        tlvdb_free(tlvRoot);
        if (pdol_data_tlv != &data_tlv) {
            free(pdol_data_tlv);
        }
        SetAPDULogging(false);
        return PM3_ESOFT;
    }
    PrintAndLogEx(INFO, "PDOL data[%zu]: %s", pdol_data_tlv_data_len, sprint_hex(pdol_data_tlv_data, pdol_data_tlv_data_len));

    // exec
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = EMVGPO(channel, leaveSignalON, pdol_data_tlv_data, pdol_data_tlv_data_len, buf, sizeof(buf), &len, &sw, tlvRoot);
    free(pdol_data_tlv_data);

    if (pdol_data_tlv != &data_tlv)
        free(pdol_data_tlv);

    tlvdb_free(tmp_ext);
    tlvdb_free(tlvRoot);

    if (sw)
        PrintAndLogEx(INFO, "APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));

    if (res)
        return res;

    if (decodeTLV)
        TLVPrintFromBuffer(buf, len);

    SetAPDULogging(false);
    return PM3_SUCCESS;
}

static int CmdEMVReadRecord(const char *Cmd) {
    uint8_t data[APDU_RES_LEN] = {0};
    int datalen = 0;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv readrec",
                  "Executes Read Record command. It returns data in TLV format.\n"
                  "Needs a bank applet to be selected and sometimes needs GPO to be executed.",
                  "emv readrec -k 0101   -> read file SFI=01, SFIrec=01\n"
                  "emv readrec -kt 0201  -> read file 0201 and show result in TLV\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k",  "keep",    "Keep field ON for next command"),
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("t",  "tlv",     "TLV decode results of selected applets"),
        arg_lit0("w",  "wired",   "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_strx1(NULL, NULL,     "<hex>", "<SFI 1 byte><SFIrecord 1 byte"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool leaveSignalON = arg_get_lit(ctx, 1);
    bool show_apdu = arg_get_lit(ctx, 2);
    bool decodeTLV = arg_get_lit(ctx, 3);
    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 4)) {
        channel = CC_CONTACT;
    }
    PrintChannel(channel);
    CLIGetHexWithReturn(ctx, 5, data, &datalen);
    CLIParserFree(ctx);

    if (datalen != 2) {
        PrintAndLogEx(ERR, "Command needs to have 2 bytes of data");
        return PM3_EINVARG;
    }

    SetAPDULogging(show_apdu);

    // exec
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = EMVReadRecord(channel, leaveSignalON, data[0], data[1], buf, sizeof(buf), &len, &sw, NULL);
    SetAPDULogging(false);

    if (sw)
        PrintAndLogEx(sw == ISO7816_OK ? SUCCESS : WARNING,
                      "APDU response status: %04x - %s", sw,
                      GetAPDUCodeDescription(sw >> 8, sw & 0xff));

    if (res) {
        PrintEMVAPDUHint(channel, res, sw);
        return res;
    }


    if (decodeTLV)
        TLVPrintFromBuffer(buf, len);

    return PM3_SUCCESS;
}

static int CmdEMVAC(const char *Cmd) {
    uint8_t data[APDU_RES_LEN] = {0};
    int datalen = 0;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv genac",
                  "Generate Application Cryptogram command. It returns data in TLV format.\n"
                  "Needs a EMV applet to be selected and GPO to be executed.",
                  "emv genac -k 0102         -> generate AC with 2-byte CDOLdata and keep field ON after command\n"
                  "emv genac -t 01020304     -> generate AC with 4-byte CDOL data, show result in TLV\n"
                  "emv genac -Daac 01020304  -> generate AC with 4-byte CDOL data and terminal decision 'declined'\n"
                  "emv genac -pmt 9F 37 04   -> load params from file, make CDOL data from CDOL, generate AC with CDOL, show result in TLV");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k",  "keep",     "Keep field ON for next command"),
        arg_lit0("c",  "cda",      "Executes CDA transaction. Needs to get SDAD in results."),
        arg_str0("d",  "decision", "<aac|tc|arqc>", "Terminal decision. aac - declined, tc - approved, arqc - online authorisation requested"),
        arg_lit0("p",  "params",   "Load parameters from `emv_defparams.json` file for CDOLdata making from CDOL and parameters"),
        arg_lit0("m",  "make",     "Make CDOLdata from CDOL (tag 8C and 8D) and parameters (def: use default parameters)"),
        arg_lit0("a",  "apdu",     "Show APDU requests and responses"),
        arg_lit0("t",  "tlv",      "TLV decode results of selected applets"),
        arg_lit0("w",  "wired",    "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_strx1(NULL, NULL,      "<hex>", "CDOLdata/CDOL"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool leaveSignalON = arg_get_lit(ctx, 1);
    bool trTypeCDA = arg_get_lit(ctx, 2);
    uint8_t termDecision = 0xff;
    if (arg_get_str_len(ctx, 3)) {
        if (!strncmp(arg_get_str(ctx, 3)->sval[0], "aac", 4)) {
            termDecision = EMVAC_AAC;
        }
        if (!strncmp(arg_get_str(ctx, 3)->sval[0], "tc", 4)) {
            termDecision = EMVAC_TC;
        }
        if (!strncmp(arg_get_str(ctx, 3)->sval[0], "arqc", 4)) {
            termDecision = EMVAC_ARQC;
        }

        if (termDecision == 0xFF) {
            PrintAndLogEx(ERR, "ERROR: can't find terminal decision '%s'", arg_get_str(ctx, 3)->sval[0]);
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    } else {
        termDecision = EMVAC_TC;
    }

    if (trTypeCDA) {
        termDecision = termDecision | EMVAC_CDAREQ;
    }
    bool paramsLoadFromFile = arg_get_lit(ctx, 4);
    bool dataMakeFromCDOL = arg_get_lit(ctx, 5);
    bool show_apdu = arg_get_lit(ctx, 6);
    bool decodeTLV = arg_get_lit(ctx, 7);

    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 8)) {
        channel = CC_CONTACT;
    }

    PrintChannel(channel);
    CLIGetHexWithReturn(ctx, 9, data, &datalen);
    CLIParserFree(ctx);

    SetAPDULogging(show_apdu);

    // Init TLV tree
    const char *alr = "Root terminal TLV tree";
    struct tlvdb *tlvRoot = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);

    // calc CDOL
    struct tlv *cdol_data_tlv = NULL;
    struct tlvdb *tmp_ext = NULL;
    struct tlv data_tlv = {
        .tag = 0x01,
        .len = datalen,
        .value = (uint8_t *)data,
    };

    if (dataMakeFromCDOL) {
        if (!ParamLoadDefaults(tlvRoot)) {
            tlvdb_free(tlvRoot);
            SetAPDULogging(false);
            return PM3_ESOFT;
        }

        if (paramsLoadFromFile) {
            PrintAndLogEx(INFO, "Params loading from file...");
            ParamLoadFromJson(tlvRoot);
        };

        tmp_ext = tlvdb_external(0x8c, datalen, data);
        cdol_data_tlv = dol_process((const struct tlv *)tmp_ext, tlvRoot, 0x01); // 0x01 - dummy tag
        if (!cdol_data_tlv) {
            PrintAndLogEx(ERR, "Can't create CDOL TLV.");
            tlvdb_free(tmp_ext);
            tlvdb_free(tlvRoot);
            SetAPDULogging(false);
            return PM3_ESOFT;
        }
    } else {
        if (paramsLoadFromFile) {
            PrintAndLogEx(WARNING, "Don't need to load parameters. Sending plain CDOL data...");
        }
        cdol_data_tlv = &data_tlv;
    }

    PrintAndLogEx(INFO, "CDOL data[%zu]: %s", cdol_data_tlv->len, sprint_hex(cdol_data_tlv->value, cdol_data_tlv->len));

    // exec
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = EMVAC(channel, leaveSignalON, termDecision, (uint8_t *)cdol_data_tlv->value, cdol_data_tlv->len, buf, sizeof(buf), &len, &sw, tlvRoot);
    SetAPDULogging(false);

    if (cdol_data_tlv != &data_tlv)
        free(cdol_data_tlv);

    tlvdb_free(tmp_ext);
    tlvdb_free(tlvRoot);

    if (sw)
        PrintAndLogEx(INFO, "APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));

    if (res)
        return res;

    if (decodeTLV)
        TLVPrintFromBuffer(buf, len);

    return PM3_SUCCESS;
}

static int emv_challenge_prepare(Iso7816CommandChannel channel) {
    struct tlvdb *applications = tlvdb_fixed(1, 0, NULL);
    struct tlvdb *context = tlvdb_fixed(1, 0, NULL);
    if (!applications || !context) {
        tlvdb_free(applications);
        tlvdb_free(context);
        return PM3_EMALLOC;
    }
    uint8_t aid[16], response[APDU_RES_LEN];
    size_t aid_len = 0, length = 0;
    uint16_t sw = 0;
    int res = EMVSearchPSE(channel, true, true, channel == CC_CONTACT ? 1 : 2, false, applications);
    if (res) res = EMVSearch(channel, true, true, false, applications, false);
    if (!res) res = EMVSelectApplication(applications, aid, &aid_len);
    if (!res && !aid_len) res = PM3_ESOFT;
    if (!res) {
        PrintAndLogEx(INFO, "GET CHALLENGE: selecting payment application %s", sprint_hex_inrow(aid, aid_len));
        res = EMVSelect(channel, false, true, aid, aid_len, response, sizeof(response), &length, &sw, context);
    }
    struct tlv *pdol = NULL;
    uint8_t *encoded = NULL;
    size_t encoded_len = 0;
    if (!res && !ParamLoadDefaults(context)) res = PM3_ESOFT;
    if (!res) {
        pdol = dol_process(tlvdb_get(context, 0x9f38, NULL), context, 0x83);
        encoded = pdol ? tlv_encode(pdol, &encoded_len) : NULL;
        if (!encoded) res = PM3_EMALLOC;
    }
    if (!res) res = EMVGPO(channel, true, encoded, encoded_len, response, sizeof(response), &length, &sw, NULL);
    free(encoded);
    free(pdol);
    tlvdb_free(applications);
    tlvdb_free(context);
    if (res) {
        PrintAndLogEx(WARNING, "GET CHALLENGE preparation failed (%d, SW %04X)", res, sw);
        DropFieldEx(channel);
    }
    return res;
}

static int CmdEMVGenerateChallenge(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv challenge",
                  "Executes Generate Challenge command. It returns 4 or 8-byte random number from card.\n"
                  "Selects a payment application and runs GPO when starting with an inactive contactless field.\n"
                  "An active session is preserved. Use --select to start a fresh application session.\n"
                  "GET CHALLENGE is optional; some card profiles do not support it.",
                  "emv challenge     -> get challenge\n"
                  "emv challenge -k  -> get challenge, keep filled ON\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k",  "keep",    "Keep field ON for next command"),
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("w",  "wired",   "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_lit0("s", "select", "Select an EMV application and run GPO first"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool leaveSignalON = arg_get_lit(ctx, 1);
    bool show_apdu = arg_get_lit(ctx, 2);
    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 3)) {
        channel = CC_CONTACT;
    }
    bool prepare = arg_get_lit(ctx, 4) || (channel == CC_CONTACTLESS && GetISODEPState() == ISODEP_INACTIVE);
    PrintChannel(channel);
    CLIParserFree(ctx);

    SetAPDULogging(show_apdu);

    if (prepare) {
        int prepared = emv_challenge_prepare(channel);
        if (prepared) {
            SetAPDULogging(false);
            return prepared;
        }
    }

    // exec
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = EMVGenerateChallenge(channel, leaveSignalON, buf, sizeof(buf), &len, &sw, NULL);
    SetAPDULogging(false);

    if (sw)
        PrintAndLogEx(sw == ISO7816_OK ? SUCCESS : WARNING,
                      "APDU response status: %04x - %s", sw,
                      GetAPDUCodeDescription(sw >> 8, sw & 0xff));

    if (res) {
        if (sw == 0x6d00 || sw == 0x6e00)
            PrintAndLogEx(INFO, "The selected card application does not support GET CHALLENGE; no challenge was generated");
        PrintEMVAPDUHint(channel, res, sw);
        return res;
    }

    PrintAndLogEx(SUCCESS, "Challenge: %s", sprint_hex(buf, len));

    if (len != 4 && len != 8) {
        PrintAndLogEx(WARNING, "Length of challenge must be 4 or 8, got " _YELLOW_("%zu"), len);
        return PM3_EWRONGANSWER;
    }

    return PM3_SUCCESS;
}

static int CmdEMVInternalAuthenticate(const char *Cmd) {
    uint8_t data[APDU_RES_LEN] = {0};
    int datalen = 0;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv intauth",
                  "Generate Internal Authenticate command. Usually needs 4-byte random number. It returns data in TLV format .\n"
                  "Needs a EMV applet to be selected and GPO to be executed.",

                  "emv intauth -k 01020304   -> execute Internal Authenticate with 4-byte DDOLdata and keep field ON after command\n"
                  "emv intauth -t 01020304   -> execute Internal Authenticate with 4-byte DDOL data, show result in TLV\n"
                  "emv intauth -pmt 9F 37 04 -> load params from file, make DDOL data from DDOL, Internal Authenticate with DDOL, show result in TLV");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k",  "keep",    "Keep field ON for next command"),
        arg_lit0("p",  "params",  "Load parameters from `emv_defparams.json` file for DDOLdata making from DDOL and parameters"),
        arg_lit0("m",  "make",    "Make DDOLdata from DDOL (tag 9F49) and parameters (def: use default parameters)"),
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("t",  "tlv",     "TLV decode results of selected applets"),
        arg_lit0("w",  "wired",   "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_strx1(NULL, NULL,     "<hex>", "DDOLdata/DDOL"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool leaveSignalON = arg_get_lit(ctx, 1);
    bool paramsLoadFromFile = arg_get_lit(ctx, 2);
    bool dataMakeFromDDOL = arg_get_lit(ctx, 3);
    bool show_apdu = arg_get_lit(ctx, 4);
    bool decodeTLV = arg_get_lit(ctx, 5);
    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 6)) {
        channel = CC_CONTACT;
    }
    PrintChannel(channel);
    CLIGetHexWithReturn(ctx, 7, data, &datalen);
    CLIParserFree(ctx);

    SetAPDULogging(show_apdu);

    // Init TLV tree
    const char *alr = "Root terminal TLV tree";
    struct tlvdb *tlvRoot = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);

    // calc DDOL
    struct tlv *ddol_data_tlv = NULL;
    struct tlvdb *tmp_ext = NULL;
    struct tlv data_tlv = {
        .tag = 0x01,
        .len = datalen,
        .value = (uint8_t *)data,
    };

    if (dataMakeFromDDOL) {
        if (!ParamLoadDefaults(tlvRoot)) {
            tlvdb_free(tlvRoot);
            SetAPDULogging(false);
            return PM3_ESOFT;
        }

        if (paramsLoadFromFile) {
            PrintAndLogEx(INFO, "Params loading from file...");
            ParamLoadFromJson(tlvRoot);
        };

        tmp_ext = tlvdb_external(0x9f49, datalen, data);
        ddol_data_tlv = dol_process((const struct tlv *)tmp_ext, tlvRoot, 0x01); // 0x01 - dummy tag
        if (!ddol_data_tlv) {
            PrintAndLogEx(ERR, "Can't create DDOL TLV.");
            tlvdb_free(tmp_ext);
            tlvdb_free(tlvRoot);
            SetAPDULogging(false);
            return PM3_ESOFT;
        }
    } else {
        if (paramsLoadFromFile) {
            PrintAndLogEx(WARNING, "Don't need to load parameters. Sending plain DDOL data...");
        }
        ddol_data_tlv = &data_tlv;
    }

    PrintAndLogEx(INFO, "DDOL data[%zu]: %s", ddol_data_tlv->len, sprint_hex(ddol_data_tlv->value, ddol_data_tlv->len));

    // exec
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = EMVInternalAuthenticate(channel, leaveSignalON,
                                      (uint8_t *)ddol_data_tlv->value, ddol_data_tlv->len,
                                      buf, sizeof(buf), &len, &sw, NULL);
    SetAPDULogging(false);

    if (ddol_data_tlv != &data_tlv)
        free(ddol_data_tlv);

    tlvdb_free(tmp_ext);
    tlvdb_free(tlvRoot);

    if (sw)
        PrintAndLogEx(INFO, "APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));

    if (res)
        return res;

    if (decodeTLV)
        TLVPrintFromBuffer(buf, len);

    return PM3_SUCCESS;
}

#define dreturn(n) { \
    free(pdol_data_tlv); \
    tlvdb_free(tlvSelect); \
    tlvdb_free(tlvRoot); \
    DropFieldEx( channel ); \
    SetAPDULogging(false); \
    return n; \
    }

static bool InitTransactionParameters(struct tlvdb *tlvRoot, bool paramLoadJSON, enum TransactionType TrType, bool GenACGPO) {

    if (!ParamLoadDefaults(tlvRoot))
        return false;

    if (paramLoadJSON) {
        PrintAndLogEx(INFO, "* * Transaction parameters loading from JSON...");
        ParamLoadFromJson(tlvRoot);
    }

    //9F66:(Terminal Transaction Qualifiers (TTQ)) len:4

    switch (TrType) {
        case TT_MSD:
            TLV_ADD(0x9F66, "\x86\x00\x00\x00"); // MSD
            break;
        // not standard for contactless. just for test.
        case TT_VSDC:
            TLV_ADD(0x9F66, "\x46\x00\x00\x00"); // VSDC
            break;
        case TT_QVSDCMCHIP:
            // qVSDC
            if (GenACGPO) {
                TLV_ADD(0x9F66, "\x26\x80\x00\x00");
            } else {
                TLV_ADD(0x9F66, "\x26\x00\x00\x00");
            }
            break;
        case TT_CDA:
            {
                const struct tlv *capabilities = tlvdb_get(tlvRoot, 0x9f33, NULL);
                if (capabilities && capabilities->len == 3) {
                    uint8_t value[3];
                    memcpy(value, capabilities->value, sizeof(value));
                    value[2] |= 0x08;
                    tlvdb_change_or_add_node(tlvRoot, 0x9f33, sizeof(value), value);
                }
            }
            // qVSDC (VISA CDA not enabled)
            if (GenACGPO) {
                TLV_ADD(0x9F66, "\x26\x80\x00\x00");
            } else {
                TLV_ADD(0x9F66, "\x26\x00\x00\x00");
            }
            break;
        case TT_END:
        default:
            break;
    }
    return true;
}

static void ProcessGPOResponseFormat1(struct tlvdb *tlvRoot, uint8_t *buf, size_t len, bool decodeTLV) {
    if (!tlvRoot || !buf || len == 0)
        return;

    struct tlvdb *response = tlvdb_parse(buf, len);
    const struct tlv *outer = tlvdb_get_tlv(response);
    if (outer && outer->tag == 0x80) {
        if (decodeTLV) {
            PrintAndLogEx(SUCCESS, "GPO response format1:");
            TLVPrintFromBuffer(buf, len);
        }

        if (outer->len < 2 || (outer->len - 2) % 4) {
            PrintAndLogEx(ERR, "GPO response format 1 parsing error. value length = %zu", outer->len);
        } else {
            // AIP
            struct tlvdb *f1AIP = tlvdb_fixed(0x82, 2, outer->value);
            struct tlvdb *f1AFL = tlvdb_fixed(0x94, outer->len - 2, outer->value + 2);
            if (!f1AIP || !f1AFL) {
                tlvdb_free(f1AIP);
                tlvdb_free(f1AFL);
                PrintAndLogEx(ERR, "Out of memory while expanding GPO format 1 response");
                tlvdb_free(response);
                return;
            }
            tlvdb_add(tlvRoot, f1AIP);
            if (decodeTLV) {
                PrintAndLogEx(INFO, "\n* * Decode response format 1 (0x80) AIP and AFL:");
                TLVPrintFromTLV(f1AIP);
            }

            // AFL
            tlvdb_add(tlvRoot, f1AFL);
            if (decodeTLV)
                TLVPrintFromTLV(f1AFL);
        }
    } else {
        if (decodeTLV)
            TLVPrintFromBuffer(buf, len);
    }
    tlvdb_free(response);
}

static void ProcessACResponseFormat1(struct tlvdb *tlvRoot, uint8_t *buf, size_t len, bool decodeTLV) {
    if (!tlvRoot || !buf || len == 0)
        return;

    struct tlvdb *response = tlvdb_parse(buf, len);
    const struct tlv *outer = tlvdb_get_tlv(response);
    if (outer && outer->tag == 0x80) {
        if (decodeTLV) {
            PrintAndLogEx(SUCCESS, "GENERATE AC response format 1:");
            TLVPrintFromBuffer(buf, len);
        }

        if (outer->len < 11) {
            PrintAndLogEx(ERR, "GENERATE AC format 1 parsing error. value length=%zu", outer->len);
        } else {
            if (decodeTLV)
                PrintAndLogEx(NORMAL, "\n------------ Format1 decoded ------------");

            // CID (Cryptogram Information Data)
            tlvdb_change_or_add_node(tlvRoot, 0x9f27, 1, outer->value);
            if (decodeTLV)
                emv_tag_dump(tlvdb_get(tlvRoot, 0x9f27, NULL), 0);

            // ATC (Application Transaction Counter)
            tlvdb_change_or_add_node(tlvRoot, 0x9f36, 2, outer->value + 1);
            if (decodeTLV)
                emv_tag_dump(tlvdb_get(tlvRoot, 0x9f36, NULL), 0);

            // AC (Application Cryptogram)
            tlvdb_change_or_add_node(tlvRoot, 0x9f26, 8, outer->value + 3);
            if (decodeTLV)
                emv_tag_dump(tlvdb_get(tlvRoot, 0x9f26, NULL), 0);

            // IAD (Issuer Application Data) - optional
            if (outer->len > 11) {
                tlvdb_change_or_add_node(tlvRoot, 0x9f10, outer->len - 11, outer->value + 11);
                if (decodeTLV)
                    emv_tag_dump(tlvdb_get(tlvRoot, 0x9f10, NULL), 0);
            }
        }
    } else {
        if (decodeTLV)
            TLVPrintFromBuffer(buf, len);
    }
    tlvdb_free(response);
}

static bool AppendODARecord(uint8_t *dst, size_t dst_capacity, size_t *dst_len,
                            uint8_t sfi, const uint8_t *record, size_t record_len) {
    if (!dst || !dst_len || !record || *dst_len > dst_capacity)
        return false;

    const uint8_t *source = record;
    size_t source_len = record_len;
    if (sfi < 11) {
        const uint8_t *value = record;
        size_t left = record_len;
        struct tlv outer;
        if (!tlv_parse_tl(&value, &left, &outer) || outer.tag != 0x70 || outer.len != left)
            return false;
        source = value;
        source_len = outer.len;
    }
    if (source_len > dst_capacity - *dst_len)
        return false;
    memcpy(dst + *dst_len, source, source_len);
    *dst_len += source_len;
    return true;
}

static struct {
    struct tlvdb *transaction;
    uint16_t atc;
    time_t started;
} emv_pending;

static void emv_pending_clear(void) {
    if (emv_pending.transaction) {
        tlvdb_free(emv_pending.transaction);
        emv_pending.transaction = NULL;
        DropFieldEx(CC_CONTACT);
    }
}

static int CmdEMVComplete(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv complete", "Complete a pending contact ARQC transaction from emv exec --online -w.\n"
                  "Supply issuer response 8A, optional 91 and scripts 71/72, or --unavailable.\n"
                  "Use the same client session and keep the card inserted. Pending state expires after 120 seconds.\n"
                  "--approve requests TC; the default requests AAC. No issuer response is generated.\n",
                  "emv complete --response 8a023035\n"
                  "emv complete --unavailable\n");
    void *argtable[] = {
        arg_param_begin,
        arg_strx0(NULL, "response", "<hex>", "Issuer response BER-TLV"),
        arg_lit0(NULL, "unavailable", "Online authorisation unavailable; request AAC"),
        arg_lit0(NULL, "approve", "Request TC using the supplied issuer response"),
        arg_lit0("a", "apdu", "Show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint8_t data[8192];
    int data_len = 0;
    CLIGetHexWithReturn(ctx, 1, data, &data_len);
    bool unavailable = arg_get_lit(ctx, 2), approve = arg_get_lit(ctx, 3), logging = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);
    if ((unavailable == (data_len != 0)) || (unavailable && approve))
        return PM3_EINVARG;
    if (!emv_pending.transaction) {
        PrintAndLogEx(ERR, "No pending contact transaction; start with emv exec --online -w");
        return PM3_EINVARG;
    }
    if (difftime(time(NULL), emv_pending.started) > 120 || time(NULL) < emv_pending.started) {
        emv_pending_clear();
        PrintAndLogEx(ERR, "Pending transaction expired; start a new transaction");
        return PM3_ETIMEOUT;
    }
    struct tlvdb *issuer = data_len ? tlvdb_parse_multi(data, data_len) : NULL;
    if (data_len && !issuer) return PM3_EINVARG;
    uint8_t response[APDU_RES_LEN];
    size_t length = 0;
    uint16_t sw = 0;
    SetAPDULogging(logging);
    int res = EMVCompleteTransaction(CC_CONTACT, emv_pending.transaction, issuer, emv_pending.atc,
                                      unavailable, approve, response, sizeof(response), &length, &sw);
    if (length && (res == PM3_SUCCESS || res == PM3_EPARTIAL)) {
        TLVPrintFromBuffer(response, length);
        const struct tlv *tvr = tlvdb_get(emv_pending.transaction, 0x95, NULL);
        const struct tlv *scripts = tlvdb_get(emv_pending.transaction, 0x9f5b, NULL);
        if (tvr) PrintAndLogEx(INFO, "Final TVR: %s", sprint_hex_inrow(tvr->value, tvr->len));
        if (scripts) PrintAndLogEx(INFO, "Issuer Script Results: %s", sprint_hex_inrow(scripts->value, scripts->len));
    }
    PrintAndLogEx(res == PM3_SUCCESS ? SUCCESS : WARNING, "Contact completion result %d, SW %04X", res, sw);
    tlvdb_free(issuer);
    emv_pending_clear();
    SetAPDULogging(false);
    return res;
}

static int CmdEMVExec(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv exec",
                  "Execute an EMV transaction with consistent stage, APDU-status, and decoded TLV output.",
                  "emv exec -sat    -> select card, execute MSD transaction, show APDU and TLV\n"
                  "emv exec -satc   -> select card, execute CDA transaction, show APDU and TLV\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("s",  "select",   "Activate field and select card"),
        arg_lit0("a",  "apdu",     "Show APDU requests and responses"),
        arg_lit0("t",  "tlv",      "TLV decode results"),
        arg_lit0("j",  "jload",    "Load transaction parameters from `emv_defparams.json` file"),
        arg_lit0(NULL, "force",    "Force search AID. Search AID instead of execute PPSE"),
        arg_rem("By default:",     "Transaction type - MSD"),
        arg_lit0(NULL, "qvsdc",    "Transaction type - qVSDC or M/Chip"),
        arg_lit0("c",  "qvsdccda", "Transaction type - qVSDC or M/Chip plus CDA (SDAD generation)"),
        arg_lit0("x",  "vsdc",     "Transaction type - VSDC. For test only. Not a standard behavior"),
        arg_lit0("g",  "acgpo",    "VISA. generate AC from GPO"),
        arg_lit0("w",  "wired",    "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_lit0(NULL, "online", "Contact only: request ARQC and retain state for emv complete"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool activateField = arg_get_lit(ctx, 1);
    bool show_apdu = arg_get_lit(ctx, 2);
    bool decodeTLV = arg_get_lit(ctx, 3);
    bool paramLoadJSON = arg_get_lit(ctx, 4);
    bool forceSearch = arg_get_lit(ctx, 5);

    enum TransactionType TrType = TT_MSD;

    if (arg_get_lit(ctx, 7)) {
        TrType = TT_QVSDCMCHIP;
    }

    if (arg_get_lit(ctx, 8)) {
        TrType = TT_CDA;
    }

    if (arg_get_lit(ctx, 9)) {
        TrType = TT_VSDC;
    }

    bool GenACGPO = arg_get_lit(ctx, 10);

    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 11)) {
        channel = CC_CONTACT;
    }
    bool online = arg_get_lit(ctx, 12);

    PrintChannel(channel);
    uint8_t psenum = (channel == CC_CONTACT) ? 1 : 2;
    CLIParserFree(ctx);

    if (online && channel != CC_CONTACT) {
        PrintAndLogEx(ERR, "Book 3 online completion requires the contact interface");
        return PM3_EINVARG;
    }
    if (online && TrType == TT_CDA) {
        PrintAndLogEx(ERR, "Online completion currently supports SDA/DDA profiles; CDA completion is not implemented");
        return PM3_EINVARG;
    }

    if (IfPm3Smartcard() == false) {
        if (channel == CC_CONTACT) {
            PrintAndLogEx(WARNING, "PM3 does not have SMARTCARD support. Exiting.");
            return PM3_EDEVNOTSUPP;
        }
    }

    SetAPDULogging(show_apdu);

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    uint8_t AID[APDU_AID_LEN] = {0};
    size_t AIDlen = 0;
    uint8_t ODAiList[4096];
    size_t ODAiListLen = 0;

    int res;

    struct tlvdb *tlvSelect = NULL;
    struct tlvdb *tlvRoot = NULL;
    struct tlv *pdol_data_tlv = NULL;

    // init applets list tree
    const char *al = "Applets list";
    tlvSelect = tlvdb_fixed(1, strlen(al), (const unsigned char *)al);

    // Application Selection
    // https://www.openscdp.org/scripts/tutorial/emv/applicationselection.html
    if (!forceSearch) {
        // PPSE
        PrintAndLogEx(INFO, "EMV transaction: discovering applications through %s", psenum == 1 ? "PSE" : "PPSE");
        SetAPDULogging(show_apdu);
        res = EMVSearchPSE(channel, activateField, true, psenum, decodeTLV, tlvSelect);

        // check PPSE instead of PSE and vice versa
        if (res) {
            PrintAndLogEx(INFO, "EMV transaction: primary directory unavailable; trying %s",
                          psenum == 1 ? "PPSE" : "PSE");
            res = EMVSearchPSE(channel, false, true, psenum == 1 ? 2 : 1, decodeTLV, tlvSelect);
        }

        // check PPSE and select application id
        if (!res) {
            TLVPrintAIDlistFromSelectTLV(tlvSelect);
            EMVSelectApplication(tlvSelect, AID, &AIDlen);
        }
    }

    // Search
    if (!AIDlen) {
        PrintAndLogEx(INFO, "EMV transaction: searching known payment AIDs");
        SetAPDULogging(show_apdu);
        if (EMVSearch(channel, activateField, true, decodeTLV, tlvSelect, false)) {
            dreturn(PM3_ERFTRANS);
        }

        // check search and select application id
        TLVPrintAIDlistFromSelectTLV(tlvSelect);
        EMVSelectApplication(tlvSelect, AID, &AIDlen);
    }

    // Init TLV tree
    const char *alr = "Root terminal TLV tree";
    tlvRoot = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);

    // check if we found EMV application on card
    if (!AIDlen) {
        PrintAndLogEx(WARNING, "Can't select AID. EMV AID not found");
        dreturn(PM3_ERFTRANS);
    }

    // Select
    PrintAndLogEx(INFO, "EMV transaction: selecting AID %s", sprint_hex_inrow(AID, AIDlen));
    SetAPDULogging(show_apdu);
    res = EMVSelect(channel, false, true, AID, AIDlen, buf, sizeof(buf), &len, &sw, tlvRoot);

    if (res) {
        PrintAndLogEx(WARNING, "Can't select AID (%d). Exit...", res);
        dreturn(PM3_ERFTRANS);
    }

    if (decodeTLV) {
        TLVPrintFromBuffer(buf, len);
    }
    PrintAndLogEx(SUCCESS, "Application selected; received %zu FCI data byte(s)", len);

    PrintAndLogEx(INFO, "EMV transaction: initializing terminal parameters for %s", TransactionTypeStr[TrType]);
    if (!InitTransactionParameters(tlvRoot, paramLoadJSON, TrType, GenACGPO))
        dreturn(PM3_ESOFT);
    if (decodeTLV) {
        PrintAndLogEx(INFO, "Terminal and application TLV data before GPO:");
        TLVPrintFromTLV(tlvRoot);
    }

    PrintAndLogEx(INFO, "EMV transaction: building PDOL data");
    pdol_data_tlv = dol_process(tlvdb_get(tlvRoot, 0x9f38, NULL), tlvRoot, 0x83);
    if (!pdol_data_tlv) {
        PrintAndLogEx(ERR, "Error: can't create PDOL TLV.");
        dreturn(PM3_ESOFT);
    }

    size_t pdol_data_tlv_data_len;
    unsigned char *pdol_data_tlv_data = tlv_encode(pdol_data_tlv, &pdol_data_tlv_data_len);
    if (!pdol_data_tlv_data) {
        PrintAndLogEx(ERR, "Error: can't create PDOL data.");
        dreturn(PM3_ESOFT);
    }
    PrintAndLogEx(INFO, "PDOL [%zu byte(s)]: %s", pdol_data_tlv_data_len, sprint_hex(pdol_data_tlv_data, pdol_data_tlv_data_len));

    PrintAndLogEx(INFO, "EMV transaction: requesting processing options (GPO)");
    res = EMVGPO(channel, true, pdol_data_tlv_data, pdol_data_tlv_data_len, buf, sizeof(buf), &len, &sw, tlvRoot);

    free(pdol_data_tlv_data);
    //free(pdol_data_tlv); --- free on exit.

    if (res) {
        PrintAndLogEx(ERR, "GPO failed (%d): %04x - %s", res, sw,
                      GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        dreturn(PM3_ERFTRANS);
    }
    PrintAndLogEx(SUCCESS, "GPO accepted; received %zu data byte(s)", len);

    // process response template format 1 [id:80  2b AIP + x4b AFL] and format 2 [id:77 TLV]
    ProcessGPOResponseFormat1(tlvRoot, buf, len, decodeTLV);

    // extract PAN from track2
    {
        const struct tlv *track2 = tlvdb_get(tlvRoot, 0x57, NULL);
        if (!tlvdb_get(tlvRoot, 0x5a, NULL) && track2 && track2->len >= 8) {
            struct tlvdb *pan = GetPANFromTrack2(track2);
            if (pan) {
                tlvdb_add(tlvRoot, pan);

                const struct tlv *pantlv = tlvdb_get(tlvRoot, 0x5a, NULL);
                PrintAndLogEx(INFO, "\n* * Extracted PAN from track2: %s", sprint_hex(pantlv->value, pantlv->len));
            } else {
                PrintAndLogEx(WARNING, "\n* * WARNING: Can't extract PAN from track2.");
            }
        }
    }

    PrintAndLogEx(INFO, "EMV transaction: reading application records from AFL");
    const struct tlv *AFL = tlvdb_get(tlvRoot, 0x94, NULL);

    if (!AFL || !AFL->len) {
        PrintAndLogEx(WARNING, "WARNING: AFL not found.");
    }

    while (AFL && AFL->len) {
        if (AFL->len % 4) {
            PrintAndLogEx(WARNING, "Warning: Wrong AFL length: %zu", AFL->len);
            break;
        }

        for (int i = 0; i < AFL->len / 4; i++) {
            uint8_t SFI = AFL->value[i * 4 + 0] >> 3;
            uint8_t SFIstart = AFL->value[i * 4 + 1];
            uint8_t SFIend = AFL->value[i * 4 + 2];
            uint8_t SFIoffline = AFL->value[i * 4 + 3];

            PrintAndLogEx(INFO, "* * SFI[%02x] start:%02x end:%02x offline count:%02x", SFI, SFIstart, SFIend, SFIoffline);
            if ((AFL->value[i * 4] & 0x07) || SFI == 0 || SFI == 31 || SFIstart == 0 ||
                    SFIstart > SFIend || SFIoffline > SFIend - SFIstart + 1) {
                PrintAndLogEx(WARNING, "SFI ERROR! Skipped...");
                continue;
            }

            for (int n = SFIstart; n <= SFIend; n++) {
                PrintAndLogEx(INFO, "* * * SFI[%02x] %d", SFI, n);

                res = EMVReadRecord(channel, true, SFI, n, buf, sizeof(buf), &len, &sw, tlvRoot);
                if (res) {
                    PrintAndLogEx(WARNING, "Error SFI[%02x]. APDU error %4x", SFI, sw);
                    continue;
                }

                if (decodeTLV) {
                    TLVPrintFromBuffer(buf, len);
                    PrintAndLogEx(NORMAL, "");
                }

                // Build Input list for Offline Data Authentication
                // EMV 4.3 book3 10.3, page 96
                if (SFIoffline > 0) {
                    if (!AppendODARecord(ODAiList, sizeof(ODAiList), &ODAiListLen, SFI, buf, len))
                        PrintAndLogEx(WARNING, "SFI[%02x] record could not be safely added to Offline Data Authentication input", SFI);
                    SFIoffline--;
                }
            }
        }

        break;
    }

    // copy Input list for Offline Data Authentication
    if (ODAiListLen) {
        struct tlvdb *oda = tlvdb_fixed(0x21, ODAiListLen, ODAiList); // not a standard tag
        if (oda) {
            tlvdb_add(tlvRoot, oda);
            PrintAndLogEx(INFO, "* Input list for Offline Data Authentication added to TLV. len=%zu \n", ODAiListLen);
        } else {
            PrintAndLogEx(ERR, "Could not allocate Offline Data Authentication input TLV");
        }
    }

    // get AIP
    uint16_t AIP = 0;
    const struct tlv *AIPtlv = tlvdb_get(tlvRoot, 0x82, NULL);
    if (AIPtlv && AIPtlv->len == 2) {
        AIP = AIPtlv->value[0] + AIPtlv->value[1] * 0x100;
        PrintAndLogEx(INFO, "* * AIP=%04x", AIP);
    } else {
        PrintAndLogEx(ERR, "Can't find a valid two-byte AIP.");
    }

    int sda_result = PM3_ENOTIMPL, dda_result = PM3_ENOTIMPL;
    // SDA
    if (AIP & 0x0040) {
        PrintAndLogEx(INFO, "\n* SDA");
        sda_result = trSDA(tlvRoot);
    }

    // DDA
    if (AIP & 0x0020) {
        PrintAndLogEx(INFO, "\n* DDA");
        dda_result = trDDA(channel, decodeTLV, tlvRoot);
    }

    if (online) {
        emv_cvm_result_t cvm;
        res = emv_cvm_evaluate(tlvRoot, &cvm);
        if (res || cvm.pending) {
            PrintAndLogEx(ERR, "CVM cannot be completed with the supplied terminal context");
            dreturn(PM3_EINVARG);
        }
        uint8_t tvr[5] = {0}, tsi[2] = {0};
        const struct tlv *old = tlvdb_get(tlvRoot, 0x95, NULL);
        if (old && old->len == 5) memcpy(tvr, old->value, 5);
        old = tlvdb_get(tlvRoot, 0x9b, NULL);
        if (old && old->len == 2) memcpy(tsi, old->value, 2);
        if (!(AIP & 0x60)) tvr[0] |= 0x80;
        if (AIP & 0x40) { tvr[0] |= 0x02; if (sda_result) tvr[0] |= 0x40; }
        if ((AIP & 0x20) && dda_result) tvr[0] |= 0x08;
        if (AIP & 0x60) tsi[0] |= 0x80;
        for (size_t i = 0; i < 5; i++) tvr[i] |= cvm.tvr[i];
        for (size_t i = 0; i < 2; i++) tsi[i] |= cvm.tsi[i];
        tlvdb_change_or_add_node(tlvRoot, 0x95, 5, tvr);
        tlvdb_change_or_add_node(tlvRoot, 0x9b, 2, tsi);
        tlvdb_change_or_add_node(tlvRoot, 0x9f34, 3, cvm.result);
        tsi[0] |= 0x20; // First GENERATE AC invokes card risk management.
        tlvdb_change_or_add_node(tlvRoot, 0x9b, 2, tsi);
        const struct tlv *cdol1 = tlvdb_get(tlvRoot, 0x8c, NULL);
        const struct tlv *cdol2 = tlvdb_get(tlvRoot, 0x8d, NULL);
        struct tlv *data = cdol1 && cdol2 ? dol_process(cdol1, tlvRoot, 1) : NULL;
        if (!data || data->len > 255) {
            free(data);
            PrintAndLogEx(ERR, "Contact online flow requires valid CDOL1 and CDOL2");
            dreturn(PM3_EINVARG);
        }
        res = EMVAC(channel, true, EMVAC_ARQC, (uint8_t *)data->value, data->len,
                     buf, sizeof(buf), &len, &sw, NULL);
        free(data);
        if (res) dreturn(res);
        emv_analysis_result_t ac_result;
        if (!emv_analyze_data(buf, len, false, EMV_FORMAT_AC, true, &ac_result))
            dreturn(PM3_EWRONGANSWER);
        struct tlvdb *response = tlvdb_parse(buf, len);
        if (response && response->tag.tag == 0x77) {
            const struct tlv *tag = tlvdb_get(response, 0x9f27, NULL);
            if (tag) tlvdb_change_or_add_node(tlvRoot, tag->tag, tag->len, tag->value);
            tag = tlvdb_get(response, 0x9f36, NULL);
            if (tag) tlvdb_change_or_add_node(tlvRoot, tag->tag, tag->len, tag->value);
        } else {
            ProcessACResponseFormat1(tlvRoot, buf, len, decodeTLV);
        }
        tlvdb_free(response);
        const struct tlv *cid = tlvdb_get(tlvRoot, 0x9f27, NULL), *atc = tlvdb_get(tlvRoot, 0x9f36, NULL);
        if (!cid || cid->len != 1 || !atc || atc->len != 2) dreturn(PM3_EWRONGANSWER);
        if ((cid->value[0] & EMVAC_AC_MASK) != EMVAC_ARQC) {
            PrintAndLogEx(INFO, "Card returned a final cryptogram; no online completion is pending");
            dreturn(PM3_SUCCESS);
        }
        emv_pending.transaction = tlvRoot;
        emv_pending.atc = ((uint16_t)atc->value[0] << 8) | atc->value[1];
        emv_pending.started = time(NULL);
        free(pdol_data_tlv);
        tlvdb_free(tlvSelect);
        SetAPDULogging(false);
        TLVPrintFromBuffer(buf, len);
        PrintAndLogEx(INFO, "ARQC pending: keep the card inserted and use emv complete in this client session");
        return PM3_SUCCESS;
    }

    // transaction check

    // qVSDC
    if (TrType == TT_QVSDCMCHIP || TrType == TT_CDA) {
        // 9F26: Application Cryptogram
        const struct tlv *AC = tlvdb_get(tlvRoot, 0x9F26, NULL);
        if (AC) {
            PrintAndLogEx(INFO, "\n--> qVSDC transaction.");
            PrintAndLogEx(INFO, "* AC path");

            // 9F36: Application Transaction Counter (ATC)
            const struct tlv *ATC = tlvdb_get(tlvRoot, 0x9F36, NULL);
            if (ATC) {

                // 9F10: Issuer Application Data - optional
                const struct tlv *IAD = tlvdb_get(tlvRoot, 0x9F10, NULL);

                // print AC data
                PrintAndLogEx(INFO, "ATC: %s", sprint_hex(ATC->value, ATC->len));
                PrintAndLogEx(INFO, "AC: %s", sprint_hex(AC->value, AC->len));
                if (IAD) {
                    PrintAndLogEx(INFO, "IAD: %s", sprint_hex(IAD->value, IAD->len));

                    // https://mst-company.ru/blog/ekvajring-emv-tranzaktsiya-emv-transaction-flow-chast-4-pdol-i-beskontaktnye-karty-osobennosti-qvsdc-i-quics
                    if (GetCardPSVendor(AID, AIDlen) != CV_VISA) {
                        PrintAndLogEx(INFO, "Issuer-specific IAD retained without Visa interpretation");
                    } else if (IAD->len == 32 && IAD->value[0] == 0x1f) {
                        PrintAndLogEx(INFO, "    Key index:  0x%02x", IAD->value[2]);
                        PrintAndLogEx(INFO, "    Crypto ver: 0x%02x(%03d)", IAD->value[1], IAD->value[1]);
                        PrintAndLogEx(INFO, "    CVR: %s", sprint_hex(&IAD->value[3], 5));
                        struct tlvdb *cvr = tlvdb_fixed(0x20, 5, &IAD->value[3]);
                        TLVPrintFromTLVLev(cvr, 1);
                        tlvdb_free(cvr);
                        PrintAndLogEx(INFO, "    IDD option id: 0x%02x", IAD->value[8]);
                        PrintAndLogEx(INFO, "    IDD: %s", sprint_hex(&IAD->value[9], 23));

                    } else if (IAD->len >= 3 && IAD->value[0] >= 2 && IAD->len >= (size_t)IAD->value[0] + 1) {
                        PrintAndLogEx(INFO, "    Key index:  0x%02x", IAD->value[1]);
                        PrintAndLogEx(INFO, "    Crypto ver: 0x%02x(%03d)", IAD->value[2], IAD->value[2]);
                        PrintAndLogEx(INFO, "    CVR: %s", sprint_hex(&IAD->value[3], IAD->value[0] - 2));
                        struct tlvdb *cvr = tlvdb_fixed(0x20, IAD->value[0] - 2, &IAD->value[3]);
                        TLVPrintFromTLVLev(cvr, 1);
                        tlvdb_free(cvr);

                        if (IAD->len >= 8) {
                            int iddLen = IAD->value[7];
                            PrintAndLogEx(NORMAL, "    IDD length: %d", iddLen);
                            if (iddLen >= 1 && IAD->len >= 9) {
                                PrintAndLogEx(NORMAL, "    IDD option id: 0x%02x", IAD->value[8]);
                            }

                            if (iddLen >= 2 && (size_t)iddLen <= IAD->len - 8) {
                                PrintAndLogEx(NORMAL, "    IDD: %s", sprint_hex(&IAD->value[9], iddLen - 1));
                            }
                        }
                    }
                } else {
                    PrintAndLogEx(WARNING, "WARNING: IAD not found.");
                }

            } else {
                PrintAndLogEx(WARNING, "Warning AC: Application Transaction Counter (ATC) not found.");
            }
        }
    }

    // Mastercard M/CHIP
    if (GetCardPSVendor(AID, AIDlen) == CV_MASTERCARD && (TrType == TT_QVSDCMCHIP || TrType == TT_CDA)) {

        const struct tlv *CDOL1 = tlvdb_get(tlvRoot, 0x8c, NULL);
        if (CDOL1 && GetCardPSVendor(AID, AIDlen) == CV_MASTERCARD) { // and m/chip transaction flag
            PrintAndLogEx(INFO, "\n--> Mastercard M/Chip transaction.");

            PrintAndLogEx(INFO, "* * Generate challenge");
            res = EMVGenerateChallenge(channel, true, buf, sizeof(buf), &len, &sw, tlvRoot);
            if (res) {
                PrintAndLogEx(ERR, "Error GetChallenge. APDU error %4x", sw);
                dreturn(PM3_ERFTRANS);
            }

            if (len < 4) {
                PrintAndLogEx(ERR, "Error GetChallenge. Wrong challenge length %zu", len);
                dreturn(PM3_ESOFT);
            }

            // ICC Dynamic Number
            struct tlvdb *ICCDynN = tlvdb_fixed(0x9f4c, len, buf);
            tlvdb_add(tlvRoot, ICCDynN);
            if (decodeTLV) {
                PrintAndLogEx(INFO, "\n* * ICC Dynamic Number:");
                TLVPrintFromTLV(ICCDynN);
            }

            PrintAndLogEx(INFO, "* * Calc CDOL1");
            struct tlv *cdol_data_tlv = dol_process(tlvdb_get(tlvRoot, 0x8c, NULL), tlvRoot, 0x01); // 0x01 - dummy tag
            if (!cdol_data_tlv) {
                PrintAndLogEx(ERR, "Error: can't create CDOL1 TLV.");
                dreturn(PM3_ESOFT);
            }

            PrintAndLogEx(INFO, "CDOL1 data[%zu]: %s", cdol_data_tlv->len, sprint_hex(cdol_data_tlv->value, cdol_data_tlv->len));

            PrintAndLogEx(INFO, "* * AC1");
            // EMVAC_TC + EMVAC_CDAREQ --- to get SDAD
            res = EMVAC(channel, true, (TrType == TT_CDA) ? EMVAC_TC + EMVAC_CDAREQ : EMVAC_TC, (uint8_t *)cdol_data_tlv->value, cdol_data_tlv->len, buf, sizeof(buf), &len, &sw, tlvRoot);
            if (res) {
                PrintAndLogEx(ERR, "AC1 error(%d): %4x. Exit...", res, sw);
                dreturn(PM3_ERFTRANS);
            }

            if (decodeTLV) {
                TLVPrintFromBuffer(buf, len);
            }

            // CDA
            PrintAndLogEx(INFO, "\n* CDA:");
            struct tlvdb *ac_tlv = tlvdb_parse_multi(buf, len);
            if (tlvdb_get(ac_tlv, 0x9f4b, NULL)) {
                res = trCDA(tlvRoot, ac_tlv, pdol_data_tlv, cdol_data_tlv);
                if (res) {
                    PrintAndLogEx(WARNING, "CDA error (%d)", res);
                }
            } else {
                PrintAndLogEx(INFO, "\n* Signed Dynamic Application Data (0x9f4b) not present");
            }

            tlvdb_free(ac_tlv);
            free(cdol_data_tlv);

            PrintAndLogEx(INFO, "\n* M/Chip transaction result:");
            // 9F27: Cryptogram Information Data (CID)
            const struct tlv *CID = tlvdb_get(tlvRoot, 0x9F27, NULL);
            if (CID) {
                emv_tag_dump(CID, 1);
                PrintAndLogEx(INFO, "------------------------------");

                if (CID->len) {
                    switch (CID->value[0] & EMVAC_AC_MASK) {
                        case EMVAC_AAC:
                            PrintAndLogEx(INFO, "Transaction DECLINED.");
                            break;
                        case EMVAC_TC:
                            PrintAndLogEx(INFO, "Transaction approved OFFLINE.");
                            break;
                        case EMVAC_ARQC:
                            PrintAndLogEx(INFO, "Online authorisation requested; issuer approval is not yet known.");
                            break;
                        default:
                            PrintAndLogEx(WARNING, "Warning: CID transaction code error %2x", CID->value[0] & EMVAC_AC_MASK);
                            break;
                    }
                } else {
                    PrintAndLogEx(WARNING, "Warning: Wrong CID length %zu", CID->len);
                }
            } else {
                PrintAndLogEx(WARNING, "Warning: CID(9F27) not found.");
            }

        }
    }

    // MSD
    if (AIP & 0x8000 && TrType == TT_MSD) {
        PrintAndLogEx(INFO, "\n--> MSD transaction.");

        PrintAndLogEx(INFO, "* MSD dCVV path. Check dCVV");

        const struct tlv *track2 = tlvdb_get(tlvRoot, 0x57, NULL);
        if (track2) {
            PrintAndLogEx(INFO, "Track2: %s", sprint_hex(track2->value, track2->len));

            struct tlvdb *dCVV = GetdCVVRawFromTrack2(track2);
            PrintAndLogEx(INFO, "dCVV raw data:");
            TLVPrintFromTLV(dCVV);

            if (GetCardPSVendor(AID, AIDlen) == CV_MASTERCARD) {
                PrintAndLogEx(INFO, "\n* Mastercard calculate UDOL");

                // UDOL (9F69)
                const struct tlv *UDOL = tlvdb_get(tlvRoot, 0x9F69, NULL);
                // UDOL(9F69) default: 9F6A (Unpredictable number) 4 bytes
                const struct tlv defUDOL = {
                    .tag = 0x01,
                    .len = 3,
                    .value = (uint8_t *)"\x9f\x6a\x04",
                };
                if (!UDOL) {
                    PrintAndLogEx(INFO, "Use default UDOL.");
                }

                struct tlv *udol_data_tlv = dol_process(UDOL ? UDOL : &defUDOL, tlvRoot, 0x01); // 0x01 - dummy tag
                if (!udol_data_tlv) {
                    PrintAndLogEx(ERR, "Error: can't create UDOL TLV.");
                    dreturn(PM3_ESOFT);
                }

                PrintAndLogEx(INFO, "UDOL data[%zu]: %s", udol_data_tlv->len, sprint_hex(udol_data_tlv->value, udol_data_tlv->len));

                PrintAndLogEx(INFO, "\n* Mastercard compute cryptographic checksum(UDOL)");

                res = MSCComputeCryptoChecksum(channel, true, (uint8_t *)udol_data_tlv->value, udol_data_tlv->len, buf, sizeof(buf), &len, &sw, tlvRoot);
                if (res) {
                    PrintAndLogEx(ERR, "Error Compute Crypto Checksum. APDU error %4x", sw);
                    free(udol_data_tlv);
                    dreturn(PM3_ESOFT);
                }

                // Mastercard compute cryptographic checksum result
                TLVPrintFromBuffer(buf, len);
                PrintAndLogEx(NORMAL, "");

                free(udol_data_tlv);

            }
        } else {
            PrintAndLogEx(ERR, "Error MSD: Track2 data not found.");
        }
    }

    // VSDC
    if (GetCardPSVendor(AID, AIDlen) == CV_VISA && (TrType == TT_VSDC || TrType == TT_CDA)) {
        PrintAndLogEx(INFO, "\n--> VSDC transaction.");

        PrintAndLogEx(INFO, "* * Calc CDOL1");
        struct tlv *cdol1_data_tlv = dol_process(tlvdb_get(tlvRoot, 0x8c, NULL), tlvRoot, 0x01); // 0x01 - dummy tag
        if (!cdol1_data_tlv) {
            PrintAndLogEx(ERR, "Error: can't create CDOL1 TLV.");
            dreturn(PM3_ESOFT);
        }

        PrintAndLogEx(INFO, "CDOL1 data[%zu]: %s", cdol1_data_tlv->len, sprint_hex(cdol1_data_tlv->value, cdol1_data_tlv->len));

        PrintAndLogEx(INFO, "* * AC1");
        // EMVAC_TC + EMVAC_CDAREQ --- to get SDAD
        res = EMVAC(channel, true, (TrType == TT_CDA) ? EMVAC_TC + EMVAC_CDAREQ : EMVAC_TC, (uint8_t *)cdol1_data_tlv->value, cdol1_data_tlv->len, buf, sizeof(buf), &len, &sw, tlvRoot);
        if (res) {
            PrintAndLogEx(ERR, "AC1 error(%d): %4x. Exit...", res, sw);
            free(cdol1_data_tlv);
            dreturn(PM3_ERFTRANS);
        }

        // process Format1 (0x80) and print Format2 (0x77)
        ProcessACResponseFormat1(tlvRoot, buf, len, decodeTLV);

        uint8_t CID = 0;
        tlvdb_get_uint8(tlvRoot, 0x9f27, &CID);

        // AC1 print result
        PrintAndLogEx(NORMAL, "");
        if ((CID & EMVAC_AC_MASK) == EMVAC_AAC)     PrintAndLogEx(INFO, "AC1 result: AAC (Transaction declined)");
        if ((CID & EMVAC_AC_MASK) == EMVAC_TC)      PrintAndLogEx(INFO, "AC1 result: TC (Transaction approved)");
        if ((CID & EMVAC_AC_MASK) == EMVAC_ARQC)    PrintAndLogEx(INFO, "AC1 result: ARQC (Online authorisation requested)");
        if ((CID & EMVAC_AC_MASK) == EMVAC_AC_MASK) PrintAndLogEx(INFO, "AC1 result: RFU");

        // decode Issuer Application Data (IAD)
        uint8_t CryptoVersion = 0;
        const struct tlv *IAD = tlvdb_get(tlvRoot, 0x9f10, NULL);
        if (IAD && IAD->len >= 3 && IAD->value[0] >= 2 && (size_t)IAD->value[0] < IAD->len) {
            PrintAndLogEx(INFO, "\n* * Issuer Application Data (IAD):");
            uint8_t VDDlen = IAD->value[0]; // Visa discretionary data length
            uint8_t IDDlen = 0;             // Issuer discretionary data length
            PrintAndLogEx(INFO, "IAD length: %zu", IAD->len);
            PrintAndLogEx(INFO, "VDDlen: %d", VDDlen);

            if (VDDlen < IAD->len - 1) {
                IDDlen = IAD->value[VDDlen + 1];
            }
            PrintAndLogEx(INFO, "IDDlen: %d", IDDlen);

            uint8_t DerivKeyIndex = IAD->value[1];
            CryptoVersion = IAD->value[2];

            PrintAndLogEx(INFO, "CryptoVersion: %d", CryptoVersion);
            PrintAndLogEx(INFO, "DerivKeyIndex: %d", DerivKeyIndex);

            // Card Verification Results (CVR) decode
            if (VDDlen > 2) {
                uint8_t CVRlen = IAD->value[3];
                if (CVRlen == (VDDlen - 2 - 1)) {
                    PrintAndLogEx(INFO, "CVR length: %d", CVRlen);
                    PrintAndLogEx(INFO, "CVR: %s", sprint_hex(&IAD->value[4], CVRlen));
                } else {
                    PrintAndLogEx(WARNING, "Wrong CVR length! CVR: %s", sprint_hex(&IAD->value[3], VDDlen - 2));
                }
            }

            if (IDDlen && (size_t)IDDlen <= IAD->len - VDDlen - 2) {
                PrintAndLogEx(INFO, "IDD: %s", sprint_hex(&IAD->value[VDDlen + 2], IDDlen));
            }

        } else {
            PrintAndLogEx(WARNING, "Issuer Application Data (IAD) not found.");
        }

        if ((CID & EMVAC_AC_MASK) == EMVAC_ARQC)
            PrintAndLogEx(INFO, "Online authorisation is required. For contact completion use emv exec --online -w.");
        free(cdol1_data_tlv);
    }

    if (decodeTLV) {
        emv_analysis_result_t analysis_result;
        PrintAndLogEx(INFO, "EMV transaction: validating the complete collected TLV profile");
        emv_analyze_tlvdb(tlvRoot, true, EMV_FORMAT_AUTO, channel == CC_CONTACT, &analysis_result);
    }

    DropFieldEx(channel);

    // Destroy TLV's
    free(pdol_data_tlv);

    tlvdb_free(tlvSelect);
    tlvdb_free(tlvRoot);

    PrintAndLogEx(SUCCESS, "EMV transaction completed");
    SetAPDULogging(false);
    return PM3_SUCCESS;
}

static int CmdEMVScan(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv scan",
                  "Scan EMV card and save it contents to a file.\n"
                  "It executes an EMV transaction and saves a JSON profile which can be used for emulation.\n"
                  "The output filename is optional; the default is a unique `emv-scan.json`.\n",
                  "emv scan -at -> scan MSD transaction mode and show APDU and TLV\n"
                  "emv scan -at my-card -> scan and save to a unique my-card.json\n"
                  "emv scan -c -> scan CDA transaction mode\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",     "Show APDU requests and responses"),
        arg_lit0("t",  "tlv",      "TLV decode results"),
        arg_lit0("e",  "extract",  "Extract TLV elements and fill Application Data"),
        arg_lit0("j",  "jload",    "Load transaction parameters from `emv_defparams.json` file"),
        arg_rem("By default:",     "Transaction type - MSD"),
        arg_lit0(NULL,  "qvsdc",   "Transaction type - qVSDC or M/Chip"),
        arg_lit0("c",  "qvsdccda", "Transaction type - qVSDC or M/Chip plus CDA (SDAD generation)"),
        arg_lit0("x",  "vsdc",     "Transaction type - VSDC. For test only. Not a standard behavior"),
        arg_lit0("g",  "acgpo",    "VISA. generate AC from GPO"),
        arg_lit0("m",  "merge",    "Merge output file with card's data. (warning: the file may be corrupted!)"),
        arg_lit0("w",  "wired",    "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_str0(NULL,  NULL,      "<fn>", "JSON output file name (optional; default: emv-scan.json)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool show_apdu = arg_get_lit(ctx, 1);
    bool decodeTLV = arg_get_lit(ctx, 2);
    bool extractTLVElements = arg_get_lit(ctx, 3);
    bool paramLoadJSON = arg_get_lit(ctx, 4);

    enum TransactionType TrType = TT_MSD;
    if (arg_get_lit(ctx, 6)) {
        TrType = TT_QVSDCMCHIP;
    }
    if (arg_get_lit(ctx, 7)) {
        TrType = TT_CDA;
    }
    if (arg_get_lit(ctx, 8)) {
        TrType = TT_VSDC;
    }

    bool GenACGPO = arg_get_lit(ctx, 9);
    bool MergeJSON = arg_get_lit(ctx, 10);

    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 11)) {
        channel = CC_CONTACT;
    }

    PrintChannel(channel);

    uint8_t psenum = (channel == CC_CONTACT) ? 1 : 2;

    uint8_t filename[FILE_PATH_SIZE] = {0};
    int filenamelen = sizeof(filename) - 1; // CLIGetStrWithReturn does not guarantee string to be null-terminated
    CLIGetStrWithReturn(ctx, 12, filename, &filenamelen);

    CLIParserFree(ctx);

    if (filenamelen == 0) {
        if (MergeJSON) {
            PrintAndLogEx(ERR, "Merge mode requires an existing JSON filename");
            return PM3_EINVARG;
        }
        const char *default_name = "emv-scan";
        memcpy(filename, default_name, strlen(default_name) + 1);
        filenamelen = strlen(default_name);
    }

    if (IfPm3Smartcard() == false) {
        if (channel == CC_CONTACT) {
            PrintAndLogEx(WARNING, "PM3 does not have SMARTCARD support, exiting");
            return PM3_EDEVNOTSUPP;
        }
    }

    uint8_t AID[APDU_AID_LEN] = {0};
    size_t AIDlen = 0;
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint8_t ODAI_list[4096];
    size_t ODAI_listlen = 0;
    uint16_t sw = 0;
    int res;

    json_t *root;
    json_error_t error;

    // current path + file name
    if (MergeJSON) {

        root = json_load_file((char *)filename, 0, &error);
        if (!root) {
            PrintAndLogEx(ERR, "Json error on line %d: %s", error.line, error.text);
            return PM3_EFILE;
        }

        if (!json_is_object(root)) {
            PrintAndLogEx(ERR, "Invalid json format. root must be an object");
            return PM3_EFILE;
        }
    } else {
        root = json_object();
    }

    SetAPDULogging(show_apdu);

    // drop field at start
    DropFieldEx(channel);

    JsonSaveStr(root, "$.File.Created", "proxmark3 `emv scan`");

    if (channel == CC_CONTACTLESS) {
        // iso 14443 select
        PrintAndLogEx(INFO, "GET UID, ATS");

        iso14a_card_select_t card;
        if (Hf14443_4aGetCardData(&card) != PM3_SUCCESS) {
            return PM3_ERFTRANS;
        }

        JsonSaveStr(root, "$.Card.Contactless.Communication", "iso14443-4a");
        JsonSaveBufAsHex(root, "$.Card.Contactless.UID", (uint8_t *)&card.uid, card.uidlen);
        JsonSaveHex(root, "$.Card.Contactless.ATQA", card.atqa[0] + (card.atqa[1] << 2), 2);
        JsonSaveHex(root, "$.Card.Contactless.SAK", card.sak, 0);
        JsonSaveBufAsHex(root, "$.Card.Contactless.ATS", (uint8_t *)card.ats, card.ats_len);
    } else {
        PrintAndLogEx(INFO, "GET ATR");

        smart_card_atr_t card;
        smart_select(true, &card);
        if (!card.atr_len) {
            PrintAndLogEx(ERR, "Can't get ATR from a smart card.");
            return PM3_ERFTRANS;
        }

        JsonSaveStr(root, "$.Card.Contact.Communication", "iso7816");
        JsonSaveBufAsHex(root, "$.Card.Contact.ATR", (uint8_t *)card.atr, card.atr_len);
    }

    // init applets list tree
    const char *al = "Applets list";
    struct tlvdb *tlvSelect = tlvdb_fixed(1, strlen(al), (const unsigned char *)al);

    // EMV PPSE
    PrintAndLogEx(INFO, "PPSE");
    res = EMVSelectPSE(channel, true, true, 2, buf, sizeof(buf), &len, &sw);

    if (!res && sw == ISO7816_OK) {
        if (decodeTLV)
            TLVPrintFromBuffer(buf, len);

        JsonSaveBufAsHex(root, "$.PPSE.AID", (uint8_t *)"2PAY.SYS.DDF01", 14);

        struct tlvdb *fci = tlvdb_parse_multi(buf, len);
        if (extractTLVElements)
            JsonSaveTLVTree(root, root, "$.PPSE.FCITemplate", fci);
        else
            JsonSaveTLVTreeElm(root, "$.PPSE.FCITemplate", fci, true, true, false);
        JsonSaveTLVValue(root, "$.Application.KernelID", tlvdb_find_full(fci, 0x9f2a));
        tlvdb_free(fci);
    }

    res = EMVSearchPSE(channel, false, true, psenum, decodeTLV, tlvSelect);

    // check PPSE and select application id
    if (!res) {
        TLVPrintAIDlistFromSelectTLV(tlvSelect);
    } else {
        // EMV SEARCH with AID list
        SetAPDULogging(false);
        PrintAndLogEx(INFO, "AID search.");
        if (EMVSearch(channel, false, true, decodeTLV, tlvSelect, false)) {
            PrintAndLogEx(ERR, "Can't found any of EMV AID, exiting...");
            tlvdb_free(tlvSelect);
            DropFieldEx(channel);
            return PM3_ERFTRANS;
        }

        // check search and select application id
        TLVPrintAIDlistFromSelectTLV(tlvSelect);
    }

    // EMV SELECT application
    SetAPDULogging(show_apdu);
    EMVSelectApplication(tlvSelect, AID, &AIDlen);

    tlvdb_free(tlvSelect);

    if (!AIDlen) {
        PrintAndLogEx(INFO, "Can't select AID. EMV AID not found, exiting...");
        DropFieldEx(channel);
        return PM3_ERFTRANS;
    }

    JsonSaveBufAsHex(root, "$.Application.AID", AID, AIDlen);

    // Init TLV tree
    const char *alr = "Root terminal TLV tree";
    struct tlvdb *tlvRoot = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);

    // EMV SELECT applet

    PrintAndLogEx(INFO, "Selecting AID: " _GREEN_("%s"), sprint_hex_inrow(AID, AIDlen));
    SetAPDULogging(show_apdu);
    res = EMVSelect(channel, false, true, AID, AIDlen, buf, sizeof(buf), &len, &sw, tlvRoot);

    if (res) {
        PrintAndLogEx(ERR, "Can't select AID (%d), exiting...", res);
        tlvdb_free(tlvRoot);
        DropFieldEx(channel);
        return PM3_ERFTRANS;
    }

    if (decodeTLV)
        TLVPrintFromBuffer(buf, len);

    // save mode
    if (tlvdb_get(tlvRoot, 0x9f38, NULL)) {
        JsonSaveStr(root, "$.Application.Mode", TransactionTypeStr[TrType]);
    }

    struct tlvdb *fci = tlvdb_parse_multi(buf, len);
    if (extractTLVElements)
        JsonSaveTLVTree(root, root, "$.Application.FCITemplate", fci);
    else
        JsonSaveTLVTreeElm(root, "$.Application.FCITemplate", fci, true, true, false);

    tlvdb_free(fci);

    // create transaction parameters
    PrintAndLogEx(INFO, "Init transaction parameters");
    if (!InitTransactionParameters(tlvRoot, paramLoadJSON, TrType, GenACGPO)) {
        tlvdb_free(tlvRoot);
        DropFieldEx(channel);
        SetAPDULogging(false);
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "Calc PDOL");
    struct tlv *pdol_data_tlv = dol_process(tlvdb_get(tlvRoot, 0x9f38, NULL), tlvRoot, 0x83);
    if (!pdol_data_tlv) {
        PrintAndLogEx(ERR, "Can't create PDOL TLV");
        tlvdb_free(tlvRoot);
        DropFieldEx(channel);
        return PM3_ESOFT;
    }

    size_t pdol_data_tlv_data_len;
    unsigned char *pdol_data_tlv_data = tlv_encode(pdol_data_tlv, &pdol_data_tlv_data_len);
    if (!pdol_data_tlv_data) {
        PrintAndLogEx(ERR, "Can't create PDOL data");
        tlvdb_free(tlvRoot);
        free(pdol_data_tlv);
        DropFieldEx(channel);
        return PM3_ESOFT;
    }
    PrintAndLogEx(INFO, "PDOL data[%zu]: %s", pdol_data_tlv_data_len, sprint_hex(pdol_data_tlv_data, pdol_data_tlv_data_len));

    PrintAndLogEx(INFO, "GPO");
    res = EMVGPO(channel, true, pdol_data_tlv_data, pdol_data_tlv_data_len, buf, sizeof(buf), &len, &sw, tlvRoot);

    free(pdol_data_tlv_data);
    free(pdol_data_tlv);

    if (res) {
        PrintAndLogEx(ERR, "GPO error(%d): %4x, exiting...", res, sw);
        tlvdb_free(tlvRoot);
        DropFieldEx(channel);
        return PM3_ERFTRANS;
    }
    ProcessGPOResponseFormat1(tlvRoot, buf, len, decodeTLV);

    struct tlvdb *gpofci = tlvdb_parse_multi(buf, len);
    if (gpofci) {
        if (extractTLVElements)
            JsonSaveTLVTree(root, root, "$.Application.GPO", gpofci);
        else
            JsonSaveTLVTreeElm(root, "$.Application.GPO", gpofci, true, true, false);
    } else {
        PrintAndLogEx(WARNING, "GPO response is not valid BER-TLV; skipping its decoded JSON tree");
    }

    // Format 1 carries AIP/AFL implicitly inside tag 80, so use the normalized
    // transaction tree populated by ProcessGPOResponseFormat1.
    JsonSaveTLVValue(root, "$.ApplicationData.AIP", tlvdb_find_full(tlvRoot, 0x82));
    JsonSaveTLVValue(root, "$.ApplicationData.AFL", tlvdb_find_full(tlvRoot, 0x94));

    tlvdb_free(gpofci);

    PrintAndLogEx(INFO, "Read records from AFL");
    const struct tlv *AFL = tlvdb_get(tlvRoot, 0x94, NULL);

    while (AFL && AFL->len) {
        if (AFL->len % 4) {
            PrintAndLogEx(ERR, "Wrong AFL length: %zu", AFL->len);
            break;
        }

        json_t *sfijson = json_path_get(root, "$.Application.Records");
        if (!sfijson) {
            json_t *app = json_path_get(root, "$.Application");
            json_object_set_new(app, "Records", json_array());

            sfijson = json_path_get(root, "$.Application.Records");
        }

        if (!json_is_array(sfijson)) {
            PrintAndLogEx(ERR, "Internal logic error. `$.Application.Records` is not an array.");
            break;
        }

        for (int i = 0; i < AFL->len / 4; i++) {
            uint8_t SFI = AFL->value[i * 4 + 0] >> 3;
            uint8_t SFIstart = AFL->value[i * 4 + 1];
            uint8_t SFIend = AFL->value[i * 4 + 2];
            uint8_t SFIoffline = AFL->value[i * 4 + 3];
            uint8_t SFIofflineTotal = SFIoffline;

            PrintAndLogEx(INFO, "   SFI[%02x] start:%02x end:%02x offline:%02x", SFI, SFIstart, SFIend, SFIoffline);
            if ((AFL->value[i * 4] & 0x07) || SFI == 0 || SFI == 31 || SFIstart == 0 ||
                    SFIstart > SFIend || SFIoffline > SFIend - SFIstart + 1) {
                PrintAndLogEx(ERR, "SFI ERROR! Skipped...");
                continue;
            }

            for (int n = SFIstart; n <= SFIend; n++) {
                PrintAndLogEx(INFO, "     SFI[%02x] %d", SFI, n);

                res = EMVReadRecord(channel, true, SFI, n, buf, sizeof(buf), &len, &sw, tlvRoot);
                if (res) {
                    PrintAndLogEx(ERR, "SFI[%02x]. APDU error %4x", SFI, sw);
                    continue;
                }

                // Build Input list for Offline Data Authentication
                // EMV 4.3 book3 10.3, page 96
                if (SFIoffline) {
                    if (!AppendODARecord(ODAI_list, sizeof(ODAI_list), &ODAI_listlen, SFI, buf, len))
                        PrintAndLogEx(WARNING, "SFI[%02x] record could not be safely added to Offline Data Authentication input", SFI);
                    SFIoffline--;
                }

                if (decodeTLV) {
                    TLVPrintFromBuffer(buf, len);
                    PrintAndLogEx(NORMAL, "");
                }

                json_t *jsonelm = json_object();
                json_array_append_new(sfijson, jsonelm);

                JsonSaveHex(jsonelm, "SFI", SFI, 1);
                JsonSaveHex(jsonelm, "RecordNum", n, 1);
                JsonSaveHex(jsonelm, "Offline", SFIofflineTotal, 1);

                struct tlvdb *rsfi = tlvdb_parse_multi(buf, len);
                if (!rsfi) {
                    PrintAndLogEx(WARNING, "SFI[%02x] record %d is not valid BER-TLV; skipping its decoded JSON tree", SFI, n);
                } else if (extractTLVElements) {
                    JsonSaveTLVTree(root, jsonelm, "$.Data", rsfi);
                } else {
                    JsonSaveTLVTreeElm(jsonelm, "$.Data", rsfi, true, true, false);
                }
                tlvdb_free(rsfi);
            }
        }
        break;
    }

    // copy Input list for Offline Data Authentication
    if (ODAI_listlen) {
        struct tlvdb *oda = tlvdb_fixed(0x21, ODAI_listlen, ODAI_list); // not a standard tag
        if (oda) {
            tlvdb_add(tlvRoot, oda);
            PrintAndLogEx(INFO, "Input list for Offline Data Authentication added to TLV [%zu bytes]", ODAI_listlen);
        } else {
            PrintAndLogEx(ERR, "Could not allocate Offline Data Authentication input TLV");
        }
    }

    // getting certificates
    if (tlvdb_get(tlvRoot, 0x90, NULL)) {
        PrintAndLogEx(INFO, "Recovering certificates");
        PKISetStrictExecution(false);
        RecoveryCertificates(tlvRoot, root);
        PKISetStrictExecution(true);
    }

    // free tlv object
    tlvdb_free(tlvRoot);

    DropFieldEx(channel);
    SetAPDULogging(false);

    if (MergeJSON == false) {
        // create unique new name
        char *fname = newfilenamemcopy((char *)filename, ".json");
        if (fname == NULL) {
            json_decref(root);
            return PM3_EMALLOC;
        }
        size_t fname_len = strlen(fname);
        if (fname_len >= sizeof(filename)) {
            PrintAndLogEx(ERR, "Output filename is too long");
            free(fname);
            json_decref(root);
            return PM3_EINVARG;
        }
        memcpy(filename, fname, fname_len + 1);
        free(fname);
    }

    res = json_dump_file(root, (char *)filename, JSON_INDENT(2));
    if (res) {
        PrintAndLogEx(ERR, "Can't save the file: %s", filename);
        return PM3_EFILE;
    }

    PrintAndLogEx(SUCCESS, "File " _YELLOW_("`%s`") " saved.", filename);

    // free json object
    json_decref(root);
    return PM3_SUCCESS;
}

static int CmdEMVList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "emv", "7816");
}

static struct tlvdb *emv_test_parse(const char *hex) {
    uint8_t data[1024];
    int len = 0;
    if (param_gethex_to_eol(hex, 0, data, sizeof(data), &len)) return NULL;
    return tlvdb_parse_multi(data, len);
}

static int emv_cvm_tests(void) {
    static const struct {
        const char *name, *hex;
        uint8_t method, outcome, tvr3, tvr4, tsi;
        bool pending;
        int result;
    } cases[] = {
        {"no CVM", "8e0a00000000000000001f009f3303000800", 0x1f, 2, 0, 0, 0x40, false, 0},
        {"no rules", "8e080000000000000000", 0x3f, 0, 0, 0, 0, false, 0},
        {"empty list", "8e00", 0x3f, 0, 0, 0, 0, false, 0},
        {"AIP excludes CVM", "820200008e0a00000000000000000000", 0x3f, 0, 0, 0, 0, false, 0},
        {"signature remains unknown", "8e0a00000000000000001e009f3303002000", 0x1e, 0, 0, 0, 0x40, false, 0},
        {"offline PIN needs evidence", "8e0a000000000000000001009f3303008000", 1, 0, 0, 0, 0, true, 0},
        {"offline PIN observed success", "8e0a000000000000000001009f33030080009f3403010002", 1, 2, 0, 0, 0x40, false, 0},
        {"offline PIN observed unknown", "8e0a000000000000000001009f33030080009f3403010000", 1, 0, 0, 0, 0, true, 0},
        {"online PIN not yet entered", "8e0a000000000000000002009f3303004000", 2, 0, 0, 0, 0, true, 0},
        {"online PIN entered", "8e0a000000000000000002009f33030040009f3403020000", 2, 0, 4, 0, 0x40, false, 0},
        {"unsupported PIN fallback", "8e0c000000000000000041001f009f3303000800", 0x1f, 2, 0x10, 0, 0x40, false, 0},
        {"unrecognised CVM fallback", "8e0c000000000000000060001f009f3303000800", 0x1f, 2, 0x40, 0, 0x40, false, 0},
        {"biometric fallback", "8e0c000000000000000046001f009f3303000800", 0x1f, 2, 0, 2, 0x40, false, 0},
        {"fail CVM always stops", "8e0c000000000000000040001f009f3303000800", 0x40, 1, 0x80, 0, 0x40, false, 0},
        {"failed PIN fallback", "8e0c000000000000000041001f009f33030088009f3403410001", 0x1f, 2, 0, 0, 0x40, false, 0},
        {"missing terminal capabilities", "8e0a00000000000000001f00", 0, 0, 0, 0, 0, false, PM3_EINVARG},
        {"odd rule list", "8e0900000000000000001f9f3303000800", 0, 0, 0, 0, 0, false, PM3_EINVARG},
        {"online PIN cannot claim verified success", "8e0a000000000000000002009f33030040009f3403020002", 0, 0, 0, 0, 0, false, PM3_EINVARG},
        {"unsupported CVM not recorded as performed", "8e0a000000000000000001009f3303000800", 0x3f, 1, 0x90, 0, 0x40, false, 0},
        {"no applicable rule", "8e0a00000000000000001f0a9f3303000800", 0x3f, 1, 0x80, 0, 0x40, false, 0},
        {"combination PIN plus signature unknown", "8e0a000000000000000003009f330300a0009f3403030000", 3, 0, 0, 0, 0x40, false, 0},
        {"last performed rule retained", "8e0c000000000000000041001e009f33030080009f3403410001", 0x41, 1, 0x80, 0, 0x40, false, 0},
    };
    size_t failures = 0;
    for (size_t i = 0; i < ARRAYLEN(cases); i++) {
        struct tlvdb *db = emv_test_parse(cases[i].hex);
        emv_cvm_result_t out;
        int res = db ? emv_cvm_evaluate(db, &out) : PM3_ESOFT;
        bool passed = res == cases[i].result;
        if (!res)
            passed &= out.result[0] == cases[i].method && out.result[2] == cases[i].outcome &&
                      out.tvr[2] == cases[i].tvr3 && out.tvr[3] == cases[i].tvr4 &&
                      out.tsi[0] == cases[i].tsi && out.pending == cases[i].pending;
        failures += !passed;
        PrintAndLogEx(passed ? SUCCESS : FAILED, "CVM test %s ( %s )", cases[i].name, passed ? "ok" : "fail");
        tlvdb_free(db);
    }
    static const struct {
        uint8_t condition, amount, terminal, type;
        bool same_currency, have_amount, applies;
    } conditions[] = {
        {6, 99, 0x22, 0, true, true, true}, {6, 100, 0x22, 0, true, true, false},
        {7, 101, 0x22, 0, true, true, true}, {7, 100, 0x22, 0, true, true, false},
        {8, 199, 0x22, 0, true, true, true}, {8, 200, 0x22, 0, true, true, false},
        {9, 201, 0x22, 0, true, true, true}, {9, 200, 0x22, 0, true, true, false},
        {6, 99, 0x22, 0, false, true, false}, {6, 99, 0x22, 0, true, false, false},
        {1, 0, 0x14, 1, true, true, true}, {1, 0, 0x22, 1, true, true, false},
        {2, 0, 0x22, 0, true, true, true}, {2, 0, 0x22, 9, true, true, false},
        {4, 0, 0x22, 1, true, true, true}, {4, 0, 0x14, 1, true, true, false},
        {5, 0, 0x22, 9, true, true, true}, {5, 0, 0x22, 0, true, true, false},
        {3, 0, 0x22, 0, true, true, true}, {10, 0, 0x22, 0, true, true, false},
    };
    for (size_t i = 0; i < ARRAYLEN(conditions); i++) {
        struct tlvdb *db = emv_test_parse("9f33030008005f2a0209789f420209789f3501229c0100");
        uint8_t list[] = {0, 0, 0, 100, 0, 0, 0, 200, 0x1f, conditions[i].condition, 0, 0};
        tlvdb_change_or_add_node(db, 0x8e, sizeof(list), list);
        tlvdb_change_or_add_node(db, 0x9f35, 1, &conditions[i].terminal);
        tlvdb_change_or_add_node(db, 0x9c, 1, &conditions[i].type);
        if (!conditions[i].same_currency) {
            uint8_t currency[] = {8, 0x40};
            tlvdb_change_or_add_node(db, 0x9f42, 2, currency);
        }
        unsigned value = conditions[i].amount;
        uint8_t amount[] = {0, 0, 0, 0, value / 100, ((value % 100 / 10) << 4) | (value % 10)};
        if (conditions[i].have_amount) tlvdb_change_or_add_node(db, 0x9f02, 6, amount);
        emv_cvm_result_t out;
        bool passed = emv_cvm_evaluate(db, &out) == 0 &&
                      out.result[0] == (conditions[i].applies ? 0x1f : 0) &&
                      out.tvr[2] == (conditions[i].applies ? 0 : 0x80);
        failures += !passed;
        PrintAndLogEx(passed ? SUCCESS : FAILED, "CVM condition test %zu ( %s )", i + 1, passed ? "ok" : "fail");
        tlvdb_free(db);
    }
    PrintAndLogEx(failures ? FAILED : SUCCESS, "CVM tests: %zu cases, %zu failures", ARRAYLEN(cases) + ARRAYLEN(conditions), failures);
    return failures ? PM3_ESOFT : PM3_SUCCESS;
}

static int emv_parser_tests(void) {
    static const struct {const char *hex; bool valid;} cases[] = {
        {"00009f360200010000", true}, {"7708009f360200010000", true},
        {"7703000000", true}, {"9f3600", true}, {"9f3681020001", true},
        {"9f3680", false}, {"9f368200", false}, {"9f360200", false},
        {"9f", false}, {"9f80", false}, {"9f81818000", false},
        {"9f368fffffffffffffffffff", false}, {"77039f3602", false}, {"ff", false},
        {"ff0100", true}, // FF is not generic padding: a private constructed tag.
    };
    size_t failures = 0;
    for (size_t i = 0; i < ARRAYLEN(cases); i++) {
        struct tlvdb *db = emv_test_parse(cases[i].hex);
        bool passed = (db != NULL) == cases[i].valid;
        failures += !passed;
        PrintAndLogEx(passed ? SUCCESS : FAILED, "BER-TLV parser test %zu ( %s )", i + 1, passed ? "ok" : "fail");
        tlvdb_free(db);
    }
    const uint8_t dols[][4] = {{0x9f, 2, 0x80, 0}, {0x9f, 2, 0xff, 0}, {0x9f, 2, 0, 0},
                               {0x9f, 2, 0, 0}, {0x9f, 0, 0, 0}, {0xe1, 3, 0, 0}};
    const size_t dol_len[] = {3, 3, 3, 2, 1, 2}, expected[] = {128, 255, 0, SIZE_MAX, SIZE_MAX, 3};
    struct tlvdb *values = emv_test_parse("9f02030012345a0212349f37020102e1035a0112");
    for (size_t i = 0; i < ARRAYLEN(dols); i++) {
        struct tlv dol = {0x8c, dol_len[i], dols[i]};
        struct tlv *result = dol_process(&dol, values, 1);
        bool passed = expected[i] == SIZE_MAX ? !result : result && result->len == expected[i];
        if (i == 5 && result)
            passed &= !memcmp(result->value, "\0\0\0", 3);
        failures += !passed;
        PrintAndLogEx(passed ? SUCCESS : FAILED, "DOL single-byte length test %zu ( %s )", i + 1, passed ? "ok" : "fail");
        free(result);
    }
    const uint8_t requests[] = {0x9f, 2, 2, 0x9f, 2, 4, 0x5a, 4, 0x9f, 0x37, 4};
    const uint8_t expected_data[] = {0x12, 0x34, 0, 0, 0x12, 0x34, 0x12, 0x34, 0xff, 0xff, 1, 2, 0, 0};
    struct tlv dol = {0x8c, sizeof(requests), requests};
    struct tlv *result = dol_process(&dol, values, 1);
    failures += !(result && result->len == sizeof(expected_data) && !memcmp(result->value, expected_data, sizeof(expected_data)));
    free(result);
    tlvdb_free(values);
    uint8_t nested[130] = {0x5a, 0};
    size_t nested_len = 2;
    for (size_t depth = 1; depth <= 40; depth++) {
        memmove(nested + 2, nested, nested_len);
        nested[0] = 0xe1;
        nested[1] = nested_len;
        nested_len += 2;
        struct tlvdb *db = tlvdb_parse(nested, nested_len);
        failures += (db != NULL) != (depth < 32);
        tlvdb_free(db);
    }
    // Deterministic malformed-input corpus, including every truncation of a
    // real format-2 GPO. Prefixes are not assumed invalid if they form a TLV.
    uint8_t sample[] = {0x77, 10, 0x82, 2, 0x19, 0x80, 0x94, 4, 8, 1, 1, 0};
    for (size_t i = 0; i < sizeof(sample); i++) {
        struct tlvdb *db = tlvdb_parse(sample, i);
        failures += db != NULL;
        tlvdb_free(db);
    }
    for (size_t i = 0; i < sizeof(sample); i++) {
        uint8_t original = sample[i];
        for (unsigned value = 0; value <= 255; value++) {
            sample[i] = value;
            struct tlvdb *db = tlvdb_parse_multi(sample, sizeof(sample));
            tlvdb_free(db);
        }
        sample[i] = original;
    }
    static const struct {tlv_tag_t tag; size_t length; uint8_t value[3]; const char *summary;} display[] = {
        {0x9f36, 2, {0, 0x2f}, "47 (hex 002F)"},
        {0x9f36, 2, {0xff, 0xff}, "65535 (hex FFFF)"},
        {0x9f17, 1, {1}, "1 (hex 01)"},
        {0x9f61, 2, {0xb1, 0xab}, "B1AB (cryptographic value)"},
        {0x9f60, 2, {0xb2, 0x4f}, "B24F (cryptographic value)"},
        {0x50, 3, {'E', 'M', 'V'}, "\"EMV\" (hex 454D56)"},
        {0x9f36, 1, {1}, "invalid length; expected 2 byte(s), raw 01"},
    };
    for (size_t i = 0; i < ARRAYLEN(display); i++) {
        struct tlv t = {display[i].tag, display[i].length, display[i].value};
        char text[128], small[2];
        bool passed = emv_tag_value_summary(&t, text, sizeof(text)) && !strcmp(text, display[i].summary) &&
                      !emv_tag_value_summary(&t, small, sizeof(small)) && small[0] == 0;
        failures += !passed;
        PrintAndLogEx(passed ? SUCCESS : FAILED, "Value display test %zu ( %s )", i + 1, passed ? "ok" : "fail");
    }
    PrintAndLogEx(failures ? FAILED : SUCCESS, "Parser tests: BER-TLV, DOL, depth limits, truncations and 3072 mutations, %zu failures", failures);
    return failures ? PM3_ESOFT : PM3_SUCCESS;
}

static int emv_analysis_tests(void) {
    static const struct {
        const char *name;
        const char *hex;
        emv_format_hint_t hint;
        bool contact;
        bool valid;
        bool warnings;
    } vectors[] = {
        {"GPO format 2", "770a82020000940408010100", EMV_FORMAT_GPO, true, true, false},
        {"GPO missing AIP", "7706940408010100", EMV_FORMAT_GPO, true, false, false},
        {"contact GPO missing AFL", "770482020000", EMV_FORMAT_GPO, true, false, false},
        {"contactless GPO without AFL", "770482020000", EMV_FORMAT_GPO, false, true, false},
        {"GPO duplicate AIP", "770e8202000082020000940408010100", EMV_FORMAT_GPO, true, false, false},
        {"AC format 2", "77149f2701809f360200019f26080011223344556677", EMV_FORMAT_AC, true, true, false},
        {"CVC3 checksum response is not GENERATE AC", "770f9f6102b1ab9f6002b24f9f3602002f", EMV_FORMAT_AUTO, false, true, false},
        {"AC missing fields", "77049f270180", EMV_FORMAT_AC, true, false, false},
        {"AC nested ATC", "771670059f360200019f2701809f26080011223344556677", EMV_FORMAT_AC, true, false, false},
        {"AC duplicate ATC", "77199f2701809f360200019f360200029f26080011223344556677", EMV_FORMAT_AC, true, false, false},
        {"CDA signed response", "770d9f2701409f360200019f4b0101", EMV_FORMAT_AC, true, true, false},
        {"AC RFU CID", "77149f2701c09f360200019f26080011223344556677", EMV_FORMAT_AC, true, false, false},
        {"AC format 1", "800b8000010011223344556677", EMV_FORMAT_AC, true, true, false},
        {"AC format 1 too short", "800180", EMV_FORMAT_AC, true, false, false},
        {"ambiguous format 1", "800e8000010011223344556677000000", EMV_FORMAT_AUTO, false, true, true},
        {"response template required", "9f270180", EMV_FORMAT_AC, true, false, false},
        {"response cannot borrow sibling ATC", "77049f2701809f360200019f26080011223344556677", EMV_FORMAT_AC, true, false, false},
        {"invalid BER length", "77059f270180", EMV_FORMAT_AUTO, false, false, false},
        {"calendar invalid day", "9a03260230", EMV_FORMAT_AUTO, false, false, false},
        {"calendar leap year", "9a03240229", EMV_FORMAT_AUTO, false, true, false},
        {"calendar non-leap year", "9a03250229", EMV_FORMAT_AUTO, false, false, false},
        {"version mismatch recorded", "9f080200019f0902000295050080000000", EMV_FORMAT_AUTO, true, true, true},
        {"version mismatch absent from TVR", "9f080200019f0902000295050000000000", EMV_FORMAT_AUTO, true, false, true},
        {"version compatible", "9f080200019f09020001", EMV_FORMAT_AUTO, true, true, false},
        {"contactless version policy deferred", "9f080200019f09020002", EMV_FORMAT_AUTO, false, true, false},
        {"not effective recorded", "5f25033001019a0326112895050020000000", EMV_FORMAT_AUTO, true, true, true},
        {"not effective absent from TVR", "5f25033001019a0326112895050000000000", EMV_FORMAT_AUTO, true, false, true},
        {"effective date boundary", "5f25032611289a03261128", EMV_FORMAT_AUTO, true, true, false},
        {"AUC domestic purchase", "9f070229809f3501225f280208409f1a0208409c0100", EMV_FORMAT_AUTO, true, true, false},
        {"AUC domestic cash", "9f070281009f3501225f280208409f1a0208409c0101", EMV_FORMAT_AUTO, true, true, false},
        {"AUC cash restriction missing from TVR", "9f070201009f3501225f280208409f1a0208409c010195050000000000", EMV_FORMAT_AUTO, true, false, true},
        {"AUC international cash", "9f070241009f3501225f280208409f1a0209789c0101", EMV_FORMAT_AUTO, true, true, false},
        {"AUC cashback allowed", "9f070229809f3501225f280208409f1a0208409c01099f0306000000000100", EMV_FORMAT_AUTO, true, true, false},
        {"AUC cashback restriction missing from TVR", "9f070229009f3501225f280208409f1a0208409c01099f030600000000010095050000000000", EMV_FORMAT_AUTO, true, false, true},
        {"AUC ATM", "9f070282009f3501149f40058000000000", EMV_FORMAT_AUTO, true, true, false},
        {"AUC ATM capability unknown", "9f070200009f350114", EMV_FORMAT_AUTO, true, true, false},
        {"Visa authentication data", "8405a0000000039f690701112233440000", EMV_FORMAT_AUTO, false, true, false},
        {"Visa authentication data length", "8405a0000000039f690101", EMV_FORMAT_AUTO, false, false, false},
        {"Mastercard UDOL", "8405a0000000049f69039f6a04", EMV_FORMAT_AUTO, false, true, false},
        {"Mastercard malformed UDOL", "8405a0000000049f69019f", EMV_FORMAT_AUTO, false, false, false},
        {"unknown 9F69 profile", "9f690701112233440000", EMV_FORMAT_AUTO, false, true, false},
        {"Mastercard record PUNATC", "8405a00000000470059f6602078e", EMV_FORMAT_AUTO, false, true, false},
        {"Mastercard record PUNATC length", "8405a00000000470079f660400000000", EMV_FORMAT_AUTO, false, false, false},
        {"Mastercard terminal data is not Visa TTQ", "8405a0000000049f6604860000009f6c020080", EMV_FORMAT_AUTO, false, true, false},
        {"Visa TTQ length", "8405a0000000039f6602078e", EMV_FORMAT_AUTO, false, false, false},
        {"Visa CDCVM capability", "8405a0000000039f6604260040009f6c020080", EMV_FORMAT_AUTO, false, true, false},
        {"Visa CDCVM capability mismatch", "8405a0000000039f6604260000009f6c020080", EMV_FORMAT_AUTO, false, false, false},
        {"Visa qVSDC GPO without AFL", "7718820220009f2701809f360200019f26080011223344556677", EMV_FORMAT_GPO, false, true, false},
        {"Visa contact GPO format 1", "8006000008010100", EMV_FORMAT_GPO, true, true, false},
        {"Amex private qualifier remains opaque", "8407a00000002501019f6602078e9f6c0100", EMV_FORMAT_AUTO, false, true, false},
        {"JCB private qualifier remains opaque", "8407a00000006510109f6602078e9f6c0100", EMV_FORMAT_AUTO, false, true, false},
        {"Discover private qualifier remains opaque", "8407a00000015230109f6602078e9f6c0100", EMV_FORMAT_AUTO, false, true, false},
        {"UnionPay private qualifier remains opaque", "8407a00000033301019f6602078e9f6c0100", EMV_FORMAT_AUTO, false, true, false},
        {"unknown RID preserves proprietary data", "8405f0000000019f6901019f6602078e9f6c0100", EMV_FORMAT_AUTO, false, true, false},
        {"ruleless CVM list", "8e080000000000000000", EMV_FORMAT_AUTO, true, true, false},
        {"numeric unpredictable number", "9f6a0499999999", EMV_FORMAT_AUTO, false, true, false},
        {"invalid numeric unpredictable number", "9f6a04ffffffff", EMV_FORMAT_AUTO, false, false, false},
    };
    size_t failures = 0;
    for (size_t i = 0; i < ARRAYLEN(vectors); i++) {
        uint8_t data[256];
        int len = 0;
        emv_analysis_result_t result = {0};
        bool decoded = param_gethex_to_eol(vectors[i].hex, 0, data, sizeof(data), &len) == 0;
        bool valid = decoded && emv_analyze_data(data, len, false, vectors[i].hint, vectors[i].contact, &result);
        bool passed = decoded && valid == vectors[i].valid && (result.warnings != 0) == vectors[i].warnings;
        failures += !passed;
        PrintAndLogEx(passed ? SUCCESS : FAILED, "Analysis test %s ( %s )", vectors[i].name, passed ? "ok" : "fail");
    }
    static const struct {
        const char *hex;
        uint8_t selected;
    } selection[] = {
        {"6f0a8405a0000000038701006f0a8405a000000004870101", 0x04},
        {"6f0a8405a0000000038701816f0a8405a000000004870102", 0x03},
        {"6f078405a0000000036f0a8405a000000004870100", 0x03},
        {"6f0a8405a0000000038701026f0a8405a000000004870102", 0x03},
        {"6f038701016f0a8405a000000004870102", 0x04},
        {"6f0b8405a000000003870201016f0a8405a000000004870102", 0x04},
    };
    for (size_t i = 0; i < ARRAYLEN(selection); i++) {
        uint8_t data[128], aid[16];
        int len = 0;
        size_t aid_len = 0;
        bool decoded = param_gethex_to_eol(selection[i].hex, 0, data, sizeof(data), &len) == 0;
        struct tlvdb *db = decoded ? tlvdb_parse_multi(data, len) : NULL;
        bool passed = db && EMVSelectApplication(db, aid, &aid_len) == PM3_SUCCESS &&
                      aid_len == 5 && aid[4] == selection[i].selected;
        tlvdb_free(db);
        failures += !passed;
        PrintAndLogEx(passed ? SUCCESS : FAILED, "Application selection test %zu ( %s )", i + 1, passed ? "ok" : "fail");
    }
    static const struct {
        uint8_t tvr, denial, online, fallback, tac_denial, tac_online, tac_default;
        bool unavailable, offline_only;
        size_t byte;
        uint8_t expected;
    } actions[] = {
        {0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, false, false, 0, EMVAC_TC},
        {0x80, 0x80, 0x80, 0x80, 0x00, 0x00, 0x00, false, false, 0, EMVAC_AAC},
        {0x80, 0x00, 0x80, 0x80, 0x80, 0x00, 0x00, false, false, 0, EMVAC_AAC},
        {0x80, 0x00, 0x80, 0x80, 0x00, 0x00, 0x00, false, false, 0, EMVAC_ARQC},
        {0x80, 0x00, 0x00, 0x80, 0x00, 0x80, 0x00, false, false, 0, EMVAC_ARQC},
        {0x80, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, true, false, 0, EMVAC_TC},
        {0x80, 0x00, 0x80, 0x80, 0x00, 0x00, 0x00, true, false, 0, EMVAC_AAC},
        {0x80, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, true, false, 0, EMVAC_TC},
        {0x80, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, false, true, 0, EMVAC_AAC},
        {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, false, true, 0, EMVAC_AAC},
        {0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, false, false, 4, EMVAC_ARQC},
    };
    for (size_t i = 0; i < ARRAYLEN(actions); i++) {
        uint8_t masks[7][5] = {{0}}, matched[5];
        const uint8_t values[] = {actions[i].tvr, actions[i].denial, actions[i].online,
                                 actions[i].fallback, actions[i].tac_denial, actions[i].tac_online, actions[i].tac_default};
        for (size_t j = 0; j < ARRAYLEN(values); j++)
            masks[j][actions[i].byte] = values[j];
        const char *stage;
        bool passed = emv_action_decision(masks, actions[i].unavailable, actions[i].offline_only,
                                          matched, &stage) == actions[i].expected;
        failures += !passed;
        PrintAndLogEx(passed ? SUCCESS : FAILED, "Action analysis test %zu ( %s )", i + 1, passed ? "ok" : "fail");
    }
    static const struct {
        const char *left;
        const char *right;
        size_t changes;
    } differences[] = {
        {"9f36020001", "9f36020001", 0},
        {"9f36020001", "9f36020002", 1},
        {"9f360200019f270180", "9f2701809f36020001", 0},
        {"9f360200019f36020002", "9f360200019f36020003", 1},
        {"77059f36020001", "77059f36020002", 1},
        {"9f36020001", "9f360200019f270180", 1},
        {"9f360200019f270180", "9f36020001", 1},
        {"70059f36020001", "77059f36020001", 2},
        {"7700", "77049f270180", 1},
    };
    for (size_t i = 0; i < ARRAYLEN(differences); i++) {
        uint8_t left[128], right[128];
        int left_len = 0, right_len = 0;
        bool decoded = param_gethex_to_eol(differences[i].left, 0, left, sizeof(left), &left_len) == 0 &&
                       param_gethex_to_eol(differences[i].right, 0, right, sizeof(right), &right_len) == 0;
        struct tlvdb *left_db = decoded ? tlvdb_parse_multi(left, left_len) : NULL;
        struct tlvdb *right_db = decoded ? tlvdb_parse_multi(right, right_len) : NULL;
        size_t changes = 0;
        bool passed = left_db && right_db &&
                      emv_diff_trees(left_db, right_db, "", false, false, &changes) == PM3_SUCCESS &&
                      changes == differences[i].changes;
        tlvdb_free(left_db);
        tlvdb_free(right_db);
        failures += !passed;
        PrintAndLogEx(passed ? SUCCESS : FAILED, "Capture comparison test %zu ( %s )", i + 1, passed ? "ok" : "fail");
    }
    static const struct {
        uint32_t sample;
        bool accepted;
        uint8_t encoded[4];
    } numeric[] = {
        {0, true, {0, 0, 0, 0}},
        {1, true, {0, 0, 0, 1}},
        {99999999UL, true, {0x99, 0x99, 0x99, 0x99}},
        {100000000UL, true, {0, 0, 0, 0}},
        {4199999999UL, true, {0x99, 0x99, 0x99, 0x99}},
        {4200000000UL, false, {0, 0, 0, 0}},
        {4294967295UL, false, {0, 0, 0, 0}},
    };
    for (size_t i = 0; i < ARRAYLEN(numeric); i++) {
        uint8_t encoded[4] = {0};
        bool passed = emv_numeric_un(numeric[i].sample, encoded) == numeric[i].accepted &&
                      !memcmp(encoded, numeric[i].encoded, sizeof(encoded));
        failures += !passed;
        PrintAndLogEx(passed ? SUCCESS : FAILED, "Numeric unpredictable-number test %zu ( %s )", i + 1, passed ? "ok" : "fail");
    }
    PrintAndLogEx(failures ? FAILED : SUCCESS, "EMV analysis tests: %zu cases, %zu failures",
                  ARRAYLEN(vectors) + ARRAYLEN(selection) + ARRAYLEN(actions) + ARRAYLEN(differences) + ARRAYLEN(numeric), failures);
    return failures ? PM3_ESOFT : PM3_SUCCESS;
}

static int CmdEMVTest(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv test",
                  "Executes EMV analysis regression tests and crypto tests\n",
                  "emv test -i\n"
                  "emv test --long\n"
                  "emv test --analysis"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("i", "ignore", "Ignore timing tests for VM"),
        arg_lit0("l", "long",   "Run long tests too"),
        arg_lit0("a", "analysis", "Run only offline analysis and application selection tests"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool ignoreTimeTest = arg_get_lit(ctx, 1);
    bool runSlowTests = arg_get_lit(ctx, 2);
    bool analysis_only = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    int res = emv_analysis_tests();
    if (emv_cvm_tests()) res = PM3_ESOFT;
    if (emv_parser_tests()) res = PM3_ESOFT;
    if (EMVTransportSelfTests()) res = PM3_ESOFT;
    if (EMVChallengeSelfTests()) res = PM3_ESOFT;
    if (EMVCompletionSelfTests()) res = PM3_ESOFT;
    if (res != PM3_SUCCESS || analysis_only)
        return res;
    return ExecuteCryptoTests(true, ignoreTimeTest, runSlowTests);
}

static size_t emv_rsa_modulus_bits(const uint8_t *modulus, size_t modulus_len) {
    if (!modulus)
        return 0;
    while (modulus_len && *modulus == 0) {
        modulus++;
        modulus_len--;
    }
    if (!modulus_len)
        return 0;
    uint8_t top = *modulus;
    size_t bits = modulus_len * 8;
    while (!(top & 0x80)) {
        top <<= 1;
        bits--;
    }
    return bits;
}

static uint32_t emv_rsa_exponent_value(const uint8_t *exponent, size_t exponent_len) {
    uint32_t value = 0;
    for (size_t i = 0; i < exponent_len; i++)
        value = (value << 8) | exponent[i];
    return value;
}

static void emv_report_rsa_key(const char *label, const uint8_t *modulus, size_t modulus_len,
                               const uint8_t *exponent, size_t exponent_len) {
    size_t bits = emv_rsa_modulus_bits(modulus, modulus_len);
    PrintAndLogEx(INFO, "%s: %zu-bit RSA modulus", label, bits);
    if (!bits || !modulus || !(modulus[modulus_len - 1] & 1))
        PrintAndLogEx(FAILED, "%s modulus is zero or even and is not a valid RSA modulus", label);
    else {
        if (bits < 1024)
            PrintAndLogEx(FAILED, "%s modulus is below 1024 bits", label);
        else if (bits < 2048)
            PrintAndLogEx(WARNING, "%s uses a legacy-sized RSA modulus; check current key-length policy", label);

        emv_roca_result_t roca = emv_rocacheck_ex(modulus, modulus_len, false);
        if (roca == EMV_ROCA_FOUND)
            PrintAndLogEx(FAILED, "%s matches the ROCA (CVE-2017-15361) fingerprint", label);
        else if (roca == EMV_ROCA_NOT_FOUND)
            PrintAndLogEx(INFO, "%s does not match the ROCA fingerprint (not proof of general key security)", label);
        else
            PrintAndLogEx(WARNING, "%s could not be tested for ROCA", label);

        if (emv_rsa_has_small_factor(modulus, modulus_len))
            PrintAndLogEx(FAILED, "%s modulus has a small prime factor", label);
    }

    if (exponent_len) {
        if (!exponent || exponent_len > 4) {
            PrintAndLogEx(FAILED, "%s exponent is malformed", label);
        } else {
            uint32_t value = emv_rsa_exponent_value(exponent, exponent_len);
            PrintAndLogEx(INFO, "%s public exponent: %u", label, value);
            if (value != 3 && value != 65537)
                PrintAndLogEx(WARNING, "%s exponent is outside the EMV RSA values 3 and 65537", label);
        }
    } else {
        PrintAndLogEx(HINT, "Hint: supply the public exponent to check EMV RSA parameter compatibility");
    }
}

static int CmdEMVKeyCheck(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv keycheck",
                  "Offline public-key research checks: ROCA, size, exponent, small factors,\n"
                  "and an optional shared-factor comparison. It never derives or prints private keys.\n",
                  "emv keycheck -m <modulus-hex> -e 010001\n"
                  "emv keycheck -m <modulus-hex> -p <peer-modulus-hex>\n");
    void *argtable[] = {
        arg_param_begin,
        arg_strx1("m", "modulus", "<hex>", "RSA public modulus, up to 4096 bits"),
        arg_strx0("e", "exponent", "<hex>", "RSA public exponent (normally 03 or 010001)"),
        arg_strx0("p", "peer", "<hex>", "second RSA modulus for a shared-factor check"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t modulus[512] = {0};
    uint8_t exponent[4] = {0};
    uint8_t peer[512] = {0};
    int modulus_len = 0;
    int exponent_len = 0;
    int peer_len = 0;
    CLIGetHexWithReturn(ctx, 1, modulus, &modulus_len);
    CLIGetHexWithReturn(ctx, 2, exponent, &exponent_len);
    CLIGetHexWithReturn(ctx, 3, peer, &peer_len);
    CLIParserFree(ctx);
    if (modulus_len <= 0) {
        PrintAndLogEx(ERR, "RSA modulus must not be empty");
        return PM3_EINVARG;
    }

    emv_report_rsa_key("Primary key", modulus, (size_t)modulus_len,
                       exponent_len ? exponent : NULL, (size_t)exponent_len);
    if (peer_len > 0) {
        emv_report_rsa_key("Peer key", peer, (size_t)peer_len, NULL, 0);
        if (modulus_len == peer_len && !memcmp(modulus, peer, modulus_len))
            PrintAndLogEx(WARNING, "The two public moduli are identical");
        else if (emv_rsa_has_shared_factor(modulus, modulus_len, peer, peer_len))
            PrintAndLogEx(FAILED, "The public moduli share a non-trivial factor (weak key generation)");
        else
            PrintAndLogEx(INFO, "No shared factor was found between the two moduli");
    }
    return PM3_SUCCESS;
}

static int CmdEMVRoca(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv roca",
                  "Extract public keys and run ROCA plus basic RSA parameter/factor checks.\n",
                  "emv roca -w  -> select --CONTACT-- card and run test\n"
                  "emv roca     -> select --CONTACTLESS-- card and run test\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "test",   "Perform self tests"),
        arg_lit0("a",  "apdu",     "Show APDU requests and responses"),
        arg_lit0("w",  "wired",    "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    if (arg_get_lit(ctx, 1)) {
        CLIParserFree(ctx);
        return roca_self_test();
    }

    bool show_apdu = arg_get_lit(ctx, 2);

    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 3))
        channel = CC_CONTACT;

    CLIParserFree(ctx);
    PrintChannel(channel);

    if (IfPm3Smartcard() == false) {
        if (channel == CC_CONTACT) {
            PrintAndLogEx(WARNING, "PM3 does not have SMARTCARD support, exiting");
            return PM3_EDEVNOTSUPP;
        }
    }

    // select card
    uint8_t psenum = (channel == CC_CONTACT) ? 1 : 2;

    SetAPDULogging(show_apdu);

    uint8_t AID[APDU_AID_LEN] = {0};
    size_t AIDlen = 0;
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    uint8_t ODAI_list[4096];
    size_t ODAI_listlen = 0;
    int res;

    // init applets list tree
    const char *al = "Applets list";
    struct tlvdb *tlvSelect = tlvdb_fixed(1, strlen(al), (const unsigned char *)al);

    // EMV PPSE
    PrintAndLogEx(INFO, "PPSE");
    res = EMVSearchPSE(channel, false, true, psenum, false, tlvSelect);

    // check PPSE and select application id
    if (!res) {
        TLVPrintAIDlistFromSelectTLV(tlvSelect);
    } else {
        // EMV SEARCH with AID list
        PrintAndLogEx(INFO, "starting AID search");
        if (EMVSearch(channel, false, true, false, tlvSelect, false)) {
            PrintAndLogEx(ERR, "Can't found any of EMV AID, exiting");
            tlvdb_free(tlvSelect);
            DropFieldEx(channel);
            SetAPDULogging(false);
            return PM3_ERFTRANS;
        }

        // check search and select application id
        TLVPrintAIDlistFromSelectTLV(tlvSelect);
    }

    // EMV SELECT application
    SetAPDULogging(false);
    EMVSelectApplication(tlvSelect, AID, &AIDlen);

    tlvdb_free(tlvSelect);

    if (!AIDlen) {
        PrintAndLogEx(INFO, "Can't select AID or EMV AID not found, exiting");
        DropFieldEx(channel);
        return PM3_ERFTRANS;
    }

    // Init TLV tree
    const char *alr = "Root terminal TLV tree";
    struct tlvdb *tlvRoot = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);

    // EMV SELECT applet
    PrintAndLogEx(INFO, "Selecting AID: " _YELLOW_("%s"), sprint_hex_inrow(AID, AIDlen));
    res = EMVSelect(channel, false, true, AID, AIDlen, buf, sizeof(buf), &len, &sw, tlvRoot);

    if (res) {
        PrintAndLogEx(ERR, "Can't select AID (%d), exiting", res);
        tlvdb_free(tlvRoot);
        DropFieldEx(channel);
        return PM3_ERFTRANS;
    }

    PrintAndLogEx(INFO, "Init transaction parameters");
    if (!InitTransactionParameters(tlvRoot, true, TT_QVSDCMCHIP, false)) {
        tlvdb_free(tlvRoot);
        DropFieldEx(channel);
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "Calc PDOL");
    struct tlv *pdol_data_tlv = dol_process(tlvdb_get(tlvRoot, 0x9f38, NULL), tlvRoot, 0x83);
    if (!pdol_data_tlv) {
        PrintAndLogEx(ERR, "Can't create PDOL TLV");
        tlvdb_free(tlvRoot);
        DropFieldEx(channel);
        return PM3_ESOFT;
    }

    size_t pdol_data_tlv_data_len;
    unsigned char *pdol_data_tlv_data = tlv_encode(pdol_data_tlv, &pdol_data_tlv_data_len);
    if (!pdol_data_tlv_data) {
        PrintAndLogEx(ERR, "Can't create PDOL data, exiting");
        tlvdb_free(tlvRoot);
        DropFieldEx(channel);
        free(pdol_data_tlv);
        return PM3_ESOFT;
    }
    PrintAndLogEx(INFO, "PDOL data[%zu]: %s", pdol_data_tlv_data_len, sprint_hex(pdol_data_tlv_data, pdol_data_tlv_data_len));

    PrintAndLogEx(INFO, "GPO");
    res = EMVGPO(channel, true, pdol_data_tlv_data, pdol_data_tlv_data_len, buf, sizeof(buf), &len, &sw, tlvRoot);

    free(pdol_data_tlv_data);
    free(pdol_data_tlv);

    if (res) {
        PrintAndLogEx(ERR, "GPO error(%d): %4x, exiting", res, sw);
        tlvdb_free(tlvRoot);
        DropFieldEx(channel);
        return PM3_ERFTRANS;
    }
    ProcessGPOResponseFormat1(tlvRoot, buf, len, false);

    PrintAndLogEx(INFO, "Read records from AFL");
    const struct tlv *AFL = tlvdb_get(tlvRoot, 0x94, NULL);

    while (AFL && AFL->len) {
        if (AFL->len % 4) {
            PrintAndLogEx(ERR, "Wrong AFL length: %zu", AFL->len);
            break;
        }

        for (int i = 0; i < AFL->len / 4; i++) {
            uint8_t SFI = AFL->value[i * 4 + 0] >> 3;
            uint8_t SFIstart = AFL->value[i * 4 + 1];
            uint8_t SFIend = AFL->value[i * 4 + 2];
            uint8_t SFIoffline = AFL->value[i * 4 + 3];

            PrintAndLogEx(INFO, "   SFI[%02x] start :%02x end :%02x  offline :%02x", SFI, SFIstart, SFIend, SFIoffline);
            if ((AFL->value[i * 4] & 0x07) || SFI == 0 || SFI == 31 || SFIstart == 0 ||
                    SFIstart > SFIend || SFIoffline > SFIend - SFIstart + 1) {
                PrintAndLogEx(ERR, "SFI ERROR, skipping");
                continue;
            }

            for (int n = SFIstart; n <= SFIend; n++) {
                PrintAndLogEx(INFO, "      SFI[%02x] %d", SFI, n);

                res = EMVReadRecord(channel, true, SFI, n, buf, sizeof(buf), &len, &sw, tlvRoot);
                if (res) {
                    PrintAndLogEx(ERR, "SFI[%02x]. APDU error %4x", SFI, sw);
                    continue;
                }

                // Build Input list for Offline Data Authentication
                // EMV 4.3 book3 10.3, page 96
                if (SFIoffline > 0) {
                    if (!AppendODARecord(ODAI_list, sizeof(ODAI_list), &ODAI_listlen, SFI, buf, len))
                        PrintAndLogEx(WARNING, "SFI[%02x] record could not be safely added to Offline Data Authentication input", SFI);
                    SFIoffline--;
                }
            }
        }
        break;
    }

    // getting certificates
    int ret = PM3_SUCCESS;

    // copy Input list for Offline Data Authentication
    if (ODAI_listlen) {
        struct tlvdb *oda = tlvdb_fixed(0x21, ODAI_listlen, ODAI_list); // not a standard tag
        if (oda) {
            tlvdb_add(tlvRoot, oda);
            PrintAndLogEx(INFO, "Input list for Offline Data Authentication added to TLV [%zu bytes]", ODAI_listlen);
        } else {
            PrintAndLogEx(ERR, "Could not allocate Offline Data Authentication input TLV");
        }
    }

    struct emv_pk *ca_pk = NULL;
    struct emv_pk *issuer_pk = NULL;
    struct emv_pk *icc_pk = NULL;
    bool relaxed_pki = false;
    if (tlvdb_get(tlvRoot, 0x90, NULL)) {
        PrintAndLogEx(INFO, "Recovering certificates");
        PKISetStrictExecution(false);
        relaxed_pki = true;

        ca_pk = get_ca_pk(tlvRoot);
        if (!ca_pk) {
            PrintAndLogEx(ERR, "ERROR: Key not found, exiting");
            ret = PM3_ESOFT;
            goto out;
        }

        issuer_pk = emv_pki_recover_issuer_cert(ca_pk, tlvRoot);
        if (!issuer_pk) {
            PrintAndLogEx(WARNING, "WARNING: Issuer certificate not found, exiting");
            ret = PM3_ESOFT;
            goto out;
        }

        PrintAndLogEx(SUCCESS, "Issuer Public key recovered  RID " _YELLOW_("%s") " IDX " _YELLOW_("%02hhx") " CSN " _YELLOW_("%s"),
                      sprint_hex(issuer_pk->rid, 5),
                      issuer_pk->index,
                      sprint_hex(issuer_pk->serial, 3)
                     );


        const struct tlv *sda_tlv = tlvdb_get(tlvRoot, 0x21, NULL);
        icc_pk = emv_pki_recover_icc_cert(issuer_pk, tlvRoot, sda_tlv);
        if (!icc_pk) {
            PrintAndLogEx(WARNING, "WARNING: ICC certificate not found, exiting");
            ret = PM3_ESOFT;
            goto out;
        }

        PrintAndLogEx(SUCCESS, "ICC Public key recovered     RID " _YELLOW_("%s") " IDX " _YELLOW_("%02hhx") " CSN " _YELLOW_("%s"),
                      sprint_hex(icc_pk->rid, 5),
                      icc_pk->index,
                      sprint_hex(icc_pk->serial, 3)
                     );

        PrintAndLogEx(INFO, "ICC Public key modulus:");
        print_hex_break(icc_pk->modulus, icc_pk->mlen, 16);

        PrintAndLogEx(NORMAL, "");
        emv_report_rsa_key("CA key", ca_pk->modulus, ca_pk->mlen, ca_pk->exp, ca_pk->elen);
        emv_report_rsa_key("Issuer key", issuer_pk->modulus, issuer_pk->mlen, issuer_pk->exp, issuer_pk->elen);
        emv_report_rsa_key("ICC key", icc_pk->modulus, icc_pk->mlen, icc_pk->exp, icc_pk->elen);
        if (emv_rsa_has_shared_factor(ca_pk->modulus, ca_pk->mlen, issuer_pk->modulus, issuer_pk->mlen) ||
                emv_rsa_has_shared_factor(ca_pk->modulus, ca_pk->mlen, icc_pk->modulus, icc_pk->mlen) ||
                emv_rsa_has_shared_factor(issuer_pk->modulus, issuer_pk->mlen, icc_pk->modulus, icc_pk->mlen))
            PrintAndLogEx(FAILED, "At least two keys in the EMV certificate chain share a non-trivial RSA factor");
    }

out:
    if (relaxed_pki)
        PKISetStrictExecution(true);
    emv_pk_free(icc_pk);
    emv_pk_free(issuer_pk);
    emv_pk_free(ca_pk);
    SetAPDULogging(false);
    tlvdb_free(tlvRoot);
    DropFieldEx(channel);
    return ret;
}

static int CmdEMVReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv reader",
                  "Act as an EMV reader and wait for a payment card instead of exiting after one missed poll.\n"
                  "It discovers applications, selects the preferred AID, runs GPO, reads every AFL record,\n"
                  "and queries common transaction/log metadata. Press Enter to stop waiting.\n"
                  "Verbose mode prints complete TLV data and decodes transaction-log records.\n",
                  "emv reader\n"
                  "emv reader -va\n"
                  "emv reader -@     -> Continuous mode\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("w", "wired", "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_lit0("a", "apdu", "Show APDU requests and responses"),
        arg_lit0("@",  NULL,   "continuous reader mode"),
        arg_lit0(NULL, "analyze", "Run complete EMV validation on the collected card profile"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 1)) {
        channel = CC_CONTACT;
    }

    uint8_t psenum = (channel == CC_CONTACT) ? 1 : 2;
    bool verbose = arg_get_lit(ctx, 2);
    bool show_apdu = arg_get_lit(ctx, 3);
    bool continuous = arg_get_lit(ctx, 4);
    bool analyze = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    if (channel == CC_CONTACT && !IfPm3Smartcard()) {
        PrintAndLogEx(ERR, "PM3 does not have SMARTCARD support");
        return PM3_EDEVNOTSUPP;
    }
    if (channel == CC_CONTACTLESS && !IfPm3Iso14443()) {
        PrintAndLogEx(ERR, "PM3 does not have ISO 14443 support");
        return PM3_EDEVNOTSUPP;
    }

    PrintChannel(channel);
    PrintAndLogEx(INFO, continuous ? "Waiting for EMV cards; press <Enter> to exit continuous mode"
                  : "Waiting for an EMV card; press <Enter> to abort");

    bool old_logging = GetAPDULogging();
    SetAPDULogging(show_apdu || verbose);

    uint8_t AID[APDU_AID_LEN] = {0};
    size_t AIDlen = 0;
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    int res = 0;
    uint16_t sw = 0;
    bool card_read = false;
    bool aborted = false;
    int final_result = PM3_SUCCESS;

    do {
        if (kbd_enter_pressed()) {
            aborted = true;
            break;
        }

        memset(AID, 0, sizeof(AID));
        AIDlen = 0;
        len = 0;
        sw = 0;

        // init applets list tree
        const char *al = "Applets";
        struct tlvdb *tlvSelect = tlvdb_fixed(1, strlen(al), (const unsigned char *)al);
        if (!tlvSelect) {
            res = PM3_EMALLOC;
            break;
        }

        // search PSE / PPSE
        PrintAndLogEx(INFO, "EMV reader: discovering applications through %s", psenum == 1 ? "PSE" : "PPSE");
        res = EMVSearchPSE(channel, true, true, psenum, verbose, tlvSelect);
        if (res) {
            // EMV SEARCH with AID list
            PrintAndLogEx(INFO, "EMV reader: payment directory unavailable; searching known AIDs");
            DropFieldEx(channel);
            if (EMVSearch(channel, true, true, verbose, tlvSelect, verbose)) {
                tlvdb_free(tlvSelect);
                DropFieldEx(channel);
                if (!continuous)
                    PrintAndLogEx(INFO, "No readable EMV application yet; continuing to wait");
                msleep(250);
                continue;
            }
        }

        TLVPrintAIDlistFromSelectTLV(tlvSelect);

        // select application
        EMVSelectApplication(tlvSelect, AID, &AIDlen);
        tlvdb_free(tlvSelect);

        if (AIDlen == 0) {
            DropFieldEx(channel);
            if (!continuous)
                PrintAndLogEx(INFO, "No EMV AID found yet; continuing to wait");
            msleep(250);
            continue;
        }

        // Init TLV tree
        const char *alr = "Root";
        struct tlvdb *tlvRoot = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);
        if (!tlvRoot) {
            res = PM3_EMALLOC;
            break;
        }

        // EMV SELECT applet
        PrintAndLogEx(INFO, "EMV reader: selecting AID %s", sprint_hex_inrow(AID, AIDlen));
        res = EMVSelect(channel, false, true, AID, AIDlen, buf, sizeof(buf), &len, &sw, tlvRoot);
        if (res) {
            PrintAndLogEx(WARNING, "AID selection failed: %04x - %s", sw,
                          GetAPDUCodeDescription(sw >> 8, sw & 0xff));
            tlvdb_free(tlvRoot);
            DropFieldEx(channel);
            msleep(250);
            continue;
        }

        card_read = true;

        // decode application parts
        emv_parse_card_details(buf, len, verbose);

        // transaction log information
        uint8_t log_file_id = 0x0B;
        uint8_t log_file_records = 31;
        struct tlvdb *tlogDB = NULL;

        // try getting the LOG TEMPLATE.
        bool log_found = false;
        bool log_template_found = false;
        if (emv_extract_log_info(buf, len, &log_file_id, &log_file_records) == PM3_SUCCESS) {
            log_found = true;
        }

        uint16_t extra_data[] = { 0x9F36, 0x9F13, 0x9F17, 0x9F4D, 0x9F4F };
        for (int i = 0; i < ARRAYLEN(extra_data); i++) {
            if (EMVGetData(channel, true, extra_data[i], buf, sizeof(buf), &len, &sw, tlvRoot)) {
                if (verbose)
                    PrintAndLogEx(INFO, "GET DATA %04X unavailable: %04x - %s", extra_data[i], sw,
                                  GetAPDUCodeDescription(sw >> 8, sw & 0xff));
                continue;
            }
            PrintAndLogEx(INFO, "GET DATA %04X [%zu byte(s)]: %s", extra_data[i], len,
                          sprint_hex_inrow(buf, len));
            if (verbose && len)
                TLVPrintFromBuffer(buf, len);
            if (extra_data[i] == 0x9F4D &&
                    emv_extract_log_info(buf, len, &log_file_id, &log_file_records) == PM3_SUCCESS)
                log_found = true;
            // Log template tag
            if (extra_data[i] == 0x9F4F)  {
                struct tlvdb *ttdb = tlvdb_find_full(tlvRoot, extra_data[i]);
                const struct tlv *ttag = tlvdb_get_tlv(ttdb);
                tlogDB = emv_logtemplate_parse(ttag);
                log_template_found = tlogDB != NULL;
                if (!log_template_found)
                    PrintAndLogEx(WARNING, "The card's Log Format (9F4F) is malformed");
            }
        }

        for (TransactionType_t tt = TT_MSD; tt < TT_END; tt++) {

            // create transaction parameters
            bool gen_acgpo = false;
            if (!InitTransactionParameters(tlvRoot, false, tt, gen_acgpo)) {
                tlvdb_free(tlogDB);
                tlvdb_free(tlvRoot);
                DropFieldEx(channel);
                SetAPDULogging(old_logging);
                return PM3_ESOFT;
            }

            struct tlv *pdol_tlv = dol_process(tlvdb_get(tlvRoot, 0x9F38, NULL), tlvRoot, 0x83);
            if (!pdol_tlv) {
                continue;
            }

            size_t pdtd_len = 0;
            unsigned char *pdol_data_tlv = tlv_encode(pdol_tlv, &pdtd_len);
            if (!pdol_data_tlv) {
                free(pdol_tlv);
                continue;
            }

            PrintAndLogEx(INFO, "EMV reader: trying GPO profile %s with PDOL %s",
                          TransactionTypeStr[tt], sprint_hex_inrow(pdol_data_tlv, pdtd_len));
            res = EMVGPO(channel, true, pdol_data_tlv, pdtd_len, buf, sizeof(buf), &len, &sw, tlvRoot);
            free(pdol_data_tlv);
            free(pdol_tlv);

            if (res) {
                if (verbose)
                    PrintAndLogEx(INFO, "GPO profile %s rejected: %04x - %s", TransactionTypeStr[tt], sw,
                                  GetAPDUCodeDescription(sw >> 8, sw & 0xff));
                continue;
            }

            ProcessGPOResponseFormat1(tlvRoot, buf, len, false);
            PrintAndLogEx(SUCCESS, "GPO profile %s accepted; received %zu data byte(s)",
                          TransactionTypeStr[tt], len);
            if (verbose)
                TLVPrintFromBuffer(buf, len);

            emv_parse_card_details(buf, len, verbose);

            if (tlvdb_get(tlvRoot, 0x77, NULL) ||
                    (tlvdb_get(tlvRoot, 0x82, NULL) && tlvdb_get(tlvRoot, 0x94, NULL))) {
                break;
            }
        }

        const struct tlv *AFL = tlvdb_get(tlvRoot, 0x94, NULL);
        if (AFL && AFL->len) {

            if (AFL->len % 4) {
                PrintAndLogEx(ERR, "Invalid AFL length %zu; record reading skipped", AFL->len);
            } else {
                PrintAndLogEx(INFO, "EMV reader: reading records described by the AFL");
                for (int i = 0; i < AFL->len / 4; i++) {
                    uint8_t SFI = AFL->value[i * 4 + 0] >> 3;
                    uint8_t SFIstart = AFL->value[i * 4 + 1];
                    uint8_t SFIend = AFL->value[i * 4 + 2];

                    if (SFI == 0 || SFI == 31 || SFIstart == 0 || SFIstart > SFIend) {
                        PrintAndLogEx(WARNING, "Skipping invalid AFL entry: SFI %u, records %u..%u",
                                      SFI, SFIstart, SFIend);
                        continue;
                    }

                    for (int n = SFIstart; n <= SFIend; n++) {
                        res = EMVReadRecord(channel, true, SFI, n, buf, sizeof(buf), &len, &sw, tlvRoot);
                        if (res) {
                            PrintAndLogEx(WARNING, "READ RECORD SFI %u record %u failed: %04x - %s",
                                          SFI, n, sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
                            continue;
                        }
                        PrintAndLogEx(INFO, "READ RECORD SFI %u record %u [%zu byte(s)]", SFI, n, len);
                        if (verbose)
                            TLVPrintFromBuffer(buf, len);
                        emv_parse_card_details(buf, len, verbose);
                    }
                }
            }
        } else {
            PrintAndLogEx(WARNING, "GPO did not provide an AFL; no application records can be read");
        }

        // only check for logs file if we found 0x9F4D
        if (verbose && log_found  && log_template_found) {

            for (int i = 1; i <= log_file_records; i++) {
                res = EMVReadRecord(channel, true, log_file_id, i, buf, sizeof(buf), &len, &sw, tlvRoot);
                if (sw == 0x6A83) {
                    PrintAndLogEx(INFO, "Transaction log ended after %u record(s)", i - 1);
                    break;
                }
                if (res) {
                    if (verbose)
                        PrintAndLogEx(INFO, "Transaction log record %u unavailable: %04x - %s", i, sw,
                                      GetAPDUCodeDescription(sw >> 8, sw & 0xff));
                    continue;
                }

                PrintAndLogEx(INFO, "");
                PrintAndLogEx(INFO, "Transaction log # " _YELLOW_("%u"), i);
                PrintAndLogEx(INFO, "---------------------");
                emv_parse_log(tlogDB, buf, len);
                PrintAndLogEx(INFO, "");
            }
        }
        tlvdb_free(tlogDB);

        if (analyze) {
            emv_analysis_result_t analysis_result;
            PrintAndLogEx(INFO, "EMV reader: running complete validation on the collected profile");
            if (!emv_analyze_tlvdb(tlvRoot, true, EMV_FORMAT_AUTO, channel == CC_CONTACT, &analysis_result))
                final_result = PM3_ESOFT;
        } else if (verbose) {
            PrintAndLogEx(INFO, "EMV reader: complete collected TLV profile");
            TLVPrintFromTLV(tlvRoot);
        }

        // free tlv object
        tlvdb_free(tlvRoot);
        PrintAndLogEx(INFO, "");
        if (continuous) {
            DropFieldEx(channel);
            PrintAndLogEx(INFO, "Card complete; remove it and present the next EMV card");
            msleep(250);
        }
    } while (continuous || !card_read);

    DropFieldEx(channel);

    SetAPDULogging(old_logging);
    if (aborted && !card_read)
        return PM3_EOPABORTED;
    if (!card_read && res != PM3_SUCCESS)
        return res;
    return final_result;
}

static command_t CommandTable[] =  {
    {"-----------", CmdHelp,                        AlwaysAvailable, "----------------------- " _CYAN_("General") " -----------------------"},
    {"analyze",     CmdEMVAnalyze,                  AlwaysAvailable, "Collect and analyze a card, or validate supplied EMV TLV data"},
    {"action",      CmdEMVAction,                   AlwaysAvailable, "Explain terminal action-code decisions offline"},
    {"cvm",         CmdEMVCVM,                      AlwaysAvailable, "Evaluate CVM rules against terminal and transaction context"},
    {"diff",        CmdEMVDiff,                     AlwaysAvailable, "Compare two BER-TLV captures by tag path"},
    {"help",        CmdHelp,                        AlwaysAvailable, "This help"},
    {"keycheck",    CmdEMVKeyCheck,                 AlwaysAvailable, "Offline ROCA and RSA public-key checks"},
    {"list",        CmdEMVList,                     AlwaysAvailable, "List ISO7816 history"},
    {"test",        CmdEMVTest,                     AlwaysAvailable, "Run EMV analysis and crypto self tests"},
    {"-----------", CmdHelp,                        IfPm3Iso14443a,  "---------------------- " _CYAN_("Operations") " ---------------------"},
    {"challenge",   CmdEMVGenerateChallenge,        IfPm3Iso14443,   "Generate challenge"},
    {"complete",    CmdEMVComplete,                 IfPm3Smartcard,  "Complete a pending contact transaction using issuer response data"},
    {"exec",        CmdEMVExec,                     IfPm3Iso14443,   "Executes EMV contactless transaction"},
    {"extauth",     CmdEMVExternalAuthenticate,     IfPm3Iso14443,   "Verify issuer authentication data (selected application required)"},
    {"genac",       CmdEMVAC,                       IfPm3Iso14443,   "Generate ApplicationCryptogram"},
    {"getdata",     CmdEMVGetData,                  IfPm3Iso14443,   "Read an application data object (selected application required)"},
    {"gpo",         CmdEMVGPO,                      IfPm3Iso14443,   "Execute GetProcessingOptions"},
    {"intauth",     CmdEMVInternalAuthenticate,     IfPm3Iso14443,   "Internal authentication"},
    {"pse",         CmdEMVPPSE,                     IfPm3Iso14443,   "Execute PPSE. It selects 2PAY.SYS.DDF01 or 1PAY.SYS.DDF01 directory"},
    {"reader",      CmdEMVReader,                   IfPm3Iso14443,   "Act like an EMV reader"},
    {"readrec",     CmdEMVReadRecord,               IfPm3Iso14443,   "Read files from card"},
    {"roca",        CmdEMVRoca,                     IfPm3Iso14443,   "Extract public keys and run ROCA/RSA checks"},
    {"scan",        CmdEMVScan,                     IfPm3Iso14443,   "Scan EMV card and save it contents to json file for emulator"},
    {"search",      CmdEMVSearch,                   IfPm3Iso14443,   "Try to select all applets from applets list and print installed applets"},
    {"select",      CmdEMVSelect,                   IfPm3Iso14443,   "Select applet"},
    {"-----------", CmdHelp,                        IfPm3Iso14443a,  "---------------------- " _CYAN_("simulation") " ---------------------"},
    {"smart2nfc",   CmdEMVSmartToNFC,               IfPm3Smartcard,  "Complete transaction as a nfc smart card, using the ISO-7816 interface for auth"},
    /*
    {"getrng",      CmdEMVGetrng,                   IfPm3Iso14443,   "Get random number from terminal"},
    {"eload",       CmdEmvELoad,                    IfPm3Iso14443,   "Load EMV tag into device"},
    {"dump",        CmdEmvDump,                     IfPm3Iso14443,   "Dump EMV tag values"},
    {"sim",         CmdEmvSim,                      IfPm3Iso14443,   "Simulate EMV tag"},
    {"clone",       CmdEmvClone,                    IfPm3Iso14443,   "Cone an EMV tag"},
    */
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdEMV(const char *Cmd) {
    // Issuer responses must apply to the immediately preceding online flow.
    // Any other EMV operation abandons that transaction and releases the card.
    if (emv_pending.transaction && !(strncmp(Cmd, "complete", 8) == 0 &&
            (Cmd[8] == 0 || Cmd[8] == ' ')))
        emv_pending_clear();
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
