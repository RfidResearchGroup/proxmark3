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
// SmartRider (Perth) and MyWay (Canberra) parser for MIFARE Classic dumps
//-----------------------------------------------------------------------------

#include "parsesmartrider.h"

#include <stdio.h>
#include <string.h>

#include "commonutil.h"         // MemLeToUint2byte
#include "ui.h"                 // PrintAndLogEx
#include "util.h"               // sprint_hex_inrow
#include "mbedtls/md5.h"
#include "parsetransit.h"
#include "parsetransitmfc.h"

#define SR_DUMP_MIN             1024
#define SR_BLK(s, b)            ((((s) * 4) + (b)) * 16)
#define SR_MAX_TAGS             12
#define SR_DAYS_TO_2000         10957

typedef enum {
    SR_UNKNOWN = 0,
    SR_SMARTRIDER,
    SR_MYWAY,
} sr_type_t;

// Sector 7 common keys, SmartRider key A and key B
static const transit_mfc_key_t sr_s7_keys[2] = {
    {7, TRANSIT_MFC_KEY_A, 0x9189449EA24E}, {7, TRANSIT_MFC_KEY_B, 0x568C9083F71C},
};

const transit_mfc_keyset_t smartrider_keyset = { sr_s7_keys, ARRAYLEN(sr_s7_keys), false };

// md5("myway" || key || "myway") of the MyWay sector 7 key, from Metrodroid
static const uint8_t sr_myway_digest[16] = {
    0x29, 0xA6, 0x1B, 0x3A, 0x4D, 0x5C, 0x81, 0x84,
    0x15, 0x35, 0x08, 0x04, 0xC8, 0x2C, 0xD8, 0x34
};

static bool sr_key_digest_is(const uint8_t *key, const char *salt, const uint8_t *digest) {
    uint8_t buf[32];
    size_t sl = strlen(salt);
    if ((2 * sl) + 6 > sizeof(buf)) {
        return false;
    }
    memcpy(buf, salt, sl);
    memcpy(buf + sl, key, 6);
    memcpy(buf + sl + 6, salt, sl);
    uint8_t md[16];
    if (mbedtls_md5_ret(buf, (2 * sl) + 6, md) != 0) {
        return false;
    }
    return memcmp(md, digest, sizeof(md)) == 0;
}

static sr_type_t sr_detect(const uint8_t *dump, size_t dumplen) {
    if (dump == NULL || dumplen < SR_DUMP_MIN) {
        return SR_UNKNOWN;
    }
    const uint8_t *t = dump + SR_BLK(7, 3);
    if (transit_mfc_keyset_match_dump(&smartrider_keyset, dump, dumplen)) {
        return SR_SMARTRIDER;
    }
    if (sr_key_digest_is(t, "myway", sr_myway_digest) || sr_key_digest_is(t + 10, "myway", sr_myway_digest)) {
        return SR_MYWAY;
    }
    return SR_UNKNOWN;
}

bool is_valid_smartrider_card(const uint8_t *dump, size_t dumplen) {
    return sr_detect(dump, dumplen) != SR_UNKNOWN;
}

// Seconds since 2000-01-01 local time
static void sr_time_str(uint32_t secs, char *out, size_t outlen) {
    transit_datetime_str(out, outlen, ((int64_t)SR_DAYS_TO_2000 * 86400) + secs);
}

// Data blocks of a sector, 48 bytes
static void sr_sector_data(const uint8_t *dump, uint8_t sector, uint8_t *out) {
    memcpy(out, dump + SR_BLK(sector, 0), 48);
}

typedef struct {
    uint16_t txn;
    int32_t balance;
    uint16_t total_fare;
    uint16_t journey;
} sr_balance_t;

static void sr_read_balance(const uint8_t *dump, uint8_t sector, sr_balance_t *b) {
    uint8_t d[48];
    sr_sector_data(dump, sector, d);
    b->txn = MemLeToUint2byte(d + 3);
    b->balance = MemLeToUint2byte(d + 39);
    if (d[2] & 0x80) {
        b->balance = -b->balance;
    }
    b->total_fare = MemLeToUint2byte(d + 33);
    b->journey = MemLeToUint2byte(d + 43);
}

static const char *sr_concession(sr_type_t type, uint8_t token) {
    if (type != SR_SMARTRIDER) {
        return "";
    }
    switch (token) {
        case 0x01:
            return "standard";
        case 0x02:
            return "student";
        case 0x04:
            return "tertiary";
        case 0x06:
            return "senior";
        case 0x07:
            return "concession";
        case 0x0E:
            return "staff";
        case 0x0F:
            return "pensioner";
        case 0x10:
            return "convention";
        default:
            return "unknown";
    }
}

static const char *sr_mode(sr_type_t type, uint8_t bitfield) {
    switch (bitfield & 0x03) {
        case 0:
            return "bus";
        case 1:
            return (type == SR_MYWAY) ? "tram" : "train";
        case 2:
            return "ferry";
        default:
            return "other";
    }
}

typedef struct {
    uint32_t ts;
    uint8_t bitfield;
    char route[5];
    uint16_t cost;
} sr_tag_t;

static void sr_read_tag(const uint8_t *blk, sr_tag_t *t) {
    t->ts = MemLeToUint4byte(blk + 3);
    t->bitfield = blk[7];
    size_t n = 0;
    for (uint8_t i = 0; i < 4; i++) {
        if (blk[8 + i] >= 0x20 && blk[8 + i] < 0x7F) {
            t->route[n++] = (char)blk[8 + i];
        }
    }
    t->route[n] = '\0';
    t->cost = MemLeToUint2byte(blk + 13);
}

int smartrider_parser_parse(const uint8_t *dump, size_t dumplen) {
    sr_type_t type = sr_detect(dump, dumplen);
    if (type == SR_UNKNOWN) {
        return PM3_EINVARG;
    }

    char s[64];
    transit_print_header((type == SR_MYWAY) ? "MyWay - Canberra" : "SmartRider - Perth");

    // serial, ten BCD digits of sector 0 block 1 with one leading zero dropped
    char serial[16];
    snprintf(serial, sizeof(serial), "%s", sprint_hex_inrow(dump + SR_BLK(0, 1) + 6, 5));
    transit_print_kv("Serial", _YELLOW_("%s"), (serial[0] == '0') ? serial + 1 : serial);

    uint8_t cfg[48];
    sr_sector_data(dump, 1, cfg);
    uint8_t token = cfg[24];
    transit_print_kv("Token type", "%u %s", token, sr_concession(type, token));

    uint16_t issue = MemLeToUint2byte(cfg + 16);
    uint16_t expiry = MemLeToUint2byte(cfg + 18);
    if (issue) {
        transit_date_str(s, sizeof(s), TRANSIT_DAYS_TO_1997 + issue);
        transit_print_kv("Issued", "%s", s);
    }
    if (expiry) {
        transit_date_str(s, sizeof(s), TRANSIT_DAYS_TO_1997 + expiry);
        transit_print_kv("Expiry", "%s", s);
    }

    sr_balance_t ba, bb;
    sr_read_balance(dump, 2, &ba);
    sr_read_balance(dump, 3, &bb);
    const sr_balance_t *bal = (bb.txn > ba.txn) ? &bb : &ba;
    transit_money_str(s, sizeof(s), bal->balance, 2, "AUD");
    transit_print_kv("Balance", _GREEN_("%s"), s);
    transit_print_kv("Transaction no", "%u", bal->txn);
    transit_print_kv("Journey no", "%u", bal->journey);

    if (type == SR_SMARTRIDER) {
        char v[32];
        transit_money_str(s, sizeof(s), MemLeToUint2byte(cfg + 20), 2, "AUD");
        transit_money_str(v, sizeof(v), MemLeToUint2byte(cfg + 22), 2, "AUD");
        transit_print_kv("Autoload", "%s when below %s", v, s);
    }

    // tag records, sectors 10..13, newest first
    sr_tag_t tags[SR_MAX_TAGS];
    uint8_t n = 0;
    for (uint8_t sec = 10; sec <= 13; sec++) {
        for (uint8_t b = 0; b < 3; b++) {
            sr_tag_t t;
            sr_read_tag(dump + SR_BLK(sec, b), &t);
            if (t.ts != 0 && n < SR_MAX_TAGS) {
                tags[n++] = t;
            }
        }
    }
    for (uint8_t i = 1; i < n; i++) {
        for (uint8_t j = i; j > 0 && tags[j].ts > tags[j - 1].ts; j--) {
            sr_tag_t tmp = tags[j];
            tags[j] = tags[j - 1];
            tags[j - 1] = tmp;
        }
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Tag on / off, times local");
    for (uint8_t i = 0; i < n; i++) {
        char cost[32];
        sr_time_str(tags[i].ts, s, sizeof(s));
        transit_money_str(cost, sizeof(cost), tags[i].cost, 2, "AUD");
        PrintAndLogEx(INFO, "  %s  %-3s  %-5s  route %-4s  %12s%s", s,
                      (tags[i].bitfield & 0x10) ? "on" : "off",
                      sr_mode(type, tags[i].bitfield), tags[i].route, cost,
                      (tags[i].bitfield & 0x08) ? "  transfer" : "");
    }
    return PM3_SUCCESS;
}

//-----------------------------------------------------------------------------
// Self test. The timestamp is Metrodroid's SmartRiderTest vector, the card is
// synthetic, built from the layout above.
//-----------------------------------------------------------------------------

int smartrider_selftest(void) {
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing SmartRider decode");

    char s[32];
    bool ok = true;
    sr_time_str(529800999, s, sizeof(s));
    ok &= transit_check_str("Metrodroid timestamp", s, "2016-10-14 22:56:39");

    static uint8_t d[SR_DUMP_MIN];
    memset(d, 0, sizeof(d));

    // key A of sector 7
    uint8_t *t = d + SR_BLK(7, 3);
    for (int i = 0; i < 6; i++) {
        t[i] = (uint8_t)(sr_s7_keys[0].key >> (40 - (8 * i)));
    }
    ok &= transit_check("detected", is_valid_smartrider_card(d, sizeof(d)), true);
    ok &= transit_mfc_check_identify("identify", d, sizeof(d), "SmartRider", TRANSIT_ID_MATCH);

    // Metrodroid's published digest of the SmartRider key A proves the hashing
    static const uint8_t sr_key2_digest[16] = {
        0xE0, 0x91, 0x35, 0x18, 0xA5, 0x00, 0x8C, 0x03,
        0xE1, 0xB3, 0xF2, 0xBB, 0x3A, 0x43, 0xFF, 0x78
    };
    ok &= transit_check("SmartRider key digest", sr_key_digest_is(t, "smartrider", sr_key2_digest), true);
    ok &= transit_check("not MyWay digest", sr_key_digest_is(t, "myway", sr_myway_digest), false);

    // serial 0123456789, standard token, balance -$2.50 in the newer sector 3
    memcpy(d + SR_BLK(0, 1) + 6, "\x01\x23\x45\x67\x89", 5);
    d[SR_BLK(1, 1) + 8] = 0x01;
    d[SR_BLK(2, 0) + 3] = 0x07;
    uint8_t *b3 = d + SR_BLK(3, 0);
    b3[2] = 0x80;
    b3[3] = 0x08;
    b3[39] = 0xFA;

    sr_balance_t bb;
    sr_read_balance(d, 3, &bb);
    ok &= transit_check("txn number", bb.txn, 8);
    ok &= transit_check("balance negated", (uint64_t)(-bb.balance), 250);

    // tag on a train, route "MAN", $3.20
    uint8_t *tag = d + SR_BLK(10, 0);
    tag[3] = 0x27;
    tag[4] = 0x1F;
    tag[5] = 0x94;
    tag[6] = 0x1F;
    tag[7] = 0x11;
    memcpy(tag + 8, "MAN\0", 4);
    tag[13] = 0x40;
    tag[14] = 0x01;
    sr_tag_t tg;
    sr_read_tag(tag, &tg);
    ok &= transit_check("tag time", tg.ts, 529800999);
    ok &= transit_check_str("tag route", tg.route, "MAN");
    ok &= transit_check("tag cost", tg.cost, 320);
    ok &= transit_check("parse", smartrider_parser_parse(d, sizeof(d)), PM3_SUCCESS);

    t[0] ^= 0xFF;
    ok &= transit_check("wrong sector 7 key", is_valid_smartrider_card(d, sizeof(d)), false);
    ok &= transit_mfc_check_identify("not identified", d, sizeof(d), "SmartRider", TRANSIT_ID_NONE);

    return transit_selftest_result("SmartRider", ok);
}
