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
// CharlieCard (MBTA, Boston) parser for MIFARE Classic dumps
//-----------------------------------------------------------------------------

#include "parsecharlie.h"

#include <stdio.h>
#include <string.h>

#include "commonutil.h"         // MemBeToUint4byte
#include "ui.h"                 // PrintAndLogEx
#include "parsetransit.h"

#define CHARLIE_DUMP_MIN        1024
#define CHARLIE_BLK(s, b)       ((((s) * 4) + (b)) * 16)
#define CHARLIE_TRIPS           12

// Sector 0 keys, either may sit in A or B depending on the dump
static const uint64_t charlie_s0_keys[2] = { 0x3060206F5B0A, 0xF1B9F5669CC8 };
// Data sector keys, A and B
static const uint64_t charlie_data_keys[2] = { 0x5EC39B022F2B, 0xF662248E7E89 };

static uint64_t charlie_key(const uint8_t *dump, uint8_t sector, bool key_b) {
    return MemBeToUint6byte(dump + CHARLIE_BLK(sector, 3) + (key_b ? 10 : 0));
}

static bool charlie_key_in(uint64_t k, const uint64_t *set) {
    return k == set[0] || k == set[1];
}

bool is_valid_charlie_card(const uint8_t *dump, size_t dumplen) {
    if (dump == NULL || dumplen < CHARLIE_DUMP_MIN) {
        return false;
    }
    bool s0 = charlie_key_in(charlie_key(dump, 0, false), charlie_s0_keys) ||
              charlie_key_in(charlie_key(dump, 0, true), charlie_s0_keys);
    bool s1 = charlie_key_in(charlie_key(dump, 1, false), charlie_data_keys) ||
              charlie_key_in(charlie_key(dump, 1, true), charlie_data_keys);
    return s0 && s1;
}

// Money in half cents, top bit is the sign
static int32_t charlie_price(const uint8_t *p) {
    int32_t v = (int32_t)MemBeToUint2byte(p);
    if (v & 0x8000) {
        v = -(v & 0x7FFF);
    }
    return v / 2;
}

// Minutes since 2003-01-01, Boston local time
static void charlie_time_str(uint32_t minutes, char *out, size_t outlen) {
    int64_t secs = ((int64_t)transit_days_from_civil(2003, 1, 1) * 86400) + ((int64_t)minutes * 60);
    transit_datetime_str(out, outlen, secs);
}

// Sectors 2 and 3 alternate, the one with the higher sequence is current
static uint8_t charlie_balance_sector(const uint8_t *dump) {
    uint64_t s2 = transit_bits_be(dump + CHARLIE_BLK(2, 0), 16, 81, 16);
    uint64_t s3 = transit_bits_be(dump + CHARLIE_BLK(3, 0), 16, 81, 16);
    return (s2 > s3) ? 2 : 3;
}

static const char *charlie_card_type(uint16_t type) {
    switch (type) {
        case 366:
            return "SV Adult";
        case 367:
            return "Adult";
        case 410:
            return "Employee ID without passback";
        case 414:
            return "Employee ID with passback";
        case 415:
            return "Retiree";
        case 416:
            return "Police/Fire";
        case 417:
            return "Blind";
        case 418:
            return "Student";
        case 419:
            return "Senior";
        case 420:
            return "TAP";
        case 426:
            return "Child";
        default:
            return "unknown";
    }
}

static const char *charlie_mode(uint16_t validator) {
    switch (validator & 7) {
        case 0:
            return "ticket machine";
        case 1:
            return "bus";
        default:
            return "other";
    }
}

int charlie_parser_parse(const uint8_t *dump, size_t dumplen) {
    if (is_valid_charlie_card(dump, dumplen) == false) {
        return PM3_EINVARG;
    }

    char s[64];
    transit_print_header("CharlieCard - MBTA Boston");
    transit_print_kv("Serial", _YELLOW_("5-%u"), MemBeToUint4byte(dump));

    uint32_t second = MemBeToUint4byte(dump + CHARLIE_BLK(8, 0));
    if (second != 0 && second != 0xFFFFFFFF) {
        transit_print_kv("2nd card number", "A%010u", second);
    }

    uint8_t bs = charlie_balance_sector(dump);
    const uint8_t *b0 = dump + CHARLIE_BLK(bs, 0);
    const uint8_t *b1 = dump + CHARLIE_BLK(bs, 1);

    uint16_t type = MemBeToUint2byte(b1) >> 6;
    transit_print_kv("Card type", "%u ( %s )", type, charlie_card_type(type));

    transit_money_str(s, sizeof(s), charlie_price(b1 + 5), 2, "USD");
    transit_print_kv("Balance", _GREEN_("%s") " ( sector %u )", s, bs);

    uint32_t issued = MemBeToUint3byte(b0 + 6);
    charlie_time_str(issued, s, sizeof(s));
    transit_print_kv("Issued", "%s", s);

    // end of validity in units of 8 minutes, zero or before issue means unset
    uint32_t ev = (MemBeToUint3byte(b1 + 1) & 0x1FFFFF) * 8;
    if (ev != 0 && ev >= issued) {
        charlie_time_str(ev, s, sizeof(s));
        transit_print_kv("Valid until", "%s", s);
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Trips, sectors 6 and 7, times local");
    for (uint8_t i = 0; i < CHARLIE_TRIPS; i++) {
        const uint8_t *t = dump + CHARLIE_BLK(6 + (i / 6), (i / 2) % 3) + (7 * (i % 2));
        if (MemBeToUint4byte(t) == 0) {
            continue;
        }
        char fare[32];
        uint16_t validator = MemBeToUint2byte(t + 3);
        charlie_time_str(MemBeToUint3byte(t), s, sizeof(s));
        transit_money_str(fare, sizeof(fare), charlie_price(t + 5), 2, "USD");
        PrintAndLogEx(INFO, "  %s  %-14s  station %5u  %12s", s, charlie_mode(validator), validator >> 3, fare);
    }
    return PM3_SUCCESS;
}

//-----------------------------------------------------------------------------
// Self test, synthetic card built from the layout above
//-----------------------------------------------------------------------------

static void charlie_put_be(uint8_t *p, uint32_t v, uint8_t n) {
    for (uint8_t i = 0; i < n; i++) {
        p[i] = (uint8_t)(v >> (8 * (n - 1 - i)));
    }
}

int charlie_selftest(void) {
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing CharlieCard decode");

    static uint8_t d[CHARLIE_DUMP_MIN];
    memset(d, 0, sizeof(d));

    charlie_put_be(d, 0x12345678, 4);
    charlie_put_be(d + CHARLIE_BLK(0, 3), (uint32_t)(charlie_s0_keys[1] >> 16), 4);
    charlie_put_be(d + CHARLIE_BLK(0, 3) + 4, (uint32_t)(charlie_s0_keys[1] & 0xFFFF), 2);
    charlie_put_be(d + CHARLIE_BLK(1, 3), (uint32_t)(charlie_data_keys[0] >> 16), 4);
    charlie_put_be(d + CHARLIE_BLK(1, 3) + 4, (uint32_t)(charlie_data_keys[0] & 0xFFFF), 2);

    // sector 3 newer than sector 2, adult card, $12.50, issued 2020-01-01 00:00
    transit_set_bits_be(d + CHARLIE_BLK(2, 0), 16, 81, 16, 4);
    transit_set_bits_be(d + CHARLIE_BLK(3, 0), 16, 81, 16, 5);
    uint8_t *b1 = d + CHARLIE_BLK(3, 1);
    charlie_put_be(b1, 367 << 6, 2);
    charlie_put_be(b1 + 5, 2500, 2);
    uint32_t issued = (uint32_t)(transit_days_from_civil(2020, 1, 1) - transit_days_from_civil(2003, 1, 1)) * 1440;
    charlie_put_be(d + CHARLIE_BLK(3, 0) + 6, issued, 3);

    // one bus trip of $1.70 at station 1234, second slot of block 0
    uint8_t *t = d + CHARLIE_BLK(6, 0) + 7;
    charlie_put_be(t, issued + 600, 3);
    charlie_put_be(t + 3, (1234 << 3) | 1, 2);
    charlie_put_be(t + 5, 340, 2);

    bool ok = true;
    ok &= transit_check("detected", is_valid_charlie_card(d, sizeof(d)), true);
    ok &= transit_check("balance sector", charlie_balance_sector(d), 3);
    ok &= transit_check("balance cents", (uint64_t)charlie_price(b1 + 5), 1250);
    ok &= transit_check("card type", MemBeToUint2byte(b1) >> 6, 367);
    ok &= transit_check("negative price", (uint64_t)(-charlie_price((const uint8_t *)"\x80\x64")), 50);

    char s[32];
    charlie_time_str(MemBeToUint3byte(t), s, sizeof(s));
    ok &= transit_check_str("trip time", s, "2020-01-01 10:00:00");
    ok &= transit_check("parse", charlie_parser_parse(d, sizeof(d)), PM3_SUCCESS);

    d[CHARLIE_BLK(1, 3)] ^= 0xFF;
    ok &= transit_check("wrong data key", is_valid_charlie_card(d, sizeof(d)), false);

    return transit_selftest_result("CharlieCard", ok);
}
