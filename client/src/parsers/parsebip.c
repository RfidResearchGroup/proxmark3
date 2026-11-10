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
// Bip! (Santiago de Chile) parser for MIFARE Classic dumps
//-----------------------------------------------------------------------------

#include "parsebip.h"

#include <stdio.h>
#include <string.h>

#include "commonutil.h"         // MemLeToUint4byte
#include "ui.h"                 // PrintAndLogEx
#include "parsetransit.h"

#define BIP_DUMP_MIN            1024
#define BIP_BLK(s, b)           ((((s) * 4) + (b)) * 16)

// Key A and key B of sector 0, key A and key B of sector 1
static const uint64_t bip_keys[4] = {
    0x3A42F33AF429, 0x1FC235AC1309, 0x6338A371C0ED, 0x243F160918D1
};

static uint64_t bip_key(const uint8_t *dump, uint8_t sector, bool key_b) {
    return MemBeToUint6byte(dump + BIP_BLK(sector, 3) + (key_b ? 10 : 0));
}

static bool bip_sector_key_ok(const uint8_t *dump, uint8_t sector) {
    return bip_key(dump, sector, false) == bip_keys[sector * 2] ||
           bip_key(dump, sector, true) == bip_keys[(sector * 2) + 1];
}

bool is_valid_bip_card(const uint8_t *dump, size_t dumplen) {
    if (dump == NULL || dumplen < BIP_DUMP_MIN) {
        return false;
    }
    return bip_sector_key_ok(dump, 0) && bip_sector_key_ok(dump, 1);
}

// Timestamp packed least significant bit first in the first five bytes
static void bip_timestamp_str(const uint8_t *blk, char *out, size_t outlen) {
    unsigned year = 2000 + (unsigned)transit_bits_le(blk, 16, 15, 5);
    unsigned month = (unsigned)transit_bits_le(blk, 16, 11, 4);
    unsigned day = (unsigned)transit_bits_le(blk, 16, 6, 5);
    unsigned hour = (unsigned)transit_bits_le(blk, 16, 20, 5);
    unsigned minute = (unsigned)transit_bits_le(blk, 16, 25, 6);
    unsigned second = (unsigned)transit_bits_le(blk, 16, 31, 6);
    snprintf(out, outlen, "%04u-%02u-%02u %02u:%02u:%02u", year, month, day, hour, minute, second);
}

static int32_t bip_balance(const uint8_t *dump) {
    const uint8_t *b = dump + BIP_BLK(8, 1);
    int32_t v = (int32_t)MemLeToUint3byte(b);
    return (b[3] & 0x7F) ? -v : v;
}

static uint32_t bip_holder_id(const uint8_t *dump) {
    return MemLeToUint4byte(dump + BIP_BLK(3, 1) + 3);
}

// An event slot is empty when everything but the type and checksum is zero
static bool bip_slot_empty(const uint8_t *blk) {
    return transit_is_zero(blk + 1, 14);
}

static const char *bip_trip_mode(uint8_t type) {
    switch (type) {
        case 0x45:
            return "metro";
        case 0x46:
            return "bus";
        default:
            return "other";
    }
}

int bip_parser_parse(const uint8_t *dump, size_t dumplen) {
    if (is_valid_bip_card(dump, dumplen) == false) {
        return PM3_EINVARG;
    }

    char s[64];
    transit_print_header("Bip! - Santiago de Chile");
    transit_print_kv("Card number", _YELLOW_("%u"), MemLeToUint4byte(dump + BIP_BLK(0, 1) + 4));

    uint32_t holder = bip_holder_id(dump);
    transit_print_kv("Card type", "%s", (holder == 0) ? "anonymous" : "personal");
    if (holder) {
        transit_print_kv("Holder id", "%u", holder);
    }

    // name kept reversed in sector 3 block 0, bytes 1..14
    const uint8_t *nb = dump + BIP_BLK(3, 0);
    if (nb[14] != 0) {
        char name[15] = {0};
        size_t n = 0;
        for (int i = 14; i >= 1; i--) {
            if (nb[i] >= 0x20 && nb[i] < 0x7F) {
                name[n++] = (char)nb[i];
            }
        }
        transit_print_kv("Holder name", "%s", name);
    }

    transit_money_str(s, sizeof(s), bip_balance(dump), 0, "CLP");
    transit_print_kv("Balance", _GREEN_("%s"), s);

    const uint8_t *tw = dump + BIP_BLK(5, 1);
    if (transit_is_zero(tw, 8) == false) {
        bip_timestamp_str(tw, s, sizeof(s));
        transit_print_kv("Trip window end", "%s", s);
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Trips");
    for (uint8_t i = 0; i < 3; i++) {
        const uint8_t *b = dump + BIP_BLK(11, i);
        if (bip_slot_empty(b)) {
            continue;
        }
        char fare[32];
        bip_timestamp_str(b, s, sizeof(s));
        transit_money_str(fare, sizeof(fare), (int64_t)transit_bits_le(b, 16, 82, 16), 0, "CLP");
        PrintAndLogEx(INFO, "  %s  %-5s  %12s", s, bip_trip_mode(b[8]), fare);
    }

    PrintAndLogEx(INFO, "Top ups");
    for (uint8_t i = 0; i < 3; i++) {
        const uint8_t *b = dump + BIP_BLK(10, i);
        if (bip_slot_empty(b)) {
            continue;
        }
        char fare[32];
        bip_timestamp_str(b, s, sizeof(s));
        transit_money_str(fare, sizeof(fare), (int64_t)transit_bits_le(b, 16, 74, 16), 0, "CLP");
        PrintAndLogEx(INFO, "  %s         +%12s", s, fare);
    }
    return PM3_SUCCESS;
}

//-----------------------------------------------------------------------------
// Self test, synthetic card built from the layout above
//-----------------------------------------------------------------------------

static void bip_set_timestamp(uint8_t *blk, unsigned y, unsigned mo, unsigned d, unsigned h, unsigned mi, unsigned sec) {
    transit_set_bits_le(blk, 16, 6, 5, d);
    transit_set_bits_le(blk, 16, 11, 4, mo);
    transit_set_bits_le(blk, 16, 15, 5, y - 2000);
    transit_set_bits_le(blk, 16, 20, 5, h);
    transit_set_bits_le(blk, 16, 25, 6, mi);
    transit_set_bits_le(blk, 16, 31, 6, sec);
}

int bip_selftest(void) {
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing Bip! decode");

    static uint8_t d[BIP_DUMP_MIN];
    memset(d, 0, sizeof(d));

    for (uint8_t s = 0; s < 2; s++) {
        uint8_t *t = d + BIP_BLK(s, 3);
        for (int i = 0; i < 6; i++) {
            t[i] = (uint8_t)(bip_keys[s * 2] >> (40 - (8 * i)));
            t[10 + i] = (uint8_t)(bip_keys[(s * 2) + 1] >> (40 - (8 * i)));
        }
    }

    // card 12345678, balance -1500 CLP, holder 7654321
    uint8_t *b = d + BIP_BLK(0, 1) + 4;
    b[0] = 0x4E;
    b[1] = 0x61;
    b[2] = 0xBC;
    b[3] = 0x00;
    b = d + BIP_BLK(8, 1);
    b[0] = 0xDC;
    b[1] = 0x05;
    b[3] = 0x01;
    b = d + BIP_BLK(3, 1) + 3;
    b[0] = 0xB1;
    b[1] = 0xCB;
    b[2] = 0x74;

    uint8_t *trip = d + BIP_BLK(11, 0);
    bip_set_timestamp(trip, 2023, 11, 28, 18, 45, 59);
    trip[8] = 0x45;
    transit_set_bits_le(trip, 16, 82, 16, 800);

    bool ok = true;
    ok &= transit_check("detected", is_valid_bip_card(d, sizeof(d)), true);
    ok &= transit_check("card number", MemLeToUint4byte(d + BIP_BLK(0, 1) + 4), 12345678);
    ok &= transit_check("balance, negated", (uint64_t)(-bip_balance(d)), 1500);
    ok &= transit_check("holder id", bip_holder_id(d), 7654321);
    ok &= transit_check("trip fare", transit_bits_le(trip, 16, 82, 16), 800);

    char s[64];
    bip_timestamp_str(trip, s, sizeof(s));
    ok &= transit_check_str("trip time", s, "2023-11-28 18:45:59");
    ok &= transit_check("parse", bip_parser_parse(d, sizeof(d)), PM3_SUCCESS);

    // one wrong key in sector 1 is still a Bip! card, both wrong is not
    d[BIP_BLK(1, 3)] ^= 0xFF;
    ok &= transit_check("sector 1 key B alone", is_valid_bip_card(d, sizeof(d)), true);
    d[BIP_BLK(1, 3) + 10] ^= 0xFF;
    ok &= transit_check("no sector 1 key", is_valid_bip_card(d, sizeof(d)), false);
    ok &= transit_check("short dump", is_valid_bip_card(d, 512), false);

    return transit_selftest_result("Bip!", ok);
}
