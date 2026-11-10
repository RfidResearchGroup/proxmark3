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
// Zolotaya Korona transport card parser for MIFARE Classic dumps
//-----------------------------------------------------------------------------

#include "parsezolotayakorona.h"

#include <stdio.h>
#include <string.h>

#include "commonutil.h"             // ARRAYLEN, MemLeToUint4byte
#include "ui.h"                     // PrintAndLogEx
#include "util.h"                   // sprint_hex_inrow
#include "parsetransit.h"
#include "parsetransitmfc.h"

#define ZK_TRIP_SECTOR          4
#define ZK_PURSE_SECTOR         6
#define ZK_INFO_SECTOR          15
#define ZK_MAD_AID_HI           0x18
#define ZK_MAD_AID_LO           0xEE

// Sector 15 blocks 0..1, "ZAO Zolotaya Korona" in CP866 with one byte off
static const uint8_t zk_signature[] = {
    0xE2, 0x87, 0x80, 0x8E, 0x20, 0x87, 0xAE, 0xAB, 0xAE, 0xF2, 0xA0, 0xEF, 0x20, 0x8A, 0xAE, 0xE0,
    0xAE, 0xAD, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

typedef struct {
    uint32_t type;
    const char *name;
} zk_card_t;

static const zk_card_t zk_cards[] = {
    { 0x230100, "Krasnodar ETK" },
    { 0x560200, "Orenburg EKG" },
    { 0x562300, "Orenburg school card" },
    { 0x562400, "Orenburg student card" },
    { 0x631500, "Samara school card" },
    { 0x632600, "Samara ETK" },
    { 0x632700, "Samara student card" },
    { 0x633500, "Samara garden dacha card" },
    { 0x760500, "Yaroslavl ETK" },
};

typedef struct {
    uint32_t type;
    int32_t balance;            // kopecks
    uint8_t status;
    uint16_t seqno;
    uint8_t discount;

    bool has_refill;
    uint16_t refill_machine;
    uint32_t refill_time;       // local pseudo unix time
    uint32_t refill_amount;
    uint16_t refill_counter;

    bool has_trip;
    uint32_t trip_validator;    // printed as hex
    uint32_t trip_time;
    uint8_t trip_track;
    uint32_t trip_prev_balance;
} zk_t;

static uint32_t zk_le(const uint8_t *p, uint8_t n) {
    uint32_t v = 0;
    for (uint8_t i = n; i > 0; i--) {
        v = (v << 8) | p[i - 1];
    }
    return v;
}

static bool zk_has_signature(const uint8_t *dump, size_t dumplen) {
    const uint8_t *b0 = transit_mfc_block(dump, dumplen, ZK_INFO_SECTOR, 0);
    const uint8_t *b1 = transit_mfc_block(dump, dumplen, ZK_INFO_SECTOR, 1);
    if (b0 == NULL || b1 == NULL) {
        return false;
    }
    return (memcmp(b0, zk_signature, 16) == 0) && (memcmp(b1, zk_signature + 16, sizeof(zk_signature) - 16) == 0);
}

static bool zk_has_mad(const uint8_t *dump, size_t dumplen) {
    const uint8_t *toc = transit_mfc_block(dump, dumplen, 0, 1);
    if (toc == NULL) {
        return false;
    }
    return toc[8] == ZK_MAD_AID_HI && toc[9] == ZK_MAD_AID_LO && toc[12] == ZK_MAD_AID_HI && toc[13] == ZK_MAD_AID_LO;
}

bool is_valid_zolotayakorona_card(const uint8_t *dump, size_t dumplen) {
    if (transit_mfc_block(dump, dumplen, ZK_INFO_SECTOR, 3) == NULL) {
        return false;
    }
    return zk_has_signature(dump, dumplen) || zk_has_mad(dump, dumplen);
}

static void zk_decode(const uint8_t *dump, size_t dumplen, zk_t *z) {
    memset(z, 0, sizeof(*z));

    const uint8_t *b = transit_mfc_block(dump, dumplen, ZK_INFO_SECTOR, 1);
    z->type = ((uint32_t)b[10] << 16) | ((uint32_t)b[11] << 8) | b[12];

    z->balance = (int32_t)MemLeToUint4byte(transit_mfc_block(dump, dumplen, ZK_PURSE_SECTOR, 0));

    b = transit_mfc_block(dump, dumplen, ZK_TRIP_SECTOR, 0);
    z->status = (uint8_t)transit_bits_be(b, 16, 60, 4);
    z->seqno = (uint16_t)((b[8] << 8) | b[9]);
    z->discount = b[10];

    b = transit_mfc_block(dump, dumplen, ZK_TRIP_SECTOR, 1);
    if (transit_is_zero(b, 16) == false) {
        z->has_refill = true;
        // high bits of the machine id are not on the card
        z->refill_machine = (uint16_t)zk_le(b + 1, 2);
        z->refill_time = zk_le(b + 3, 4);
        z->refill_amount = zk_le(b + 7, 4);
        z->refill_counter = (uint16_t)zk_le(b + 11, 2);
    }

    b = transit_mfc_block(dump, dumplen, ZK_TRIP_SECTOR, 2);
    if (transit_is_zero(b, 16) == false) {
        z->has_trip = true;
        z->trip_validator = ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 8) | b[4];
        z->trip_time = zk_le(b + 6, 4);
        z->trip_track = b[10];
        z->trip_prev_balance = zk_le(b + 11, 4);
    }
}

// Sector 15 block 2 bytes 4..13 as hex, first 19 digits grouped 4 5 5 5
static void zk_serial_str(char *out, size_t outlen, const uint8_t *b) {
    char h[24];
    snprintf(h, sizeof(h), "%s", sprint_hex_inrow(b + 4, 10));
    snprintf(out, outlen, "%.4s %.5s %.5s %.5s", h, h + 4, h + 9, h + 14);
}

static const char *zk_card_name(uint32_t type) {
    for (size_t i = 0; i < ARRAYLEN(zk_cards); i++) {
        if (zk_cards[i].type == type) {
            return zk_cards[i].name;
        }
    }
    return "unknown";
}

int zolotayakorona_parser_parse(const uint8_t *dump, size_t dumplen) {
    if (is_valid_zolotayakorona_card(dump, dumplen) == false) {
        return PM3_EINVARG;
    }

    zk_t z;
    zk_decode(dump, dumplen, &z);

    char buf[64];
    transit_print_header("Zolotaya Korona");
    transit_print_kv("Card type", "%06X  ( %s )", z.type, zk_card_name(z.type));
    transit_print_kv("Region", "%02X", (z.type >> 16) & 0xFF);
    zk_serial_str(buf, sizeof(buf), transit_mfc_block(dump, dumplen, ZK_INFO_SECTOR, 2));
    transit_print_kv("Card number", _YELLOW_("%s"), buf);
    transit_print_kv("Card serial", "%s", sprint_hex_inrow(dump, 4));
    transit_money_str(buf, sizeof(buf), z.balance, 2, "RUB");
    transit_print_kv("Balance", _YELLOW_("%s"), buf);
    transit_print_kv("Discount", "%02X", z.discount);
    transit_print_kv("Status", "%u, issue seqno %u", z.status, z.seqno);

    if (z.has_trip && z.trip_time != 0) {
        char prev[24];
        transit_datetime_str(buf, sizeof(buf), z.trip_time);
        transit_money_str(prev, sizeof(prev), z.trip_prev_balance, 2, "RUB");
        transit_print_kv("Last trip", "%s  validator %06X, track %u, balance before %s", buf,
                         z.trip_validator, z.trip_track, prev);
    }
    if (z.has_refill && z.refill_time != 0) {
        char amount[24];
        transit_datetime_str(buf, sizeof(buf), z.refill_time);
        transit_money_str(amount, sizeof(amount), z.refill_amount, 2, "RUB");
        transit_print_kv("Last refill", "%s  %s, machine %u", buf, amount, z.refill_machine);
    }
    transit_print_kv("Refill counter", "%u", z.has_refill ? z.refill_counter : 0);
    PrintAndLogEx(INFO, "Times are local time of the region");
    return PM3_SUCCESS;
}

// Synthetic card built from the Metrodroid layout
int zolotayakorona_selftest(void) {
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing Zolotaya Korona decode");

    uint8_t dump[1024] = {0};
    uint8_t *s15 = dump + (60 * 16);
    memcpy(s15, zk_signature, sizeof(zk_signature));
    s15[16 + 10] = 0x76;
    s15[16 + 11] = 0x05;
    s15[16 + 12] = 0x00;
    const uint8_t sn[] = { 0x96, 0x43, 0x07, 0x60, 0x50, 0x01, 0x23, 0x45, 0x67, 0x89 };
    memcpy(s15 + 32 + 4, sn, sizeof(sn));

    const uint8_t purse[] = { 0x10, 0x27, 0x00, 0x00 };
    memcpy(dump + (24 * 16), purse, sizeof(purse));

    uint8_t *s4 = dump + (16 * 16);
    s4[7] = 0x03;
    s4[8] = 0x00;
    s4[9] = 0x05;
    s4[10] = 0x47;
    // refill of 200.00 at 1700000000, counter 3, machine 0x0102
    const uint8_t refill[] = { 0x00, 0x02, 0x01, 0x00, 0xF1, 0x53, 0x65, 0x20, 0x4E, 0x00, 0x00, 0x03, 0x00 };
    memcpy(s4 + 16, refill, sizeof(refill));
    // trip at 1700003600, validator 123456, balance before 115.00
    const uint8_t trip[] = { 0x00, 0x00, 0x12, 0x34, 0x56, 0x00, 0x10, 0xFF, 0x53, 0x65, 0x07, 0xEC, 0x2C, 0x00, 0x00 };
    memcpy(s4 + 32, trip, sizeof(trip));

    bool ok = transit_check("detected by signature", is_valid_zolotayakorona_card(dump, sizeof(dump)), 1);

    zk_t z;
    zk_decode(dump, sizeof(dump), &z);
    ok &= transit_check("card type", z.type, 0x760500);
    ok &= transit_check("balance", (uint64_t)z.balance, 10000);
    ok &= transit_check("status", z.status, 3);
    ok &= transit_check("issue seqno", z.seqno, 5);
    ok &= transit_check("discount", z.discount, 0x47);
    ok &= transit_check("refill time", z.refill_time, 1700000000);
    ok &= transit_check("refill amount", z.refill_amount, 20000);
    ok &= transit_check("refill counter", z.refill_counter, 3);
    ok &= transit_check("refill machine", z.refill_machine, 0x0102);
    ok &= transit_check("trip validator", z.trip_validator, 0x123456);
    ok &= transit_check("trip time", z.trip_time, 1700003600);
    ok &= transit_check("trip track", z.trip_track, 7);
    ok &= transit_check("balance before", z.trip_prev_balance, 11500);

    char buf[32];
    zk_serial_str(buf, sizeof(buf), s15 + 32);
    ok &= transit_check_str("card number", buf, "9643 07605 00123 45678");

    s15[11] ^= 0x01;
    ok &= transit_check("bad signature rejected", is_valid_zolotayakorona_card(dump, sizeof(dump)), 0);
    dump[16 + 8] = ZK_MAD_AID_HI;
    dump[16 + 9] = ZK_MAD_AID_LO;
    dump[16 + 12] = ZK_MAD_AID_HI;
    dump[16 + 13] = ZK_MAD_AID_LO;
    ok &= transit_check("detected by MAD", is_valid_zolotayakorona_card(dump, sizeof(dump)), 1);

    return transit_selftest_result("Zolotaya Korona", ok);
}
