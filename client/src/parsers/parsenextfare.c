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
// Cubic Nextfare parser for MIFARE Classic dumps
//-----------------------------------------------------------------------------

#include "parsenextfare.h"

#include <stdio.h>
#include <string.h>

#include "commonutil.h"         // MemLeToUint2byte
#include "ui.h"                 // PrintAndLogEx
#include "util.h"               // sprint_hex_inrow
#include "parsetransit.h"

#define NF_DUMP_MIN             1024
#define NF_BLK(s, b)            ((((s) * 4) + (b)) * 16)
#define NF_MAX_TAPS             12

static const uint8_t nf_manufacturer[8] = { 0x16, 0x18, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
static const uint8_t nf_seqgo_code1[6] = { 0x5A, 0x5B, 0x20, 0x21, 0x22, 0x23 };
static const uint8_t nf_seqgo_code2[6] = { 0x20, 0x21, 0x22, 0x23, 0x01, 0x01 };
static const uint8_t nf_us_code[6] = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
static const uint8_t nf_msp_block2[16] = {
    0x3F, 0x33, 0x22, 0x11, 0xC0, 0xCC, 0xDD, 0xEE, 0x3F, 0x33, 0x22, 0x11, 0x01, 0xFE, 0x01, 0xFE
};

typedef enum {
    NF_UNKNOWN = 0,
    NF_SEQGO,
    NF_LAXTAP,
    NF_MSPGOTO,
} nf_system_t;

static bool nf_block1_match(const uint8_t *block1) {
    return (block1 != NULL) && (memcmp(block1 + 1, nf_manufacturer, sizeof(nf_manufacturer)) == 0);
}

bool is_valid_nextfare_card(const uint8_t *dump, size_t dumplen) {
    if (dump == NULL || dumplen < NF_DUMP_MIN) {
        return false;
    }
    return nf_block1_match(dump + NF_BLK(0, 1));
}

transit_id_t nextfare_identify(const transit_mfc_info_t *info) {
    return nf_block1_match(info->block1) ? TRANSIT_ID_MATCH : TRANSIT_ID_NONE;
}

static nf_system_t nf_system(const uint8_t *dump) {
    const uint8_t *code = dump + NF_BLK(0, 1) + 9;
    const uint8_t *b2 = dump + NF_BLK(0, 2);
    if (memcmp(code, nf_seqgo_code1, 6) == 0 || memcmp(code, nf_seqgo_code2, 6) == 0) {
        return NF_SEQGO;
    }
    if (memcmp(code, nf_us_code, 6) == 0) {
        if (memcmp(b2, nf_msp_block2, sizeof(nf_msp_block2)) == 0) {
            return NF_MSPGOTO;
        }
        if (transit_is_zero(b2, 4)) {
            return NF_LAXTAP;
        }
    }
    return NF_UNKNOWN;
}

// "0160 nnnn nnnn nnnL", eleven digit serial plus a Luhn digit
static void nf_serial_str(uint32_t serial, char *out, size_t outlen) {
    char digits[20];
    snprintf(digits, sizeof(digits), "0160%011u", serial);
    int sum = 0;
    size_t n = strlen(digits);
    for (size_t i = 0; i < n; i++) {
        int v = digits[n - 1 - i] - '0';
        if ((i & 1) == 0) {
            v *= 2;
            if (v > 9) {
                v -= 9;
            }
        }
        sum += v;
    }
    int check = (10 - (sum % 10)) % 10;
    snprintf(out, outlen, "%.4s %.4s %.4s %.3s%d", digits, digits + 4, digits + 8, digits + 12, check);
}

// Packed date: day 5 bits, month 4, year 7 from 2000, minute of day 11
static bool nf_date_str(const uint8_t *p, char *out, size_t outlen) {
    uint32_t ts = MemLeToUint4byte(p);
    unsigned day = ts & 0x1F;
    unsigned month = (ts >> 5) & 0x0F;
    unsigned year = ((ts >> 9) & 0x7F) + 2000;
    unsigned minute = (ts >> 16) & 0x7FF;
    if (minute > 1440 || month > 12) {
        snprintf(out, outlen, "invalid ( %08X )", ts);
        return false;
    }
    snprintf(out, outlen, "%04u-%02u-%02u %02u:%02u", year, month, day, minute / 60, minute % 60);
    return true;
}

typedef struct {
    uint8_t version;
    int32_t balance;
    bool travel_pass;
} nf_balance_t;

static void nf_read_balance(const uint8_t *b, nf_balance_t *r) {
    r->version = b[13];
    int32_t v = MemLeToUint2byte(b + 2);
    if (v & 0x8000) {
        v = -(v & 0x7FFF);
    } else if (b[1] & 0x80) {
        v = -v;
    }
    r->balance = v;
    r->travel_pass = (b[7] != 0);
}

typedef struct {
    uint8_t type;
    uint8_t mode;
    uint32_t ts;
    uint16_t journey;
    bool continuation;
    int32_t value;
    uint16_t station;
    const uint8_t *raw;
} nf_tap_t;

// False for an empty slot or one of the record types Metrodroid ignores
static bool nf_read_tap(const uint8_t *b, nf_tap_t *t) {
    if (b[0] == 0x71 || b[0] == 0x79 || b[0] == 0x89) {
        return false;
    }
    if (transit_is_zero(b + 1, 8)) {
        return false;
    }
    t->type = b[0];
    t->mode = b[1];
    t->ts = MemLeToUint4byte(b + 2);
    uint16_t j = MemLeToUint2byte(b + 5);
    t->journey = j >> 5;
    t->continuation = (j & 0x10) != 0;
    int32_t v = MemLeToUint2byte(b + 7);
    if (v > 0x8000) {
        v = -(v & 0x7FFF);
    }
    t->value = v;
    t->station = MemLeToUint2byte(b + 12);
    t->raw = b;
    return true;
}

static const char *nf_tap_type(uint8_t type) {
    switch (type) {
        case 0x05:
            return "travel pass trip";
        case 0x31:
            return "stored value trip";
        case 0x41:
            return "travel pass sale";
        default:
            return "unknown";
    }
}

static const char *nf_seqgo_ticket(uint16_t t) {
    switch (t) {
        case 0x000F:
            return "Adult Explore";
        case 0x0801:
        case 0x0C01:
            return "Adult";
        case 0x0803:
            return "Child";
        case 0x08A5:
            return "Concession";
        default:
            return "unknown";
    }
}

int nextfare_parser_parse(const uint8_t *dump, size_t dumplen) {
    if (is_valid_nextfare_card(dump, dumplen) == false) {
        return PM3_EINVARG;
    }

    nf_system_t sys = nf_system(dump);
    const char *title = "Nextfare - unknown system";
    const char *cur = "";
    switch (sys) {
        case NF_SEQGO:
            title = "Go card - Translink Brisbane";
            cur = "AUD";
            break;
        case NF_LAXTAP:
            title = "TAP - Los Angeles";
            cur = "USD";
            break;
        case NF_MSPGOTO:
            title = "Go-To card - Minneapolis";
            cur = "USD";
            break;
        case NF_UNKNOWN:
            break;
    }

    char s[64];
    transit_print_header(title);
    nf_serial_str(MemLeToUint4byte(dump), s, sizeof(s));
    transit_print_kv("Card number", _YELLOW_("%s"), s);
    transit_print_kv("System code", "%s", sprint_hex_inrow(dump + NF_BLK(0, 1) + 9, 6));

    // two balance records, the higher version is current except across the wrap
    nf_balance_t b0, b1;
    nf_read_balance(dump + NF_BLK(1, 0), &b0);
    nf_read_balance(dump + NF_BLK(1, 1), &b1);
    const nf_balance_t *hi = (b1.version > b0.version) ? &b1 : &b0;
    const nf_balance_t *lo = (hi == &b0) ? &b1 : &b0;
    const nf_balance_t *bal = (hi->version >= 240 && lo->version <= 10) ? lo : hi;
    transit_money_str(s, sizeof(s), bal->balance, 2, cur);
    transit_print_kv("Balance", _GREEN_("%s"), s);
    if (bal->travel_pass) {
        transit_print_kv("Travel pass", "available");
    }

    const uint8_t *cfg = dump + NF_BLK(1, 2);
    uint16_t ticket = MemLeToUint2byte(cfg + 8);
    if (sys == NF_SEQGO) {
        transit_print_kv("Ticket type", "0x%04X ( %s )", ticket, nf_seqgo_ticket(ticket));
    } else {
        transit_print_kv("Ticket type", "0x%04X", ticket);
    }
    nf_date_str(cfg + 4, s, sizeof(s));
    transit_print_kv("Expiry", "%s", s);

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Top ups, times local");
    for (uint8_t i = 0; i < 3; i++) {
        const uint8_t *b = dump + NF_BLK(2, i);
        if (transit_is_zero(b + 2, 6)) {
            continue;
        }
        char amt[32];
        nf_date_str(b + 2, s, sizeof(s));
        transit_money_str(amt, sizeof(amt), MemLeToUint2byte(b + 6) & 0x7FFF, 2, cur);
        PrintAndLogEx(INFO, "  %s  +%-12s  station %5u%s", s, amt, MemLeToUint2byte(b + 12),
                      (b[0] == 0x31) ? "  automatic" : "");
    }

    for (uint8_t i = 0; i < 3; i++) {
        const uint8_t *b = dump + NF_BLK(3, i);
        if (MemBeToUint4byte(b + 2) == 0 || b[13] == 0) {
            continue;
        }
        nf_date_str(b + 2, s, sizeof(s));
        PrintAndLogEx(INFO, "Travel pass, version %u, %s", b[13], s);
    }

    // taps, sectors 5..8, sorted by journey then time, newest first
    nf_tap_t taps[NF_MAX_TAPS];
    uint8_t n = 0;
    for (uint8_t sec = 5; sec <= 8; sec++) {
        for (uint8_t i = 0; i < 3 && n < NF_MAX_TAPS; i++) {
            if (nf_read_tap(dump + NF_BLK(sec, i), &taps[n])) {
                n++;
            }
        }
    }
    for (uint8_t i = 1; i < n; i++) {
        for (uint8_t j = i; j > 0; j--) {
            const nf_tap_t *a = &taps[j - 1], *c = &taps[j];
            bool newer = (c->journey != a->journey) ? (c->journey > a->journey) : (c->ts > a->ts);
            if (newer == false) {
                break;
            }
            nf_tap_t tmp = taps[j];
            taps[j] = taps[j - 1];
            taps[j - 1] = tmp;
        }
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Taps, times local");
    for (uint8_t i = 0; i < n; i++) {
        char amt[32];
        nf_date_str(taps[i].raw + 2, s, sizeof(s));
        transit_money_str(amt, sizeof(amt), -taps[i].value, 2, cur);
        PrintAndLogEx(INFO, "  %s  journey %4u%s  mode %3u  station %5u  %12s  %s", s,
                      taps[i].journey, taps[i].continuation ? "+" : " ", taps[i].mode,
                      taps[i].station, amt, nf_tap_type(taps[i].type));
    }
    return PM3_SUCCESS;
}

//-----------------------------------------------------------------------------
// Self test, Metrodroid NextfareTest vectors
//-----------------------------------------------------------------------------

int nextfare_selftest(void) {
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing Nextfare decode");

    bool ok = true;
    char s[64];

    static const uint8_t cfg[3][16] = {
        {0x01, 0x03, 0x00, 0x00, 0xC2, 0x32, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x0C},
        {0x01, 0x03, 0x00, 0x00, 0x39, 0x31, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x92, 0x4A},
        {0x01, 0x03, 0x00, 0x01, 0x0F, 0x25, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFB, 0x75, 0xC2, 0xF7},
    };
    static const char *expiry[3] = { "2025-06-02 00:00", "2024-09-25 00:00", "2018-08-15 00:00" };
    for (int i = 0; i < 3; i++) {
        nf_date_str(cfg[i] + 4, s, sizeof(s));
        ok &= transit_check_str("config expiry", s, expiry[i]);
    }

    static const uint8_t bal[3][16] = {
        {0x01, 0x28, 0xD2, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0xFF, 0xFF},
        {0x01, 0xA8, 0xE8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x23, 0xFF, 0xFF},
        {0x01, 0xA0, 0xE8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0xFF, 0xFF},
    };
    nf_balance_t r;
    nf_read_balance(bal[0], &r);
    ok &= transit_check("balance 12.34", (uint64_t)r.balance, 1234);
    ok &= transit_check("balance version", r.version, 0x12);
    nf_read_balance(bal[1], &r);
    ok &= transit_check("balance -10.00 negated", (uint64_t)(-r.balance), 1000);
    nf_read_balance(bal[2], &r);
    ok &= transit_check("balance -10.00 negated", (uint64_t)(-r.balance), 1000);

    static const uint8_t null_tap[16] = {0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x7F, 0x28};
    nf_tap_t t;
    ok &= transit_check("null transaction", nf_read_tap(null_tap, &t), false);

    nf_serial_str(123456789, s, sizeof(s));
    ok &= transit_check_str("Go card serial", s, "0160 0012 3456 7893");
    nf_serial_str(987654321, s, sizeof(s));
    ok &= transit_check_str("Go card serial", s, "0160 0098 7654 3213");
    nf_serial_str(0xC0CD0DC4, s, sizeof(s));
    ok &= transit_check_str("TAP serial", s, "0160 0323 4663 8769");

    // card as NextfareTest.buildNextfareCard makes it
    static uint8_t d[NF_DUMP_MIN];
    memset(d, 0, sizeof(d));
    memcpy(d, "\x15\xcd\x5b\x07", 4);
    memcpy(d + NF_BLK(0, 1) + 1, nf_manufacturer, sizeof(nf_manufacturer));
    memcpy(d + NF_BLK(0, 1) + 9, nf_seqgo_code1, 6);
    memcpy(d + NF_BLK(1, 0), bal[0], 16);
    memcpy(d + NF_BLK(1, 2), cfg[0], 16);
    ok &= transit_check("detected", is_valid_nextfare_card(d, sizeof(d)), true);
    ok &= transit_mfc_check_identify("identify", d, sizeof(d), "Nextfare", TRANSIT_ID_MATCH);
    ok &= transit_check("Go card system", nf_system(d), NF_SEQGO);
    ok &= transit_check("parse", nextfare_parser_parse(d, sizeof(d)), PM3_SUCCESS);

    memcpy(d + NF_BLK(0, 1) + 9, nf_us_code, 6);
    memcpy(d + NF_BLK(0, 2), nf_msp_block2, sizeof(nf_msp_block2));
    ok &= transit_check("Go-To system", nf_system(d), NF_MSPGOTO);
    memset(d + NF_BLK(0, 2), 0, 16);
    ok &= transit_check("TAP system", nf_system(d), NF_LAXTAP);
    memset(d + NF_BLK(0, 2), 0xFF, 16);
    ok &= transit_check("unknown system", nf_system(d), NF_UNKNOWN);

    d[NF_BLK(0, 1) + 1] ^= 0xFF;
    ok &= transit_mfc_check_identify("not identified", d, sizeof(d), "Nextfare", TRANSIT_ID_NONE);

    return transit_selftest_result("Nextfare", ok);
}
