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
// Ventra (Chicago) paper ticket parser for MIFARE Ultralight
//-----------------------------------------------------------------------------

#include "parseventra.h"

#include <stdio.h>
#include <string.h>

#include "commonutil.h"         // MemBeToUint4byte
#include "ui.h"                 // PrintAndLogEx
#include "parsetransit.h"

#define VENTRA_PAGE_SIZE        4
#define VENTRA_MIN_LEN          (16 * VENTRA_PAGE_SIZE)

// Two transaction records of four pages each
static const uint8_t ventra_txn_pages[] = { 8, 12 };

typedef struct {
    bool used;
    uint8_t type;
    uint16_t minutes;           // time of day
    uint8_t day;                // days before the base date
    uint8_t seq;
    uint16_t locus;             // stop or station
    uint8_t line;               // 0 purchase, 1 train, 2 bus
} ventra_txn_t;

static const uint8_t *ventra_page(const uint8_t *data, uint8_t page) {
    return data + (page * VENTRA_PAGE_SIZE);
}

bool is_valid_ventra_card(const uint8_t *data, size_t datalen) {
    if (data == NULL || datalen < VENTRA_MIN_LEN) {
        return false;
    }
    const uint8_t *p4 = ventra_page(data, 4);
    const uint8_t *p5 = ventra_page(data, 5);
    const uint8_t *p6 = ventra_page(data, 6);
    if (p4[0] != 0x0A || (p4[1] != 0x04 && p4[1] != 0x08) || p4[2] != 0x00) {
        return false;
    }
    if (p5[1] != 0x01 || (p5[2] & 0x80) || p5[3] != 0x00) {
        return false;
    }
    return (p6[0] == 0 && p6[1] == 0 && p6[2] == 0);
}

static int ventra_luhn(const char *s) {
    int sum = 0;
    size_t n = strlen(s);
    for (size_t i = 0; i < n; i++) {
        int d = s[n - 1 - i] - '0';
        if ((i & 1) == 0) {
            d *= 2;
            if (d > 9) {
                d -= 9;
            }
        }
        sum += d;
    }
    return (10 - (sum % 10)) % 10;
}

// UID based number as printed on the ticket, 20 digits in groups of four
static void ventra_serial_str(const uint8_t *data, char *out, size_t outlen) {
    uint64_t num = (((uint64_t)((data[1] << 8) | data[2]) << 32) | MemBeToUint4byte(data + 4)) + 1000000000000000ULL;
    char digits[24];
    snprintf(digits, sizeof(digits), "%" PRIu64, num);
    char f[24];
    snprintf(f, sizeof(f), "%019" PRIu64 "%d", num, ventra_luhn(digits));
    snprintf(out, outlen, "%.4s %.4s %.4s %.4s %.4s", f, f + 4, f + 8, f + 12, f + 16);
}

static int32_t ventra_base_days(const uint8_t *data) {
    uint16_t b = ventra_page(data, 4)[3] | (ventra_page(data, 5)[0] << 8);
    return transit_days_from_civil((b >> 9) + 2000, (b >> 5) & 0x0F, b & 0x1F);
}

static void ventra_read_txn(const uint8_t *data, uint8_t page, ventra_txn_t *t) {
    const uint8_t *p0 = ventra_page(data, page);
    const uint8_t *p1 = ventra_page(data, page + 1);
    const uint8_t *p2 = ventra_page(data, page + 2);
    uint16_t ts = p0[0] | (p0[1] << 8);
    uint32_t work = p1[0] | (p1[1] << 8) | ((uint32_t)p1[2] << 16);
    t->type = ts & 0x1F;
    t->minutes = (ts >> 5) & 0x7FF;
    t->day = p0[2];
    t->seq = work & 0x7F;
    t->locus = p2[1] | (p2[2] << 8);
    t->line = p2[3];
    t->used = (t->seq != 0);
}

static const char *ventra_product_str(uint8_t code, bool *is_pass) {
    *is_pass = true;
    switch (code) {
        case 0x02:
        case 0x1F:
            *is_pass = false;
            return "single ride ticket";
        case 0x03:
        case 0x3F:
            return "1-day pass";
        case 0x04:
            return "3-day pass";
        default:
            return "unknown pass";
    }
}

// OTP bits mark off the rides of a ticket
static int ventra_rides_left(uint8_t otp) {
    switch (otp) {
        case 0x00:
            return 3;
        case 0x02:
            return 2;
        case 0x06:
            return 1;
        case 0x0E:
        case 0x7E:
            return 0;
        default:
            return -1;
    }
}

static void ventra_print_txn(const ventra_txn_t *t, int32_t base) {
    static const char line_names[] = "PTB";
    char when[32];
    transit_datetime_str(when, sizeof(when), (((int64_t)base - t->day) * 86400) + ((int64_t)t->minutes * 60));
    when[16] = '\0';
    char line = (t->line < 3) ? line_names[t->line] : '?';
    if (t->line == 2) {
        PrintAndLogEx(INFO, "  seq %3u  %s  %c  stop %5u  type %u", t->seq, when, line, t->locus, t->type);
    } else {
        PrintAndLogEx(INFO, "  seq %3u  %s  %c  stop %04X   type %u", t->seq, when, line, t->locus, t->type);
    }
}

int ventra_parser_parse(const uint8_t *data, size_t datalen) {

    if (is_valid_ventra_card(data, datalen) == false) {
        return PM3_EINVARG;
    }

    bool is_pass;
    const char *product = ventra_product_str(ventra_page(data, 5)[2], &is_pass);
    int32_t base = ventra_base_days(data);
    char buf[40];

    transit_print_header("Ventra");
    transit_print_kv("Issuer", "Chicago Transit Authority");
    ventra_serial_str(data, buf, sizeof(buf));
    transit_print_kv("Serial", _YELLOW_("%s"), buf);
    transit_print_kv("Product", "%s ( %02X )", product, ventra_page(data, 5)[2]);
    transit_date_str(buf, sizeof(buf), base);
    transit_print_kv("Expiry", "%s", buf);
    if (is_pass == false) {
        int left = ventra_rides_left(ventra_page(data, 3)[0]);
        if (left >= 0) {
            transit_print_kv("Rides left", "%d", left);
        } else {
            transit_print_kv("Rides left", "unknown, OTP %02X", ventra_page(data, 3)[0]);
        }
    }
    transit_print_kv("TVM id", "%02X%02X", ventra_page(data, 7)[1], ventra_page(data, 7)[0]);

    ventra_txn_t t[ARRAYLEN(ventra_txn_pages)];
    uint8_t high = 0;
    for (size_t i = 0; i < ARRAYLEN(ventra_txn_pages); i++) {
        ventra_read_txn(data, ventra_txn_pages[i], &t[i]);
        if (t[i].seq > high) {
            high = t[i].seq;
        }
    }
    transit_print_kv("Transactions", "%u", high);

    transit_print_header("Ventra transactions, newest first");
    bool first_newer = (t[0].seq >= t[1].seq);
    for (size_t i = 0; i < 2; i++) {
        const ventra_txn_t *x = first_newer ? &t[i] : &t[1 - i];
        if (x->used) {
            ventra_print_txn(x, base);
        }
    }
    return PM3_SUCCESS;
}

int ventra_selftest(void) {

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing Ventra decode");

    // synthetic single ride ticket, expiry 2024-05-19, one train ride
    uint8_t data[20 * VENTRA_PAGE_SIZE] = {
        0x04, 0x12, 0x34, 0x00, 0x56, 0x78, 0x9A, 0xBC,
    };
    uint16_t b = (24 << 9) | (5 << 5) | 19;
    uint8_t *p = data;
    p[3 * 4] = 0x02;                                    // one ride used
    p[4 * 4] = 0x0A;
    p[4 * 4 + 1] = 0x04;
    p[4 * 4 + 3] = b & 0xFF;
    p[5 * 4] = b >> 8;
    p[5 * 4 + 1] = 0x01;
    p[5 * 4 + 2] = 0x02;
    p[7 * 4] = 0x34;
    p[7 * 4 + 1] = 0x12;
    uint16_t ts = ((8 * 60 + 30) << 5) | 1;             // 08:30
    p[8 * 4] = ts & 0xFF;
    p[8 * 4 + 1] = ts >> 8;
    p[8 * 4 + 2] = 3;                                   // three days before expiry
    p[9 * 4] = 0x02;                                    // seq 2
    p[10 * 4 + 1] = 0x2A;
    p[10 * 4 + 3] = 1;                                  // train

    bool ok = true;
    ok &= transit_check("detected", is_valid_ventra_card(data, sizeof(data)), true);
    char buf[40];
    transit_date_str(buf, sizeof(buf), ventra_base_days(data));
    ok &= transit_check_str("expiry", buf, "2024-05-19");
    ventra_txn_t t;
    ventra_read_txn(data, 8, &t);
    ok &= transit_check("seq", t.seq, 2);
    ok &= transit_check("minutes", t.minutes, 510);
    ok &= transit_check("locus", t.locus, 0x2A);
    ok &= transit_check("rides left", (uint64_t)ventra_rides_left(data[12]), 2);

    // Luhn of 308425 1234 5678 from the myki vector is 0
    ok &= transit_check("luhn", (uint64_t)ventra_luhn("30842512345678"), 0);
    ventra_serial_str(data, buf, sizeof(buf));
    // uid 123456789ABC + 10^15, Luhn digit 1
    ok &= transit_check_str("serial", buf, "0001 0200 1599 8343 8681");
    if (ok) {
        ventra_parser_parse(data, sizeof(data));
    }

    p[4 * 4] = 0x0B;
    ok &= transit_check("other header rejected", is_valid_ventra_card(data, sizeof(data)), false);

    return transit_selftest_result("Ventra", ok);
}
