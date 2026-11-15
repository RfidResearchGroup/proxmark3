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
// TRT, Tianjin Railway Transit single ticket parser for MIFARE Ultralight
//-----------------------------------------------------------------------------

#include "parsetrt.h"

#include <stdio.h>
#include <string.h>

#include "commonutil.h"         // MemBeToUint2byte
#include "ui.h"                 // PrintAndLogEx
#include "parsetransit.h"

#define TRT_PAGE_SIZE           4
#define TRT_PAGE_BALANCE        0x08
#define TRT_PAGE_SALE_FULL      0x09
#define TRT_PAGE_SALE_A         0x0C
#define TRT_PAGE_SALE_B         0x0E
#define TRT_SALE_MARKER         0x02
#define TRT_MIN_LEN             ((TRT_PAGE_SALE_B + 1) * TRT_PAGE_SIZE)

// NDEF capability container, never on a ticket
#define TRT_NDEF_CC_MAGIC       0xE1

typedef struct {
    uint16_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint16_t balance;           // fen
} trt_ticket_t;

// Latest sale is kept twice, the short copy right before the marker page
static bool trt_decode(const uint8_t *data, size_t datalen, trt_ticket_t *t) {
    if (data == NULL || datalen < TRT_MIN_LEN || data[3 * TRT_PAGE_SIZE] == TRT_NDEF_CC_MAGIC) {
        return false;
    }

    uint8_t page;
    if (data[TRT_PAGE_SALE_A * TRT_PAGE_SIZE] == TRT_SALE_MARKER) {
        page = TRT_PAGE_SALE_A;
    } else if (data[TRT_PAGE_SALE_B * TRT_PAGE_SIZE] == TRT_SALE_MARKER) {
        page = TRT_PAGE_SALE_B;
    } else {
        return false;
    }

    // yyyyyyy mmmm ddddd hhhhh nnnnnn
    uint32_t part = (uint32_t)transit_bits_be(data, datalen, ((page - 1) * TRT_PAGE_SIZE * 8) + 3, 20);
    uint32_t full = (uint32_t)transit_bits_be(data, datalen, TRT_PAGE_SALE_FULL * TRT_PAGE_SIZE * 8, 27);
    if (part == 0 || full == 0 || part != (full & 0xFFFFF)) {
        return false;
    }

    t->year    = ((full >> 20) & 0x7F) + 2000;
    t->month   = (full >> 16) & 0x0F;
    t->day     = (full >> 11) & 0x1F;
    t->hour    = (full >> 6) & 0x1F;
    t->minute  = full & 0x3F;
    t->balance = MemBeToUint2byte(data + (TRT_PAGE_BALANCE * TRT_PAGE_SIZE) + 2);

    return (t->month >= 1 && t->month <= 12 && t->day >= 1 && t->hour < 24 && t->minute < 60);
}

bool is_valid_trt_card(const uint8_t *data, size_t datalen) {
    trt_ticket_t t;
    return trt_decode(data, datalen, &t);
}

int trt_parser_parse(const uint8_t *data, size_t datalen) {

    trt_ticket_t t;
    if (trt_decode(data, datalen, &t) == false) {
        return PM3_EINVARG;
    }

    char buf[24];
    transit_print_header("TRT Tianjin Metro");
    transit_print_kv("Type", "single use ticket");
    transit_money_str(buf, sizeof(buf), t.balance, 2, "CNY");
    transit_print_kv("Balance", _GREEN_("%s"), buf);
    transit_print_kv("Sold", "%04u-%02u-%02u %02u:%02u", t.year, t.month, t.day, t.hour, t.minute);
    return PM3_SUCCESS;
}

int trt_selftest(void) {

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing TRT decode");

    // synthetic ticket, 2.00 CNY sold 2024-05-19 13:45
    uint8_t data[20 * TRT_PAGE_SIZE] = {0};
    uint32_t full = (24U << 20) | (5U << 16) | (19U << 11) | (13U << 6) | 45U;
    transit_set_bits_be(data, sizeof(data), TRT_PAGE_SALE_FULL * 32, 27, full);
    transit_set_bits_be(data, sizeof(data), ((TRT_PAGE_SALE_A - 1) * 32) + 3, 20, full & 0xFFFFF);
    data[TRT_PAGE_SALE_A * TRT_PAGE_SIZE] = TRT_SALE_MARKER;
    data[(TRT_PAGE_BALANCE * TRT_PAGE_SIZE) + 3] = 200;

    bool ok = true;
    trt_ticket_t t = {0};
    ok &= transit_check("decoded", trt_decode(data, sizeof(data), &t), true);
    ok &= transit_check("year", t.year, 2024);
    ok &= transit_check("month", t.month, 5);
    ok &= transit_check("day", t.day, 19);
    ok &= transit_check("hour", t.hour, 13);
    ok &= transit_check("minute", t.minute, 45);
    ok &= transit_check("balance", t.balance, 200);
    ok &= transit_mfu_check_identify("identify", data, sizeof(data), "TRT", TRANSIT_ID_POSSIBLE);
    if (ok) {
        trt_parser_parse(data, sizeof(data));
    }

    ok &= transit_check("short dump rejected", is_valid_trt_card(data, TRT_MIN_LEN - 1), false);
    data[(TRT_PAGE_SALE_A - 1) * TRT_PAGE_SIZE] ^= 0x01;
    ok &= transit_check("copy mismatch rejected", is_valid_trt_card(data, sizeof(data)), false);
    data[(TRT_PAGE_SALE_A - 1) * TRT_PAGE_SIZE] ^= 0x01;
    data[3 * TRT_PAGE_SIZE] = TRT_NDEF_CC_MAGIC;
    ok &= transit_check("NDEF tag rejected", is_valid_trt_card(data, sizeof(data)), false);
    ok &= transit_mfu_check_identify("not identified", data, sizeof(data), "TRT", TRANSIT_ID_NONE);

    return transit_selftest_result("TRT", ok);
}
