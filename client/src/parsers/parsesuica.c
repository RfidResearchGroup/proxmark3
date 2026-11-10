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
// Japan IC transit card parser for FeliCa dumps
//-----------------------------------------------------------------------------

#include "parsesuica.h"

#include <stdio.h>
#include <string.h>

#include "commonutil.h"         // ARRAYLEN
#include "ui.h"                 // PrintAndLogEx
#include "util.h"               // sprint_hex_inrow

#define SUICA_BLOCK_SIZE        16
#define SUICA_CONSOLE_BUS       0x05
#define SUICA_PROCESS_CHARGE    0x02

//-----------------------------------------------------------------------------
// Card identification by service codes >= 0x1800, Metrodroid SuicaUtil
//-----------------------------------------------------------------------------

typedef struct {
    const char *name;
    const uint16_t *codes;
    size_t count;
} suica_issuer_t;

static const uint16_t suica_hayakaken[] = {
    0x1f88, 0x1f8a, 0x2048, 0x204a, 0x2448, 0x244a, 0x2488, 0x248a, 0x24c8, 0x24ca, 0x2508,
    0x250a, 0x2548, 0x254a
};
static const uint16_t suica_icoca[] = { 0x1a48, 0x1a4a, 0x1a88, 0x1a8a, 0x9608, 0x960a };
static const uint16_t suica_kitaca[] = {
    0x1848, 0x184b, 0x2088, 0x208b, 0x20c8, 0x20cb, 0x2108, 0x210b, 0x2148, 0x214b, 0x2188,
    0x218b
};
static const uint16_t suica_manaca[] = {
    0x9888, 0x988b, 0x98cc, 0x98cf, 0x9908, 0x990a, 0x9948, 0x994a, 0x9988, 0x998b
};
static const uint16_t suica_nimoca[] = {
    0x1f48, 0x1f4a, 0x1f88, 0x1f8a, 0x1fc8, 0x1fca, 0x2008, 0x200a, 0x2048, 0x204a
};
static const uint16_t suica_pasmo[] = {
    0x1848, 0x184b, 0x1908, 0x190a, 0x1948, 0x194b, 0x1988, 0x198b, 0x1cc8, 0x1cca, 0x1d08,
    0x1d0a, 0x2308, 0x230a, 0x2348, 0x234b, 0x2388, 0x238b, 0x23c8, 0x23cb
};
static const uint16_t suica_pitapa[] = { 0x1b88, 0x1b8a, 0x9748, 0x974a };
static const uint16_t suica_sugoca[] = {
    0x1f88, 0x1f8a, 0x2048, 0x204b, 0x21c8, 0x21cb, 0x2208, 0x220a, 0x2248, 0x224a, 0x2288,
    0x228a
};
static const uint16_t suica_suica[] = {
    0x1808, 0x180a, 0x1848, 0x184b, 0x18c8, 0x18ca, 0x1908, 0x190a, 0x1948, 0x194b, 0x1988,
    0x198b, 0x2308, 0x230a, 0x2348, 0x234b, 0x2388, 0x238b, 0x23c8, 0x23cb
};
static const uint16_t suica_toica[] = {
    0x1848, 0x184b, 0x1e08, 0x1e0a, 0x1e48, 0x1e4a, 0x1e88, 0x1e8a, 0x1e8b, 0x1ecc, 0x1ecf
};

static const suica_issuer_t suica_issuers[] = {
    { "Hayakaken", suica_hayakaken, ARRAYLEN(suica_hayakaken) },
    { "ICOCA", suica_icoca, ARRAYLEN(suica_icoca) },
    { "Kitaca", suica_kitaca, ARRAYLEN(suica_kitaca) },
    { "manaca", suica_manaca, ARRAYLEN(suica_manaca) },
    { "nimoca", suica_nimoca, ARRAYLEN(suica_nimoca) },
    { "PASMO", suica_pasmo, ARRAYLEN(suica_pasmo) },
    { "PiTaPa", suica_pitapa, ARRAYLEN(suica_pitapa) },
    { "SUGOCA", suica_sugoca, ARRAYLEN(suica_sugoca) },
    { "Suica", suica_suica, ARRAYLEN(suica_suica) },
    { "TOICA", suica_toica, ARRAYLEN(suica_toica) },
};

static bool suica_in_list(const uint16_t *codes, size_t count, uint16_t code) {
    for (size_t i = 0; i < count; i++) {
        if (codes[i] == code) {
            return true;
        }
    }
    return false;
}

// A code counts for an issuer only when no other issuer lists it
static bool suica_code_unique_to(size_t issuer, uint16_t code) {
    for (size_t j = 0; j < ARRAYLEN(suica_issuers); j++) {
        if (j != issuer && suica_in_list(suica_issuers[j].codes, suica_issuers[j].count, code)) {
            return false;
        }
    }
    return true;
}

// Exactly one issuer must match, otherwise the generic name
static const char *suica_card_name(const uint16_t *codes, size_t count) {
    const char *found = NULL;
    for (size_t i = 0; i < ARRAYLEN(suica_issuers); i++) {
        bool hit = false;
        for (size_t k = 0; k < count && hit == false; k++) {
            hit = suica_in_list(suica_issuers[i].codes, suica_issuers[i].count, codes[k]) &&
                  suica_code_unique_to(i, codes[k]);
        }
        if (hit) {
            if (found != NULL) {
                return "Japan IC";
            }
            found = suica_issuers[i].name;
        }
    }
    return (found != NULL) ? found : "Japan IC";
}

//-----------------------------------------------------------------------------
// Names, Metrodroid SuicaUtil after felicalib
//-----------------------------------------------------------------------------

static const char *suica_console_name(uint8_t c) {
    switch (c) {
        case 0x03:
            return "Fare adjustment";
        case 0x04:
            return "Portable terminal";
        case 0x05:
            return "Bus";
        case 0x07:
        case 0x08:
            return "Ticket machine";
        case 0x09:
            return "Quick refill";
        case 0x12:
            return "Monorail TVM";
        case 0x13:
        case 0x14:
        case 0x15:
            return "TVM";
        case 0x16:
            return "Turnstile";
        case 0x17:
            return "Ticket validator";
        case 0x18:
            return "Ticket booth";
        case 0x19:
            return "Green window";
        case 0x1A:
            return "Gate terminal";
        case 0x1B:
            return "Mobile phone";
        case 0x1C:
            return "Connection adj.";
        case 0x1D:
            return "Transfer adj.";
        case 0x1F:
            return "Simple deposit";
        case 0x46:
        case 0x48:
            return "VIEW ALTTE";
        case 0xC7:
            return "POS";
        case 0xC8:
            return "Vending machine";
        default:
            return "?";
    }
}

static const char *suica_process_name(uint8_t p) {
    switch (p) {
        case 0x01:
            return "Exit turnstile";
        case 0x02:
            return "Refill";
        case 0x03:
            return "Magnetic ticket";
        case 0x04:
            return "Fare adjustment";
        case 0x05:
            return "Admission payment";
        case 0x06:
            return "Booth exit";
        case 0x07:
            return "New issue";
        case 0x08:
            return "Booth payment";
        case 0x0D:
            return "Bus (PiTaPa)";
        case 0x0F:
            return "Bus (IruCa)";
        case 0x11:
            return "Re-issue";
        case 0x13:
            return "Shinkansen payment";
        case 0x14:
            return "Entry, autorefill";
        case 0x15:
            return "Exit, autorefill";
        case 0x1F:
            return "Bus deposit";
        case 0x23:
            return "Special ticket";
        case 0x46:
            return "Purchase";
        case 0x48:
            return "Bonus refill";
        case 0x49:
            return "Register refill";
        case 0x4A:
            return "Cancel purchase";
        case 0x4B:
            return "Purchase/admission";
        case 0x84:
            return "Payment, 3rd party";
        case 0x85:
            return "Admission, 3rd party";
        case 0xC6:
            return "Purchase, part cash";
        case 0xCB:
            return "Admission, part cash";
        default:
            return "?";
    }
}

//-----------------------------------------------------------------------------
// History record, service 090F, newest first
//-----------------------------------------------------------------------------

typedef struct {
    uint8_t console;
    uint8_t process;
    bool used;
    bool sale;
    uint16_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint16_t from;
    uint16_t to;
    uint16_t balance;
    uint8_t region;
} suica_trip_t;

static bool suica_is_tvm(uint8_t c) {
    return (c == 0x03 || c == 0x07 || c == 0x08 || c == 0x12 || c == 0x13 || c == 0x14 || c == 0x15);
}

static void suica_read_trip(const uint8_t *d, suica_trip_t *t) {
    memset(t, 0, sizeof(*t));
    t->console = d[0];
    t->process = d[1];
    t->used = (MemBeToUint2byte(d + 4) != 0);
    t->sale = (t->console == 0xC7 || t->console == 0xC8);
    t->year = 2000 + (uint16_t)transit_bits_be(d, SUICA_BLOCK_SIZE, 32, 7);
    t->month = (uint8_t)transit_bits_be(d, SUICA_BLOCK_SIZE, 39, 4);
    t->day = (uint8_t)transit_bits_be(d, SUICA_BLOCK_SIZE, 43, 5);
    if (t->sale) {
        t->hour = (uint8_t)transit_bits_be(d, SUICA_BLOCK_SIZE, 48, 5);
        t->minute = (uint8_t)transit_bits_be(d, SUICA_BLOCK_SIZE, 53, 6);
    }
    // line << 8 | station for rail, line and stop numbers for bus
    t->from = MemBeToUint2byte(d + 6);
    t->to = MemBeToUint2byte(d + 8);
    t->balance = MemLeToUint2byte(d + 10);
    t->region = d[15];
}

static void suica_print_trip(uint16_t idx, const suica_trip_t *t, const suica_trip_t *older) {
    char date[24];
    if (t->sale) {
        snprintf(date, sizeof(date), "%04u-%02u-%02u %02u:%02u", t->year, t->month, t->day, t->hour, t->minute);
    } else {
        snprintf(date, sizeof(date), "%04u-%02u-%02u", t->year, t->month, t->day);
    }

    // no stations for sales and refills, one for bus and ticket machines
    char from[8] = "", to[8] = "";
    if (t->sale == false && t->process != SUICA_PROCESS_CHARGE) {
        snprintf(from, sizeof(from), "%04X", t->from);
        if (t->console != SUICA_CONSOLE_BUS && suica_is_tvm(t->console) == false) {
            snprintf(to, sizeof(to), "%04X", t->to);
        }
    }

    char fare[24] = "";
    if (older != NULL) {
        transit_money_str(fare, sizeof(fare), (int64_t)older->balance - t->balance, 0, NULL);
    }
    char bal[24];
    transit_money_str(bal, sizeof(bal), t->balance, 0, NULL);

    PrintAndLogEx(INFO, " %2u | %-16s | %-17s | %-20s | %-4s | %-4s | %6s | %6s",
                  idx, date, suica_console_name(t->console), suica_process_name(t->process),
                  from, to, fare, bal);
}

//-----------------------------------------------------------------------------
// Detection and printing
//-----------------------------------------------------------------------------

static const transit_felica_service_t *suica_history(const transit_felica_card_t *card) {
    const transit_felica_system_t *sys = transit_felica_find_system(card, SUICA_SYSTEM_CODE);
    return transit_felica_find_service(sys, SUICA_SERVICE_HISTORY);
}

bool is_valid_suica_card(const transit_felica_card_t *card) {
    const transit_felica_service_t *h = suica_history(card);
    return (h != NULL && h->block_count > 0);
}

int suica_parser_parse(const transit_felica_card_t *card) {

    if (is_valid_suica_card(card) == false) {
        return PM3_EINVARG;
    }

    const transit_felica_system_t *sys = transit_felica_find_system(card, SUICA_SYSTEM_CODE);
    const transit_felica_service_t *h = suica_history(card);

    uint16_t codes[256];
    size_t ncodes = 0;
    for (size_t i = 0; i < sys->service_count && ncodes < ARRAYLEN(codes); i++) {
        codes[ncodes++] = sys->services[i].code;
    }

    transit_print_header("Japan IC transit card");
    transit_print_kv("Card", _YELLOW_("%s"), suica_card_name(codes, ncodes));
    transit_print_kv("IDm", "%s", sprint_hex_inrow(sys->idm, sizeof(sys->idm)));

    suica_trip_t latest;
    suica_read_trip(h->blocks, &latest);
    if (latest.used) {
        char s[24];
        transit_money_str(s, sizeof(s), latest.balance, 0, "JPY");
        transit_print_kv("Balance", _GREEN_("%s"), s);
        // balance expires ten years after the last use
        transit_print_kv("Expiry", "%04u-%02u-%02u", latest.year + 10, latest.month, latest.day);
    } else {
        transit_print_kv("Balance", "no history yet");
    }

    // attribute block keeps the balance little endian at offset 11
    const transit_felica_service_t *attr = transit_felica_find_service(sys, SUICA_SERVICE_ATTRIBUTE);
    if (attr != NULL && attr->block_count > 0 && latest.used) {
        uint16_t ab = MemLeToUint2byte(attr->blocks + 11);
        transit_print_kv("Attribute 008B", "%u JPY ( %s )", ab,
                         (ab == latest.balance) ? _GREEN_("matches history") : _YELLOW_("differs from history"));
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "History, newest first. Stations are line/station codes, region per record");
    PrintAndLogEx(INFO, "  # | Date             | Terminal          | Process              | From | To   |   Fare | Balance");
    PrintAndLogEx(INFO, "----+------------------+-------------------+----------------------+------+------+--------+--------");

    uint16_t shown = 0;
    for (uint16_t i = 0; i < h->block_count; i++) {
        suica_trip_t t;
        suica_read_trip(h->blocks + (i * SUICA_BLOCK_SIZE), &t);
        if (t.used == false) {
            continue;
        }
        suica_trip_t older;
        bool has_older = false;
        if (i + 1 < h->block_count) {
            suica_read_trip(h->blocks + ((i + 1) * SUICA_BLOCK_SIZE), &older);
            has_older = older.used;
        }
        suica_print_trip(i, &t, has_older ? &older : NULL);
        shown++;
    }
    if (shown == 0) {
        PrintAndLogEx(INFO, "    no records");
    }
    return PM3_SUCCESS;
}

//-----------------------------------------------------------------------------
// Self test
//-----------------------------------------------------------------------------

// Service code sets of real cards, Metrodroid SuicaTest
static const uint16_t suica_test_common[] = {
    0x48, 0x4a, 0x88, 0x8b, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0x810, 0x812,
    0x816, 0x850, 0x852, 0x856, 0x890, 0x892, 0x896, 0x8c8, 0x8ca, 0x90a, 0x90c, 0x90f, 0x1008,
    0x100a, 0x1048, 0x104a, 0x108c, 0x108f, 0x10c8, 0x10cb, 0x1108, 0x110a, 0x1148, 0x114a
};

static bool suica_check_name(const char *what, const uint16_t *extra, size_t extra_len, const char *want) {
    uint16_t codes[96];
    size_t n = 0;
    for (size_t i = 0; i < ARRAYLEN(suica_test_common); i++) {
        codes[n++] = suica_test_common[i];
    }
    for (size_t i = 0; i < extra_len && n < ARRAYLEN(codes); i++) {
        codes[n++] = extra[i];
    }
    return transit_check_str(what, suica_card_name(codes, n), want);
}

int suica_selftest(void) {

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing Japan IC decode");

    bool ok = true;
    ok &= suica_check_name("identify Suica", suica_suica, ARRAYLEN(suica_suica), "Suica");
    ok &= suica_check_name("identify PASMO", suica_pasmo, ARRAYLEN(suica_pasmo), "PASMO");
    ok &= suica_check_name("identify ICOCA", suica_icoca, ARRAYLEN(suica_icoca), "ICOCA");
    ok &= suica_check_name("identify nimoca", suica_nimoca, ARRAYLEN(suica_nimoca), "nimoca");
    ok &= suica_check_name("identify Hayakaken", suica_hayakaken, ARRAYLEN(suica_hayakaken), "Hayakaken");

    // open services only, shared by PASMO and Suica
    const uint16_t ambiguous[] = { 0x8b, 0x90f, 0x108f, 0x10cb, 0x184b, 0x194b, 0x234b, 0x238b, 0x23cb };
    ok &= transit_check_str("ambiguous PASMO/Suica", suica_card_name(ambiguous, ARRAYLEN(ambiguous)), "Japan IC");

    // history: newest is a turnstile trip on 2019-04-03 leaving 1234 JPY,
    // the older one a refill on 2019-04-02 leaving 1400 JPY
    uint8_t hist[3 * SUICA_BLOCK_SIZE] = {0};
    uint8_t *b0 = hist, *b1 = hist + SUICA_BLOCK_SIZE;
    b0[0] = 0x16;
    b0[1] = 0x01;
    transit_set_bits_be(b0, SUICA_BLOCK_SIZE, 32, 7, 19);
    transit_set_bits_be(b0, SUICA_BLOCK_SIZE, 39, 4, 4);
    transit_set_bits_be(b0, SUICA_BLOCK_SIZE, 43, 5, 3);
    b0[6] = 0xE3;
    b0[7] = 0x29;
    b0[8] = 0xE3;
    b0[9] = 0x3D;
    b0[10] = 0xD2;  // 1234 little endian
    b0[11] = 0x04;
    b1[0] = 0x07;
    b1[1] = 0x02;
    transit_set_bits_be(b1, SUICA_BLOCK_SIZE, 32, 7, 19);
    transit_set_bits_be(b1, SUICA_BLOCK_SIZE, 39, 4, 4);
    transit_set_bits_be(b1, SUICA_BLOCK_SIZE, 43, 5, 2);
    b1[10] = 0x78;  // 1400
    b1[11] = 0x05;

    suica_trip_t t0, t1, t2;
    suica_read_trip(b0, &t0);
    suica_read_trip(b1, &t1);
    suica_read_trip(hist + (2 * SUICA_BLOCK_SIZE), &t2);
    ok &= transit_check("date raw word", MemBeToUint2byte(b0 + 4), 0x2683);
    ok &= transit_check("year", t0.year, 2019);
    ok &= transit_check("month", t0.month, 4);
    ok &= transit_check("day", t0.day, 3);
    ok &= transit_check("entry line/station", t0.from, 0xE329);
    ok &= transit_check("exit line/station", t0.to, 0xE33D);
    ok &= transit_check("balance", t0.balance, 1234);
    ok &= transit_check("fare from older record", t1.balance - t0.balance, 166);
    ok &= transit_check("empty record unused", t2.used, 0);

    // vending machine sale carries a time
    uint8_t sale[SUICA_BLOCK_SIZE] = {0};
    sale[0] = 0xC8;
    sale[1] = 0x46;
    transit_set_bits_be(sale, sizeof(sale), 32, 7, 20);
    transit_set_bits_be(sale, sizeof(sale), 39, 4, 12);
    transit_set_bits_be(sale, sizeof(sale), 43, 5, 31);
    transit_set_bits_be(sale, sizeof(sale), 48, 5, 23);
    transit_set_bits_be(sale, sizeof(sale), 53, 6, 59);
    suica_trip_t ts;
    suica_read_trip(sale, &ts);
    ok &= transit_check("sale hour", ts.hour, 23);
    ok &= transit_check("sale minute", ts.minute, 59);

    // through the dispatcher view
    const transit_felica_service_t svc[] = {
        { SUICA_SERVICE_HISTORY, 3, hist },
        { 0x1808, 0, NULL },
    };
    transit_felica_system_t sys = { .system_code = SUICA_SYSTEM_CODE, .service_count = ARRAYLEN(svc), .services = svc };
    transit_felica_card_t card = { .system_count = 1, .systems = &sys };
    ok &= transit_check("detected", is_valid_suica_card(&card), 1);
    ok &= transit_check("parse", (uint64_t)suica_parser_parse(&card), PM3_SUCCESS);

    sys.system_code = 0x8008;
    ok &= transit_check("other system not detected", is_valid_suica_card(&card), 0);

    return transit_selftest_result("Japan IC", ok);
}
