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
// Umarsh parser for MIFARE Classic dumps
//-----------------------------------------------------------------------------

#include "parseumarsh.h"

#include <stdio.h>
#include <string.h>

#include "commonutil.h"             // ARRAYLEN, MemLeToUint4byte
#include "ui.h"                     // PrintAndLogEx
#include "parsetransit.h"
#include "parsetransitmfc.h"

#define UMARSH_SECTOR           8
#define UMARSH_EXTRA_SECTOR     7   // aerial tramway, Nizhny Novgorod only
#define UMARSH_REGION_NN        52

typedef enum {
    UMARSH_DENOM_DEFAULT,       // purse when total is 0, else trips
    UMARSH_DENOM_UNLIMITED,
    UMARSH_DENOM_TRIPS,
    UMARSH_DENOM_RUB,
} umarsh_denom_t;

typedef struct {
    uint8_t region;
    const char *name;
} umarsh_system_t;

static const umarsh_system_t umarsh_systems[] = {
    { 12, "Yoshkar-Ola" },
    { 18, "Strizh, Izhevsk" },
    { 22, "Barnaul" },
    { 33, "Siticard, Vladimir" },
    { 43, "Kirov" },
    { 52, "Siticard, Nizhny Novgorod" },
    { 55, "Omka, Omsk" },
    { 58, "Penza" },
    { 66, "E-karta, Ekaterinburg" },
    { 91, "Crimea trolleybus" },
};

typedef struct {
    uint8_t region;
    uint32_t tariff;
    umarsh_denom_t denom;
} umarsh_tariff_t;

// Tariffs Metrodroid gives an explicit denomination
static const umarsh_tariff_t umarsh_tariffs[] = {
    { 52, 0x0A7F00, UMARSH_DENOM_RUB },
    { 52, 0x0A007F, UMARSH_DENOM_RUB },
    { 52, 0x21007F, UMARSH_DENOM_RUB },
    { 52, 0x2564FF, UMARSH_DENOM_UNLIMITED },
    { 52, 0x31002F, UMARSH_DENOM_RUB },
    { 52, 0x33690F, UMARSH_DENOM_TRIPS },
    { 52, 0x34690F, UMARSH_DENOM_TRIPS },
    { 55, 0x5700FF, UMARSH_DENOM_RUB },
    { 55, 0x5780FF, UMARSH_DENOM_RUB },
    { 55, 0x6300FF, UMARSH_DENOM_RUB },
    { 55, 0x5800FF, UMARSH_DENOM_RUB },
    { 55, 0x5900FF, UMARSH_DENOM_RUB },
    { 55, 0x15EAFF, UMARSH_DENOM_TRIPS },
    { 55, 0x5500FF, UMARSH_DENOM_UNLIMITED },
    { 55, 0x5600FF, UMARSH_DENOM_UNLIMITED },
    { 55, 0x5B00FF, UMARSH_DENOM_UNLIMITED },
    { 55, 0x5C00FF, UMARSH_DENOM_UNLIMITED },
    { 55, 0x6000FF, UMARSH_DENOM_RUB },
    { 55, 0x6100FF, UMARSH_DENOM_TRIPS },
    { 55, 0x6200FF, UMARSH_DENOM_TRIPS },
    { 55, 0x5300FF, UMARSH_DENOM_TRIPS },
    { 55, 0x5400FF, UMARSH_DENOM_TRIPS },
    { 66, 0x42640F, UMARSH_DENOM_UNLIMITED },
    { 91, 0x3D7F00, UMARSH_DENOM_UNLIMITED },
    { 91, 0x467F00, UMARSH_DENOM_UNLIMITED },
};

typedef struct {
    uint32_t counter;
    uint16_t expiry;            // packed date, see umarsh_date_str()
    uint16_t total;
    uint8_t refill_counter;
    uint8_t region;
    uint32_t serial;
    uint32_t tariff;
    uint16_t valid_to;
    uint32_t machine;
    uint16_t last_refill;
    uint16_t balance_rub;
    uint8_t balance_kop;
} umarsh_sector_t;

static uint32_t umarsh_be(const uint8_t *p, uint8_t n) {
    uint32_t v = 0;
    for (uint8_t i = 0; i < n; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

// 7 bit year since 2000, 4 bit month, 5 bit day
static bool umarsh_date_str(char *out, size_t outlen, uint16_t d) {
    if (d == 0 || d == 0xFFFF) {
        return false;
    }
    snprintf(out, outlen, "%04u-%02u-%02u", 2000 + (d >> 9), (d >> 5) & 0x0F, d & 0x1F);
    return true;
}

// Value block whose value sits just under 0x7FFFFFFF, address byte 0x70..0x7F
static bool umarsh_check(const uint8_t *b) {
    uint32_t v = MemLeToUint4byte(b);
    return (v == (uint32_t)~MemLeToUint4byte(b + 4))
           && (v == MemLeToUint4byte(b + 8))
           && ((uint8_t)(b[12] + b[13]) == 0xFF)
           && (b[12] == b[14]) && (b[13] == b[15])
           && (v >= 0x7FFFFF00) && (v <= 0x7FFFFFFF)
           && (b[13] >= 0x70) && (b[13] <= 0x7F);
}

static void umarsh_decode(const uint8_t *b0, const uint8_t *b1, const uint8_t *b2, umarsh_sector_t *s) {
    memset(s, 0, sizeof(*s));
    s->counter = 0x7FFFFFFF - MemLeToUint4byte(b0);
    s->expiry = (uint16_t)umarsh_be(b1 + 1, 2);
    s->total = (uint16_t)umarsh_be(b1 + 5, 2);
    s->refill_counter = b1[7];
    s->region = (uint8_t)(transit_bits_be(b1, 16, 100, 4) | (transit_bits_be(b1, 16, 64, 3) << 4));
    s->serial = (uint32_t)transit_bits_be(b1, 16, 67, 29);
    s->tariff = umarsh_be(b1 + 13, 3);
    s->valid_to = (uint16_t)umarsh_be(b2, 2);
    s->machine = umarsh_be(b2 + 3, 3);
    s->last_refill = (uint16_t)umarsh_be(b2 + 6, 2);
    s->balance_rub = (uint16_t)transit_bits_be(b2, 16, 65, 15);
    s->balance_kop = b2[10] & 0x7F;
}

static bool umarsh_read_sector(const uint8_t *dump, size_t dumplen, uint8_t sector, umarsh_sector_t *s) {
    const uint8_t *b0 = transit_mfc_block(dump, dumplen, sector, 0);
    const uint8_t *b1 = transit_mfc_block(dump, dumplen, sector, 1);
    const uint8_t *b2 = transit_mfc_block(dump, dumplen, sector, 2);
    if (b0 == NULL || b1 == NULL || b2 == NULL || umarsh_check(b0) == false) {
        return false;
    }
    umarsh_decode(b0, b1, b2, s);
    return true;
}

bool is_valid_umarsh_card(const uint8_t *dump, size_t dumplen) {
    umarsh_sector_t s;
    return umarsh_read_sector(dump, dumplen, UMARSH_SECTOR, &s) && (s.serial != 0);
}

static umarsh_denom_t umarsh_denom(const umarsh_sector_t *s) {
    for (size_t i = 0; i < ARRAYLEN(umarsh_tariffs); i++) {
        if (umarsh_tariffs[i].region == s->region && umarsh_tariffs[i].tariff == s->tariff) {
            return umarsh_tariffs[i].denom;
        }
    }
    return (s->total == 0) ? UMARSH_DENOM_RUB : UMARSH_DENOM_TRIPS;
}

static const char *umarsh_system_name(uint8_t region) {
    for (size_t i = 0; i < ARRAYLEN(umarsh_systems); i++) {
        if (umarsh_systems[i].region == region) {
            return umarsh_systems[i].name;
        }
    }
    return "unknown";
}

static void umarsh_print_sector(const umarsh_sector_t *s, uint8_t sector) {
    char buf[40];

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Sector %u%s", sector, (sector == UMARSH_EXTRA_SECTOR) ? "  ( aerial tramway )" : "");
    transit_print_kv("Tariff", "%06X", s->tariff);

    switch (umarsh_denom(s)) {
        case UMARSH_DENOM_RUB:
            transit_money_str(buf, sizeof(buf), ((int64_t)s->balance_rub * 100) + s->balance_kop, 2, "RUB");
            transit_print_kv("Balance", _YELLOW_("%s"), buf);
            break;
        case UMARSH_DENOM_TRIPS:
            transit_print_kv("Trips left", "%u of %u", s->balance_rub, s->total);
            break;
        case UMARSH_DENOM_UNLIMITED:
            transit_print_kv("Trips", "unlimited");
            break;
        case UMARSH_DENOM_DEFAULT:
        default:
            break;
    }
    if (umarsh_date_str(buf, sizeof(buf), s->valid_to)) {
        transit_print_kv("Valid to", "%s", buf);
    }
    if (umarsh_date_str(buf, sizeof(buf), s->expiry)) {
        transit_print_kv("Card expiry", "%s", buf);
    }
    if (umarsh_date_str(buf, sizeof(buf), s->last_refill)) {
        transit_print_kv("Last refill", "%s  machine %u", buf, s->machine);
    }
    transit_print_kv("Refill counter", "%u", s->refill_counter);
}

static const char *umarsh_mode_str(uint8_t trans) {
    switch (trans) {
        case 1:
        case 4:
        case 5:
            return "bus";
        case 2:
            return "trolleybus";
        case 3:
            return "tram";
        default:
            return "other";
    }
}

int umarsh_parser_parse(const uint8_t *dump, size_t dumplen) {
    umarsh_sector_t s8;
    if (is_valid_umarsh_card(dump, dumplen) == false || umarsh_read_sector(dump, dumplen, UMARSH_SECTOR, &s8) == false) {
        return PM3_EINVARG;
    }

    char buf[40];
    char sn[16];
    snprintf(sn, sizeof(sn), "%09u", s8.serial);

    transit_print_header("Umarsh");
    transit_print_kv("System", "%s", umarsh_system_name(s8.region));
    transit_print_kv("Card number", _YELLOW_("%.3s %.3s %.3s"), sn, sn + 3, sn + 6);
    transit_print_kv("Region", "%u", s8.region);

    umarsh_print_sector(&s8, UMARSH_SECTOR);

    umarsh_sector_t s7;
    if (s8.region == UMARSH_REGION_NN && umarsh_read_sector(dump, dumplen, UMARSH_EXTRA_SECTOR, &s7)) {
        umarsh_print_sector(&s7, UMARSH_EXTRA_SECTOR);
    }

    // last validation, sector 0 block 1
    const uint8_t *v = transit_mfc_block(dump, dumplen, 0, 1);
    uint16_t vdate = (uint16_t)umarsh_be(v + 2, 2);
    if (umarsh_date_str(buf, sizeof(buf), vdate)) {
        uint8_t trans = (uint8_t)transit_bits_be(v, 16, 0, 3);
        uint16_t tm = (uint16_t)transit_bits_be(v, 16, 3, 13);
        char route[7], veh[7];
        memcpy(route, v + 4, 6);
        memcpy(veh, v + 10, 6);
        route[6] = veh[6] = '\0';
        for (uint8_t i = 0; i < 6; i++) {
            if (route[i] < 0x20 || route[i] > 0x7E) {
                route[i] = '.';
            }
            if (veh[i] < 0x20 || veh[i] > 0x7E) {
                veh[i] = '.';
            }
        }
        PrintAndLogEx(INFO, "");
        transit_print_kv("Last trip", "%s %02u:%02u  %s, route %s, vehicle %s", buf, tm / 100, tm % 100,
                         umarsh_mode_str(trans), route, veh);
    }
    PrintAndLogEx(INFO, "Times are local time of the region");
    return PM3_SUCCESS;
}

// Synthetic card built from the Metrodroid layout
int umarsh_selftest(void) {
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing Umarsh decode");

    uint8_t dump[1024] = {0};
    uint8_t *s8 = dump + (32 * 16);

    // value block 0x7FFFFFF0, address 0x7A
    const uint8_t vb[16] = {
        0xF0, 0xFF, 0xFF, 0x7F, 0x0F, 0x00, 0x00, 0x80,
        0xF0, 0xFF, 0xFF, 0x7F, 0x85, 0x7A, 0x85, 0x7A
    };
    memcpy(s8, vb, sizeof(vb));

    // region 55 (bits 64..66 = 3, bits 100..103 = 7), serial 123456789, tariff 0x5800FF
    uint8_t *b1 = s8 + 16;
    transit_set_bits_be(b1, 16, 8, 16, (26 << 9) | (12 << 5) | 31);
    b1[7] = 4;
    transit_set_bits_be(b1, 16, 64, 3, 3);
    transit_set_bits_be(b1, 16, 67, 29, 123456789);
    transit_set_bits_be(b1, 16, 100, 4, 7);
    b1[13] = 0x58;
    b1[14] = 0x00;
    b1[15] = 0xFF;

    // balance 250 RUB, machine 0x010203, last refill 2024-05-06
    uint8_t *b2 = s8 + 32;
    transit_set_bits_be(b2, 16, 0, 16, (25 << 9) | (6 << 5) | 30);
    b2[3] = 0x01;
    b2[4] = 0x02;
    b2[5] = 0x03;
    transit_set_bits_be(b2, 16, 48, 16, (24 << 9) | (5 << 5) | 6);
    transit_set_bits_be(b2, 16, 65, 15, 250);
    b2[10] = 0x80;

    bool ok = transit_check("detected", is_valid_umarsh_card(dump, sizeof(dump)), 1);

    umarsh_sector_t s;
    umarsh_read_sector(dump, sizeof(dump), UMARSH_SECTOR, &s);
    ok &= transit_check("counter", s.counter, 15);
    ok &= transit_check("region", s.region, 55);
    ok &= transit_check("serial", s.serial, 123456789);
    ok &= transit_check("tariff", s.tariff, 0x5800FF);
    ok &= transit_check("denomination rub", umarsh_denom(&s), UMARSH_DENOM_RUB);
    ok &= transit_check("balance rub", s.balance_rub, 250);
    ok &= transit_check("balance kop", s.balance_kop, 0);
    ok &= transit_check("machine", s.machine, 0x010203);
    ok &= transit_check("refill counter", s.refill_counter, 4);

    char buf[20];
    umarsh_date_str(buf, sizeof(buf), s.expiry);
    ok &= transit_check_str("card expiry", buf, "2026-12-31");
    umarsh_date_str(buf, sizeof(buf), s.last_refill);
    ok &= transit_check_str("last refill", buf, "2024-05-06");

    s8[13] = 0x6A;
    s8[15] = 0x6A;
    s8[12] = 0x95;
    s8[14] = 0x95;
    ok &= transit_check("address below 0x70 rejected", is_valid_umarsh_card(dump, sizeof(dump)), 0);

    return transit_selftest_result("Umarsh", ok);
}
