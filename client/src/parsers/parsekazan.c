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
// Kazan transport card parser for MIFARE Classic dumps
//-----------------------------------------------------------------------------

#include "parsekazan.h"

#include <stdio.h>
#include <string.h>

#include "commonutil.h"             // ARRAYLEN, MemLeToUint4byte
#include "ui.h"                     // PrintAndLogEx
#include "parsetransit.h"
#include "parsetransitmfc.h"

#define KAZAN_TICKET_SECTOR     8
#define KAZAN_COUNTER_SECTOR    9
#define KAZAN_TYPE_PURSE        0x53

// Sector 8 keys of the known key sets
static const transit_mfc_key_t kazan_keys[] = {
    {KAZAN_TICKET_SECTOR, TRANSIT_MFC_KEY_AB, 0xE954024EE754}, {KAZAN_TICKET_SECTOR, TRANSIT_MFC_KEY_AB, 0x0CD464CDC100},
    {KAZAN_TICKET_SECTOR, TRANSIT_MFC_KEY_AB, 0x2058EAEE8446}, {KAZAN_TICKET_SECTOR, TRANSIT_MFC_KEY_AB, 0xCB9B23815F87},
};

const transit_mfc_keyset_t kazan_keyset = { kazan_keys, ARRAYLEN(kazan_keys), false };

typedef struct {
    uint8_t type;
    const char *name;
    const char *counts;         // what the counter holds
} kazan_tariff_t;

static const kazan_tariff_t kazan_tariffs[] = {
    { 0x00, "blank", "counter" },
    { 0x01, "token", "trips left" },
    { 0x0F, "underground only", "trips left" },
    { 0x51, "social, adult", "days" },
    { 0x53, "standard purse", "balance" },
    { 0x60, "unlimited", "counter" },
    { 0x67, "ground electric transport, 1 month", "days" },
    { 0x6D, "tram, 60 minutes, transfer, 10 trips", "trips left" },
};

bool is_valid_kazan_card(const uint8_t *dump, size_t dumplen) {
    if (transit_mfc_block(dump, dumplen, KAZAN_COUNTER_SECTOR, 3) == NULL) {
        return false;
    }
    return transit_mfc_keyset_match_dump(&kazan_keyset, dump, dumplen);
}

// YY MM DD, false when unset or out of range
static bool kazan_date(const uint8_t *p, char *out, size_t outlen) {
    if (p[0] == 0 && p[1] == 0 && p[2] == 0) {
        return false;
    }
    if (p[1] < 1 || p[1] > 12 || p[2] < 1 || p[2] > 31) {
        return false;
    }
    snprintf(out, outlen, "%04u-%02u-%02u", 2000 + p[0], p[1], p[2]);
    return true;
}

int kazan_parser_parse(const uint8_t *dump, size_t dumplen) {
    if (is_valid_kazan_card(dump, dumplen) == false) {
        return PM3_EINVARG;
    }

    const uint8_t *b0 = transit_mfc_block(dump, dumplen, KAZAN_TICKET_SECTOR, 0);
    const uint8_t *b2 = transit_mfc_block(dump, dumplen, KAZAN_TICKET_SECTOR, 2);
    const uint8_t *cb = transit_mfc_block(dump, dumplen, KAZAN_COUNTER_SECTOR, 0);
    uint32_t counter = MemLeToUint4byte(cb);
    uint8_t type = b0[6];

    const kazan_tariff_t *tariff = NULL;
    for (size_t i = 0; i < ARRAYLEN(kazan_tariffs); i++) {
        if (kazan_tariffs[i].type == type) {
            tariff = &kazan_tariffs[i];
        }
    }

    char buf[40];
    transit_print_header("Kazan transport card");
    transit_print_kv("Card number", _YELLOW_("%010u"), MemLeToUint4byte(dump));
    transit_print_kv("Tariff", "%02X  ( %s )", type, (tariff != NULL) ? tariff->name : "unknown");

    if (type == KAZAN_TYPE_PURSE) {
        transit_money_str(buf, sizeof(buf), (int64_t)counter * 100, 2, "RUB");
        transit_print_kv("Balance", _YELLOW_("%s"), buf);
    } else {
        transit_print_kv((tariff != NULL) ? tariff->counts : "counter", "%u", counter);
    }

    if (kazan_date(b0 + 7, buf, sizeof(buf))) {
        transit_print_kv("Valid from", "%s", buf);
    }
    if (kazan_date(b0 + 10, buf, sizeof(buf))) {
        transit_print_kv("Valid to", "%s", buf);
    }

    const uint8_t *t = b2 + 1;
    if (kazan_date(t, buf, sizeof(buf)) && t[3] < 24 && t[4] < 60) {
        transit_print_kv("Last trip", "%s %02u:%02u", buf, t[3], t[4]);
    }
    return PM3_SUCCESS;
}

// Synthetic card built from the layout
int kazan_selftest(void) {
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing Kazan decode");

    uint8_t dump[1024] = {0};
    const uint8_t uid[] = { 0x78, 0x56, 0x34, 0x12 };
    memcpy(dump, uid, sizeof(uid));
    transit_mfc_set_key(dump, sizeof(dump), KAZAN_TICKET_SECTOR, false, 0x2058EAEE8446);

    uint8_t *s8 = dump + (32 * 16);
    const uint8_t ticket[] = { 0, 0, 0, 0, 0, 0, KAZAN_TYPE_PURSE, 23, 1, 15, 25, 12, 31 };
    const uint8_t trip[] = { 0, 24, 3, 7, 8, 45 };
    memcpy(s8, ticket, sizeof(ticket));
    memcpy(s8 + 32, trip, sizeof(trip));
    dump[36 * 16] = 150;

    bool ok = transit_check("detected", is_valid_kazan_card(dump, sizeof(dump)), 1);
    ok &= transit_mfc_check_identify("identify", dump, sizeof(dump), "Kazan", TRANSIT_ID_MATCH);
    ok &= transit_check("card number", MemLeToUint4byte(dump), 0x12345678);
    ok &= transit_check("counter", MemLeToUint4byte(dump + (36 * 16)), 150);

    char buf[20];
    ok &= transit_check("valid from set", kazan_date(s8 + 7, buf, sizeof(buf)), 1);
    ok &= transit_check_str("valid from", buf, "2023-01-15");
    ok &= transit_check("valid to set", kazan_date(s8 + 10, buf, sizeof(buf)), 1);
    ok &= transit_check_str("valid to", buf, "2025-12-31");
    ok &= transit_check("last trip set", kazan_date(s8 + 33, buf, sizeof(buf)), 1);
    ok &= transit_check_str("last trip", buf, "2024-03-07");
    ok &= transit_check("bad month rejected", kazan_date((const uint8_t[]) {24, 13, 1}, buf, sizeof(buf)), 0);

    transit_mfc_set_key(dump, sizeof(dump), KAZAN_TICKET_SECTOR, false, 0xFFFFFFFFFFFF);
    ok &= transit_check("wrong key rejected", is_valid_kazan_card(dump, sizeof(dump)), 0);
    ok &= transit_mfc_check_identify("not identified", dump, sizeof(dump), "Kazan", TRANSIT_ID_NONE);

    return transit_selftest_result("Kazan", ok);
}
