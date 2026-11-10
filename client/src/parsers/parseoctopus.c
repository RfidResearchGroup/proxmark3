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
// Octopus (Hong Kong) and Shenzhen Tong parser for FeliCa dumps
//-----------------------------------------------------------------------------

#include "parseoctopus.h"

#include <string.h>

#include "commonutil.h"         // MemBeToUint4byte, ARRAYLEN
#include "ui.h"                 // PrintAndLogEx
#include "util.h"               // sprint_hex_inrow

// The stored value is in HK$0.1 plus an offset that allows a negative balance.
// The offset went from 350 to 500 on 2017-10-01. A dump carries no scan date,
// so the current offset is used and the old one shown alongside.
#define OCTOPUS_OFFSET_1997     350
#define OCTOPUS_OFFSET_2017     500
#define SZT_OFFSET              350

// cents
static int64_t octopus_balance(const uint8_t *block, int32_t offset) {
    return ((int64_t)MemBeToUint4byte(block) - offset) * 10;
}

static const uint8_t *octopus_block(const transit_felica_card_t *card, uint16_t system, uint16_t service) {
    const transit_felica_service_t *s = transit_felica_find_service(transit_felica_find_system(card, system), service);
    return (s != NULL && s->block_count > 0) ? s->blocks : NULL;
}

bool is_valid_octopus_card(const transit_felica_card_t *card) {
    return (octopus_block(card, OCTOPUS_SYSTEM_CODE, OCTOPUS_SERVICE_BALANCE) != NULL) ||
           (octopus_block(card, SZT_SYSTEM_CODE, SZT_SERVICE_BALANCE) != NULL);
}

int octopus_parser_parse(const transit_felica_card_t *card) {

    if (is_valid_octopus_card(card) == false) {
        return PM3_EINVARG;
    }

    const uint8_t *hk = octopus_block(card, OCTOPUS_SYSTEM_CODE, OCTOPUS_SERVICE_BALANCE);
    const uint8_t *sz = octopus_block(card, SZT_SYSTEM_CODE, SZT_SERVICE_BALANCE);

    const char *name = "Octopus";
    if (hk != NULL && sz != NULL) {
        name = "Octopus / Shenzhen Tong";
    } else if (hk == NULL) {
        name = "Shenzhen Tong";
    }
    transit_print_header(name);

    const transit_felica_system_t *sys = transit_felica_find_system(card, (hk != NULL) ? OCTOPUS_SYSTEM_CODE : SZT_SYSTEM_CODE);
    transit_print_kv("IDm", "%s", sprint_hex_inrow(sys->idm, sizeof(sys->idm)));

    char s[32];
    if (hk != NULL) {
        transit_money_str(s, sizeof(s), octopus_balance(hk, OCTOPUS_OFFSET_2017), 2, "HKD");
        transit_print_kv("Balance", _GREEN_("%s"), s);
        transit_money_str(s, sizeof(s), octopus_balance(hk, OCTOPUS_OFFSET_1997), 2, "HKD");
        transit_print_kv("Pre 2017-10", "%s  ( old negative balance offset )", s);
        transit_print_kv("Raw", "%s", sprint_hex_inrow(hk, 16));
    }
    if (sz != NULL) {
        transit_money_str(s, sizeof(s), octopus_balance(sz, SZT_OFFSET), 2, "CNY");
        transit_print_kv("SZT balance", _GREEN_("%s"), s);
        transit_print_kv("SZT raw", "%s", sprint_hex_inrow(sz, 16));
    }
    return PM3_SUCCESS;
}

int octopus_selftest(void) {

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing Octopus decode");

    // Metrodroid OctopusTest, HKD -14.40 after the 2017 change and -1.20 before it
    const uint8_t c2018[16] = { 0x00, 0x00, 0x01, 0x64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x21 };
    const uint8_t c2016[16] = { 0x00, 0x00, 0x01, 0x52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x86, 0xB1 };

    bool ok = true;
    ok &= transit_check("2018 card, offset 500", (uint64_t)octopus_balance(c2018, OCTOPUS_OFFSET_2017), (uint64_t) -1440);
    ok &= transit_check("2016 card, offset 350", (uint64_t)octopus_balance(c2016, OCTOPUS_OFFSET_1997), (uint64_t) -120);

    char s[32];
    transit_money_str(s, sizeof(s), octopus_balance(c2018, OCTOPUS_OFFSET_2017), 2, "HKD");
    ok &= transit_check_str("formatted", s, "-14.40 HKD");

    const uint8_t empty[16] = {0};
    const transit_felica_service_t svc[] = {
        { OCTOPUS_SERVICE_BALANCE, 1, c2018 },
        { 0x100B, 1, empty },
    };
    transit_felica_system_t sys = { .system_code = OCTOPUS_SYSTEM_CODE, .service_count = ARRAYLEN(svc), .services = svc };
    transit_felica_card_t card = { .system_count = 1, .systems = &sys };
    ok &= transit_check("detected", is_valid_octopus_card(&card), 1);
    ok &= transit_check("parse", (uint64_t)octopus_parser_parse(&card), PM3_SUCCESS);

    sys.system_code = 0x0003;
    ok &= transit_check("other system not detected", is_valid_octopus_card(&card), 0);

    return transit_selftest_result("Octopus", ok);
}
