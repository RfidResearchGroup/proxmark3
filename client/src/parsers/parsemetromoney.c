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
// Metromoney (Tbilisi) parser for MIFARE Classic dumps
//-----------------------------------------------------------------------------

#include "parsemetromoney.h"

#include <string.h>

#include "commonutil.h"             // MemLeToUint4byte
#include "ui.h"                     // PrintAndLogEx
#include "parsetransit.h"
#include "parsetransitmfc.h"

#define METROMONEY_S0_KEY_A     0x2803BCB0C7E1
#define METROMONEY_S0_KEY_B     0x4FA9EB49F75E
#define METROMONEY_S1_KEY_A     0x9C616585E26D
#define METROMONEY_S1_KEY_B     0xD1C71E590D16

// The stored balance carries a +1.00 GEL offset (Flipper), Metrodroid shows it raw
#define METROMONEY_OFFSET       100

bool is_valid_metromoney_card(const uint8_t *dump, size_t dumplen) {
    if (transit_mfc_block(dump, dumplen, 1, 3) == NULL) {
        return false;
    }
    bool s0 = transit_mfc_has_key(dump, dumplen, 0, METROMONEY_S0_KEY_A) || transit_mfc_has_key(dump, dumplen, 0, METROMONEY_S0_KEY_B);
    bool s1 = transit_mfc_has_key(dump, dumplen, 1, METROMONEY_S1_KEY_A) || transit_mfc_has_key(dump, dumplen, 1, METROMONEY_S1_KEY_B);
    return s0 && s1;
}

int metromoney_parser_parse(const uint8_t *dump, size_t dumplen) {
    if (is_valid_metromoney_card(dump, dumplen) == false) {
        return PM3_EINVARG;
    }

    uint32_t stored = MemLeToUint4byte(transit_mfc_block(dump, dumplen, 1, 1));

    transit_print_header("Metromoney");
    transit_print_kv("Card number", _YELLOW_("%010u"), MemLeToUint4byte(dump));
    if (stored >= METROMONEY_OFFSET) {
        char buf[32];
        transit_money_str(buf, sizeof(buf), (int64_t)stored - METROMONEY_OFFSET, 2, "GEL");
        transit_print_kv("Balance", _YELLOW_("%s"), buf);
    }
    transit_print_kv("Stored value", "%u  ( raw )", stored);
    return PM3_SUCCESS;
}

// Synthetic card built from the layout
int metromoney_selftest(void) {
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing Metromoney decode");

    uint8_t dump[1024] = {0};
    const uint8_t uid[] = { 0xEF, 0xBE, 0xAD, 0xDE };
    memcpy(dump, uid, sizeof(uid));
    transit_mfc_set_key(dump, sizeof(dump), 0, false, METROMONEY_S0_KEY_A);
    transit_mfc_set_key(dump, sizeof(dump), 1, false, METROMONEY_S1_KEY_A);
    const uint8_t value[] = { 0xD2, 0x04, 0x00, 0x00 };
    memcpy(dump + (5 * 16), value, sizeof(value));

    bool ok = transit_check("detected", is_valid_metromoney_card(dump, sizeof(dump)), 1);
    ok &= transit_check("card number", MemLeToUint4byte(dump), 0xDEADBEEF);
    ok &= transit_check("stored value", MemLeToUint4byte(dump + (5 * 16)), 1234);

    transit_mfc_set_key(dump, sizeof(dump), 0, false, 0xFFFFFFFFFFFF);
    ok &= transit_check("sector 0 key required", is_valid_metromoney_card(dump, sizeof(dump)), 0);

    return transit_selftest_result("Metromoney", ok);
}
