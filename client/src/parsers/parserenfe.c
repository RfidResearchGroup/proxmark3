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
// RENFE Cercanias Suma 10 parser for MIFARE Classic dumps
//-----------------------------------------------------------------------------

#include "parserenfe.h"

#include <stdio.h>
#include <string.h>

#include "commonutil.h"         // MemBeToUint2byte
#include "ui.h"                 // PrintAndLogEx
#include "util.h"               // sprint_hex_inrow
#include "parsetransit.h"

#define RENFE_DUMP_MIN          1024
#define RENFE_BLK(b)            ((b) * 16)

static const uint64_t renfe_keys[2] = { 0xA8844B0BCA06, 0xCB5ED0E57B08 };

// Blocks Metroflip found the event log in
static const uint8_t renfe_history_blocks[] = { 18, 22, 28, 29, 30, 44, 45, 46 };

bool is_valid_renfe_card(const uint8_t *dump, size_t dumplen) {
    if (dump == NULL || dumplen < RENFE_DUMP_MIN) {
        return false;
    }
    return MemBeToUint6byte(dump + RENFE_BLK(3)) == renfe_keys[0] &&
           MemBeToUint6byte(dump + RENFE_BLK(7)) == renfe_keys[1];
}

static const char *renfe_event_name(uint8_t type) {
    switch (type) {
        case 0x13:
            return "entry";
        case 0x16:
            return "validation";
        case 0x17:
            return "inspection";
        case 0x18:
            return "check";
        case 0x1A:
            return "exit";
        case 0x1E:
            return "transfer";
        case 0x23:
            return "discount";
        case 0x2A:
            return "penalty";
        case 0x2B:
            return "special";
        case 0x33:
            return "top up";
        case 0x3A:
            return "charge";
        default:
            return "unknown";
    }
}

// Metroflip's test for a used event slot
static bool renfe_is_event(const uint8_t *b) {
    uint16_t station = MemBeToUint2byte(b + 9);
    if (station == 0x0000 || station == 0x2000 || station == 0xFFFF) {
        return false;
    }
    uint32_t ts = MemBeToUint3byte(b + 2);
    if (ts == 0 || ts == 0xFFFFFF) {
        return false;
    }
    if (b[1] == 0x98 && b[0] != 0x00) {
        return true;
    }
    switch (b[0]) {
        case 0x13:
        case 0x16:
        case 0x1A:
        case 0x1E:
        case 0x33:
        case 0x3A:
            return b[1] != 0xFF;
        default:
            return false;
    }
}

static uint8_t renfe_collect(const uint8_t *dump, const uint8_t **ev, uint8_t max) {
    uint8_t n = 0;
    for (size_t i = 0; i < ARRAYLEN(renfe_history_blocks) && n < max; i++) {
        const uint8_t *b = dump + RENFE_BLK(renfe_history_blocks[i]);
        if (renfe_is_event(b)) {
            ev[n++] = b;
        }
    }
    // newest first by the raw time field
    for (uint8_t i = 1; i < n; i++) {
        for (uint8_t j = i; j > 0 && MemBeToUint3byte(ev[j] + 2) > MemBeToUint3byte(ev[j - 1] + 2); j--) {
            const uint8_t *tmp = ev[j];
            ev[j] = ev[j - 1];
            ev[j - 1] = tmp;
        }
    }
    return n;
}

int renfe_parser_parse(const uint8_t *dump, size_t dumplen) {
    if (is_valid_renfe_card(dump, dumplen) == false) {
        return PM3_EINVARG;
    }

    transit_print_header("RENFE Cercanias - Suma 10");
    transit_print_kv("UID", _YELLOW_("%s"), sprint_hex_inrow(dump, 4));

    const uint8_t *b5 = dump + RENFE_BLK(5);
    if (b5[0] == 0x01 && b5[1] == 0x00 && b5[2] == 0x00 && b5[3] == 0x00) {
        transit_print_kv("Trips left", _GREEN_("%u"), b5[4]);
    }
    transit_print_kv("Zone code", "%04X", MemBeToUint2byte(b5 + 5));

    const uint8_t *ev[ARRAYLEN(renfe_history_blocks)];
    uint8_t n = renfe_collect(dump, ev, ARRAYLEN(renfe_history_blocks));

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "History, newest first ( time field undecoded )");
    for (uint8_t i = 0; i < n; i++) {
        PrintAndLogEx(INFO, "  %-10s  station %04X  time %06X", renfe_event_name(ev[i][0]),
                      MemBeToUint2byte(ev[i] + 9), MemBeToUint3byte(ev[i] + 2));
    }
    return PM3_SUCCESS;
}

//-----------------------------------------------------------------------------
// Self test, synthetic card built from the layout above
//-----------------------------------------------------------------------------

int renfe_selftest(void) {
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing RENFE Suma 10 decode");

    static uint8_t d[RENFE_DUMP_MIN];
    memset(d, 0, sizeof(d));
    memcpy(d + RENFE_BLK(3), "\xA8\x84\x4B\x0B\xCA\x06", 6);
    memcpy(d + RENFE_BLK(7), "\xCB\x5E\xD0\xE5\x7B\x08", 6);
    memcpy(d + RENFE_BLK(5), "\x01\x00\x00\x00\x07\x6C\x00", 7);

    // an exit newer than an entry, a top up at the default station is dropped
    memcpy(d + RENFE_BLK(18), "\x13\x00\x01\x02\x03\x00\x00\x00\x00\x12\x34", 11);
    memcpy(d + RENFE_BLK(22), "\x1A\x00\x01\x02\x09\x00\x00\x00\x00\x12\x35", 11);
    memcpy(d + RENFE_BLK(28), "\x33\x00\x01\x02\x0A\x00\x00\x00\x00\x20\x00", 11);

    const uint8_t *ev[ARRAYLEN(renfe_history_blocks)];
    uint8_t n = renfe_collect(d, ev, ARRAYLEN(renfe_history_blocks));

    bool ok = true;
    ok &= transit_check("detected", is_valid_renfe_card(d, sizeof(d)), true);
    ok &= transit_check("events", n, 2);
    ok &= transit_check("newest is exit", (n > 0) ? ev[0][0] : 0, 0x1A);
    ok &= transit_check("parse", renfe_parser_parse(d, sizeof(d)), PM3_SUCCESS);

    d[RENFE_BLK(7)] ^= 0xFF;
    ok &= transit_check("wrong sector 1 key", is_valid_renfe_card(d, sizeof(d)), false);

    return transit_selftest_result("RENFE Suma 10", ok);
}
