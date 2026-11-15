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
// Troika (Moscow) parser for MIFARE Classic and Ultralight dumps
//-----------------------------------------------------------------------------

#include "parsetroika.h"

#include <stdio.h>
#include <string.h>

#include "commonutil.h"             // ARRAYLEN
#include "ui.h"                     // PrintAndLogEx
#include "parsetransit.h"
#include "parsetransitmfc.h"

// Troika block, the first 32 bytes of a sector or of pages 4..11
#define TROIKA_BLOCK_LEN        32

// Moscow local epochs, as days since 1970-01-01
#define TROIKA_DAYS_TO_1992     8035
#define TROIKA_DAYS_TO_2016     16801
#define TROIKA_DAYS_TO_2019     17897

#define TROIKA_UL_FIRST_PAGE    4

typedef struct {
    bool valid;
    bool date_only;
    int64_t secs;               // Moscow local time
} troika_time_t;

typedef enum {
    TROIKA_TT_NONE,
    TROIKA_TT_UNKNOWN,
    TROIKA_TT_SUBWAY,
    TROIKA_TT_MONORAIL,
    TROIKA_TT_GROUND,
    TROIKA_TT_MCC,
} troika_transport_t;

typedef struct {
    uint32_t serial;
    uint16_t ticket_type;
    uint8_t layout;
    uint8_t sublayout;          // layout E only

    troika_time_t expiry;
    troika_time_t last_validation;
    troika_time_t validity_start;
    troika_time_t validity_end;
    troika_time_t last_refill;

    int32_t validity_minutes;   // -1 when absent
    int32_t remaining_trips;
    int32_t validator;
    int32_t balance;            // kopecks
    int32_t refill_counter;
    int32_t purse_trips;

    uint8_t transfer_count;
    int32_t transfers[2];       // minutes after the first validation

    // transport of the last trip, see troika_transport()
    int32_t lead_code;          // -1 when absent
    int32_t long_code;
    int32_t e2_code;            // layout E2 keeps its own 2 bit code
    const char *fare;
    bool is_purse;
    bool known_layout;
} troika_block_t;

// Sector keys A, 1K and 4K agree on these
#define TROIKA_S4_KEY_A         0x73068F118C13
#define TROIKA_S8_KEY_A         0xA73F5DC1D333
static const uint64_t troika_sector_keys[16] = {
    [1] = 0xA82607B01C0D,
    [4] = TROIKA_S4_KEY_A,
    [7] = 0xAE3D65A3DAD4,
    [8] = TROIKA_S8_KEY_A,
};

// Sector 1 on a 4K card uses the MAD key A, key B tells it apart
#define TROIKA_4K_S1_KEY_B      0x7DE02A7F6025

// Metrodroid decodes these sectors in this order
static const uint8_t troika_sectors[] = { 8, 7, 4, 1 };

static uint64_t troika_bits(const uint8_t *b, size_t off, uint8_t n) {
    return transit_bits_be(b, TROIKA_BLOCK_LEN, off, n);
}

//-----------------------------------------------------------------------------
// Time conversion, day 1 is the epoch itself
//-----------------------------------------------------------------------------

static troika_time_t troika_dt(int32_t epoch, uint32_t days, uint32_t mins) {
    troika_time_t t = {0};
    if (days == 0 && mins == 0) {
        return t;
    }
    t.valid = true;
    t.secs = ((int64_t)(epoch + (int32_t)days - 1) * 86400) + ((int64_t)mins * 60);
    return t;
}

static troika_time_t troika_date(int32_t epoch, uint32_t days) {
    troika_time_t t = {0};
    if (days == 0) {
        return t;
    }
    t.valid = true;
    t.date_only = true;
    t.secs = (int64_t)(epoch + (int32_t)days - 1) * 86400;
    return t;
}

static void troika_time_str(char *out, size_t outlen, troika_time_t t) {
    if (t.date_only) {
        transit_date_str(out, outlen, (int32_t)(t.secs / 86400));
    } else {
        transit_datetime_str(out, outlen, t.secs);
    }
}

//-----------------------------------------------------------------------------
// Block decoding
//-----------------------------------------------------------------------------

static bool troika_check(const uint8_t *b) {
    uint64_t v = troika_bits(b, 0, 10);
    return (v == 0x117 || v == 0x108 || v == 0x106);
}

static void troika_decode(const uint8_t *b, troika_block_t *t) {
    memset(t, 0, sizeof(*t));
    t->serial = (uint32_t)troika_bits(b, 20, 32);
    t->ticket_type = (uint16_t)troika_bits(b, 4, 16);
    t->layout = (uint8_t)troika_bits(b, 52, 4);
    t->validity_minutes = -1;
    t->remaining_trips = -1;
    t->validator = -1;
    t->balance = -1;
    t->refill_counter = -1;
    t->purse_trips = -1;
    t->lead_code = -1;
    t->long_code = -1;
    t->e2_code = -1;
    t->known_layout = true;

    switch (t->layout) {
        case 0x2: {
            t->expiry = troika_dt(TROIKA_DAYS_TO_1992, (uint32_t)troika_bits(b, 56, 16), 0);
            t->last_validation = troika_dt(TROIKA_DAYS_TO_1992, (uint32_t)troika_bits(b, 141, 16), (uint32_t)troika_bits(b, 130, 11));
            t->validity_start = troika_dt(TROIKA_DAYS_TO_1992, (uint32_t)troika_bits(b, 157, 16), 0);
            t->validity_end = troika_dt(TROIKA_DAYS_TO_1992, (uint32_t)troika_bits(b, 173, 16), 0);
            t->validator = (int32_t)troika_bits(b, 205, 16);
            break;
        }
        case 0xA: {
            uint32_t start = (uint32_t)troika_bits(b, 67, 9);
            uint32_t len = (uint32_t)troika_bits(b, 76, 19);
            t->validity_minutes = (int32_t)len;
            t->last_validation = troika_dt(TROIKA_DAYS_TO_2016, start, (uint32_t)troika_bits(b, 96, 19));
            t->transfers[t->transfer_count++] = (int32_t)troika_bits(b, 119, 7);
            t->remaining_trips = (int32_t)troika_bits(b, 128, 8);
            t->validator = (int32_t)troika_bits(b, 136, 16);
            t->lead_code = (int32_t)troika_bits(b, 126, 2);
            t->long_code = (int32_t)troika_bits(b, 152, 8);
            t->validity_end = troika_dt(TROIKA_DAYS_TO_2016, start, len - 1);
            t->validity_start = troika_dt(TROIKA_DAYS_TO_2016, start, 0);
            break;
        }
        case 0xD: {
            t->validity_end = troika_date(TROIKA_DAYS_TO_1992, (uint32_t)troika_bits(b, 64, 16));
            t->validity_start = troika_date(TROIKA_DAYS_TO_1992, (uint32_t)troika_bits(b, 128, 16));
            t->validity_minutes = (int32_t)troika_bits(b, 144, 8) * 60 * 24;
            t->transfers[t->transfer_count++] = (int32_t)troika_bits(b, 155, 5) * 5;
            t->lead_code = (int32_t)troika_bits(b, 160, 2);
            t->long_code = (int32_t)troika_bits(b, 251, 2);
            t->remaining_trips = (int32_t)troika_bits(b, 166, 10);
            t->validator = (int32_t)troika_bits(b, 176, 16);
            t->last_validation = troika_dt(TROIKA_DAYS_TO_1992, (uint32_t)troika_bits(b, 224, 16), (uint32_t)troika_bits(b, 240, 11));
            break;
        }
        case 0xE: {
            t->sublayout = (uint8_t)troika_bits(b, 56, 5);
            if (t->sublayout == 2) {
                uint32_t len = (uint32_t)troika_bits(b, 131, 20);
                uint32_t start = (uint32_t)troika_bits(b, 97, 16);
                t->e2_code = (int32_t)troika_bits(b, 163, 2);
                t->expiry = troika_dt(TROIKA_DAYS_TO_1992, (uint32_t)troika_bits(b, 71, 16), 0);
                t->validity_minutes = (int32_t)len;
                t->transfers[t->transfer_count++] = (int32_t)troika_bits(b, 154, 8);
                t->remaining_trips = (int32_t)troika_bits(b, 167, 10);
                t->validator = (int32_t)troika_bits(b, 177, 16);
                t->validity_start = troika_dt(TROIKA_DAYS_TO_1992, start, 0);
                t->validity_end = troika_dt(TROIKA_DAYS_TO_1992, start, len - 1);
                t->last_validation = troika_dt(TROIKA_DAYS_TO_1992, start, len - (uint32_t)troika_bits(b, 196, 20));
            } else if (t->sublayout == 3) {
                t->is_purse = true;
                t->expiry = troika_dt(TROIKA_DAYS_TO_1992, (uint32_t)troika_bits(b, 61, 16), 0);
                t->validator = (int32_t)troika_bits(b, 128, 16);
                t->last_validation = troika_dt(TROIKA_DAYS_TO_2016, 0, (uint32_t)troika_bits(b, 144, 23));
                t->transfers[t->transfer_count++] = (int32_t)troika_bits(b, 171, 7);
                t->lead_code = (int32_t)troika_bits(b, 178, 2);
                t->long_code = (int32_t)troika_bits(b, 180, 8);
                t->balance = (int32_t)troika_bits(b, 188, 22);
                switch (troika_bits(b, 210, 2)) {
                    case 1:
                        t->fare = "single trip";
                        break;
                    case 2:
                        t->fare = "90 minutes";
                        break;
                    default:
                        break;
                }
            } else if (t->sublayout == 5) {
                t->is_purse = true;
                t->expiry = troika_date(TROIKA_DAYS_TO_2019, (uint32_t)troika_bits(b, 61, 13));
                t->last_refill = troika_dt(TROIKA_DAYS_TO_2019, 0, (uint32_t)troika_bits(b, 84, 23));
                t->refill_counter = (int32_t)troika_bits(b, 107, 10);
                t->last_validation = troika_dt(TROIKA_DAYS_TO_2019, 0, (uint32_t)troika_bits(b, 128, 23));
                t->transfers[t->transfer_count++] = (int32_t)troika_bits(b, 151, 7);
                t->transfers[t->transfer_count++] = (int32_t)troika_bits(b, 158, 7);
                t->balance = (int32_t)troika_bits(b, 167, 19);
                t->validator = (int32_t)troika_bits(b, 186, 16);
                t->purse_trips = (int32_t)troika_bits(b, 216, 7);
            } else {
                t->known_layout = false;
            }
            break;
        }
        default:
            t->known_layout = false;
            break;
    }
}

// Transport of the last (get_last) or first leg of a journey
static troika_transport_t troika_transport(const troika_block_t *t, bool get_last) {
    if (t->e2_code >= 0) {
        switch (t->e2_code) {
            case 0:
                return TROIKA_TT_NONE;
            case 1:
                return TROIKA_TT_SUBWAY;
            case 2:
                return TROIKA_TT_MONORAIL;
            default:
                return TROIKA_TT_GROUND;
        }
    }

    switch (t->lead_code) {
        case 0:
            return TROIKA_TT_NONE;
        case 1:
            break;
        case 2:
            return get_last ? TROIKA_TT_GROUND : TROIKA_TT_UNKNOWN;
        default:
            return TROIKA_TT_UNKNOWN;
    }

    if (t->long_code <= 0) {
        return TROIKA_TT_UNKNOWN;
    }

    // four 2 bit codes used in sequence, most significant first
    troika_transport_t first = TROIKA_TT_UNKNOWN, last = TROIKA_TT_UNKNOWN;
    int found = 0;
    for (int i = 6; i >= 0; i -= 2) {
        int sc = (t->long_code >> i) & 3;
        if (sc == 0) {
            continue;
        }
        troika_transport_t type = (sc == 1) ? TROIKA_TT_SUBWAY : (sc == 2) ? TROIKA_TT_MONORAIL : TROIKA_TT_MCC;
        if (found == 0) {
            first = type;
        }
        last = type;
        found++;
    }
    if (found == 1 && get_last == false) {
        return TROIKA_TT_UNKNOWN;
    }
    return get_last ? last : first;
}

static const char *troika_transport_str(troika_transport_t tt) {
    switch (tt) {
        case TROIKA_TT_NONE:
            return "none";
        case TROIKA_TT_SUBWAY:
            return "metro";
        case TROIKA_TT_MONORAIL:
            return "monorail";
        case TROIKA_TT_GROUND:
            return "ground transport";
        case TROIKA_TT_MCC:
            return "MCC";
        case TROIKA_TT_UNKNOWN:
        default:
            return "unknown";
    }
}

static const char *troika_ticket_str(uint16_t type) {
    switch (type) {
        case 0x5D3D:
        case 0x5D3E:
        case 0x5D48:
        case 0x2135:
            return "empty ticket holder";
        case 0x183D:
        case 0x2129:
            return "Druzhinnik card";
        case 0x5D9A:
        case 0x5D9B:
            return "1 ride";
        case 0x5D9C:
            return "2 rides";
        case 0x5DA0:
            return "20 rides";
        case 0x5DB1:
            return "Troika purse";
        case 0x5DD3:
            return "60 rides";
        default:
            return "unknown";
    }
}

static bool troika_has_subscription(const troika_block_t *t) {
    if (t->is_purse || t->known_layout == false) {
        return false;
    }
    // layout 2 placeholder of an empty holder
    if (t->layout == 0x2) {
        switch (t->ticket_type) {
            case 0x5D3D:
            case 0x5D3E:
            case 0x5D48:
            case 0x2135:
            case 0x2141:
                return false;
            default:
                break;
        }
    }
    return true;
}

static void troika_serial_str(char *out, size_t outlen, uint32_t sn) {
    char d[16];
    snprintf(d, sizeof(d), "%010u", sn);
    snprintf(out, outlen, "%.4s %.3s %.3s", d, d + 4, d + 7);
}

//-----------------------------------------------------------------------------
// Printing
//-----------------------------------------------------------------------------

static void troika_print_block(const troika_block_t *t, const char *where) {
    char buf[64];

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "%s  ( layout %X%s )", where, t->layout,
                  (t->layout == 0xE) ? ((t->sublayout == 2) ? ", E2" : (t->sublayout == 3) ? ", E3 purse" : (t->sublayout == 5) ? ", E5 purse" : ", unknown") : "");

    transit_print_kv("Ticket", "%04X  ( %s )", t->ticket_type, troika_ticket_str(t->ticket_type));

    if (t->known_layout == false) {
        transit_print_kv("Layout", "not decoded");
        return;
    }

    if (t->balance >= 0) {
        transit_money_str(buf, sizeof(buf), t->balance, 2, "RUB");
        transit_print_kv("Balance", _YELLOW_("%s"), buf);
    }
    if (t->expiry.valid) {
        troika_time_str(buf, sizeof(buf), t->expiry);
        transit_print_kv("Expiry", "%s", buf);
    }
    if (troika_has_subscription(t)) {
        if (t->validity_start.valid) {
            troika_time_str(buf, sizeof(buf), t->validity_start);
            transit_print_kv("Valid from", "%s", buf);
        }
        if (t->validity_end.valid) {
            troika_time_str(buf, sizeof(buf), t->validity_end);
            transit_print_kv("Valid to", "%s", buf);
        }
        if (t->validity_minutes > 0) {
            transit_print_kv("Validity", "%d min", t->validity_minutes);
        }
        if (t->remaining_trips >= 0) {
            transit_print_kv("Trips left", "%d", t->remaining_trips);
        }
    }
    if (t->last_refill.valid) {
        troika_time_str(buf, sizeof(buf), t->last_refill);
        transit_print_kv("Last refill", "%s", buf);
    }
    if (t->refill_counter >= 0) {
        transit_print_kv("Refill counter", "%d", t->refill_counter);
    }
    if (t->purse_trips >= 0) {
        transit_print_kv("Purse trips", "%d", t->purse_trips);
    }
    if (t->fare != NULL) {
        transit_print_kv("Last fare", "%s", t->fare);
    }

    if (t->last_validation.valid == false) {
        return;
    }

    // latest leg first, the base time is the first validation of the journey
    int32_t legs[3];
    uint8_t n = 0;
    for (uint8_t i = 0; i < t->transfer_count; i++) {
        if (t->transfers[i] != 0) {
            legs[n++] = t->transfers[i];
        }
    }
    if (n == 2 && legs[1] > legs[0]) {
        int32_t tmp = legs[0];
        legs[0] = legs[1];
        legs[1] = tmp;
    }
    legs[n++] = 0;

    for (uint8_t i = 0; i < n; i++) {
        troika_time_t lt = t->last_validation;
        lt.secs += (int64_t)legs[i] * 60;
        troika_time_str(buf, sizeof(buf), lt);
        if (i == 0) {
            if (t->validator >= 0) {
                transit_print_kv("Trip", "%s  %s, validator 0x%04X", buf, troika_transport_str(troika_transport(t, true)), (unsigned)t->validator);
            } else {
                transit_print_kv("Trip", "%s  %s", buf, troika_transport_str(troika_transport(t, true)));
            }
        } else {
            transit_print_kv("Trip", "%s  %s", buf, troika_transport_str(troika_transport(t, false)));
        }
    }
}

//-----------------------------------------------------------------------------
// MIFARE Classic
//-----------------------------------------------------------------------------

static const transit_mfc_key_t troika_id_keys[] = {
    {8, TRANSIT_MFC_KEY_AB, TROIKA_S8_KEY_A}, {4, TRANSIT_MFC_KEY_AB, TROIKA_S4_KEY_A},
};

const transit_mfc_keyset_t troika_keyset = { troika_id_keys, ARRAYLEN(troika_id_keys), true };

static bool troika_sector_has_key(const uint8_t *dump, size_t dumplen, uint8_t sector) {
    if (transit_mfc_has_key(dump, dumplen, sector, troika_sector_keys[sector])) {
        return true;
    }
    return (sector == 1) && transit_mfc_has_key(dump, dumplen, sector, TROIKA_4K_S1_KEY_B);
}

// The 32 byte block of a sector, when it carries the Troika keys and header
static bool troika_sector_block(const uint8_t *dump, size_t dumplen, uint8_t sector, uint8_t *out) {
    const uint8_t *b0 = transit_mfc_block(dump, dumplen, sector, 0);
    const uint8_t *b1 = transit_mfc_block(dump, dumplen, sector, 1);
    if (b0 == NULL || b1 == NULL || troika_sector_has_key(dump, dumplen, sector) == false) {
        return false;
    }
    memcpy(out, b0, 16);
    memcpy(out + 16, b1, 16);
    return troika_check(out);
}

bool is_valid_troika_card(const uint8_t *dump, size_t dumplen) {
    uint8_t b[TROIKA_BLOCK_LEN];
    return troika_sector_block(dump, dumplen, 8, b) || troika_sector_block(dump, dumplen, 4, b);
}

int troika_parser_parse(const uint8_t *dump, size_t dumplen) {
    if (is_valid_troika_card(dump, dumplen) == false) {
        return PM3_EINVARG;
    }

    transit_print_header("Troika");

    bool first = true;
    for (size_t i = 0; i < ARRAYLEN(troika_sectors); i++) {
        uint8_t b[TROIKA_BLOCK_LEN];
        if (troika_sector_block(dump, dumplen, troika_sectors[i], b) == false) {
            continue;
        }
        troika_block_t t;
        troika_decode(b, &t);
        if (first) {
            char sn[20];
            troika_serial_str(sn, sizeof(sn), t.serial);
            transit_print_kv("Card number", _YELLOW_("%s"), sn);
            first = false;
        }
        char where[16];
        snprintf(where, sizeof(where), "Sector %u", troika_sectors[i]);
        troika_print_block(&t, where);
    }
    PrintAndLogEx(INFO, "Times are Moscow local time");
    return PM3_SUCCESS;
}

//-----------------------------------------------------------------------------
// MIFARE Ultralight
//-----------------------------------------------------------------------------

bool is_valid_troika_ul_card(const uint8_t *data, size_t datalen) {
    if (data == NULL || datalen < (TROIKA_UL_FIRST_PAGE * 4) + TROIKA_BLOCK_LEN) {
        return false;
    }
    return troika_check(data + (TROIKA_UL_FIRST_PAGE * 4));
}

int troika_ul_parser_parse(const uint8_t *data, size_t datalen) {
    if (is_valid_troika_ul_card(data, datalen) == false) {
        return PM3_EINVARG;
    }

    troika_block_t t;
    troika_decode(data + (TROIKA_UL_FIRST_PAGE * 4), &t);

    char sn[20];
    troika_serial_str(sn, sizeof(sn), t.serial);
    transit_print_header("Troika ticket");
    transit_print_kv("Card number", _YELLOW_("%s"), sn);
    troika_print_block(&t, "Pages 4..11");
    PrintAndLogEx(INFO, "Times are Moscow local time");
    return PM3_SUCCESS;
}

//-----------------------------------------------------------------------------
// Self tests
//-----------------------------------------------------------------------------

// Metrodroid test asset troika/troikaul.json, pages 0..19
static const uint8_t troika_ul_vector[] = {
    0x12, 0x34, 0x56, 0xBD, 0x77, 0x88, 0x99, 0x00, 0x98, 0x48, 0xF0, 0x00, 0xFF, 0xFF, 0xFF, 0xFC,
    0x45, 0xD9, 0xA1, 0x23, 0x45, 0x67, 0x8D, 0x00, 0x26, 0x01, 0x00, 0x00, 0x26, 0x01, 0x00, 0x00,
    0x25, 0xBC, 0x05, 0x00, 0x80, 0x00, 0x78, 0xAA, 0x4F, 0x84, 0xE6, 0x0C, 0x25, 0xBC, 0x3B, 0xA0,
    0x25, 0xBC, 0x05, 0x00, 0x80, 0x00, 0x78, 0xAA, 0x4F, 0x84, 0xE6, 0x0C, 0x25, 0xBC, 0x3B, 0xA0,
    0x00, 0x00, 0x00, 0xFF, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// Checks the decode against Metrodroid's parsed/troikaul.json
static bool troika_check_ul_vector(const uint8_t *b) {
    troika_block_t t;
    troika_decode(b, &t);

    char buf[40];
    bool ok = true;
    troika_serial_str(buf, sizeof(buf), t.serial);
    ok &= transit_check_str("serial", buf, "0305 419 896");
    ok &= transit_check("layout", t.layout, 0xD);
    ok &= transit_check("ticket type", t.ticket_type, 0x5D9A);
    ok &= transit_check("valid from (days)", (uint64_t)(t.validity_start.secs / 86400), 17694);
    ok &= transit_check("valid to (days)", (uint64_t)(t.validity_end.secs / 86400), 17763);
    ok &= transit_check("trips left", (uint64_t)t.remaining_trips, 0);
    ok &= transit_check("validator", (uint64_t)t.validator, 0x78AA);
    // 1528779420 is UTC, Moscow is three hours ahead
    ok &= transit_check("last validation", (uint64_t)t.last_validation.secs, 1528779420 + (3 * 3600));
    ok &= transit_check("transport is ground", troika_transport(&t, true), TROIKA_TT_GROUND);
    return ok;
}

int troika_ul_selftest(void) {
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing Troika Ultralight decode");

    bool ok = transit_check("detected", is_valid_troika_ul_card(troika_ul_vector, sizeof(troika_ul_vector)), 1);
    ok &= transit_mfu_check_identify("identify", troika_ul_vector, sizeof(troika_ul_vector), "Troika Ultralight", TRANSIT_ID_POSSIBLE);
    ok &= troika_check_ul_vector(troika_ul_vector + (TROIKA_UL_FIRST_PAGE * 4));

    uint8_t bad[sizeof(troika_ul_vector)];
    memcpy(bad, troika_ul_vector, sizeof(bad));
    bad[16] = 0x00;
    ok &= transit_check("bad header rejected", is_valid_troika_ul_card(bad, sizeof(bad)), 0);
    ok &= transit_mfu_check_identify("not identified", bad, sizeof(bad), "Troika Ultralight", TRANSIT_ID_NONE);
    return transit_selftest_result("Troika Ultralight", ok);
}

int troika_selftest(void) {
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing Troika MIFARE Classic decode");

    // synthetic 1K: the Ultralight block in sector 8, an E5 purse built from the layout in sector 4
    uint8_t dump[1024] = {0};
    memcpy(dump + (32 * 16), troika_ul_vector + 16, 32);
    for (uint8_t s = 0; s < 16; s++) {
        transit_mfc_set_key(dump, sizeof(dump), s, false, 0xFFFFFFFFFFFF);
    }
    transit_mfc_set_key(dump, sizeof(dump), 8, false, troika_sector_keys[8]);

    bool ok = transit_check("detected", is_valid_troika_card(dump, sizeof(dump)), 1);
    ok &= transit_mfc_check_identify("identify", dump, sizeof(dump), "Troika", TRANSIT_ID_MATCH);

    uint8_t b[TROIKA_BLOCK_LEN];
    ok &= transit_check("sector 8 read", troika_sector_block(dump, sizeof(dump), 8, b), 1);
    ok &= troika_check_ul_vector(b);

    uint8_t *p = dump + (16 * 16);
    transit_set_bits_be(p, 32, 0, 10, 0x117);
    transit_set_bits_be(p, 32, 4, 16, 0x5DB1);
    transit_set_bits_be(p, 32, 20, 32, 305419896);
    transit_set_bits_be(p, 32, 52, 4, 0xE);
    transit_set_bits_be(p, 32, 56, 5, 5);
    transit_set_bits_be(p, 32, 61, 13, 2000);
    transit_set_bits_be(p, 32, 107, 10, 7);
    transit_set_bits_be(p, 32, 128, 23, 1440 + 90);
    transit_set_bits_be(p, 32, 167, 19, 12345);
    transit_set_bits_be(p, 32, 186, 16, 4242);

    ok &= transit_check("sector 4 needs its key", troika_sector_block(dump, sizeof(dump), 4, b), 0);
    transit_mfc_set_key(dump, sizeof(dump), 4, false, troika_sector_keys[4]);
    ok &= transit_check("sector 4 with its key", troika_sector_block(dump, sizeof(dump), 4, b), 1);

    troika_block_t t;
    troika_decode(b, &t);
    ok &= transit_check("E5 purse", t.is_purse && t.sublayout == 5, 1);
    ok &= transit_check("E5 balance", (uint64_t)t.balance, 12345);
    ok &= transit_check("E5 refill counter", (uint64_t)t.refill_counter, 7);
    ok &= transit_check("E5 validator", (uint64_t)t.validator, 4242);
    ok &= transit_check("E5 expiry (days)", (uint64_t)(t.expiry.secs / 86400), TROIKA_DAYS_TO_2019 + 1999);
    // minutes since 2019-01-01 00:00 minus a day, Metrodroid's day zero
    ok &= transit_check("E5 last validation", (uint64_t)t.last_validation.secs, ((uint64_t)TROIKA_DAYS_TO_2019 * 86400) + (90 * 60));

    // a matching header under the wrong keys is not Troika
    transit_mfc_set_key(dump, sizeof(dump), 8, false, 0xFFFFFFFFFFFF);
    transit_mfc_set_key(dump, sizeof(dump), 4, false, 0xFFFFFFFFFFFF);
    ok &= transit_check("wrong keys rejected", is_valid_troika_card(dump, sizeof(dump)), 0);
    ok &= transit_mfc_check_identify("not identified", dump, sizeof(dump), "Troika", TRANSIT_ID_NONE);
    ok &= transit_check("short dump rejected", is_valid_troika_card(dump, 512), 0);

    return transit_selftest_result("Troika", ok);
}
