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
// NORTIC travel card parser for MIFARE DESFire dumps
//-----------------------------------------------------------------------------

#include "parsenortic.h"

#include <stdio.h>                  // snprintf
#include <string.h>

#include "commonutil.h"             // ARRAYLEN
#include "ui.h"                     // PrintAndLogEx
#include "util.h"                   // sprint_hex_inrow

#define NORTIC_CI_HEADER_SIZE   16

// Days from 1970-01-01 to the EN 1545 date epoch of 1997-01-01
#define NORTIC_DAYS_TO_1997     9862

#define NORTIC_LABEL            "%-22s"

//-----------------------------------------------------------------------------
// Bit access
//
// EN 1545 packs fields most significant bit first, so bit 0 is the top bit of
// byte 0. This is the opposite of the RKF Type CL-1 layout in parserkf.c, where
// RKF-0022 section 7.4.1 numbers bits from the least significant end.
//-----------------------------------------------------------------------------

static uint64_t nortic_bits(const uint8_t *buf, uint16_t off, uint8_t len) {
    uint64_t v = 0;
    for (uint8_t k = 0; k < len; k++) {
        uint16_t b = off + k;
        v = (v << 1) | ((buf[b >> 3] >> (7 - (b & 7))) & 1);
    }
    return v;
}

static void nortic_set_bits(uint8_t *buf, uint16_t off, uint8_t len, uint64_t v) {
    for (uint8_t k = 0; k < len; k++) {
        uint16_t b = off + k;
        uint8_t bit = (v >> (len - 1 - k)) & 1;
        if (bit) {
            buf[b >> 3] |= (uint8_t)(1 << (7 - (b & 7)));
        } else {
            buf[b >> 3] &= (uint8_t)~(1 << (7 - (b & 7)));
        }
    }
}

//-----------------------------------------------------------------------------
// Card issuer header, file 0C of AID 578000, 16 bytes
//-----------------------------------------------------------------------------

#define NORTIC_OFF_COUNTRY      0
#define NORTIC_OFF_FORMAT       10
#define NORTIC_OFF_CHOICE       30
#define NORTIC_OFF_SERIAL       32
#define NORTIC_OFF_VALIDITY     64
#define NORTIC_OFF_OWNER        78
#define NORTIC_OFF_RETAILER     98
#define NORTIC_OFF_KEYVERSION   118
#define NORTIC_OFF_UNUSED       122

typedef struct {
    uint16_t country;
    uint32_t format;
    uint8_t choice;
    uint32_t serial;
    uint16_t validity_end;
    uint32_t owner;
    uint32_t retailer;
    uint8_t key_version;
    uint8_t unused;
} nortic_ci_t;

static void nortic_read_ci(const uint8_t *d, nortic_ci_t *c) {
    c->country      = (uint16_t)nortic_bits(d, NORTIC_OFF_COUNTRY, 10);
    c->format       = (uint32_t)nortic_bits(d, NORTIC_OFF_FORMAT, 20);
    c->choice       = (uint8_t)nortic_bits(d, NORTIC_OFF_CHOICE, 2);
    c->serial       = (uint32_t)nortic_bits(d, NORTIC_OFF_SERIAL, 32);
    c->validity_end = (uint16_t)nortic_bits(d, NORTIC_OFF_VALIDITY, 14);
    c->owner        = (uint32_t)nortic_bits(d, NORTIC_OFF_OWNER, 20);
    c->retailer     = (uint32_t)nortic_bits(d, NORTIC_OFF_RETAILER, 20);
    c->key_version  = (uint8_t)nortic_bits(d, NORTIC_OFF_KEYVERSION, 4);
    c->unused       = (uint8_t)nortic_bits(d, NORTIC_OFF_UNUSED, 6);
}

//-----------------------------------------------------------------------------
// Value decoding
//-----------------------------------------------------------------------------

static void nortic_civil_from_days(int32_t z, int *year, unsigned *month, unsigned *day) {
    z += 719468;
    int32_t era = ((z >= 0) ? z : (z - 146096)) / 146097;
    uint32_t doe = (uint32_t)(z - (era * 146097));
    uint32_t yoe = (doe - (doe / 1460) + (doe / 36524) - (doe / 146096)) / 365;
    int32_t y = (int32_t)yoe + (era * 400);
    uint32_t doy = doe - ((365 * yoe) + (yoe / 4) - (yoe / 100));
    uint32_t mp = ((5 * doy) + 2) / 153;
    *day = doy - (((153 * mp) + 2) / 5) + 1;
    *month = (mp < 10) ? (mp + 3) : (mp - 9);
    *year = y + ((*month <= 2) ? 1 : 0);
}

// EN 1545 date, day 0 is 1 January 1997
static void nortic_date_str(uint16_t v, char *out, size_t outlen) {
    int y;
    unsigned m, d;
    nortic_civil_from_days((int32_t)v + NORTIC_DAYS_TO_1997, &y, &m, &d);
    snprintf(out, outlen, "%04d-%02u-%02u", y, m, d);
}

static const char *nortic_country_name(uint16_t code) {
    switch (code) {
        case 208:
            return "Denmark";
        case 246:
            return "Finland";
        case 578:
            return "Norway";
        case 752:
            return "Sweden";
        default:
            return NULL;
    }
}

// The choice bitmap says which optional card identifier is present
static const char *nortic_choice_name(uint8_t choice) {
    switch (choice) {
        case 0:
            return "none";
        case 1:
            return "RFU";
        case 2:
            return "cardIDNumber32bits";
        default:
            return "RFU";
    }
}

//-----------------------------------------------------------------------------
// Transport application file map
//-----------------------------------------------------------------------------

static const struct {
    uint8_t fid;
    const char *name;
    const char *note;
} nortic_transport_files[] = {
    {0x01, "Product Retailer",  "384 bytes, written with key 4"},
    {0x02, "Service Provider",  "128 bytes, written with key 6"},
    {0x03, "Special Event",     "288 bytes, written with key 6"},
    {0x04, "Stored Value",      "value file, written with key 5"},
    {0x05, "General Event Log", "cyclic, 36 bytes per record"},
    {0x06, "SV Reload Log",     "cyclic, 32 bytes per record"},
    {0x0A, "Environment",       "32 bytes, written with key 2"},
    {0x0C, "Card Holder",       "32 bytes, written with key 3"},
};

static const char *nortic_transport_file_name(uint8_t fid) {
    for (size_t i = 0; i < ARRAYLEN(nortic_transport_files); i++) {
        if (nortic_transport_files[i].fid == fid) {
            return nortic_transport_files[i].name;
        }
    }
    return NULL;
}

//-----------------------------------------------------------------------------
// Lookup helpers
//-----------------------------------------------------------------------------

static const desfire_dump_app_t *nortic_find_app(const desfire_dump_t *dump, uint32_t aid) {
    if (dump == NULL) {
        return NULL;
    }
    for (uint8_t i = 0; i < dump->appcount && i < DESFIRE_MAX_APP_COUNT; i++) {
        if (dump->app[i].aid == aid) {
            return &dump->app[i];
        }
    }
    return NULL;
}

static const desfire_dump_file_t *nortic_find_file(const desfire_dump_app_t *app, uint8_t fid) {
    if (app == NULL) {
        return NULL;
    }
    for (uint8_t i = 0; i < app->filecount && i < DESFIRE_MAX_FILE_COUNT; i++) {
        if (app->files[i].num == fid) {
            return &app->files[i];
        }
    }
    return NULL;
}

//-----------------------------------------------------------------------------
// Detection
//-----------------------------------------------------------------------------

bool is_valid_nortic_card(const desfire_dump_t *dump) {
    return (nortic_find_app(dump, NORTIC_AID_CARD_ISSUER) != NULL);
}

//-----------------------------------------------------------------------------
// Printing
//-----------------------------------------------------------------------------

static void nortic_print_ci(const nortic_ci_t *c) {

    char buf[32];
    const char *country = nortic_country_name(c->country);

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Card issuer header") " --- AID %06X file %02X",
                  NORTIC_AID_CARD_ISSUER, NORTIC_FID_CI_HEADER);

    PrintAndLogEx(INFO, NORTIC_LABEL " %u  ( %s )", "Country code", c->country,
                  country ? country : "unknown");
    PrintAndLogEx(INFO, NORTIC_LABEL " %u", "Format", c->format);
    PrintAndLogEx(INFO, NORTIC_LABEL " %u  ( %s )", "Choice bitmap", c->choice,
                  nortic_choice_name(c->choice));
    PrintAndLogEx(INFO, NORTIC_LABEL " " _YELLOW_("%u") "  ( %08X )", "Card serial number",
                  c->serial, c->serial);

    nortic_date_str(c->validity_end, buf, sizeof(buf));
    PrintAndLogEx(INFO, NORTIC_LABEL " " _YELLOW_("%s") "  ( day %u )", "Valid until", buf,
                  c->validity_end);

    PrintAndLogEx(INFO, NORTIC_LABEL " %u", "App owner company", c->owner);
    PrintAndLogEx(INFO, NORTIC_LABEL " %u", "Retailer organisation", c->retailer);
    PrintAndLogEx(INFO, NORTIC_LABEL " %u", "Card key version", c->key_version);

    if (c->unused != 0) {
        PrintAndLogEx(INFO, NORTIC_LABEL " %u  ( " _YELLOW_("expected 0") " )", "Unused bits", c->unused);
    }
}

static void nortic_print_transport(const desfire_dump_app_t *app) {

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Transport application") " --- AID %06X", NORTIC_AID_TRANSPORT);

    if (app == NULL) {
        PrintAndLogEx(INFO, "Not present on this card");
        return;
    }

    PrintAndLogEx(INFO, " fid | file                | read");
    PrintAndLogEx(INFO, "-----+---------------------+---------------------------------------");

    for (uint8_t i = 0; i < app->filecount && i < DESFIRE_MAX_FILE_COUNT; i++) {

        const desfire_dump_file_t *f = &app->files[i];
        const char *name = nortic_transport_file_name(f->num);

        PrintAndLogEx(INFO, "  %02X | %-19s | %s", f->num, name ? name : "unknown",
                      f->read_ok ? _GREEN_("read") : _YELLOW_("not read, needs key 7"));
    }

    PrintAndLogEx(INFO, "-----+---------------------+---------------------------------------");

    // Contents are only printed as hex. The field layouts of these files are in
    // Handbok V821 Del 18, which is not published.
    for (uint8_t i = 0; i < app->filecount && i < DESFIRE_MAX_FILE_COUNT; i++) {

        const desfire_dump_file_t *f = &app->files[i];
        if (f->read_ok == false || f->data == NULL || f->datalen == 0) {
            continue;
        }

        const char *name = nortic_transport_file_name(f->num);
        PrintAndLogEx(INFO, "");
        PrintAndLogEx(INFO, "file %02X  %s  %u bytes  " _YELLOW_("not decoded"), f->num,
                      name ? name : "unknown", f->datalen);

        for (uint32_t off = 0; off < f->datalen; off += 16) {
            uint32_t n = (f->datalen - off < 16) ? (f->datalen - off) : 16;
            PrintAndLogEx(INFO, "  %04X  %s", off, sprint_hex_inrow(f->data + off, n));
        }
    }
}

//-----------------------------------------------------------------------------
// Top level
//-----------------------------------------------------------------------------

int nortic_parser_parse(const desfire_dump_t *dump) {

    const desfire_dump_app_t *ci = nortic_find_app(dump, NORTIC_AID_CARD_ISSUER);
    if (ci == NULL) {
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("NORTIC travel card") " ------------------------");
    PrintAndLogEx(INFO, "Norwegian Ticketing Interoperable Concept");

    const desfire_dump_file_t *f = nortic_find_file(ci, NORTIC_FID_CI_HEADER);

    if (f == NULL) {
        PrintAndLogEx(INFO, "");
        PrintAndLogEx(INFO, "Card issuer header (file %02X) is not in this dump",
                      NORTIC_FID_CI_HEADER);
    } else if (f->read_ok == false || f->data == NULL) {
        PrintAndLogEx(INFO, "");
        PrintAndLogEx(INFO, "Card issuer header was not read. It needs no key, so retry the dump");
    } else if (f->datalen < NORTIC_CI_HEADER_SIZE) {
        PrintAndLogEx(INFO, "");
        PrintAndLogEx(INFO, "Card issuer header is %u bytes, expected %u", f->datalen,
                      NORTIC_CI_HEADER_SIZE);
    } else {
        nortic_ci_t c;
        nortic_read_ci(f->data, &c);
        nortic_print_ci(&c);

        if (c.country != NORTIC_COUNTRY_NORWAY) {
            PrintAndLogEx(INFO, "");
            PrintAndLogEx(WARNING, "Country code is %u, not %u. The layout below is the",
                          c.country, NORTIC_COUNTRY_NORWAY);
            PrintAndLogEx(WARNING, "Norwegian one and may not hold.");
        }
    }

    nortic_print_transport(nortic_find_app(dump, NORTIC_AID_TRANSPORT));

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Transport application layouts are in Handbok V821 Del 18, which is");
    PrintAndLogEx(INFO, "not published. Its files also need read key 7, which is not public");
    return PM3_SUCCESS;
}

//-----------------------------------------------------------------------------
// Self test
//-----------------------------------------------------------------------------

static bool nortic_check(const char *what, uint64_t got, uint64_t want) {
    bool ok = (got == want);
    PrintAndLogEx(INFO, "  %-24s %12llu  ( %s )", what, (unsigned long long)got,
                  ok ? _GREEN_("ok") : _RED_("fail"));
    return ok;
}

int nortic_selftest(void) {

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing NORTIC card issuer header decode");

    // The published card issuer header, with the serial number filled in where
    // the capture redacted it
    const uint8_t ci[NORTIC_CI_HEADER_SIZE] = {
        0x90, 0x80, 0x00, 0x02, 0xAA, 0xBB, 0xCC, 0xDD,
        0x6C, 0x68, 0x00, 0x28, 0x00, 0x02, 0x80, 0x40
    };

    nortic_ci_t c;
    nortic_read_ci(ci, &c);

    bool ok = true;
    ok &= nortic_check("country code", c.country, NORTIC_COUNTRY_NORWAY);
    ok &= nortic_check("format", c.format, 0);
    ok &= nortic_check("choice bitmap", c.choice, 2);
    ok &= nortic_check("card serial number", c.serial, 0xAABBCCDD);
    ok &= nortic_check("validity end day", c.validity_end, 6938);
    ok &= nortic_check("app owner company", c.owner, 160);
    ok &= nortic_check("retailer organisation", c.retailer, 160);
    ok &= nortic_check("card key version", c.key_version, 1);
    ok &= nortic_check("unused bits", c.unused, 0);

    char buf[32];
    nortic_date_str(c.validity_end, buf, sizeof(buf));
    bool dok = (strcmp(buf, "2015-12-31") == 0);
    PrintAndLogEx(INFO, "  %-24s %12s  ( %s )", "validity end date", buf,
                  dok ? _GREEN_("ok") : _RED_("fail"));
    ok &= dok;

    // EN 1545 is most significant bit first. Reading it the RKF way gives 144,
    // so a wrong bit order cannot pass unnoticed.
    uint64_t lsb = 0;
    for (uint8_t k = 0; k < 10; k++) {
        if ((ci[k >> 3] >> (k & 7)) & 1) {
            lsb |= (uint64_t)1 << k;
        }
    }
    ok &= nortic_check("lsb first would give", lsb, 144);

    // round trip through the encoder
    uint8_t enc[NORTIC_CI_HEADER_SIZE] = {0};
    nortic_set_bits(enc, NORTIC_OFF_COUNTRY, 10, c.country);
    nortic_set_bits(enc, NORTIC_OFF_FORMAT, 20, c.format);
    nortic_set_bits(enc, NORTIC_OFF_CHOICE, 2, c.choice);
    nortic_set_bits(enc, NORTIC_OFF_SERIAL, 32, c.serial);
    nortic_set_bits(enc, NORTIC_OFF_VALIDITY, 14, c.validity_end);
    nortic_set_bits(enc, NORTIC_OFF_OWNER, 20, c.owner);
    nortic_set_bits(enc, NORTIC_OFF_RETAILER, 20, c.retailer);
    nortic_set_bits(enc, NORTIC_OFF_KEYVERSION, 4, c.key_version);
    nortic_set_bits(enc, NORTIC_OFF_UNUSED, 6, c.unused);

    bool rok = (memcmp(enc, ci, NORTIC_CI_HEADER_SIZE) == 0);
    PrintAndLogEx(INFO, "  %-24s %12s  ( %s )", "re-encodes to the same 16 B",
                  sprint_hex_inrow(enc, 4), rok ? _GREEN_("ok") : _RED_("fail"));
    ok &= rok;

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "NORTIC self test ( %s )", ok ? _GREEN_("ok") : _RED_("fail"));
    return ok ? PM3_SUCCESS : PM3_ESOFT;
}
