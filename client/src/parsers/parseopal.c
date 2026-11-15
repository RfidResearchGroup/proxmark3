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
// Opal (Sydney) parser for MIFARE DESFire dumps
//-----------------------------------------------------------------------------

#include "parseopal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ui.h"                 // PrintAndLogEx
#include "parsetransit.h"

#define OPAL_CARD_LEN           16
#define OPAL_SERIAL_BASE        3085220000000000ULL

typedef struct {
    uint16_t checksum;
    uint8_t weekly_trips;
    bool auto_topup;
    uint8_t action;
    uint8_t mode;
    uint16_t minute;
    uint16_t day;               // days since 1980-01-01, Sydney local time
    int32_t balance;            // cents
    uint16_t txn_number;
    uint8_t last_digit;
    uint32_t serial;
} opal_card_t;

static const char *opal_mode_str(uint8_t m) {
    switch (m) {
        case 0:
            return "rail";
        case 1:
            return "ferry / light rail";
        case 2:
            return "bus";
        default:
            return "unknown";
    }
}

static const char *opal_action_str(uint8_t a) {
    static const char *actions[] = {
        "none",
        "new journey",
        "transfer, same mode",
        "transfer, other mode",
        "Manly ferry, new journey",
        "Manly ferry, transfer same mode",
        "Manly ferry, transfer other mode",
        "journey completed, distance fare",
        "journey completed, flat rate",
        "journey completed, automatic on",
        "journey completed, automatic off",
        "tap on reversal",
        "tap on rejected",
    };
    return (a < 13) ? actions[a] : "unknown";
}

static const desfire_dump_app_t *opal_find_app(const desfire_dump_t *dump) {
    if (dump == NULL) {
        return NULL;
    }
    for (uint8_t i = 0; i < dump->appcount && i < DESFIRE_MAX_APP_COUNT; i++) {
        if (dump->app[i].aid == OPAL_AID) {
            return &dump->app[i];
        }
    }
    return NULL;
}

static const desfire_dump_file_t *opal_find_file(const desfire_dump_app_t *app, uint8_t fid) {
    for (uint8_t i = 0; i < app->filecount && i < DESFIRE_MAX_FILE_COUNT; i++) {
        if (app->files[i].num == fid) {
            return &app->files[i];
        }
    }
    return NULL;
}

// The 16 bytes read as one little endian 128 bit number, field 0 at the top
static void opal_decode(const uint8_t *raw, opal_card_t *c) {
    uint8_t d[OPAL_CARD_LEN];
    for (int i = 0; i < OPAL_CARD_LEN; i++) {
        d[i] = raw[OPAL_CARD_LEN - 1 - i];
    }
    c->checksum     = (uint16_t)transit_bits_be(d, sizeof(d), 0, 16);
    c->weekly_trips = (uint8_t)transit_bits_be(d, sizeof(d), 16, 4);
    c->auto_topup   = transit_bits_be(d, sizeof(d), 20, 1);
    c->action       = (uint8_t)transit_bits_be(d, sizeof(d), 21, 4);
    c->mode         = (uint8_t)transit_bits_be(d, sizeof(d), 25, 3);
    c->minute       = (uint16_t)transit_bits_be(d, sizeof(d), 28, 11);
    c->day          = (uint16_t)transit_bits_be(d, sizeof(d), 39, 15);
    c->balance      = (int32_t)transit_sign_extend(transit_bits_be(d, sizeof(d), 54, 21), 21);
    c->txn_number   = (uint16_t)transit_bits_be(d, sizeof(d), 75, 16);
    c->last_digit   = (uint8_t)transit_bits_be(d, sizeof(d), 92, 4);
    c->serial       = (uint32_t)transit_bits_be(d, sizeof(d), 96, 32);
}

static void opal_serial_str(char *out, size_t outlen, const opal_card_t *c) {
    uint64_t n = OPAL_SERIAL_BASE + ((uint64_t)c->serial * 10) + c->last_digit;
    snprintf(out, outlen, "%04u %04u %04u %04u",
             (unsigned)(n / 1000000000000ULL), (unsigned)((n / 100000000ULL) % 10000),
             (unsigned)((n / 10000) % 10000), (unsigned)(n % 10000));
}

static void opal_time_str(char *out, size_t outlen, const opal_card_t *c) {
    int64_t secs = (((int64_t)TRANSIT_DAYS_TO_1980 + c->day) * 86400) + ((int64_t)c->minute * 60);
    transit_datetime_str(out, outlen, secs);
    // minutes only
    size_t n = strlen(out);
    if (n > 3) {
        out[n - 3] = '\0';
    }
}

transit_id_t opal_identify(const transit_mfdes_info_t *info) {
    return (transit_mfdes_info_has_aid(info, OPAL_AID)) ? TRANSIT_ID_MATCH : TRANSIT_ID_NONE;
}

bool is_valid_opal_card(const desfire_dump_t *dump) {
    transit_mfdes_info_t info;
    transit_mfdes_info_from_dump(dump, &info);
    return opal_identify(&info) == TRANSIT_ID_MATCH;
}

int opal_parser_parse(const desfire_dump_t *dump) {

    const desfire_dump_app_t *app = opal_find_app(dump);
    if (app == NULL) {
        return PM3_EINVARG;
    }

    transit_print_header("Opal");
    transit_print_kv("Issuer", "Transport for NSW, Sydney");

    const desfire_dump_file_t *f = opal_find_file(app, OPAL_FID_CARD);
    if (f == NULL || f->read_ok == false || f->data == NULL || f->datalen < OPAL_CARD_LEN) {
        PrintAndLogEx(HINT, "Hint: Use `" _YELLOW_("hf mfdes dump --no-auth") "`");
        return PM3_SUCCESS;
    }

    opal_card_t c;
    opal_decode(f->data, &c);

    char buf[40];
    opal_serial_str(buf, sizeof(buf), &c);
    transit_print_kv("Serial", _YELLOW_("%s"), buf);
    transit_money_str(buf, sizeof(buf), c.balance, 2, "AUD");
    transit_print_kv("Balance", _GREEN_("%s"), buf);
    transit_print_kv("Auto top up", "%s", c.auto_topup ? "yes" : "no");
    transit_print_kv("Weekly trips", "%u", c.weekly_trips);

    transit_print_header("Opal last transaction");
    opal_time_str(buf, sizeof(buf), &c);
    transit_print_kv("Date", "%s Sydney time", buf);
    transit_print_kv("Mode", "%s", opal_mode_str(c.mode));
    transit_print_kv("Action", "%s", opal_action_str(c.action));
    transit_print_kv("Counter", "%u", c.txn_number);
    transit_print_kv("Checksum", "%04X", c.checksum);
    return PM3_SUCCESS;
}

//-----------------------------------------------------------------------------
// Self test, Metrodroid OpalTest and opal-transit-litter vectors
//-----------------------------------------------------------------------------

static bool opal_check_vector(const char *name, const uint8_t *raw, const char *serial, int32_t balance,
                              const char *when, uint8_t mode, uint8_t action, uint16_t txn, uint8_t weekly) {
    opal_card_t c;
    opal_decode(raw, &c);
    char buf[40];
    bool ok = true;
    PrintAndLogEx(INFO, "  %s", name);
    opal_serial_str(buf, sizeof(buf), &c);
    ok &= transit_check_str("serial", buf, serial);
    ok &= transit_check("balance + 1000", (uint64_t)(c.balance + 1000), (uint64_t)(balance + 1000));
    opal_time_str(buf, sizeof(buf), &c);
    ok &= transit_check_str("last transaction", buf, when);
    ok &= transit_check("mode", c.mode, mode);
    ok &= transit_check("action", c.action, action);
    ok &= transit_check("counter", c.txn_number, txn);
    ok &= transit_check("weekly trips", c.weekly_trips, weekly);
    return ok;
}

int opal_selftest(void) {

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing Opal decode");

    // mocked data, 2015-10-05 09:06 Sydney
    static uint8_t demo[OPAL_CARD_LEN] = {
        0x87, 0xd6, 0x12, 0x00, 0xe0, 0x04, 0x00, 0x2a, 0x00, 0x14, 0xcc, 0x44, 0xa4, 0x13, 0x39, 0x30
    };
    // real card thrown away in litter
    static uint8_t litter[OPAL_CARD_LEN] = {
        0x60, 0xe0, 0x77, 0x00, 0xa2, 0x02, 0x40, 0xe9, 0xff, 0xff, 0xca, 0xa0, 0x88, 0x23, 0x64, 0x31
    };

    bool ok = true;
    ok &= opal_check_vector("demo card", demo, "3085 2200 1234 5670", 336, "2015-10-05 09:06", 2, 7, 39, 1);
    ok &= opal_check_vector("litter card", litter, "3085 2200 7856 2242", -182, "2015-07-27 18:24", 0, 7, 21, 2);

    opal_card_t c;
    opal_decode(litter, &c);
    ok &= transit_check("litter checksum", c.checksum, 12644);

    desfire_dump_t *dump = calloc(1, sizeof(desfire_dump_t));
    if (dump == NULL) {
        return PM3_EMALLOC;
    }
    dump->appcount = 1;
    dump->app[0].aid = OPAL_AID;
    dump->app[0].filecount = 1;
    dump->app[0].files[0].num = OPAL_FID_CARD;
    dump->app[0].files[0].read_ok = true;
    dump->app[0].files[0].data = litter;
    dump->app[0].files[0].datalen = sizeof(litter);
    ok &= transit_check("detected", is_valid_opal_card(dump), true);
    ok &= transit_mfdes_check_identify("identify", dump, "Opal", TRANSIT_ID_MATCH);
    if (ok) {
        opal_parser_parse(dump);
    }
    dump->app[0].aid = 0xF21190;
    ok &= transit_check("other AID rejected", is_valid_opal_card(dump), false);
    ok &= transit_mfdes_check_identify("not identified", dump, "Opal", TRANSIT_ID_NONE);
    free(dump);

    return transit_selftest_result("Opal", ok);
}
