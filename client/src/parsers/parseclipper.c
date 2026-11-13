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
// Clipper (San Francisco Bay Area) parser for MIFARE DESFire dumps
//-----------------------------------------------------------------------------

#include "parseclipper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "commonutil.h"         // ARRAYLEN, MemBeToUint
#include "ui.h"                 // PrintAndLogEx
#include "util.h"               // sprint_hex_inrow
#include "parsetransit.h"

#define CLIPPER_RECORD_LEN      32
#define CLIPPER_MAX_RECORDS     64

// Timestamps count seconds, the expiry days, both from 1900-01-01 UTC
#define CLIPPER_EPOCH_OFFSET    2208988800LL
#define CLIPPER_DAYS_TO_1970    25567

#define CLIPPER_AGENCY_BART     0x0004

typedef struct {
    uint16_t id;
    const char *name;
} clipper_name_t;

static const clipper_name_t clipper_agencies[] = {
    {0x0001, "AC Transit"},
    {0x0004, "BART"},
    {0x0006, "Caltrain"},
    {0x0008, "CCTA"},
    {0x000b, "GGT"},
    {0x000c, "SMART"},
    {0x000f, "SamTrans"},
    {0x0011, "VTA"},
    {0x0012, "Muni"},
    {0x0019, "GG Ferry"},
    {0x001b, "SF Bay Ferry"},
};

static const clipper_name_t clipper_bart_stations[] = {
    {0x0001, "Colma"},
    {0x0002, "Daly City"},
    {0x0003, "Balboa Park"},
    {0x0004, "Glen Park"},
    {0x0005, "24th St Mission"},
    {0x0006, "16th St Mission"},
    {0x0007, "Civic Center/UN Plaza"},
    {0x0008, "Powell St"},
    {0x0009, "Montgomery St"},
    {0x000a, "Embarcadero"},
    {0x000b, "West Oakland"},
    {0x000c, "12th St/Oakland City Center"},
    {0x000d, "19th St/Oakland"},
    {0x000e, "MacArthur"},
    {0x000f, "Rockridge"},
    {0x0010, "Orinda"},
    {0x0011, "Lafayette"},
    {0x0012, "Walnut Creek"},
    {0x0013, "Pleasant Hill/Contra Costa Centre"},
    {0x0014, "Concord"},
    {0x0015, "North Concord/Martinez"},
    {0x0016, "Pittsburg/Bay Point"},
    {0x0017, "Ashby"},
    {0x0018, "Downtown Berkeley"},
    {0x0019, "North Berkeley"},
    {0x001a, "El Cerrito Plaza"},
    {0x001b, "El Cerrito Del Norte"},
    {0x001c, "Richmond"},
    {0x001d, "Lake Merritt"},
    {0x001e, "Fruitvale"},
    {0x001f, "Coliseum"},
    {0x0020, "San Leandro"},
    {0x0021, "Bay Fair"},
    {0x0022, "Hayward"},
    {0x0023, "South Hayward"},
    {0x0024, "Union City"},
    {0x0025, "Fremont"},
    {0x0026, "Castro Valley"},
    {0x0027, "Dublin/Pleasanton"},
    {0x0028, "South San Francisco"},
    {0x0029, "San Bruno"},
    {0x002a, "SFO Airport"},
    {0x002b, "Millbrae"},
    {0x002c, "West Dublin/Pleasanton"},
    {0x002d, "OAK Airport"},
    {0x002e, "Warm Springs/South Fremont"},
    {0x002f, "Milpitas"},
    {0x0030, "Berryessa/North San Jose"},
};

typedef struct {
    uint16_t agency;
    int16_t fare;
    uint16_t vehicle;
    uint32_t start;
    uint32_t end;
    uint16_t from;
    uint16_t to;
    uint16_t route;
    uint16_t transport;
} clipper_trip_t;

//-----------------------------------------------------------------------------
// Dump access
//-----------------------------------------------------------------------------

static const desfire_dump_app_t *clipper_find_app(const desfire_dump_t *dump) {
    if (dump == NULL) {
        return NULL;
    }
    for (uint8_t i = 0; i < dump->appcount && i < DESFIRE_MAX_APP_COUNT; i++) {
        if (dump->app[i].aid == CLIPPER_AID_CARD || dump->app[i].aid == CLIPPER_AID_MOBILE) {
            return &dump->app[i];
        }
    }
    return NULL;
}

static const desfire_dump_file_t *clipper_find_file(const desfire_dump_app_t *app, uint8_t fid) {
    for (uint8_t i = 0; i < app->filecount && i < DESFIRE_MAX_FILE_COUNT; i++) {
        if (app->files[i].num == fid) {
            return &app->files[i];
        }
    }
    return NULL;
}

// File contents when read and at least minlen long, NULL otherwise
static const uint8_t *clipper_file_data(const desfire_dump_app_t *app, uint8_t fid, uint32_t minlen, uint32_t *len) {
    const desfire_dump_file_t *f = clipper_find_file(app, fid);
    if (f == NULL || f->read_ok == false || f->data == NULL || f->datalen < minlen) {
        return NULL;
    }
    if (len != NULL) {
        *len = f->datalen;
    }
    return f->data;
}

//-----------------------------------------------------------------------------
// Decoding
//-----------------------------------------------------------------------------

static const char *clipper_lookup(const clipper_name_t *t, size_t n, uint16_t id) {
    for (size_t i = 0; i < n; i++) {
        if (t[i].id == id) {
            return t[i].name;
        }
    }
    return NULL;
}

static const char *clipper_agency_name(uint16_t agency) {
    const char *s = clipper_lookup(clipper_agencies, ARRAYLEN(clipper_agencies), agency);
    return (s != NULL) ? s : "unknown";
}

static void clipper_station_str(char *out, size_t outlen, uint16_t agency, uint16_t station) {
    const char *s = NULL;
    if (agency == CLIPPER_AGENCY_BART) {
        s = clipper_lookup(clipper_bart_stations, ARRAYLEN(clipper_bart_stations), station);
    }
    if (s != NULL) {
        snprintf(out, outlen, "%s", s);
    } else {
        snprintf(out, outlen, "%04X", station);
    }
}

// Newer Muni readers store a 4 digit vehicle number and a letter, 20461 is 2046A
static void clipper_vehicle_str(char *out, size_t outlen, uint16_t v) {
    if (v == 0 || v == 0xFFFF) {
        snprintf(out, outlen, "-");
    } else if (v <= 9999) {
        snprintf(out, outlen, "%u", v);
    } else {
        snprintf(out, outlen, "%u%X", v / 10, (v % 10) + 9);
    }
}

static const char *clipper_mode_str(uint16_t transport, uint16_t agency) {
    switch (transport) {
        case 0x62:
            if (agency == 0x19 || agency == 0x1b) {
                return "ferry";
            }
            if (agency == 0x06 || agency == 0x0c) {
                return "train";
            }
            return "tram";
        case 0x6f:
            return "metro";
        case 0x61:
        case 0x75:
        case 0x77:
            return "bus";
        case 0x73:
            return "ferry";
        case 0x78:
            return "train";
        default:
            return "other";
    }
}

static void clipper_time_str(char *out, size_t outlen, uint32_t t) {
    if (t == 0) {
        snprintf(out, outlen, "-");
        return;
    }
    transit_datetime_str(out, outlen, (int64_t)t - CLIPPER_EPOCH_OFFSET);
}

static void clipper_read_trip(const uint8_t *r, clipper_trip_t *t) {
    t->agency    = MemBeToUint2byte(r + 0x02);
    t->fare      = (int16_t)MemBeToUint2byte(r + 0x06);
    t->vehicle   = MemBeToUint2byte(r + 0x0A);
    t->start     = MemBeToUint4byte(r + 0x0C);
    t->end       = MemBeToUint4byte(r + 0x10);
    t->from      = MemBeToUint2byte(r + 0x14);
    t->to        = MemBeToUint2byte(r + 0x16);
    t->route     = MemBeToUint2byte(r + 0x1C);
    t->transport = MemBeToUint2byte(r + 0x1E);
}

static int clipper_trip_cmp(const void *a, const void *b) {
    uint32_t x = ((const clipper_trip_t *)a)->start;
    uint32_t y = ((const clipper_trip_t *)b)->start;
    return (x < y) ? 1 : (x > y) ? -1 : 0;
}

// Temporary records share the start time of the final one, keep the one with an exit
static size_t clipper_collect_trips(const uint8_t *d, uint32_t len, clipper_trip_t *out, size_t max) {
    size_t n = 0;
    for (uint32_t pos = 0; pos + CLIPPER_RECORD_LEN <= len; pos += CLIPPER_RECORD_LEN) {
        clipper_trip_t t;
        clipper_read_trip(d + pos, &t);
        if (t.agency == 0) {
            continue;
        }
        bool skip = false;
        for (size_t i = 0; i < n; i++) {
            if (out[i].start == t.start) {
                if (out[i].end == 0) {
                    out[i] = t;
                }
                skip = true;
                break;
            }
        }
        if (skip == false && n < max) {
            out[n++] = t;
        }
    }
    qsort(out, n, sizeof(clipper_trip_t), clipper_trip_cmp);
    return n;
}

//-----------------------------------------------------------------------------
// Detection and printing
//-----------------------------------------------------------------------------

transit_id_t clipper_identify(const transit_mfdes_info_t *info) {
    return (transit_mfdes_info_has_aid(info, CLIPPER_AID_CARD) || transit_mfdes_info_has_aid(info, CLIPPER_AID_MOBILE)) ? TRANSIT_ID_MATCH : TRANSIT_ID_NONE;
}

bool is_valid_clipper_card(const desfire_dump_t *dump) {
    transit_mfdes_info_t info;
    transit_mfdes_info_from_dump(dump, &info);
    return clipper_identify(&info) == TRANSIT_ID_MATCH;
}

static void clipper_print_trips(const desfire_dump_app_t *app) {
    uint32_t len = 0;
    const uint8_t *d = clipper_file_data(app, CLIPPER_FID_HISTORY, CLIPPER_RECORD_LEN, &len);
    if (d == NULL) {
        return;
    }

    clipper_trip_t *trips = calloc(CLIPPER_MAX_RECORDS, sizeof(clipper_trip_t));
    if (trips == NULL) {
        return;
    }
    size_t n = clipper_collect_trips(d, len, trips, CLIPPER_MAX_RECORDS);

    transit_print_header("Clipper trips, newest first");
    char ts[32], te[32], from[40], to[40], veh[16], fare[24];
    for (size_t i = 0; i < n; i++) {
        const clipper_trip_t *t = &trips[i];
        clipper_time_str(ts, sizeof(ts), t->start);
        clipper_time_str(te, sizeof(te), t->end);
        clipper_station_str(from, sizeof(from), t->agency, t->from);
        clipper_station_str(to, sizeof(to), t->agency, t->to);
        clipper_vehicle_str(veh, sizeof(veh), t->vehicle);
        transit_money_str(fare, sizeof(fare), t->fare, 2, "USD");
        PrintAndLogEx(INFO, "%s UTC  %-12s %-5s  fare " _YELLOW_("%s"), ts,
                      clipper_agency_name(t->agency), clipper_mode_str(t->transport, t->agency), fare);
        PrintAndLogEx(INFO, "    from %s  to %s  exit %s  vehicle %s  route %04X", from,
                      (t->end != 0) ? to : "-", te, veh, t->route);
    }
    if (n == 0) {
        PrintAndLogEx(INFO, "no trips recorded");
    }
    free(trips);
}

static void clipper_print_refills(const desfire_dump_app_t *app) {
    uint32_t len = 0;
    const uint8_t *d = clipper_file_data(app, CLIPPER_FID_REFILLS, CLIPPER_RECORD_LEN, &len);
    if (d == NULL) {
        return;
    }

    transit_print_header("Clipper refills");
    char ts[32], amount[24];
    int n = 0;
    for (uint32_t pos = 0; pos + CLIPPER_RECORD_LEN <= len; pos += CLIPPER_RECORD_LEN) {
        const uint8_t *r = d + pos;
        uint32_t t = MemBeToUint4byte(r + 0x04);
        if (t == 0) {
            continue;
        }
        uint16_t agency = MemBeToUint2byte(r + 0x02);
        clipper_time_str(ts, sizeof(ts), t);
        transit_money_str(amount, sizeof(amount), MemBeToUint2byte(r + 0x0E), 2, "USD");
        PrintAndLogEx(INFO, "%s UTC  " _YELLOW_("+%s") "  agency %04X ( %s )  machine %s", ts, amount,
                      agency, clipper_agency_name(agency), sprint_hex_inrow(r + 0x08, 4));
        n++;
    }
    if (n == 0) {
        PrintAndLogEx(INFO, "no refills recorded");
    }
}

int clipper_parser_parse(const desfire_dump_t *dump) {

    const desfire_dump_app_t *app = clipper_find_app(dump);
    if (app == NULL) {
        return PM3_EINVARG;
    }

    transit_print_header("Clipper");
    transit_print_kv("Issuer", "Metropolitan Transportation Commission, SF Bay Area");
    transit_print_kv("Application", "%06X ( %s )", app->aid,
                     (app->aid == CLIPPER_AID_MOBILE) ? "mobile device" : "card");

    bool any = false;
    const uint8_t *d = clipper_file_data(app, CLIPPER_FID_IDENTITY, 5, NULL);
    if (d != NULL) {
        transit_print_kv("Serial", _YELLOW_("%u"), MemBeToUint4byte(d + 1));
        any = true;
    }

    uint32_t len = 0;
    d = clipper_file_data(app, CLIPPER_FID_ECASH, 0x14, &len);
    if (d != NULL) {
        char buf[32];
        transit_money_str(buf, sizeof(buf), (int16_t)MemBeToUint2byte(d + 0x12), 2, "USD");
        transit_print_kv("Balance", _GREEN_("%s"), buf);
        uint32_t upd = MemBeToUint4byte(d + 0x04);
        clipper_time_str(buf, sizeof(buf), upd);
        transit_print_kv("Last update", "%s%s", buf, (upd != 0) ? " UTC" : "");
        transit_print_kv("Terminal", "%04X", MemBeToUint2byte(d + 0x08));
        transit_print_kv("Transaction id", "%u", MemBeToUint2byte(d + 0x10));
        transit_print_kv("Counter", "%u", MemBeToUint2byte(d + 0x02));
        any = true;
    }

    d = clipper_file_data(app, CLIPPER_FID_INFO, 10, NULL);
    if (d != NULL) {
        uint16_t exp = MemBeToUint2byte(d + 8);
        if (exp != 0) {
            char buf[16];
            transit_date_str(buf, sizeof(buf), (int32_t)exp - CLIPPER_DAYS_TO_1970);
            transit_print_kv("Expiry", "%s", buf);
        }
    }

    clipper_print_trips(app);
    clipper_print_refills(app);

    if (any == false) {
        PrintAndLogEx(HINT, "Hint: Use `" _YELLOW_("hf mfdes dump --no-auth") "`");
    }
    return PM3_SUCCESS;
}

//-----------------------------------------------------------------------------
// Self test, Metrodroid ClipperTest vectors
//-----------------------------------------------------------------------------

static void clipper_test_file(desfire_dump_file_t *f, uint8_t fid, uint8_t *data, uint32_t len) {
    f->num = fid;
    f->read_ok = true;
    f->data = data;
    f->datalen = len;
}

int clipper_selftest(void) {

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing Clipper decode");

    // mocked card from Metrodroid
    static uint8_t ecash[20] = {
        [0x12] = 0x77, [0x13] = 0x77
    };
    static uint8_t identity[] = { 0x00, 0x22, 0x22, 0x95, 0x33 };
    static uint8_t refill[CLIPPER_RECORD_LEN] = {
        0x00, 0x00, 0x02, 0xcf, 0xde, 0x44, 0x00, 0x00, 0x78, 0x12, 0x34, 0x56, 0x00, 0x00, 0x13, 0x88
    };
    static uint8_t trip[CLIPPER_RECORD_LEN] = {
        0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x02, 0x76, 0x00, 0x00, 0x00, 0x00, 0xde, 0x58, 0x00, 0x00,
        0xde, 0x58, 0x10, 0x00, 0x00, 0x08, 0x00, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6f
    };

    desfire_dump_t *dump = calloc(1, sizeof(desfire_dump_t));
    if (dump == NULL) {
        return PM3_EMALLOC;
    }
    dump->appcount = 1;
    desfire_dump_app_t *app = &dump->app[0];
    app->aid = CLIPPER_AID_CARD;
    app->filecount = 4;
    clipper_test_file(&app->files[0], CLIPPER_FID_ECASH, ecash, sizeof(ecash));
    clipper_test_file(&app->files[1], CLIPPER_FID_REFILLS, refill, sizeof(refill));
    clipper_test_file(&app->files[2], CLIPPER_FID_IDENTITY, identity, sizeof(identity));
    clipper_test_file(&app->files[3], CLIPPER_FID_HISTORY, trip, sizeof(trip));

    bool ok = true;
    ok &= transit_check("detected", is_valid_clipper_card(dump), true);
    ok &= transit_mfdes_check_identify("identify", dump, "Clipper", TRANSIT_ID_MATCH);

    transit_mfdes_info_t info;
    transit_mfdes_info_from_dump(dump, &info);
    transit_mfdes_file_t sf[4];
    ok &= transit_check("summary files", transit_mfdes_summary_files(&info, sf, ARRAYLEN(sf)), 2);
    ok &= transit_check("serial", MemBeToUint4byte(clipper_file_data(app, CLIPPER_FID_IDENTITY, 5, NULL) + 1), 572691763);
    ok &= transit_check("balance cents", (uint16_t)MemBeToUint2byte(ecash + 0x12), 30583);

    char buf[40];
    clipper_time_str(buf, sizeof(buf), MemBeToUint4byte(refill + 4));
    ok &= transit_check_str("refill time", buf, "2018-03-02 16:53:20");
    ok &= transit_check("refill amount", MemBeToUint2byte(refill + 0x0E), 5000);

    clipper_trip_t t[2];
    ok &= transit_check("trip count", clipper_collect_trips(trip, sizeof(trip), t, ARRAYLEN(t)), 1);
    ok &= transit_check("trip agency", t[0].agency, CLIPPER_AGENCY_BART);
    ok &= transit_check("trip fare", (uint64_t)t[0].fare, 630);
    clipper_time_str(buf, sizeof(buf), t[0].start);
    ok &= transit_check_str("trip start", buf, "2018-03-17 20:58:40");
    clipper_station_str(buf, sizeof(buf), t[0].agency, t[0].from);
    ok &= transit_check_str("trip from", buf, "Powell St");
    clipper_station_str(buf, sizeof(buf), t[0].agency, t[0].to);
    ok &= transit_check_str("trip to", buf, "Dublin/Pleasanton");
    ok &= transit_check_str("trip mode", clipper_mode_str(t[0].transport, t[0].agency), "metro");

    // vehicle numbers from real cards
    clipper_vehicle_str(buf, sizeof(buf), 0x0422);
    ok &= transit_check_str("vehicle 0422", buf, "1058");
    clipper_vehicle_str(buf, sizeof(buf), 0x4e85);
    ok &= transit_check_str("vehicle 4E85", buf, "2010A");
    clipper_vehicle_str(buf, sizeof(buf), 0x5084);
    ok &= transit_check_str("vehicle 5084", buf, "2061B");
    clipper_vehicle_str(buf, sizeof(buf), 0xffff);
    ok &= transit_check_str("vehicle FFFF", buf, "-");

    app->aid = 0x534531;
    ok &= transit_check("other AID rejected", is_valid_clipper_card(dump), false);
    ok &= transit_mfdes_check_identify("not identified", dump, "Clipper", TRANSIT_ID_NONE);
    app->aid = CLIPPER_AID_CARD;

    if (ok) {
        clipper_parser_parse(dump);
    }

    free(dump);
    return transit_selftest_result("Clipper", ok);
}
