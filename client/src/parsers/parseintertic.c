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
// Intertic parser for ST25TB / SRT512 dumps
//-----------------------------------------------------------------------------

#include "parseintertic.h"

#include <string.h>

#include "commonutil.h"         // ARRAYLEN
#include "ui.h"                 // PrintAndLogEx
#include "parsetransit.h"

#define INTERTIC_STREAM_LEN     64      // blocks 0..15, the system block is not used
#define INTERTIC_PART_LEN       24

#define INTERTIC_COUNTRY_FRANCE     0x250
#define INTERTIC_COUNTRY_MOROCCO    0x504

//-----------------------------------------------------------------------------
// Usage record layouts, one per network family, offsets in bits after the
// 10 bit date and 11 bit time. -1 when the layout has no such field.
//-----------------------------------------------------------------------------

typedef enum {
    IT_USAGE_GENERIC = 0,
    IT_USAGE_1,
    IT_USAGE_1_1,
    IT_USAGE_1_2,
    IT_USAGE_2,
    IT_USAGE_2_1,
    IT_USAGE_2_2,
    IT_USAGE_3,
    IT_USAGE_4,
} intertic_usage_t;

typedef struct {
    int16_t nature_off;
    uint8_t nature_len;
    int16_t type_off;
    uint8_t type_len;
    int16_t vehicle_off;        // 16 bits
    int16_t route_off;          // 14 bits
    int16_t dir_off;            // 2 bits
    int16_t pass_off;           // 4 bits
    int16_t first_off;          // 11 bits
} intertic_layout_t;

// indexed by intertic_usage_t, generic falls back to layout 1
static const intertic_layout_t intertic_layouts[] = {
    { -1, 0, -1, 0, -1, -1, -1, -1, 86 },
    { -1, 0, -1, 0, -1, -1, -1, -1, 86 },
    { 29, 5, 34, 5, 50, 66, 80, 82, 86 },
    { 31, 4, 35, 4, 50, 66, 80, 82, 86 },
    { 29, 5, 34, 5, -1, 50, 64, 66, 70 },
    { 29, 5, 34, 5, 74, 58, 72, 90, 94 },
    { 29, 5, 34, 5, 66, 50, 64, 100, 86 },
    { -1, 0, -1, 0, -1, -1, -1, -1, 48 },
    { -1, 0, -1, 0, -1, -1, -1, -1, 84 },
};

typedef struct {
    uint16_t country;
    uint16_t authority;
    uint8_t provider;
    const char *city;
    const char *company;
    intertic_usage_t usage;
} intertic_network_t;

static const intertic_network_t intertic_networks[] = {
    { INTERTIC_COUNTRY_FRANCE, 0x000, 1, "Valenciennes", "Transvilles / Keolis", IT_USAGE_1_1 },
    { INTERTIC_COUNTRY_FRANCE, 0x000, 5, "Lille", "Ilevia / Keolis", IT_USAGE_1_1 },
    { INTERTIC_COUNTRY_FRANCE, 0x000, 7, "Lens-Bethune", "Tadao / Transdev", IT_USAGE_1_1 },
    { INTERTIC_COUNTRY_FRANCE, 0x006, 1, "Amiens", "Ametis / Keolis", IT_USAGE_GENERIC },
    { INTERTIC_COUNTRY_FRANCE, 0x008, 15, "Angouleme", "STGA", IT_USAGE_1_1 },
    { INTERTIC_COUNTRY_FRANCE, 0x013, 1, "Avignon", "Orizo", IT_USAGE_GENERIC },
    { INTERTIC_COUNTRY_FRANCE, 0x021, 1, "Bordeaux", "TBM / Keolis", IT_USAGE_1_1 },
    { INTERTIC_COUNTRY_FRANCE, 0x040, 28, "Colmar", "Trace / Keolis", IT_USAGE_1_1 },
    { INTERTIC_COUNTRY_FRANCE, 0x057, 1, "Lyon", "TCL / Keolis", IT_USAGE_1 },
    { INTERTIC_COUNTRY_FRANCE, 0x072, 1, "Tours", "filbleu / Keolis", IT_USAGE_1_1 },
    { INTERTIC_COUNTRY_FRANCE, 0x078, 4, "Reims", "Citura / Transdev", IT_USAGE_1_2 },
    { INTERTIC_COUNTRY_FRANCE, 0x091, 1, "Strasbourg", "CTS", IT_USAGE_4 },
    { INTERTIC_COUNTRY_FRANCE, 0x091, 5, "Strasbourg", "CTS / new", IT_USAGE_4 },
    { INTERTIC_COUNTRY_FRANCE, 0x502, 83, "Annecy", "Sibra", IT_USAGE_2 },
    { INTERTIC_COUNTRY_FRANCE, 0x502, 84, "Bourg-en-Bresse", "Rubis / Keolis", IT_USAGE_GENERIC },
    { INTERTIC_COUNTRY_FRANCE, 0x502, 10, "Clermont-Ferrand", "T2C", IT_USAGE_2_2 },
    { INTERTIC_COUNTRY_FRANCE, 0x907, 1, "Dijon", "Divia / Keolis", IT_USAGE_GENERIC },
    { INTERTIC_COUNTRY_FRANCE, 0x908, 1, "Rennes", "STAR / Keolis", IT_USAGE_2 },
    { INTERTIC_COUNTRY_FRANCE, 0x908, 8, "Saint-Malo", "MAT / RATP", IT_USAGE_1_1 },
    { INTERTIC_COUNTRY_FRANCE, 0x911, 5, "Besancon", "Ginko / Keolis", IT_USAGE_GENERIC },
    { INTERTIC_COUNTRY_FRANCE, 0x912, 3, "Le Havre", "Lia / Transdev", IT_USAGE_1_1 },
    { INTERTIC_COUNTRY_FRANCE, 0x912, 29, "Caen", "Twisto / RATP", IT_USAGE_2 },
    { INTERTIC_COUNTRY_FRANCE, 0x912, 35, "Cherbourg-en-Cotentin", "Cap Cotentin / Transdev", IT_USAGE_GENERIC },
    { INTERTIC_COUNTRY_FRANCE, 0x913, 3, "Nimes", "Tango / Transdev", IT_USAGE_3 },
    { INTERTIC_COUNTRY_FRANCE, 0x915, 1, "Metz", "Le Met' / TAMM", IT_USAGE_GENERIC },
    { INTERTIC_COUNTRY_FRANCE, 0x917, 4, "Angers", "Irigo / RATP", IT_USAGE_1_2 },
    { INTERTIC_COUNTRY_FRANCE, 0x917, 7, "Saint-Nazaire", "Stran", IT_USAGE_GENERIC },
    { INTERTIC_COUNTRY_FRANCE, 0x920, 9, "Aix-en-Provence", "Aixenbus / Keolis", IT_USAGE_2_1 },
    { INTERTIC_COUNTRY_MOROCCO, 0x001, 1, "Casablanca", "Casa Transports / RATP", IT_USAGE_2_1 },
};

static const intertic_network_t *intertic_find_network(uint16_t country, uint16_t authority, uint8_t provider) {
    for (size_t i = 0; i < ARRAYLEN(intertic_networks); i++) {
        const intertic_network_t *n = &intertic_networks[i];
        if (n->country == country && n->authority == authority && n->provider == provider) {
            return n;
        }
    }
    return NULL;
}

static const char *intertic_nature_name(uint8_t v, bool reims) {
    if (reims) {
        // Reims swaps these two
        if (v == 0x4) {
            return "urban bus";
        }
        if (v == 0x1) {
            return "tramway";
        }
        return "?";
    }
    switch (v) {
        case 0x1:
            return "urban bus";
        case 0x2:
            return "interurban bus";
        case 0x3:
            return "metro";
        case 0x4:
            return "tramway";
        case 0x5:
            return "train";
        case 0x8:
            return "parking";
        default:
            return "?";
    }
}

static const char *intertic_type_name(uint8_t v) {
    switch (v) {
        case 0x01:
            return "entry validation";
        case 0x02:
            return "exit validation";
        case 0x04:
            return "ticket inspecting";
        case 0x06:
            return "connection entry validation";
        case 0x14:
            return "test validation";
        case 0x15:
            return "connection exit validation";
        case 0x16:
            return "canceled validation";
        case 0x17:
            return "invalidation";
        case 0x18:
            return "distribution";
        default:
            return "?";
    }
}

static const char *intertic_direction_name(uint8_t v) {
    static const char *const names[] = { "undefined", "outward", "inward", "circular" };
    return names[v & 3];
}

//-----------------------------------------------------------------------------
// Ticket layout. Each block is read least significant byte first, and the
// blocks then form one most significant bit first stream.
//-----------------------------------------------------------------------------

typedef struct {
    uint8_t key_id;
    uint8_t pid;
    uint8_t dist[INTERTIC_PART_LEN];
    uint8_t usage_a[INTERTIC_PART_LEN];
    uint8_t usage_b[INTERTIC_PART_LEN];
    uint16_t usage_bits;
    uint8_t reloading;
    uint32_t counter;
    uint32_t swap;
    uint16_t cer_a;
    uint16_t cer_b;
    uint32_t cer_dist;
} intertic_ticket_t;

typedef struct {
    uint16_t country;
    uint16_t authority;
    uint8_t version;
    uint8_t provider;
    uint16_t tariff;
    uint16_t end_date;
} intertic_dist_t;

static void intertic_stream(const uint8_t *data, uint8_t *stream) {
    for (size_t b = 0; b < INTERTIC_STREAM_LEN; b += 4) {
        stream[b + 0] = data[b + 3];
        stream[b + 1] = data[b + 2];
        stream[b + 2] = data[b + 1];
        stream[b + 3] = data[b + 0];
    }
}

static void intertic_copy(uint8_t *dst, uint16_t *dst_off, const uint8_t *stream, uint16_t off, uint16_t n) {
    for (uint16_t k = 0; k < n; k++) {
        uint64_t bit = transit_bits_be(stream, INTERTIC_STREAM_LEN, off + k, 1);
        transit_set_bits_be(dst, INTERTIC_PART_LEN, *dst_off + k, 1, bit);
    }
    *dst_off += n;
}

static bool intertic_pid_known(uint8_t pid) {
    return (pid == 0x10 || pid == 0x11 || pid == 0x19);
}

static bool intertic_split(const uint8_t *stream, intertic_ticket_t *t) {
    memset(t, 0, sizeof(*t));
    t->key_id = (uint8_t)transit_bits_be(stream, INTERTIC_STREAM_LEN, 23, 4);
    t->pid = (uint8_t)transit_bits_be(stream, INTERTIC_STREAM_LEN, 27, 5);
    if (intertic_pid_known(t->pid) == false) {
        return false;
    }

    uint16_t d = 0, a = 0, b = 0;
    if (t->pid == 0x10) {
        intertic_copy(t->dist, &d, stream, 32, 64);
        intertic_copy(t->dist, &d, stream, 0, 23);
        intertic_copy(t->usage_a, &a, stream, 96, 64);
        intertic_copy(t->usage_a, &a, stream, 224, 80);
        intertic_copy(t->usage_b, &b, stream, 320, 144);
        t->cer_a = (uint16_t)transit_bits_be(stream, INTERTIC_STREAM_LEN, 304, 16);
    } else {
        intertic_copy(t->dist, &d, stream, 32, 128);
        intertic_copy(t->dist, &d, stream, 0, 23);
        intertic_copy(t->usage_a, &a, stream, 224, 112);
        intertic_copy(t->usage_b, &b, stream, 352, 112);
        t->cer_a = (uint16_t)transit_bits_be(stream, INTERTIC_STREAM_LEN, 336, 16);
    }
    t->usage_bits = a;
    t->reloading = (uint8_t)transit_bits_be(stream, INTERTIC_STREAM_LEN, 160, 8);
    t->counter = (uint32_t)transit_bits_be(stream, INTERTIC_STREAM_LEN, 168, 24);
    t->swap = (uint32_t)transit_bits_be(stream, INTERTIC_STREAM_LEN, 192, 32);
    t->cer_b = (uint16_t)transit_bits_be(stream, INTERTIC_STREAM_LEN, 464, 16);
    t->cer_dist = (uint32_t)transit_bits_be(stream, INTERTIC_STREAM_LEN, 480, 32);
    return true;
}

static void intertic_read_dist(const uint8_t *p, intertic_dist_t *d) {
    d->country = (uint16_t)transit_bits_be(p, INTERTIC_PART_LEN, 0, 12);
    d->authority = (uint16_t)transit_bits_be(p, INTERTIC_PART_LEN, 12, 12);
    d->version = (uint8_t)transit_bits_be(p, INTERTIC_PART_LEN, 24, 6);
    d->provider = (uint8_t)transit_bits_be(p, INTERTIC_PART_LEN, 30, 8);
    d->tariff = (uint16_t)transit_bits_be(p, INTERTIC_PART_LEN, 38, 16);
    d->end_date = (uint16_t)transit_bits_be(p, INTERTIC_PART_LEN, 54, 14);
}

static bool intertic_decode(const uint8_t *data, size_t datalen, intertic_ticket_t *t, intertic_dist_t *d) {
    if (data == NULL || datalen != INTERTIC_DUMP_SIZE) {
        return false;
    }
    uint8_t stream[INTERTIC_STREAM_LEN];
    intertic_stream(data, stream);
    if (intertic_split(stream, t) == false) {
        return false;
    }
    intertic_read_dist(t->dist, d);
    return true;
}

//-----------------------------------------------------------------------------
// Detection and printing
//-----------------------------------------------------------------------------

bool is_valid_intertic_card(const uint8_t *data, size_t datalen, const uint8_t *uid) {
    (void)uid;
    intertic_ticket_t t;
    intertic_dist_t d;
    if (intertic_decode(data, datalen, &t, &d) == false) {
        return false;
    }
    return (d.country == INTERTIC_COUNTRY_FRANCE || d.country == INTERTIC_COUNTRY_MOROCCO);
}

static void intertic_print_usage(const char *title, const uint8_t *u, uint16_t cer, uint16_t end_date,
                                 intertic_usage_t usage, bool reims) {

    if (transit_is_zero(u, INTERTIC_PART_LEN)) {
        PrintAndLogEx(INFO, "");
        PrintAndLogEx(INFO, "%s ( empty )", title);
        return;
    }

    const intertic_layout_t *l = &intertic_layouts[usage];
    uint16_t day = (uint16_t)transit_bits_be(u, INTERTIC_PART_LEN, 0, 10);
    uint16_t time = (uint16_t)transit_bits_be(u, INTERTIC_PART_LEN, 10, 11);

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "%s", title);

    // dated backwards from the end of validity
    char s[24];
    transit_date_str(s, sizeof(s), TRANSIT_DAYS_TO_1997 + (int32_t)end_date - day);
    transit_print_kv("  Date", "%s %02u:%02u", s, time / 60, time % 60);

    if (l->nature_off >= 0) {
        uint8_t v = (uint8_t)transit_bits_be(u, INTERTIC_PART_LEN, l->nature_off, l->nature_len);
        transit_print_kv("  Nature", "0x%X ( %s )", v, intertic_nature_name(v, reims));
    }
    if (l->type_off >= 0) {
        uint8_t v = (uint8_t)transit_bits_be(u, INTERTIC_PART_LEN, l->type_off, l->type_len);
        transit_print_kv("  Type", "0x%X ( %s )", v, intertic_type_name(v));
    }
    if (l->route_off >= 0) {
        transit_print_kv("  Route", "%u", (unsigned)transit_bits_be(u, INTERTIC_PART_LEN, l->route_off, 14));
    }
    if (l->dir_off >= 0) {
        transit_print_kv("  Direction", "%s", intertic_direction_name((uint8_t)transit_bits_be(u, INTERTIC_PART_LEN, l->dir_off, 2)));
    }
    if (l->vehicle_off >= 0) {
        transit_print_kv("  Vehicle", "%u", (unsigned)transit_bits_be(u, INTERTIC_PART_LEN, l->vehicle_off, 16));
    }
    if (l->pass_off >= 0) {
        transit_print_kv("  Passengers (?)", "%u", (unsigned)transit_bits_be(u, INTERTIC_PART_LEN, l->pass_off, 4));
    }
    uint16_t first = (uint16_t)transit_bits_be(u, INTERTIC_PART_LEN, l->first_off, 11);
    transit_print_kv("  First valid.", "%02u:%02u", first / 60, first % 60);
    transit_print_kv("  Certificate", "%04X", cer);
}

int intertic_parser_parse(const uint8_t *data, size_t datalen, const uint8_t *uid) {

    if (is_valid_intertic_card(data, datalen, uid) == false) {
        return PM3_EINVARG;
    }

    intertic_ticket_t t;
    intertic_dist_t d;
    (void)intertic_decode(data, datalen, &t, &d);
    const intertic_network_t *n = intertic_find_network(d.country, d.authority, d.provider);

    transit_print_header("Intertic transport ticket");
    transit_print_kv("Country", "%03X ( %s )", d.country, (d.country == INTERTIC_COUNTRY_FRANCE) ? "France" : "Morocco");
    if (n != NULL) {
        transit_print_kv("Network", _YELLOW_("%s") " ( %s )", n->city, n->company);
    } else {
        transit_print_kv("Network", "unknown");
    }
    transit_print_kv("Authority", "%03X", d.authority);
    transit_print_kv("Provider", "%u", d.provider);
    transit_print_kv("Product id", "0x%02X, key id %u", t.pid, t.key_id);
    transit_print_kv("App version", "%u", d.version);
    transit_print_kv("Tariff", "%u", d.tariff);

    char s[24];
    transit_date_str(s, sizeof(s), TRANSIT_DAYS_TO_1997 + d.end_date);
    transit_print_kv("Valid until", _YELLOW_("%s"), s);
    transit_print_kv("Counter", _GREEN_("%u") " ( 0x%06X ), reloading 0x%02X", t.counter, t.counter, t.reloading);
    transit_print_kv("Last usage", "%c ( swap 0x%08X )", (t.swap & 1) ? 'B' : 'A', t.swap);
    transit_print_kv("Certificate", "%08X", t.cer_dist);

    intertic_usage_t usage = (n != NULL) ? n->usage : IT_USAGE_GENERIC;
    if (usage == IT_USAGE_GENERIC) {
        PrintAndLogEx(INFO, "Usage layout unknown for this network, decoded as the most common one");
    }
    bool reims = (usage == IT_USAGE_1_2 && n != NULL && n->authority == 0x078);
    intertic_print_usage("Usage A", t.usage_a, t.cer_a, d.end_date, usage, reims);
    intertic_print_usage("Usage B", t.usage_b, t.cer_b, d.end_date, usage, reims);
    return PM3_SUCCESS;
}

//-----------------------------------------------------------------------------
// Self test
//-----------------------------------------------------------------------------

static void intertic_stream_to_card(const uint8_t *stream, uint8_t *card) {
    memset(card, 0, INTERTIC_DUMP_SIZE);
    intertic_stream(stream, card);
    // system block, OTP lock bytes as delivered
    card[64] = 0xFF;
    card[65] = 0xFF;
    card[66] = 0xFF;
    card[67] = 0xFF;
}

int intertic_selftest(void) {

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing Intertic decode");

    bool ok = true;

    // PID 11, Rennes STAR: distribution fills 32..159 and then block 0 bits 0..22
    uint8_t s[INTERTIC_STREAM_LEN] = {0};
    transit_set_bits_be(s, sizeof(s), 23, 4, 0x3);
    transit_set_bits_be(s, sizeof(s), 27, 5, 0x11);
    transit_set_bits_be(s, sizeof(s), 32, 12, INTERTIC_COUNTRY_FRANCE);
    transit_set_bits_be(s, sizeof(s), 44, 12, 0x908);
    transit_set_bits_be(s, sizeof(s), 56, 6, 2);
    transit_set_bits_be(s, sizeof(s), 62, 8, 1);
    transit_set_bits_be(s, sizeof(s), 70, 16, 1234);
    transit_set_bits_be(s, sizeof(s), 86, 14, 10000);
    transit_set_bits_be(s, sizeof(s), 160, 8, 0x01);
    transit_set_bits_be(s, sizeof(s), 168, 24, 9);
    transit_set_bits_be(s, sizeof(s), 192, 32, 0x00000001);
    // usage A at 224: day 3 before the end, 08:30, metro entry, route 42, inward
    transit_set_bits_be(s, sizeof(s), 224 + 0, 10, 3);
    transit_set_bits_be(s, sizeof(s), 224 + 10, 11, 510);
    transit_set_bits_be(s, sizeof(s), 224 + 29, 5, 0x3);
    transit_set_bits_be(s, sizeof(s), 224 + 34, 5, 0x1);
    transit_set_bits_be(s, sizeof(s), 224 + 50, 14, 42);
    transit_set_bits_be(s, sizeof(s), 224 + 64, 2, 2);
    transit_set_bits_be(s, sizeof(s), 224 + 70, 11, 505);
    transit_set_bits_be(s, sizeof(s), 336, 16, 0xBEEF);
    transit_set_bits_be(s, sizeof(s), 480, 32, 0xCAFEF00D);

    uint8_t card[INTERTIC_DUMP_SIZE];
    intertic_stream_to_card(s, card);

    // PID sits in the low bits of the first byte as the card returns it
    ok &= transit_check("card byte 0 holds the PID", card[0] & 0x1F, 0x11);

    intertic_ticket_t t;
    intertic_dist_t d;
    ok &= transit_check("decodes", intertic_decode(card, sizeof(card), &t, &d), 1);
    ok &= transit_check("key id", t.key_id, 3);
    ok &= transit_check("country", d.country, INTERTIC_COUNTRY_FRANCE);
    ok &= transit_check("authority", d.authority, 0x908);
    ok &= transit_check("version", d.version, 2);
    ok &= transit_check("provider", d.provider, 1);
    ok &= transit_check("tariff", d.tariff, 1234);
    ok &= transit_check("end date", d.end_date, 10000);
    ok &= transit_check("counter", t.counter, 9);
    ok &= transit_check("usage A certificate", t.cer_a, 0xBEEF);
    ok &= transit_check("distribution certificate", t.cer_dist, 0xCAFEF00D);
    ok &= transit_check("usage A day", transit_bits_be(t.usage_a, INTERTIC_PART_LEN, 0, 10), 3);
    ok &= transit_check("usage A route", transit_bits_be(t.usage_a, INTERTIC_PART_LEN, intertic_layouts[IT_USAGE_2].route_off, 14), 42);

    char str[24];
    transit_date_str(str, sizeof(str), TRANSIT_DAYS_TO_1997 + d.end_date);
    ok &= transit_check_str("end date string", str, "2024-05-19");

    const intertic_network_t *n = intertic_find_network(d.country, d.authority, d.provider);
    ok &= transit_check_str("network", n ? n->city : NULL, "Rennes");
    ok &= transit_check("detected", is_valid_intertic_card(card, sizeof(card), NULL), 1);
    ok &= transit_st25tb_check_identify("identify", card, sizeof(card), "Intertic", TRANSIT_ID_POSSIBLE);
    ok &= transit_check("parse", (uint64_t)intertic_parser_parse(card, sizeof(card), NULL), PM3_SUCCESS);

    // PID 10, distribution runs 32..95 and on into block 0, usage A is split around the counter
    memset(s, 0, sizeof(s));
    transit_set_bits_be(s, sizeof(s), 27, 5, 0x10);
    transit_set_bits_be(s, sizeof(s), 32, 12, INTERTIC_COUNTRY_FRANCE);
    transit_set_bits_be(s, sizeof(s), 44, 12, 0x000);
    transit_set_bits_be(s, sizeof(s), 62, 8, 5);
    transit_set_bits_be(s, sizeof(s), 86, 10, 0x2AA);   // end date top 10 bits
    transit_set_bits_be(s, sizeof(s), 0, 4, 0xB);       // end date low 4 bits, from block 0
    transit_set_bits_be(s, sizeof(s), 96 + 50, 14, 0x1555);  // usage A vehicle top 14 bits
    transit_set_bits_be(s, sizeof(s), 224, 2, 0x2);          // and its last 2
    intertic_stream_to_card(s, card);
    ok &= transit_check("pid 10 decodes", intertic_decode(card, sizeof(card), &t, &d), 1);
    ok &= transit_check("pid 10 end date across block 0", d.end_date, (0x2AA << 4) | 0xB);
    ok &= transit_check("pid 10 usage A across counter", transit_bits_be(t.usage_a, INTERTIC_PART_LEN, 50, 16), (0x1555 << 2) | 0x2);
    ok &= transit_check("pid 10 usage length", t.usage_bits, 144);
    n = intertic_find_network(d.country, d.authority, d.provider);
    ok &= transit_check_str("pid 10 network", n ? n->city : NULL, "Lille");

    // wrong size, unknown PID and blank tickets are rejected
    ok &= transit_check("SRIX4K size rejected", is_valid_intertic_card(card, 516, NULL), 0);
    card[0] = (uint8_t)((card[0] & 0xE0) | 0x02);
    ok &= transit_check("unknown pid rejected", is_valid_intertic_card(card, sizeof(card), NULL), 0);
    memset(card, 0xFF, sizeof(card));
    ok &= transit_check("blank rejected", is_valid_intertic_card(card, sizeof(card), NULL), 0);
    ok &= transit_st25tb_check_identify("not identified", card, sizeof(card), "Intertic", TRANSIT_ID_NONE);

    return transit_selftest_result("Intertic", ok);
}
