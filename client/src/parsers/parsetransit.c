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
// Transit card parsers, shared helpers and per technology dispatch
//-----------------------------------------------------------------------------

#include "parsetransit.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "ui.h"                 // PrintAndLogEx

#include "parsebip.h"
#include "parsecharlie.h"
#include "parseclipper.h"
#include "parseitso.h"
#include "parsekazan.h"
#include "parsemetromoney.h"
#include "parsemyki.h"
#include "parsenextfare.h"
#include "parsenol.h"
#include "parseopal.h"
#include "parseplantain.h"
#include "parserenfe.h"
#include "parsesmartrider.h"
#include "parsetmobilitat.h"
#include "parsetroika.h"
#include "parsetrt.h"
#include "parseumarsh.h"
#include "parseventra.h"
#include "parsezolotayakorona.h"

#define TRANSIT_LABEL_WIDTH     17

//-----------------------------------------------------------------------------
// Bit and byte access
//-----------------------------------------------------------------------------

uint64_t transit_bits_be(const uint8_t *buf, size_t buflen, size_t off, uint8_t n) {
    uint64_t v = 0;
    for (uint8_t k = 0; k < n && k < 64; k++) {
        size_t b = off + k;
        uint8_t bit = 0;
        if (buf != NULL && (b >> 3) < buflen) {
            bit = (buf[b >> 3] >> (7 - (b & 7))) & 1;
        }
        v = (v << 1) | bit;
    }
    return v;
}

uint64_t transit_bits_le(const uint8_t *buf, size_t buflen, size_t off, uint8_t n) {
    uint64_t v = 0;
    for (uint8_t k = 0; k < n && k < 64; k++) {
        size_t b = off + k;
        if (buf != NULL && (b >> 3) < buflen && ((buf[b >> 3] >> (b & 7)) & 1)) {
            v |= (uint64_t)1 << k;
        }
    }
    return v;
}

void transit_set_bits_be(uint8_t *buf, size_t buflen, size_t off, uint8_t n, uint64_t v) {
    for (uint8_t k = 0; k < n && k < 64; k++) {
        size_t b = off + k;
        if ((b >> 3) >= buflen) {
            return;
        }
        uint8_t mask = (uint8_t)(1 << (7 - (b & 7)));
        if ((v >> (n - 1 - k)) & 1) {
            buf[b >> 3] |= mask;
        } else {
            buf[b >> 3] &= (uint8_t)~mask;
        }
    }
}

void transit_set_bits_le(uint8_t *buf, size_t buflen, size_t off, uint8_t n, uint64_t v) {
    for (uint8_t k = 0; k < n && k < 64; k++) {
        size_t b = off + k;
        if ((b >> 3) >= buflen) {
            return;
        }
        uint8_t mask = (uint8_t)(1 << (b & 7));
        if ((v >> k) & 1) {
            buf[b >> 3] |= mask;
        } else {
            buf[b >> 3] &= (uint8_t)~mask;
        }
    }
}

int64_t transit_sign_extend(uint64_t v, uint8_t n) {
    if (n == 0 || n >= 64) {
        return (int64_t)v;
    }
    uint64_t m = (uint64_t)1 << (n - 1);
    v &= ((uint64_t)1 << n) - 1;
    return (int64_t)((v ^ m) - m);
}

bool transit_is_zero(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i]) {
            return false;
        }
    }
    return true;
}

int transit_bcd(uint8_t b) {
    if ((b >> 4) > 9 || (b & 0x0F) > 9) {
        return -1;
    }
    return ((b >> 4) * 10) + (b & 0x0F);
}

//-----------------------------------------------------------------------------
// Formatting
//-----------------------------------------------------------------------------

// Howard Hinnant's days_from_civil and its inverse
void transit_civil_from_days(int32_t z, int *year, unsigned *month, unsigned *day) {
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

int32_t transit_days_from_civil(int year, unsigned month, unsigned day) {
    int32_t y = year - ((month <= 2) ? 1 : 0);
    int32_t era = ((y >= 0) ? y : (y - 399)) / 400;
    uint32_t yoe = (uint32_t)(y - (era * 400));
    uint32_t doy = ((153 * ((month > 2) ? (month - 3) : (month + 9))) + 2) / 5 + day - 1;
    uint32_t doe = (yoe * 365) + (yoe / 4) - (yoe / 100) + doy;
    return (era * 146097) + (int32_t)doe - 719468;
}

void transit_date_str(char *out, size_t outlen, int32_t days) {
    int y;
    unsigned m, d;
    transit_civil_from_days(days, &y, &m, &d);
    snprintf(out, outlen, "%04d-%02u-%02u", y, m, d);
}

void transit_datetime_str(char *out, size_t outlen, int64_t secs) {
    int64_t days = secs / 86400;
    int64_t rem = secs % 86400;
    if (rem < 0) {
        rem += 86400;
        days--;
    }
    int y;
    unsigned m, d;
    transit_civil_from_days((int32_t)days, &y, &m, &d);
    snprintf(out, outlen, "%04d-%02u-%02u %02u:%02u:%02u", y, m, d,
             (unsigned)(rem / 3600), (unsigned)((rem / 60) % 60), (unsigned)(rem % 60));
}

void transit_money_str(char *out, size_t outlen, int64_t minor, uint8_t decimals, const char *currency) {
    const char *sign = (minor < 0) ? "-" : "";
    uint64_t a = (minor < 0) ? (uint64_t)(-(minor + 1)) + 1 : (uint64_t)minor;
    const char *cur = (currency != NULL) ? currency : "";
    const char *sep = (cur[0] != '\0') ? " " : "";

    if (decimals == 0) {
        snprintf(out, outlen, "%s%" PRIu64 "%s%s", sign, a, sep, cur);
        return;
    }

    uint64_t div = 1;
    for (uint8_t i = 0; i < decimals; i++) {
        div *= 10;
    }
    snprintf(out, outlen, "%s%" PRIu64 ".%0*" PRIu64 "%s%s", sign, a / div, (int)decimals, a % div, sep, cur);
}

//-----------------------------------------------------------------------------
// Printing
//-----------------------------------------------------------------------------

void transit_print_header(const char *title) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("%s") " ---------------------------", title);
}

void transit_print_kv(const char *label, const char *fmt, ...) {
    char lbl[TRANSIT_LABEL_WIDTH + 1];
    size_t n = strlen(label);
    if (n > TRANSIT_LABEL_WIDTH) {
        n = TRANSIT_LABEL_WIDTH;
    }
    memcpy(lbl, label, n);
    memset(lbl + n, '.', TRANSIT_LABEL_WIDTH - n);
    lbl[TRANSIT_LABEL_WIDTH] = '\0';

    char val[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(val, sizeof(val), fmt, args);
    va_end(args);

    PrintAndLogEx(SUCCESS, "%s %s", lbl, val);
}

bool transit_check(const char *what, uint64_t got, uint64_t want) {
    bool ok = (got == want);
    PrintAndLogEx(INFO, "  %-28s %14" PRIu64 "  ( %s )", what, got, ok ? _GREEN_("ok") : _RED_("fail"));
    return ok;
}

bool transit_check_str(const char *what, const char *got, const char *want) {
    bool ok = (got != NULL && want != NULL && strcmp(got, want) == 0);
    PrintAndLogEx(INFO, "  %-28s %14s  ( %s )", what, got ? got : "(null)", ok ? _GREEN_("ok") : _RED_("fail"));
    return ok;
}

int transit_selftest_result(const char *name, bool ok) {
    PrintAndLogEx(INFO, "%s selftest ( %s )", name, ok ? _GREEN_("ok") : _RED_("fail"));
    return ok ? PM3_SUCCESS : PM3_ESOFT;
}

//-----------------------------------------------------------------------------
// FeliCa and Calypso lookups
//-----------------------------------------------------------------------------

const transit_felica_system_t *transit_felica_find_system(const transit_felica_card_t *card, uint16_t system_code) {
    if (card == NULL || card->systems == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < card->system_count; i++) {
        if (card->systems[i].system_code == system_code) {
            return &card->systems[i];
        }
    }
    return NULL;
}

const transit_felica_service_t *transit_felica_find_service(const transit_felica_system_t *sys, uint16_t code) {
    if (sys == NULL || sys->services == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < sys->service_count; i++) {
        if (sys->services[i].code == code && sys->services[i].blocks != NULL) {
            return &sys->services[i];
        }
    }
    return NULL;
}

static int transit_helpers_selftest(void) {
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing transit helpers");

    const uint8_t b[] = { 0xA5, 0x3C };
    bool ok = true;
    ok &= transit_check("bits be 4..11", transit_bits_be(b, sizeof(b), 4, 8), 0x53);
    ok &= transit_check("bits le 4..11", transit_bits_le(b, sizeof(b), 4, 8), 0xCA);
    ok &= transit_check("bits be past end", transit_bits_be(b, sizeof(b), 12, 8), 0xC0);
    ok &= transit_check("sign extend 0xFFF/12", (uint64_t)transit_sign_extend(0xFFF, 12), (uint64_t) -1);

    uint8_t w[2] = {0};
    transit_set_bits_be(w, sizeof(w), 4, 8, 0x53);
    transit_set_bits_le(w, sizeof(w), 4, 4, 0xA);
    transit_set_bits_be(w, sizeof(w), 12, 4, 0xC);
    ok &= transit_check("set bits round trip", ((uint64_t)w[0] << 8) | w[1], 0xA53C);

    char s[40];
    transit_date_str(s, sizeof(s), TRANSIT_DAYS_TO_1997);
    ok &= transit_check_str("EN 1545 epoch", s, "1997-01-01");
    ok &= transit_check("days from civil 2000-03-01", (uint64_t)transit_days_from_civil(2000, 3, 1), 11017);
    transit_datetime_str(s, sizeof(s), 951782400 + 3723);
    ok &= transit_check_str("datetime", s, "2000-02-29 01:02:03");
    transit_money_str(s, sizeof(s), -1234, 2, "AUD");
    ok &= transit_check_str("money -12.34", s, "-12.34 AUD");
    transit_money_str(s, sizeof(s), 5, 2, NULL);
    ok &= transit_check_str("money 0.05", s, "0.05");
    transit_money_str(s, sizeof(s), 210, 0, "JPY");
    ok &= transit_check_str("money JPY", s, "210 JPY");
    return transit_selftest_result("Transit helpers", ok);
}

//-----------------------------------------------------------------------------
// Dispatch tables, one row per card system, NULL name ends a table
//-----------------------------------------------------------------------------

typedef struct {
    const char *name;
    bool (*detect)(const uint8_t *dump, size_t dumplen);
    int (*parse)(const uint8_t *dump, size_t dumplen);
    int (*selftest)(void);
} transit_buf_parser_t;

typedef struct {
    const char *name;
    bool (*detect)(const desfire_dump_t *dump);
    int (*parse)(const desfire_dump_t *dump);
    int (*selftest)(void);
} transit_mfdes_parser_t;

typedef struct {
    const char *name;
    bool (*detect)(const uint8_t *data, size_t datalen, const uint8_t *uid);
    int (*parse)(const uint8_t *data, size_t datalen, const uint8_t *uid);
    int (*selftest)(void);
} transit_st25tb_parser_t;

typedef struct {
    const char *name;
    bool (*detect)(const transit_felica_card_t *card);
    int (*parse)(const transit_felica_card_t *card);
    int (*selftest)(void);
} transit_felica_parser_t;

typedef struct {
    const char *name;
    bool (*detect)(const transit_calypso_card_t *card);
    int (*parse)(const transit_calypso_card_t *card);
    int (*selftest)(void);
} transit_calypso_parser_t;

static const transit_buf_parser_t mfc_parsers[] = {
    {"Bip!", is_valid_bip_card, bip_parser_parse, bip_selftest},
    {"CharlieCard", is_valid_charlie_card, charlie_parser_parse, charlie_selftest},
    {"Kazan", is_valid_kazan_card, kazan_parser_parse, kazan_selftest},
    {"Metromoney", is_valid_metromoney_card, metromoney_parser_parse, metromoney_selftest},
    {"Nextfare", is_valid_nextfare_card, nextfare_parser_parse, nextfare_selftest},
    {"Podorozhnik", is_valid_plantain_card, plantain_parser_parse, plantain_selftest},
    {"RENFE Suma 10", is_valid_renfe_card, renfe_parser_parse, renfe_selftest},
    {"SmartRider", is_valid_smartrider_card, smartrider_parser_parse, smartrider_selftest},
    {"Troika", is_valid_troika_card, troika_parser_parse, troika_selftest},
    {"Umarsh", is_valid_umarsh_card, umarsh_parser_parse, umarsh_selftest},
    {"Zolotaya Korona", is_valid_zolotayakorona_card, zolotayakorona_parser_parse, zolotayakorona_selftest},
    {NULL, NULL, NULL, NULL}
};

static const transit_mfdes_parser_t mfdes_parsers[] = {
    {"Clipper", is_valid_clipper_card, clipper_parser_parse, clipper_selftest},
    {"ITSO", is_valid_itso_card, itso_parser_parse, itso_selftest},
    {"myki", is_valid_myki_card, myki_parser_parse, myki_selftest},
    {"nol", is_valid_nol_card, nol_parser_parse, nol_selftest},
    {"Opal", is_valid_opal_card, opal_parser_parse, opal_selftest},
    {"T-Mobilitat", is_valid_tmobilitat_card, tmobilitat_parser_parse, tmobilitat_selftest},
    {NULL, NULL, NULL, NULL}
};

static const transit_buf_parser_t mfu_parsers[] = {
    {"Troika Ultralight", is_valid_troika_ul_card, troika_ul_parser_parse, troika_ul_selftest},
    {"TRT", is_valid_trt_card, trt_parser_parse, trt_selftest},
    {"Ventra", is_valid_ventra_card, ventra_parser_parse, ventra_selftest},
    {NULL, NULL, NULL, NULL}
};

static const transit_st25tb_parser_t st25tb_parsers[] = {
    {NULL, NULL, NULL, NULL}
};

static const transit_felica_parser_t felica_parsers[] = {
    {NULL, NULL, NULL, NULL}
};

static const transit_calypso_parser_t calypso_parsers[] = {
    {NULL, NULL, NULL, NULL}
};

// Runs every self test of a table, all of them even after a failure
#define TRANSIT_RUN_SELFTESTS(table) do { \
        bool ok = (transit_helpers_selftest() == PM3_SUCCESS); \
        int cnt = 0; \
        for (size_t i = 0; table[i].name != NULL; i++) { \
            if (table[i].selftest != NULL) { \
                ok &= (table[i].selftest() == PM3_SUCCESS); \
                cnt++; \
            } \
        } \
        PrintAndLogEx(INFO, ""); \
        PrintAndLogEx(INFO, "%d transit parser selftest(s)", cnt); \
        return transit_selftest_result("Transit", ok); \
    } while (0)

int transit_mfc_parse(const uint8_t *dump, size_t dumplen) {
    int hits = 0;
    for (size_t i = 0; dump != NULL && mfc_parsers[i].name != NULL; i++) {
        if (mfc_parsers[i].detect(dump, dumplen)) {
            (void)mfc_parsers[i].parse(dump, dumplen);
            hits++;
        }
    }
    return hits;
}

int transit_mfc_selftest(void) {
    TRANSIT_RUN_SELFTESTS(mfc_parsers);
}

int transit_mfdes_parse(const desfire_dump_t *dump) {
    int hits = 0;
    for (size_t i = 0; dump != NULL && mfdes_parsers[i].name != NULL; i++) {
        if (mfdes_parsers[i].detect(dump)) {
            (void)mfdes_parsers[i].parse(dump);
            hits++;
        }
    }
    return hits;
}

int transit_mfdes_selftest(void) {
    TRANSIT_RUN_SELFTESTS(mfdes_parsers);
}

int transit_mfu_parse(const uint8_t *data, size_t datalen) {
    int hits = 0;
    for (size_t i = 0; data != NULL && mfu_parsers[i].name != NULL; i++) {
        if (mfu_parsers[i].detect(data, datalen)) {
            (void)mfu_parsers[i].parse(data, datalen);
            hits++;
        }
    }
    return hits;
}

int transit_mfu_selftest(void) {
    TRANSIT_RUN_SELFTESTS(mfu_parsers);
}

int transit_st25tb_parse(const uint8_t *data, size_t datalen, const uint8_t *uid) {
    int hits = 0;
    for (size_t i = 0; data != NULL && st25tb_parsers[i].name != NULL; i++) {
        if (st25tb_parsers[i].detect(data, datalen, uid)) {
            (void)st25tb_parsers[i].parse(data, datalen, uid);
            hits++;
        }
    }
    return hits;
}

int transit_st25tb_selftest(void) {
    TRANSIT_RUN_SELFTESTS(st25tb_parsers);
}

int transit_felica_parse(const transit_felica_card_t *card) {
    int hits = 0;
    for (size_t i = 0; card != NULL && felica_parsers[i].name != NULL; i++) {
        if (felica_parsers[i].detect(card)) {
            (void)felica_parsers[i].parse(card);
            hits++;
        }
    }
    return hits;
}

int transit_felica_selftest(void) {
    TRANSIT_RUN_SELFTESTS(felica_parsers);
}

int transit_calypso_parse(const transit_calypso_card_t *card) {
    int hits = 0;
    for (size_t i = 0; card != NULL && calypso_parsers[i].name != NULL; i++) {
        if (calypso_parsers[i].detect(card)) {
            (void)calypso_parsers[i].parse(card);
            hits++;
        }
    }
    return hits;
}

int transit_calypso_selftest(void) {
    TRANSIT_RUN_SELFTESTS(calypso_parsers);
}
