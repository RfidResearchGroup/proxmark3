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

#include "commonutil.h"         // num_to_bytes
#include "ui.h"                 // PrintAndLogEx

#include "parsebip.h"
#include "parsecharlie.h"
#include "parseclipper.h"
#include "parseintercode.h"
#include "parseintertic.h"
#include "parseitso.h"
#include "parsekazan.h"
#include "parsemetromoney.h"
#include "parsemyki.h"
#include "parsenextfare.h"
#include "parsenol.h"
#include "parseoctopus.h"
#include "parseopal.h"
#include "parseopus.h"
#include "parseplantain.h"
#include "parseravkav.h"
#include "parserenfe.h"
#include "parsesmartrider.h"
#include "parsesuica.h"
#include "parsetmobilitat.h"
#include "parsetroika.h"
#include "parsetrt.h"
#include "parseumarsh.h"
#include "parseventra.h"
#include "parsezolotayakorona.h"
#include "parsetransitmfc.h"

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
// Identification output
//-----------------------------------------------------------------------------

static void transit_ident_add(transit_idents_t *ids, const char *name, const char *region, const char *hint, transit_id_t id) {
    if (id == TRANSIT_ID_NONE || ids->count >= TRANSIT_MAX_IDENTS) {
        return;
    }
    transit_ident_t *t = &ids->ident[ids->count++];
    t->name = name;
    t->region = region;
    t->hint = hint;
    t->possible = (id == TRANSIT_ID_POSSIBLE);
}

void transit_print_idents(const transit_idents_t *ids) {
    for (uint8_t i = 0; ids != NULL && i < ids->count; i++) {
        const transit_ident_t *t = &ids->ident[i];
        if (t->possible) {
            transit_print_kv("Transit", "Possible " _YELLOW_("%s") " ( %s )", t->name, t->region);
        } else {
            transit_print_kv("Transit", _GREEN_("%s") " ( %s )", t->name, t->region);
        }
    }
}

void transit_print_ident_hints(const transit_idents_t *ids, const char *current_cmd) {
    for (uint8_t i = 0; ids != NULL && i < ids->count; i++) {
        const char *hint = ids->ident[i].hint;
        if (hint == NULL || (current_cmd != NULL && strcmp(hint, current_cmd) == 0)) {
            continue;
        }
        bool seen = false;
        for (uint8_t j = 0; j < i; j++) {
            seen |= (ids->ident[j].hint != NULL && strcmp(ids->ident[j].hint, hint) == 0);
        }
        if (seen == false) {
            PrintAndLogEx(HINT, "Hint: Try `" _YELLOW_("%s") "` to decode", hint);
        }
    }
}

bool transit_check_ident(const char *what, const transit_idents_t *ids, const char *name, transit_id_t want) {
    transit_id_t got = TRANSIT_ID_NONE;
    for (uint8_t i = 0; ids != NULL && i < ids->count; i++) {
        if (strcmp(ids->ident[i].name, name) == 0) {
            got = ids->ident[i].possible ? TRANSIT_ID_POSSIBLE : TRANSIT_ID_MATCH;
        }
    }
    return transit_check(what, got, want);
}

//-----------------------------------------------------------------------------
// MIFARE Classic key sets, matched against a dump or the keys an info command found
//-----------------------------------------------------------------------------

typedef bool (*transit_mfc_has_key_fn)(const void *ctx, uint8_t sector, uint8_t keytype, uint64_t key);

typedef struct {
    const uint8_t *dump;
    size_t dumplen;
} transit_mfc_dumpref_t;

static bool transit_mfc_dump_has(const void *ctx, uint8_t sector, uint8_t keytype, uint64_t key) {
    const transit_mfc_dumpref_t *d = ctx;
    if (keytype != TRANSIT_MFC_KEY_B && transit_mfc_key(d->dump, d->dumplen, sector, false) == key) {
        return true;
    }
    return (keytype != TRANSIT_MFC_KEY_A) && (transit_mfc_key(d->dump, d->dumplen, sector, true) == key);
}

static bool transit_mfc_info_has(const void *ctx, uint8_t sector, uint8_t keytype, uint64_t key) {
    const transit_mfc_info_t *info = ctx;
    for (uint8_t t = 0; t < 2; t++) {
        if ((keytype == t || keytype == TRANSIT_MFC_KEY_AB) && info->found[sector][t] && info->key[sector][t] == key) {
            return true;
        }
    }
    return false;
}

static bool transit_mfc_keyset_match(const transit_mfc_keyset_t *ks, transit_mfc_has_key_fn has, const void *ctx) {
    if (ks == NULL || ks->count == 0) {
        return false;
    }
    uint64_t listed = 0, matched = 0;
    for (uint8_t i = 0; i < ks->count; i++) {
        const transit_mfc_key_t *k = &ks->keys[i];
        if (k->sector >= TRANSIT_MFC_MAX_SECTORS) {
            return false;
        }
        uint64_t bit = 1ULL << k->sector;
        listed |= bit;
        if ((matched & bit) == 0 && has(ctx, k->sector, k->keytype, k->key)) {
            matched |= bit;
        }
    }
    return ks->any_sector ? (matched != 0) : (matched == listed);
}

bool transit_mfc_keyset_match_dump(const transit_mfc_keyset_t *ks, const uint8_t *dump, size_t dumplen) {
    transit_mfc_dumpref_t d = { dump, dumplen };
    return (dump != NULL) && transit_mfc_keyset_match(ks, transit_mfc_dump_has, &d);
}

bool transit_mfc_keyset_match_info(const transit_mfc_keyset_t *ks, const transit_mfc_info_t *info) {
    return (info != NULL) && transit_mfc_keyset_match(ks, transit_mfc_info_has, info);
}

//-----------------------------------------------------------------------------
// DESFire application list
//-----------------------------------------------------------------------------

void transit_mfdes_info_from_dump(const desfire_dump_t *dump, transit_mfdes_info_t *info) {
    memset(info, 0, sizeof(*info));
    if (dump == NULL) {
        return;
    }
    info->aids_known = true;
    for (uint8_t i = 0; i < dump->appcount && i < DESFIRE_MAX_APP_COUNT; i++) {
        info->aids[info->aidcount++] = dump->app[i].aid;
    }
    info->card = &dump->card_info;
}

bool transit_mfdes_info_has_aid(const transit_mfdes_info_t *info, uint32_t aid) {
    for (uint8_t i = 0; info != NULL && i < info->aidcount && i < DESFIRE_MAX_APP_COUNT; i++) {
        if (info->aids[i] == aid) {
            return true;
        }
    }
    return false;
}

//-----------------------------------------------------------------------------
// Dispatch tables, one row per card system, NULL name ends a table.
// A row without detect only identifies.
//-----------------------------------------------------------------------------

#define TRANSIT_HINT_MFC        "hf mf autopwn"
#define TRANSIT_HINT_MFDES      "hf mfdes dump --no-auth"
#define TRANSIT_HINT_MFU        "hf mfu dump"
#define TRANSIT_HINT_ST25TB     "hf 14b dump"
#define TRANSIT_HINT_FELICA     "hf felica dump"
#define TRANSIT_HINT_CALYPSO    "hf calypso info"

typedef struct {
    const char *name;
    const char *region;
    bool (*detect)(const uint8_t *dump, size_t dumplen);
    int (*parse)(const uint8_t *dump, size_t dumplen);
    int (*selftest)(void);
    const transit_mfc_keyset_t *keyset;                 // identify by sector keys
    transit_id_t (*identify)(const transit_mfc_info_t *info);
} transit_mfc_parser_t;

typedef struct {
    const char *name;
    const char *region;
    const char *hint;
    bool (*detect)(const desfire_dump_t *dump);
    int (*parse)(const desfire_dump_t *dump);
    int (*selftest)(void);
    transit_id_t (*identify)(const transit_mfdes_info_t *info);
    const transit_mfdes_file_t *summary;                // free files with card number, balance
    uint8_t summary_count;
} transit_mfdes_parser_t;

// Info commands read the same data as a dump, id_level is what a detect hit is worth
typedef struct {
    const char *name;
    const char *region;
    bool (*detect)(const uint8_t *data, size_t datalen);
    int (*parse)(const uint8_t *data, size_t datalen);
    int (*selftest)(void);
    transit_id_t id_level;
} transit_mfu_parser_t;

typedef struct {
    const char *name;
    const char *region;
    bool (*detect)(const uint8_t *data, size_t datalen, const uint8_t *uid);
    int (*parse)(const uint8_t *data, size_t datalen, const uint8_t *uid);
    int (*selftest)(void);
    transit_id_t id_level;
} transit_st25tb_parser_t;

typedef struct {
    const char *name;
    const char *region;
    bool (*detect)(const transit_felica_card_t *card);
    int (*parse)(const transit_felica_card_t *card);
    int (*selftest)(void);
    transit_id_t (*identify)(const uint16_t *system_codes, size_t count);
} transit_felica_parser_t;

typedef struct {
    const char *name;
    const char *region;
    bool (*detect)(const transit_calypso_card_t *card);
    int (*parse)(const transit_calypso_card_t *card);
    int (*selftest)(void);
    transit_id_t id_level;
} transit_calypso_parser_t;

static const transit_mfc_parser_t mfc_parsers[] = {
    {"Bip!", "Santiago, Chile", is_valid_bip_card, bip_parser_parse, bip_selftest, &bip_keyset, NULL},
    {"CharlieCard", "MBTA, Boston", is_valid_charlie_card, charlie_parser_parse, charlie_selftest, &charlie_keyset, NULL},
    {"Kazan", "Kazan, Russia", is_valid_kazan_card, kazan_parser_parse, kazan_selftest, &kazan_keyset, NULL},
    {"Metromoney", "Tbilisi, Georgia", is_valid_metromoney_card, metromoney_parser_parse, metromoney_selftest, &metromoney_keyset, NULL},
    {"Nextfare", "Cubic, Brisbane / Los Angeles / Minneapolis", is_valid_nextfare_card, nextfare_parser_parse, nextfare_selftest, NULL, nextfare_identify},
    {"Podorozhnik", "Saint Petersburg, Russia", is_valid_plantain_card, plantain_parser_parse, plantain_selftest, &plantain_keyset, NULL},
    {"RENFE Suma 10", "Renfe Cercanias, Spain", is_valid_renfe_card, renfe_parser_parse, renfe_selftest, &renfe_keyset, NULL},
    {"SmartRider", "Transperth, Perth", is_valid_smartrider_card, smartrider_parser_parse, smartrider_selftest, &smartrider_keyset, NULL},
    {"Troika", "Moscow, Russia", is_valid_troika_card, troika_parser_parse, troika_selftest, &troika_keyset, NULL},
    {"Umarsh", "Russia", is_valid_umarsh_card, umarsh_parser_parse, umarsh_selftest, NULL, NULL},
    {"Zolotaya Korona", "Russia", is_valid_zolotayakorona_card, zolotayakorona_parser_parse, zolotayakorona_selftest, NULL, zolotayakorona_identify},
    {NULL, NULL, NULL, NULL, NULL, NULL, NULL}
};

static const transit_mfdes_file_t clipper_summary[] = {
    {CLIPPER_AID_CARD, CLIPPER_FID_IDENTITY}, {CLIPPER_AID_CARD, CLIPPER_FID_ECASH},
    {CLIPPER_AID_MOBILE, CLIPPER_FID_IDENTITY}, {CLIPPER_AID_MOBILE, CLIPPER_FID_ECASH},
};
static const transit_mfdes_file_t itso_summary[] = { {ITSO_AID, ITSO_FID_SHELL} };
static const transit_mfdes_file_t myki_summary[] = { {MYKI_AID_1, MYKI_FID_SERIAL} };
static const transit_mfdes_file_t nol_summary[] = { {NOL_AID_SERIAL, NOL_FID_SERIAL} };
static const transit_mfdes_file_t opal_summary[] = { {OPAL_AID, OPAL_FID_CARD} };

static const transit_mfdes_parser_t mfdes_parsers[] = {
    {"Clipper", "San Francisco Bay Area", TRANSIT_HINT_MFDES, is_valid_clipper_card, clipper_parser_parse, clipper_selftest, clipper_identify, clipper_summary, ARRAYLEN(clipper_summary)},
    {"ITSO", "United Kingdom", TRANSIT_HINT_MFDES, is_valid_itso_card, itso_parser_parse, itso_selftest, itso_identify, itso_summary, ARRAYLEN(itso_summary)},
    {"myki", "Melbourne, Australia", TRANSIT_HINT_MFDES, is_valid_myki_card, myki_parser_parse, myki_selftest, myki_identify, myki_summary, ARRAYLEN(myki_summary)},
    {"nol", "Dubai, UAE", TRANSIT_HINT_MFDES, is_valid_nol_card, nol_parser_parse, nol_selftest, nol_identify, nol_summary, ARRAYLEN(nol_summary)},
    {"Opal", "Sydney, Australia", TRANSIT_HINT_MFDES, is_valid_opal_card, opal_parser_parse, opal_selftest, opal_identify, opal_summary, ARRAYLEN(opal_summary)},
    // card number is in the ATS, balance and trips need keys
    {"T-Mobilitat", "Barcelona, Spain", "hf mfdes info", is_valid_tmobilitat_card, tmobilitat_parser_parse, tmobilitat_selftest, tmobilitat_identify, NULL, 0},
    {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0}
};

static const transit_mfu_parser_t mfu_parsers[] = {
    {"Troika Ultralight", "Moscow, Russia", is_valid_troika_ul_card, troika_ul_parser_parse, troika_ul_selftest, TRANSIT_ID_POSSIBLE},
    {"TRT", "Tianjin Metro, China", is_valid_trt_card, trt_parser_parse, trt_selftest, TRANSIT_ID_POSSIBLE},
    {"Ventra", "Chicago Transit Authority", is_valid_ventra_card, ventra_parser_parse, ventra_selftest, TRANSIT_ID_POSSIBLE},
    {NULL, NULL, NULL, NULL, NULL, TRANSIT_ID_NONE}
};

static const transit_st25tb_parser_t st25tb_parsers[] = {
    {"Intertic", "France / Morocco", is_valid_intertic_card, intertic_parser_parse, intertic_selftest, TRANSIT_ID_POSSIBLE},
    {NULL, NULL, NULL, NULL, NULL, TRANSIT_ID_NONE}
};

static const transit_felica_parser_t felica_parsers[] = {
    {"Japan IC", "Suica / PASMO / ICOCA ..., Japan", is_valid_suica_card, suica_parser_parse, suica_selftest, suica_identify},
    {"Octopus", "Hong Kong", is_valid_octopus_card, octopus_parser_parse, octopus_selftest, octopus_identify},
    {"Shenzhen Tong", "Shenzhen, China", NULL, NULL, NULL, szt_identify},
    {NULL, NULL, NULL, NULL, NULL, NULL}
};

static const transit_calypso_parser_t calypso_parsers[] = {
    {"Navigo", "Ile-de-France Mobilites, Paris", is_valid_navigo_card, navigo_parser_parse, navigo_selftest, TRANSIT_ID_MATCH},
    {"Intercode", "France", is_valid_intercode_card, intercode_parser_parse, intercode_selftest, TRANSIT_ID_MATCH},
    {"Opus", "Montreal / Quebec", is_valid_opus_card, opus_parser_parse, opus_selftest, TRANSIT_ID_MATCH},
    {"Rav-Kav", "Israel", is_valid_ravkav_card, ravkav_parser_parse, ravkav_selftest, TRANSIT_ID_MATCH},
    {NULL, NULL, NULL, NULL, NULL, TRANSIT_ID_NONE}
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

// Runs the parser of every row whose detect matches
#define TRANSIT_RUN_PARSERS(table, valid, ...) do { \
        int hits = 0; \
        for (size_t i = 0; (valid) && table[i].name != NULL; i++) { \
            if (table[i].detect != NULL && table[i].detect(__VA_ARGS__)) { \
                (void)table[i].parse(__VA_ARGS__); \
                hits++; \
            } \
        } \
        return hits; \
    } while (0)

int transit_mfc_parse(const uint8_t *dump, size_t dumplen) {
    TRANSIT_RUN_PARSERS(mfc_parsers, dump != NULL, dump, dumplen);
}

int transit_mfc_selftest(void) {
    TRANSIT_RUN_SELFTESTS(mfc_parsers);
}

uint64_t transit_mfc_probe_sectors(void) {
    uint64_t mask = 0;
    for (size_t i = 0; mfc_parsers[i].name != NULL; i++) {
        const transit_mfc_keyset_t *ks = mfc_parsers[i].keyset;
        for (uint8_t k = 0; ks != NULL && k < ks->count; k++) {
            mask |= 1ULL << ks->keys[k].sector;
        }
    }
    return mask;
}

size_t transit_mfc_probe_keys(uint8_t sector, uint8_t keytype, uint8_t *keys, size_t maxkeys) {
    size_t n = 0;
    for (size_t i = 0; mfc_parsers[i].name != NULL; i++) {
        const transit_mfc_keyset_t *ks = mfc_parsers[i].keyset;
        for (uint8_t k = 0; ks != NULL && k < ks->count && n < maxkeys; k++) {
            const transit_mfc_key_t *e = &ks->keys[k];
            if (e->sector != sector || (e->keytype != keytype && e->keytype != TRANSIT_MFC_KEY_AB)) {
                continue;
            }
            bool dup = false;
            for (size_t j = 0; j < n; j++) {
                dup |= (bytes_to_num(keys + (j * 6), 6) == e->key);
            }
            if (dup == false) {
                num_to_bytes(e->key, 6, keys + (n * 6));
                n++;
            }
        }
    }
    return n;
}

static void transit_mfc_info_probe_dump(const uint8_t *dump, size_t dumplen, transit_mfc_info_t *info) {
    memset(info, 0, sizeof(*info));
    uint64_t mask = transit_mfc_probe_sectors();
    for (uint8_t s = 0; s < TRANSIT_MFC_MAX_SECTORS; s++) {
        if ((mask & (1ULL << s)) == 0) {
            continue;
        }
        for (uint8_t t = 0; t < 2; t++) {
            uint8_t keys[16 * 6];
            size_t n = transit_mfc_probe_keys(s, t, keys, 16);
            uint64_t have = transit_mfc_key(dump, dumplen, s, t == TRANSIT_MFC_KEY_B);
            for (size_t i = 0; i < n; i++) {
                if (bytes_to_num(keys + (i * 6), 6) == have) {
                    info->found[s][t] = true;
                    info->key[s][t] = have;
                }
            }
        }
    }
    info->block1 = transit_mfc_block(dump, dumplen, 0, 1);
}

int transit_mfc_identify(const transit_mfc_info_t *info, transit_idents_t *ids) {
    memset(ids, 0, sizeof(*ids));
    for (size_t i = 0; info != NULL && mfc_parsers[i].name != NULL; i++) {
        transit_id_t id = TRANSIT_ID_NONE;
        if (transit_mfc_keyset_match_info(mfc_parsers[i].keyset, info)) {
            id = TRANSIT_ID_MATCH;
        } else if (mfc_parsers[i].identify != NULL) {
            id = mfc_parsers[i].identify(info);
        }
        transit_ident_add(ids, mfc_parsers[i].name, mfc_parsers[i].region, TRANSIT_HINT_MFC, id);
    }
    return ids->count;
}

bool transit_mfc_check_identify(const char *what, const uint8_t *dump, size_t dumplen, const char *name, transit_id_t want) {
    transit_mfc_info_t info;
    transit_mfc_info_probe_dump(dump, dumplen, &info);
    transit_idents_t ids;
    transit_mfc_identify(&info, &ids);
    return transit_check_ident(what, &ids, name, want);
}

int transit_mfdes_parse(const desfire_dump_t *dump) {
    TRANSIT_RUN_PARSERS(mfdes_parsers, dump != NULL, dump);
}

int transit_mfdes_selftest(void) {
    TRANSIT_RUN_SELFTESTS(mfdes_parsers);
}

int transit_mfdes_identify(const transit_mfdes_info_t *info, transit_idents_t *ids) {
    memset(ids, 0, sizeof(*ids));
    for (size_t i = 0; info != NULL && mfdes_parsers[i].name != NULL; i++) {
        transit_ident_add(ids, mfdes_parsers[i].name, mfdes_parsers[i].region, mfdes_parsers[i].hint, mfdes_parsers[i].identify(info));
    }
    return ids->count;
}

bool transit_mfdes_check_identify(const char *what, const desfire_dump_t *dump, const char *name, transit_id_t want) {
    transit_mfdes_info_t info;
    transit_mfdes_info_from_dump(dump, &info);
    transit_idents_t ids;
    transit_mfdes_identify(&info, &ids);
    return transit_check_ident(what, &ids, name, want);
}

size_t transit_mfdes_summary_files(const transit_mfdes_info_t *info, transit_mfdes_file_t *files, size_t maxfiles) {
    size_t n = 0;
    for (size_t i = 0; info != NULL && mfdes_parsers[i].name != NULL; i++) {
        if (mfdes_parsers[i].identify(info) != TRANSIT_ID_MATCH) {
            continue;
        }
        for (uint8_t k = 0; k < mfdes_parsers[i].summary_count && n < maxfiles; k++) {
            if (transit_mfdes_info_has_aid(info, mfdes_parsers[i].summary[k].aid)) {
                files[n++] = mfdes_parsers[i].summary[k];
            }
        }
    }
    return n;
}

int transit_mfu_parse(const uint8_t *data, size_t datalen) {
    TRANSIT_RUN_PARSERS(mfu_parsers, data != NULL, data, datalen);
}

int transit_mfu_selftest(void) {
    TRANSIT_RUN_SELFTESTS(mfu_parsers);
}

int transit_mfu_identify(const uint8_t *data, size_t datalen, transit_idents_t *ids) {
    memset(ids, 0, sizeof(*ids));
    for (size_t i = 0; data != NULL && mfu_parsers[i].name != NULL; i++) {
        if (mfu_parsers[i].detect(data, datalen)) {
            transit_ident_add(ids, mfu_parsers[i].name, mfu_parsers[i].region, TRANSIT_HINT_MFU, mfu_parsers[i].id_level);
        }
    }
    return ids->count;
}

int transit_st25tb_parse(const uint8_t *data, size_t datalen, const uint8_t *uid) {
    TRANSIT_RUN_PARSERS(st25tb_parsers, data != NULL, data, datalen, uid);
}

int transit_st25tb_selftest(void) {
    TRANSIT_RUN_SELFTESTS(st25tb_parsers);
}

int transit_st25tb_identify(const uint8_t *data, size_t datalen, const uint8_t *uid, transit_idents_t *ids) {
    memset(ids, 0, sizeof(*ids));
    for (size_t i = 0; data != NULL && st25tb_parsers[i].name != NULL; i++) {
        if (st25tb_parsers[i].detect(data, datalen, uid)) {
            transit_ident_add(ids, st25tb_parsers[i].name, st25tb_parsers[i].region, TRANSIT_HINT_ST25TB, st25tb_parsers[i].id_level);
        }
    }
    return ids->count;
}

int transit_felica_parse(const transit_felica_card_t *card) {
    TRANSIT_RUN_PARSERS(felica_parsers, card != NULL, card);
}

int transit_felica_selftest(void) {
    TRANSIT_RUN_SELFTESTS(felica_parsers);
}

bool transit_felica_has_system_code(const uint16_t *system_codes, size_t count, uint16_t code) {
    for (size_t i = 0; system_codes != NULL && i < count; i++) {
        if (system_codes[i] == code) {
            return true;
        }
    }
    return false;
}

bool transit_felica_check_identify(const char *what, uint16_t system_code, const char *name, transit_id_t want) {
    // common area first, as a card lists it
    const uint16_t codes[] = { 0xFE00, system_code };
    transit_idents_t ids;
    transit_felica_identify(codes, ARRAYLEN(codes), &ids);
    return transit_check_ident(what, &ids, name, want);
}

int transit_felica_identify(const uint16_t *system_codes, size_t count, transit_idents_t *ids) {
    memset(ids, 0, sizeof(*ids));
    for (size_t i = 0; system_codes != NULL && felica_parsers[i].name != NULL; i++) {
        transit_ident_add(ids, felica_parsers[i].name, felica_parsers[i].region, TRANSIT_HINT_FELICA, felica_parsers[i].identify(system_codes, count));
    }
    return ids->count;
}

int transit_calypso_parse(const transit_calypso_card_t *card) {
    TRANSIT_RUN_PARSERS(calypso_parsers, card != NULL, card);
}

int transit_calypso_selftest(void) {
    TRANSIT_RUN_SELFTESTS(calypso_parsers);
}

int transit_calypso_identify(const transit_calypso_card_t *card, transit_idents_t *ids) {
    memset(ids, 0, sizeof(*ids));
    for (size_t i = 0; card != NULL && calypso_parsers[i].name != NULL; i++) {
        if (calypso_parsers[i].detect(card)) {
            transit_ident_add(ids, calypso_parsers[i].name, calypso_parsers[i].region, TRANSIT_HINT_CALYPSO, calypso_parsers[i].id_level);
        }
    }
    return ids->count;
}

bool transit_mfu_check_identify(const char *what, const uint8_t *data, size_t datalen, const char *name, transit_id_t want) {
    transit_idents_t ids;
    transit_mfu_identify(data, datalen, &ids);
    return transit_check_ident(what, &ids, name, want);
}

bool transit_st25tb_check_identify(const char *what, const uint8_t *data, size_t datalen, const char *name, transit_id_t want) {
    transit_idents_t ids;
    transit_st25tb_identify(data, datalen, NULL, &ids);
    return transit_check_ident(what, &ids, name, want);
}

bool transit_calypso_check_identify(const char *what, const transit_calypso_card_t *card, const char *name, transit_id_t want) {
    transit_idents_t ids;
    transit_calypso_identify(card, &ids);
    return transit_check_ident(what, &ids, name, want);
}
