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
//
// Each card system lives in its own parsers/parse<name>.c and exposes
// is_valid_<name>_card(), <name>_parser_parse() and <name>_selftest() over
// plain byte buffers. The dispatchers below run every parser of a technology
// whose detection matches.
//-----------------------------------------------------------------------------

#ifndef PARSETRANSIT_H__
#define PARSETRANSIT_H__

#include "common.h"
#include "fileutils.h"          // desfire_dump_t
#include "ui.h"                 // PM3_PRINTF_FORMAT

// Days from 1970-01-01 to common transit epochs
#define TRANSIT_DAYS_TO_1980    3652
#define TRANSIT_DAYS_TO_1990    7305
#define TRANSIT_DAYS_TO_1997    9862    // EN 1545
#define TRANSIT_DAYS_TO_2000    10957

//-----------------------------------------------------------------------------
// Bit and byte access, out of range bits read as zero
//-----------------------------------------------------------------------------

// Most significant bit first, bit 0 is the top bit of byte 0 (EN 1545)
uint64_t transit_bits_be(const uint8_t *buf, size_t buflen, size_t off, uint8_t n);

// Least significant bit first, bit 0 is the low bit of byte 0
uint64_t transit_bits_le(const uint8_t *buf, size_t buflen, size_t off, uint8_t n);

// Writers for building self test vectors
void transit_set_bits_be(uint8_t *buf, size_t buflen, size_t off, uint8_t n, uint64_t v);
void transit_set_bits_le(uint8_t *buf, size_t buflen, size_t off, uint8_t n, uint64_t v);

// Sign extend the low n bits of v
int64_t transit_sign_extend(uint64_t v, uint8_t n);

bool transit_is_zero(const uint8_t *buf, size_t len);

// Two digit BCD byte, -1 when a nibble is not a digit
int transit_bcd(uint8_t b);

//-----------------------------------------------------------------------------
// Formatting, all write a NUL terminated string into out
//-----------------------------------------------------------------------------

void transit_civil_from_days(int32_t days, int *year, unsigned *month, unsigned *day);
int32_t transit_days_from_civil(int year, unsigned month, unsigned day);

// days since 1970-01-01 -> YYYY-MM-DD
void transit_date_str(char *out, size_t outlen, int32_t days);

// seconds since 1970-01-01 -> YYYY-MM-DD HH:MM:SS, no time zone applied
void transit_datetime_str(char *out, size_t outlen, int64_t secs);

// minor units -> "-12.34 AUD", decimals is the currency exponent
void transit_money_str(char *out, size_t outlen, int64_t minor, uint8_t decimals, const char *currency);

//-----------------------------------------------------------------------------
// Printing in one style for every card system
//-----------------------------------------------------------------------------

// Blank line and a cyan section banner
void transit_print_header(const char *title);

// "Label........... value", value formatted printf style
void transit_print_kv(const char *label, const char *fmt, ...) __attribute__((format(PM3_PRINTF_FORMAT, 2, 3)));

// Self test helper, prints and returns got == want
bool transit_check(const char *what, uint64_t got, uint64_t want);
bool transit_check_str(const char *what, const char *got, const char *want);

// Final self test line, returns PM3_SUCCESS or PM3_ESOFT
int transit_selftest_result(const char *name, bool ok);

//-----------------------------------------------------------------------------
// FeliCa view handed to the parsers. Service codes are as the specs write
// them, e.g. 0x090F for the Suica history.
//-----------------------------------------------------------------------------

typedef struct {
    uint16_t code;
    uint16_t block_count;
    const uint8_t *blocks;      // block_count * 16 bytes, block 0 first, NULL when not read
} transit_felica_service_t;

typedef struct {
    uint16_t system_code;
    uint8_t idm[8];
    size_t service_count;
    const transit_felica_service_t *services;
} transit_felica_system_t;

typedef struct {
    size_t system_count;
    const transit_felica_system_t *systems;
} transit_felica_card_t;

const transit_felica_system_t *transit_felica_find_system(const transit_felica_card_t *card, uint16_t system_code);
const transit_felica_service_t *transit_felica_find_service(const transit_felica_system_t *sys, uint16_t code);

//-----------------------------------------------------------------------------
// Calypso view handed to the parsers, records as read from the card
//-----------------------------------------------------------------------------

#define TRANSIT_CALYPSO_REC_LEN         29
#define TRANSIT_CALYPSO_MAX_CONTRACTS   8
#define TRANSIT_CALYPSO_MAX_EVENTS      3

typedef struct {
    uint8_t len;                // 0 when not read
    uint8_t data[TRANSIT_CALYPSO_REC_LEN];
} transit_calypso_record_t;

typedef struct {
    uint8_t serial[8];
    bool has_serial;
    transit_calypso_record_t env;           // SFI 07, 2001
    transit_calypso_record_t contract_list; // SFI 1E, 2050
    transit_calypso_record_t counters;      // SFI 19, 2069
    uint8_t contract_count;
    transit_calypso_record_t contracts[TRANSIT_CALYPSO_MAX_CONTRACTS];  // SFI 09, 2020
    uint8_t event_count;
    transit_calypso_record_t events[TRANSIT_CALYPSO_MAX_EVENTS];        // SFI 08, 2010
} transit_calypso_card_t;

//-----------------------------------------------------------------------------
// Dispatch per technology, return how many parsers matched
//-----------------------------------------------------------------------------

// MIFARE Classic, dump starts at block 0
int transit_mfc_parse(const uint8_t *dump, size_t dumplen);
int transit_mfc_selftest(void);

// MIFARE DESFire, as written by `hf mfdes dump`
int transit_mfdes_parse(const desfire_dump_t *dump);
int transit_mfdes_selftest(void);

// MIFARE Ultralight / NTAG, page 0 first, no dump prefix
int transit_mfu_parse(const uint8_t *data, size_t datalen);
int transit_mfu_selftest(void);

// ST25TB / SRx, block 0 first, uid as printed by `hf 14b view`
int transit_st25tb_parse(const uint8_t *data, size_t datalen, const uint8_t *uid);
int transit_st25tb_selftest(void);

int transit_felica_parse(const transit_felica_card_t *card);
int transit_felica_selftest(void);

int transit_calypso_parse(const transit_calypso_card_t *card);
int transit_calypso_selftest(void);

#endif
