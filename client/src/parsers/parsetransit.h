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
// whose detection matches, the identify functions name a card for info commands.
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
    transit_calypso_record_t icc;           // SFI 02, 0002
    transit_calypso_record_t env;           // SFI 07, 2001
    transit_calypso_record_t contract_list; // SFI 1E, 2050
    transit_calypso_record_t counters;      // SFI 19, 2069
    uint8_t contract_count;
    transit_calypso_record_t contracts[TRANSIT_CALYPSO_MAX_CONTRACTS];  // SFI 09 then 06, 2020 / 2030
    transit_calypso_record_t contract_counters[4];                      // SFI 0A..0D, 202A..202D
    uint8_t event_count;
    transit_calypso_record_t events[TRANSIT_CALYPSO_MAX_EVENTS];        // SFI 08, 2010
} transit_calypso_card_t;

//-----------------------------------------------------------------------------
// Identification from the partial data an info command has at hand
//-----------------------------------------------------------------------------

typedef enum {
    TRANSIT_ID_NONE = 0,
    TRANSIT_ID_POSSIBLE,        // heuristic evidence only
    TRANSIT_ID_MATCH,
} transit_id_t;

typedef struct {
    const char *name;
    const char *region;         // area or operator
    const char *hint;           // command that fully decodes it
    bool possible;
} transit_ident_t;

#define TRANSIT_MAX_IDENTS      4

typedef struct {
    uint8_t count;
    transit_ident_t ident[TRANSIT_MAX_IDENTS];
} transit_idents_t;

// "Transit.......... name ( region )" per identification
void transit_print_idents(const transit_idents_t *ids);

// One hint per distinct decode command, skipping the command already running
void transit_print_ident_hints(const transit_idents_t *ids, const char *current_cmd);

// Self test helper, checks how ids name a card system
bool transit_check_ident(const char *what, const transit_idents_t *ids, const char *name, transit_id_t want);

// MIFARE Classic: keys found per sector, MAD block when read
#define TRANSIT_MFC_MAX_SECTORS 40
#define TRANSIT_MFC_KEY_A       0       // same as MF_KEY_A
#define TRANSIT_MFC_KEY_B       1
#define TRANSIT_MFC_KEY_AB      2

typedef struct {
    bool found[TRANSIT_MFC_MAX_SECTORS][2];
    uint64_t key[TRANSIT_MFC_MAX_SECTORS][2];
    const uint8_t *block1;      // sector 0 block 1, NULL when not read
} transit_mfc_info_t;

// Identifying key of a sector
typedef struct {
    uint8_t sector;
    uint8_t keytype;
    uint64_t key;
} transit_mfc_key_t;

// Every listed sector needs one matching key, or just one sector with any_sector
typedef struct {
    const transit_mfc_key_t *keys;
    uint8_t count;
    bool any_sector;
} transit_mfc_keyset_t;

bool transit_mfc_keyset_match_dump(const transit_mfc_keyset_t *ks, const uint8_t *dump, size_t dumplen);
bool transit_mfc_keyset_match_info(const transit_mfc_keyset_t *ks, const transit_mfc_info_t *info);

// Distinct signature keys of a sector for one key type, 6 bytes each, returns the count
size_t transit_mfc_signature_keys(uint8_t sector, uint8_t keytype, uint8_t *keys, size_t maxkeys);

// Checks keys of one sector, true and *found set when one authenticates
typedef bool (*transit_mfc_check_fn)(void *ctx, uint8_t sector, uint8_t keytype, const uint8_t *keys, size_t n, uint64_t *found);

// Two stage probe: one key A check per sector with the parsers' signature keys, then only
// the remaining keys of parsers whose signature matched. Keys already in info are reused.
void transit_mfc_probe(transit_mfc_info_t *info, uint8_t sectors, transit_mfc_check_fn check, void *ctx);

// Self test helper, identifies a dump from the keys an info command probe would find
bool transit_mfc_check_identify(const char *what, const uint8_t *dump, size_t dumplen, const char *name, transit_id_t want);

int transit_mfc_identify(const transit_mfc_info_t *info, transit_idents_t *ids);

// MIFARE DESFire: application list and ATS
typedef struct {
    bool aids_known;
    uint8_t aidcount;
    uint32_t aids[DESFIRE_MAX_APP_COUNT];
    const iso14a_card_select_t *card;   // NULL when the ATS is unknown
} transit_mfdes_info_t;

typedef struct {
    uint32_t aid;
    uint8_t fid;
} transit_mfdes_file_t;

void transit_mfdes_info_from_dump(const desfire_dump_t *dump, transit_mfdes_info_t *info);
bool transit_mfdes_info_has_aid(const transit_mfdes_info_t *info, uint32_t aid);

int transit_mfdes_identify(const transit_mfdes_info_t *info, transit_idents_t *ids);

// Self test helper, identifies a dump from its application list and ATS
bool transit_mfdes_check_identify(const char *what, const desfire_dump_t *dump, const char *name, transit_id_t want);

// Free files the identified parsers decode a summary from, returns the count
size_t transit_mfdes_summary_files(const transit_mfdes_info_t *info, transit_mfdes_file_t *files, size_t maxfiles);

// FeliCa: system codes as the specs write them
bool transit_felica_has_system_code(const uint16_t *system_codes, size_t count, uint16_t code);
int transit_felica_identify(const uint16_t *system_codes, size_t count, transit_idents_t *ids);

// Self test helper, identifies a card from one system code
bool transit_felica_check_identify(const char *what, uint16_t system_code, const char *name, transit_id_t want);

// Ultralight, ST25TB and Calypso info commands read the same data a dump has
#define TRANSIT_MFU_IDENTIFY_LEN    64      // pages 0..15 cover every Ultralight parser
int transit_mfu_identify(const uint8_t *data, size_t datalen, transit_idents_t *ids);
int transit_st25tb_identify(const uint8_t *data, size_t datalen, const uint8_t *uid, transit_idents_t *ids);
int transit_calypso_identify(const transit_calypso_card_t *card, transit_idents_t *ids);

// Self test helpers for the three above
bool transit_mfu_check_identify(const char *what, const uint8_t *data, size_t datalen, const char *name, transit_id_t want);
bool transit_st25tb_check_identify(const char *what, const uint8_t *data, size_t datalen, const char *name, transit_id_t want);
bool transit_calypso_check_identify(const char *what, const transit_calypso_card_t *card, const char *name, transit_id_t want);

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
