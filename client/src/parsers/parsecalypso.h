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
// EN 1545 structure walker and Calypso helpers shared by the Calypso parsers
//
// Bitmap driven field layout after Metrodroid's En1545Parser (GPLv3).
//-----------------------------------------------------------------------------

#ifndef PARSECALYPSO_H__
#define PARSECALYPSO_H__

#include "common.h"
#include "parsetransit.h"

typedef enum {
    EN1545_K_INT,           // fixed width field, wider than 64 bits is only marked present
    EN1545_K_BITMAP,        // presence bitmap, one bit per child, lowest bit first
    EN1545_K_CONTAINER,     // children in sequence
    EN1545_K_REPEAT,        // counter of `bits` width, then the single child that many times
} en1545_kind_t;

typedef struct en1545_field {
    en1545_kind_t kind;
    uint16_t bits;
    const char *name;
    const struct en1545_field *sub;
    uint8_t nsub;
} en1545_field_t;

#define EN1545_INT(n, b)        { EN1545_K_INT, (b), (n), NULL, 0 }
#define EN1545_BITMAP(a)        { EN1545_K_BITMAP, 0, NULL, (a), (uint8_t)(sizeof(a) / sizeof((a)[0])) }
#define EN1545_CONTAINER(a)     { EN1545_K_CONTAINER, 0, NULL, (a), (uint8_t)(sizeof(a) / sizeof((a)[0])) }
#define EN1545_REPEAT(c, a)     { EN1545_K_REPEAT, (c), NULL, (a), 1 }

#define EN1545_MAX_VALUES       64

typedef struct {
    const char *name;
    uint8_t idx;            // iteration of the enclosing repeat, 0 outside one
    uint16_t off;
    uint16_t bits;
    uint64_t value;
} en1545_value_t;

typedef struct {
    uint8_t count;
    en1545_value_t v[EN1545_MAX_VALUES];
} en1545_parsed_t;

// Walk buf from bit off, returns the bit offset after the structure.
// Fields running past the buffer are not stored.
size_t en1545_parse(const uint8_t *buf, size_t buflen, size_t off, const en1545_field_t *f, en1545_parsed_t *out);

bool en1545_get(const en1545_parsed_t *p, const char *name, uint8_t idx, uint64_t *value);
uint64_t en1545_get_or(const en1545_parsed_t *p, const char *name, uint8_t idx, uint64_t def);

// EN 1545 day 0 is 1997-01-01, day 0 prints as "-"
void en1545_date_str(char *out, size_t outlen, uint64_t days);
void en1545_datetime_str(char *out, size_t outlen, uint64_t days, uint64_t minutes);

// Intercode ticketing environment, also used by Opus
extern const en1545_field_t calypso_intercode_env;

// EnvNetworkId of an Intercode style environment, 0 when not read
uint32_t calypso_intercode_network(const transit_calypso_card_t *card);

bool calypso_record_empty(const transit_calypso_record_t *rec);

// Counter of a contract, 1 based record number: 2069 first, then its own 202A..202D
bool calypso_contract_counter(const transit_calypso_card_t *card, uint8_t recno, uint32_t *value);

// Event code high nibble is the transport, low nibble what happened
const char *calypso_transport_str(uint8_t transport);
const char *calypso_event_action_str(uint8_t action);

// Card number from the ICC record (Intercode / Opus), else the FCI serial
bool calypso_icc_card_number(const transit_calypso_card_t *card, char *out, size_t outlen);
void calypso_print_serial(const transit_calypso_card_t *card, bool use_icc);

// Walker checks shared by the Calypso parser self tests
bool en1545_selftest(void);

#endif
