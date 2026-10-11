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
#ifndef MIFARE_GALLAGHERCORE_H__
#define MIFARE_GALLAGHERCORE_H__

#include "common.h"
#include "crypto/libpcrypto.h"
#include <stdint.h>

typedef struct {
    uint8_t region_code;
    uint16_t facility_code;
    uint32_t card_number;
    uint8_t issue_level;
    bool mes;
    uint8_t csn[10];
    size_t csn_len;
    uint8_t site_key[16];
} GallagherCredentials_t;

int gallagher_diversify_classic_key(uint8_t *site_key, uint8_t *csn, size_t csn_len, uint8_t *key_output);

int gallagher_parse_cad(uint8_t *cad, uint8_t region, uint16_t facility);

void gallagher_encode_creds(uint8_t *eight_bytes, GallagherCredentials_t *creds);

void gallagher_decode_creds(uint8_t *eight_bytes, GallagherCredentials_t *creds);

int gallagher_construct_credential(GallagherCredentials_t *creds, uint8_t region, uint16_t facility, uint32_t card, uint8_t issue, bool mes, uint8_t *csn, size_t csn_len, uint8_t *site_key);

int gallagher_encode_mes(uint8_t *sector, GallagherCredentials_t *creds);

int gallagher_decode_mes(uint8_t *sector, GallagherCredentials_t *creds);

bool gallagher_is_valid_creds(uint64_t region_code, uint64_t facility_code, uint64_t card_number, uint64_t issue_level);

bool gallagher_is_valid_creds_struct(GallagherCredentials_t *creds);

void print_gallagher_creds(GallagherCredentials_t *creds);

#endif
