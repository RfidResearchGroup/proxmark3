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
#include <stdint.h>

typedef struct {
    uint8_t region_code;
    uint16_t facility_code;
    uint32_t card_number;
    uint8_t issue_level;
} GallagherCredentials_t;

void gallagher_encode_creds(uint8_t *eight_bytes, GallagherCredentials_t *creds);

void gallagher_decode_creds(uint8_t *eight_bytes, GallagherCredentials_t *creds);

bool gallagher_is_valid_creds(uint64_t region_code, uint64_t facility_code, uint64_t card_number, uint64_t issue_level);

#endif
