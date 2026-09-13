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
// VIGIK PACS parser for MIFARE Classic dumps
//-----------------------------------------------------------------------------

#ifndef PARSEVIGIK_H__
#define PARSEVIGIK_H__

#include "common.h"
#include "protocol_vigik.h"

// MAD application ids the VIGIK scheme claims
#define VIGIK_MAD_AID       0x4910
#define VIGIK_MAD_AID_ALT   0x4916

// True when the MAD of this dump advertises the VIGIK application
bool is_valid_vigik_card(const uint8_t *dump, size_t dumplen);

// Collect the VIGIK sectors out of a whole card dump and print them
int vigik_parser_parse(const uint8_t *dump, size_t dumplen);

// Lower level helpers, on an already assembled VIGIK structure
const char *vigik_get_service(uint16_t service_code);
int vigik_verify(mfc_vigik_t *d);
int vigik_annotate(mfc_vigik_t *d);

#endif
