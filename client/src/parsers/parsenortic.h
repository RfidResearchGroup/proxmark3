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
// NORTIC travel card parser for MIFARE DESFire dumps
//
// Norwegian Ticketing Interoperable Concept, the national public transport card
// specified by Statens vegvesen and now Jernbanedirektoratet, Handbok V821.
// Fields are EN 1545 coded.
//-----------------------------------------------------------------------------

#ifndef PARSENORTIC_H__
#define PARSENORTIC_H__

#include "common.h"
#include "fileutils.h"          // desfire_dump_t

// Card Issuer application. Its header file is free to read, no key needed.
#define NORTIC_AID_CARD_ISSUER  0x578000
#define NORTIC_FID_CI_HEADER    0x0C

// Transport application. Every file needs the read key, number 7.
#define NORTIC_AID_TRANSPORT    0x578001

// ISO 3166 numeric code carried in the first field of the card issuer header
#define NORTIC_COUNTRY_NORWAY   578

// True when the dump carries the NORTIC card issuer application
bool is_valid_nortic_card(const desfire_dump_t *dump);

// Decode the card issuer header and name what the transport application holds
int nortic_parser_parse(const desfire_dump_t *dump);

// Check the decoder against the published card issuer header
int nortic_selftest(void);

#endif
