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
// Zolotaya Korona transport card parser for MIFARE Classic dumps
//
// Regional Russian cards (Krasnodar, Samara, Orenburg, Yaroslavl, ...).
// Layout ported from Metrodroid (GPLv3) transit/zolotayakorona, the info
// sector signature from the Flipper Zero zolotaya_korona plugin (GPLv3).
//-----------------------------------------------------------------------------

#ifndef PARSEZOLOTAYAKORONA_H__
#define PARSEZOLOTAYAKORONA_H__

#include "common.h"
#include "parsetransit.h"       // transit_mfc_info_t

// MAD entries for AID 18EE or the issuer name in sector 15
bool is_valid_zolotayakorona_card(const uint8_t *dump, size_t dumplen);

// The MAD entries in the block 1 an info command read
transit_id_t zolotayakorona_identify(const transit_mfc_info_t *info);
int zolotayakorona_parser_parse(const uint8_t *dump, size_t dumplen);
int zolotayakorona_selftest(void);

#endif
