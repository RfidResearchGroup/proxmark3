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
// nol (Dubai) parser for MIFARE DESFire dumps
//
// Layout from Metrodroid NolTransitData and Metroflip nol plugin, both GPLv3.
// Only the card number and type are free to read.
//-----------------------------------------------------------------------------

#ifndef PARSENOL_H__
#define PARSENOL_H__

#include "common.h"
#include "fileutils.h"          // desfire_dump_t
#include "parsetransit.h"       // transit_mfdes_info_t

// AIDs as pm3 holds them, wire order 00 40 78 and FF FF FF
#define NOL_AID_TRANSIT         0x784000
#define NOL_AID_SERIAL          0xFFFFFF
#define NOL_FID_SERIAL          0x08

bool is_valid_nol_card(const desfire_dump_t *dump);

// Both nol AIDs in the application list
transit_id_t nol_identify(const transit_mfdes_info_t *info);

int nol_parser_parse(const desfire_dump_t *dump);
int nol_selftest(void);

#endif
