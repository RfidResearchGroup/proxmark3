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
// myki (Melbourne) parser for MIFARE DESFire dumps
//
// Layout from Metrodroid MykiTransitData (GPLv3). Only the card number is
// free to read, everything else is locked.
//-----------------------------------------------------------------------------

#ifndef PARSEMYKI_H__
#define PARSEMYKI_H__

#include "common.h"
#include "fileutils.h"          // desfire_dump_t
#include "parsetransit.h"       // transit_mfdes_info_t

// AIDs as pm3 holds them, wire order 00 11 F2 and F0 10 F2
#define MYKI_AID_1              0xF21100
#define MYKI_AID_2              0xF210F0
#define MYKI_FID_SERIAL         0x0F

bool is_valid_myki_card(const desfire_dump_t *dump);

// Both myki AIDs in the application list
transit_id_t myki_identify(const transit_mfdes_info_t *info);

int myki_parser_parse(const desfire_dump_t *dump);
int myki_selftest(void);

#endif
