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
// Clipper (San Francisco Bay Area) parser for MIFARE DESFire dumps
//
// Layout from Metrodroid ClipperTransitData and the Flipper Zero clipper
// plugin by Jeremy Cooper, both GPLv3.
//-----------------------------------------------------------------------------

#ifndef PARSECLIPPER_H__
#define PARSECLIPPER_H__

#include "common.h"
#include "fileutils.h"          // desfire_dump_t
#include "parsetransit.h"       // transit_mfdes_info_t

// AIDs as pm3 holds them, wire order 90 11 F2 and 91 11 F2
#define CLIPPER_AID_CARD        0xF21190
#define CLIPPER_AID_MOBILE      0xF21191

#define CLIPPER_FID_INFO        0x01    // expiry
#define CLIPPER_FID_ECASH       0x02    // balance
#define CLIPPER_FID_REFILLS     0x04
#define CLIPPER_FID_IDENTITY    0x08    // serial
#define CLIPPER_FID_HISTORY     0x0E

bool is_valid_clipper_card(const desfire_dump_t *dump);

// Card or mobile AID in the application list
transit_id_t clipper_identify(const transit_mfdes_info_t *info);

int clipper_parser_parse(const desfire_dump_t *dump);
int clipper_selftest(void);

#endif
