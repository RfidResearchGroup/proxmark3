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
// ITSO (UK) parser for MIFARE DESFire dumps
//
// Layout from the Flipper Zero itso plugin (GPLv3): ISRN and expiry in file 0F.
//-----------------------------------------------------------------------------

#ifndef PARSEITSO_H__
#define PARSEITSO_H__

#include "common.h"
#include "fileutils.h"          // desfire_dump_t
#include "parsetransit.h"       // transit_mfdes_info_t

// AID as pm3 holds it, wire order 16 02 A0
#define ITSO_AID                0xA00216
#define ITSO_FID_SHELL          0x0F

bool is_valid_itso_card(const desfire_dump_t *dump);

// ITSO AID in the application list
transit_id_t itso_identify(const transit_mfdes_info_t *info);

int itso_parser_parse(const desfire_dump_t *dump);
int itso_selftest(void);

#endif
