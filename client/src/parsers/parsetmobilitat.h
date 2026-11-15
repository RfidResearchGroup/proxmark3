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
// T-Mobilitat (Barcelona) parser for MIFARE DESFire dumps
//
// From the Metroflip tmobilitat plugin (GPLv3): the card number sits in the
// ATS historical bytes, the files are locked.
//-----------------------------------------------------------------------------

#ifndef PARSETMOBILITAT_H__
#define PARSETMOBILITAT_H__

#include "common.h"
#include "fileutils.h"          // desfire_dump_t
#include "parsetransit.h"       // transit_mfdes_info_t

// AID as pm3 holds it, wire order 05 00 00. Ljubljana Urbana uses it too.
#define TMOBILITAT_AID          0x000005

bool is_valid_tmobilitat_card(const desfire_dump_t *dump);

// Historical bytes and AID, only possible when the application list is unknown
transit_id_t tmobilitat_identify(const transit_mfdes_info_t *info);

int tmobilitat_parser_parse(const desfire_dump_t *dump);
int tmobilitat_selftest(void);

#endif
