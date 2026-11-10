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
// Opal (Sydney) parser for MIFARE DESFire dumps
//
// Layout from Metrodroid OpalTransitData (GPLv3), free read file 07.
//-----------------------------------------------------------------------------

#ifndef PARSEOPAL_H__
#define PARSEOPAL_H__

#include "common.h"
#include "fileutils.h"          // desfire_dump_t
#include "parsetransit.h"       // transit_mfdes_info_t

// AID as pm3 holds it, wire order 31 45 53
#define OPAL_AID                0x534531
#define OPAL_FID_CARD           0x07

bool is_valid_opal_card(const desfire_dump_t *dump);

// Opal AID in the application list
transit_id_t opal_identify(const transit_mfdes_info_t *info);

int opal_parser_parse(const desfire_dump_t *dump);
int opal_selftest(void);

#endif
