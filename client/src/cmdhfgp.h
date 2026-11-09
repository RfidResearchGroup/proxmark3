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
// GlobalPlatform commands
//-----------------------------------------------------------------------------

#ifndef CMDHFGP_H__
#define CMDHFGP_H__

#include "common.h"
#include "iso7816/iso7816core.h"

int CmdHFGP(const char *Cmd);

// Find applet AIDs via partial SELECT, empty prefix sweeps known prefixes and registered RIDs
int gp_find_aids(Iso7816CommandChannel channel, const uint8_t *prefix, size_t prefix_len, bool quick, bool verbose);

// Read ISD info without authentication: card data, CPLC, key info, IIN, CIN
int gp_info(Iso7816CommandChannel channel, bool verbose);

// List contactless applets via the GP CRS application (no authentication needed)
int gp_crs_list(Iso7816CommandChannel channel, const uint8_t *aid, size_t aid_len, bool verbose);

#endif
