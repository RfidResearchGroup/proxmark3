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
// AID DESFire functions
//-----------------------------------------------------------------------------

#ifndef _AIDDESFIRE_H_
#define _AIDDESFIRE_H_

#include "common.h"

const char *nxp_cluster_to_text(uint8_t cluster);
int AIDDFDecodeAndPrint(uint8_t aid[3]);

#endif // _AIDDESFIRE_H_
