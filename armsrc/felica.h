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
// Definitions internal to the FeliCa functionality
//-----------------------------------------------------------------------------
#ifndef __FELICA_H
#define __FELICA_H

#include "common.h"
#include "cmd.h"

void felica_sendraw(const PacketCommandNG *c);
void felica_sniff(uint32_t samplesToSkip, uint32_t triggersToSkip);
void felica_sim_lite(const uint8_t *uid);
void felica_dump_lite_s(void);

#endif
