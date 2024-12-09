//-----------------------------------------------------------------------------
// Copyright (C) Gerhard de Koning Gans - May 2008
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
// Mifare Classic Card Simulation
//-----------------------------------------------------------------------------

#ifndef __EMVSIM_H
#define __EMVSIM_H

#include "common.h"

#define AUTHKEYNONE              0xff

void EMVsim(uint16_t flags, uint8_t exitAfterNReads, uint8_t *datain, uint16_t atqa, uint8_t sak);

#endif