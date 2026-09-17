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
// Routines to support the German electronic "Personalausweis" (ID card)
//-----------------------------------------------------------------------------

#ifndef __EPA_H
#define __EPA_H

#include "common.h"
#include "pm3_cmd.h"

void EPA_PACE_Collect_Nonce(const PacketCommandNG *c);
void EPA_PACE_Replay(const PacketCommandNG *c);
void EPA_PACE_Simulate(const PacketCommandNG *c);

#endif /* __EPA_H */
