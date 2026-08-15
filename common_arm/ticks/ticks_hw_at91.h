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
// Timers / Clocks HAL: AT91 (SAM7S) hardware definitions.
//-----------------------------------------------------------------------------

#ifndef TICKS_HW_AT91_H
#define TICKS_HW_AT91_H

#include "at91sam7s512.h"

// Input capture edge-event flags (single-bit masks in the TC1 status register).
// On AT91, reading TC_SR clears these flags automatically.
#define INPUT_CAPTURE_EVT_RA   AT91C_TC_LDRAS   // rising-edge load (RA) event
#define INPUT_CAPTURE_EVT_RB   AT91C_TC_LDRBS   // falling-edge load (RB) event

#endif // TICKS_HW_AT91_H
