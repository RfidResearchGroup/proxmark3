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
// MIFARE DESFire tag simulation.
//
// Self contained: everything DESFire lives in desfiresim.c, including its own
// ISO 14443-A loop. It borrows the library helpers from iso14443a.c -- the
// precompiled activation answers, the receive call, the send calls -- but not
// SimulateIso14443aTag() itself, which is complicated enough without a DESFire
// state machine threaded through it.
//-----------------------------------------------------------------------------

#ifndef __DESFIRESIM_H
#define __DESFIRESIM_H

#include "common.h"

// Simulate the DESFire card image sitting in emulator memory, as put there by
// `hf mfdes eload`. Self contained: this owns its own ISO 14443-A loop rather
// than hooking into SimulateIso14443aTag(), which is busy enough already.
// Runs until the button is pressed or the client breaks the loop, and answers
// on CMD_HF_DESFIRE_SIMULATE.
void SimulateDesfireTag(void);

#endif // __DESFIRESIM_H
