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
// This is the DESFire half only. The 14a layer -- anticollision, RATS, framing,
// timing -- belongs to SimulateIso14443aTag() in iso14443a.c, which calls in
// here for tag type 3.
//-----------------------------------------------------------------------------

#ifndef __DESFIRESIM_H
#define __DESFIRESIM_H

#include "common.h"

// Largest answer built before the 14443-4 prologue and CRC are added.
// GetApplicationIDs on a full PICC is 28 * 3 bytes plus a status byte.
#define DESFIRE_SIM_MAX_RESP    128

// Pick up the card image `hf mfdes eload` put in emulator memory. False when
// there is none, or it is not a layout this firmware speaks -- the caller then
// simulates a bare DESFire shell that only answers the anticollision.
// Idempotent: call it as often as convenient, it parses once.
bool desfire_sim_init(void);

// Whether desfire_sim_init() found an image. Cheap, safe before init.
bool desfire_sim_ready(void);

// Card identity out of the image, for the precompiled 14a answers. Every
// pointer is optional; `ats` wants room for 20 bytes and comes back without its
// CRC, which is what SimulateIso14443aInit() expects.
void desfire_sim_identity(uint8_t *uid, uint8_t *uidlen, uint8_t *atqa, uint8_t *sak, uint8_t *ats, uint8_t *atslen);

// A fresh activation or a HALT puts the PICC back at AID 000000 and drops any
// command that was being chained.
void desfire_sim_reset(void);

// Answer one DESFire command. `in`/`inlen` is the ISO 14443-4 I-block payload
// with the prologue and CRC already stripped; `out` receives the status byte
// and its payload, at most DESFIRE_SIM_MAX_RESP bytes. Returns that length.
uint16_t desfire_sim_apdu(const uint8_t *in, uint16_t inlen, uint8_t *out);

// One line about what is loaded, for the simulation banner.
void desfire_sim_print_banner(void);

#endif // __DESFIRESIM_H
