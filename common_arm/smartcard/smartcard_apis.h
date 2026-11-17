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
// What every board has to provide so the layers above can talk to a card.
// Only interfaces about the card and its adapter live here; anything that is
// one board's own business stays in that board's header.
//-----------------------------------------------------------------------------

#ifndef SMARTCARD_APIS_H
#define SMARTCARD_APIS_H

#include <stdbool.h>
#include <stdint.h>

// --- porting layer: one implementation per board -----------------------------

// How a frame goes on the wire. Which controller opcode this becomes is the
// board's business, so no opcode appears in the shared interface.
typedef enum {
    SC_MODE_RAW = 0,    // the host owns the framing
    SC_MODE_T0,
    SC_MODE_T1,
} smartcard_mode_t;

// Reset the card and hand back the ATR bytes it answered with. Done together
// because on some boards the answer only exists inside the reset window.
bool SmartCard_HwAtr(uint8_t *atr, uint16_t *len, uint32_t wait);
bool SmartCard_HwSend(smartcard_mode_t mode, const uint8_t *data, uint16_t len);
bool SmartCard_HwRecv(uint8_t *dest, uint16_t *len, uint32_t wait);

// ISO 7816-3 clause 9. req is PPS0, optionally followed by PPS1; out is
// [ok][protocol in force][TA1 in force].
bool SmartCard_HwPps(const uint8_t *req, uint8_t req_len, uint8_t out[3], uint32_t wait);

// Adapter identity. Both boards carry an adapter, so the version is what says
// whether one is connected at all. Anything else the board can tell us about it
// goes through info, whose layout belongs to that board - see its header.
int SmartCard_HwModuleInfo(uint8_t *major, uint8_t *minor, void *info);

// Bring the adapter up.
void SmartCard_HwOpen(void);

// Put the link back on a rate negotiated earlier, in 16x clocks per etu.
bool SmartCard_HwSetReload(uint16_t reload);

// Card clock.
void SmartCard_HwSetClock(uint64_t f);

#endif // SMARTCARD_APIS_H
