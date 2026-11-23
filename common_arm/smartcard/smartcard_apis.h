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

// Card supply voltage. Not every board can select one; the porting layer says
// so rather than pretending.
typedef enum {
    SC_VCC_1V8 = 0,
    SC_VCC_3V0,
    SC_VCC_5V0,
} smartcard_vcc_t;

// Card-detect result. SC_CHK_UNSUPPORTED means the board has no way to tell.
// Both SC_CHK_PRESENT and SC_CHK_UNSUPPORTED should be considered as indicating that the card is present.
typedef enum {
    SC_CHK_PRESENT = 0, // The card does indeed exist.
    SC_CHK_NONE,        // There is indeed no card.
    SC_CHK_UNSUPPORTED, // There is no card-insertion detection feature.
} smartcard_present_t;

// Reset the card and hand back the ATR bytes it answered with. Done together
// because on some boards the answer only exists inside the reset window.
bool SmartCard_HwATR(uint8_t *atr, uint16_t *len, uint32_t wait);

// Hand one frame to the card with the requested framing. A board may run the
// whole T=0 dialogue here and hold the answer for SmartCard_HwRecv(). False
// means the frame could not be sent.
bool SmartCard_HwSend(smartcard_mode_t mode, const uint8_t *data, uint16_t len);

// Read the card's answer. On entry *len is the capacity of dest; on success it
// is the number of bytes read. wait is the board's receive budget. False means
// no answer or a link error.
bool SmartCard_HwRecv(uint8_t *dest, uint16_t *len, uint32_t wait);

// ISO 7816-3 clause 9. req is PPS0, optionally followed by PPS1; out is
// [ok][protocol in force][TA1 in force].
bool SmartCard_HwPPS(const uint8_t *req, uint8_t req_len, uint8_t out[3], uint32_t wait);

// Adapter identity. Both boards carry an adapter, so the version is what says
// whether one is connected at all. Anything else the board can tell us about it
// goes through info, whose layout belongs to that board - see its header.
int SmartCard_HwAdapterInfo(uint8_t *major, uint8_t *minor, void *info);

// Bring the adapter up.
void SmartCard_HwOpen(void);

// Power the card down. The adapter stays up; a later open or ATR powers the
// card again. Boards without card power control do nothing.
void SmartCard_HwClose(void);

// Ask whether a card is inserted. A board without card-detect hardware reports
// SC_CHK_UNSUPPORTED rather than pretending the card is absent.
smartcard_present_t SmartCard_HwGetPresent(void);

// Put the link back on a rate negotiated earlier, in 16x clocks per etu.
bool SmartCard_HwSetReload(uint16_t reload);

// Card clock.
void SmartCard_HwSetClock(uint64_t f);

// Select the card supply voltage. Applied by the next reset, so this does not
// disturb a running card. Returns false when the board cannot select it.
bool SmartCard_HwSetVoltage(smartcard_vcc_t v);

#endif // SMARTCARD_APIS_H
