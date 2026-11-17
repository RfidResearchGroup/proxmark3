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
// ATR decoding: what the answer to reset says about the card.
//-----------------------------------------------------------------------------

#ifndef SMARTCARD_ATR_H
#define SMARTCARD_ATR_H

#include <stdbool.h>
#include <stdint.h>

// Protocols an ATR offers, as (1 << T). 0 when the ATR is too short to tell.
uint8_t SmartCard_ATRProtocols(const uint8_t *atr, uint8_t len);

// The protocol named by TD1, which is what the card runs until a PPS changes
// it. 0 when the ATR does not name one.
uint8_t SmartCard_ATRFirstProto(const uint8_t *atr, uint8_t len);

// True when the ATR carries no checksum, or its checksum is correct.
bool SmartCard_ATRCheckTCK(const uint8_t *atr, uint8_t len);

#endif // SMARTCARD_ATR_H
