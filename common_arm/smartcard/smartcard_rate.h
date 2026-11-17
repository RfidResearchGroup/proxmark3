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
// Fi/Di arithmetic: what a card's interface bytes mean for the link rate.
//-----------------------------------------------------------------------------

#ifndef SMARTCARD_RATE_H
#define SMARTCARD_RATE_H

#include <stdbool.h>
#include <stdint.h>

// The controller's divisor for a TA1 (Fi / (16 * Di)), or 0 when the pair is
// unusable.
uint16_t SmartCard_RateReload(uint8_t ta1);

// The fastest rate worth proposing to a card, or 0 for none.
uint8_t SmartCard_RateBestTa1(const uint8_t *atr, uint8_t len);

#endif // SMARTCARD_RATE_H
