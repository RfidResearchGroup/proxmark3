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
// PM5 card side: a small controller on the I2C bus owns the card's voltage,
// activation and reset, and wires the card's I/O line straight through to a
// USART. Everything above the electrical layer - framing included - is ours.
//-----------------------------------------------------------------------------

#ifndef SMARTCARD_HW_PM5_H
#define SMARTCARD_HW_PM5_H

#include <stdint.h>

// Frames are bounded by the buffers this stack reserves, not by the controller.
// Keep in step with ISO7816_MAX_FRAME in the command layer.
#define SC_PM5_MAX_FRAME        270

// The controller answers on this 8-bit I2C address. A register is addressed by
// a write of its number; the data body follows, in either direction.
#define SC_PM5_CTRL_ADDR        (0x52 << 1)

#define SC_PM5_REG_VCC          0x01    // 0 = 1.8 V, 1 = 3 V, 2 = 5 V
#define SC_PM5_REG_CARD_CTRL    0x02    // 1 = activate, 0 = deactivate
#define SC_PM5_REG_OFFN         0x03    // read only: bit0 = 1 no fault, card present
#define SC_PM5_REG_RST          0x04    // 1 = reset released (high), 0 = asserted (low)
#define SC_PM5_REG_CLK_DIV      0x05    // 0 = /8, 1 = /4, 2 = /2, 3 = /1
#define SC_PM5_REG_FW_VERSION   0xFF    // [major, minor]

// Card clock as it reaches the card. A timer drives 7.2 MHz into the front
// end, which halves it by default; a PPS moves Fi/Di, not this clock.
#define SC_PM5_CARD_CLK_HZ      3600000

// Divider the front end applies to its clock input: /2.
#define SC_PM5_CLK_DIV_2        2

#endif // SMARTCARD_HW_PM5_H
