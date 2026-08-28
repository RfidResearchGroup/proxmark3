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
// PM5 antenna-RGB "alive on battery" indicator (WITH_PM5_PWR_LED).
//
// Policy layer on top of the low-level RGB driver (rgb_apis.h / RgbLedSet): lights
// the antenna RGB dim green while the PM5 runs on battery and turns it off on USB.
// It also arbitrates ownership of the LED with `hf/lf tune --rgb`, which claims the
// RGB directly via CMD_PM5_RGB_SET.
//-----------------------------------------------------------------------------

#ifndef __RGB_INDICATOR_H
#define __RGB_INDICATOR_H

#include "common.h"

#ifdef WITH_PM5_PWR_LED

// Throttled + edge-triggered indicator update. Call from the idle loop: it only
// touches the RGB over I2C when the USB-present state actually changes, and it
// yields the LED entirely while an external user (tune) owns it.
void rgb_indicator_update(void);

// Claim/release the RGB for an external user (e.g. tune). While claimed, the
// indicator leaves the LED alone; releasing it forces a refresh next update.
// `owned` = true when a non-zero colour was set, false when cleared.
void rgb_indicator_set_external(bool owned);

#endif // WITH_PM5_PWR_LED

#endif // __RGB_INDICATOR_H
