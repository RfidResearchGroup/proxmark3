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
// Proxmark5 power-save idle: core clock scaling + WFI - see pm5_power.c.
//-----------------------------------------------------------------------------
#ifndef PM5_POWER_H__
#define PM5_POWER_H__

#include "common.h"

#ifdef PM5

// Call once from AppMain after USB is up.
void pm5_power_init(void);

// Refcounted hold on the full 288 MHz core clock. Wrap anything with timing
// that assumes the boot clock (commands, standalone mode, I2C, buzzer).
void pm5_power_boost(void);
void pm5_power_unboost(void);

// Main-loop idle step: drop to the idle clock when allowed, then halt the core
// until the next IRQ or the 1 ms wake tick.
void pm5_power_idle(void);

// Runtime toggle (default on). Off = spin at 288 MHz like before.
void pm5_power_set_enabled(bool on);
bool pm5_power_get_enabled(void);

// `hw status` section.
void pm5_power_print_status(void);

#endif // PM5

#endif // PM5_POWER_H__
