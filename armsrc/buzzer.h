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
// PM5 (AT32F435) mainboard buzzer.
//
// The buzzer is a piezo on PB13 (enable) driven by TMR8_CH4 PWM on PC9. This is
// NOT BWM-specific hardware - it lives on the PM5 mainboard - so the API is
// generic and any feature (QC self-test, BWM low-battery warning, ...) can use
// it. Only the PM5 platform builds the implementation; callers must therefore
// guard usage with #ifdef PM5 (or a PM5-only feature flag).
//-----------------------------------------------------------------------------

#ifndef __BUZZER_H
#define __BUZZER_H

#include "common.h"

// Default PWM period (TMR8 auto-reload) and compare value programmed by
// BuzzerSetup(). period 999 with the /96 prescaler in the setup gives ~2 kHz
// from the 192 MHz timer clock; duty 500 is ~50%.
#define BUZZER_DEFAULT_PERIOD   999
#define BUZZER_DEFAULT_DUTY     500

// One-time TMR8/GPIO bring-up. Safe to call more than once (it just re-runs the
// init). BuzzerTone()/BuzzerBeep() call this automatically on first use, so most
// callers never need to invoke it directly.
void BuzzerSetup(void);

// Sound the buzzer for on_ms milliseconds at the given PWM period/duty.
//   period : TMR8 auto-reload value  (higher period -> lower pitch)
//   duty   : TMR8_CH4 compare value  (~duty/period fraction)
// Blocking (SpinDelay) - only call from a context that may block (e.g. the idle
// loop or a self-test), never from inside a time-critical operation.
void BuzzerTone(uint16_t period, uint16_t duty, uint16_t on_ms);

// Sound the buzzer for on_ms milliseconds at the default pitch/duty.
void BuzzerBeep(uint16_t on_ms);

// Force the buzzer enable line low (silence). No-op if never set up.
void BuzzerOff(void);

#endif // __BUZZER_H
