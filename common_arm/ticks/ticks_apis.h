//-----------------------------------------------------------------------------
// Copyright (C) Jonathan Westhues, Aug 2005
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
// Timers, Clocks functions used in LF or Legic where you would need detailed time.
//-----------------------------------------------------------------------------

#ifndef TICKS_H_
#define TICKS_H_

#include "common.h"

#ifndef GET_TICKS
#define GET_TICKS GetTicks()
#endif

void StartTicks(void);
uint32_t GetTicks(void);
uint32_t RAMFUNC GetTicksDelta(uint32_t start);
void WaitUS(uint32_t us);
void WaitTicks(uint32_t ticks);
void ResetTicks(void);
void StopTicks(void);

void StartCountUS(void);
uint32_t RAMFUNC GetCountUS(void);

void SpinDelayUs(int us);

#ifndef AS_BOOTROM //////////////////////////////////////////////////////////////
// Bootrom does not require these functions.
// Wrap in #ifndef to avoid accidental bloat of bootrom

void SpinDelay(int ms);
void SpinDelayUsPrecision(int us);  // precision 0.6us , running for 43ms before

void StartTickCount(void);
uint32_t RAMFUNC GetTickCount(void);
uint32_t RAMFUNC GetTickCountDelta(uint32_t start_ticks);
void UpdateTickCountLabel(void);
uint32_t GetTickCountLabel(void);

// void ResetUSClock(void); No implemented?
// void SpinDelayCountUs(uint32_t us);

void StartCountSspClk(void);
void ResetSspClk(void);
uint32_t RAMFUNC GetCountSspClk(void);
uint32_t RAMFUNC GetCountSspClkDelta(uint32_t start);

void WaitMS(uint32_t ms);

#endif // #ifndef AS_BOOTROM

#endif // TICKS_H_
