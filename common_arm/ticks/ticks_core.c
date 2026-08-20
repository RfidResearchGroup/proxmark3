//-----------------------------------------------------------------------------
// Copyright (C) Jonathan Westhues, Sept 2005
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
#include "ticks_apis.h"

// For OS include
#ifndef AS_BOOTROM
#include "dbprint.h"
#endif

#ifndef AS_BOOTROM

// Increments whenever StartTickCount() reconfigures/resets RTTC.
// Callers can use this to detect that previously saved tick deltas are no longer valid.
static uint32_t g_tickcount_label = 0;

// WARNING: timer can't measure more than 1.39s (21.3us * 0xffff)
void SpinDelay(int ms) {
    if (ms > 1390) {
        if (g_dbglevel >= DBG_ERROR) Dbprintf(_RED_("Error, SpinDelay called with %i > 1390"), ms);
        ms = 1390;
    }
    // convert to us and call microsecond delay function
    SpinDelayUs(ms * 1000);
}

// Get tick count from start_ticks to now.
uint32_t RAMFUNC GetTickCountDelta(uint32_t start_ticks) {
    uint32_t stop_ticks = GetTickCount();
    if (stop_ticks >= start_ticks) {
        return stop_ticks - start_ticks;
    }
    return (UINT32_MAX - start_ticks) + stop_ticks;
}

/*
 * Call this function within StartTickCount() to increment the tick count label.
 * You must do it in all platform implementations.
 */
void UpdateTickCountLabel(void) {
    g_tickcount_label++;
}

/*
 * Get current RTTC counter label.
 * If counter config changes between calls, the value is incremented.
 */
uint32_t GetTickCountLabel(void) {
    return g_tickcount_label;
}

uint32_t RAMFUNC GetCountSspClkDelta(uint32_t start) {
    uint32_t stop = GetCountSspClk();
    if (stop >= start) {
        return stop - start;
    }
    return (UINT32_MAX - start) + stop;
}

void WaitMS(uint32_t ms) {
    WaitTicks((ms & 0x1FFFFF) * 1500);
}

#endif

uint32_t RAMFUNC GetTicksDelta(uint32_t start) {
    uint32_t stop = GetTicks();
    if (stop >= start) {
        return stop - start;
    }
    return (UINT32_MAX - start) + stop;
}

// Wait - Spindelay in ticks.
// if called with a high number, this will trigger the WDT...
void WaitTicks(uint32_t ticks) {
    if (ticks == 0) return;
    ticks += GetTicks();
    while (GetTicks() < ticks);
}

// Wait / Spindelay in us (microseconds)
// 1us = 1.5ticks.
void WaitUS(uint32_t us) {
    WaitTicks((us & 0x3FFFFFFF) * 3 / 2);
}
