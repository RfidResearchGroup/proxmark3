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
void SpinDelayUsPrecision(int us);  // precision 0.6us, no upper bound on the delay

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

// -------------------------------------------------------------------------
// Generic precision timer counter, input capture and timestamp counter.
// These primitives back the precise timing / edge-capture needs of the LF
// protocols (e.g. Hitag). They are intentionally generic and platform-agnostic.
//
// The precision counter and timestamp counter both run at 1.5 MHz
// (12 counts = 1 T0 = 8 us, see hitag_common.h for the T0 definition).
// -------------------------------------------------------------------------

// Free-running precision counter @ 1.5 MHz (12 counts = 1 T0 = 8 us).
//
// The counter is never stopped or zeroed while a session is running.  It is
// 16 bit, so it wraps every 43.7 ms, and every reading here is a difference:
// unsigned 16 bit subtraction gives the right answer straight across a wrap, for
// any interval shorter than a full turn of the counter.
//
// ResetPrecisionCounter() therefore only moves the reference the plain
// GetPrecisionCounter() is measured from; it does not touch the hardware.  That
// keeps all the "time since the last mark" call sites reading the same as
// before, without a software trigger whose effect has to be waited for - waiting
// for the counter to read exactly zero could step over the window and then sit
// out a whole 43.7 ms wrap before zero came round again.
void     StartPrecisionCounter(void);   // configure + start
void     StopPrecisionCounter(void);
void     ResetPrecisionCounter(void);   // mark a new reference point
uint16_t RAMFUNC GetPrecisionCounter(void);      // ticks since that reference
uint16_t RAMFUNC GetPrecisionCounterRaw(void);   // the free running counter itself
uint16_t RAMFUNC GetPrecisionCounterDelta(uint16_t start); // ticks since `start`

// Input capture(LF_EDGE_DETECT): rising/falling edges of an external signal.
void      StartLoEdgeCapture(void);       // configure + start + reset
void      StopLoEdgeCapture(void);        // disable capture
void      EnableLoEdgeCapture(void);      // re-enable + reset (no reconfiguration)
void      ResetLoEdgeCapture(void);       // software reset
typedef   enum { LO_EDGE_NO = 0, LO_EDGE_RISING = 1, LO_EDGE_FALLING = 2 } lo_edge_t;
lo_edge_t RAMFUNC GetLoEdgeCaptureStatus(void);  // edge-event flags (reading clears them)
uint16_t  RAMFUNC GetLoEdgeCaptureCount(void);   // current free-running count
uint16_t  RAMFUNC GetLoEdgeCaptureFalling(void); // value captured on the falling edge
uint16_t  RAMFUNC GetLoEdgeCaptureRising(void);  // value captured on the rising edge

// Monotonic timestamp counter (free-running + overflow accumulation).
// One 125 kHz carrier period (8 us) equals this many counter ticks at 1.5 MHz.
#define TICKS_PER_CARRIER_PERIOD 12
void     StartTimestamp(void);    // configure + start + clear (counter and overflow)
void     StopTimestamp(void);
uint32_t RAMFUNC GetTimestamp(void); // monotonic timestamp in 125 kHz carrier periods

#endif // #ifndef AS_BOOTROM

#ifdef PM5
#include "ticks_hw_at32.h"
#else
#include "ticks_hw_at91.h"
#endif

#endif // TICKS_H_
