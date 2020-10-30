//-----------------------------------------------------------------------------
// Jonathan Westhues, Aug 2005
// Iceman, Sept 2016
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Timers, Clocks functions used in LF or Legic where you would need detailed time.
//-----------------------------------------------------------------------------

#ifndef __TICKS_H
#define __TICKS_H

#include "common.h"

#ifndef GET_TICKS
#define GET_TICKS GetTicks()
#endif

void SpinDelay(int ms);
void SpinDelayUs(int us);
void SpinDelayUsPrecision(int us);  // precision 0.6us , running for 43ms before

void StartTickCount(void);
uint32_t RAMFUNC GetTickCount(void);
uint32_t RAMFUNC GetTickCountDelta(uint32_t start_ticks);

void StartCountUS(void);
uint32_t RAMFUNC GetCountUS(void);
void ResetUSClock(void);
void SpinDelayCountUs(uint32_t us);

void StartCountSspClk(void);
void ResetSspClk(void);
uint32_t RAMFUNC GetCountSspClk(void);
uint32_t RAMFUNC GetCountSspClkDelta(uint32_t start);

void StartTicks(void);
uint32_t GetTicks(void);
void WaitTicks(uint32_t ticks);
void WaitUS(uint32_t us);
void WaitMS(uint32_t ms);

void StopTicks(void);

#endif
