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
#include "proxmark3_arm.h"


// Both delays below run on PWM channel 0 and wait the same way.
//
// The wait is on the wrapped difference from a starting count, not on
// `now == end`. Equality only holds if the loop happens to sample that exact
// value, so an interrupt or a slow read that steps the counter past it used to
// cost a full 16 bit period before it came round again - 1.39 s at this
// prescaler, 43.7 ms at the precision one. It also needed an `if (end == 0)
// end++` guard that the difference form does not.
//
// The counter is 16 bit, so one comparison spans at most 65535 ticks. Longer
// waits are walked in chunks, advancing `start` by exactly the chunk that
// elapsed so they join without drift; chunks are capped at half a period to
// keep the unsigned difference unambiguous. The tick count used to be
// truncated into a uint16, which silently returned early: a requested 60 ms
// delay measured 17.5 ms on an RDV4, and `hw tearoff --delay` accepts values
// right across that boundary.
//
// Keep this inline. Splitting the arming and the wait into helpers broke the
// SIM module link outright - `smart info` could not read the module version -
// with arithmetic that is otherwise identical.

// timer counts in 21.3us increments (1024/48MHz), rounding applies
void SpinDelayUs(int us) {
    uint32_t ticks = (us > 0) ? ((((uint32_t)(MCK / 1000000) * (uint32_t)us) + 512) >> 10) : 0;

    // Borrow a PWM unit for my real-time clock
    AT91C_BASE_PWMC->PWMC_ENA = PWM_CHANNEL(0);

    // 48 MHz / 1024 gives 46.875 kHz
    AT91C_BASE_PWMC_CH0->PWMC_CMR = PWM_CH_MODE_PRESCALER(10);      // Channel Mode Register
    AT91C_BASE_PWMC_CH0->PWMC_CDTYR = 0;                            // Channel Duty Cycle Register
    AT91C_BASE_PWMC_CH0->PWMC_CPRDR = 0xffff;                       // Channel Period Register

    uint32_t remaining = (uint32_t)ticks;
    uint16_t start = AT91C_BASE_PWMC_CH0->PWMC_CCNTR;
    while (remaining) {
        uint16_t chunk = (remaining > 0x8000UL) ? 0x8000U : (uint16_t)remaining;
        while ((uint16_t)(AT91C_BASE_PWMC_CH0->PWMC_CCNTR - start) < chunk) {
            WDT_HIT();
        }
        start = (uint16_t)(start + chunk);
        remaining -= chunk;
    }
}

#ifndef AS_BOOTROM

// timer counts in 666ns increments (32/48MHz), rounding applies
// WARNING: timer can't measure more than 43ms (666ns * 0xFFFF)
void SpinDelayUsPrecision(int us) {
    uint32_t ticks = (us > 0) ? ((((uint32_t)(MCK / 1000000) * (uint32_t)us) + 16) >> 5) : 0;

    // Borrow a PWM unit for my real-time clock
    AT91C_BASE_PWMC->PWMC_ENA = PWM_CHANNEL(0);

    // 48 MHz / 32 gives 1.5 Mhz
    AT91C_BASE_PWMC_CH0->PWMC_CMR = PWM_CH_MODE_PRESCALER(5);      // Channel Mode Register
    AT91C_BASE_PWMC_CH0->PWMC_CDTYR = 0;                           // Channel Duty Cycle Register
    AT91C_BASE_PWMC_CH0->PWMC_CPRDR = 0xFFFF;                      // Channel Period Register

    uint32_t remaining = (uint32_t)ticks;
    uint16_t start = AT91C_BASE_PWMC_CH0->PWMC_CCNTR;
    while (remaining) {
        uint16_t chunk = (remaining > 0x8000UL) ? 0x8000U : (uint16_t)remaining;
        while ((uint16_t)(AT91C_BASE_PWMC_CH0->PWMC_CCNTR - start) < chunk) {
            WDT_HIT();
        }
        start = (uint16_t)(start + chunk);
        remaining -= chunk;
    }
}

//  -------------------------------------------------------------------------
//  Timer lib: 1 kHz: TickCount functions
//
//  Precision Test Procedure:
//    ti = GetTickCount();
//    SpinDelay(1000);
//    ti = GetTickCount() - ti;
//    Dbprintf("timer(1s): %d t=%d", ti, GetTickCount());
//  -------------------------------------------------------------------------
void StartTickCount(void) {
    UpdateTickCountLabel();
    // This timer is based on the slow clock. The slow clock frequency is between 22kHz and 40kHz.
    // We can determine the actual slow clock frequency by looking at the Main Clock Frequency Register.
    while ((AT91C_BASE_PMC->PMC_MCFR & AT91C_CKGR_MAINRDY) == 0);       // Wait for MAINF value to become available...
    uint16_t mainf = AT91C_BASE_PMC->PMC_MCFR & AT91C_CKGR_MAINF;       // Get # main clocks within 16 slow clocks
    // set RealTimeCounter divider to count at 1kHz, should be 32 if RC is exactly at 32kHz:
    AT91C_BASE_RTTC->RTTC_RTMR = AT91C_RTTC_RTTRST | ((((MAINCK / 1000 * 16) + (mainf / 2)) / mainf) & AT91C_RTTC_RTPRES);
    // note: worst case precision is approx 2.5%
}

// Get the current count.
uint32_t RAMFUNC GetTickCount(void) {
    return AT91C_BASE_RTTC->RTTC_RTVR;
}

//  -------------------------------------------------------------------------
//  Timer for iso14443 commands. Uses ssp_clk from FPGA
//  -------------------------------------------------------------------------
void StartCountSspClk(void) {
    AT91C_BASE_PMC->PMC_PCER |= (1 << AT91C_ID_TC0) | (1 << AT91C_ID_TC1) | (1 << AT91C_ID_TC2);  // Enable Clock to all timers
    AT91C_BASE_TCB->TCB_BMR = AT91C_TCB_TC0XC0S_TIOA1       // XC0 Clock = TIOA1
                              | AT91C_TCB_TC1XC1S_NONE      // XC1 Clock = none
                              | AT91C_TCB_TC2XC2S_TIOA0;    // XC2 Clock = TIOA0

    // configure TC1 to create a short pulse on TIOA1 when a rising edge on TIOB1 (= ssp_clk from FPGA) occurs:
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;               // disable TC1
    AT91C_BASE_TC1->TC_CMR = AT91C_TC_CLKS_TIMER_DIV1_CLOCK // TC1 Clock = MCK(48MHz)/2 = 24MHz
                             | AT91C_TC_CPCSTOP             // Stop clock on RC compare
                             | AT91C_TC_EEVTEDG_RISING      // Trigger on rising edge of Event
                             | AT91C_TC_EEVT_TIOB           // Event-Source: TIOB1 (= ssp_clk from FPGA = 13,56MHz/16)
                             | AT91C_TC_ENETRG              // Enable external trigger event
                             | AT91C_TC_WAVESEL_UP          // Upmode without automatic trigger on RC compare
                             | AT91C_TC_WAVE                // Waveform Mode
                             | AT91C_TC_AEEVT_SET           // Set TIOA1 on external event
                             | AT91C_TC_ACPC_CLEAR;         // Clear TIOA1 on RC Compare
    AT91C_BASE_TC1->TC_RC = 0x01;                           // RC Compare value = 0x01, pulse width to TC0

    // use TC0 to count TIOA1 pulses
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;               // disable TC0
    AT91C_BASE_TC0->TC_CMR = AT91C_TC_CLKS_XC0              // TC0 clock = XC0 clock = TIOA1
                             | AT91C_TC_WAVE                // Waveform Mode
                             | AT91C_TC_WAVESEL_UP          // just count
                             | AT91C_TC_ACPA_CLEAR          // Clear TIOA0 on RA Compare
                             | AT91C_TC_ACPC_SET            // Set TIOA0 on RC Compare
                             | AT91C_TC_ASWTRG_SET;         // Set TIOA0 on software trigger to trigger instant reset of TC2
    AT91C_BASE_TC0->TC_RA = 1;                              // RA Compare value = 1; pulse width to TC2
    AT91C_BASE_TC0->TC_RC = 0;                              // RC Compare value = 0; increment TC2 on overflow

    // use TC2 to count TIOA0 pulses (giving us a 32bit counter (TC0/TC2) clocked by ssp_clk)
    AT91C_BASE_TC2->TC_CCR = AT91C_TC_CLKDIS;               // disable TC2
    AT91C_BASE_TC2->TC_CMR = AT91C_TC_CLKS_XC2              // TC2 clock = XC2 clock = TIOA0
                             | AT91C_TC_WAVE                // Waveform Mode
                             | AT91C_TC_WAVESEL_UP;         // just count

    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;                // enable and reset TC0
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;                // enable and reset TC1
    AT91C_BASE_TC2->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;                // enable and reset TC2

    //
    // synchronize the counter with the ssp_frame signal.
    // Note: FPGA must be in a FPGA mode with SSC transfer, otherwise SSC_FRAME and SSC_CLK signals would not be present
    //
    while (Gpio_SSC_FRAME_Read());     // wait for ssp_frame to be low
    while (!(Gpio_SSC_FRAME_Read()));  // wait for ssp_frame to go high (start of frame)
    while (!(Gpio_SSC_CLK_Read()));    // wait for ssp_clk to go high; 1st ssp_clk after start of frame
    while (Gpio_SSC_CLK_Read());       // wait for ssp_clk to go low;
    while (!(Gpio_SSC_CLK_Read()));    // wait for ssp_clk to go high; 2nd ssp_clk after start of frame
    if ((AT91C_BASE_SSC->SSC_RFMR & SSC_FRAME_MODE_BITS_IN_WORD(32)) == SSC_FRAME_MODE_BITS_IN_WORD(16)) { // 16bit frame
        while (Gpio_SSC_CLK_Read());   // wait for ssp_clk to go low;
        while (!(Gpio_SSC_CLK_Read())); // wait for ssp_clk to go high; 3rd ssp_clk after start of frame
        while (Gpio_SSC_CLK_Read());   // wait for ssp_clk to go low;
        while (!(Gpio_SSC_CLK_Read())); // wait for ssp_clk to go high; 4th ssp_clk after start of frame
        while (Gpio_SSC_CLK_Read());   // wait for ssp_clk to go low;
        while (!(Gpio_SSC_CLK_Read())); // wait for ssp_clk to go high; 5th ssp_clk after start of frame
        while (Gpio_SSC_CLK_Read());   // wait for ssp_clk to go low;
        while (!(Gpio_SSC_CLK_Read())); // wait for ssp_clk to go high; 6th ssp_clk after start of frame
    }

    // note: up to now two ssp_clk rising edges have passed since the rising edge of ssp_frame
    // it is now safe to assert a sync signal. This sets all timers to 0 on next active clock edge
    AT91C_BASE_TCB->TCB_BCR = 1;                            // assert Sync (set all timers to 0 on next active clock edge)
    // at the next (3rd) ssp_clk rising edge, TC1 will be reset (and not generate a clock signal to TC0)
    // at the next (4th) ssp_clk rising edge, TC0 (the low word of our counter) will be reset. From now on,
    // whenever the last three bits of our counter go 0, we can be sure to be in the middle of a frame transfer.
    // (just started with the transfer of the 4th Bit).

    // The high word of the counter (TC2) will not reset until the low word (TC0) clocks to process the external trigger.
    // Therefore may need to wait a little bit before we can use the counter.
    while (AT91C_BASE_TC2->TC_CV > 0);
}

void ResetSspClk(void) {
    //enable clock of timer and software trigger
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
    AT91C_BASE_TC2->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
    while (AT91C_BASE_TC2->TC_CV > 0);
}

uint32_t RAMFUNC GetCountSspClk(void) {
    uint32_t tmp_count = (AT91C_BASE_TC2->TC_CV << 16) | AT91C_BASE_TC0->TC_CV;

    // small chance that we may have missed an increment in TC2
    if ((tmp_count & 0x0000ffff) == 0) {
        return (AT91C_BASE_TC2->TC_CV << 16);
    }
    return tmp_count;
}

//  -------------------------------------------------------------------------
//  Precision counter (TC0), input capture (TC1) and timestamp (TC2).
//  These are used by the LF protocols (e.g. Hitag) and are configured at
//  1.5 MHz (MCK/32), so 12 counts = 1 T0 = 8 us.
//  -------------------------------------------------------------------------

// TC2 overflow count, combined with the TC2 counter for ~47 min timing.
static uint16_t timestamp_high = 0;


// Wait for a software trigger to take effect, without ever spinning on an exact
// value.
//
// TC_CV restarts on the next TIMER_CLOCK3 edge, 32 MCK cycles away, and reading
// a timer register costs a good fraction of that.  A loop that waits for exactly
// 0 can therefore step straight over the window, and the counter then has to run
// all the way round its 16 bits - 43.7 ms - before zero comes past again.  In
// ResetPrecisionCounter(), which the Hitag reader calls once per transmitted
// bit, that turns into a stall long enough that the Proxmark stops answering USB
// and looks like it has hung.  Accept any value that is plainly post-reset, and
// give up rather than wait forever.
#define TC_WAIT_RESTART(tc)                        \
    do {                                           \
        for (uint32_t _i = 0; _i < 256; _i++) {    \
            if ((tc)->TC_CV < 4) {                 \
                break;                             \
            }                                      \
        }                                          \
    } while (0)

// Reference the plain GetPrecisionCounter() measures from.  See ticks_apis.h:
// this moves, the hardware counter does not.
static uint16_t precision_ref = 0;

void StartPrecisionCounter(void) {
    // Enable peripheral clock for TC0 (precision counter).
    AT91C_BASE_PMC->PMC_PCER |= (1 << AT91C_ID_TC0);

    // Disable TC0 before reconfiguration.
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;

    // TC0: capture mode, default timer source = MCK/32 (TIMER_CLOCK3), no triggers (free-running).
    AT91C_BASE_TC0->TC_CMR = AT91C_TC_CLKS_TIMER_DIV3_CLOCK;
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
    TC_WAIT_RESTART(AT91C_BASE_TC0);  // wait until the reset takes effect
    precision_ref = 0;
}

void StopPrecisionCounter(void) {
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;
}

void ResetPrecisionCounter(void) {
    precision_ref = (uint16_t)AT91C_BASE_TC0->TC_CV;
}

uint16_t RAMFUNC GetPrecisionCounter(void) {
    return (uint16_t)(AT91C_BASE_TC0->TC_CV - precision_ref);
}

uint16_t RAMFUNC GetPrecisionCounterRaw(void) {
    return (uint16_t)AT91C_BASE_TC0->TC_CV;
}

uint16_t RAMFUNC GetPrecisionCounterDelta(uint16_t start) {
    return (uint16_t)(AT91C_BASE_TC0->TC_CV - start);
}

void StartLoEdgeCapture(void) {
    // Enable peripheral clock for TC1 (input capture).
    AT91C_BASE_PMC->PMC_PCER |= (1 << AT91C_ID_TC1);

    // Route SSC_FRAME to the timer input (TIOA) so its edges can be captured by TC1.
    AT91C_BASE_PIOA->PIO_BSR = GPIO_SSC_FRAME;

    // Disable TC1 before reconfiguration.
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;

    // TC1: capture mode, default timer source = MCK/32 (TIMER_CLOCK3),
    // TIOA is external trigger, load RA on rising edge, load RB on falling edge.
    AT91C_BASE_TC1->TC_CMR = AT91C_TC_CLKS_TIMER_DIV3_CLOCK  // use MCK/32 (TIMER_CLOCK3)
                             | AT91C_TC_ABETRG               // TIOA is used as an external trigger
                             | AT91C_TC_ETRGEDG_FALLING      // external trigger on falling edge
                             | AT91C_TC_LDRA_RISING          // load RA on rising edge of TIOA
                             | AT91C_TC_LDRB_FALLING;        // load RB on falling edge of TIOA
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
    TC_WAIT_RESTART(AT91C_BASE_TC1);  // wait until the reset takes effect
}

void StopLoEdgeCapture(void) {
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;
}

void EnableLoEdgeCapture(void) {
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
}

void ResetLoEdgeCapture(void) {
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_SWTRG;
}

uint16_t RAMFUNC GetLoEdgeCaptureCount(void) {
    return (uint16_t)AT91C_BASE_TC1->TC_CV;
}

lo_edge_t RAMFUNC GetLoEdgeCaptureStatus(void) {
    // Read Once Only: Reading TC_SR will simultaneously clear status bits such as LDRAS/LDRBS.
    uint32_t sr = AT91C_BASE_TC1->TC_SR;
    if (sr & INPUT_CAPTURE_EVT_RISING_EDGE) {
        return LO_EDGE_RISING;
    }
    if (sr & INPUT_CAPTURE_EVT_FALLING_EDGE) {
        return LO_EDGE_FALLING;
    }
    return LO_EDGE_NO;
}

uint16_t RAMFUNC GetLoEdgeCaptureFalling(void) {
    return (uint16_t)AT91C_BASE_TC1->TC_RB;
}

uint16_t RAMFUNC GetLoEdgeCaptureRising(void) {
    return (uint16_t)AT91C_BASE_TC1->TC_RA;
}

void StartTimestamp(void) {
    // Enable peripheral clock for TC2 (timestamp).
    AT91C_BASE_PMC->PMC_PCER |= (1 << AT91C_ID_TC2);

    // Disable TC2 before reconfiguration.
    AT91C_BASE_TC2->TC_CCR = AT91C_TC_CLKDIS;

    // TC2: capture mode, default timer source = MCK/32 (TIMER_CLOCK3), no triggers (free-running).
    AT91C_BASE_TC2->TC_CMR = AT91C_TC_CLKS_TIMER_DIV3_CLOCK;
    AT91C_BASE_TC2->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
    TC_WAIT_RESTART(AT91C_BASE_TC2);  // wait until the reset takes effect

    // Reset the overflow accumulator, and the hardware flag it counts.
    //
    // Reading TC_SR is what clears COVFS.  Without this, an overflow left over
    // from a previous run is still pending, so the very first GetTimestamp()
    // counts it and every timestamp for the rest of the session is 65536 ticks -
    // 5461 T0 - too high.  It shows up in a trace as a frame whose end is exactly
    // start + 65536, followed by rows with negative looking start times where the
    // client subtracts the inflated value.
    (void)AT91C_BASE_TC2->TC_SR;
    timestamp_high = 0;
}

void StopTimestamp(void) {
    AT91C_BASE_TC2->TC_CCR = AT91C_TC_CLKDIS;
}

uint32_t RAMFUNC GetTimestamp(void) {
    // Read the counter on both sides of the overflow check.
    //
    // TC2 is 16 bits at MCK/32, so it wraps every 43.7 ms, and reading TC_SR is
    // what latches that wrap into timestamp_high - and clears the flag, so it may
    // only be read once.  Checking the flag first and reading TC_CV afterwards
    // leaves a window: a wrap landing between the two reads is not seen, the low
    // half has already restarted near zero, and the result comes back 65536 ticks
    // (5461 T0) BELOW the previous one.  Timestamps that go backwards break every
    // caller that measures with an unsigned difference; the Hitag 2 simulator's
    // turnaround, `while ((TIMESTAMP - rx_end) < ...)`, wraps to a huge value and
    // stops waiting at once, putting the answer on the air a full frame early.
    //
    // Sampling either side of the flag read closes it: if the flag is set the
    // wrap is at or before the flag read, so the second sample is the one that
    // belongs with the incremented high half.
    uint16_t cv_before = (uint16_t)AT91C_BASE_TC2->TC_CV;
    bool overflowed = (AT91C_BASE_TC2->TC_SR & AT91C_TC_COVFS) != 0;
    uint16_t cv_after = (uint16_t)AT91C_BASE_TC2->TC_CV;

    if (overflowed) {
        timestamp_high++;
        cv_before = cv_after;
    }
    return (((uint32_t)timestamp_high << 16) + cv_before) / TICKS_PER_CARRIER_PERIOD;
}

#endif // #ifndef AS_BOOTROM

//  -------------------------------------------------------------------------
//  microseconds timer
//  1us = 1tick
//  -------------------------------------------------------------------------
void StartCountUS(void) {
    AT91C_BASE_PMC->PMC_PCER |= (1 << AT91C_ID_TC0) | (1 << AT91C_ID_TC1);
    AT91C_BASE_TCB->TCB_BMR = AT91C_TCB_TC0XC0S_NONE | AT91C_TCB_TC1XC1S_TIOA0 | AT91C_TCB_TC2XC2S_NONE;

    // fast clock
    // tick=1.5mks
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS; // timer disable
    AT91C_BASE_TC0->TC_CMR = AT91C_TC_CLKS_TIMER_DIV3_CLOCK | // MCK(48MHz) / 32
                             AT91C_TC_WAVE | AT91C_TC_WAVESEL_UP_AUTO | AT91C_TC_ACPA_CLEAR |
                             AT91C_TC_ACPC_SET | AT91C_TC_ASWTRG_SET;
    AT91C_BASE_TC0->TC_RA = 1;
    AT91C_BASE_TC0->TC_RC = 0xBFFF + 1; // 0xC000

    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS; // timer disable
    AT91C_BASE_TC1->TC_CMR = AT91C_TC_CLKS_XC1; // from timer 0

    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;

    // Assert a sync signal. This sets all timers to 0 on next active clock edge
    AT91C_BASE_TCB->TCB_BCR = 1;

    while (AT91C_BASE_TC1->TC_CV > 0);
}

uint32_t RAMFUNC GetCountUS(void) {
    //return (AT91C_BASE_TC1->TC_CV * 0x8000) + ((AT91C_BASE_TC0->TC_CV / 15) * 10);
    //  By suggestion from PwPiwi, http://www.proxmark.org/forum/viewtopic.php?pid=17548#p17548
    return ((uint32_t)AT91C_BASE_TC1->TC_CV) * 0x8000 + (((uint32_t)AT91C_BASE_TC0->TC_CV) * 2) / 3;
}

// Maybe we can make it a static inline function, but to avoid possible compiler quirks,
// it's best not to do so, otherwise it may increase the time wasted on stack entry and exit due to not expanding the inline function,
// leading to synchronization zeroing failure!
#define WaitSyncTicks()                                                                             \
    /* synchronized startup procedure */                                                            \
    while (AT91C_BASE_TC0->TC_CV > 0); /* wait until TC0 returned to zero */                        \
    while (AT91C_BASE_TC0->TC_CV < 2); /* and has started (TC_CV > TC_RA, now TC1 is cleared) */    \
    /* return to zero */                                                                            \
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_SWTRG;                                                        \
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;                                                        \
    while (AT91C_BASE_TC0->TC_CV > 0);

//  -------------------------------------------------------------------------
//  Timer for bitbanging, or LF stuff when you need a very precise timer
//  1us = 1.5ticks
//  -------------------------------------------------------------------------
void StartTicks(void) {
    // initialization of the timer
    AT91C_BASE_PMC->PMC_PCER |= (1 << AT91C_ID_TC0) | (1 << AT91C_ID_TC1);
    AT91C_BASE_TCB->TCB_BMR   = AT91C_TCB_TC0XC0S_NONE | AT91C_TCB_TC1XC1S_TIOA0 | AT91C_TCB_TC2XC2S_NONE;

    // disable TC0 and TC1 for re-configuration
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;

    // first configure TC1 (higher, 0xFFFF0000) 16 bit counter
    AT91C_BASE_TC1->TC_CMR = AT91C_TC_CLKS_XC1; // just connect to TIOA0 from TC0
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG; // re-enable timer and wait for TC0

    // second configure TC0 (lower, 0x0000FFFF) 16 bit counter
    AT91C_BASE_TC0->TC_CMR = AT91C_TC_CLKS_TIMER_DIV3_CLOCK | // MCK(48MHz) / 32
                             AT91C_TC_WAVE | AT91C_TC_WAVESEL_UP_AUTO |
                             AT91C_TC_ACPA_CLEAR | // RA comperator clears TIOA (carry bit)
                             AT91C_TC_ACPC_SET |   // RC comperator sets TIOA (carry bit)
                             AT91C_TC_ASWTRG_SET;  // SWTriger sets TIOA (carry bit)
    AT91C_BASE_TC0->TC_RC  = 0; // set TIOA (carry bit) on overflow, return to zero
    AT91C_BASE_TC0->TC_RA  = 1; // clear carry bit on next clock cycle
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG; // reset and re-enable timer

    WaitSyncTicks();
}

// Reset the count value to 0 for TC0 & TC1
void ResetTicks(void) {
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;

    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;

    WaitSyncTicks();
}

// stop clock
void StopTicks(void) {
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;
    AT91C_BASE_TC2->TC_CCR = AT91C_TC_CLKDIS;

    // TODO DXL StartTicks() did not use TC2, is this code worthless?
    //  In some places, StartCountSspClk() is called after StopTicks(), so it seems necessary to disable timers completely.
    //  In that case, the role of StopTicks() is not limited to being paired with StartTicks(),
    //  but is a general release function for all ticks modules.
    //  ---
    //  Do we need to provide a StopXXX for each StartXXXX?
    //  Such as:
    //    * StartTicks -> StopTicks
    //    * StartCountSspClk -> StopCountSspClk
    //    * StartTickCount -> StopTickCount
    //    * StartCountUS -> StopCountUS
    //    * StartPrecisionCounter -> StopPrecisionCounter
    //    * StartLoEdgeCapture -> StopLoEdgeCapture
    //    * StartTimestamp -> StopTimestamp
    //  It seems best for everyone(api) to do their own job.
}

uint32_t GetTicks(void) {
    uint32_t hi, lo;

    do {
        hi = AT91C_BASE_TC1->TC_CV;
        lo = AT91C_BASE_TC0->TC_CV;
    } while (hi != AT91C_BASE_TC1->TC_CV);

    return (hi << 16) | lo;
}
