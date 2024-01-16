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
#include "ticks.h"

#include "proxmark3_arm.h"
#ifndef AS_BOOTROM
#include "dbprint.h"
#endif


#ifndef AS_BOOTROM

// timer counts in 666ns increments (32/48MHz), rounding applies
// WARNING: timer can't measure more than 43ms (666ns * 0xFFFF)
void SpinDelayUsPrecision(int us) {
    int ticks = ((MCK / 1000000) * us + 16) >> 5;

    // Borrow a PWM unit for my real-time clock
    AT91C_BASE_PWMC->PWMC_ENA = PWM_CHANNEL(0);

    // 48 MHz / 32 gives 1.5 Mhz
    AT91C_BASE_PWMC_CH0->PWMC_CMR = PWM_CH_MODE_PRESCALER(5);      // Channel Mode Register
    AT91C_BASE_PWMC_CH0->PWMC_CDTYR = 0;                           // Channel Duty Cycle Register
    AT91C_BASE_PWMC_CH0->PWMC_CPRDR = 0xFFFF;                      // Channel Period Register

    uint16_t end = AT91C_BASE_PWMC_CH0->PWMC_CCNTR + ticks;
    if (end == 0) // AT91C_BASE_PWMC_CH0->PWMC_CCNTR is never == 0
        end++;    // so we have to end++ to avoid inivity loop

    for (;;) {
        uint16_t now = AT91C_BASE_PWMC_CH0->PWMC_CCNTR;

        if (now == end)
            return;

        WDT_HIT();
    }
}

// timer counts in 21.3us increments (1024/48MHz), rounding applies
// WARNING: timer can't measure more than 1.39s (21.3us * 0xffff)
void SpinDelayUs(int us) {
    int ticks = ((MCK / 1000000) * us + 512) >> 10;

    // Borrow a PWM unit for my real-time clock
    AT91C_BASE_PWMC->PWMC_ENA = PWM_CHANNEL(0);

    // 48 MHz / 1024 gives 46.875 kHz
    AT91C_BASE_PWMC_CH0->PWMC_CMR = PWM_CH_MODE_PRESCALER(10);      // Channel Mode Register
    AT91C_BASE_PWMC_CH0->PWMC_CDTYR = 0;                            // Channel Duty Cycle Register
    AT91C_BASE_PWMC_CH0->PWMC_CPRDR = 0xffff;                       // Channel Period Register

    uint16_t end = AT91C_BASE_PWMC_CH0->PWMC_CCNTR + ticks;
    if (end == 0) // AT91C_BASE_PWMC_CH0->PWMC_CCNTR is never == 0
        end++;    // so we have to end++ to avoid inivity loop

    for (;;) {
        uint16_t now = AT91C_BASE_PWMC_CH0->PWMC_CCNTR;

        if (now == end)
            return;
        WDT_HIT();
    }
}

// WARNING: timer can't measure more than 1.39s (21.3us * 0xffff)
void SpinDelay(int ms) {
    if (ms > 1390) {
        if (g_dbglevel >= DBG_ERROR) Dbprintf(_RED_("Error, SpinDelay called with %i > 1390"), ms);
        ms = 1390;
    }
    // convert to us and call microsecond delay function
    SpinDelayUs(ms * 1000);
}
//  -------------------------------------------------------------------------
//  timer lib
//  -------------------------------------------------------------------------
//  test procedure:
//
//    ti = GetTickCount();
//    SpinDelay(1000);
//    ti = GetTickCount() - ti;
//    Dbprintf("timer(1s): %d t=%d", ti, GetTickCount());
void StartTickCount(void) {
    // This timer is based on the slow clock. The slow clock frequency is between 22kHz and 40kHz.
    // We can determine the actual slow clock frequency by looking at the Main Clock Frequency Register.
    while ((AT91C_BASE_PMC->PMC_MCFR & AT91C_CKGR_MAINRDY) == 0);       // Wait for MAINF value to become available...
    uint16_t mainf = AT91C_BASE_PMC->PMC_MCFR & AT91C_CKGR_MAINF;       // Get # main clocks within 16 slow clocks
    // set RealTimeCounter divider to count at 1kHz, should be 32 if RC is exactly at 32kHz:
    AT91C_BASE_RTTC->RTTC_RTMR = AT91C_RTTC_RTTRST | ((((MAINCK / 1000 * 16) + (mainf / 2)) / mainf) & AT91C_RTTC_RTPRES);
    // note: worst case precision is approx 2.5%
}

/*
* Get the current count.
*/
uint32_t RAMFUNC GetTickCount(void) {
    return AT91C_BASE_RTTC->RTTC_RTVR;
}

uint32_t RAMFUNC GetTickCountDelta(uint32_t start_ticks) {
    uint32_t stop_ticks = AT91C_BASE_RTTC->RTTC_RTVR;
    if (stop_ticks >= start_ticks)
        return stop_ticks - start_ticks;
    return (UINT32_MAX - start_ticks) + stop_ticks;
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
                             | AT91C_TC_ACPC_SET;           // Set TIOA0 on RC Compare
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
    while (AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_FRAME);     // wait for ssp_frame to be low
    while (!(AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_FRAME));  // wait for ssp_frame to go high (start of frame)
    while (!(AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK));    // wait for ssp_clk to go high; 1st ssp_clk after start of frame
    while (AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK);       // wait for ssp_clk to go low;
    while (!(AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK));    // wait for ssp_clk to go high; 2nd ssp_clk after start of frame
    if ((AT91C_BASE_SSC->SSC_RFMR & SSC_FRAME_MODE_BITS_IN_WORD(32)) == SSC_FRAME_MODE_BITS_IN_WORD(16)) { // 16bit frame
        while (AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK);   // wait for ssp_clk to go low;
        while (!(AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK)); // wait for ssp_clk to go high; 3rd ssp_clk after start of frame
        while (AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK);   // wait for ssp_clk to go low;
        while (!(AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK)); // wait for ssp_clk to go high; 4th ssp_clk after start of frame
        while (AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK);   // wait for ssp_clk to go low;
        while (!(AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK)); // wait for ssp_clk to go high; 5th ssp_clk after start of frame
        while (AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK);   // wait for ssp_clk to go low;
        while (!(AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK)); // wait for ssp_clk to go high; 6th ssp_clk after start of frame
    }

    // note: up to now two ssp_clk rising edges have passed since the rising edge of ssp_frame
    // it is now safe to assert a sync signal. This sets all timers to 0 on next active clock edge
    AT91C_BASE_TCB->TCB_BCR = 1;                            // assert Sync (set all timers to 0 on next active clock edge)
    // at the next (3rd) ssp_clk rising edge, TC1 will be reset (and not generate a clock signal to TC0)
    // at the next (4th) ssp_clk rising edge, TC0 (the low word of our counter) will be reset. From now on,
    // whenever the last three bits of our counter go 0, we can be sure to be in the middle of a frame transfer.
    // (just started with the transfer of the 4th Bit).

    // The high word of the counter (TC2) will not reset until the low word (TC0) overflows.
    // Therefore need to wait quite some time before we can use the counter.
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
    if ((tmp_count & 0x0000ffff) == 0)  //small chance that we may have missed an increment in TC2
        return (AT91C_BASE_TC2->TC_CV << 16);
    return tmp_count;
}

uint32_t RAMFUNC GetCountSspClkDelta(uint32_t start) {
    uint32_t stop = GetCountSspClk();
    if (stop >= start)
        return stop - start;
    return (UINT32_MAX - start) + stop;
}

void WaitMS(uint32_t ms) {
    WaitTicks((ms & 0x1FFFFF) * 1500);
}

#endif // #ifndef AS_BOOTROM

//  -------------------------------------------------------------------------
//  microseconds timer
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


//  -------------------------------------------------------------------------
//  Timer for bitbanging, or LF stuff when you need a very precis timer
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

    // synchronized startup procedure
    while (AT91C_BASE_TC0->TC_CV > 0); // wait until TC0 returned to zero
    while (AT91C_BASE_TC0->TC_CV < 2); // and has started (TC_CV > TC_RA, now TC1 is cleared)

    // return to zero
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_SWTRG;
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;
    while (AT91C_BASE_TC0->TC_CV > 0);
}
uint32_t GetTicks(void) {
    uint32_t hi, lo;

    do {
        hi = AT91C_BASE_TC1->TC_CV;
        lo = AT91C_BASE_TC0->TC_CV;
    } while (hi != AT91C_BASE_TC1->TC_CV);

    return (hi << 16) | lo;
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

// stop clock
void StopTicks(void) {
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;
}
