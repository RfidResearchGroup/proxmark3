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
#include "clocks.h"
#include "proxmark3_arm.h"

void mck_from_pll_to_slck(void) {
    // switch main clk to slow clk, first CSS then PRES
    AT91C_BASE_PMC->PMC_MCKR = AT91C_PMC_PRES_CLK_2 | AT91C_PMC_CSS_SLOW_CLK;
    while (!(AT91C_BASE_PMC->PMC_SR & AT91C_PMC_MCKRDY)) {};
    AT91C_BASE_PMC->PMC_MCKR = AT91C_PMC_PRES_CLK | AT91C_PMC_CSS_SLOW_CLK;
    while (!(AT91C_BASE_PMC->PMC_SR & AT91C_PMC_MCKRDY)) {};

    // disable the PLL
    AT91C_BASE_PMC->PMC_PLLR = 0x0;

    // disable main oscillator
    AT91C_BASE_PMC->PMC_MOR = 0;
}

void mck_from_slck_to_pll(void) {
    // worst case scenario, with MAINCK = 16MHz xtal, startup delay is 1.4ms
    // if SLCK slow clock runs at its worst case (max) frequency of 42kHz
    // max startup delay = (1.4ms*42k)/8 = 7.356 so round up to 8
    // UPDATE:
    // we observed on 10% of the devices very wrong initial slow clock RC TIA measures.
    // Bumping delay to 16 helps fixing the issue even on the most screwed RC.

    // enable main oscillator and set startup delay
    AT91C_BASE_PMC->PMC_MOR =
        AT91C_CKGR_MOSCEN |
        PMC_MAIN_OSC_STARTUP_DELAY(16);

    // wait for main oscillator to stabilize
    while (!(AT91C_BASE_PMC->PMC_SR & AT91C_PMC_MOSCS)) {};

    // PLL output clock frequency in range  80 - 160 MHz needs CKGR_PLL = 00
    // PLL output clock frequency in range 150 - 180 MHz needs CKGR_PLL = 10
    // PLL output is MAINCK * multiplier / divisor = 16MHz * 12 / 2 = 96MHz
    AT91C_BASE_PMC->PMC_PLLR =
        PMC_PLL_DIVISOR(2) |
        //PMC_PLL_COUNT_BEFORE_LOCK(0x10) |
        PMC_PLL_COUNT_BEFORE_LOCK(0x3F) |
        PMC_PLL_FREQUENCY_RANGE(0) |
        PMC_PLL_MULTIPLIER(12) |
        PMC_PLL_USB_DIVISOR(1);

    // wait for PLL to lock
    while (!(AT91C_BASE_PMC->PMC_SR & AT91C_PMC_LOCK)) {};

    // we want a master clock (MCK) to be PLL clock / 2 = 96MHz / 2 = 48MHz
    // datasheet recommends that this register is programmed in two operations
    // when changing to PLL, program the prescaler first then the source
    AT91C_BASE_PMC->PMC_MCKR = AT91C_PMC_PRES_CLK_2 | AT91C_PMC_CSS_SLOW_CLK;

    // wait for main clock ready signal
    while (!(AT91C_BASE_PMC->PMC_SR & AT91C_PMC_MCKRDY)) {};

    // set the source to PLL
    AT91C_BASE_PMC->PMC_MCKR = AT91C_PMC_PRES_CLK_2 | AT91C_PMC_CSS_PLL_CLK;

    // wait for main clock ready signal
    while (!(AT91C_BASE_PMC->PMC_SR & AT91C_PMC_MCKRDY)) {};
}
