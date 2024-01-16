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
// Utility functions used in many places, not specific to any piece of code.
//-----------------------------------------------------------------------------
#include "util.h"

#include "proxmark3_arm.h"
#include "ticks.h"
#include "commonutil.h"
#include "dbprint.h"
#include "string.h"
#include "usb_cdc.h"
#include "usart.h"

size_t nbytes(size_t nbits) {
    return (nbits >> 3) + ((nbits % 8) > 0);
}

//convert hex digit to integer
uint8_t hex2int(char hexchar) {
    switch (hexchar) {
        case '0':
            return 0;
            break;
        case '1':
            return 1;
            break;
        case '2':
            return 2;
            break;
        case '3':
            return 3;
            break;
        case '4':
            return 4;
            break;
        case '5':
            return 5;
            break;
        case '6':
            return 6;
            break;
        case '7':
            return 7;
            break;
        case '8':
            return 8;
            break;
        case '9':
            return 9;
            break;
        case 'a':
        case 'A':
            return 10;
            break;
        case 'b':
        case 'B':
            return 11;
            break;
        case 'c':
        case 'C':
            return 12;
            break;
        case 'd':
        case 'D':
            return 13;
            break;
        case 'e':
        case 'E':
            return 14;
            break;
        case 'f':
        case 'F':
            return 15;
            break;
        default:
            return 0;
    }
}

void LEDsoff(void) {
    LED_A_OFF();
    LED_B_OFF();
    LED_C_OFF();
    LED_D_OFF();
}

//ICEMAN:   LED went from 1,2,3,4 -> 1,2,4,8
void LED(int led, int ms) {
    if (led & LED_A) // Proxmark3 historical mapping: LED_ORANGE
        LED_A_ON();
    if (led & LED_B) // Proxmark3 historical mapping: LED_GREEN
        LED_B_ON();
    if (led & LED_C) // Proxmark3 historical mapping: LED_RED
        LED_C_ON();
    if (led & LED_D) // Proxmark3 historical mapping: LED_RED2
        LED_D_ON();

    if (!ms)
        return;

    SpinDelay(ms);

    if (led & LED_A)
        LED_A_OFF();
    if (led & LED_B)
        LED_B_OFF();
    if (led & LED_C)
        LED_C_OFF();
    if (led & LED_D)
        LED_D_OFF();
}

void SpinOff(uint32_t pause) {
    LED_A_OFF();
    LED_B_OFF();
    LED_C_OFF();
    LED_D_OFF();
    SpinDelay(pause);
}

// Blinks..
// A = 1, B = 2, C = 4, D = 8
void SpinErr(uint8_t led, uint32_t speed, uint8_t times) {
    SpinOff(speed);
    NTIME(times) {

        if (led & LED_A) // Proxmark3 historical mapping: LED_ORANGE
            LED_A_INV();
        if (led & LED_B) // Proxmark3 historical mapping: LED_GREEN
            LED_B_INV();
        if (led & LED_C) // Proxmark3 historical mapping: LED_RED
            LED_C_INV();
        if (led & LED_D) // Proxmark3 historical mapping: LED_RED2
            LED_D_INV();

        SpinDelay(speed);
    }
    LED_A_OFF();
    LED_B_OFF();
    LED_C_OFF();
    LED_D_OFF();
}

void SpinDown(uint32_t speed) {
    SpinOff(speed);
    LED_D_ON();
    SpinDelay(speed);
    LED_D_OFF();
    LED_C_ON();
    SpinDelay(speed);
    LED_C_OFF();
    LED_B_ON();
    SpinDelay(speed);
    LED_B_OFF();
    LED_A_ON();
    SpinDelay(speed);
    LED_A_OFF();
}

void SpinUp(uint32_t speed) {
    SpinOff(speed);
    LED_A_ON();
    SpinDelay(speed);
    LED_A_OFF();
    LED_B_ON();
    SpinDelay(speed);
    LED_B_OFF();
    LED_C_ON();
    SpinDelay(speed);
    LED_C_OFF();
    LED_D_ON();
    SpinDelay(speed);
    LED_D_OFF();
}


// Determine if a button is double clicked, single clicked,
// not clicked, or held down (for ms || 1sec)
// In general, don't use this function unless you expect a
// double click, otherwise it will waste 500ms -- use BUTTON_HELD instead
int BUTTON_CLICKED(int ms) {
    // Up to 500ms in between clicks to mean a double click
    // timer counts in 21.3us increments (1024/48MHz)
    // WARNING: timer can't measure more than 1.39s (21.3us * 0xffff)
    if (ms > 1390) {
        if (g_dbglevel >= DBG_ERROR) Dbprintf(_RED_("Error, BUTTON_CLICKED called with %i > 1390"), ms);
        ms = 1390;
    }
    int ticks = ((MCK / 1000) * (ms ? ms : 1000)) >> 10;

    // If we're not even pressed, forget about it!
    if (BUTTON_PRESS() == false)
        return BUTTON_NO_CLICK;

    // Borrow a PWM unit for my real-time clock
    AT91C_BASE_PWMC->PWMC_ENA = PWM_CHANNEL(0);
    // 48 MHz / 1024 gives 46.875 kHz
    AT91C_BASE_PWMC_CH0->PWMC_CMR = PWM_CH_MODE_PRESCALER(10);
    AT91C_BASE_PWMC_CH0->PWMC_CDTYR = 0;
    AT91C_BASE_PWMC_CH0->PWMC_CPRDR = 0xffff;

    uint16_t start = AT91C_BASE_PWMC_CH0->PWMC_CCNTR;

    int letoff = 0;
    for (;;) {
        uint16_t now = AT91C_BASE_PWMC_CH0->PWMC_CCNTR;

        // We haven't let off the button yet
        if (!letoff) {
            // We just let it off!
            if (BUTTON_PRESS() == false) {
                letoff = 1;

                // reset our timer for 500ms
                start = AT91C_BASE_PWMC_CH0->PWMC_CCNTR;
                ticks = ((MCK / 1000) * (500)) >> 10;
            }

            // Still haven't let it off
            else
                // Have we held down a full second?
                if (now == (uint16_t)(start + ticks))
                    return BUTTON_HOLD;
        }

        // We already let off, did we click again?
        else
            // Sweet, double click!
            if (BUTTON_PRESS())
                return BUTTON_DOUBLE_CLICK;

        // Have we ran out of time to double click?
            else if (now == (uint16_t)(start + ticks))
                // At least we did a single click
                return BUTTON_SINGLE_CLICK;

        WDT_HIT();
    }

    // We should never get here
    return BUTTON_ERROR;
}

// Determine if a button is held down
int BUTTON_HELD(int ms) {
    // timer counts in 21.3us increments (1024/48MHz)
    // WARNING: timer can't measure more than 1.39s (21.3us * 0xffff)
    if (ms > 1390) {
        if (g_dbglevel >= DBG_ERROR) Dbprintf(_RED_("Error, BUTTON_HELD called with %i > 1390"), ms);
        ms = 1390;
    }
    // If button is held for one second
    int ticks = (48000 * (ms ? ms : 1000)) >> 10;

    // If we're not even pressed, forget about it!
    if (BUTTON_PRESS() == false)
        return BUTTON_NO_CLICK;

    // Borrow a PWM unit for my real-time clock
    AT91C_BASE_PWMC->PWMC_ENA = PWM_CHANNEL(0);
    // 48 MHz / 1024 gives 46.875 kHz
    AT91C_BASE_PWMC_CH0->PWMC_CMR = PWM_CH_MODE_PRESCALER(10);
    AT91C_BASE_PWMC_CH0->PWMC_CDTYR = 0;
    AT91C_BASE_PWMC_CH0->PWMC_CPRDR = 0xffff;

    uint16_t start = AT91C_BASE_PWMC_CH0->PWMC_CCNTR;

    for (;;) {
        uint16_t now = AT91C_BASE_PWMC_CH0->PWMC_CCNTR;

        // As soon as our button let go, we didn't hold long enough
        if (BUTTON_PRESS() == false)
            return BUTTON_SINGLE_CLICK;

        // Have we waited the full second?
        else if (now == (uint16_t)(start + ticks))
            return BUTTON_HOLD;

        WDT_HIT();
    }

    // We should never get here
    return BUTTON_ERROR;
}

bool data_available(void) {
#ifdef WITH_FPC_USART_HOST
    return usb_poll_validate_length() || (usart_rxdata_available() > 0);
#else
    return usb_poll_validate_length();
#endif
}
