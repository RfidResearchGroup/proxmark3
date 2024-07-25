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
uint8_t hex2int(char x) {
    switch (x) {
        case '0':
            return 0;
        case '1':
            return 1;
        case '2':
            return 2;
        case '3':
            return 3;
        case '4':
            return 4;
        case '5':
            return 5;
        case '6':
            return 6;
        case '7':
            return 7;
        case '8':
            return 8;
        case '9':
            return 9;
        case 'a':
        case 'A':
            return 10;
        case 'b':
        case 'B':
            return 11;
        case 'c':
        case 'C':
            return 12;
        case 'd':
        case 'D':
            return 13;
        case 'e':
        case 'E':
            return 14;
        case 'f':
        case 'F':
            return 15;
        default:
            return 0;
    }
}

/*
The following methods comes from Rfidler sourcecode.
https://github.com/ApertureLabsLtd/RFIDler/blob/master/firmware/Pic32/RFIDler.X/src/
*/
// convert hex to sequence of 0/1 bit values
// returns number of bits converted
int hex2binarray(char *target, char *source) {
    return hex2binarray_n(target, source, strlen(source));
}

int hex2binarray_n(char *target, const char *source, int sourcelen) {
    int count = 0;

    // process 4 bits (1 hex digit) at a time
    while (sourcelen--) {

        char x = *(source++);

        *(target++) = (x >> 7) & 1;
        *(target++) = (x >> 6) & 1;
        *(target++) = (x >> 5) & 1;
        *(target++) = (x >> 4) & 1;
        *(target++) = (x >> 3) & 1;
        *(target++) = (x >> 2) & 1;
        *(target++) = (x >> 1) & 1;
        *(target++) = (x & 1);

        count += 8;
    }
    return count;
}

int binarray2hex(const uint8_t *bs, int bs_len, uint8_t *hex) {

    int count = 0;
    int byte_index = 0;

    // Clear output buffer
    memset(hex, 0, bs_len >> 3);

    for (int i = 0; i < bs_len; i++) {

        // Set the appropriate bit in hex
        if (bs[i] == 1) {
            hex[byte_index] |= (1 << (7 - (count % 8)));
        }

        count++;

        // Move to the next byte if 8 bits have been filled
        if (count % 8 == 0) {
            byte_index++;
        }
    }

    return count;
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
    if (BUTTON_PRESS() == false) {
        return BUTTON_NO_CLICK;
    }

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
        if (BUTTON_PRESS() == false) {
            return BUTTON_SINGLE_CLICK;
        }

        // Have we waited the full second?
        else if (now == (uint16_t)(start + ticks)) {
            return BUTTON_HOLD;
        }

        WDT_HIT();
    }

    // We should never get here
    return BUTTON_ERROR;
}

// This function returns false if no data is available or
// the USB connection is invalid.
bool data_available(void) {
#ifdef WITH_FPC_USART_HOST
    return usb_poll_validate_length() || (usart_rxdata_available() > 0);
#else
    return usb_poll_validate_length();
#endif
}

// This function doesn't check if the USB connection is valid.
// In most of the cases, you should use data_available() unless
// the timing is critical.
bool data_available_fast(void) {
#ifdef WITH_FPC_USART_HOST
    return usb_available_length() || (usart_rxdata_available() > 0);
#else
    return usb_available_length();
#endif
}

uint32_t flash_size_from_cidr(uint32_t cidr) {
    uint8_t nvpsiz = (cidr & 0xF00) >> 8;
    switch (nvpsiz) {
        case 0:
            return 0;
        case 1:
            return 8 * 1024;
        case 2:
            return 16 * 1024;
        case 3:
            return 32 * 1024;
        case 5:
            return 64 * 1024;
        case 7:
            return 128 * 1024;
        case 9:
            return 256 * 1024;
        case 10:
            return 512 * 1024;
        case 12:
            return 1024 * 1024;
        case 14:
        default: // for 'reserved' values, guess 2MB
            return 2048 * 1024;
    }
}

uint32_t get_flash_size(void) {
    return flash_size_from_cidr(*AT91C_DBGU_CIDR);
}

// Combined function to convert an unsigned int to an array of hex values corresponding to the last three bits of k1
void convertToHexArray(uint8_t num, uint8_t *partialkey) {
    char binaryStr[25];  // 24 bits for binary representation + 1 for null terminator
    binaryStr[24] = '\0';  // Null-terminate the string

    // Convert the number to binary string
    for (int i = 23; i >= 0; i--) {
        binaryStr[i] = (num % 2) ? '1' : '0';
        num /= 2;
    }

    // Split the binary string into groups of 3 and convert to hex
    for (int i = 0; i < 8 ; i++) {
        char group[4];
        strncpy(group, binaryStr + i * 3, 3);
        group[3] = '\0';  // Null-terminate the group string
        partialkey[i] = (uint8_t)strtoul(group, NULL, 2);
    }
}
