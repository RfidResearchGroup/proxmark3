//-----------------------------------------------------------------------------
// Jonathan Westhues, Sept 2005
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Utility functions used in many places, not specific to any piece of code.
//-----------------------------------------------------------------------------
#include "util.h"

size_t nbytes(size_t nbits) {
    return (nbits >> 3) + ((nbits % 8) > 0);
}

/*
 ref  http://www.csm.ornl.gov/~dunigan/crc.html
 Returns the value v with the bottom b [0,32] bits reflected.
 Example: reflect(0x3e23L,3) == 0x3e26
*/
uint32_t reflect(uint32_t v, int b) {
    uint32_t t = v;
    for (int i = 0; i < b; ++i) {
        if (t & 1)
            v |=  BITMASK((b - 1) - i);
        else
            v &= ~BITMASK((b - 1) - i);
        t >>= 1;
    }
    return v;
}

uint8_t reflect8(uint8_t b) {
    return ((b * 0x80200802ULL) & 0x0884422110ULL) * 0x0101010101ULL >> 32;
}
uint16_t reflect16(uint16_t b) {
    uint16_t v = 0;
    v |= (b & 0x8000) >> 15;
    v |= (b & 0x4000) >> 13;
    v |= (b & 0x2000) >> 11;
    v |= (b & 0x1000) >> 9;
    v |= (b & 0x0800) >> 7;
    v |= (b & 0x0400) >> 5;
    v |= (b & 0x0200) >> 3;
    v |= (b & 0x0100) >> 1;

    v |= (b & 0x0080) << 1;
    v |= (b & 0x0040) << 3;
    v |= (b & 0x0020) << 5;
    v |= (b & 0x0010) << 7;
    v |= (b & 0x0008) << 9;
    v |= (b & 0x0004) << 11;
    v |= (b & 0x0002) << 13;
    v |= (b & 0x0001) << 15;
    return v;
}

void num_to_bytes(uint64_t n, size_t len, uint8_t *dest) {
    while (len--) {
        dest[len] = (uint8_t) n;
        n >>= 8;
    }
}

uint64_t bytes_to_num(uint8_t *src, size_t len) {
    uint64_t num = 0;
    while (len--) {
        num = (num << 8) | (*src);
        src++;
    }
    return num;
}

// RotateLeft - Ultralight, Desfire
void rol(uint8_t *data, const size_t len) {
    uint8_t first = data[0];
    for (size_t i = 0; i < len - 1; i++) {
        data[i] = data[i + 1];
    }
    data[len - 1] = first;
}

void lsl(uint8_t *data, size_t len) {
    for (size_t n = 0; n < len - 1; n++) {
        data[n] = (data[n] << 1) | (data[n + 1] >> 7);
    }
    data[len - 1] <<= 1;
}

int32_t le24toh(uint8_t data[3]) {
    return (data[2] << 16) | (data[1] << 8) | data[0];
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

void LEDsoff() {
    LED_A_OFF();
    LED_B_OFF();
    LED_C_OFF();
    LED_D_OFF();
}

// LEDs: R(C) O(A) G(B) -- R(D) [1, 2, 4 and 8]
void LED(int led, int ms) {
    if (led & LED_RED)
        LED_C_ON();
    if (led & LED_ORANGE)
        LED_A_ON();
    if (led & LED_GREEN)
        LED_B_ON();
    if (led & LED_RED2)
        LED_D_ON();

    if (!ms)
        return;

    SpinDelay(ms);

    if (led & LED_RED)
        LED_C_OFF();
    if (led & LED_ORANGE)
        LED_A_OFF();
    if (led & LED_GREEN)
        LED_B_OFF();
    if (led & LED_RED2)
        LED_D_OFF();
}

void SpinOff(uint32_t pause) {
    LED_A_OFF();
    LED_B_OFF();
    LED_C_OFF();
    LED_D_OFF();
    SpinDelay(pause);
}

// 0=A, 1=B, 2=C, 3=D
void SpinErr(uint8_t led, uint32_t speed, uint8_t times) {
    SpinOff(speed);
    NTIME(times) {
        switch (led) {
            case 0:
                LED_A_INV();
                break;
            case 1:
                LED_B_INV();
                break;
            case 2:
                LED_C_INV();
                break;
            case 3:
                LED_D_INV();
                break;
        }
        SpinDelay(speed);
    }
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
    int ticks = (48000 * (ms ? ms : 1000)) >> 10;

    // If we're not even pressed, forget about it!
    if (!BUTTON_PRESS())
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
            if (!BUTTON_PRESS()) {
                letoff = 1;

                // reset our timer for 500ms
                start = AT91C_BASE_PWMC_CH0->PWMC_CCNTR;
                ticks = (48000 * (500)) >> 10;
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
    // If button is held for one second
    int ticks = (48000 * (ms ? ms : 1000)) >> 10;

    // If we're not even pressed, forget about it!
    if (!BUTTON_PRESS())
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
        if (!BUTTON_PRESS())
            return BUTTON_SINGLE_CLICK;

        // Have we waited the full second?
        else if (now == (uint16_t)(start + ticks))
            return BUTTON_HOLD;

        WDT_HIT();
    }

    // We should never get here
    return BUTTON_ERROR;
}

/* Similar to FpgaGatherVersion this formats stored version information
 * into a string representation. It takes a pointer to the struct version_information,
 * verifies the magic properties, then stores a formatted string, prefixed by
 * prefix in dst.
 */
void FormatVersionInformation(char *dst, int len, const char *prefix, void *version_information) {
    struct version_information *v = (struct version_information *)version_information;
    dst[0] = 0;
    strncat(dst, prefix, len - 1);
    if (v->magic != VERSION_INFORMATION_MAGIC) {
        strncat(dst, "Missing/Invalid version information\n", len - strlen(dst) - 1);
        return;
    }
    if (v->versionversion != 1) {
        strncat(dst, "Version information not understood\n", len - strlen(dst) - 1);
        return;
    }
    if (!v->present) {
        strncat(dst, "Version information not available\n", len - strlen(dst) - 1);
        return;
    }

    strncat(dst, v->gitversion, len - strlen(dst) - 1);
    if (v->clean == 0) {
        strncat(dst, "-unclean", len - strlen(dst) - 1);
    } else if (v->clean == 2) {
        strncat(dst, "-suspect", len - strlen(dst) - 1);
    }

    strncat(dst, " ", len - strlen(dst) - 1);
    strncat(dst, v->buildtime, len - strlen(dst) - 1);
    strncat(dst, "\n", len - strlen(dst) - 1);
}
