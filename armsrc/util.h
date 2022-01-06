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
// Utility functions used in many places, not specific to any piece of code.
//-----------------------------------------------------------------------------

#ifndef __UTIL_H
#define __UTIL_H

#include "common.h"

// PRIx64 definition missing with gcc-arm-none-eabi v8?
#ifndef PRIx64
#define PRIx64 "llx"
#endif

// Basic macros

#ifndef SHORT_COIL
#define SHORT_COIL()     LOW(GPIO_SSC_DOUT)
#endif

#ifndef OPEN_COIL
#define OPEN_COIL()      HIGH(GPIO_SSC_DOUT)
#endif

#ifndef BYTEx
#define BYTEx(x, n) (((x) >> (n * 8)) & 0xff )
#endif

// Proxmark3 RDV4.0 LEDs
#define LED_A 1
#define LED_B 2
#define LED_C 4
#define LED_D 8

// Proxmark3 historical LEDs
#define LED_ORANGE LED_A
#define LED_GREEN  LED_B
#define LED_RED    LED_C
#define LED_RED2   LED_D

#define BUTTON_HOLD 1
#define BUTTON_NO_CLICK 0
#define BUTTON_SINGLE_CLICK -1
#define BUTTON_DOUBLE_CLICK -2
#define BUTTON_ERROR -99

#ifndef REV8
#define REV8(x) ((((x)>>7)&1)+((((x)>>6)&1)<<1)+((((x)>>5)&1)<<2)+((((x)>>4)&1)<<3)+((((x)>>3)&1)<<4)+((((x)>>2)&1)<<5)+((((x)>>1)&1)<<6)+(((x)&1)<<7))
#endif

#ifndef REV16
#define REV16(x)        (REV8(x) + (REV8 ((x) >> 8) << 8))
#endif

#ifndef REV32
#define REV32(x)        (REV16(x) + (REV16((x) >> 16) << 16))
#endif

#ifndef REV64
#define REV64(x)        (REV32(x) + ((uint64_t)(REV32((x) >> 32) << 32)))
#endif

#ifndef BIT32
#define BIT32(x,n)      ((((x)[(n)>>5])>>((n)))&1)
#endif

#ifndef INV32
#define INV32(x,i,n)    ((x)[(i)>>5]^=((uint32_t)(n))<<((i)&31))
#endif

#ifndef ROTL64
#define ROTL64(x, n)    ((((uint64_t)(x))<<((n)&63))+(((uint64_t)(x))>>((0-(n))&63)))
#endif

size_t nbytes(size_t nbits);

uint8_t hex2int(char hexchar);

void LED(int led, int ms);
void LEDsoff(void);
void SpinOff(uint32_t pause);
void SpinErr(uint8_t led, uint32_t speed, uint8_t times);
void SpinDown(uint32_t speed);
void SpinUp(uint32_t speed);

int BUTTON_CLICKED(int ms);
int BUTTON_HELD(int ms);
bool data_available(void);

#endif
