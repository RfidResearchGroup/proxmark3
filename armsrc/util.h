//-----------------------------------------------------------------------------
// Jonathan Westhues, Aug 2005
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Utility functions used in many places, not specific to any piece of code.
//-----------------------------------------------------------------------------

#ifndef __UTIL_H
#define __UTIL_H

#include "common.h"
#include "proxmark3.h"
#include "string.h"
#include "BigBuf.h"
#include "ticks.h"

// Basic macros
# define _BLUE_(s) "\x1b[34m" s "\x1b[0m "
# define _RED_(s) "\x1b[31m" s "\x1b[0m "
# define _GREEN_(s) "\x1b[32m" s "\x1b[0m "
# define _YELLOW_(s) "\x1b[33m" s "\x1b[0m "
# define _MAGENTA_(s) "\x1b[35m" s "\x1b[0m "
# define _CYAN_(s) "\x1b[36m" s "\x1b[0m "

#ifndef SHORT_COIL
#define SHORT_COIL()     LOW(GPIO_SSC_DOUT)
#endif

#ifndef OPEN_COIL
#define OPEN_COIL()      HIGH(GPIO_SSC_DOUT)
#endif

#ifndef BYTEx
#define BYTEx(x, n) (((x) >> (n * 8)) & 0xff )
#endif

#define LED_RED 1
#define LED_ORANGE 2
#define LED_GREEN 4
#define LED_RED2 8
#define BUTTON_HOLD 1
#define BUTTON_NO_CLICK 0
#define BUTTON_SINGLE_CLICK -1
#define BUTTON_DOUBLE_CLICK -2
#define BUTTON_ERROR -99

#ifndef REV8
#define REV8(x) ((((x)>>7)&1)+((((x)>>6)&1)<<1)+((((x)>>5)&1)<<2)+((((x)>>4)&1)<<3)+((((x)>>3)&1)<<4)+((((x)>>2)&1)<<5)+((((x)>>1)&1)<<6)+(((x)&1)<<7))
#endif

#ifndef REV16
#define REV16(x)        (REV8(x) + (REV8 (x >> 8) << 8))
#endif

#ifndef REV32
#define REV32(x)        (REV16(x) + (REV16(x >> 16) << 16))
#endif

#ifndef REV64
#define REV64(x)        (REV32(x) + (REV32(x >> 32) << 32))
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
void FormatVersionInformation(char *dst, int len, const char *prefix, void *version_information);

#endif
