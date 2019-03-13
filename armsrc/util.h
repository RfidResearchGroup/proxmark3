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

#ifndef BSWAP_16
# define BSWAP_16(x) ((( ((x) & 0xFF00 ) >> 8))| ( (((x) & 0x00FF) << 8)))
#endif
#ifndef BITMASK
# define BITMASK(X) (1 << (X))
#endif
#ifndef ARRAYLEN
# define ARRAYLEN(x) (sizeof(x)/sizeof((x)[0]))
#endif

#ifndef NTIME
# define NTIME(n) for (int _index = 0; _index < n; _index++)
#endif

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

extern uint32_t reflect(uint32_t v, int b); // used in crc.c ...
extern uint8_t reflect8(uint8_t b);         // dedicated 8bit reversal
extern uint16_t reflect16(uint16_t b);      // dedicated 16bit reversal

void num_to_bytes(uint64_t n, size_t len, uint8_t *dest);
uint64_t bytes_to_num(uint8_t *src, size_t len);
void rol(uint8_t *data, const size_t len);
void lsl(uint8_t *data, size_t len);
int32_t le24toh(uint8_t data[3]);
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
