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

#include <stddef.h>
#include <stdint.h>

#define RAMFUNC __attribute((long_call, section(".ramfunc")))

#define BYTEx(x, n) (((x) >> (n * 8)) & 0xff )

#define LED_RED 1
#define LED_ORANGE 2
#define LED_GREEN 4
#define LED_RED2 8
#define BUTTON_HOLD 1
#define BUTTON_NO_CLICK 0
#define BUTTON_SINGLE_CLICK -1
#define BUTTON_DOUBLE_CLICK -2
#define BUTTON_ERROR -99

void num_to_bytes(uint64_t n, size_t len, uint8_t* dest);
uint64_t bytes_to_num(uint8_t* src, size_t len);

void SpinDelay(int ms);
void SpinDelayUs(int us);
void LED(int led, int ms);
void LEDsoff();
int BUTTON_CLICKED(int ms);
int BUTTON_HELD(int ms);
void FormatVersionInformation(char *dst, int len, const char *prefix, void *version_information);

void StartTickCount();
uint32_t RAMFUNC GetTickCount();

void StartCountUS();
uint32_t RAMFUNC GetCountUS();
uint32_t RAMFUNC GetDeltaCountUS();

#endif
