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

#ifndef I2C_APIS_H
#define I2C_APIS_H

#include <stdbool.h>
#include <stdint.h>

#define SCL_H       Gpio_I2C_SCL_High()
#define SCL_L       Gpio_I2C_SCL_Low()
#define SDA_H       Gpio_I2C_SDA_High()
#define SDA_L       Gpio_I2C_SDA_Low()
#define RST_H       Gpio_I2C_RST_High()
#define RST_L       Gpio_I2C_RST_Low()
#define SCL_read    Gpio_I2C_SCL_Read()
#define SDA_read    Gpio_I2C_SDA_Read()
#define I2C_ERROR   "I2C_WaitAck Error"

// Only one delay per bit is rise time critical: the one bracketing an SDA
// transition, where a released line has to charge through the pull-up before
// it reads as a 1. Sampling before that is what corrupted the bus every time
// these were simply scaled down together. The others are padding - hold after
// SCL falls (spec 0.3 us) and SCL high width (spec 4 us) - so they get the
// standard mode minimum with margin instead of a full clock.
#define I2C_DELAY_SDA_US        15
#define I2C_DELAY_SDA_FAST_US   8
#define I2C_FAST_SDA_TIMING     1
#define I2C_DELAY_HOLD_US       2
#define I2C_DELAY_HIGH_US       6

#define I2C_STRETCH_TIMEOUT_MS  100     // slave stretching SCL inside a transfer

// The fast profile shortens only the SDA settle delay. I2C_DELAY_1CLK also
// sets the timeout conversion above, so tightening it would rescale every
// millisecond timeout in the callers without any of them changing.
bool I2C_SetFastSDATiming(bool enabled);        // returns the previous state

// SCL polling, bounded by an iteration count built with I2C_ITERS_FOR_MS().

bool I2C_WaitSCL_H(uint32_t iters);
bool I2C_WaitSCL_L(uint32_t iters);

// Framing primitives: the caller owns START/STOP and the acknowledge phase, so
// a device driver can put whatever address bytes its own register map needs on
// the wire. The helpers below only cover the single command byte case.

bool I2C_Start(void);
void I2C_Stop(void);
bool I2C_WaitAck(void);
void I2C_SendByte(uint8_t data);
int16_t I2C_ReadByte(void);
void I2C_Ack(void);
void I2C_NoAck(void);

// Upper level API. Most of the time, we only need to use these APIs to complete the required functions.

void I2C_init(bool has_ticks);
void I2C_recovery(void);
bool I2C_WriteCmd(uint8_t device_cmd, uint8_t device_address);
bool I2C_WriteByte(uint8_t data, uint8_t device_cmd, uint8_t device_address);
bool I2C_BufferWrite(const uint8_t *data, uint16_t len, uint8_t device_cmd, uint8_t device_address);
int16_t I2C_BufferRead(uint8_t *data, uint16_t len, uint8_t device_cmd, uint8_t device_address);
int16_t I2C_AdaptiveRead(uint8_t *data, uint16_t len, uint8_t device_cmd, uint8_t device_address);

#ifdef PM5
#include "i2c_hw_at32.h"
#else
#include "i2c_hw_at91.h"
#endif

// The SCL wait loops spend one 1CLK per iteration, so their timeouts are
// iteration counts. Written in ms and converted here so the two cannot drift.
#define I2C_ITERS_PER_MS        (1000U / I2C_DELAY_1CLK_US)
#define I2C_ITERS_FOR_MS(ms)    ((uint32_t)(ms) * (uint32_t)I2C_ITERS_PER_MS)

// -std=c99, so no _Static_assert
#define I2C_BUILD_ASSERT(cond, name) typedef char i2c_assert_##name[(cond) ? 1 : -1]
I2C_BUILD_ASSERT((1000U % I2C_DELAY_1CLK_US) == 0, clk_divides_ms);

#endif //I2C_APIS_H
