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
#ifndef __I2C_H
#define __I2C_H

#include "common.h"
#include "pm3_cmd.h"

#define I2C_DEVICE_ADDRESS_BOOT     0xB0
#define I2C_DEVICE_ADDRESS_MAIN     0xC0

#define I2C_DEVICE_CMD_GENERATE_ATR 0x01
#define I2C_DEVICE_CMD_SEND         0x02
#define I2C_DEVICE_CMD_READ         0x03
#define I2C_DEVICE_CMD_SETBAUD      0x04
#define I2C_DEVICE_CMD_SIM_CLC      0x05
#define I2C_DEVICE_CMD_GETVERSION   0x06
#define I2C_DEVICE_CMD_SEND_T0      0x07
// SIM module firmware v4.51 and up.  SEND_T1 takes a plain APDU and runs the
// whole T=1 block layer on the module - chaining, R block recovery, S(WTX),
// LRC/CRC - the same way SEND_T0 handles the T=0 procedure bytes.
#define I2C_DEVICE_CMD_SEND_T1      0x08
#define I2C_DEVICE_CMD_PPS          0x09

// SIM module firmware versions this build knows about.
//
//   v4.42 - the stock firmware, T=0 only
//   v4.51 - adds SEND_T1 (0x08) and PPS (0x09)
//
// Anything at or above the baseline is reported as ok, so a module does not go
// red every time its firmware moves on.
#define SIM_MODULE_VERS_MIN_HI      4
#define SIM_MODULE_VERS_MIN_LO      42
#define SIM_MODULE_VERS_T1_HI       4
#define SIM_MODULE_VERS_T1_LO       51

// The SIM module v4 supports up to 384 bytes for the length.
#define  ISO7816_MAX_FRAME 270

/*
 * Bit banged bus timing.
 *
 * I2C_DELAY_1CLK is spent twice per bit and I2C_DELAY_2CLK once, so the bit
 * period is 2 * 1CLK + 2CLK.  At 2/4 us that is ~125 kHz nominal; expect nearer
 * 90 kHz once SpinDelayUsPrecision()'s own overhead at these short durations is
 * counted.
 *
 * TODO DXL 修改了速度到比较慢的情况，测完需要改回来，原先是2和4
 *
 * ("the speed was changed to a slower setting; change it back after testing,
 *  originally 2 and 4")
 *
 * That TODO belongs to the HAL refactoring for the Proxmark5 (Artery
 * AT32F435/437), where SpinDelayUsPrecision() is a different implementation
 * whose overhead at a two microsecond request has not been measured.  The
 * 20/22 us it was raised to is kept for that platform rather than thrown away.
 *
 * Nothing depends on it yet: smartcard support is not built for PM5 - see the
 * "暂时不要编译i2c" note beside its PLATFORM_DEFS in common_arm/Makefile.hal -
 * so the AT32 branch below is an unvalidated starting point, not a measurement.
 * When that bring-up happens, measure the AT32 delay and set it here; every
 * timeout in this file is derived from these two numbers, so that is the only
 * place it needs to change.
 */
/*
 * 20/22 on both platforms for now.
 *
 * Dropping this to 2/4 was tried and the bus stopped working entirely - no ATR,
 * no answer to anything - even with the delay primitive's overshoot bug fixed
 * (see SpinDelayUsPrecision in common_arm/ticks/ticks_hw_at91.c).  8 us per bit
 * is about 125 kHz, and something in the path will not carry it: rise time
 * through the pull ups is the obvious candidate, but it was not measured.
 *
 * Worth revisiting with a scope on SCL and SDA rather than by trial.  Every
 * timeout below is derived from these two numbers, so changing them is a
 * two line edit once someone knows what the bus can actually do.
 */
#define I2C_DELAY_1CLK_US       20
#define I2C_DELAY_2CLK_US       22

/*
 * Every SCL wait loop spends one I2C_DELAY_1CLK per iteration, so the timeouts
 * below are iteration counts rather than times - which is why changing the
 * delay used to silently rescale every one of them, and why the constants had
 * drifted to roughly 6.5x their documented length.
 *
 * They are written in milliseconds now and converted in one place, so the two
 * cannot come apart again.  The conversion uses the nominal delay rather than a
 * measured one on purpose: with the real per-iteration cost being a little
 * higher, a timeout always lasts at least as long as it asks for.
 */
#define I2C_ITERS_PER_MS        (1000U / I2C_DELAY_1CLK_US)
#define I2C_ITERS_FOR_MS(ms)    ((uint32_t)(ms) * (uint32_t)I2C_ITERS_PER_MS)

// How long the master tolerates the slave stretching SCL inside a transfer.
#define I2C_STRETCH_TIMEOUT_MS  100

/*
 * How long to wait for the SIM module to finish an operation and release SCL.
 *
 * This has to cover the card's own thinking time.  A T=1 card's block waiting
 * time is 1.4 s at the default BWI = 4, and a HID iCLASS SE SAM asks for
 * BWI = 5, i.e. 2.9 s - so 3 s is the smallest value that clears both.
 */
// Upper bound on a host supplied SC_WAIT, so the conversion cannot overflow.
#define I2C_WAIT_MAX_MS         60000

#define SIM_WAIT_MS             3000
#define SIM_WAIT_DELAY          I2C_ITERS_FOR_MS(SIM_WAIT_MS)

/*
 * Compile time guards on the two numbers above.  The build is -std=c99 so this
 * is the negative array size trick rather than _Static_assert.
 */
#define I2C_BUILD_ASSERT(cond, name) typedef char i2c_assert_##name[(cond) ? 1 : -1]

// A delay that does not divide 1000 makes I2C_ITERS_PER_MS silently lose
// precision, and every timeout with it.
I2C_BUILD_ASSERT((1000U % I2C_DELAY_1CLK_US) == 0, clk_divides_ms);

// A T=1 card may sit quiet for its whole block waiting time before answering:
// 1.4 s at the default BWI = 4, and 2.9 s at the BWI = 5 a HID iCLASS SE SAM
// asks for.  Shorten this and T=1 starts timing out on slow cards with nothing
// to show for it but an empty response.
I2C_BUILD_ASSERT(SIM_WAIT_MS >= 3000, sim_wait_covers_bwt);

// The largest host supplied wait must still fit the iteration counter.
I2C_BUILD_ASSERT((uint64_t)I2C_WAIT_MAX_MS * I2C_ITERS_PER_MS <= 0xFFFFFFFFULL, wait_fits_u32);


void I2C_recovery(void);
void I2C_init(bool has_ticks);
void I2C_Reset(void); // TODO DXL: Not implemented but defined?
void I2C_SetResetStatus(uint8_t LineRST, uint8_t LineSCK, uint8_t LineSDA);

void I2C_Reset_EnterMainProgram(void);
void I2C_Reset_EnterBootloader(void);

bool I2C_WriteCmd(uint8_t device_cmd, uint8_t device_address);

bool I2C_WriteByte(uint8_t data, uint8_t device_cmd, uint8_t device_address);
bool I2C_BufferWrite(const uint8_t *data, uint16_t len, uint8_t device_cmd, uint8_t device_address);
int16_t I2C_BufferReadRaw(uint8_t *data, uint16_t len, uint8_t device_cmd, uint8_t device_address);
int16_t I2C_BufferRead(uint8_t *data, uint16_t len, uint8_t device_cmd, uint8_t device_address);

// for firmware
int16_t I2C_ReadFW(uint8_t *data, uint8_t len, uint8_t msb, uint8_t lsb, uint8_t device_address);
bool I2C_WriteFW(const uint8_t *data, uint8_t len, uint8_t msb, uint8_t lsb, uint8_t device_address);

// Which SIM module opcode a set of SC_RAW* flags asks for.
uint8_t sc_raw_device_cmd(smartcard_command_t flags);

bool sc_rx_bytes(uint8_t *dest, uint16_t *destlen, uint32_t wait);
//
bool GetATR(smart_card_atr_t *card_ptr, bool verbose);

// generice functions
void SmartCardAtr(void);
void SmartCardRaw(const smart_card_raw_t *p);
void SmartCardUpgrade(uint64_t arg0);
void SmartCardSetBaud(uint64_t arg0);
void SmartCardSetClock(uint64_t arg0);
void SmartCardPPS(const smart_card_pps_t *p);
void I2C_print_status(void);
int I2C_get_version(uint8_t *major, uint8_t *minor);

#endif
