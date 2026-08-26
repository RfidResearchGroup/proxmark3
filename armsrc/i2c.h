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

// Bit banged bus timing. 1CLK is spent twice per bit, 2CLK once, so the bit
// period is 2 * 1CLK + 2CLK, here 17 us or about 59 kHz. Every timeout below
// derives from these, so they are the only two numbers to change.
#define I2C_DELAY_1CLK_US        5
#define I2C_DELAY_2CLK_US        7

// The SCL wait loops spend one 1CLK per iteration, so their timeouts are
// iteration counts. Written in ms and converted here so the two cannot drift.
#define I2C_ITERS_PER_MS        (1000U / I2C_DELAY_1CLK_US)
#define I2C_ITERS_FOR_MS(ms)    ((uint32_t)(ms) * (uint32_t)I2C_ITERS_PER_MS)

#define I2C_STRETCH_TIMEOUT_MS  100     // slave stretching SCL inside a transfer
#define I2C_WAIT_MAX_MS         60000   // clamp on a host supplied SC_WAIT

// Must cover the card's block waiting time: 1.4 s at BWI=4, 2.9 s at BWI=5.
#define SIM_WAIT_MS             3000
#define SIM_WAIT_DELAY          I2C_ITERS_FOR_MS(SIM_WAIT_MS)

// -std=c99, so no _Static_assert
#define I2C_BUILD_ASSERT(cond, name) typedef char i2c_assert_##name[(cond) ? 1 : -1]

I2C_BUILD_ASSERT((1000U % I2C_DELAY_1CLK_US) == 0, clk_divides_ms);
I2C_BUILD_ASSERT(SIM_WAIT_MS >= 3000, sim_wait_covers_bwt);
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
