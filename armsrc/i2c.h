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

void I2C_recovery(void);
void I2C_init(bool has_ticks);
void I2C_Reset(void);
void I2C_SetResetStatus(uint8_t LineRST, uint8_t LineSCK, uint8_t LineSDA);

void I2C_Reset_EnterMainProgram(void);
void I2C_Reset_EnterBootloader(void);

bool I2C_WriteCmd(uint8_t device_cmd, uint8_t device_address);

bool I2C_WriteByte(uint8_t data, uint8_t device_cmd, uint8_t device_address);
bool I2C_BufferWrite(const uint8_t *data, uint16_t len, uint8_t device_cmd, uint8_t device_address);
int16_t I2C_BufferRead(uint8_t *data, uint16_t len, uint8_t device_cmd, uint8_t device_address);

// for firmware
int16_t I2C_ReadFW(uint8_t *data, uint8_t len, uint8_t msb, uint8_t lsb, uint8_t device_address);
bool I2C_WriteFW(const uint8_t *data, uint8_t len, uint8_t msb, uint8_t lsb, uint8_t device_address);

bool sc_rx_bytes(uint8_t *dest, uint16_t *destlen);
//
bool GetATR(smart_card_atr_t *card_ptr, bool verbose);

// generice functions
void SmartCardAtr(void);
void SmartCardRaw(const smart_card_raw_t *p);
void SmartCardUpgrade(uint64_t arg0);
void SmartCardSetBaud(uint64_t arg0);
void SmartCardSetClock(uint64_t arg0);
void I2C_print_status(void);
int I2C_get_version(uint8_t *maj, uint8_t *min);

#endif
